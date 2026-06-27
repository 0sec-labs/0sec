/**
 * Hunt scan stage — pwnkit's parallel NOVEL-BUG discovery loop, as a first-class
 * engine stage (sibling of runCraftScan / runExploitScan).
 *
 * Benchmarks reproduce KNOWN bugs; this finds UNKNOWN ones. It codifies the
 * discovery architecture that has actually produced 0-days for us (the TIPC
 * incomplete-fix variant hunt) instead of doing it ad-hoc via subagents:
 *
 *   candidates ──fan out (parallel)──> FINDER (agenticScan, per candidate)
 *                                          │  findings
 *                                          ▼
 *                                   SKEPTIC + PROVER (injected `verify`)
 *                                          │  confirmed, novel, reachable
 *                                          ▼
 *                                     HuntScanResult.confirmed
 *
 * Four levers, made concrete:
 *  - PARALLELIZATION (coverage): fan finders out over many candidates at once.
 *  - FRESHNESS (the proven edge): caller points `candidates` at under-audited
 *    surface (new drivers / linux-next) or VARIANT sites of a recent fix.
 *  - MODEL DIVERSITY: pass several `models`; each candidate is hunted by each,
 *    findings unioned — different models surface different bugs.
 *  - THE ORACLE (no self-grading): `verify` is the skeptic+prover gate (assume-FP
 *    refute → build+run+sanitizer reproduce). Injected, so prod wires the real
 *    verify pipeline and this stage stays generic.
 *
 * Reuses the finder (`agenticScan`) verbatim; the new part is the fan-out +
 * candidate model + the verify gate.
 */

import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmSync } from "node:fs";
import type { Finding, RuntimeMode, ScanConfig } from "@pwnkit/shared";
import { agenticScan } from "../agentic-scanner.js";

// Per-scan throwaway SQLite DB. The finders/skeptics run concurrently and the
// default DB is a single shared ~/.pwnkit/pwnkit.db — at any real fan-out width
// they contend on its write lock ("SQLite database is locked"), which crashed
// verify steps mid-sweep (NOT a refute — a crash, silently dropping the gate).
// Each agenticScan gets its own DB so there is zero cross-scan contention.
let huntDbCounter = 0;
function freshHuntDb(): string {
  return join(tmpdir(), `pwnkit-hunt-${process.pid}-${huntDbCounter++}.db`);
}
function cleanupHuntDb(path: string): void {
  for (const suffix of ["", "-wal", "-shm"]) {
    try { rmSync(path + suffix, { force: true }); } catch { /* best-effort */ }
  }
}

// ── Contract ─────────────────────────────────────────────────────────────────

/** One place to hunt: a file/dir + an optional per-candidate hint. */
export interface HuntCandidate {
  /** Path (under sourceRoot) the finder scans — a file, dir, or subsystem. */
  path: string;
  /** Optional per-candidate guidance (e.g. "the variant of CVE-XXXX lives near fn foo()"). */
  hint?: string;
}

/**
 * The hunt brief — the bug pattern to look for. For a VARIANT hunt this encodes
 * a recent fix's bug class so the finder looks for the same unguarded pattern
 * elsewhere / an incomplete fix. Omit for a generic fresh-surface bug hunt.
 */
export interface HuntBrief {
  /** The bug class, e.g. "missing length check before a multi-byte read". */
  bugClass: string;
  /** The concrete pattern to match (the sink/shape), and how the fix guarded it. */
  pattern: string;
  /** Optional reference to the originating fix/CVE (provenance). */
  fixReference?: string;
}

/** Skeptic+prover gate: refute (assume-FP) then build+run+sanitizer reproduce. Never self-graded. */
export type HuntVerifier = (
  finding: Finding,
  candidate: HuntCandidate,
) => Promise<{ confirmed: boolean; reason: string }>;

export interface HuntScanOptions {
  sourceRoot: string;
  /** Where to hunt (under-audited files / variant sites). The coverage frontier. */
  candidates: HuntCandidate[];
  /** Variant-hunt brief; omit for a generic bug hunt. */
  brief?: HuntBrief;
  runtime: RuntimeMode;
  /** One or more finder models (diversity). Defaults to the configured provider. */
  models?: string[];
  /** Max finders running at once. Default 8. */
  concurrency?: number;
  /** Per-finder scan depth. Default "quick". */
  depth?: "quick" | "deep";
  /** The skeptic+prover gate. When omitted, all findings are returned unconfirmed. */
  verify?: HuntVerifier;
  log?: (msg: string) => void;
}

export interface HuntScanResult {
  /** Every candidate finding the finders surfaced. */
  findings: Finding[];
  /** Findings that passed the skeptic+prover gate (real, novel, reachable). */
  confirmed: Finding[];
  /** How many (candidate × model) finder runs executed. */
  scanned: number;
  warnings: string[];
}

// ── Stage ────────────────────────────────────────────────────────────────────

/** Run `tasks` with at most `limit` in flight; returns results in input order (failures → null). */
async function pool<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<(R | null)[]> {
  const out: (R | null)[] = new Array(items.length).fill(null);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      try { out[i] = await fn(items[i], i); } catch { out[i] = null; }
    }
  });
  await Promise.all(workers);
  return out;
}

function huntHint(brief: HuntBrief | undefined, candidate: HuntCandidate): string {
  const parts: string[] = [];
  if (brief) {
    parts.push(
      `VARIANT HUNT. Look ONLY for this specific bug class: ${brief.bugClass}.`,
      `Concrete pattern to find: ${brief.pattern}.`,
      brief.fixReference ? `It mirrors the recently-fixed ${brief.fixReference} — find the SAME unguarded pattern here, or an INCOMPLETE fix.` : "",
      "Report a finding ONLY when you can point to the exact unguarded sink (file:line) and the attacker-controlled path to it. Do not report speculative or already-guarded code.",
    );
  } else {
    parts.push(
      "Novel-bug hunt on under-audited code. Find a concrete, exploitable memory-safety / logic bug with an attacker-reachable path.",
      "Report ONLY a grounded finding (exact sink file:line + the reaching path). No speculation, no already-guarded code.",
    );
  }
  if (candidate.hint) parts.push(candidate.hint);
  return parts.filter(Boolean).join(" ");
}

// ── Gate building blocks ─────────────────────────────────────────────────────

/**
 * The SKEPTIC half of the gate: a second adversarial finder pass prompted to
 * REFUTE the finding (assume-FP), re-reading the same code. It kills the
 * plausible-but-wrong findings the first pass invents. This is necessary but
 * NOT sufficient — it is still a model reading code, so it only filters; it
 * never PROVES. Compose it with a real prover (build+run+sanitizer for
 * userspace, the kernel-vm verify for kernel) before trusting a "confirmed".
 */
export function makeSkepticVerifier(opts: {
  sourceRoot: string;
  runtime: RuntimeMode;
  model?: string;
}): HuntVerifier {
  return async (finding, candidate) => {
    const hint =
      `ADVERSARIAL REVIEW. A prior pass claims this finding in ${candidate.path}:\n` +
      `  title: ${finding.title}\n  detail: ${finding.description}\n` +
      "Assume it is a FALSE POSITIVE and try HARD to REFUTE it. Generic checks: is the sink actually " +
      "guarded upstream, is the precondition impossible, is it already fixed? Then run these THREE " +
      "checks that catch the false positives a naive re-read misses (each has burned us — a real " +
      "submitted patch was wrong because we skipped them):\n" +
      "  1. ENTRY-POINT / REACHABILITY GATE: trace from the userspace entry (ioctl dispatcher, syscall, " +
      "netlink handler, parser entry) all the way to the sink. Is the entry itself DISABLED or gated " +
      "off before the sink is reached? Look for `if (cmd) return -EINVAL` umbrella disables, a " +
      "'disallow all private ioctls' guard, a compiled-out CONFIG, a deprecated/being-removed driver, " +
      "or a capability/permission check. If the path is dead code, it is a FALSE POSITIVE.\n" +
      "  2. CONTROL-FLOW COMPOSITION: if the bug needs two events in sequence (e.g. flush THEN resume, " +
      "free in fn A THEN use in fn B), verify those functions are actually on the SAME reachable path " +
      "and not disjoint (e.g. one is teardown-only and never precedes the other). If the composition " +
      "never happens, it is a FALSE POSITIVE (or mis-attributed).\n" +
      "  3. FIX SIDE-EFFECTS (only if a fix/guard is implied): would the proposed guard (esp. an early " +
      "return / goto) SKIP required code below it — register writes, unlocks, frees, DMA setup — and " +
      "thereby introduce a NEW bug? If so, the finding/fix is unsafe.\n" +
      "Only report a finding if, after genuinely trying to refute it AND passing all three checks, you " +
      "CANNOT refute it — i.e. you can still point to the exact unguarded sink (file:line), a concrete " +
      "ENABLED attacker-reachable path, and (if a fix is implied) a fix that skips no required code. " +
      "If you cannot, report NOTHING.";
    // A FOCUSED re-read, not a fresh broad hunt: the challengeHint already
    // targets the one claim, so "quick" depth keeps the gate fast enough to run
    // per-finding at scale (a "deep" full-template scan took ~10min on a 10-line
    // file in smoke testing — prohibitive across many findings).
    const config: ScanConfig = {
      target: candidate.path,
      depth: "quick",
      format: "json",
      mode: "deep",
      timeout: 60_000,
      runtime: opts.runtime,
      repoPath: opts.sourceRoot,
      ...(opts.model ? { model: opts.model } : {}),
    };
    const dbPath = freshHuntDb();
    try {
      const report = await agenticScan({ config, dbPath, challengeHint: hint });
      const survived = (report.findings ?? []).length > 0;
      return survived
        ? { confirmed: true, reason: "survived adversarial refute pass" }
        : { confirmed: false, reason: "refuted: skeptic could not reproduce the claim from source" };
    } finally {
      cleanupHuntDb(dbPath);
    }
  };
}

/**
 * Compose gate stages into one verifier, short-circuiting on the first that
 * rejects. Put the cheap skeptic first, the expensive prover last:
 *   verify: composeGate(makeSkepticVerifier(...), myKernelVmProver)
 */
export function composeGate(...stages: HuntVerifier[]): HuntVerifier {
  return async (finding, candidate) => {
    for (const stage of stages) {
      const v = await stage(finding, candidate);
      if (!v.confirmed) return v;
    }
    return { confirmed: true, reason: "passed all gate stages" };
  };
}

export async function runHuntScan(opts: HuntScanOptions): Promise<HuntScanResult> {
  const log = opts.log ?? (() => {});
  const models = opts.models && opts.models.length > 0 ? opts.models : [undefined as unknown as string];
  const concurrency = opts.concurrency ?? 8;
  const depth = opts.depth ?? "quick";
  const warnings: string[] = [];

  // (candidate × model) finder runs — the parallel coverage sweep.
  const runs: Array<{ candidate: HuntCandidate; model?: string }> = [];
  for (const candidate of opts.candidates) for (const model of models) runs.push({ candidate, model });

  log(`[hunt] ${opts.candidates.length} candidate(s) × ${models.length} model(s) = ${runs.length} finder run(s), ${concurrency}-wide`);

  const reports = await pool(runs, concurrency, async (run) => {
    const dbPath = freshHuntDb();
    try {
      const config: ScanConfig = {
        target: run.candidate.path,
        depth,
        format: "json",
        mode: "deep",
        timeout: 60_000,
        runtime: opts.runtime,
        repoPath: opts.sourceRoot,
        ...(run.model ? { model: run.model } : {}),
      };
      const report = await agenticScan({ config, dbPath, challengeHint: huntHint(opts.brief, run.candidate) });
      return { candidate: run.candidate, findings: report.findings ?? [] };
    } catch (e) {
      warnings.push(`hunt: finder failed on ${run.candidate.path}: ${String(e).slice(0, 120)}`);
      return { candidate: run.candidate, findings: [] as Finding[] };
    } finally {
      cleanupHuntDb(dbPath);
    }
  });

  const all: Array<{ finding: Finding; candidate: HuntCandidate }> = [];
  for (const r of reports) if (r) for (const finding of r.findings) all.push({ finding, candidate: r.candidate });
  log(`[hunt] finders surfaced ${all.length} candidate finding(s)`);

  // Skeptic + prover gate (parallel). No verifier → everything stays unconfirmed.
  let confirmed: Finding[] = [];
  if (opts.verify && all.length > 0) {
    const verdicts = await pool(all, concurrency, async ({ finding, candidate }) => {
      try {
        const v = await opts.verify!(finding, candidate);
        return v.confirmed ? finding : null;
      } catch (e) {
        warnings.push(`hunt: verify failed for ${finding.title}: ${String(e).slice(0, 100)}`);
        return null;
      }
    });
    confirmed = verdicts.filter((f): f is Finding => f != null);
    log(`[hunt] ${confirmed.length}/${all.length} finding(s) confirmed by the skeptic+prover gate`);
  }

  return {
    findings: all.map((a) => a.finding),
    confirmed,
    scanned: runs.length,
    warnings,
  };
}
