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
import {
  checkNovelty,
  findingToQuery,
  type NoveltyCheckOptions,
  type NoveltyQuery,
  type LoreNoveltyResult,
} from "./novelty-check.js";
import { judgeHuntCandidatesWithLlm, type HuntCandidateJudge } from "./hunt-judge.js";
import { HuntMemory, huntFlywheelEnabled, primedOrderKey, type HuntPriming } from "./hunt-flywheel.js";
import { huntNegativesEnabled, matchNegative, negativeContext, type KnownNegative } from "./hunt-negatives.js";

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
  /**
   * Independent finder attempts per (candidate, model) — the best-of-N
   * breadth (mirrors CYBERGYM_BEST_OF_N). Default 1 reproduces today's
   * behavior exactly: one finder run per (candidate, model), everything goes
   * straight to `verify`. Raising this fans out N attempts per (candidate,
   * model); when N>1 surfaces >1 finding at the same site, only the top
   * `judgeTopK` (by {@link judgeCandidates}) reach the skeptic+prover gate, so
   * skeptic call-count stays ~flat while finder coverage widens N×.
   */
  attemptsPerCandidate?: number;
  /**
   * How many judge-ranked findings per (candidate, model) group advance to
   * `verify` when that group has >1 finding. Default 1.
   */
  judgeTopK?: number;
  /** Optional judge model override (mirrors the `HUNT_SKEPTIC_MODEL` convention). */
  judgeModel?: string;
  /** Injectable candidate judge; defaults to {@link judgeHuntCandidatesWithLlm}. Exposed for tests. */
  judgeCandidates?: HuntCandidateJudge;
  /** The skeptic+prover gate. When omitted, all findings are returned unconfirmed. */
  verify?: HuntVerifier;
  /**
   * OPTIONAL second-audit refinement (the "treat every crash as shallow" step).
   * Runs on each surfaced finding BEFORE the verify gate: deepen the candidate to
   * its root cause / a fix-bypass path, THEN verify the deepened candidate. Given
   * `(finding, candidate)`, returns the candidate the gate should reproduce (the
   * original candidate when the audit finds nothing deeper). Additive — omit it
   * and the hunt verifies the first-order candidate exactly as before. Wire it
   * with {@link makeSecondAuditRefiner} from second-audit.ts.
   */
  refine?: (finding: Finding, candidate: HuntCandidate) => Promise<HuntCandidate>;
  /**
   * OPTIONAL lore-mirror novelty gate (issue: Rockchip AV1 re-find). When set,
   * every confirmed finding is checked against on-list (pending/merged) upstream
   * patches via {@link checkNovelty}. DUPLICATE findings are moved out of
   * `confirmed` into `duplicates`; NOVEL ones pass through unchanged. Additive —
   * omit it and the hunt behaves exactly as before. `queryFor` maps a finding to
   * its search facts; defaults to {@link findingToQuery} (auto-mines the prose).
   */
  novelty?: NoveltyCheckOptions & { queryFor?: (finding: Finding) => NoveltyQuery };
  /**
   * OPTIONAL memory-flywheel priming (`PWNKIT_HUNT_FLYWHEEL=1`, see
   * hunt-flywheel.ts). Injectable for tests; when the flag is on and
   * `opts.brief` is set but no instance is passed, defaults to a fresh
   * `HuntMemory()` (archetype preseed only — no corpus path). PRIMES the
   * best-of-N judge ORDERING and the attempt-budget cost-router ONLY —
   * `opts.verify` (the skeptic+prover gate) never receives it. See
   * hunt-flywheel.ts's header for the primes-never-confirms invariant.
   */
  huntMemory?: HuntMemory;
  log?: (msg: string) => void;
}

/**
 * Full per-finding tuple for corpus persistence (see `@pwnkit/benchmark`'s
 * `hunt-corpus.ts`) — never flattened to titles-only. One row per raw finding
 * the finders surfaced, carrying its provenance (site/model/attempt) plus
 * whatever gates it actually passed through.
 */
export interface HuntFindingRecord {
  /** The candidate path (site) this finding was surfaced at. */
  candidatePath: string;
  /** The finder model that produced it (undefined → provider default). */
  model?: string;
  /** Which attempt (0-indexed) at this (candidate, model) pair produced it. */
  attempt: number;
  /** The full finding, including `evidence.request/response/analysis`. */
  finding: Finding;
  /** Set only when its (candidate, model) group had >1 finding and was judged. */
  judgeScore?: number;
  judgeReason?: string;
  /** Set only for findings that actually ran through `opts.verify`. */
  skepticConfirmed?: boolean;
  skepticReason?: string;
  /** True when the novelty gate ruled this (confirmed) finding a duplicate. */
  duplicate: boolean;
}

export interface HuntScanResult {
  /** Every candidate finding the finders surfaced. */
  findings: Finding[];
  /** Findings that passed the skeptic+prover gate (real, novel, reachable). */
  confirmed: Finding[];
  /**
   * Confirmed findings the novelty gate ruled DUPLICATE of an on-list upstream
   * fix. Empty unless `opts.novelty` is set. These are dropped from `confirmed`.
   */
  duplicates: Array<{ finding: Finding; novelty: LoreNoveltyResult }>;
  /** How many (candidate × model × attempt) finder runs executed. */
  scanned: number;
  /**
   * Finder-fanout health (see HUNT_FINDER_TIMEOUT_MS / HUNT_FINDER_MAX_RETRIES):
   * how many of the `scanned` finder runs actually finished vs were ABANDONED
   * for exceeding the hard per-finder timeout vs gave up after exhausting the
   * transient-error retry budget. `finderCompleted + finderTimedOut +
   * finderErrored === scanned`. Backend health at a glance instead of a
   * silent stall.
   */
  finderCompleted: number;
  finderTimedOut: number;
  finderErrored: number;
  warnings: string[];
  /** The full per-finding tuple for every raw finding — see {@link HuntFindingRecord}. */
  records: HuntFindingRecord[];
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

// ── Finder-fanout resilience (env-gated) ─────────────────────────────────────
//
// Observed on bench repeatedly: the ChatGPT/Codex backend can HANG on a
// finder (`agenticScan`) call — 0% CPU, no error, no completion. Before this,
// that pool slot never freed and the ENTIRE sweep stalled forever (every bench
// hunt lost this way). Two independent guards, scoped to the finder fan-out
// only — never the skeptic/oracle gate (`opts.verify` is untouched):
//
//   1. HUNT_FINDER_TIMEOUT_MS — a hard wall-clock cap per finder call.
//      `agenticScan` has no cancellation signal in its option surface, so on
//      expiry the call is ABANDONED (not awaited further) rather than
//      cancelled — the pool slot frees immediately and the candidate is
//      recorded `timed-out`. Default 240_000 (4 min) is ON by default: the
//      old effectively-infinite wait was the bug, not a feature. Set very
//      high (or a non-positive/non-numeric value) to approximate the old
//      "wait forever" behavior.
//   2. HUNT_FINDER_MAX_RETRIES — bounded retries when the finder call
//      REJECTS with a transient-looking error (fetch failed / 429 / 5xx /
//      timeout-ish). Backoff between attempts; after the budget is spent the
//      candidate is recorded `errored` and skipped. Never infinite — we've
//      also seen retry-storms on this backend. Timeouts (case 1) are never
//      retried here — a hang isn't a "try again" situation.
const DEFAULT_HUNT_FINDER_TIMEOUT_MS = 240_000;
const DEFAULT_HUNT_FINDER_MAX_RETRIES = 2;

function huntFinderTimeoutMs(): number {
  const raw = process.env.HUNT_FINDER_TIMEOUT_MS;
  if (!raw) return DEFAULT_HUNT_FINDER_TIMEOUT_MS;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_HUNT_FINDER_TIMEOUT_MS;
}

function huntFinderMaxRetries(): number {
  const raw = process.env.HUNT_FINDER_MAX_RETRIES;
  if (raw === undefined || raw === "") return DEFAULT_HUNT_FINDER_MAX_RETRIES;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : DEFAULT_HUNT_FINDER_MAX_RETRIES;
}

// Mirrors the transient-LLM-error heuristic in agent/native-loop.ts (429/529/5xx,
// "overloaded", rate-limit language, connection resets) plus the fetch/timeout
// phrasing this stage actually observed on bench ("fetch failed", "timed out").
const TRANSIENT_FINDER_ERROR_RE =
  /\b(429|502|503|504|529)\b|overloaded|rate.?limit|temporarily|too many requests|time(d)?.?out|ETIMEDOUT|ECONNRESET|econnreset|fetch failed|throttl/i;

function isTransientFinderError(e: unknown): boolean {
  return TRANSIENT_FINDER_ERROR_RE.test(String(e).slice(0, 300));
}

/** Outcome of one finder (candidate × model × attempt) invocation. */
type FinderStatus = "completed" | "timed-out" | "errored";

type RaceOutcome<T> = { hit: "value"; value: T } | { hit: "timeout" } | { hit: "error"; error: unknown };

/** Race `promise` against a `ms` timer. Never rejects — resolves to a tagged outcome. */
function raceTimeout<T>(promise: Promise<T>, ms: number): Promise<RaceOutcome<T>> {
  return new Promise((resolve) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ hit: "timeout" });
    }, ms);
    // Attached synchronously, before the timer can fire — so even when we've
    // already resolved via timeout, this handler still runs later (keeping
    // the abandoned call's rejection from becoming an unhandled rejection).
    promise.then(
      (value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ hit: "value", value });
      },
      (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve({ hit: "error", error });
      },
    );
  });
}

/**
 * Run one finder attempt with a hard timeout + bounded transient-error
 * retries. `attemptFn` is called fresh on each retry (a brand-new
 * `agenticScan` call, its own dbPath). A hung call (timeout) is ABANDONED and
 * returned immediately as `timed-out` — never retried. A rejected call is
 * retried up to `maxRetries` times ONLY when it looks transient; otherwise
 * (or once the retry budget is spent) it's returned as `errored`.
 */
async function runFinderResilient<T>(
  attemptFn: () => Promise<T>,
  opts: { timeoutMs: number; maxRetries: number },
): Promise<{ status: FinderStatus; value?: T; error?: unknown }> {
  let lastError: unknown;
  for (let attempt = 0; ; attempt++) {
    const outcome = await raceTimeout(attemptFn(), opts.timeoutMs);
    if (outcome.hit === "value") return { status: "completed", value: outcome.value };
    if (outcome.hit === "timeout") return { status: "timed-out" };
    lastError = outcome.error;
    if (attempt < opts.maxRetries && isTransientFinderError(outcome.error)) {
      const backoffMs = Math.min(10_000, 500 * 2 ** attempt);
      await new Promise((r) => setTimeout(r, backoffMs));
      continue;
    }
    return { status: "errored", error: lastError };
  }
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
  /**
   * OPTIONAL learned-negatives context (`PWNKIT_HUNT_NEGATIVES=1`, see
   * hunt-negatives.ts). When a finding matches a known-refuted shape closely
   * enough, its prior refute reason is appended to the skeptic prompt as a
   * NOTE — it never auto-rejects; the skeptic call below still runs and
   * still decides.
   */
  negatives?: readonly KnownNegative[];
}): HuntVerifier {
  return async (finding, candidate) => {
    let hint =
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
    // Learned negatives (PWNKIT_HUNT_NEGATIVES=1): attach a prior refute
    // reason as CONTEXT when this shape was already refuted before — a
    // label the skeptic reads, never an auto-rejection. The skeptic call
    // below is unchanged either way: it still runs, still decides.
    if (huntNegativesEnabled() && opts.negatives && opts.negatives.length > 0) {
      const match = matchNegative(finding, opts.negatives);
      if (match) hint += `\n\n${negativeContext(match)}`;
    }
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

/** Group key for best-of-N judging: per (candidate site, model) — NOT per candidate alone, so
 *  model-diversity fan-out (models.length > 1) with the default attemptsPerCandidate=1 never
 *  produces a >1-length group and stays byte-for-byte identical to pre-best-of-N behavior. */
function siteGroupKey(candidatePath: string, model: string | undefined): string {
  return `${candidatePath} ${model ?? ""}`;
}

export async function runHuntScan(opts: HuntScanOptions): Promise<HuntScanResult> {
  const log = opts.log ?? (() => {});
  const models = opts.models && opts.models.length > 0 ? opts.models : [undefined as unknown as string];
  const concurrency = opts.concurrency ?? 8;
  const depth = opts.depth ?? "quick";
  const judgeTopK = Math.max(1, opts.judgeTopK ?? 1);
  const judgeCandidates = opts.judgeCandidates ?? judgeHuntCandidatesWithLlm;
  const warnings: string[] = [];

  // Memory-flywheel priming (PWNKIT_HUNT_FLYWHEEL=1, hunt-flywheel.ts): OFF by
  // default (`priming` stays `null`, every use below is a no-op and the run
  // is byte-identical to before this existed). When on and a brief is given,
  // priming ONLY (a) adjusts the attempt-budget cost-router below and (b)
  // reorders the best-of-N judge ranking further down — `opts.verify` (the
  // skeptic+prover gate, the sole adjudicator) never receives it.
  let priming: HuntPriming | null = null;
  if (huntFlywheelEnabled() && opts.brief) {
    const memory = opts.huntMemory ?? new HuntMemory();
    priming = memory.prime(opts.brief);
    log(
      `[hunt] flywheel: ${priming.active ? `primed (top=${priming.topScore.toFixed(2)})` : "no similar memory"} — cost_route=${priming.costRoute}`,
    );
  }

  let attemptsPerCandidate = Math.max(1, opts.attemptsPerCandidate ?? 1);
  if (priming && priming.costRoute === "cheap" && attemptsPerCandidate > 1) {
    warnings.push(
      `hunt: flywheel cost-router saw no similar memory for this brief — capping attemptsPerCandidate to 1 (was ${attemptsPerCandidate})`,
    );
    attemptsPerCandidate = 1;
  }

  // (candidate × model × attempt) finder runs — the parallel coverage sweep.
  // attemptsPerCandidate=1 (default) reproduces the original candidate × model
  // fan-out exactly.
  const runs: Array<{ candidate: HuntCandidate; model?: string; attempt: number }> = [];
  for (const candidate of opts.candidates)
    for (const model of models)
      for (let attempt = 0; attempt < attemptsPerCandidate; attempt++) runs.push({ candidate, model, attempt });

  log(
    `[hunt] ${opts.candidates.length} candidate(s) × ${models.length} model(s) × ${attemptsPerCandidate} attempt(s) ` +
      `= ${runs.length} finder run(s), ${concurrency}-wide`,
  );

  const finderTimeoutMs = huntFinderTimeoutMs();
  const finderMaxRetries = huntFinderMaxRetries();

  const reports = await pool(runs, concurrency, async (run) => {
    const attemptOnce = async () => {
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
        return await agenticScan({ config, dbPath, challengeHint: huntHint(opts.brief, run.candidate) });
      } finally {
        cleanupHuntDb(dbPath);
      }
    };
    const outcome = await runFinderResilient(attemptOnce, { timeoutMs: finderTimeoutMs, maxRetries: finderMaxRetries });
    if (outcome.status === "timed-out") {
      warnings.push(`hunt: finder timed out on ${run.candidate.path} after ${finderTimeoutMs}ms — abandoned, skipping`);
    } else if (outcome.status === "errored") {
      warnings.push(`hunt: finder failed on ${run.candidate.path}: ${String(outcome.error).slice(0, 120)}`);
    }
    return {
      candidate: run.candidate,
      model: run.model,
      attempt: run.attempt,
      status: outcome.status,
      findings: outcome.status === "completed" ? (outcome.value?.findings ?? []) : ([] as Finding[]),
    };
  });

  let finderCompleted = 0;
  let finderTimedOut = 0;
  let finderErrored = 0;
  for (const r of reports) {
    if (!r) { finderErrored++; continue; }
    if (r.status === "completed") finderCompleted++;
    else if (r.status === "timed-out") finderTimedOut++;
    else finderErrored++;
  }
  log(
    `[hunt] finder fan-out health: ${finderCompleted} completed, ${finderTimedOut} timed-out, ${finderErrored} errored ` +
      `(of ${runs.length})`,
  );

  const all: Array<{ finding: Finding; candidate: HuntCandidate; model?: string; attempt: number }> = [];
  for (const r of reports)
    if (r) for (const finding of r.findings) all.push({ finding, candidate: r.candidate, model: r.model, attempt: r.attempt });
  log(`[hunt] finders surfaced ${all.length} candidate finding(s)`);

  // OPTIONAL second-audit refinement: DEEPEN each finding's candidate (root cause
  // / fix-bypass) BEFORE grouping/judging/verifying. Runs in parallel; a refiner
  // failure leaves the original candidate (never drops the finding). Refining
  // `all` up front means the deepened candidate propagates into `records`, the
  // best-of-N judge groups, and `toVerify` — deepen, then judge, then verify.
  if (opts.refine && all.length > 0) {
    const refined = await pool(all, concurrency, async (entry) => {
      try {
        return await opts.refine!(entry.finding, entry.candidate);
      } catch (e) {
        warnings.push(`hunt: refine failed for ${entry.finding.title}: ${String(e).slice(0, 100)}`);
        return entry.candidate;
      }
    });
    for (let i = 0; i < all.length; i++) {
      const c = refined[i];
      if (c) all[i].candidate = c;
    }
    log(`[hunt] second-audit refined ${all.length} candidate(s) before the gate`);
  }

  // The full per-finding tuple, keyed by finding.id — filled in as each gate runs.
  const records = new Map<string, HuntFindingRecord>(
    all.map((a) => [
      a.finding.id,
      { candidatePath: a.candidate.path, model: a.model, attempt: a.attempt, finding: a.finding, duplicate: false },
    ]),
  );

  // Best-of-N judge: group raw findings by (candidate, model). A group with >1
  // finding means attemptsPerCandidate>1 surfaced more than one candidate at
  // that site — judge them and only the top-judgeTopK reach `verify`, so
  // skeptic call-count stays ~flat while the judge input pool is N× wider.
  // Groups of exactly 1 (the default) skip the judge entirely — unmodified.
  const groups = new Map<string, typeof all>();
  for (const item of all) {
    const key = siteGroupKey(item.candidate.path, item.model);
    const g = groups.get(key);
    if (g) g.push(item);
    else groups.set(key, [item]);
  }

  const toVerify: Array<{ finding: Finding; candidate: HuntCandidate }> = [];
  for (const group of groups.values()) {
    if (group.length <= 1) {
      toVerify.push(...group.map((g) => ({ finding: g.finding, candidate: g.candidate })));
      continue;
    }
    if (!opts.brief) {
      // No bug-class/pattern to judge against — keep the first judgeTopK by attempt order.
      warnings.push(
        `hunt: ${group.length} attempts at ${group[0].candidate.path} but no brief to judge against; keeping first ${judgeTopK}`,
      );
      toVerify.push(...group.slice(0, judgeTopK).map((g) => ({ finding: g.finding, candidate: g.candidate })));
      continue;
    }
    let scores: Map<string, { score: number; reason: string }>;
    try {
      scores = await judgeCandidates(opts.brief, group.map((g) => g.finding), {
        ...(opts.judgeModel ? { model: opts.judgeModel } : {}),
        runtime: opts.runtime,
      });
    } catch (e) {
      warnings.push(`hunt: judge failed for ${group[0].candidate.path}: ${String(e).slice(0, 120)}`);
      scores = new Map();
    }
    for (const item of group) {
      const s = scores.get(item.finding.id);
      const record = records.get(item.finding.id);
      if (s && record) {
        record.judgeScore = s.score;
        record.judgeReason = s.reason;
      }
    }
    // Ordering only: `priming.rankBonus` (when active) nudges which findings
    // reach `verify` first/at all under `judgeTopK`; it is never itself
    // passed to `verify` below, and when `priming` is `null` (flag off, or no
    // similar memory) `primedOrderKey` reduces to the plain judge score, so
    // this is byte-identical to the pre-flywheel comparator in that case.
    const ranked = [...group].sort((a, b) => {
      const rawA = scores.get(a.finding.id)?.score ?? 0;
      const rawB = scores.get(b.finding.id)?.score ?? 0;
      const keyA = priming ? primedOrderKey(rawA, priming, a.finding) : rawA;
      const keyB = priming ? primedOrderKey(rawB, priming, b.finding) : rawB;
      return keyB - keyA || a.attempt - b.attempt;
    });
    toVerify.push(...ranked.slice(0, judgeTopK).map((g) => ({ finding: g.finding, candidate: g.candidate })));
  }

  // Skeptic + prover gate (parallel). No verifier → everything stays unconfirmed.
  let confirmed: Finding[] = [];
  if (opts.verify && toVerify.length > 0) {
    const verdicts = await pool(toVerify, concurrency, async ({ finding, candidate }) => {
      try {
        const v = await opts.verify!(finding, candidate);
        const record = records.get(finding.id);
        if (record) {
          record.skepticConfirmed = v.confirmed;
          record.skepticReason = v.reason;
        }
        return v.confirmed ? finding : null;
      } catch (e) {
        warnings.push(`hunt: verify failed for ${finding.title}: ${String(e).slice(0, 100)}`);
        return null;
      }
    });
    confirmed = verdicts.filter((f): f is Finding => f != null);
    log(`[hunt] ${confirmed.length}/${toVerify.length} finding(s) confirmed by the skeptic+prover gate`);
  }

  // OPTIONAL novelty gate: drop confirmed findings that duplicate an on-list
  // upstream fix (lore mirror). Runs only when opts.novelty is provided.
  const duplicates: Array<{ finding: Finding; novelty: LoreNoveltyResult }> = [];
  if (opts.novelty && confirmed.length > 0) {
    const queryFor = opts.novelty.queryFor ?? ((f: Finding) => findingToQuery(f));
    const novel: Finding[] = [];
    for (const finding of confirmed) {
      try {
        const result = await checkNovelty(queryFor(finding), { ...opts.novelty, log });
        if (result.novel) {
          novel.push(finding);
        } else {
          duplicates.push({ finding, novelty: result });
          const record = records.get(finding.id);
          if (record) record.duplicate = true;
          log(`[hunt] novelty: DROP "${finding.title}" — duplicate of ${result.duplicates.map((d) => d.messageId).join(", ")}`);
        }
      } catch (e) {
        // A novelty-gate failure must not silently drop a real finding: keep it.
        warnings.push(`hunt: novelty check failed for ${finding.title}: ${String(e).slice(0, 100)}`);
        novel.push(finding);
      }
    }
    confirmed = novel;
    log(`[hunt] ${confirmed.length} novel, ${duplicates.length} duplicate after novelty gate`);
  }

  return {
    findings: all.map((a) => a.finding),
    confirmed,
    duplicates,
    scanned: runs.length,
    finderCompleted,
    finderTimedOut,
    finderErrored,
    warnings,
    records: [...records.values()],
  };
}
