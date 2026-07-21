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
import { randomUUID } from "node:crypto";
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
import { crossFamilyRefuteEnabled, selectCrossFamilyRefuter } from "./hunt-cross-family.js";
import { scoreGeometry } from "../kernel/geometry-score.js";

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

/**
 * A specialized FINDER LENS — a new fan-out axis exactly like a finder model.
 * Each lens re-hunts the SAME candidates with a focused adversarial angle
 * (e.g. "arithmetic/accounting" vs "access-control/reentrancy"), and findings
 * UNION across lenses (they do not compete — each lens keeps its own best-of-N
 * group). Omit / pass an empty array and the hunt runs today's single-brief loop
 * BYTE-IDENTICALLY (a single empty sentinel lens is used internally, appending
 * nothing to the finder hint and leaving the group key unchanged). See the
 * on-chain profiles' `*FinderLenses` exports for ready-made sets.
 */
export interface FinderLens {
  /** Stable lens id — becomes part of the best-of-N group key so lenses union. */
  id: string;
  /** The focused hunt angle, appended to the brief/candidate finder hint. */
  challengeHint: string;
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
  /**
   * OPTIONAL specialized-lens fan-out (the "depth method"): re-hunt every
   * candidate through each lens's focused angle, exactly like the `models`
   * axis. The run product becomes candidate × model × lens × attempt and
   * findings UNION across lenses (each lens keeps its own best-of-N group via
   * {@link siteGroupKey}). Absent / empty → today's single-brief loop, run for
   * run BYTE-IDENTICAL (a single empty sentinel lens appends nothing to the
   * finder hint and leaves the group key untouched).
   */
  lenses?: FinderLens[];
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
   * OPTIONAL PROVE stage (issue #1119): the exploitability-upgrade oracle,
   * composed as a THIRD, TERMINAL gate stage AFTER `opts.verify`. Because
   * {@link composeGate} short-circuits on the first stage that rejects, this only
   * runs on skeptic+prover-CONFIRMED findings; it never rejects a reproduced bug
   * — it stamps an `ExploitabilityVerdict` and gates the expensive
   * weaponize→root call (`runExploitScan`) on `upgraded || reachesPrivesc`. Build
   * it with `makeExploitabilityGate(deps)` from triage/exploitability-upgrade.ts.
   * Additive — omit it and the gate is exactly the skeptic+prover pair as before.
   * Requires `opts.verify` to be set (there is nothing to run the PROVE stage on
   * otherwise); ignored with a warning when `opts.verify` is absent.
   */
  exploitability?: HuntVerifier;
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
  /**
   * OPTIONAL exploitable-geometry ranking of the verify queue (LPE-hunt plan #0,
   * `PWNKIT_HUNT_GEOMETRY_RANK=1`; this option overrides the env). When on, the
   * findings about to hit the skeptic+prover gate are STABLE-sorted by
   * {@link scoreGeometry} — a sibling-type type-confusion + elastic-reclaimable
   * heap-corruption candidate sorts ahead of a pure read-OOB / DoS, so the
   * weaponizable bugs reach the expensive gate first and lead `confirmed`.
   * Additive — RE-RANKS only (nothing dropped); default OFF is byte-identical to
   * before this existed. Runs AFTER the best-of-N judge / flywheel ordering.
   */
  geometryRank?: boolean;
  /**
   * OPTIONAL incremental-persistence hook: invoked with each finding the moment
   * it passes the skeptic+prover gate (inside the verify pool), BEFORE the run
   * returns. Lets a long fan-out PERSIST confirmed leads as they land instead of
   * only in one burst after the whole sweep — so a sandbox/deadline kill
   * mid-sweep still leaves the leads found so far (an incomplete scan, not a
   * failed one with zero findings). A throwing hook never drops the finding (it
   * stays in `confirmed`); the error is recorded as a warning.
   *
   * NOTE on ordering: this fires when the gate CONFIRMS, which is BEFORE the
   * optional novelty gate ({@link HuntScanOptions.novelty}) can later reclassify
   * a confirmed finding as a DUPLICATE. A caller that both streams here AND uses
   * the novelty gate may therefore stream a finding that is later deduped. The
   * seedless `deep-review` command (its sole user today) runs no novelty gate,
   * so its streamed leads exactly equal `confirmed`.
   */
  onConfirmed?: (finding: Finding) => void | Promise<void>;
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

/**
 * One (file × lens) coverage cell that was NOT fully hunted because its finder
 * exceeded the wall-clock budget and was abandoned (see HUNT_FINDER_TIMEOUT_MS).
 * Emitted as a structured signal — not just a log line — so a future
 * self-improving coverage loop can consume "these cells were never fully
 * hunted" and re-hunt them. Any findings the abandoned finder streamed BEFORE
 * the hang are still returned in {@link HuntScanResult.findings} (tagged
 * partial/timed-out); this record is the orthogonal "coverage is incomplete"
 * signal, independent of whether partials were recovered.
 */
export interface CoverageGap {
  /** Candidate path (the file / dir / subsystem site the finder was hunting). */
  file: string;
  /** Specialized-lens id for this cell ("" for the default sentinel lens). */
  lensId: string;
  /** Why the cell is incomplete. Currently only the finder wall-clock timeout. */
  reason: "timeout";
  /** The per-finder wall-clock budget (ms) that was exceeded (see huntFinderTimeoutMs). */
  budgetMs: number;
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
  /** How many (candidate × model × lens × attempt) finder runs executed. */
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
  /**
   * (file × lens) cells whose finder was abandoned for exceeding the
   * per-finder wall-clock budget — see {@link CoverageGap}. Optional/additive:
   * absent on callers/fakes that predate it, empty when every finder finished
   * within budget. This is the substrate a future self-improving coverage loop
   * consumes to re-hunt the cells that were never fully explored. Distinct from
   * `findings`: partials the abandoned finder streamed before the hang are
   * still in `findings` (tagged partial/timed-out); this only says the cell's
   * coverage is INCOMPLETE.
   */
  incompleteCoverage?: CoverageGap[];
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

/** Outcome of one finder (candidate × model × lens × attempt) invocation. */
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

/** Provenance tag stamped on findings recovered from an abandoned (timed-out) finder. */
const PARTIAL_TIMEOUT_PROVENANCE = "partial/timed-out";

const FINDING_SEVERITIES: ReadonlySet<string> = new Set(["critical", "high", "medium", "low", "info"]);

/**
 * Reconstruct a {@link Finding} from a streamed `save_finding` event payload
 * captured while a finder was running, used ONLY to recover partial evidence
 * from a finder that HUNG and got abandoned at the timeout (its normalized
 * report never returns). agenticScan emits one `finding` event per save_finding
 * tool call as the finder works (agentic-scanner.ts onTurn handler), carrying
 * the raw tool arguments in `event.data`.
 *
 * The canonical args→Finding mapping lives in the tool executor
 * (agent/tools.ts `saveFinding`); we cannot reach it from here without the
 * finder completing, so this mirrors the structurally load-bearing subset so a
 * recovered lead enters the SAME verify gate as a completed finder's findings.
 * Deliberately conservative — some streamed calls are ones the executor would
 * have rejected (empty-PoC / fabricated-path), so we do NOT treat these as
 * ground truth: `status` stays "discovered" (verify is the sole adjudicator —
 * NEVER auto-confirmed) and `triageNote` records the partial/timed-out
 * provenance. Returns null when the payload lacks the minimum (a title) to be a
 * real lead.
 */
function partialFindingFromEvent(data: unknown): Finding | null {
  if (!data || typeof data !== "object") return null;
  const args = data as Record<string, unknown>;
  const title = typeof args.title === "string" && args.title.trim() ? args.title : undefined;
  if (!title) return null;
  const severity: Finding["severity"] =
    typeof args.severity === "string" && FINDING_SEVERITIES.has(args.severity)
      ? (args.severity as Finding["severity"])
      : "medium";
  return {
    id: randomUUID(),
    templateId: typeof args.template_id === "string" ? args.template_id : "hunt-partial",
    title,
    description: typeof args.description === "string" ? args.description : "",
    severity,
    // Mirrors the executor's permissive cast (agent/tools.ts): category is a
    // free-form label here, not switched on downstream. Default matches the
    // engine's generic bucket.
    category: (typeof args.category === "string" ? args.category : "other") as Finding["category"],
    status: "discovered",
    evidence: {
      request: typeof args.evidence_request === "string" ? args.evidence_request : "",
      response: typeof args.evidence_response === "string" ? args.evidence_response : "",
      analysis: typeof args.evidence_analysis === "string" ? args.evidence_analysis : undefined,
    },
    triageNote: `${PARTIAL_TIMEOUT_PROVENANCE}: finder hung before completion; evidence recovered from the pre-timeout stream`,
    timestamp: Date.now(),
  };
}

function huntHint(brief: HuntBrief | undefined, candidate: HuntCandidate, lensHint?: string): string {
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
  // Lens focus (the depth-method finder axis) is appended LAST so the
  // brief/candidate hint above is byte-identical to today when no lens is set
  // (the sentinel lens carries an empty challengeHint → nothing appended).
  if (lensHint) parts.push(lensHint);
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
  /**
   * OPTIONAL lens focus — a single specialized angle this refute pass should
   * concentrate on (used by {@link makeMultiLensVerifier} to turn one skeptic
   * into a per-lens quorum member). Appended to the adversarial hint; absent →
   * the skeptic prompt is byte-identical to before.
   */
  focus?: string;
  /**
   * OPTIONAL cross-family refuter (issue #661, `PWNKIT_HUNT_CROSS_FAMILY=1`).
   * When enabled AND a distinct second family is available, force this refute
   * pass onto a model of a DIFFERENT family than the finder so their errors
   * decorrelate before a finding is promoted. Defaults to
   * {@link crossFamilyRefuteEnabled}. OFF, or no distinct family available →
   * the configured `model` is used unchanged (byte-identical to today).
   */
  crossFamilyRefute?: boolean;
  /** Finder model/family the cross-family refuter must decorrelate from. */
  finderModel?: string;
  /** Alternate refuter models to pick a distinct family from, tried in order. */
  refuterCandidates?: readonly string[];
}): HuntVerifier {
  // Cross-family refuter selection is static (all inputs come from opts), so
  // resolve it ONCE. Passthrough when disabled / no distinct family → the config
  // model and reason strings below stay byte-identical to before this existed.
  const refuter = selectCrossFamilyRefuter({
    enabled: opts.crossFamilyRefute ?? crossFamilyRefuteEnabled(),
    ...(opts.finderModel ? { finderModel: opts.finderModel } : {}),
    ...(opts.model ? { refuterModel: opts.model } : {}),
    ...(opts.refuterCandidates ? { candidates: opts.refuterCandidates } : {}),
  });
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
      "Then, for source-level (non-kernel) findings, run these THREE checks — each names a false " +
      "positive this engine has confidently shipped before:\n" +
      "  4. LAYOUT / PARSE MISREAD (Aiken, Haskell, Plutus, Nix, Python — any whitespace- or " +
      "precedence-sensitive language): the most dangerous class. Re-derive the claimed 'missing check' " +
      "from the REAL file's indentation, columns, and operator precedence — never from a quoted snippet. " +
      "We have hallucinated a 0.9+ 'critical' by misreading `case ... of {...} && (d == outDatum)` as if " +
      "the `&&` bound only the last alternative, when layout ANDs it with the WHOLE case (so the datum " +
      "check WAS enforced). If the check is actually present once you parse the true layout, it is a " +
      "FALSE POSITIVE.\n" +
      "  5. BY-DESIGN / DEMO / CLI / EXAMPLE: before reporting an 'unauthenticated exposure', " +
      "'default credential', or 'arbitrary command/mint/spend', read the README / SECURITY.md / the " +
      "file's own header for intent — 'example', 'demo', 'not production-ready', 'testing only', " +
      "'trusted mode', `//// @hidden`/sample markers, or a contract where the behavior IS the tool's " +
      "purpose (a wallet CLI printing a mnemonic, a sandbox demo running commands). If the behavior is " +
      "the documented intent of a non-production / operator-run tool, it is a FALSE POSITIVE.\n" +
      "  6. NO TRUST BOUNDARY / KNOWN-CVE: if the only 'attacker-controlled' input is supplied by the " +
      "same principal who runs the code (a CLI's own argv, a build script's own flags, an SDK " +
      "self-injecting its config), no privilege is crossed — FALSE POSITIVE. Likewise, if the finding " +
      "merely restates an already-public CVE/GHSA n-day (e.g. lodash `_.template`, ImageTragick delegate " +
      "expansion, a pinned vulnerable dependency version), it is NOT a novel finding — do not report it.\n" +
      "Only report a finding if, after genuinely trying to refute it AND passing all applicable checks, you " +
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
    // Lens focus (multi-lens quorum member): concentrate this one refute pass
    // on a single angle. Absent → identical to the general skeptic prompt.
    if (opts.focus) {
      hint += `\n\nLENS FOCUS — concentrate this refute pass specifically on: ${opts.focus}`;
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
      ...(refuter.model ? { model: refuter.model } : {}),
    };
    const dbPath = freshHuntDb();
    try {
      const report = await agenticScan({ config, dbPath, challengeHint: hint });
      const survived = (report.findings ?? []).length > 0;
      // Only annotate when a cross-family refuter actually ran — the default
      // (same-family / disabled) reason strings stay byte-identical to today.
      const note = refuter.crossFamily
        ? ` (cross-family refuter: ${refuter.refuterFamily} vs finder ${refuter.finderFamily})`
        : "";
      return survived
        ? { confirmed: true, reason: `survived adversarial refute pass${note}` }
        : { confirmed: false, reason: `refuted: skeptic could not reproduce the claim from source${note}` };
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

/**
 * One VERIFY LENS — a focused adversarial refute pass for the multi-lens
 * quorum. Each lens re-runs the skeptic ({@link makeSkepticVerifier}) with a
 * lens-specific `focus`, so the same finding is challenged from several
 * independent angles (reachability, completeness, novelty, scope). See the
 * on-chain profiles' `*VerifyLenses` exports for ready-made sets.
 */
export interface VerifyLens {
  /** Stable lens id, surfaced in the quorum reason string. */
  id: string;
  /** The focused refute angle handed to the skeptic pass as its `focus`. */
  challengeHint: string;
}

export interface MultiLensVerifierOptions {
  /** Source tree the skeptic passes re-read. Required — every lens is a real refute pass. */
  sourceRoot: string;
  runtime: RuntimeMode;
  /** Optional skeptic model override (mirrors HUNT_SKEPTIC_MODEL). */
  model?: string;
  /** Optional learned-negatives context, forwarded to each skeptic pass. */
  negatives?: readonly KnownNegative[];
  /**
   * OPTIONAL cross-family refuter (issue #661), forwarded to each skeptic pass.
   * When enabled AND a distinct family is available, every lens refutes with a
   * DIFFERENT family than the finder. OFF / no distinct family → byte-identical.
   */
  crossFamilyRefute?: boolean;
  /** Finder model/family the cross-family refuter must decorrelate from. */
  finderModel?: string;
  /** Alternate refuter models to pick a distinct family from, tried in order. */
  refuterCandidates?: readonly string[];
  /**
   * Confirmation threshold: a finding is confirmed ONLY when 0 lenses refute it
   * AND at least `quorum` lenses survive. Default = majority `ceil(N/2)`.
   */
  quorum?: number;
  /**
   * Injectable per-lens pass factory (tests). Defaults to a focused
   * {@link makeSkepticVerifier}. Exposed so the quorum logic can be unit-tested
   * with fake passes and zero LLM calls.
   */
  makePass?: (lens: VerifyLens) => HuntVerifier;
}

/**
 * MULTI-LENS VERIFY QUORUM (the "depth method" verify side): run several
 * focused adversarial refute passes over ONE finding in parallel and require a
 * quorum of survivors with ZERO refutes. Confirmed iff
 * `refuted === 0 && survived >= quorum` (quorum default = majority
 * `ceil(lenses.length/2)`). Any single lens that REFUTES the finding fails it
 * outright (fail-closed); a lens that ERRORS counts as neither a survival nor a
 * refute, so it lowers the survivor count (also fail-closed). Plugs straight
 * into the existing `opts.verify` slot — it IS a {@link HuntVerifier}, so
 * `runHuntScan` needs no change.
 */
export function makeMultiLensVerifier(lenses: VerifyLens[], opts: MultiLensVerifierOptions): HuntVerifier {
  if (lenses.length === 0) throw new Error("makeMultiLensVerifier requires at least one verify lens");
  const quorum = Math.max(1, opts.quorum ?? Math.ceil(lenses.length / 2));
  const makePass =
    opts.makePass ??
    ((lens: VerifyLens) =>
      makeSkepticVerifier({
        sourceRoot: opts.sourceRoot,
        runtime: opts.runtime,
        ...(opts.model ? { model: opts.model } : {}),
        ...(opts.negatives ? { negatives: opts.negatives } : {}),
        ...(opts.crossFamilyRefute !== undefined ? { crossFamilyRefute: opts.crossFamilyRefute } : {}),
        ...(opts.finderModel ? { finderModel: opts.finderModel } : {}),
        ...(opts.refuterCandidates ? { refuterCandidates: opts.refuterCandidates } : {}),
        focus: lens.challengeHint,
      }));
  const passes = lenses.map((lens) => ({ lens, run: makePass(lens) }));
  return async (finding, candidate) => {
    const results = await Promise.all(
      passes.map(async ({ lens, run }) => {
        try {
          const v = await run(finding, candidate);
          return { lensId: lens.id, survived: v.confirmed, errored: false };
        } catch {
          // A pass that throws couldn't adjudicate — counts as neither a
          // survival nor a refute, so it just lowers the survivor count.
          return { lensId: lens.id, survived: false, errored: true };
        }
      }),
    );
    const refuted = results.filter((r) => !r.survived && !r.errored);
    const survived = results.filter((r) => r.survived);
    if (refuted.length > 0) {
      return {
        confirmed: false,
        reason: `multi-lens: refuted by ${refuted.map((r) => r.lensId).join(", ")} (${survived.length}/${lenses.length} survived, quorum ${quorum})`,
      };
    }
    if (survived.length >= quorum) {
      return {
        confirmed: true,
        reason: `multi-lens quorum met: ${survived.length}/${lenses.length} lenses survived, 0 refuted (quorum ${quorum})`,
      };
    }
    return {
      confirmed: false,
      reason: `multi-lens below quorum: ${survived.length}/${lenses.length} survived < ${quorum}, 0 refuted`,
    };
  };
}

/** Group key for best-of-N judging: per (ORIGINAL candidate site, model) — NOT per candidate
 *  alone, so model-diversity fan-out (models.length > 1) with the default attemptsPerCandidate=1
 *  never produces a >1-length group and stays byte-for-byte identical to pre-best-of-N behavior.
 *  Callers pass the pre-refine `originPath`, so grouping tracks which candidate PRODUCED the
 *  finding — two distinct findings the second-audit refiner deepens to the same path do NOT
 *  collapse into one group (which the no-brief `judgeTopK` truncation would then silently drop). */
function siteGroupKey(candidatePath: string, model: string | undefined, lensId?: string): string {
  // NUL separator preserved from the pre-lens key so the sentinel case is
  // byte-identical at runtime; the lens segment is appended ONLY for a real
  // lens, so each lens keeps its OWN best-of-N group and lens findings union
  // rather than truncate each other.
  const base = `${candidatePath}\0${model ?? ""}`;
  return lensId ? `${base} ${lensId}` : base;
}

export async function runHuntScan(opts: HuntScanOptions): Promise<HuntScanResult> {
  const log = opts.log ?? (() => {});
  const models = opts.models && opts.models.length > 0 ? opts.models : [undefined as unknown as string];
  const concurrency = opts.concurrency ?? 8;
  const depth = opts.depth ?? "quick";
  const judgeTopK = Math.max(1, opts.judgeTopK ?? 1);
  const judgeCandidates = opts.judgeCandidates ?? judgeHuntCandidatesWithLlm;
  const warnings: string[] = [];
  // Structured coverage-gap signal: (file × lens) cells abandoned at the
  // finder timeout. Fed back on the result as `incompleteCoverage` for a future
  // self-improving loop. `.push` from the concurrent pool below is safe — same
  // single-threaded, between-await mutation pattern as `warnings`.
  const coverageGaps: CoverageGap[] = [];

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

  // Specialized-lens fan-out axis (the "depth method"). Absent/empty → a single
  // EMPTY SENTINEL lens: its id is "" (siteGroupKey drops the segment) and its
  // challengeHint is "" (huntHint appends nothing), so the loop order, run
  // count, finder hint, and group keys below are all byte-identical to today.
  const lenses: FinderLens[] =
    opts.lenses && opts.lenses.length > 0 ? opts.lenses : [{ id: "", challengeHint: "" }];

  // (candidate × model × lens × attempt) finder runs — the parallel coverage
  // sweep. With the sentinel lens (default), the loop reduces to the original
  // candidate × model × attempt product, run for run.
  const runs: Array<{ candidate: HuntCandidate; model?: string; lens: FinderLens; attempt: number }> = [];
  for (const candidate of opts.candidates)
    for (const model of models)
      for (const lens of lenses)
        for (let attempt = 0; attempt < attemptsPerCandidate; attempt++) runs.push({ candidate, model, lens, attempt });

  const lensNote = opts.lenses && opts.lenses.length > 0 ? ` × ${lenses.length} lens(es)` : "";
  log(
    `[hunt] ${opts.candidates.length} candidate(s) × ${models.length} model(s)${lensNote} × ${attemptsPerCandidate} attempt(s) ` +
      `= ${runs.length} finder run(s), ${concurrency}-wide`,
  );

  const finderTimeoutMs = huntFinderTimeoutMs();
  const finderMaxRetries = huntFinderMaxRetries();

  const reports = await pool(runs, concurrency, async (run) => {
    // Partial-evidence capture. agenticScan streams a `finding` event per
    // save_finding tool call as the finder works. When the finder HANGS and is
    // abandoned at the timeout, its returned promise never resolves — but the
    // findings it already streamed are real leads we must NOT silently discard
    // (this is exactly how the epb method-authz lead was lost). We accumulate
    // them off the event stream so a timed-out cell surfaces its partials
    // instead of an empty array. Reset at the top of each attempt so only the
    // LAST attempt's partials survive a transient-error retry.
    let partials: Finding[] = [];
    const attemptOnce = async () => {
      partials = [];
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
        return await agenticScan({
          config,
          dbPath,
          challengeHint: huntHint(opts.brief, run.candidate, run.lens.challengeHint),
          onEvent: (event) => {
            if (event.type !== "finding") return;
            const partial = partialFindingFromEvent(event.data);
            if (partial) partials.push(partial);
          },
        });
      } finally {
        cleanupHuntDb(dbPath);
      }
    };
    const outcome = await runFinderResilient(attemptOnce, { timeoutMs: finderTimeoutMs, maxRetries: finderMaxRetries });
    let findings: Finding[];
    if (outcome.status === "completed") {
      findings = outcome.value?.findings ?? [];
    } else if (outcome.status === "timed-out") {
      // Recover whatever the finder streamed before it hung. Snapshot NOW — the
      // abandoned call may keep running, but we've captured the evidence
      // observed up to the budget. Each partial re-enters the SAME verify gate
      // (status stays "discovered" — never auto-confirmed). Also emit the
      // structured coverage-gap so a self-improving loop can re-hunt this cell.
      findings = partials;
      const recovered = findings.length > 0 ? ` — recovered ${findings.length} partial finding(s)` : "";
      warnings.push(
        `hunt: finder timed out on ${run.candidate.path} after ${finderTimeoutMs}ms — abandoned${recovered}`,
      );
      coverageGaps.push({ file: run.candidate.path, lensId: run.lens.id, reason: "timeout", budgetMs: finderTimeoutMs });
    } else {
      findings = [];
      warnings.push(`hunt: finder failed on ${run.candidate.path}: ${String(outcome.error).slice(0, 120)}`);
    }
    return {
      candidate: run.candidate,
      model: run.model,
      lensId: run.lens.id,
      attempt: run.attempt,
      status: outcome.status,
      findings,
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

  // `originPath` freezes the finder's ORIGINAL candidate site BEFORE the
  // second-audit refiner (below) can rewrite `candidate.path` to a deeper
  // root-cause path. The best-of-N judge groups on it (not the post-refine
  // path) so a group is always "the N attempts at ONE original site" — see
  // siteGroupKey. Without this, refine deepening two DISTINCT findings to the
  // SAME path collapses them into one group, and the no-brief truncation to
  // `judgeTopK` then silently drops the confirmed extra.
  const all: Array<{ finding: Finding; candidate: HuntCandidate; originPath: string; model?: string; lensId: string; attempt: number }> = [];
  for (const r of reports)
    if (r) for (const finding of r.findings) all.push({ finding, candidate: r.candidate, originPath: r.candidate.path, model: r.model, lensId: r.lensId, attempt: r.attempt });
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
    const key = siteGroupKey(item.originPath, item.model, item.lensId);
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

  // EXPLOITABLE-GEOMETRY RANK (LPE-hunt plan #0): re-order the verify queue by
  // exploitable geometry — a sibling-type type-confusion + elastic-reclaimable
  // heap-corruption candidate sorts ahead of a pure read-OOB / DoS. This only
  // RE-RANKS (stable; nothing dropped), so the highest-geometry findings reach
  // the expensive skeptic+prover gate first and lead the `confirmed` output.
  // Opt-in (default OFF → byte-identical): the option overrides the env flag.
  const geometryRank = opts.geometryRank ?? process.env.PWNKIT_HUNT_GEOMETRY_RANK === "1";
  if (geometryRank && toVerify.length > 1) {
    toVerify
      .map((v, i) => ({ v, i, score: scoreGeometry(v.finding).geometryScore }))
      .sort((a, b) => b.score - a.score || a.i - b.i)
      .forEach((x, rank) => (toVerify[rank] = x.v));
    log(`[hunt] geometry-ranked ${toVerify.length} finding(s) for the verify queue (type-confusion / elastic-reclaim first)`);
  }

  // Skeptic + prover gate (parallel). No verifier → everything stays unconfirmed.
  // PROVE stage (issue #1119): when set, the exploitability-upgrade oracle is
  // composed as a TERMINAL stage after the skeptic+prover pair — it runs only on
  // findings the earlier stages already confirmed (composeGate short-circuits),
  // stamps a verdict and gates weaponization. Additive: absent → unchanged.
  let verify = opts.verify;
  if (opts.exploitability) {
    if (opts.verify) {
      verify = composeGate(opts.verify, opts.exploitability);
      log(`[hunt] PROVE stage wired as the terminal gate (refine → judge → verify → exploitability)`);
    } else {
      warnings.push("hunt: opts.exploitability set but opts.verify is absent — PROVE stage skipped (nothing confirmed to prove)");
    }
  }

  let confirmed: Finding[] = [];
  if (verify && toVerify.length > 0) {
    const verifyFn = verify;
    const verdicts = await pool(toVerify, concurrency, async ({ finding, candidate }) => {
      try {
        const v = await verifyFn(finding, candidate);
        const record = records.get(finding.id);
        if (record) {
          record.skepticConfirmed = v.confirmed;
          record.skepticReason = v.reason;
        }
        // Incremental persistence: hand each confirmed finding to the caller
        // AS IT LANDS (see HuntScanOptions.onConfirmed) so a mid-sweep kill
        // still leaves the leads found so far. A throwing hook must not drop
        // the finding — record it as a warning and keep the confirmation.
        if (v.confirmed && opts.onConfirmed) {
          try {
            await opts.onConfirmed(finding);
          } catch (e) {
            warnings.push(`hunt: onConfirmed hook failed for ${finding.title}: ${String(e).slice(0, 100)}`);
          }
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
    incompleteCoverage: coverageGaps,
  };
}
