/**
 * Learned negatives — a known-refuted-shape memory for the hunt skeptic gate.
 *
 * `makeSkepticVerifier` (hunt-scan.ts) already re-reads a claimed finding and
 * tries hard to refute it. What it doesn't have is memory: if the SAME shape
 * (a debug-gated driver "bug" that's dead code, an already-CVE'd path) was
 * refuted last run, this run's skeptic re-derives that from scratch every
 * time. This module derives a `known-negatives` set from the hunt-variant
 * corpus (`@pwnkit/benchmark`'s `hunt-variant-v1.jsonl`, read by PATH — core
 * must not depend on `@pwnkit/benchmark`) — rows where the skeptic+prover gate
 * already returned `skepticConfirmed === false` — and, when a new finding
 * matches one closely enough, attaches that prior reason as CONTEXT to the
 * skeptic's prompt.
 *
 * Mirrors 0verse's `oracle.suspected_known()` discipline (labels, never
 * auto-dismisses): a match is a NOTE the skeptic reads, not a rejection. The
 * skeptic call still runs, still decides, and can still confirm a finding
 * that matches a known-negative shape if a new distinguishing fact overrides
 * it. This module never returns a verdict and never drops a finding on its
 * own — see `matchNegative`'s docstring.
 *
 * Reuses `hunt-flywheel.ts`'s token vocabulary (`classTokens` / `jaccard` /
 * `memoryTokens` / `loadHuntCorpusRows`) so a "known-negative shape" and a
 * "primed memory shape" are scored by the exact same join key — one
 * similarity vocabulary for the whole flywheel + learned-negatives pair, not
 * two independently-drifting ones.
 */

import type { Finding } from "@pwnkit/shared";
import { findingTokens, jaccard, loadHuntCorpusRows, memoryTokens, type HuntCorpusRow } from "./hunt-flywheel.js";
import {
  disprovenHuntClaims,
  loadHuntLedger,
  type ResolvedHuntClaim,
} from "./hunt-evidence-ledger.js";

/**
 * Default ON. Unlike `huntFlywheelEnabled()` — which reorders the verify queue
 * and therefore changes WHICH findings get gated — this flag only appends at
 * most one paragraph of prior-refute context to a skeptic prompt that was going
 * to run anyway. It costs no extra LLM call, and it is INERT unless a caller
 * actually supplies a corpus of known negatives (`opts.negatives` /
 * {@link loadKnownNegativesFromEnv}), so the default-ON blast radius on a
 * deployment with no corpus is exactly zero. Set `PWNKIT_HUNT_NEGATIVES=0` to
 * pin the old behaviour for an ablation.
 *
 * The residual risk is ANCHORING — a skeptic told "this shape was refuted
 * before" rubber-stamping the refutation of a genuinely new bug. Three things
 * bound it: the context is explicitly labelled as overridable (see
 * {@link negativeContext}), only the single BEST match is ever attached, and the
 * prior reason is truncated ({@link MAX_NEGATIVE_REASON_CHARS}) so it can never
 * dominate the prompt.
 */
export function huntNegativesEnabled(): boolean {
  const raw = process.env.PWNKIT_HUNT_NEGATIVES;
  // Unset → ON. Explicitly empty/0/false/no → OFF (matches the `env()` helper
  // convention in agent/features.ts, where an unset var takes the default).
  if (raw === undefined) return true;
  return !["", "0", "false", "no"].includes(raw.toLowerCase());
}

/** A shape must clear this Jaccard floor to attach negative context — the same order-of-magnitude bar as the flywheel's `PRIME_MIN`. */
export const NEGATIVE_MIN = 0.18;

/**
 * Hard cap on the derived negatives set. `matchNegative` is O(negatives) token
 * jaccard per finding, run once per finding per verify lens, so an unbounded
 * corpus turns the gate's cheap labelling step into a per-finding hot loop as
 * the corpus grows over months of hunts. The MOST RECENT rows are kept (the
 * corpus is append-only, so the tail is the freshest refute evidence and the
 * one most likely to describe a shape this run will re-derive).
 */
export const MAX_KNOWN_NEGATIVES = 500;

/**
 * Hard cap on how much of a prior refute reason is quoted into the skeptic
 * prompt. Corpus reasons are free text written by an earlier skeptic and have
 * no length bound; a multi-kilobyte one would both blow up the prompt and drown
 * the finding under discussion.
 */
export const MAX_NEGATIVE_REASON_CHARS = 400;

export interface KnownNegative {
  key: string;
  classTokens: ReadonlySet<string>;
  sinkTokens: ReadonlySet<string>;
  /** The skeptic's prior refute reason, verbatim (the actual evidence, never fabricated). */
  reason: string;
  candidatePath: string;
  provenance: string;
}

/**
 * Derive the known-negatives set from a hunt-variant corpus: rows the
 * skeptic+prover gate already refuted (`skepticConfirmed === false`) — e.g. a
 * debug-gated driver "bug" that's dead code on the target, or a path already
 * fixed upstream. Best-effort: a missing/empty/unparseable corpus is a
 * no-op, same discipline as `HuntMemory.loadCorpus`.
 *
 * Bounded to the most recent {@link MAX_KNOWN_NEGATIVES} rows — see that
 * constant for why an unbounded set is a per-finding cost.
 */
export function loadKnownNegatives(corpusPath: string): KnownNegative[] {
  const rows = loadHuntCorpusRows(corpusPath);
  const negatives: KnownNegative[] = [];
  for (const row of rows) {
    if (row.skepticConfirmed !== false) continue;
    negatives.push(negativeFromRow(row));
  }
  return negatives.length > MAX_KNOWN_NEGATIVES ? negatives.slice(-MAX_KNOWN_NEGATIVES) : negatives;
}

/**
 * The known-negatives set for the ambient run, or `[]` when no corpus is
 * configured.
 *
 * `HUNT_CORPUS_PATH` is the same env var `@pwnkit/benchmark`'s
 * `resolveHuntCorpusPath()` reads, so a bench sweep and a CLI hunt share one
 * corpus without core taking a dependency on the benchmark package (see this
 * module's header). There is deliberately NO fallback default path: the
 * package-relative default lives inside `@pwnkit/benchmark` and guessing at it
 * from here would silently feed a hunt refute-context it never asked for. Unset
 * env → empty set → the negatives feature is inert, which is exactly the
 * default-ON contract in {@link huntNegativesEnabled}.
 */
export function loadKnownNegativesFromEnv(): KnownNegative[] {
  const path = process.env.HUNT_CORPUS_PATH;
  if (!path || !path.trim()) return [];
  return loadKnownNegatives(path.trim());
}

function negativeFromRow(row: HuntCorpusRow): KnownNegative {
  const text = `${row.finding?.title ?? ""} ${row.finding?.description ?? ""} ${row.finding?.evidence?.analysis ?? ""}`;
  const { classToks, sinkToks } = memoryTokens(row.bugClass, row.pattern, text);
  return {
    key: `${row.candidatePath ?? ""}:${row.bugClass ?? ""}`,
    classTokens: classToks,
    sinkTokens: sinkToks,
    reason: row.skepticReason ?? "refuted by the skeptic gate",
    candidatePath: row.candidatePath ?? "",
    provenance: `record:${row.candidatePath ?? ""} model=${row.model ?? "default"}`,
  };
}

/**
 * Known negatives derived from a LIVE hunt evidence ledger
 * (`hunt-evidence-ledger.ts`) rather than from the end-of-run corpus.
 *
 * Same output type, same {@link matchNegative} / {@link negativeContext} path,
 * same anchoring bounds — the only thing that changes is freshness. The corpus
 * source (`loadKnownNegatives`) can only ever describe hunts that have already
 * FINISHED, because `appendToCorpus` runs after `runHuntScan` returns. A ledger
 * is appended to as each verdict lands, so a shape a sibling worker killed two
 * minutes ago is visible to this skeptic now, and to a second hunt process on
 * the same campaign. That in-run window is where the re-walked dead ends
 * actually are.
 *
 * The refute reason quoted into the prompt is built from the claim's
 * OBSERVATIONS only. Assumption-stance evidence is deliberately dropped here:
 * anchoring a skeptic on another worker's inference is exactly the failure this
 * module's header warns about, and the ledger's terminal-status rule already
 * guarantees a `disproven` claim carries at least one observation. Conflicted
 * claims never reach this function ({@link disprovenHuntClaims} filters them),
 * so a shape two workers disagree about never suppresses a third.
 *
 * A missing/unreadable ledger yields `[]` — inert, exactly like an unset
 * corpus path.
 */
export function loadKnownNegativesFromLedger(ledgerPath: string): KnownNegative[] {
  let claims: ResolvedHuntClaim[];
  try {
    claims = disprovenHuntClaims(loadHuntLedger(ledgerPath));
  } catch {
    return [];
  }
  const negatives = claims.map(negativeFromClaim);
  return negatives.length > MAX_KNOWN_NEGATIVES ? negatives.slice(-MAX_KNOWN_NEGATIVES) : negatives;
}

function negativeFromClaim(claim: ResolvedHuntClaim): KnownNegative {
  const observations = claim.observations.map((o) => `${o.statement} (${o.locator ?? o.source})`).join("; ");
  const { classToks, sinkToks } = memoryTokens(
    claim.shape.bugClass,
    undefined,
    `${claim.statement} ${observations}`,
  );
  // The worker that actually recorded the refutation, not the whole roster —
  // provenance has to name one accountable producer to be worth reading.
  const refuter = claim.records.filter((r) => r.status === "disproven").at(-1)?.worker ?? "unknown";
  return {
    key: `${claim.shape.path}:${claim.shape.bugClass}`,
    classTokens: classToks,
    sinkTokens: sinkToks,
    reason: observations || claim.statement,
    candidatePath: claim.shape.path,
    provenance: `ledger:${claim.claimKey.slice("sha256:".length, "sha256:".length + 12)} worker=${refuter}`,
  };
}

export interface NegativeMatch {
  negative: KnownNegative;
  score: number;
}

/**
 * Does `finding` match a known-refuted shape closely enough to attach its
 * prior reason as context? Returns the BEST match at or above `minScore`, or
 * `null` — never throws, never mutates `finding`, never signals a verdict.
 * The caller (`makeSkepticVerifier`) decides what to do with a match; this
 * function only labels.
 */
export function matchNegative(
  finding: Finding,
  negatives: readonly KnownNegative[],
  opts: { minScore?: number } = {},
): NegativeMatch | null {
  const minScore = opts.minScore ?? NEGATIVE_MIN;
  const { classToks, sinkToks } = findingTokens(finding);
  let best: NegativeMatch | null = null;
  for (const negative of negatives) {
    const cls = jaccard(classToks, negative.classTokens);
    const snk = jaccard(sinkToks, negative.sinkTokens);
    // A known-negative is about a specific SITE shape, not just a class
    // label, so sink overlap counts as much as class overlap here (unlike
    // the flywheel's class-dominant recall blend).
    const score = 0.5 * cls + 0.5 * snk;
    if (score >= minScore && (!best || score > best.score)) best = { negative, score };
  }
  return best;
}

/**
 * The context string attached to the skeptic prompt for a matched negative — a
 * label + an explicit override instruction, never an instruction to auto-drop.
 * The quoted prior reason is truncated to {@link MAX_NEGATIVE_REASON_CHARS} so
 * an unbounded corpus string can never dominate the prompt over the finding
 * actually under review.
 */
export function negativeContext(match: NegativeMatch): string {
  const reason =
    match.negative.reason.length > MAX_NEGATIVE_REASON_CHARS
      ? `${match.negative.reason.slice(0, MAX_NEGATIVE_REASON_CHARS)}…`
      : match.negative.reason;
  return (
    "KNOWN PRIOR REFUTE (learned negative): a finding with this shape was investigated before and refuted — " +
    `"${reason}" (${match.negative.provenance}). This is a LABEL, not an auto-dismissal: only ` +
    "surface this finding if you can point to a NEW distinguishing fact (a different sink, a changed guard, a " +
    "different reachable path) that overrides that prior refute."
  );
}
