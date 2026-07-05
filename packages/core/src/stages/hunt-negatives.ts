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

/** Default OFF — mirrors `huntFlywheelEnabled()` / `archetypeSweepEnabled()`'s opt-in discipline. */
export function huntNegativesEnabled(): boolean {
  return !["", "0", "false", "no"].includes((process.env.PWNKIT_HUNT_NEGATIVES ?? "").toLowerCase());
}

/** A shape must clear this Jaccard floor to attach negative context — the same order-of-magnitude bar as the flywheel's `PRIME_MIN`. */
export const NEGATIVE_MIN = 0.18;

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
 */
export function loadKnownNegatives(corpusPath: string): KnownNegative[] {
  const rows = loadHuntCorpusRows(corpusPath);
  const negatives: KnownNegative[] = [];
  for (const row of rows) {
    if (row.skepticConfirmed !== false) continue;
    negatives.push(negativeFromRow(row));
  }
  return negatives;
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

/** The context string attached to the skeptic prompt for a matched negative — a label + an explicit override instruction, never an instruction to auto-drop. */
export function negativeContext(match: NegativeMatch): string {
  return (
    "KNOWN PRIOR REFUTE (learned negative): a finding with this shape was investigated before and refuted — " +
    `"${match.negative.reason}" (${match.negative.provenance}). This is a LABEL, not an auto-dismissal: only ` +
    "surface this finding if you can point to a NEW distinguishing fact (a different sink, a changed guard, a " +
    "different reachable path) that overrides that prior refute."
  );
}
