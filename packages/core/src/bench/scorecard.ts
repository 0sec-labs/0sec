/**
 * Bench scorecard — aggregates per-case verdicts into a scan-level,
 * third-party-defensible capability/FP number, and a CI regression gate
 * (0sec#556).
 *
 * This is the missing piece the issue calls out: we already have strong
 * per-finding oracles, but nothing that rolls a target/corpus up to a single
 * scan-level pass@k metric plus a false-positive rate measured against
 * known-negatives, plus cost-per-success. The scorecard is plain JSON so CI
 * (and the marketing/compliance claim-gate) can consume it directly.
 *
 * Determinism: `aggregateScorecard` is pure. `generatedAt` is only stamped
 * when a `clock` is supplied, so unit tests get a byte-stable object.
 */

import type { RunSuiteResult, BenchCaseResult } from "./runner.js";

// ── Wilson score interval (inlined) ───────────────────────────────────
//
// `packages/benchmark/wilson.ts` already implements this, but that package
// DEPENDS on @0sec/core, so core can't import it back without a cycle.
// The math is tiny and stable; we inline the 95% form here.

const Z_95 = 1.959963984540054;

/** 95% Wilson score interval for `passes` successes in `attempts` trials. */
export function wilson95(passes: number, attempts: number): [number, number] {
  if (attempts <= 0) return [0, 1];
  const n = attempts;
  const p = passes / n;
  const z2 = Z_95 * Z_95;
  const denom = 1 + z2 / n;
  const center = (p + z2 / (2 * n)) / denom;
  const margin = (Z_95 * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  let lower = Math.max(0, center - margin);
  let upper = Math.min(1, center + margin);
  if (passes === 0) lower = 0;
  if (passes === attempts) upper = 1;
  return [lower, upper];
}

// ── Scorecard shape (STABLE — shared with downstream consumers) ───────
//
// This shape is a contract: the CI gate, the marketing/compliance claim
// surface, and sibling regression harnesses (e.g. specialist-routing,
// 0sec#557) all read it. Add fields additively; do not rename or remove.

export interface BenchScorecard {
  schemaVersion: 1;
  manifestId: string;
  /** ISO-8601, only when a clock is supplied. Omitted for deterministic runs. */
  generatedAt?: string;
  config: {
    passAtK: number;
    maxTurns: number;
    costCeilingUsd: number | null;
    ciSubset: boolean;
  };
  totals: {
    cases: number;
    positives: number;
    knownNegatives: number;
    verified: number;
    refuted: number;
    inconclusive: number;
  };
  /** verified positives / gradeable positives (positives that weren't inconclusive). */
  successRate: number;
  /** 95% Wilson CI on successRate. */
  successRateCI95: [number, number];
  /** Known-negatives that produced a `verified` (false exploit) verdict. */
  falsePositives: number;
  /** falsePositives / gradeable known-negatives. Target: 0. */
  fpRate: number;
  totalCostUsd: number;
  /** totalCostUsd / verified positives, or null when there were no successes. */
  costPerSuccessUsd: number | null;
  totalAttackTurns: number;
  /** Per-objective-type slice of the success rate. */
  byObjective: Record<string, { total: number; verified: number; successRate: number }>;
  cases: BenchCaseResult[];
}

export interface AggregateOptions {
  /** Supply to stamp `generatedAt`; omit for deterministic output. */
  clock?: () => string;
}

/**
 * Fold a suite run into a scorecard. Pure given a fixed (or absent) clock.
 *
 * "Gradeable" excludes inconclusive cases from the denominators so a flaky
 * provision/timeout neither inflates the success rate nor the FP rate — it's
 * reported in `totals.inconclusive` but doesn't poison the headline numbers.
 */
export function aggregateScorecard(
  run: RunSuiteResult,
  opts: AggregateOptions = {},
): BenchScorecard {
  const cases = run.cases;
  const positives = cases.filter((c) => !c.knownNegative);
  const knownNegatives = cases.filter((c) => c.knownNegative);

  const verified = cases.filter((c) => c.verdict === "verified").length;
  const refuted = cases.filter((c) => c.verdict === "refuted").length;
  const inconclusive = cases.filter((c) => c.verdict === "inconclusive").length;

  // Success rate: only over gradeable positives.
  const gradeablePositives = positives.filter((c) => c.verdict !== "inconclusive");
  const verifiedPositives = positives.filter((c) => c.verdict === "verified").length;
  const successRate =
    gradeablePositives.length === 0 ? 0 : verifiedPositives / gradeablePositives.length;
  const successRateCI95 = wilson95(verifiedPositives, gradeablePositives.length);

  // FP rate: over gradeable known-negatives.
  const gradeableNegatives = knownNegatives.filter((c) => c.verdict !== "inconclusive");
  const falsePositives = knownNegatives.filter((c) => c.falsePositive).length;
  const fpRate =
    gradeableNegatives.length === 0 ? 0 : falsePositives / gradeableNegatives.length;

  const totalCostUsd = cases.reduce((s, c) => s + c.costUsd, 0);
  const totalAttackTurns = cases.reduce((s, c) => s + c.attackTurns, 0);
  const costPerSuccessUsd =
    verifiedPositives === 0 ? null : totalCostUsd / verifiedPositives;

  // Per-objective slice (positives only — the capability axis).
  const byObjective: BenchScorecard["byObjective"] = {};
  for (const c of positives) {
    const slot = (byObjective[c.objective] ??= { total: 0, verified: 0, successRate: 0 });
    slot.total++;
    if (c.verdict === "verified") slot.verified++;
  }
  for (const slot of Object.values(byObjective)) {
    slot.successRate = slot.total === 0 ? 0 : slot.verified / slot.total;
  }

  return {
    schemaVersion: 1,
    manifestId: run.manifestId,
    ...(opts.clock ? { generatedAt: opts.clock() } : {}),
    config: {
      passAtK: run.passAtK,
      maxTurns: run.maxTurns,
      costCeilingUsd: run.costCeilingUsd,
      ciSubset: run.ciSubset,
    },
    totals: {
      cases: cases.length,
      positives: positives.length,
      knownNegatives: knownNegatives.length,
      verified,
      refuted,
      inconclusive,
    },
    successRate,
    successRateCI95,
    falsePositives,
    fpRate,
    totalCostUsd,
    costPerSuccessUsd,
    totalAttackTurns,
    byObjective,
    cases,
  };
}

// ── CI regression gate ────────────────────────────────────────────────

export interface GateThresholds {
  /** Fail if successRate < this. Default 0 (disabled). */
  minSuccessRate?: number;
  /** Fail if fpRate > this. Default 0 — known-negatives must stay clean. */
  maxFpRate?: number;
  /**
   * Fail if more than this fraction of cases were inconclusive (flaky
   * infra). Default 1 (disabled).
   */
  maxInconclusiveRate?: number;
}

export interface GateResult {
  passed: boolean;
  reasons: string[];
  thresholds: Required<GateThresholds>;
}

const DEFAULT_THRESHOLDS: Required<GateThresholds> = {
  minSuccessRate: 0,
  maxFpRate: 0,
  maxInconclusiveRate: 1,
};

/**
 * Evaluate a scorecard against CI thresholds. Pure. The CI runner calls this
 * on the fast subset's scorecard and exits non-zero when `passed` is false.
 */
export function evaluateGate(
  scorecard: BenchScorecard,
  thresholds: GateThresholds = {},
): GateResult {
  const t: Required<GateThresholds> = { ...DEFAULT_THRESHOLDS, ...thresholds };
  const reasons: string[] = [];

  if (scorecard.successRate < t.minSuccessRate) {
    reasons.push(
      `success rate ${(scorecard.successRate * 100).toFixed(1)}% < min ${(t.minSuccessRate * 100).toFixed(1)}%`,
    );
  }
  if (scorecard.fpRate > t.maxFpRate) {
    reasons.push(
      `false-positive rate ${(scorecard.fpRate * 100).toFixed(1)}% > max ${(t.maxFpRate * 100).toFixed(1)}%`,
    );
  }
  const inconclusiveRate =
    scorecard.totals.cases === 0
      ? 0
      : scorecard.totals.inconclusive / scorecard.totals.cases;
  if (inconclusiveRate > t.maxInconclusiveRate) {
    reasons.push(
      `inconclusive rate ${(inconclusiveRate * 100).toFixed(1)}% > max ${(t.maxInconclusiveRate * 100).toFixed(1)}%`,
    );
  }

  return { passed: reasons.length === 0, reasons, thresholds: t };
}

/** One-line human summary of a scorecard, for CI logs. */
export function formatScorecardSummary(s: BenchScorecard): string {
  const succ = `${(s.successRate * 100).toFixed(1)}%`;
  const ci = `[${(s.successRateCI95[0] * 100).toFixed(1)}–${(s.successRateCI95[1] * 100).toFixed(1)}%]`;
  const fp = `${(s.fpRate * 100).toFixed(1)}%`;
  const cps = s.costPerSuccessUsd == null ? "n/a" : `$${s.costPerSuccessUsd.toFixed(3)}`;
  return (
    `${s.manifestId}: success ${succ} ${ci} ` +
    `(${s.totals.verified}✓/${s.totals.refuted}✗/${s.totals.inconclusive}?) ` +
    `fp ${fp} (${s.falsePositives}/${s.totals.knownNegatives}) ` +
    `cost/success ${cps} turns ${s.totalAttackTurns}`
  );
}
