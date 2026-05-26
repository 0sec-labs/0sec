/**
 * Wilson score confidence interval for binomial proportions.
 *
 * The Wilson score interval is the right CI to use for "k successes out of
 * n trials" when n is small and/or the observed rate is near 0 or 1 —
 * which is exactly the regime we're in for n=10 statistical evaluation
 * against XBOW challenges where a per-attempt success rate may be 0, 10%,
 * or 100%.
 *
 * The normal-approximation ("Wald") interval has two well-known failure
 * modes in that regime: it produces [0, 0] when k=0 (implying zero
 * uncertainty about a rate we've barely measured), and it can extend
 * outside [0, 1] for rates near the boundaries. Wilson fixes both.
 *
 * Reference: Wilson, E.B. (1927). "Probable inference, the law of
 * succession, and statistical inference." JASA 22(158): 209–212.
 * Worked examples: https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval
 *
 * For `passes` successes in `attempts` trials at 95% confidence (z = 1.96):
 *
 *   p      = passes / attempts
 *   center = (p + z²/(2n)) / (1 + z²/n)
 *   margin = (z * sqrt(p(1-p)/n + z²/(4n²))) / (1 + z²/n)
 *   [lower, upper] = [center - margin, center + margin]
 *
 * This file is extracted from the xbow-runner so it can be unit-tested
 * independently of the runner's Docker / agent loop plumbing.
 */

export interface WilsonInterval {
  lower: number;
  upper: number;
}

/** 95% z-score, used by default throughout the harness. */
export const Z_95 = 1.959963984540054;

/**
 * Compute the Wilson score interval for a binomial proportion.
 *
 * @param passes   Number of successful trials (k)
 * @param attempts Total number of trials (n). Must be >= 0.
 * @param z        Optional z-score (default 1.96 for 95% CI).
 * @returns { lower, upper } clamped to [0, 1].
 */
export function wilsonInterval(
  passes: number,
  attempts: number,
  z: number = Z_95,
): WilsonInterval {
  if (!Number.isFinite(passes) || !Number.isFinite(attempts)) {
    throw new RangeError(`wilsonInterval: passes and attempts must be finite (got ${passes}, ${attempts})`);
  }
  if (attempts < 0 || passes < 0 || passes > attempts) {
    throw new RangeError(`wilsonInterval: require 0 <= passes <= attempts (got ${passes}/${attempts})`);
  }
  // Degenerate case: no trials at all. The interval is the entire [0, 1]
  // range, which correctly encodes "we have no information."
  if (attempts === 0) return { lower: 0, upper: 1 };

  const n = attempts;
  const p = passes / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const center = (p + z2 / (2 * n)) / denom;
  const margin = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;

  // When k=0 or k=n the analytic Wilson interval touches exactly 0 or 1,
  // but floating-point evaluation can land 1 ULP away. Snap back to the
  // exact boundary in those degenerate cases so consumers reading the
  // JSON don't see `0.9999999999999999` for a 10/10 cell.
  let lower = Math.max(0, center - margin);
  let upper = Math.min(1, center + margin);
  if (passes === 0) lower = 0;
  if (passes === attempts) upper = 1;
  return { lower, upper };
}

/** Tuple form `[lower, upper]` used in the JSON result schema. */
export function wilsonIntervalTuple(
  passes: number,
  attempts: number,
  z: number = Z_95,
): [number, number] {
  const { lower, upper } = wilsonInterval(passes, attempts, z);
  return [lower, upper];
}

/** Mean of a numeric array, or 0 for an empty array. */
export function mean(values: readonly number[]): number {
  if (values.length === 0) return 0;
  let sum = 0;
  for (const v of values) sum += v;
  return sum / values.length;
}

/**
 * Population standard deviation of a numeric array.
 *
 * We use the population form (divide by N, not N-1) because the N in the
 * n=10 harness is the actual population of attempts we ran, not a sample
 * drawn from a larger pool.
 */
export function stdDev(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const m = mean(values);
  let sumSq = 0;
  for (const v of values) {
    const d = v - m;
    sumSq += d * d;
  }
  return Math.sqrt(sumSq / values.length);
}

/**
 * One run inside a repeat cell.
 *
 * This is the minimal shape the aggregator needs; the xbow runner's
 * full result type extends it with challenge metadata.
 */
export interface RepeatRun {
  runIndex: number;
  passed: boolean;
  turns: number;
  cost: number;
  durationMs: number;
}

/**
 * Aggregation of N independent runs for a single (challenge, config) cell.
 *
 * Matches the JSON fields documented in the benchmark README:
 *   attempts, passes, successRate, successRateCI95,
 *   meanTurns, stdDevTurns, meanCostUsd, stdDevCostUsd, perRun.
 */
export interface RepeatAggregate {
  attempts: number;
  passes: number;
  successRate: number;
  successRateCI95: [number, number];
  meanTurns: number;
  stdDevTurns: number;
  meanCostUsd: number;
  stdDevCostUsd: number;
  meanDurationMs: number;
  stdDevDurationMs: number;
  perRun: RepeatRun[];
  costCeilingHit: boolean;
}

export interface AggregateOptions {
  /** If the sweep stopped early because of --repeat-cost-ceiling-usd. */
  costCeilingHit?: boolean;
}

/** Aggregate N independent runs into a RepeatAggregate summary. */
export function aggregateRuns(
  runs: readonly RepeatRun[],
  opts: AggregateOptions = {},
): RepeatAggregate {
  const attempts = runs.length;
  const passes = runs.filter((r) => r.passed).length;
  const successRate = attempts === 0 ? 0 : passes / attempts;
  const ci = wilsonIntervalTuple(passes, attempts);
  const turns = runs.map((r) => r.turns);
  const costs = runs.map((r) => r.cost);
  const durations = runs.map((r) => r.durationMs);
  return {
    attempts,
    passes,
    successRate,
    successRateCI95: ci,
    meanTurns: mean(turns),
    stdDevTurns: stdDev(turns),
    meanCostUsd: mean(costs),
    stdDevCostUsd: stdDev(costs),
    meanDurationMs: mean(durations),
    stdDevDurationMs: stdDev(durations),
    perRun: [...runs],
    costCeilingHit: opts.costCeilingHit ?? false,
  };
}
