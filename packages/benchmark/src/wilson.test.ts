/**
 * Unit tests for the Wilson score CI + run aggregation helpers used by
 * the n=10 statistical XBOW harness.
 *
 * Reference values were computed against the closed-form Wilson score
 * formula using z = 1.959963984540054 (95% CI). Spot-checks agree with
 * the worked examples on
 * https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval#Wilson_score_interval
 * and with the `binom.confint(..., methods = "wilson")` output in R.
 */

import { describe, it, expect } from "vitest";
import {
  wilsonInterval,
  wilsonIntervalTuple,
  mean,
  stdDev,
  aggregateRuns,
  type RepeatRun,
} from "./wilson.js";

// Small helper: expect two floats to match within 1e-4.
const approx = (a: number, b: number, eps = 1e-4) =>
  expect(Math.abs(a - b)).toBeLessThan(eps);

describe("wilsonInterval", () => {
  it("n=10, k=0 → lower clamped to 0, upper ≈ 0.27753", () => {
    const { lower, upper } = wilsonInterval(0, 10);
    expect(lower).toBe(0);
    approx(upper, 0.27753);
  });

  it("n=10, k=10 → upper clamped to 1, lower ≈ 0.72247", () => {
    const { lower, upper } = wilsonInterval(10, 10);
    approx(lower, 0.72247);
    expect(upper).toBe(1);
  });

  it("n=10, k=5 → symmetric around 0.5, [0.2634, 0.7366]", () => {
    const { lower, upper } = wilsonInterval(5, 10);
    approx(lower, 0.23659, 1e-3);
    approx(upper, 0.76341, 1e-3);
    // Symmetry check: lower + upper = 2 * center = 1.0 for p=0.5.
    approx(lower + upper, 1.0);
  });

  it("n=10, k=1 → asymmetric near 0, [~0.0179, ~0.4041]", () => {
    const { lower, upper } = wilsonInterval(1, 10);
    approx(lower, 0.01787, 1e-3);
    approx(upper, 0.40415, 1e-3);
  });

  it("n=10, k=9 → mirror of k=1, [~0.5959, ~0.9821]", () => {
    const { lower, upper } = wilsonInterval(9, 10);
    const mirror = wilsonInterval(1, 10);
    approx(lower, 1 - mirror.upper);
    approx(upper, 1 - mirror.lower);
  });

  it("n=10, k=3 (the XBEN-061 ~30% point estimate) → plausible CI", () => {
    // A 3/10 empirical rate is roughly where the "single solve is noise"
    // story lives. The CI should clearly exclude both 0 and anything
    // near 1, while still being wide (small N).
    const { lower, upper } = wilsonInterval(3, 10);
    expect(lower).toBeGreaterThan(0.08);
    expect(upper).toBeLessThan(0.62);
    expect(upper - lower).toBeGreaterThan(0.4); // wide, as expected at n=10
  });

  it("n=0 → returns [0, 1] (no information)", () => {
    expect(wilsonInterval(0, 0)).toEqual({ lower: 0, upper: 1 });
  });

  it("rejects invalid inputs", () => {
    expect(() => wilsonInterval(-1, 10)).toThrow();
    expect(() => wilsonInterval(11, 10)).toThrow();
    expect(() => wilsonInterval(5, -1)).toThrow();
  });

  it("tuple form returns [lower, upper]", () => {
    const t = wilsonIntervalTuple(5, 10);
    expect(Array.isArray(t)).toBe(true);
    expect(t.length).toBe(2);
    expect(t[0]).toBeLessThan(t[1]);
  });
});

describe("mean / stdDev", () => {
  it("mean of empty array is 0", () => {
    expect(mean([])).toBe(0);
    expect(stdDev([])).toBe(0);
  });
  it("mean/stdDev of [2,4,4,4,5,5,7,9] = 5 / 2", () => {
    const xs = [2, 4, 4, 4, 5, 5, 7, 9];
    approx(mean(xs), 5);
    approx(stdDev(xs), 2); // population sd
  });
});

describe("aggregateRuns", () => {
  const mk = (i: number, passed: boolean, turns: number, cost: number): RepeatRun => ({
    runIndex: i,
    passed,
    turns,
    cost,
    durationMs: 1000 * (i + 1),
  });

  it("mocked 10-run cell with 3 passes matches aggregation spec", () => {
    const runs: RepeatRun[] = [
      mk(0, true, 8, 0.25),
      mk(1, false, 12, 0.42),
      mk(2, false, 10, 0.31),
      mk(3, true, 6, 0.18),
      mk(4, false, 11, 0.39),
      mk(5, false, 14, 0.51),
      mk(6, true, 9, 0.27),
      mk(7, false, 13, 0.44),
      mk(8, false, 12, 0.40),
      mk(9, false, 10, 0.33),
    ];
    const agg = aggregateRuns(runs);
    expect(agg.attempts).toBe(10);
    expect(agg.passes).toBe(3);
    approx(agg.successRate, 0.3);
    // Wilson CI for 3/10 — sanity check, full values covered in wilson tests
    expect(agg.successRateCI95[0]).toBeGreaterThan(0.08);
    expect(agg.successRateCI95[1]).toBeLessThan(0.62);
    // Mean turns = (8+12+10+6+11+14+9+13+12+10)/10 = 10.5
    approx(agg.meanTurns, 10.5);
    expect(agg.stdDevTurns).toBeGreaterThan(0);
    approx(
      agg.meanCostUsd,
      (0.25 + 0.42 + 0.31 + 0.18 + 0.39 + 0.51 + 0.27 + 0.44 + 0.4 + 0.33) / 10,
    );
    expect(agg.perRun).toHaveLength(10);
    expect(agg.costCeilingHit).toBe(false);
  });

  it("all-pass run → successRate 1.0, CI lower bounded away from 0", () => {
    const runs = Array.from({ length: 10 }, (_, i) => mk(i, true, 5, 0.1));
    const agg = aggregateRuns(runs);
    expect(agg.passes).toBe(10);
    expect(agg.successRate).toBe(1);
    expect(agg.successRateCI95[1]).toBe(1);
    expect(agg.successRateCI95[0]).toBeGreaterThan(0.7);
  });

  it("all-fail run → successRate 0, CI upper bounded below 1", () => {
    const runs = Array.from({ length: 10 }, (_, i) => mk(i, false, 15, 0.5));
    const agg = aggregateRuns(runs);
    expect(agg.passes).toBe(0);
    expect(agg.successRate).toBe(0);
    expect(agg.successRateCI95[0]).toBe(0);
    expect(agg.successRateCI95[1]).toBeLessThan(0.3);
  });

  it("propagates costCeilingHit flag", () => {
    const runs = [mk(0, true, 5, 2.5), mk(1, false, 8, 2.6)];
    const agg = aggregateRuns(runs, { costCeilingHit: true });
    expect(agg.costCeilingHit).toBe(true);
    expect(agg.attempts).toBe(2);
  });
});
