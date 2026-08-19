/**
 * Unit tests for the n=10 repeat harness aggregation in xbow-runner.
 *
 * These tests cover `runChallengeRepeated` by injecting a fake
 * `runOne` (so they never touch Docker, the agent loop, or an LLM). The
 * goal is to prove that:
 *
 *   1. The aggregation rolls up attempts, passes, successRate, Wilson
 *      CI, and mean/stdDev correctly from a synthetic sequence of runs.
 *   2. `passes > 0` ⇒ `passed = true` on the rolled-up XbowResult, but
 *      `successRate` is the honest per-attempt number (not 0/1).
 *   3. The cost ceiling aborts subsequent runs and sets `costCeilingHit`.
 *   4. Legacy single-run fields (attackTurns, estimatedCostUsd, etc.)
 *      come from the first attempt for backward compatibility.
 */

import { describe, it, expect } from "vitest";
import {
  runChallengeRepeated,
  type XbowChallenge,
  type XbowResult,
} from "./xbow-runner.js";

const fakeChallenge: XbowChallenge = {
  id: "XBEN-061",
  name: "Fake IDOR",
  description: "",
  level: 2,
  tags: ["idor"],
  winCondition: "flag",
  path: "/tmp/does-not-exist",
};

function mkResult(
  overrides: Partial<XbowResult>,
): XbowResult {
  return {
    id: fakeChallenge.id,
    name: fakeChallenge.name,
    level: fakeChallenge.level,
    tags: fakeChallenge.tags,
    passed: false,
    flagFound: false,
    findingsCount: 0,
    durationMs: 1000,
    attackTurns: 10,
    estimatedCostUsd: 0.2,
    ...overrides,
  };
}

describe("runChallengeRepeated (n=10 harness)", () => {
  it("aggregates 10 runs with 3 flags into a Wilson-CI summary", async () => {
    const seq: XbowResult[] = [
      mkResult({ flagFound: true, passed: true, attackTurns: 8, estimatedCostUsd: 0.25 }),
      mkResult({ attackTurns: 12, estimatedCostUsd: 0.42 }),
      mkResult({ attackTurns: 10, estimatedCostUsd: 0.31 }),
      mkResult({ flagFound: true, passed: true, attackTurns: 6, estimatedCostUsd: 0.18 }),
      mkResult({ attackTurns: 11, estimatedCostUsd: 0.39 }),
      mkResult({ attackTurns: 14, estimatedCostUsd: 0.51 }),
      mkResult({ flagFound: true, passed: true, attackTurns: 9, estimatedCostUsd: 0.27 }),
      mkResult({ attackTurns: 13, estimatedCostUsd: 0.44 }),
      mkResult({ attackTurns: 12, estimatedCostUsd: 0.4 }),
      mkResult({ attackTurns: 10, estimatedCostUsd: 0.33 }),
    ];
    let i = 0;
    const runOne = async () => seq[i++];

    const result = await runChallengeRepeated(fakeChallenge, 10, 100, runOne);

    expect(result.attempts).toBe(10);
    expect(result.passes).toBe(3);
    expect(result.successRate).toBeCloseTo(0.3, 6);
    expect(result.successRateCI95).toBeDefined();
    const [lo, hi] = result.successRateCI95!;
    expect(lo).toBeGreaterThan(0.08);
    expect(hi).toBeLessThan(0.62);

    // passed/flagFound = "did any attempt solve it?" (best-of-N semantics
    // for the legacy top-level counters).
    expect(result.passed).toBe(true);
    expect(result.flagFound).toBe(true);

    // Legacy single-shot fields come from the first attempt for
    // backward compatibility.
    expect(result.attackTurns).toBe(8);
    expect(result.estimatedCostUsd).toBeCloseTo(0.25, 6);

    // Mean turns = 10.5
    expect(result.meanTurns).toBeCloseTo(10.5, 6);
    expect(result.stdDevTurns).toBeGreaterThan(0);
    expect(result.perRun).toHaveLength(10);
    expect(result.costCeilingHit).toBe(false);
  });

  it("all-fail 10-run cell: successRate=0, passed=false, CI upper < 0.3", async () => {
    const runOne = async () => mkResult({ attackTurns: 15, estimatedCostUsd: 0.1 });
    const result = await runChallengeRepeated(fakeChallenge, 10, 100, runOne);
    expect(result.attempts).toBe(10);
    expect(result.passes).toBe(0);
    expect(result.successRate).toBe(0);
    expect(result.passed).toBe(false);
    expect(result.flagFound).toBe(false);
    expect(result.successRateCI95![1]).toBeLessThan(0.3);
  });

  it("cost ceiling aborts further runs and sets costCeilingHit", async () => {
    // Each run costs $2, ceiling is $5 → we should stop after run 3.
    // runOne is called for run 1 ($2 total), run 2 ($4), run 3 ($6 ≥ 5)
    // and then no more.
    let calls = 0;
    const runOne = async () => {
      calls++;
      return mkResult({ attackTurns: 5, estimatedCostUsd: 2 });
    };
    const result = await runChallengeRepeated(fakeChallenge, 10, 5, runOne);
    expect(calls).toBe(3);
    expect(result.attempts).toBe(3);
    expect(result.costCeilingHit).toBe(true);
    expect(result.passes).toBe(0);
  });

  it("single pass in 10 attempts reflects honest ~10% rate, not 100%", async () => {
    // This is the XBEN-061 v1-vs-v2 story: one lucky solve in N attempts
    // is NOT a generalizable signal. The harness must not promote it
    // to a 100% success rate.
    const seq = Array.from({ length: 10 }, (_, i) =>
      mkResult({
        flagFound: i === 4,
        passed: i === 4,
        attackTurns: 10,
        estimatedCostUsd: 0.2,
      }),
    );
    let i = 0;
    const runOne = async () => seq[i++];
    const result = await runChallengeRepeated(fakeChallenge, 10, 100, runOne);
    expect(result.passes).toBe(1);
    expect(result.successRate).toBeCloseTo(0.1, 6);
    // Wilson CI for 1/10 is roughly [0.018, 0.404]
    expect(result.successRateCI95![0]).toBeGreaterThan(0.01);
    expect(result.successRateCI95![1]).toBeLessThan(0.45);
    // The top-level "passed" still reads true (at least one solve) — but
    // a caller that trusts successRate can see this is ~10%, not 100%.
    expect(result.passed).toBe(true);
  });
});
