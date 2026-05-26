import { describe, expect, it } from "vitest";
import { computeNpmBenchMetrics } from "./npm-bench-metrics.js";

function result(
  verdict: "malicious" | "vulnerable" | "safe",
  hasFindings: boolean,
) {
  return {
    pkg: `${verdict}-${hasFindings}`,
    verdict,
    reason: "fixture",
    repeatIndex: 1,
    findingsCount: hasFindings ? 1 : 0,
    hasFindings,
    correct: verdict === "safe" ? !hasFindings : hasFindings,
    durationMs: 1,
    infrastructureError: false,
    usage: null,
    tokenUsage: null,
    estimatedCostUsd: null,
    findings: [],
  };
}

describe("computeNpmBenchMetrics", () => {
  it("computes attempt-level npm-bench rates with Wilson confidence intervals", () => {
    const metrics = computeNpmBenchMetrics([
      result("malicious", true),
      result("malicious", false),
      result("vulnerable", true),
      result("safe", true),
      result("safe", false),
      result("safe", false),
    ], true);

    expect(metrics.tp).toBe(2);
    expect(metrics.fn).toBe(1);
    expect(metrics.fp).toBe(1);
    expect(metrics.tn).toBe(2);
    expect(metrics.detectionRate).toBeCloseTo(2 / 3);
    expect(metrics.falsePositiveRate).toBeCloseTo(1 / 3);
    expect(metrics.accuracy).toBeCloseTo(4 / 6);
    expect(metrics.detectionRateCI95).toHaveLength(2);
    expect(metrics.falsePositiveRateCI95).toHaveLength(2);
  });

  it("omits scores when infrastructure failures invalidate the run", () => {
    const metrics = computeNpmBenchMetrics([result("safe", false)], false);

    expect(metrics.accuracy).toBeNull();
    expect(metrics.accuracyCI95).toBeNull();
    expect(metrics.detectionRate).toBeNull();
    expect(metrics.falsePositiveRate).toBeNull();
    expect(metrics.f1).toBeNull();
  });
});
