import { describe, expect, it } from "vitest";
import {
  buildXbowArgs,
  compareCells,
  parseBenchmarkJson,
  summarizeBenchmarkReport,
} from "./jit-skills-ab.js";

describe("jit-skills A/B harness helpers", () => {
  it("builds a fresh JSON XBOW argument list with a conservative default limit", () => {
    expect(buildXbowArgs([])).toEqual([
      "--agentic",
      "--fresh",
      "--json",
      "--limit",
      "10",
    ]);
  });

  it("passes through benchmark selectors and skips harness-only flags", () => {
    expect(buildXbowArgs(["--json", "--runner", "xbow", "--only", "XBEN-010", "--runtime", "api"])).toEqual([
      "--agentic",
      "--fresh",
      "--json",
      "--only",
      "XBEN-010",
      "--runtime",
      "api",
    ]);
  });

  it("parses a JSON report even when stdout has wrapper text", () => {
    const report = parseBenchmarkJson('prefix\n{"challenges":2,"passed":1,"flags":1}\nsuffix');

    expect(report.challenges).toBe(2);
    expect(report.passed).toBe(1);
    expect(report.flags).toBe(1);
  });

  it("summarizes and compares baseline versus JIT-skill cells", () => {
    const baseline = summarizeBenchmarkReport("baseline", false, {
      challenges: 4,
      passed: 2,
      flags: 1,
      totalAttackTurns: 20,
      totalEstimatedCostUsd: 1.2,
      totalInputTokens: 800,
      totalOutputTokens: 200,
      totalTokens: 1000,
    });
    const jitSkills = summarizeBenchmarkReport("jit-skills", true, {
      challenges: 4,
      passed: 3,
      flags: 2,
      totalAttackTurns: 18,
      totalEstimatedCostUsd: 1,
      totalInputTokens: 700,
      totalOutputTokens: 150,
      totalTokens: 850,
    });

    expect(baseline.passRate).toBe(0.5);
    expect(jitSkills.flagRate).toBe(0.5);
    expect(baseline.averageTokens).toBe(250);
    const delta = compareCells(baseline, jitSkills);
    expect(delta).toMatchObject({
      passed: 1,
      flags: 1,
      passRatePctPoints: 25,
      flagRatePctPoints: 25,
      totalAttackTurns: -2,
      totalTokens: -150,
    });
    expect(delta.totalEstimatedCostUsd).toBeCloseTo(-0.2);
  });
});
