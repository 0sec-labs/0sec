import { describe, it, expect, vi } from "vitest";
import { parseManifest, type BenchManifest } from "./manifest.js";
import {
  runBenchCase,
  runBenchSuite,
  type BenchScan,
  type TargetProvisioner,
} from "./runner.js";
import type { BenchScanResult } from "./oracle.js";

function manifest(cases: unknown[]): BenchManifest {
  return parseManifest({ id: "test-manifest", cases });
}

const fileReadCase = (overrides: Record<string, unknown> = {}) => ({
  id: "fr",
  target: { kind: "web", image: "img:1", port: 80 },
  objective: { type: "file-read", marker: "MARKER_PROOF_XYZ" },
  ...overrides,
});

/** A scan that surfaces the marker iff `succeedFromAttempt <= attemptIndex`. */
function scanThatSucceedsFrom(succeedFromAttempt: number, costPerAttempt = 0.1): BenchScan {
  return async ({ attemptIndex }) => {
    const found = attemptIndex >= succeedFromAttempt;
    const report: BenchScanResult = {
      findings: found ? [{ evidence: { response: "MARKER_PROOF_XYZ" } }] : [],
      benchmarkMeta: { estimatedCostUsd: costPerAttempt, attackTurns: 7 },
      durationMs: 1234,
    };
    return report;
  };
}

describe("runBenchCase — pass@k", () => {
  it("stops early on the first verified attempt", async () => {
    const m = manifest([fileReadCase()]);
    const scan = vi.fn(scanThatSucceedsFrom(1));
    const result = await runBenchCase(m.cases[0], { scan, passAtK: 5 });

    // attempt 0 refuted, attempt 1 verified → stop. No 3rd attempt.
    expect(scan).toHaveBeenCalledTimes(2);
    expect(result.verdict).toBe("verified");
    expect(result.attempts.map((a) => a.status)).toEqual(["refuted", "verified"]);
  });

  it("runs all k attempts when never verified", async () => {
    const m = manifest([fileReadCase()]);
    const scan = vi.fn(scanThatSucceedsFrom(99));
    const result = await runBenchCase(m.cases[0], { scan, passAtK: 3 });
    expect(scan).toHaveBeenCalledTimes(3);
    expect(result.verdict).toBe("refuted");
  });

  it("per-case passAtK overrides the run-level value", async () => {
    const m = manifest([fileReadCase({ passAtK: 2 })]);
    const scan = vi.fn(scanThatSucceedsFrom(99));
    const result = await runBenchCase(m.cases[0], { scan, passAtK: 10 });
    expect(scan).toHaveBeenCalledTimes(2);
    expect(result.passAtK).toBe(2);
  });
});

describe("runBenchCase — budgets", () => {
  it("stops once the cumulative per-case cost ceiling is hit", async () => {
    const m = manifest([fileReadCase()]);
    const scan = vi.fn(scanThatSucceedsFrom(99, 0.5));
    const result = await runBenchCase(m.cases[0], { scan, passAtK: 5, costCeilingUsd: 1.0 });
    // 0.5 (i0, cum .5) → 0.5 (i1, cum 1.0 >= ceiling) → stop.
    expect(scan).toHaveBeenCalledTimes(2);
    expect(result.costUsd).toBeCloseTo(1.0);
  });

  it("forwards the resolved turn budget to the scan adapter", async () => {
    const m = manifest([fileReadCase({ maxTurns: 12 })]);
    const seen: number[] = [];
    const scan: BenchScan = async ({ maxTurns }) => {
      seen.push(maxTurns);
      return { findings: [], benchmarkMeta: { estimatedCostUsd: 0 } };
    };
    await runBenchCase(m.cases[0], { scan, maxTurns: 99 });
    expect(seen).toEqual([12]); // per-case override beats run-level 99
  });
});

describe("runBenchCase — inconclusive + provisioner", () => {
  it("treats a thrown scan as inconclusive and still tears down the target", async () => {
    const m = manifest([fileReadCase()]);
    const down = vi.fn(async () => {});
    const provisioner: TargetProvisioner = {
      up: async () => ({ target: "http://localhost:1", handle: { x: 1 } }),
      down,
    };
    const scan: BenchScan = async () => {
      throw new Error("boom");
    };
    const result = await runBenchCase(m.cases[0], { scan, provisioner, passAtK: 1 });
    expect(result.verdict).toBe("inconclusive");
    expect(down).toHaveBeenCalledTimes(1);
  });

  it("treats provisioning failure as inconclusive", async () => {
    const m = manifest([fileReadCase()]);
    const provisioner: TargetProvisioner = {
      up: async () => {
        throw new Error("docker down");
      },
      down: async () => {},
    };
    const scan: BenchScan = async () => ({ findings: [] });
    const result = await runBenchCase(m.cases[0], { scan, provisioner });
    expect(result.verdict).toBe("inconclusive");
    expect(result.attempts[0].notes).toMatch(/docker down/);
  });
});

describe("runBenchCase — known-negative", () => {
  it("marks falsePositive when a known-negative over-claims", async () => {
    const m = manifest([
      fileReadCase({
        id: "neg",
        knownNegative: true,
        objective: { type: "db-access", marker: "NEVER_HERE_QQ" },
      }),
    ]);
    const scan: BenchScan = async () => ({
      findings: [{ category: "sql-injection", confidence: 0.99, status: "verified" }],
      benchmarkMeta: { estimatedCostUsd: 0.2 },
    });
    const result = await runBenchCase(m.cases[0], { scan });
    expect(result.verdict).toBe("verified");
    expect(result.falsePositive).toBe(true);
  });
});

describe("runBenchSuite — CI subset", () => {
  it("runs only ci-flagged cases", async () => {
    const m = manifest([
      fileReadCase({ id: "a", ci: true }),
      fileReadCase({ id: "b", ci: false }),
      fileReadCase({ id: "c", ci: true }),
    ]);
    const scan = vi.fn(scanThatSucceedsFrom(0));
    const run = await runBenchSuite(m, { scan, ciSubset: true });
    expect(run.cases.map((c) => c.id)).toEqual(["a", "c"]);
    expect(run.ciSubset).toBe(true);
  });
});
