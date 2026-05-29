import { describe, it, expect } from "vitest";
import { parseManifest } from "./manifest.js";
import { runBenchSuite, type BenchScan } from "./runner.js";
import type { BenchScanResult } from "./oracle.js";
import {
  aggregateScorecard,
  evaluateGate,
  formatScorecardSummary,
  wilson95,
} from "./scorecard.js";

// ── A fixed, fully-specified corpus (the "mocked LLM / fixed seed" world) ──
//
// 7 positives (one of which is inconclusive) + 3 known-negatives (one of
// which the scanner over-claims → a false positive). Every scan outcome is
// canned so the scorecard is byte-deterministic.

const MANIFEST = parseManifest({
  id: "deterministic-corpus",
  cases: [
    { id: "p-fileread", target: { kind: "web", image: "i:1" }, objective: { type: "file-read", marker: "MK_FILEREAD" } },
    { id: "p-db", target: { kind: "web", image: "i:2" }, objective: { type: "db-access", marker: "MK_DBROW" } },
    { id: "p-admin", target: { kind: "web", image: "i:3" }, objective: { type: "admin-login", marker: "MK_ADMIN" } },
    { id: "p-ssrf", target: { kind: "web", image: "i:4" }, objective: { type: "ssrf-callback", token: "MK_OAST" } },
    { id: "p-kernel-uaf", target: { kind: "kernel", reproducerRef: "c://k/1" }, objective: { type: "kasan-hit", signature: "slab-use-after-free" } },
    { id: "p-kernel-oob", target: { kind: "kernel", reproducerRef: "c://k/2" }, objective: { type: "kasan-hit" } },
    { id: "p-incon", target: { kind: "web", image: "i:5" }, objective: { type: "file-read", marker: "MK_INCON" } },
    { id: "neg-db", target: { kind: "web", image: "i:6" }, objective: { type: "db-access", marker: "NEVER_1" }, knownNegative: true },
    { id: "neg-ssrf", target: { kind: "web", image: "i:7" }, objective: { type: "ssrf-callback", token: "NEVER_2" }, knownNegative: true },
    { id: "neg-admin", target: { kind: "web", image: "i:8" }, objective: { type: "admin-login", marker: "NEVER_3" }, knownNegative: true },
  ],
});

const OUTCOMES: Record<string, BenchScanResult> = {
  "p-fileread": { findings: [{ evidence: { response: "leaked MK_FILEREAD" } }], benchmarkMeta: { estimatedCostUsd: 0.1, attackTurns: 5 } },
  "p-db": { findings: [{ evidence: { response: "row=MK_DBROW" } }], benchmarkMeta: { estimatedCostUsd: 0.2, attackTurns: 8 } },
  "p-admin": { findings: [{ category: "security-misconfiguration", confidence: 0.5 }], benchmarkMeta: { estimatedCostUsd: 0.15, attackTurns: 6 } },
  "p-ssrf": { findings: [{ evidence: { response: "cb MK_OAST" } }], benchmarkMeta: { estimatedCostUsd: 0.05, attackTurns: 3 } },
  "p-kernel-uaf": { findings: [{ evidence: { analysis: "BUG: KASAN: slab-use-after-free in x+0x1" } }], benchmarkMeta: { estimatedCostUsd: 0.3, attackTurns: 10 } },
  "p-kernel-oob": { findings: [{ evidence: { analysis: "no crash, exit 0" } }], benchmarkMeta: { estimatedCostUsd: 0.1, attackTurns: 4 } },
  "p-incon": { error: "docker build failed" },
  "neg-db": { findings: [{ category: "sql-injection", confidence: 0.98, status: "verified" }], benchmarkMeta: { estimatedCostUsd: 0.2, attackTurns: 9 } },
  "neg-ssrf": { findings: [{ category: "ssrf", confidence: 0.3 }], benchmarkMeta: { estimatedCostUsd: 0.05, attackTurns: 2 } },
  "neg-admin": { findings: [], benchmarkMeta: { estimatedCostUsd: 0.05, attackTurns: 2 } },
};

const cannedScan: BenchScan = async ({ case: c }) => OUTCOMES[c.id];

describe("aggregateScorecard — end-to-end deterministic", () => {
  it("computes success rate over gradeable positives", async () => {
    const run = await runBenchSuite(MANIFEST, { scan: cannedScan });
    const sc = aggregateScorecard(run);
    // 4 verified of 6 gradeable positives (p-incon excluded as inconclusive).
    expect(sc.successRate).toBeCloseTo(4 / 6, 10);
    expect(sc.totals.positives).toBe(7);
  });

  it("computes the FP rate over >=3 known-negatives", async () => {
    const run = await runBenchSuite(MANIFEST, { scan: cannedScan });
    const sc = aggregateScorecard(run);
    expect(sc.totals.knownNegatives).toBe(3);
    expect(sc.falsePositives).toBe(1); // neg-db over-claimed
    expect(sc.fpRate).toBeCloseTo(1 / 3, 10);
  });

  it("computes verdict totals and cost-per-success", async () => {
    const run = await runBenchSuite(MANIFEST, { scan: cannedScan });
    const sc = aggregateScorecard(run);
    expect(sc.totals).toMatchObject({
      cases: 10,
      verified: 5, // 4 positives + 1 false-positive negative
      refuted: 4,
      inconclusive: 1,
    });
    expect(sc.totalCostUsd).toBeCloseTo(1.2, 10);
    // costPerSuccess uses verified POSITIVES (4), not the FP negative.
    expect(sc.costPerSuccessUsd).toBeCloseTo(1.2 / 4, 10);
    expect(sc.totalAttackTurns).toBe(5 + 8 + 6 + 3 + 10 + 4 + 0 + 9 + 2 + 2);
  });

  it("slices success rate by objective", async () => {
    const run = await runBenchSuite(MANIFEST, { scan: cannedScan });
    const sc = aggregateScorecard(run);
    expect(sc.byObjective["file-read"]).toEqual({ total: 2, verified: 1, successRate: 0.5 });
    expect(sc.byObjective["db-access"]).toEqual({ total: 1, verified: 1, successRate: 1 });
    expect(sc.byObjective["admin-login"]).toEqual({ total: 1, verified: 0, successRate: 0 });
    expect(sc.byObjective["kasan-hit"]).toEqual({ total: 2, verified: 1, successRate: 0.5 });
  });

  it("is byte-stable across runs and omits generatedAt without a clock", async () => {
    const a = aggregateScorecard(await runBenchSuite(MANIFEST, { scan: cannedScan }));
    const b = aggregateScorecard(await runBenchSuite(MANIFEST, { scan: cannedScan }));
    expect(JSON.stringify(a)).toEqual(JSON.stringify(b));
    expect(a.generatedAt).toBeUndefined();
  });

  it("stamps generatedAt only when a clock is supplied", async () => {
    const run = await runBenchSuite(MANIFEST, { scan: cannedScan });
    const sc = aggregateScorecard(run, { clock: () => "2026-05-29T00:00:00.000Z" });
    expect(sc.generatedAt).toBe("2026-05-29T00:00:00.000Z");
  });
});

describe("wilson95", () => {
  it("returns [0,1] for zero trials", () => {
    expect(wilson95(0, 0)).toEqual([0, 1]);
  });
  it("snaps to exact boundaries for k=0 and k=n", () => {
    expect(wilson95(0, 10)[0]).toBe(0);
    expect(wilson95(10, 10)[1]).toBe(1);
  });
  it("brackets the point estimate", () => {
    const [lo, hi] = wilson95(4, 6);
    expect(lo).toBeLessThan(4 / 6);
    expect(hi).toBeGreaterThan(4 / 6);
  });
});

describe("evaluateGate", () => {
  async function scorecard() {
    return aggregateScorecard(await runBenchSuite(MANIFEST, { scan: cannedScan }));
  }

  it("fails the build when the FP rate exceeds the max (default 0)", async () => {
    const gate = evaluateGate(await scorecard());
    expect(gate.passed).toBe(false);
    expect(gate.reasons.join(" ")).toMatch(/false-positive rate/);
  });

  it("fails when success rate is below the floor", async () => {
    const gate = evaluateGate(await scorecard(), { minSuccessRate: 0.9, maxFpRate: 1 });
    expect(gate.passed).toBe(false);
    expect(gate.reasons.join(" ")).toMatch(/success rate/);
  });

  it("passes when thresholds are met", async () => {
    const gate = evaluateGate(await scorecard(), { minSuccessRate: 0.5, maxFpRate: 0.5 });
    expect(gate.passed).toBe(true);
    expect(gate.reasons).toEqual([]);
  });

  it("can gate on inconclusive rate", async () => {
    const gate = evaluateGate(await scorecard(), { maxFpRate: 1, maxInconclusiveRate: 0.05 });
    expect(gate.passed).toBe(false);
    expect(gate.reasons.join(" ")).toMatch(/inconclusive rate/);
  });
});

describe("formatScorecardSummary", () => {
  it("produces a one-line summary", async () => {
    const sc = aggregateScorecard(await runBenchSuite(MANIFEST, { scan: cannedScan }));
    const line = formatScorecardSummary(sc);
    expect(line).toMatch(/deterministic-corpus/);
    expect(line).toMatch(/fp 33\.3%/);
    expect(line).toMatch(/cost\/success \$0\.300/);
  });
});
