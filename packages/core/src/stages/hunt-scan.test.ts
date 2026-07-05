/**
 * `runHuntScan` best-of-N + judge gate. Mock-at-module-boundary for the
 * finder (`agenticScan`, mirrors `unified-pipeline.dispatch.test.ts`'s
 * strategy) so these tests never make a real LLM call; the `verify` and
 * `judgeCandidates` seams are already injectable so tests supply plain fakes.
 *
 * Coverage:
 *   - Backward compat: attemptsPerCandidate=1 / judgeTopK=1 (unset env knobs)
 *     reproduces today's candidate × model fan-out byte-for-byte, INCLUDING
 *     the model-diversity case (multiple models on one candidate) — the judge
 *     never fires and every finding reaches `verify` individually.
 *   - Best-of-N: attemptsPerCandidate>1 surfaces >1 finding at a site; only
 *     the judge's top-judgeTopK reach `verify`, keeping skeptic call-count
 *     flat while `records` still carries the full judged pool (never
 *     flattened to titles).
 *   - No-brief fallback: attemptsPerCandidate>1 with no `brief` skips the
 *     judge (no bug-class/pattern to score against) and keeps the first
 *     `judgeTopK` attempts in order.
 */

import { describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";

const agenticScanMock = vi.fn();
vi.mock("../agentic-scanner.js", () => ({
  agenticScan: (...args: unknown[]) => agenticScanMock(...args),
}));

const { runHuntScan } = await import("./hunt-scan.js");

function mkFinding(id: string, title: string, analysis: string): Finding {
  return {
    id,
    templateId: "hunt-test",
    title,
    description: title,
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis },
    timestamp: 1_700_000_000_000,
  };
}

describe("runHuntScan — best-of-N + judge gate", () => {
  it("attemptsPerCandidate=1/judgeTopK=1 (defaults) reproduces plain candidate × model fan-out, including model diversity", async () => {
    agenticScanMock.mockReset();
    // Two models, one candidate: each model's finder call returns ONE finding.
    agenticScanMock.mockImplementation(async ({ config }: { config: { model?: string } }) => ({
      findings: [mkFinding(`f-${config.model}`, `finding from ${config.model}`, "")],
    }));

    const verifyCalls: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      verifyCalls.push(finding.id);
      return { confirmed: true, reason: "ok" };
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }],
      models: ["model-a", "model-b"],
      runtime: "api",
      concurrency: 4,
      verify,
    });

    // No widening: both model findings go straight to verify, unmodified.
    expect(res.scanned).toBe(2); // 1 candidate × 2 models × 1 attempt
    expect(res.findings).toHaveLength(2);
    expect(verifyCalls.sort()).toEqual(["f-model-a", "f-model-b"]);
    expect(res.confirmed).toHaveLength(2);
    // No judge call: no finding carries a judge score.
    expect(res.records.every((r) => r.judgeScore === undefined)).toBe(true);
    expect(res.records.every((r) => r.skepticConfirmed === true)).toBe(true);
  });

  it("attemptsPerCandidate>1 judges the widened pool and only the top-judgeTopK reach verify", async () => {
    agenticScanMock.mockReset();
    let call = 0;
    agenticScanMock.mockImplementation(async () => {
      const i = call++;
      return { findings: [mkFinding(`f-${i}`, `attempt ${i}`, i === 2 ? "the real sink pattern" : "noise")] };
    });

    const verifyCalls: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      verifyCalls.push(finding.id);
      return { confirmed: true, reason: "survived" };
    };

    const judgeCandidates: Parameters<typeof runHuntScan>[0]["judgeCandidates"] = async (_brief, findings) => {
      const scores = new Map<string, { score: number; reason: string }>();
      for (const f of findings) {
        scores.set(f.id, { score: f.id === "f-2" ? 9 : 2, reason: f.id === "f-2" ? "matches pattern" : "noise" });
      }
      return scores;
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }],
      brief: { bugClass: "missing length check", pattern: "memcpy without bound check" },
      runtime: "api",
      concurrency: 4,
      attemptsPerCandidate: 4,
      judgeTopK: 1,
      judgeCandidates,
      verify,
    });

    expect(res.scanned).toBe(4); // 1 candidate × 1 model × 4 attempts
    expect(res.findings).toHaveLength(4);
    // Only the top-judged finding (f-2) reached verify — skeptic call-count stayed flat.
    expect(verifyCalls).toEqual(["f-2"]);
    expect(res.confirmed).toHaveLength(1);
    expect(res.confirmed[0].id).toBe("f-2");

    // Every attempt in the group is judged (never dropped from the corpus)...
    const byId = new Map(res.records.map((r) => [r.finding.id, r]));
    expect(byId.get("f-2")?.judgeScore).toBe(9);
    expect(byId.get("f-0")?.judgeScore).toBe(2);
    // ...but only the winner ran through the skeptic gate.
    expect(byId.get("f-2")?.skepticConfirmed).toBe(true);
    expect(byId.get("f-0")?.skepticConfirmed).toBeUndefined();
  });

  it("attemptsPerCandidate>1 with no brief skips the judge and keeps the first judgeTopK by attempt order", async () => {
    agenticScanMock.mockReset();
    let call = 0;
    agenticScanMock.mockImplementation(async () => {
      const i = call++;
      return { findings: [mkFinding(`f-${i}`, `attempt ${i}`, "")] };
    });

    const verifyCalls: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      verifyCalls.push(finding.id);
      return { confirmed: true, reason: "ok" };
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }],
      // no brief -> generic hunt, judge has nothing to score against
      runtime: "api",
      concurrency: 4,
      attemptsPerCandidate: 3,
      judgeTopK: 1,
      verify,
    });

    expect(res.scanned).toBe(3);
    expect(verifyCalls).toEqual(["f-0"]); // first attempt, in order
    expect(res.warnings.some((w) => w.includes("no brief to judge against"))).toBe(true);
    expect(res.records.every((r) => r.judgeScore === undefined)).toBe(true);
  });
});
