import { describe, expect, it } from "vitest";
import { planSpecdriftHypotheses, runSpecdriftPlan } from "./plan.js";
import type { SpecdriftScanResult } from "./types.js";

function scanFixture(): SpecdriftScanResult {
  return {
    mode: "specdrift",
    stage: "scan",
    spec: "proto.txt",
    source: "/tmp/impl",
    warnings: [],
    invariants: [{
      id: "inv-001-reject-oversized-frame",
      kind: "rejection",
      summary: "Implementations MUST reject oversized frames",
      rule: "Implementations MUST reject oversized frames.",
      citations: [{ spec: "proto.txt", lineStart: 1, lineEnd: 1, text: "Implementations MUST reject oversized frames." }],
      securityRelevance: "high",
    }],
    candidates: [{
      invariantId: "inv-001-reject-oversized-frame",
      file: "src/parser.c",
      lineStart: 10,
      lineEnd: 14,
      snippet: "10: if (len > max) return -1;",
      matchedTerms: ["reject", "oversized", "frames"],
      reason: "rejection invariant terms matched implementation code",
      confidence: 0.8,
      status: "candidate",
    }],
  };
}

describe("planSpecdriftHypotheses", () => {
  it("turns mapped candidates into non-sendable drift hypotheses", () => {
    const hypotheses = planSpecdriftHypotheses({ scan: scanFixture() });

    expect(hypotheses).toHaveLength(1);
    expect(hypotheses[0]).toMatchObject({
      invariantId: "inv-001-reject-oversized-frame",
      candidateFile: "src/parser.c",
      suggestedAdapter: "raw-bytes",
      status: "hypothesis",
    });
    expect(hypotheses[0]?.question).toContain("reject inputs");
    expect(hypotheses[0]?.rationale).toContain("hypothesis only");
  });

  it("runs the scan+plan workflow", () => {
    const result = runSpecdriftPlan({
      specName: "proto.txt",
      specText: "Implementations MUST reject frames whose declared length exceeds the remaining input.",
      sourceRoot: "/tmp/no-such-tree",
      maxFiles: 1,
    });

    expect(result.stage).toBe("plan");
    expect(result.hypotheses).toEqual([]);
    expect(result.warnings).toContain("no implementation candidates matched extracted invariants");
  });
});
