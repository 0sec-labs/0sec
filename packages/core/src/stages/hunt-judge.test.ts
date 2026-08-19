/**
 * `judgeHuntCandidatesWithLlm` + `heuristicCandidateScore` — the pure/testable
 * core of the hunt best-of-N judge. `LlmApiRuntime` is mocked at the module
 * boundary (mirrors `unified-pipeline.dispatch.test.ts`'s strategy) so these
 * tests never make a real API call.
 */

import { describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import type { HuntBrief } from "./hunt-scan.js";

const executeNativeMock = vi.fn();
vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    constructor(public config: Record<string, unknown>) {}
    executeNative(...args: unknown[]) {
      return executeNativeMock(...args);
    }
  },
}));

const { judgeHuntCandidatesWithLlm, heuristicCandidateScore } = await import("./hunt-judge.js");

const BRIEF: HuntBrief = {
  bugClass: "missing length check before a multi-byte read",
  pattern: "memcpy(dst, src, attacker_len) with no bound on attacker_len",
};

function mkFinding(id: string, description: string, analysis = ""): Finding {
  return {
    id,
    templateId: "t",
    title: id,
    description,
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis },
    timestamp: 1_700_000_000_000,
  };
}

describe("heuristicCandidateScore", () => {
  it("scores higher when the finding text names the pattern's sink keywords", () => {
    const matching = mkFinding("f1", "buffer overflow", "memcpy(dst, src, attacker_len) with no bound check");
    const unrelated = mkFinding("f2", "unrelated race condition", "totally different bug, nothing here");
    const good = heuristicCandidateScore(BRIEF, matching);
    const bad = heuristicCandidateScore(BRIEF, unrelated);
    expect(good.score).toBeGreaterThan(bad.score);
    expect(good.reason).toMatch(/sink pattern keyword/);
  });

  it("falls back to a flat low score when the pattern has no extractable keywords", () => {
    const brief: HuntBrief = { bugClass: "x", pattern: "!!! ??" };
    const result = heuristicCandidateScore(brief, mkFinding("f1", "anything"));
    expect(result.score).toBe(1);
    expect(result.reason).toMatch(/no pattern keywords/);
  });
});

describe("judgeHuntCandidatesWithLlm", () => {
  it("parses a valid {score,reason} JSON response per finding", async () => {
    executeNativeMock.mockReset();
    executeNativeMock.mockResolvedValueOnce({
      content: [{ type: "text", text: '{"score": 8, "reason": "matches the sink shape"}' }],
      stopReason: "end_turn",
      durationMs: 1,
    });
    const findings = [mkFinding("f1", "candidate one")];
    const scores = await judgeHuntCandidatesWithLlm(BRIEF, findings, { runtime: "api" });
    expect(scores.get("f1")).toEqual({ score: 8, reason: "matches the sink shape" });
  });

  it("clamps out-of-range scores into [0,10]", async () => {
    executeNativeMock.mockReset();
    executeNativeMock.mockResolvedValueOnce({
      content: [{ type: "text", text: '{"score": 42, "reason": "way too high"}' }],
      stopReason: "end_turn",
      durationMs: 1,
    });
    const scores = await judgeHuntCandidatesWithLlm(BRIEF, [mkFinding("f1", "x")], { runtime: "api" });
    expect(scores.get("f1")?.score).toBe(10);
  });

  it("falls back to heuristicCandidateScore per-finding when the judge call throws", async () => {
    executeNativeMock.mockReset();
    executeNativeMock.mockRejectedValueOnce(new Error("provider timeout"));
    const finding = mkFinding("f1", "buffer overflow", "memcpy(dst, src, attacker_len) with no bound check");
    const scores = await judgeHuntCandidatesWithLlm(BRIEF, [finding], { runtime: "api" });
    const expected = heuristicCandidateScore(BRIEF, finding);
    expect(scores.get("f1")).toEqual(expected);
  });

  it("falls back per-finding when the response is empty or unparseable, without dropping other findings", async () => {
    executeNativeMock.mockReset();
    executeNativeMock
      .mockResolvedValueOnce({ content: [{ type: "text", text: "" }], stopReason: "end_turn", durationMs: 1 })
      .mockResolvedValueOnce({
        content: [{ type: "text", text: '{"score": 7, "reason": "good match"}' }],
        stopReason: "end_turn",
        durationMs: 1,
      });
    const findings = [mkFinding("f1", "empty response case"), mkFinding("f2", "valid response case")];
    const scores = await judgeHuntCandidatesWithLlm(BRIEF, findings, { runtime: "api" });
    expect(scores.get("f1")).toEqual(heuristicCandidateScore(BRIEF, findings[0]));
    expect(scores.get("f2")).toEqual({ score: 7, reason: "good match" });
  });

  it("returns an empty map for an empty candidate list (no LLM call)", async () => {
    executeNativeMock.mockReset();
    const scores = await judgeHuntCandidatesWithLlm(BRIEF, [], { runtime: "api" });
    expect(scores.size).toBe(0);
    expect(executeNativeMock).not.toHaveBeenCalled();
  });
});
