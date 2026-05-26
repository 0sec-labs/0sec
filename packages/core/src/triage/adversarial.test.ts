import { describe, it, expect, vi } from "vitest";
import {
  runAdversarialDebate,
  parseJudgeOutput,
  type DebateResult,
} from "./adversarial.js";
import {
  reconcileVerifyAndDebate,
  runVerifyWithDebate,
  type VerifyResult,
  type DebateFn,
  type VerifyFn,
} from "./structured-verify.js";
import type { AttackCategory, Finding } from "@pwnkit/shared";
import type {
  NativeRuntime,
  NativeRuntimeResult,
  NativeContentBlock,
} from "../runtime/types.js";

// ── Fixtures ──

function makeFinding(): Finding {
  return {
    id: "debate-test",
    templateId: "audit-sink",
    title: "Possible SQL injection in /items",
    description: "User-controlled `id` parameter flows unsanitised into a raw SQL query.",
    severity: "high",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "GET /items?id=1' OR 1=1-- HTTP/1.1",
      response: "HTTP/1.1 200 OK\n\n[{\"id\":1},{\"id\":2},{\"id\":3}]",
    },
    confidence: 0.7,
    timestamp: Date.now(),
  };
}

function fakeVerify(
  verdict: "confirmed" | "rejected",
  confidence = 0.9,
): VerifyResult {
  return {
    verdict,
    confidence,
    steps: [],
    reasoning: `fake verify ${verdict}`,
  };
}

function fakeDebate(
  verdict: "real" | "false_positive" | "unclear",
  confidence = 0.9,
): DebateResult {
  return {
    verdict,
    confidence,
    rounds: [
      { prosecutor: "fake prosecution", defender: "fake defense" },
      { prosecutor: "fake rebuttal 1", defender: "fake rebuttal 2" },
    ],
    judgeReasoning: `fake judge: ${verdict}`,
    prosecutorWon: verdict === "real",
  };
}

/**
 * Build a NativeRuntime mock that returns the supplied text responses in FIFO
 * order. Each runAdversarialDebate call consumes: maxRounds * 2 debater turns
 * + 1 judge turn.
 */
function queueRuntime(responses: string[]): NativeRuntime {
  const queue = [...responses];
  return {
    type: "api",
    isAvailable: async () => true,
    executeNative: vi.fn(async (): Promise<NativeRuntimeResult> => {
      const text = queue.shift();
      if (text === undefined) {
        throw new Error("runtime called more times than expected");
      }
      const content: NativeContentBlock[] = [{ type: "text", text }];
      return {
        content,
        stopReason: "end_turn",
        usage: { inputTokens: 100, outputTokens: 50 },
        durationMs: 10,
      };
    }),
  };
}

// ── parseJudgeOutput ──

describe("parseJudgeOutput", () => {
  it("parses a well-formed JSON response", () => {
    const raw = `{"verdict":"real","confidence":0.9,"reasoning":"solid evidence"}`;
    const parsed = parseJudgeOutput(raw);
    expect(parsed.verdict).toBe("real");
    expect(parsed.confidence).toBe(0.9);
    expect(parsed.reasoning).toBe("solid evidence");
  });

  it("strips markdown code fencing", () => {
    const raw = "```json\n{\"verdict\":\"false_positive\",\"confidence\":0.8,\"reasoning\":\"nope\"}\n```";
    const parsed = parseJudgeOutput(raw);
    expect(parsed.verdict).toBe("false_positive");
  });

  it("handles surrounding prose", () => {
    const raw =
      'Here is my verdict:\n{"verdict":"unclear","confidence":0.5,"reasoning":"split"}\nThanks.';
    const parsed = parseJudgeOutput(raw);
    expect(parsed.verdict).toBe("unclear");
  });

  it("rejects invalid verdict values", () => {
    const raw = `{"verdict":"maybe","confidence":0.5,"reasoning":"..."}`;
    expect(() => parseJudgeOutput(raw)).toThrow(/Invalid 'verdict'/);
  });

  it("rejects confidence out of range", () => {
    const raw = `{"verdict":"real","confidence":1.5,"reasoning":"..."}`;
    expect(() => parseJudgeOutput(raw)).toThrow(/confidence/);
  });
});

// ── runAdversarialDebate (integration with queue runtime) ──

describe("runAdversarialDebate", () => {
  it("runs maxRounds prosecutor/defender turns and returns judge verdict", async () => {
    // maxRounds=2 → 2 prosecutor + 2 defender + 1 judge = 5 calls
    const runtime = queueRuntime([
      "Prosecutor round 1: this is real because ...",
      "Defender round 1: this is fake because ...",
      "Prosecutor round 2: rebuttal ...",
      "Defender round 2: counter-rebuttal ...",
      `{"verdict":"real","confidence":0.85,"reasoning":"prosecutor made the stronger case"}`,
    ]);

    const result = await runAdversarialDebate(
      makeFinding(),
      "http://example.com",
      runtime,
      { maxRounds: 2 },
    );

    expect(result.verdict).toBe("real");
    expect(result.prosecutorWon).toBe(true);
    expect(result.confidence).toBe(0.85);
    expect(result.rounds).toHaveLength(2);
    expect(result.rounds[0]!.prosecutor).toContain("Prosecutor round 1");
    expect(result.rounds[0]!.defender).toContain("Defender round 1");
    expect(result.rounds[1]!.prosecutor).toContain("rebuttal");
    expect(result.judgeReasoning).toContain("stronger case");
  });

  it("defaults to 2 rounds", async () => {
    const runtime = queueRuntime([
      "p1",
      "d1",
      "p2",
      "d2",
      `{"verdict":"false_positive","confidence":0.9,"reasoning":"defender won"}`,
    ]);
    const result = await runAdversarialDebate(
      makeFinding(),
      "http://example.com",
      runtime,
    );
    expect(result.rounds).toHaveLength(2);
    expect(result.verdict).toBe("false_positive");
    expect(result.prosecutorWon).toBe(false);
  });

  it("supports single-round debates", async () => {
    const runtime = queueRuntime([
      "p1",
      "d1",
      `{"verdict":"unclear","confidence":0.4,"reasoning":"inconclusive"}`,
    ]);
    const result = await runAdversarialDebate(
      makeFinding(),
      "http://example.com",
      runtime,
      { maxRounds: 1 },
    );
    expect(result.rounds).toHaveLength(1);
    expect(result.verdict).toBe("unclear");
  });

  it("falls back to unclear verdict on malformed judge response", async () => {
    const runtime = queueRuntime([
      "p1",
      "d1",
      "p2",
      "d2",
      "this is not JSON at all",
    ]);
    const result = await runAdversarialDebate(
      makeFinding(),
      "http://example.com",
      runtime,
    );
    expect(result.verdict).toBe("unclear");
    expect(result.confidence).toBe(0);
    expect(result.judgeReasoning).toContain("Failed to parse");
  });
});

// ── reconcileVerifyAndDebate (pure helper) ──

describe("reconcileVerifyAndDebate", () => {
  it("agrees when both say real", () => {
    const result = reconcileVerifyAndDebate(
      fakeVerify("confirmed", 0.9),
      fakeDebate("real", 0.8),
    );
    expect(result.verdict).toBe("confirmed");
    expect(result.reconciliation).toBe("agree");
    // 0.6*0.9 + 0.4*0.8 = 0.86
    expect(result.confidence).toBeCloseTo(0.86, 2);
  });

  it("agrees when both say false positive", () => {
    const result = reconcileVerifyAndDebate(
      fakeVerify("rejected", 0.8),
      fakeDebate("false_positive", 0.9),
    );
    expect(result.verdict).toBe("rejected");
    expect(result.reconciliation).toBe("agree");
  });

  it("downgrades when verify confirms but debate rules FP with high confidence", () => {
    const result = reconcileVerifyAndDebate(
      fakeVerify("confirmed", 0.9),
      fakeDebate("false_positive", 0.85),
    );
    expect(result.verdict).toBe("rejected");
    expect(result.reconciliation).toBe("downgrade");
    expect(result.confidence).toBe(0.85);
  });

  it("does not downgrade when debate FP confidence is below threshold", () => {
    const result = reconcileVerifyAndDebate(
      fakeVerify("confirmed", 0.9),
      fakeDebate("false_positive", 0.5),
    );
    expect(result.verdict).toBe("confirmed");
    expect(result.reconciliation).toBe("unclear");
    // Confidence shaved by 0.2
    expect(result.confidence).toBeCloseTo(0.7, 2);
  });

  it("escalates when verify rejects but debate rules real with high confidence", () => {
    const result = reconcileVerifyAndDebate(
      fakeVerify("rejected", 0.6),
      fakeDebate("real", 0.9),
    );
    expect(result.verdict).toBe("confirmed");
    expect(result.reconciliation).toBe("escalate");
    expect(result.confidence).toBe(0.9);
  });

  it("keeps verify verdict when debate is unclear", () => {
    const result = reconcileVerifyAndDebate(
      fakeVerify("confirmed", 0.8),
      fakeDebate("unclear", 0.3),
    );
    expect(result.verdict).toBe("confirmed");
    expect(result.reconciliation).toBe("unclear");
    expect(result.confidence).toBe(0.8);
  });

  it("respects custom overrideThreshold", () => {
    // With threshold 0.95, a 0.9 debate should NOT override
    const result = reconcileVerifyAndDebate(
      fakeVerify("confirmed", 0.9),
      fakeDebate("false_positive", 0.9),
      0.95,
    );
    expect(result.verdict).toBe("confirmed");
    expect(result.reconciliation).toBe("unclear");
  });
});

// ── runVerifyWithDebate end-to-end via mocks ──

describe("runVerifyWithDebate", () => {
  const fakeRuntime = {} as NativeRuntime;

  it("runs both verify and debate and reconciles (unanimous real)", async () => {
    const verifyFn: VerifyFn = async () => fakeVerify("confirmed", 0.9);
    const debateFn: DebateFn = async () => fakeDebate("real", 0.9);

    const result = await runVerifyWithDebate(
      makeFinding(),
      "http://example.com",
      fakeRuntime,
      { verifyFn, debateFn },
    );

    expect(result.verdict).toBe("confirmed");
    expect(result.reconciliation).toBe("agree");
  });

  it("downgrades on unanimous defender win vs confirmed verify", async () => {
    const verifyFn: VerifyFn = async () => fakeVerify("confirmed", 0.9);
    const debateFn: DebateFn = async () => fakeDebate("false_positive", 0.9);

    const result = await runVerifyWithDebate(
      makeFinding(),
      "http://example.com",
      fakeRuntime,
      { verifyFn, debateFn },
    );

    expect(result.verdict).toBe("rejected");
    expect(result.reconciliation).toBe("downgrade");
  });

  it("forwards unclear debate through to verify verdict", async () => {
    const verifyFn: VerifyFn = async () => fakeVerify("rejected", 0.7);
    const debateFn: DebateFn = async () => fakeDebate("unclear", 0.5);

    const result = await runVerifyWithDebate(
      makeFinding(),
      "http://example.com",
      fakeRuntime,
      { verifyFn, debateFn },
    );

    expect(result.verdict).toBe("rejected");
    expect(result.reconciliation).toBe("unclear");
  });
});
