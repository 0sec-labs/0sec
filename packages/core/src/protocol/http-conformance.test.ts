import { describe, expect, it, vi } from "vitest";

import type {
  NativeMessage,
  NativeRuntime,
  NativeRuntimeResult,
  NativeToolDef,
} from "../runtime/types.js";
import { runHttpConformanceCheck, type HttpSender } from "./http-conformance.js";

const PROTOCOL = { name: "HTTP/1.1", version: "RFC 9110", specRef: "RFC 9110 §9" };
const SPEC = "A server that does not support TRACE MUST respond with 405.";
const IMPL = "function handle(req){ return 200; }";

const MODEL = {
  rules: [
    {
      id: "trace-must-405",
      specCitation: "RFC 9110 §9.3.8",
      level: "MUST",
      surface: "method",
      mandate: "MUST respond 405 to unsupported TRACE",
      exercise: { method: "TRACE", path: "/" },
    },
  ],
  hypotheses: [
    {
      ruleId: "trace-must-405",
      specCitation: "RFC 9110 §9.3.8",
      level: "MUST",
      implLocation: "handle()",
      rationale: "returns 200 for every method",
      predictedObservable: {
        surface: "method",
        expectedStatusIn: [405],
        forbiddenStatusIn: [200],
      },
      exercise: { method: "TRACE", path: "/" },
      confidence: 0.5,
    },
  ],
};

function mockLlm(obj: unknown): NativeRuntime {
  return {
    type: "api",
    async executeNative(
      _s: string,
      _m: NativeMessage[],
      _t: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      return {
        content: [{ type: "text", text: "```json\n" + JSON.stringify(obj) + "\n```" }],
        stopReason: "end_turn",
        durationMs: 1,
      };
    },
    async isAvailable() {
      return true;
    },
  };
}

describe("runHttpConformanceCheck", () => {
  it("crafts the exercise, sends it, and emits a CONFIRMED divergence Finding on a MUST violation", async () => {
    const llm = mockLlm(MODEL);
    // Vulnerable target: returns 200 to TRACE (the forbidden status).
    const send: HttpSender = vi.fn(async () => ({
      success: true,
      output: { status: 200, headers: { server: "x" } },
    }));

    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      "https://target.test",
      llm,
      send,
      PROTOCOL,
    );

    expect(result.ok).toBe(true);
    expect(result.attempts).toHaveLength(1);
    expect(result.attempts[0].verdict.status).toBe("confirmed");
    expect(result.findings).toHaveLength(1);

    const f = result.findings[0];
    expect(f.status).toBe("confirmed");
    expect(f.confidence).toBe(1.0);
    expect(f.evidence.analysis).toMatch(/Oracle: confirmed/);
    expect(f.evidence.analysis).toMatch(/Hypothesis: false/);
    expect(f.fingerprint).toBe("protoconf:HTTP/1.1:trace-must-405");

    // The exercise was crafted onto the right URL + method.
    expect(send).toHaveBeenCalledWith(
      expect.objectContaining({ url: "https://target.test/", method: "TRACE" }),
    );
  });

  it("emits NO finding when the target is conformant (oracle refutes)", async () => {
    const llm = mockLlm(MODEL);
    // Conformant target: returns 405 to TRACE.
    const send: HttpSender = async () => ({ success: true, output: { status: 405 } });

    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      "https://target.test",
      llm,
      send,
      PROTOCOL,
    );

    expect(result.ok).toBe(true);
    expect(result.attempts[0].verdict.status).toBe("refuted");
    expect(result.findings).toHaveLength(0);
  });

  it("emits NO finding on an inconclusive observation (ambiguous status)", async () => {
    const llm = mockLlm(MODEL);
    // 501 is neither the expected 405 nor the forbidden 200.
    const send: HttpSender = async () => ({ success: true, output: { status: 501 } });

    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      "https://target.test",
      llm,
      send,
      PROTOCOL,
    );

    expect(result.attempts[0].verdict.status).toBe("inconclusive");
    expect(result.findings).toHaveLength(0);
  });

  it("treats a failed http_request as inconclusive, never confirmed", async () => {
    const llm = mockLlm(MODEL);
    const send: HttpSender = async () => ({ success: false, error: "timeout" });

    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      "https://target.test",
      llm,
      send,
      PROTOCOL,
    );

    expect(result.attempts[0].observed.error).toBeDefined();
    expect(result.attempts[0].verdict.status).toBe("inconclusive");
    expect(result.findings).toHaveLength(0);
  });

  it("survives an http_request that throws — inconclusive, no crash", async () => {
    const llm = mockLlm(MODEL);
    const send: HttpSender = async () => {
      throw new Error("boom");
    };

    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      "https://target.test",
      llm,
      send,
      PROTOCOL,
    );

    expect(result.attempts[0].verdict.status).toBe("inconclusive");
    expect(result.findings).toHaveLength(0);
  });

  it("returns ok:false when conformance-gen never validates", async () => {
    // The LLM keeps producing an empty-rules model (invalid).
    const llm = mockLlm({ rules: [], hypotheses: [] });
    const send: HttpSender = vi.fn(async () => ({ success: true, output: { status: 200 } }));

    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      "https://target.test",
      llm,
      send,
      PROTOCOL,
      { gen: { maxIterations: 2 } },
    );

    expect(result.ok).toBe(false);
    expect(result.findings).toHaveLength(0);
    expect(send).not.toHaveBeenCalled();
    expect(result.reason).toMatch(/conformance-gen failed/);
  });

  it("respects maxExercises (cost guard)", async () => {
    const twoHyp = {
      rules: MODEL.rules,
      hypotheses: [
        MODEL.hypotheses[0],
        // Verb-swapped copy — but it references rule `trace-must-405`, so after
        // reconciliation the SENT method must be the rule's TRACE, not "TRACK".
        { ...MODEL.hypotheses[0], ruleId: "trace-must-405", exercise: { method: "TRACK", path: "/" } },
      ],
    };
    const llm = mockLlm(twoHyp);
    const send: HttpSender = vi.fn(async () => ({ success: true, output: { status: 405 } }));

    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      "https://target.test",
      llm,
      send,
      PROTOCOL,
      { maxExercises: 1 },
    );

    expect(result.attempts).toHaveLength(1);
    expect(send).toHaveBeenCalledTimes(1);
  });

  // FP guard #1: the rule, not the hypothesis's copies, is authoritative. A
  // hypothesis that "upgrades" a SHOULD rule to MUST (or verb-swaps the
  // exercise) must NOT yield a confirmed finding.
  it("derives level + exercise from the rule, refusing a hypothesis 'upgrade'", async () => {
    const upgraded = {
      rules: [
        {
          id: "trace-should-405",
          specCitation: "RFC 9110 §9.3.8",
          // The HONEST rule is only SHOULD-level → can never be confirmed.
          level: "SHOULD",
          surface: "method",
          mandate: "SHOULD respond 405 to unsupported TRACE",
          // The honest exercise is a benign GET, not TRACE.
          exercise: { method: "GET", path: "/" },
        },
      ],
      hypotheses: [
        {
          ruleId: "trace-should-405",
          specCitation: "RFC 9110 §9.3.8",
          // Hypothesis tries to upgrade to MUST and swap to TRACE.
          level: "MUST",
          implLocation: "handle()",
          rationale: "attempts to upgrade a SHOULD rule to MUST",
          predictedObservable: {
            surface: "method",
            expectedStatusIn: [405],
            forbiddenStatusIn: [200],
          },
          exercise: { method: "TRACE", path: "/" },
          confidence: 0.5,
        },
      ],
    };
    const llm = mockLlm(upgraded);
    // Target returns 200 — would be "confirmed" IF the MUST upgrade were trusted.
    const send: HttpSender = vi.fn(async () => ({ success: true, output: { status: 200 } }));

    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      "https://target.test",
      llm,
      send,
      PROTOCOL,
    );

    expect(result.ok).toBe(true);
    // The rule is SHOULD → the 200 is at most inconclusive, never confirmed.
    expect(result.attempts[0].verdict.status).toBe("inconclusive");
    expect(result.findings).toHaveLength(0);
    // And the SENT method is the rule's GET, not the hypothesis's TRACE.
    expect(send).toHaveBeenCalledWith(
      expect.objectContaining({ method: "GET" }),
    );
  });

  // FP guard #1b: surface drift (header matcher on a method rule) cannot be
  // safely reconciled → inconclusive, not exercised, never confirmed.
  it("treats a hypothesis whose surface drifts from its rule as inconclusive", async () => {
    const drift = {
      rules: [
        {
          id: "trace-must-405",
          specCitation: "RFC 9110 §9.3.8",
          level: "MUST",
          surface: "method",
          mandate: "MUST respond 405 to unsupported TRACE",
          exercise: { method: "TRACE", path: "/" },
        },
      ],
      hypotheses: [
        {
          ruleId: "trace-must-405",
          specCitation: "RFC 9110 §9.3.8",
          level: "MUST",
          implLocation: "handle()",
          rationale: "surface drift: claims a header matcher on a method rule",
          predictedObservable: {
            surface: "header",
            forbiddenHeader: "x-powered-by",
          },
          exercise: { method: "TRACE", path: "/" },
          confidence: 0.5,
        },
      ],
    };
    const llm = mockLlm(drift);
    const send: HttpSender = vi.fn(async () => ({
      success: true,
      output: { status: 200, headers: { "x-powered-by": "Express" } },
    }));

    const result = await runHttpConformanceCheck(
      SPEC,
      IMPL,
      "https://target.test",
      llm,
      send,
      PROTOCOL,
    );

    expect(result.attempts[0].verdict.status).toBe("inconclusive");
    expect(result.findings).toHaveLength(0);
    // Drifted hypothesis is NOT exercised at all.
    expect(send).not.toHaveBeenCalled();
  });
});
