import { describe, expect, it } from "vitest";

import type {
  NativeMessage,
  NativeRuntime,
  NativeRuntimeResult,
  NativeToolDef,
} from "../runtime/types.js";
import {
  generateConformanceModel,
  structurallyValidateConformanceModel,
  extractJsonBlock,
} from "./conformance-gen.js";
import type { ProtocolModel } from "./model.js";

const PROTOCOL: ProtocolModel = {
  name: "HTTP/1.1",
  version: "RFC 9110",
  specRef: "RFC 9110 §9",
  specExcerpt:
    "The TRACE method requests a remote, application-level loop-back. A server " +
    "that does not support TRACE MUST respond with 405 (Method Not Allowed).",
};

const IMPL_EXCERPT =
  "function handle(req){ if(req.method==='GET') return 200; return 200; }";

// A well-formed conformance model: one MUST rule + a confirmable hypothesis.
const VALID_MODEL = {
  rules: [
    {
      id: "trace-must-405",
      specCitation: "RFC 9110 §9.3.8",
      level: "MUST",
      surface: "method",
      mandate: "a server that does not support TRACE MUST respond 405",
      exercise: { method: "TRACE", path: "/" },
    },
  ],
  hypotheses: [
    {
      ruleId: "trace-must-405",
      specCitation: "RFC 9110 §9.3.8",
      level: "MUST",
      implLocation: "handle()",
      rationale: "handler returns 200 for every method, including TRACE",
      predictedObservable: {
        surface: "method",
        expectedStatusIn: [405],
        forbiddenStatusIn: [200, 201, 204],
      },
      exercise: { method: "TRACE", path: "/" },
      confidence: 0.5,
    },
  ],
};

// Invalid: unknown enum level, a hypothesis with a dangling ruleId, and a
// matcher-less prediction — three distinct structural problems.
const INVALID_MODEL = {
  rules: [
    {
      id: "rule-a",
      specCitation: "RFC 9110",
      level: "REQUIRED", // not an RFC-2119 enum value
      surface: "method",
      mandate: "x",
      exercise: { method: "TRACE" },
    },
  ],
  hypotheses: [
    {
      ruleId: "does-not-exist", // dangling reference
      specCitation: "RFC 9110",
      level: "MUST",
      implLocation: "h()",
      rationale: "y",
      predictedObservable: { surface: "method" }, // no matcher
      exercise: { method: "TRACE" },
      confidence: 0.5,
    },
  ],
};

/**
 * Scripted NativeRuntime: returns each queued JSON object in turn, wrapped in a
 * ```json fenced block the way a real model would, and records prompts so we
 * can assert the repair prompt carried the validation errors. Mirrors the
 * mockLlm in `kernel/spec-gen.test.ts`.
 */
function mockLlm(objects: unknown[]): NativeRuntime & { prompts: string[] } {
  const prompts: string[] = [];
  let i = 0;
  return {
    type: "api",
    prompts,
    async executeNative(
      _system: string,
      messages: NativeMessage[],
      _tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      const text = messages[0].content
        .map((b) => (b.type === "text" ? b.text : ""))
        .join("");
      prompts.push(text);
      const body = JSON.stringify(objects[Math.min(i, objects.length - 1)]);
      i++;
      return {
        content: [{ type: "text", text: "```json\n" + body + "\n```" }],
        stopReason: "end_turn",
        durationMs: 1,
      };
    },
    async isAvailable() {
      return true;
    },
  };
}

describe("structurallyValidateConformanceModel", () => {
  it("accepts a well-formed model", () => {
    const r = structurallyValidateConformanceModel(VALID_MODEL);
    expect(r.valid).toBe(true);
    expect(r.model?.rules).toHaveLength(1);
    expect(r.model?.hypotheses).toHaveLength(1);
  });

  it("rejects an unknown requirement level", () => {
    const r = structurallyValidateConformanceModel(INVALID_MODEL);
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => /level/.test(e.path))).toBe(true);
  });

  it("rejects a hypothesis with a dangling ruleId", () => {
    const r = structurallyValidateConformanceModel({
      rules: VALID_MODEL.rules,
      hypotheses: [{ ...VALID_MODEL.hypotheses[0], ruleId: "nope" }],
    });
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => /unknown ruleId/.test(e.message))).toBe(true);
  });

  it("rejects a prediction with no matcher", () => {
    const r = structurallyValidateConformanceModel({
      rules: VALID_MODEL.rules,
      hypotheses: [
        {
          ...VALID_MODEL.hypotheses[0],
          predictedObservable: { surface: "method" },
        },
      ],
    });
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => /no matcher/.test(e.message))).toBe(true);
  });

  it("rejects an empty rules list", () => {
    const r = structurallyValidateConformanceModel({ rules: [], hypotheses: [] });
    expect(r.valid).toBe(false);
  });

  it("rejects non-object input", () => {
    expect(structurallyValidateConformanceModel("not an object").valid).toBe(false);
  });
});

describe("extractJsonBlock", () => {
  it("pulls the body out of a ```json fence", () => {
    expect(extractJsonBlock('pre\n```json\n{"a":1}\n```\npost')).toBe('{"a":1}');
  });
});

describe("generateConformanceModel repair loop", () => {
  it("converges: invalid first, valid second → returns the valid model", async () => {
    const llm = mockLlm([INVALID_MODEL, VALID_MODEL]);

    const result = await generateConformanceModel(PROTOCOL, IMPL_EXCERPT, llm);

    expect(result.ok).toBe(true);
    expect(result.iterations).toBe(2);
    expect(result.model?.rules[0].id).toBe("trace-must-405");
    expect(result.errors).toEqual([]);

    // The second (repair) prompt must have carried the validation errors back.
    expect(llm.prompts).toHaveLength(2);
    expect(llm.prompts[1]).toMatch(/Validation errors/);
    expect(llm.prompts[1]).toMatch(/level|unknown ruleId|no matcher/);
  });

  it("re-prompts on non-JSON output, then converges", async () => {
    // First response is unparseable JSON, second is valid. The loop must feed a
    // "not valid JSON" error into the repair prompt rather than throwing.
    const llm: NativeRuntime & { prompts: string[] } = (() => {
      const prompts: string[] = [];
      let i = 0;
      const bodies = ["{ this is not json", JSON.stringify(VALID_MODEL)];
      return {
        type: "api",
        prompts,
        async executeNative(_s, messages) {
          prompts.push(
            messages[0].content.map((b) => (b.type === "text" ? b.text : "")).join(""),
          );
          const body = bodies[Math.min(i, bodies.length - 1)];
          i++;
          return {
            content: [{ type: "text", text: "```json\n" + body + "\n```" }],
            stopReason: "end_turn" as const,
            durationMs: 1,
          };
        },
        async isAvailable() {
          return true;
        },
      };
    })();

    const result = await generateConformanceModel(PROTOCOL, IMPL_EXCERPT, llm);
    expect(result.ok).toBe(true);
    expect(result.iterations).toBe(2);
    expect(llm.prompts[1]).toMatch(/not valid JSON/);
  });

  it("gives up after maxIterations and reports the last errors", async () => {
    const llm = mockLlm([INVALID_MODEL]); // always invalid

    const result = await generateConformanceModel(PROTOCOL, IMPL_EXCERPT, llm, {
      maxIterations: 3,
    });

    expect(result.ok).toBe(false);
    expect(result.iterations).toBe(3);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(llm.prompts).toHaveLength(3);
  });

  it("honors a pluggable validator (the semantic-validator drop-in point)", async () => {
    const llm = mockLlm([VALID_MODEL]);
    let called = 0;
    const result = await generateConformanceModel(PROTOCOL, IMPL_EXCERPT, llm, {
      validator: (candidate) => {
        called++;
        return {
          valid: true,
          model: candidate as never,
          errors: [],
        };
      },
    });
    expect(called).toBe(1);
    expect(result.ok).toBe(true);
    expect(result.iterations).toBe(1);
  });
});
