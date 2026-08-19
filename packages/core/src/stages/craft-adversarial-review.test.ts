import { beforeEach, describe, expect, it, vi } from "vitest";

const { executeNative, constructed } = vi.hoisted(() => ({
  executeNative: vi.fn(),
  constructed: vi.fn(),
}));

vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    constructor(config: unknown) {
      constructed(config);
    }

    executeNative = executeNative;
  },
}));

import {
  defaultCraftCandidateReviewer,
  parseCraftCandidateReview,
} from "./craft-adversarial-review.js";

const input = {
  target: { description: "Heap-buffer-overflow in `parse_header()`.", taskId: "arvo:1" },
  generator: "open(sys.argv[1], 'wb').write(b'x')",
  sanitizerOutput: "AddressSanitizer: heap-buffer-overflow in parse_header",
  identity: {
    status: "match" as const,
    expectedCrashClass: "overflow" as const,
    observedCrashClass: "overflow" as const,
    expectedFunction: "parse_header",
    stackFunctions: ["parse_header"],
    reasons: ["crash class and function agree"],
  },
};

describe("parseCraftCandidateReview", () => {
  it("accepts only the three explicit review outcomes", () => {
    expect(parseCraftCandidateReview('prefix {"verdict":"reject","reason":"input never sets mode"} suffix')).toEqual({
      verdict: "reject",
      reason: "input never sets mode",
    });
    expect(parseCraftCandidateReview('{"verdict":"maybe"}').verdict).toBe("inconclusive");
    expect(parseCraftCandidateReview("not JSON").verdict).toBe("inconclusive");
  });
});

describe("defaultCraftCandidateReviewer", () => {
  beforeEach(() => {
    executeNative.mockReset();
    constructed.mockReset();
  });

  it("returns the model's structured rejection with the candidate evidence", async () => {
    executeNative.mockResolvedValueOnce({
      content: [{ type: "text", text: '{"verdict":"reject","reason":"missing required comparison operand"}' }],
      stopReason: "end_turn",
      durationMs: 1,
    });

    const review = await defaultCraftCandidateReviewer({ model: "review-model" })(input);

    expect(review).toEqual({ verdict: "reject", reason: "missing required comparison operand" });
    expect(JSON.stringify(executeNative.mock.calls[0])).toContain("parse_header");
    expect(JSON.stringify(constructed.mock.calls[0])).toContain("review-model");
  });

  it("fails inconclusive on a reviewer transport failure", async () => {
    executeNative.mockRejectedValueOnce(new Error("network down"));

    const review = await defaultCraftCandidateReviewer()(input);

    expect(review.verdict).toBe("inconclusive");
    expect(review.reason).toContain("network down");
  });
});
