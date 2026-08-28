import { describe, expect, it } from "vitest";
import { createSessionTranscriptDocument } from "./session-presentation.js";
import type { SessionState } from "./session-state.js";

const state: SessionState = {
  target: "https://example.test",
  depth: "quick",
  mode: "scan",
  connection: { runtime: "api", localRuntimes: [] },
  usage: { inputTokens: 0, outputTokens: 0, estimatedCostUsd: 0 },
  stages: [],
  summary: null,
  thinking: null,
  pendingUserMessages: [],
  transcript: [
    { id: "thinking", kind: "thinking", text: "checking flow", turn: 2 },
    { id: "tool", kind: "tool-group", text: "Read · 2 steps", label: "Read", actions: ["read a", "read b"], turn: 2 },
    { id: "error", kind: "error", text: "failed", turn: 2 },
  ],
};

describe("createSessionTranscriptDocument", () => {
  it("maps legacy session transcript items into the shared document", () => {
    const document = createSessionTranscriptDocument(state);

    expect(document).toMatchObject({
      protocol: "0sec.presentation/v1",
      documentType: "transcript",
      entries: [
        { id: "thinking", kind: "reasoning", text: "checking flow", turn: 2 },
        { id: "tool", kind: "notice", text: "TOOL ACTIVITY · Read · 2 steps", detail: "read a\nread b", turn: 2 },
        { id: "error", kind: "error", text: "failed", turn: 2 },
      ],
    });
  });
});
