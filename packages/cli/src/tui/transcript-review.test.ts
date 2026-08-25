import { describe, expect, it } from "vitest";
import { compileTranscriptReview } from "./transcript-review.js";
import type { ChatEntry } from "./chat/types.js";

function entry(overrides: Partial<ChatEntry> & Pick<ChatEntry, "id" | "kind" | "text">): ChatEntry {
  return { turn: 1, ...overrides };
}

describe("compileTranscriptReview", () => {
  it("compiles markdown messages into semantic plain-text review lines", () => {
    const document = compileTranscriptReview([
      entry({ id: "user", kind: "user", text: "check **this**" }),
      entry({ id: "assistant", kind: "assistant", text: "# Result\n\n**verified**" }),
    ], { width: 60, detail: "expanded" });

    expect(document.text).toContain("OPERATOR");
    expect(document.text).toContain("check this");
    expect(document.text).toContain("0SEC");
    expect(document.text).toContain("# Result");
    expect(document.text).toContain("verified");
  });

  it("uses the existing folded transcript plan for collapsed detail", () => {
    const document = compileTranscriptReview([
      entry({ id: "tool", kind: "tool", text: "read_file", detail: "src/index.ts", turn: 4, success: true }),
      entry({ id: "reasoning", kind: "reasoning", text: "thinking", turn: 4 }),
    ], { width: 60, detail: "collapsed" });

    expect(document.lines).toEqual([
      expect.objectContaining({ text: expect.stringMatching(/^▸ /), tone: "fold", turn: 4 }),
    ]);
  });

  it("retains rich tool output in expanded review mode", () => {
    const document = compileTranscriptReview([
      entry({
        id: "command",
        kind: "tool",
        text: "run_command",
        toolArgs: "pnpm test",
        commandOutput: "line one\nline two",
        detail: "2 lines",
        success: true,
      }),
    ], { width: 60, detail: "expanded" });

    expect(document.text).toContain("TOOL done · run_command · pnpm test");
    expect(document.text).toContain("line one");
    expect(document.text).toContain("line two");
  });

  it("sanitizes terminal control sequences in non-markdown detail", () => {
    const document = compileTranscriptReview([
      entry({ id: "error", kind: "error", text: "failed", detail: "\u001b[31munsafe\u001b[0m" }),
    ], { width: 60, detail: "expanded" });

    expect(document.text).toContain("unsafe");
    expect(document.text).not.toContain("\u001b");
  });
});
