import { describe, expect, it } from "vitest";
import { deletePreviousWord, deleteToLineStart } from "./composer-edit.js";

describe("deleteToLineStart", () => {
  it("empties a line", () => {
    expect(deleteToLineStart("scan example.com for idor")).toBe("");
  });

  it("is a no-op on empty input", () => {
    expect(deleteToLineStart("")).toBe("");
  });

  it("is idempotent", () => {
    expect(deleteToLineStart(deleteToLineStart("anything"))).toBe("");
  });

  it("does not spare a leading slash command", () => {
    expect(deleteToLineStart("/mode copilot")).toBe("");
  });
});

describe("deletePreviousWord", () => {
  it("removes the final word", () => {
    expect(deletePreviousWord("foo bar")).toBe("foo ");
  });

  it("removes trailing whitespace and the word it follows in one step", () => {
    expect(deletePreviousWord("foo bar   ")).toBe("foo ");
  });

  it("collapses an all-whitespace buffer", () => {
    expect(deletePreviousWord("   ")).toBe("");
  });

  it("is a no-op on empty input", () => {
    expect(deletePreviousWord("")).toBe("");
  });

  it("clears a single word", () => {
    expect(deletePreviousWord("word")).toBe("");
  });

  it("walks back one word per application and terminates", () => {
    let text = "alpha beta gamma";
    text = deletePreviousWord(text);
    expect(text).toBe("alpha beta ");
    text = deletePreviousWord(text);
    expect(text).toBe("alpha ");
    text = deletePreviousWord(text);
    expect(text).toBe("");
    // Repeated application past empty must not loop or throw.
    expect(deletePreviousWord(text)).toBe("");
  });

  it("treats punctuation as part of the word (whitespace is the only boundary)", () => {
    expect(deletePreviousWord("check https://example.com/path?a=b")).toBe("check ");
  });

  it("keeps multi-byte characters intact", () => {
    expect(deletePreviousWord("héllo wörld")).toBe("héllo ");
  });

  it("does not split an astral code point", () => {
    const text = "🙂👍 tail";
    const next = deletePreviousWord(text);
    expect(next).toBe("🙂👍 ");
    // Every code unit still pairs up: no lone surrogate survived the cut.
    expect([...next].join("")).toBe(next);
    expect(deletePreviousWord(next)).toBe("");
  });

  it("handles tabs and newlines as whitespace", () => {
    expect(deletePreviousWord("one\ttwo")).toBe("one\t");
    expect(deletePreviousWord("one\ntwo\n")).toBe("one\n");
  });
});
