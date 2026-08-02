import { describe, it, expect } from "vitest";
import {
  BYTES_PER_TOKEN,
  DEFAULT_TOOL_OUTPUT_TOKENS,
  estimateTokens,
  formatTruncated,
  truncateMiddle,
} from "./output-truncation.js";

/** True when the string contains a surrogate code unit without its partner. */
function hasLoneSurrogate(s: string): boolean {
  return Array.from(s).some(
    (ch) => ch.length === 1 && ch.charCodeAt(0) >= 0xd800 && ch.charCodeAt(0) <= 0xdfff,
  );
}

describe("truncateMiddle", () => {
  it("returns empty input unchanged", () => {
    const r = truncateMiddle("", { limit: 10 });
    expect(r.truncated).toBe(false);
    expect(r.text).toBe("");
    expect(r.originalTokens).toBe(0);
    expect(r.originalLines).toBe(0);
    expect(r.truncatedTokens).toBe(0);
  });

  it("returns under-limit input unchanged", () => {
    const text = "a".repeat(100);
    const r = truncateMiddle(text, { limit: 100, mode: "bytes" });
    expect(r.truncated).toBe(false);
    expect(r.text).toBe(text);
  });

  it("does not truncate at exactly the limit", () => {
    const text = "a".repeat(40);
    const r = truncateMiddle(text, { limit: 10 }); // 10 tokens = 40 bytes
    expect(r.truncated).toBe(false);
    expect(r.text).toBe(text);
  });

  it("truncates one byte over the limit", () => {
    const text = "a".repeat(41);
    const r = truncateMiddle(text, { limit: 10 });
    expect(r.truncated).toBe(true);
  });

  it("keeps the head AND the tail", () => {
    const text = `HEAD${"x".repeat(1000)}TAIL`;
    const r = truncateMiddle(text, { limit: 100, mode: "bytes" });
    expect(r.truncated).toBe(true);
    expect(r.text.startsWith("HEAD")).toBe(true);
    expect(r.text.endsWith("TAIL")).toBe(true);
  });

  it("splits the budget 50/50 between head and tail", () => {
    const text = "a".repeat(500) + "b".repeat(500);
    const r = truncateMiddle(text, { limit: 100, mode: "bytes" });
    const [head, tail] = r.text.split(/\n….*…\n/);
    expect(head).toHaveLength(50);
    expect(tail).toHaveLength(50);
    expect(head).toBe("a".repeat(50));
    expect(tail).toBe("b".repeat(50));
  });

  it("reports an accurate truncated-token count", () => {
    // 1000 bytes in, 100 bytes kept → 900 bytes dropped → 225 tokens.
    const text = "a".repeat(1000);
    const r = truncateMiddle(text, { limit: 100, mode: "bytes" });
    expect(r.truncatedTokens).toBe(900 / BYTES_PER_TOKEN);
    expect(r.text).toContain(`…${r.truncatedTokens} tokens truncated…`);
  });

  it("counts original tokens and lines from the ORIGINAL text", () => {
    const text = Array.from({ length: 40 }, () => "z".repeat(49)).join("\n"); // 2000 bytes
    const r = truncateMiddle(text, { limit: 100, mode: "bytes" });
    expect(r.originalLines).toBe(40);
    expect(r.originalTokens).toBe(2000 / BYTES_PER_TOKEN);
  });

  it("never splits a surrogate pair at the head boundary", () => {
    // "😀" is 4 UTF-8 bytes / 2 UTF-16 code units. A 51-byte budget gives the
    // head 25 bytes: 6 emoji (24 bytes) fit, the 7th does not.
    const text = "😀".repeat(100);
    const r = truncateMiddle(text, { limit: 51, mode: "bytes" });
    const [head, tail] = r.text.split(/\n….*…\n/);
    expect(head).toBe("😀".repeat(6));
    expect(tail).toBe("😀".repeat(6));
    // No lone surrogates survived the cut.
    expect(hasLoneSurrogate(r.text)).toBe(false);
  });

  it("handles multibyte characters that straddle the boundary from both sides", () => {
    // 3-byte characters: 5 bytes of budget per side fits exactly one.
    const text = "€".repeat(50);
    const r = truncateMiddle(text, { limit: 10, mode: "bytes" });
    const [head, tail] = r.text.split(/\n….*…\n/);
    expect(head).toBe("€");
    expect(tail).toBe("€");
    expect(hasLoneSurrogate(r.text)).toBe(false);
  });

  it("defaults to the 10,000-token tool-output policy", () => {
    const text = "a".repeat(DEFAULT_TOOL_OUTPUT_TOKENS * BYTES_PER_TOKEN);
    expect(truncateMiddle(text).truncated).toBe(false);
    expect(truncateMiddle(text + "a").truncated).toBe(true);
  });
});

describe("estimateTokens", () => {
  it("counts UTF-8 bytes, not code units", () => {
    expect(estimateTokens("")).toBe(0);
    expect(estimateTokens("abcd")).toBe(1);
    expect(estimateTokens("abcde")).toBe(2);
    expect(estimateTokens("😀")).toBe(1); // 4 bytes
  });
});

describe("formatTruncated", () => {
  it("returns untruncated text with no header", () => {
    expect(formatTruncated("short", { limit: 100, mode: "bytes" })).toBe("short");
  });

  it("prepends the original token count and line count when truncated", () => {
    const text = Array.from({ length: 40 }, () => "z".repeat(49)).join("\n"); // 2000 bytes, 40 lines
    const out = formatTruncated(text, { limit: 100, mode: "bytes" });
    const lines = out.split("\n");
    expect(lines[0]).toBe("Warning: truncated output (original token count: 500)");
    expect(lines[1]).toBe("Total output lines: 40");
    expect(lines[2]).toBe("");
    expect(out).toContain("tokens truncated…");
  });

  it("keeps the verdict at the end of a long command output", () => {
    const out = formatTruncated(
      `starting\n${"noise\n".repeat(20_000)}FAILED: exit code 1`,
      { limit: 200, mode: "bytes" },
    );
    expect(out.endsWith("FAILED: exit code 1")).toBe(true);
    expect(out).toContain("starting");
  });
});
