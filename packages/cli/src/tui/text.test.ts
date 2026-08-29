import { describe, expect, it } from "vitest";
import { fitTuiText, fitTuiUrl, sanitizeComposerText, sanitizeTuiText } from "./text.js";

describe("sanitizeComposerText", () => {
  it("preserves whitespace exactly (trailing, leading, and runs)", () => {
    // The composer caret must be able to sit after a just-typed space — so
    // unlike sanitizeTuiText this must NOT collapse runs or trim the ends.
    expect(sanitizeComposerText("the ")).toBe("the ");
    expect(sanitizeComposerText("a  b")).toBe("a  b");
    expect(sanitizeComposerText("  x")).toBe("  x");
    expect(sanitizeComposerText("")).toBe("");
  });

  it("still strips terminal control sequences (paste safety)", () => {
    expect(sanitizeComposerText("\x1b[31mred\x1b[0m more")).toBe("red more");
  });
});

describe("sanitizeTuiText", () => {
  it("collapses whitespace and strips terminal control sequences", () => {
    expect(sanitizeTuiText("\x1b[31mred\x1b[0m\n\tvalue")).toBe("red value");
  });

  it("replaces large encoded payloads before rendering", () => {
    const encoded = "A".repeat(180);
    expect(sanitizeTuiText(`token=${encoded}`)).toBe("token=[encoded payload omitted]");
  });

  it("falls back to the default encoded-run limit for non-finite options", () => {
    const encoded = "A".repeat(180);
    expect(sanitizeTuiText(`token=${encoded}`, { maxEncodedRun: Number.NaN })).toBe("token=[encoded payload omitted]");
    expect(sanitizeTuiText(`token=${encoded}`, { maxEncodedRun: Number.POSITIVE_INFINITY })).toBe("token=[encoded payload omitted]");
  });

  it("normalizes fractional encoded-run limits before building the regexp", () => {
    const encoded = "A".repeat(33);
    expect(sanitizeTuiText(`token=${encoded}`, { maxEncodedRun: 32.9 })).toBe("token=[encoded payload omitted]");
  });

  it("clamps absurdly large encoded-run limits to the safe upper bound", () => {
    const encoded = "A".repeat(1_500_000);
    expect(sanitizeTuiText(`token=${encoded}`, { maxEncodedRun: 1e+300 })).toBe("token=[encoded payload omitted]");
  });

  it("falls back to the cap for unsafe-integer-range values that would stringify to scientific notation", () => {
    const encoded = "A".repeat(1_500_000);
    // 1e+21 would stringify with scientific notation and break regexp construction
    // without the clamp; the cap normalizes it to a decimal-digit quantifier.
    expect(sanitizeTuiText(`token=${encoded}`, { maxEncodedRun: 1e+21 })).toBe("token=[encoded payload omitted]");
  });
});

describe("fitTuiText", () => {
  it("returns short text unchanged", () => {
    expect(fitTuiText("short", 12)).toBe("short");
  });

  it("clips long text at the end with a stable max width", () => {
    const out = fitTuiText("abcdefghijklmnopqrstuvwxyz", 10);
    expect(out).toBe("abcdefg...");
    expect(out.length).toBe(10);
  });

  it("handles very small widths without overflowing", () => {
    expect(fitTuiText("abcdef", 2)).toBe("..");
  });
});

describe("fitTuiUrl", () => {
  it("preserves both ends of long paths and URLs", () => {
    const out = fitTuiUrl("https://example.com/a/very/long/path/with/query?token=secret", 24);
    expect(out).toBe("https://exa...ken=secret");
    expect(out.length).toBe(24);
  });
});
