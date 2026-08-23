import { describe, expect, it } from "vitest";

import {
  COMPOSER_MAX_ROWS,
  COMPOSER_MIN_ROWS,
  composerContentRows,
  composerCursorGlyph,
  composerRailRows,
  wrapComposerInput,
} from "./Composer.js";

/** Rows must always concatenate back to the source line — no content lost. */
function concatEquals(text: string, width: number): boolean {
  return wrapComposerInput(text, width).join("") === text;
}

describe("composerCursorGlyph", () => {
  it("is a filled block when focused and a hollow outline when not", () => {
    expect(composerCursorGlyph(true)).toBe("█");
    expect(composerCursorGlyph(false)).toBe("▯");
  });
});

describe("wrapComposerInput", () => {
  it("keeps a short line on one row", () => {
    expect(wrapComposerInput("scan example.com", 40)).toEqual(["scan example.com"]);
  });

  it("soft-wraps a long line onto multiple rows at word boundaries", () => {
    const rows = wrapComposerInput("the quick brown fox jumps", 10);
    expect(rows.length).toBeGreaterThan(1);
    for (const row of rows) expect(row.length).toBeLessThanOrEqual(10);
    expect(rows.join("")).toBe("the quick brown fox jumps");
  });

  it("preserves explicit newlines as row breaks", () => {
    expect(wrapComposerInput("a\nb", 40)).toEqual(["a", "b"]);
  });

  it("keeps a trailing empty line from a fresh newline", () => {
    expect(wrapComposerInput("hi\n", 40)).toEqual(["hi", ""]);
  });

  it("hard-splits a word longer than the whole row", () => {
    const rows = wrapComposerInput("abcdefghij", 4);
    expect(rows).toEqual(["abcd", "efgh", "ij"]);
    expect(rows.join("")).toBe("abcdefghij");
  });

  it("never loses content across wraps (concat invariant)", () => {
    expect(concatEquals("alpha beta gamma delta epsilon", 7)).toBe(true);
    expect(concatEquals("one   two    three", 5)).toBe(true);
    expect(concatEquals("nowhitespaceatallhere", 6)).toBe(true);
  });

  it("is total on degenerate widths", () => {
    expect(wrapComposerInput("abc", 0)).toEqual(["a", "b", "c"]);
    expect(wrapComposerInput("", 10)).toEqual([""]);
  });
});

describe("composerContentRows", () => {
  it("spills the cursor onto a fresh row when the last row is full", () => {
    const rows = composerContentRows("abcd", 4);
    expect(rows).toEqual(["abcd", ""]);
  });

  it("caps the visible rows at COMPOSER_MAX_ROWS, keeping the newest", () => {
    const text = Array.from({ length: 20 }, (_, i) => `line${i}`).join("\n");
    const rows = composerContentRows(text, 40);
    expect(rows.length).toBe(COMPOSER_MAX_ROWS);
    expect(rows[rows.length - 1]).toBe("line19");
  });

  it("is never empty", () => {
    expect(composerContentRows("", 40)).toEqual([""]);
  });
});

describe("composerRailRows", () => {
  it("holds an idle composer at the min height", () => {
    expect(composerRailRows("", 40, false)).toBe(COMPOSER_MIN_ROWS);
  });

  it("holds a short composing buffer at the min height", () => {
    expect(composerRailRows("hi", 40, true)).toBe(COMPOSER_MIN_ROWS);
  });

  it("grows with content but never past the max", () => {
    const many = Array.from({ length: 20 }, (_, i) => `l${i}`).join("\n");
    expect(composerRailRows(many, 40, true)).toBe(COMPOSER_MAX_ROWS);
  });
});
