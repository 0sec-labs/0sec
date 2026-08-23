import { describe, expect, it } from "vitest";
import {
  budgetSidebarRows,
  budgetWrappedRows,
  todoTextWidth,
  wrapCells,
} from "./todos-sidebar-layout.js";
import { fitTuiText } from "../text.js";

describe("budgetSidebarRows", () => {
  it("shows everything when the list fits, with no tail", () => {
    expect(budgetSidebarRows(3, 5)).toEqual({ visible: 3, overflow: 0 });
    expect(budgetSidebarRows(5, 5)).toEqual({ visible: 5, overflow: 0 });
    expect(budgetSidebarRows(0, 5)).toEqual({ visible: 0, overflow: 0 });
  });

  it("reserves one row for the tail when the list overflows", () => {
    // 5 rows, 8 items → 4 visible + a "+4 more" tail = 5 painted rows.
    expect(budgetSidebarRows(8, 5)).toEqual({ visible: 4, overflow: 4 });
  });

  it("hides everything into the tail when only one row is available", () => {
    expect(budgetSidebarRows(8, 1)).toEqual({ visible: 0, overflow: 8 });
  });

  it("paints nothing when there are no rows", () => {
    expect(budgetSidebarRows(8, 0)).toEqual({ visible: 0, overflow: 8 });
  });

  it("sweep: rows painted never exceed the budget and counts are conserved", () => {
    for (let count = 0; count <= 60; count++) {
      for (let rows = 0; rows <= 25; rows++) {
        const { visible, overflow } = budgetSidebarRows(count, rows);
        const painted = visible + (overflow > 0 ? 1 : 0);
        // With no rows granted nothing is painted (all items report as
        // overflow); the tail row only exists when there is a row to hold it.
        if (rows > 0) expect(painted).toBeLessThanOrEqual(rows);
        else expect(visible).toBe(0);
        expect(visible).toBeGreaterThanOrEqual(0);
        expect(overflow).toBeGreaterThanOrEqual(0);
        expect(visible + overflow).toBe(count);
      }
    }
  });
});

describe("todoTextWidth", () => {
  it("reserves the glyph cell and its gap", () => {
    expect(todoTextWidth(24)).toBe(22);
    expect(todoTextWidth(32)).toBe(30);
  });

  it("never returns less than one cell", () => {
    expect(todoTextWidth(2)).toBe(1);
    expect(todoTextWidth(1)).toBe(1);
    expect(todoTextWidth(0)).toBe(1);
  });

  it("sweep: fitted todo text never exceeds the row's text width", () => {
    const sample =
      "Enumerate the authentication surface and map every unauthenticated endpoint";
    for (let width = 1; width <= 40; width++) {
      const textWidth = todoTextWidth(width);
      const fitted = fitTuiText(sample, textWidth);
      expect(fitted.length).toBeLessThanOrEqual(textWidth);
      // The whole row (glyph + gap + text) never exceeds the column.
      expect(1 + 1 + fitted.length).toBeLessThanOrEqual(Math.max(3, width));
    }
  });
});

describe("wrapCells", () => {
  it("keeps a short title on a single row, unbroken", () => {
    expect(wrapCells("short title", 20, 2)).toEqual(["short title"]);
  });

  it("wraps on a word boundary across two rows without splitting a word", () => {
    const lines = wrapCells("unsafe tar extraction of attacker archive", 14, 2);
    expect(lines.length).toBeLessThanOrEqual(2);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(14);
    // No line starts or ends with a stray space; words stay intact where they fit.
    for (const line of lines) expect(line).toBe(line.trim());
  });

  it("ellipsises the last row when content remains beyond maxLines", () => {
    const lines = wrapCells(
      "patch archive extraction to reject path traversal entries entirely now",
      12,
      2,
    );
    expect(lines).toHaveLength(2);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(12);
    expect(lines[1].endsWith("...")).toBe(true);
  });

  it("hard-splits a word longer than the width", () => {
    const lines = wrapCells("supercalifragilisticexpialidocious", 6, 2);
    expect(lines[0].length).toBeLessThanOrEqual(6);
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(6);
  });

  it("honours a narrower first row for a trailing badge", () => {
    const lines = wrapCells("directory traversal in archive handler", 18, 2, 12);
    expect(lines[0].length).toBeLessThanOrEqual(12);
    for (let i = 1; i < lines.length; i++) expect(lines[i].length).toBeLessThanOrEqual(18);
  });

  it("always returns at least one row", () => {
    expect(wrapCells("", 10, 2)).toEqual([""]);
    expect(wrapCells("   ", 10, 2)).toEqual([""]);
  });

  it("sweep: every wrapped row fits its width and rows never exceed maxLines", () => {
    const samples = [
      "Unsafe tar extraction of attacker-controlled archive leads to RCE",
      "patch archive extraction to reject path traversal entries",
      "SSRF",
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];
    for (const sample of samples) {
      for (let width = 1; width <= 40; width++) {
        for (let maxLines = 1; maxLines <= 3; maxLines++) {
          for (const first of [width, Math.max(1, width - 5)]) {
            const lines = wrapCells(sample, width, maxLines, first);
            expect(lines.length).toBeGreaterThanOrEqual(1);
            expect(lines.length).toBeLessThanOrEqual(maxLines);
            lines.forEach((line, idx) => {
              const limit = idx === 0 ? first : width;
              expect(line.length).toBeLessThanOrEqual(limit);
            });
          }
        }
      }
    }
  });
});

describe("budgetWrappedRows", () => {
  it("shows everything when the total row cost fits, with no tail", () => {
    expect(budgetWrappedRows([1, 2, 1], 5)).toEqual({ visible: 3, overflow: 0 });
    expect(budgetWrappedRows([2, 2], 4)).toEqual({ visible: 2, overflow: 0 });
    expect(budgetWrappedRows([], 5)).toEqual({ visible: 0, overflow: 0 });
  });

  it("reserves one row for the tail when items overflow the budget", () => {
    // 5 rows, items costing 2+2+2 → two fit (4 rows) + a tail row = 5 painted.
    expect(budgetWrappedRows([2, 2, 2], 5)).toEqual({ visible: 2, overflow: 1 });
    // 4 rows, same items → only one fits beside the tail (2 + 1 = 3 ≤ 4).
    expect(budgetWrappedRows([2, 2, 2], 4)).toEqual({ visible: 1, overflow: 2 });
  });

  it("paints nothing but the tail when the first item cannot fit beside it", () => {
    expect(budgetWrappedRows([2, 2], 2)).toEqual({ visible: 0, overflow: 2 });
  });

  it("paints nothing when there are no rows", () => {
    expect(budgetWrappedRows([1, 2], 0)).toEqual({ visible: 0, overflow: 2 });
  });

  it("sweep: rows painted never exceed the budget and counts are conserved", () => {
    const costLists = [
      [1, 1, 1, 1, 1, 1, 1, 1],
      [2, 2, 2, 2, 2, 2],
      [1, 2, 1, 2, 1, 2, 1],
      [2, 1, 1, 2, 2, 1, 1, 2, 2],
    ];
    for (const costs of costLists) {
      for (let rows = 0; rows <= 20; rows++) {
        const { visible, overflow } = budgetWrappedRows(costs, rows);
        const paintedItemRows = costs
          .slice(0, visible)
          .reduce((acc, c) => acc + c, 0);
        const painted = paintedItemRows + (overflow > 0 ? 1 : 0);
        if (rows > 0) expect(painted).toBeLessThanOrEqual(rows);
        else expect(visible).toBe(0);
        expect(visible).toBeGreaterThanOrEqual(0);
        expect(overflow).toBeGreaterThanOrEqual(0);
        expect(visible + overflow).toBe(costs.length);
      }
    }
  });
});
