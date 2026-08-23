import { describe, expect, it } from "vitest";
import { budgetSidebarRows, todoTextWidth } from "./todos-sidebar-layout.js";
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
