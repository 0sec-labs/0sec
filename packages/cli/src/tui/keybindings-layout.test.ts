import { describe, expect, it } from "vitest";

import { KEYBINDINGS } from "./keybindings.js";
import {
  buildShortcutsRows,
  clipShortcutsRows,
  computeShortcutsColumns,
  computeShortcutsLayout,
  shortcutsFooterHint,
  shortcutsTitle,
  widestKeys,
  type ShortcutsLayout,
  type ShortcutsRow,
} from "./keybindings-layout.js";

const isInteger = (value: number): boolean => Number.isInteger(value) && value >= 0;

/**
 * A swept axis: every `step`th value in `[min, max]`, plus the boundary sizes
 * always tested explicitly.
 */
const sweepAxis = (min: number, max: number, step: number): number[] => {
  const seen = new Set<number>([min, min + 1, min + 2, max]);
  for (let v = min; v <= max; v += step) seen.add(v);
  return [...seen].filter((v) => v >= min && v <= max).sort((a, b) => a - b);
};

function layoutNumbers(layout: ShortcutsLayout): [string, number][] {
  return [
    ["contentWidth", layout.contentWidth],
    ["bodyRows", layout.bodyRows],
    ["pane.width", layout.pane.width],
    ["pane.innerWidth", layout.pane.innerWidth],
    ["pane.height", layout.pane.height],
    ["pane.bodyRows", layout.pane.bodyRows],
    ["columns.width", layout.columns.width],
    ["columns.keysWidth", layout.columns.keysWidth],
    ["columns.gap", layout.columns.gap],
    ["columns.descriptionWidth", layout.columns.descriptionWidth],
    ["visibleRows", layout.visibleRows],
  ];
}

describe("buildShortcutsRows", () => {
  it("emits one binding row per registry entry", () => {
    const rows = buildShortcutsRows();
    const bindingRows = rows.filter((row) => row.kind === "binding");
    expect(bindingRows.length).toBe(KEYBINDINGS.length);
  });

  it("emits a heading before each category's bindings", () => {
    const rows = buildShortcutsRows();
    const headings = rows.filter((row) => row.kind === "heading");
    // One heading per distinct category present in the registry.
    const categories = new Set(KEYBINDINGS.map((b) => b.category));
    expect(headings.length).toBe(categories.size);
    // The very first row is a heading (no leading blank).
    expect(rows[0]?.kind).toBe("heading");
  });

  it("carries keys and description on every binding row", () => {
    for (const row of buildShortcutsRows()) {
      if (row.kind !== "binding") continue;
      expect(row.keys && row.keys.length).toBeGreaterThan(0);
      expect(row.description && row.description.length).toBeGreaterThan(0);
    }
  });

  it("returns nothing for an empty registry", () => {
    expect(buildShortcutsRows([])).toEqual([]);
  });
});

describe("widestKeys", () => {
  it("returns the longest chord label among binding rows", () => {
    const rows: ShortcutsRow[] = [
      { kind: "heading", label: "X" },
      { kind: "binding", keys: "A", description: "d" },
      { kind: "binding", keys: "Ctrl+Shift+K", description: "d" },
    ];
    expect(widestKeys(rows)).toBe("Ctrl+Shift+K".length);
  });

  it("is zero with no binding rows", () => {
    expect(widestKeys([{ kind: "blank" }])).toBe(0);
  });
});

describe("computeShortcutsColumns", () => {
  it("columns plus gap always sum to exactly the inner width", () => {
    for (const width of sweepAxis(0, 200, 3)) {
      for (const maxKeys of [0, 3, 8, 22, 40]) {
        const c = computeShortcutsColumns(width, maxKeys);
        for (const [name, value] of Object.entries(c)) {
          expect(isInteger(value), `${name}@${width}/${maxKeys}`).toBe(true);
        }
        const sum = c.keysWidth + c.gap + c.descriptionWidth;
        // The zero-width case degrades to all-zero; otherwise the split is total.
        if (c.width > 0) expect(sum, `sum@${width}/${maxKeys}`).toBe(c.width);
      }
    }
  });

  it("caps the keys column and never starves the description", () => {
    const c = computeShortcutsColumns(120, 80);
    expect(c.keysWidth).toBeLessThanOrEqual(22);
    expect(c.descriptionWidth).toBeGreaterThanOrEqual(12);
  });

  it("drops the description column on a very narrow row", () => {
    const c = computeShortcutsColumns(10, 8);
    expect(c.descriptionWidth).toBe(0);
    expect(c.keysWidth).toBe(c.width);
  });
});

describe("computeShortcutsLayout", () => {
  it("never lets a column claim more than the pane's inner width", () => {
    const maxKeys = widestKeys(buildShortcutsRows());
    for (const width of sweepAxis(0, 200, 3)) {
      for (const height of sweepAxis(0, 80, 3)) {
        const layout = computeShortcutsLayout({ width, height }, maxKeys);
        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name}@${width}x${height}`).toBe(true);
        }
        // A row's columns never exceed the pane's inner width.
        expect(
          layout.columns.keysWidth + layout.columns.gap + layout.columns.descriptionWidth,
          `columns@${width}x${height}`,
        ).toBeLessThanOrEqual(layout.pane.innerWidth === 0 ? 0 : layout.pane.innerWidth);
        // The pane never claims more than the content column.
        expect(layout.pane.width, `pane.width@${width}x${height}`).toBeLessThanOrEqual(
          layout.contentWidth,
        );
        // Body rows never exceed the pane's outer height.
        expect(layout.pane.bodyRows, `pane.bodyRows@${width}x${height}`).toBeLessThanOrEqual(
          layout.pane.height,
        );
      }
    }
  });

  it("drops the border on a short terminal", () => {
    const tall = computeShortcutsLayout({ width: 120, height: 60 });
    expect(tall.bordered).toBe(true);
    const short = computeShortcutsLayout({ width: 120, height: 6 });
    expect(short.bordered).toBe(false);
  });
});

describe("clipShortcutsRows", () => {
  const rows: ShortcutsRow[] = buildShortcutsRows();

  it("returns everything when it fits", () => {
    expect(clipShortcutsRows(rows, rows.length + 5).length).toBe(rows.length);
  });

  it("clips and marks the cut", () => {
    const clipped = clipShortcutsRows(rows, 5);
    expect(clipped.length).toBe(5);
    expect(clipped[4]?.label).toMatch(/more$/);
  });

  it("returns nothing for zero visible rows", () => {
    expect(clipShortcutsRows(rows, 0)).toEqual([]);
  });
});

describe("static labels", () => {
  it("names the title and read-only footer keys", () => {
    expect(shortcutsTitle()).toBe("KEYBOARD SHORTCUTS");
    expect(shortcutsFooterHint()).toContain("esc back");
    expect(shortcutsFooterHint()).toContain("ctrl+c exit");
  });
});
