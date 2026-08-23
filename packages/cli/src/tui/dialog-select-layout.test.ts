import { describe, expect, it } from "vitest";

import {
  buildDialogRows,
  clampDialogSelection,
  computeDialogPanel,
  dialogColumnsWidth,
  dialogDisplayIndex,
  dialogRowColumns,
  dialogWindow,
  filterDialogItems,
  firstEnabled,
  moveDialogSelection,
  rankDialogItem,
  type DialogItem,
  type DialogSize,
} from "./dialog-select-layout.js";

const SIZES: DialogSize[] = ["small", "medium", "large"];

function items(n: number, withCategory = false): DialogItem[] {
  // Categories are contiguous (as real callers pre-group them): the first
  // third in group-0, the next in group-1, the rest in group-2.
  return Array.from({ length: n }, (_, i) => ({
    id: `id-${i}`,
    label: `label ${i}`,
    description: i % 2 === 0 ? `description ${i}` : undefined,
    meta: `meta-${i}`,
    category: withCategory ? `group-${Math.floor(i / Math.max(1, Math.ceil(n / 3)))}` : undefined,
    current: i === 0,
  }));
}

// ---------------------------------------------------------------------------
// Fuzzy filter
// ---------------------------------------------------------------------------

describe("filterDialogItems", () => {
  it("keeps input order for an empty query", () => {
    const list = items(4);
    expect(filterDialogItems(list, "").map((i) => i.id)).toEqual(list.map((i) => i.id));
    expect(filterDialogItems(list, "   ").map((i) => i.id)).toEqual(list.map((i) => i.id));
  });

  it("weights a label match over a category match", () => {
    const list: DialogItem[] = [
      { id: "cat", label: "something else", category: "gpt models" },
      { id: "lbl", label: "gpt-5", category: "openai" },
    ];
    // "gpt" is a prefix of the label of `lbl` and only in the category of `cat`.
    expect(filterDialogItems(list, "gpt")[0]?.id).toBe("lbl");
  });

  it("ranks a substring ahead of a subsequence in the same field", () => {
    const list: DialogItem[] = [
      { id: "seq", label: "g p t 5" },
      { id: "sub", label: "gpt-5" },
    ];
    expect(filterDialogItems(list, "gpt")[0]?.id).toBe("sub");
  });

  it("finds subsequence matches", () => {
    const list: DialogItem[] = [{ id: "a", label: "gpt-5.5" }];
    expect(filterDialogItems(list, "g55").map((i) => i.id)).toEqual(["a"]);
    expect(rankDialogItem(list[0]!, "zzz")).toBe(Number.POSITIVE_INFINITY);
  });

  it("drops non-matching items", () => {
    const list = items(5);
    expect(filterDialogItems(list, "label 2").map((i) => i.id)).toEqual(["id-2"]);
    expect(filterDialogItems(list, "nope")).toHaveLength(0);
  });

  it("breaks ties by input order", () => {
    const list: DialogItem[] = [
      { id: "b", label: "match b" },
      { id: "a", label: "match a" },
    ];
    // Both are label prefixes of "match"; input order wins.
    expect(filterDialogItems(list, "match").map((i) => i.id)).toEqual(["b", "a"]);
  });
});

// ---------------------------------------------------------------------------
// Row assembly & navigation
// ---------------------------------------------------------------------------

describe("buildDialogRows", () => {
  it("emits no headers when nothing has a category", () => {
    const rows = buildDialogRows(items(3));
    expect(rows.every((r) => r.kind === "item")).toBe(true);
  });

  it("emits one header per category in first-seen order", () => {
    const rows = buildDialogRows(items(6, true));
    const headers = rows.filter((r) => r.kind === "header");
    expect(headers.map((h) => (h.kind === "header" ? h.category : ""))).toEqual([
      "group-0",
      "group-1",
      "group-2",
    ]);
  });

  it("carries the source item index on each item row", () => {
    const rows = buildDialogRows(items(4, true));
    const itemRows = rows.filter((r) => r.kind === "item");
    expect(itemRows.map((r) => (r.kind === "item" ? r.itemIndex : -1))).toEqual([0, 1, 2, 3]);
    expect(dialogDisplayIndex(rows, 2)).toBeGreaterThanOrEqual(0);
    expect(rows[dialogDisplayIndex(rows, 2)]).toMatchObject({ kind: "item", itemIndex: 2 });
    expect(dialogDisplayIndex(rows, 99)).toBe(-1);
  });
});

describe("navigation", () => {
  it("skips disabled rows and wraps", () => {
    const list: DialogItem[] = [
      { id: "a", label: "a" },
      { id: "b", label: "b", disabled: true },
      { id: "c", label: "c" },
    ];
    expect(moveDialogSelection(list, 0, 1)).toBe(2); // skip disabled b
    expect(moveDialogSelection(list, 2, 1)).toBe(0); // wrap
    expect(moveDialogSelection(list, 0, -1)).toBe(2); // wrap backwards
    expect(firstEnabled(list)).toBe(0);
  });

  it("holds still when every row is disabled", () => {
    const list: DialogItem[] = [{ id: "a", label: "a", disabled: true }];
    expect(moveDialogSelection(list, 0, 1)).toBe(0);
    expect(firstEnabled(list)).toBe(0);
  });

  it("clamps a stale index onto an enabled row", () => {
    const list: DialogItem[] = [
      { id: "a", label: "a" },
      { id: "b", label: "b", disabled: true },
    ];
    expect(clampDialogSelection(list, 99)).toBe(0);
    expect(clampDialogSelection(list, 1)).toBe(0); // b disabled -> seek next enabled
    expect(clampDialogSelection([], 3)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Sweep: geometry & columns never overflow the panel
// ---------------------------------------------------------------------------

describe("panel / column sweep", () => {
  it("keeps panelWidth <= width and column sums <= rowWidth <= innerWidth for every size and shape", () => {
    for (let width = 0; width <= 200; width += 3) {
      for (let height = 4; height <= 80; height += 6) {
        for (const size of SIZES) {
          for (const total of [0, 1, 40, 500]) {
            for (const withDetail of [false, true]) {
              const panel = computeDialogPanel({ width, height, size, totalRows: total, withDetail });

              expect(panel.panelWidth).toBeLessThanOrEqual(Math.max(1, width));
              expect(panel.left).toBeGreaterThanOrEqual(0);
              expect(panel.left + panel.panelWidth).toBeLessThanOrEqual(Math.max(1, width));
              expect(panel.innerWidth).toBeLessThanOrEqual(panel.panelWidth);
              expect(panel.rowWidth).toBeGreaterThanOrEqual(1);
              expect(panel.rowWidth).toBeLessThanOrEqual(panel.innerWidth);
              expect(panel.visibleRows).toBeGreaterThanOrEqual(1);
              expect(panel.visibleRows).toBeLessThanOrEqual(panel.capacityRows);
              expect(panel.top).toBeGreaterThanOrEqual(0);

              // The list column and the detail column (plus their gap) sum to at
              // most the inner width — no column ever overlaps its neighbour.
              expect(panel.listWidth).toBeGreaterThanOrEqual(1);
              expect(panel.listWidth).toBeLessThanOrEqual(panel.innerWidth);
              expect(panel.detailWidth).toBeGreaterThanOrEqual(0);
              expect(panel.detailGap).toBeGreaterThanOrEqual(0);
              expect(panel.rowWidth).toBeLessThanOrEqual(panel.listWidth);
              expect(panel.listWidth + panel.detailGap + panel.detailWidth).toBeLessThanOrEqual(
                panel.innerWidth,
              );
              if (panel.showDetail) {
                // Detail on: the split fills the inner width exactly and both
                // columns clear their floors.
                expect(panel.detailWidth).toBeGreaterThanOrEqual(30);
                expect(panel.detailGap).toBeGreaterThanOrEqual(1);
                expect(panel.listWidth + panel.detailGap + panel.detailWidth).toBe(panel.innerWidth);
              } else {
                // Detail off (never asked for, or hidden on a narrow terminal):
                // the list owns the whole inner width, exactly as before.
                expect(panel.detailWidth).toBe(0);
                expect(panel.detailGap).toBe(0);
                expect(panel.listWidth).toBe(panel.innerWidth);
              }

              for (const hasGutter of [false, true]) {
                for (const hasDescription of [false, true]) {
                  for (const metaContentWidth of [0, 3, 40, panel.rowWidth + 10]) {
                    const cols = dialogRowColumns({
                      rowWidth: panel.rowWidth,
                      hasGutter,
                      metaContentWidth,
                      hasDescription,
                    });
                    const sum = dialogColumnsWidth(cols);
                    expect(sum).toBeLessThanOrEqual(panel.rowWidth);
                    for (const v of Object.values(cols)) expect(v).toBeGreaterThanOrEqual(0);
                  }
                }
              }
            }
          }
        }
      }
    }
  });

  it("shows a detail column on a wide terminal and hides it below a min width", () => {
    // Wide: two columns, promoted to at least the large band, summing exactly.
    const wide = computeDialogPanel({ width: 120, height: 40, size: "medium", totalRows: 40, withDetail: true });
    expect(wide.showDetail).toBe(true);
    expect(wide.panelWidth).toBe(116); // promoted from medium(88) to large(116)
    expect(wide.detailWidth).toBeGreaterThanOrEqual(30);
    expect(wide.listWidth + wide.detailGap + wide.detailWidth).toBe(wide.innerWidth);

    // 80x24 still splits without overflowing.
    const std = computeDialogPanel({ width: 80, height: 24, size: "large", totalRows: 40, withDetail: true });
    expect(std.showDetail).toBe(true);
    expect(std.left + std.panelWidth).toBeLessThanOrEqual(80);
    expect(std.listWidth + std.detailGap + std.detailWidth).toBe(std.innerWidth);

    // Narrow: the split cannot keep both columns above their floors, so the
    // detail is hidden and the list takes the whole inner width.
    const narrow = computeDialogPanel({ width: 56, height: 24, size: "large", totalRows: 40, withDetail: true });
    expect(narrow.showDetail).toBe(false);
    expect(narrow.detailWidth).toBe(0);
    expect(narrow.listWidth).toBe(narrow.innerWidth);
    expect(narrow.left + narrow.panelWidth).toBeLessThanOrEqual(56);
  });

  it("is unchanged from list-only when no detail is requested", () => {
    const a = computeDialogPanel({ width: 120, height: 40, size: "medium", totalRows: 3 });
    const b = computeDialogPanel({ width: 120, height: 40, size: "medium", totalRows: 3, withDetail: false });
    expect(a).toEqual(b);
    expect(a.showDetail).toBe(false);
    expect(a.listWidth).toBe(a.innerWidth);
    expect(a.rowWidth).toBe(a.innerWidth); // no scrollbar reserved for a short list
  });

  it("gives each size its expected max inner width on a wide terminal", () => {
    expect(computeDialogPanel({ width: 300, height: 60, size: "small", totalRows: 10 }).panelWidth).toBe(60);
    expect(computeDialogPanel({ width: 300, height: 60, size: "medium", totalRows: 10 }).panelWidth).toBe(88);
    expect(computeDialogPanel({ width: 300, height: 60, size: "large", totalRows: 10 }).panelWidth).toBe(116);
  });

  it("reserves a scrollbar column only when the list overflows", () => {
    const few = computeDialogPanel({ width: 120, height: 40, size: "medium", totalRows: 3 });
    expect(few.scrolls).toBe(false);
    expect(few.rowWidth).toBe(few.innerWidth);

    const many = computeDialogPanel({ width: 120, height: 40, size: "medium", totalRows: 5000 });
    expect(many.scrolls).toBe(true);
    expect(many.rowWidth).toBe(many.innerWidth - 1);
  });

  it("does not overflow at 80x24 or 120x40", () => {
    for (const [w, h] of [
      [80, 24],
      [120, 40],
    ]) {
      const panel = computeDialogPanel({ width: w, height: h, size: "medium", totalRows: 100 });
      expect(panel.left + panel.panelWidth).toBeLessThanOrEqual(w);
      expect(panel.top + panel.visibleRows).toBeLessThanOrEqual(h);
    }
  });
});

// ---------------------------------------------------------------------------
// Sweep: the window always contains the selection
// ---------------------------------------------------------------------------

describe("dialogWindow", () => {
  it("keeps the selected item's display row inside the window across sizes and heights", () => {
    for (const withCategory of [false, true]) {
      const list = items(60, withCategory);
      const rows = buildDialogRows(list);
      for (let maxRows = 1; maxRows <= 30; maxRows += 1) {
        for (let selected = 0; selected < list.length; selected += 1) {
          const displayRow = dialogDisplayIndex(rows, selected);
          const win = dialogWindow(rows, displayRow, maxRows);
          expect(displayRow).toBeGreaterThanOrEqual(win.start);
          expect(displayRow).toBeLessThan(win.end);
          expect(win.end - win.start).toBeLessThanOrEqual(Math.min(maxRows, rows.length));
          expect(win.start).toBeGreaterThanOrEqual(0);
          expect(win.end).toBeLessThanOrEqual(rows.length);
        }
      }
    }
  });

  it("pulls in the heading above the cursor when there is room", () => {
    const rows = buildDialogRows(items(9, true));
    // Find an item that sits directly under a header.
    const under = rows.findIndex((r, i) => r.kind === "item" && rows[i - 1]?.kind === "header");
    const win = dialogWindow(rows, under, 4);
    expect(win.start).toBe(under - 1); // heading included
  });

  it("keeps the cursor over the heading when capacity is one", () => {
    const rows = buildDialogRows(items(9, true));
    const under = rows.findIndex((r, i) => r.kind === "item" && rows[i - 1]?.kind === "header");
    const win = dialogWindow(rows, under, 1);
    expect(win.start).toBe(under); // cursor kept, heading dropped
    expect(win.end).toBe(under + 1);
  });

  it("returns an empty window for zero rows or zero capacity", () => {
    expect(dialogWindow([], 0, 5)).toMatchObject({ start: 0, end: 0 });
    expect(dialogWindow(buildDialogRows(items(3)), 0, 0)).toMatchObject({ start: 0, end: 0 });
  });
});
