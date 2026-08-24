import { describe, expect, it } from "vitest";

import {
  computeKvSplit,
  computeListWindow,
  computePaneSplit,
  paneTitleColumns,
  type KvSplitConfig,
  type PaneSplitConfig,
} from "./pane-layout.js";

// A representative split config (the connect screen's real tuning).
const SPLIT: PaneSplitConfig = {
  twoPaneMinWidth: 76,
  detailMinWidth: 30,
  detailMaxWidth: 56,
  detailWidthShare: 0.44,
  listMinWidth: 34,
  borderedMinRows: 12,
  stackedDetailShare: 0.4,
  stackedDetailMaxRows: 10,
};

const KV: KvSplitConfig = {
  minRoom: 14,
  labelMinWidth: 6,
  labelMaxWidth: 12,
  valueWidthShare: 0.6,
};

type Row = { kind?: string };

function headings(pattern: ("heading" | "item")[]): Row[] {
  return pattern.map((kind) => ({ kind }));
}

describe("computeListWindow", () => {
  it("returns an empty window when nothing is visible", () => {
    const rows = headings(["item", "item", "item"]);
    expect(computeListWindow({ rows, selected: 0, visible: 0 })).toEqual({
      start: 0,
      end: 0,
      count: 0,
      total: 3,
      hasAbove: true,
      hasBelow: false,
    });
  });

  it("keeps count within the visible capacity and inside the row bounds", () => {
    const rows = headings(Array.from({ length: 20 }, () => "item"));
    for (let visible = 1; visible <= 12; visible++) {
      for (let selected = 0; selected < rows.length; selected++) {
        const w = computeListWindow({ rows, selected, visible });
        expect(w.count).toBeLessThanOrEqual(visible);
        expect(w.count).toBe(w.end - w.start);
        expect(w.start).toBeGreaterThanOrEqual(0);
        expect(w.end).toBeLessThanOrEqual(rows.length);
        // The cursor is always inside the window it produces.
        expect(selected).toBeGreaterThanOrEqual(w.start);
        expect(selected).toBeLessThan(w.end);
        expect(w.hasAbove).toBe(w.start > 0);
        expect(w.hasBelow).toBe(w.end < rows.length);
      }
    }
  });

  it("pulls the window up to keep a group heading on screen", () => {
    // Row 5 is a heading; row 6 is its first item. Selecting row 6 should pull
    // the heading (row 5) into view when there is room for at least two rows.
    const rows = headings([
      "heading",
      "item",
      "item",
      "item",
      "item",
      "heading",
      "item",
      "item",
    ]);
    const w = computeListWindow({ rows, selected: 6, visible: 3, anchor: 6 });
    expect(w.start).toBe(5);
    expect(w.start).toBeLessThanOrEqual(5);
  });

  it("does not pull the heading up when capacity is a single row", () => {
    const rows = headings(["heading", "item"]);
    const w = computeListWindow({ rows, selected: 1, visible: 1, anchor: 1 });
    expect(w.start).toBe(1);
    expect(w.count).toBe(1);
  });

  it("scrolls from the anchor rather than re-centring", () => {
    const rows = headings(Array.from({ length: 30 }, () => "item"));
    const w = computeListWindow({ rows, selected: 10, visible: 5, anchor: 8 });
    // The cursor already sits inside [anchor, anchor+capacity), so the window
    // stays anchored instead of centring on the cursor.
    expect(w.start).toBe(8);
  });

  it("degrades garbage geometry to a safe empty window", () => {
    const rows = headings(["item", "item"]);
    const w = computeListWindow({ rows, selected: Number.NaN, visible: Number.NaN });
    expect(w).toEqual({
      start: 0,
      end: 0,
      count: 0,
      total: 2,
      hasAbove: true,
      hasBelow: false,
    });
  });
});

describe("computePaneSplit", () => {
  it("never lets the panes overflow the content column", () => {
    for (let contentWidth = 0; contentWidth <= 160; contentWidth += 1) {
      for (const bodyRows of [0, 1, 5, 11, 12, 20, 40]) {
        const s = computePaneSplit(contentWidth, bodyRows, SPLIT);
        expect(s.contentWidth).toBe(contentWidth);
        expect(s.bodyRows).toBe(bodyRows);
        // Every pane dimension is a non-negative integer.
        for (const pane of [s.list, s.detail]) {
          expect(pane.width).toBeGreaterThanOrEqual(0);
          expect(pane.height).toBeGreaterThanOrEqual(0);
          expect(pane.innerWidth).toBeGreaterThanOrEqual(0);
          expect(pane.bodyRows).toBeGreaterThanOrEqual(0);
          expect(Number.isInteger(pane.width)).toBe(true);
          expect(Number.isInteger(pane.innerWidth)).toBe(true);
        }
        // Side by side, the two panes plus their gap fit the content column.
        if (!s.stacked && s.list.width > 0 && s.detail.width > 0) {
          expect(s.list.width + s.detail.width + s.paneGap).toBeLessThanOrEqual(contentWidth);
        }
      }
    }
  });

  it("stacks when the content column is below the two-pane minimum", () => {
    const s = computePaneSplit(SPLIT.twoPaneMinWidth - 1, 40, SPLIT);
    expect(s.stacked).toBe(true);
    // A stacked layout carries no horizontal gap between list and detail.
    expect(s.paneGap).toBe(0);
  });

  it("splits into two panes when wide and tall enough", () => {
    const s = computePaneSplit(120, 40, SPLIT);
    expect(s.stacked).toBe(false);
    expect(s.bordered).toBe(true);
    expect(s.detail.width).toBeGreaterThanOrEqual(SPLIT.detailMinWidth);
    expect(s.detail.width).toBeLessThanOrEqual(SPLIT.detailMaxWidth + 4); // + border chrome
    expect(s.paneGap).toBe(1);
  });

  it("drops borders on a short terminal", () => {
    const s = computePaneSplit(120, SPLIT.borderedMinRows - 1, SPLIT);
    expect(s.bordered).toBe(false);
  });

  it("honours the detail width share and max cap", () => {
    // Very wide: the detail pane is bounded by detailMaxWidth (+ chrome), not the share.
    const s = computePaneSplit(400, 40, SPLIT);
    expect(s.detail.innerWidth).toBeLessThanOrEqual(SPLIT.detailMaxWidth);
  });
});

describe("computeKvSplit", () => {
  it("claims exactly its width whenever a value column survives", () => {
    for (let width = 0; width <= 120; width++) {
      const kv = computeKvSplit(width, KV);
      expect(kv.width).toBe(Math.max(0, width));
      expect(kv.labelWidth).toBeGreaterThanOrEqual(0);
      expect(kv.valueWidth).toBeGreaterThanOrEqual(0);
      if (kv.valueWidth > 0) {
        // label + gap + value sum to exactly the row width — no under-claim, no overflow.
        expect(kv.labelWidth + kv.gap + kv.valueWidth).toBe(kv.width);
        expect(kv.gap).toBe(1);
        expect(kv.labelWidth).toBeLessThanOrEqual(KV.labelMaxWidth);
      } else {
        expect(kv.gap).toBe(0);
      }
    }
  });

  it("drops the value column below the minimum room", () => {
    const kv = computeKvSplit(KV.minRoom - 1, KV);
    expect(kv.valueWidth).toBe(0);
    expect(kv.labelWidth).toBe(KV.minRoom - 1);
  });

  it("degrades a zero-width row to all zeros", () => {
    expect(computeKvSplit(0, KV)).toEqual({ width: 0, labelWidth: 0, gap: 0, valueWidth: 0 });
  });
});

describe("paneTitleColumns", () => {
  it("sums to exactly the inner width and never starves the title", () => {
    for (let width = 0; width <= 120; width++) {
      for (const metaLen of [0, 1, 3, 8, 40, 200]) {
        const cols = paneTitleColumns(width, metaLen);
        expect(cols.titleWidth + cols.gap + cols.metaWidth).toBe(Math.max(0, width));
        if (cols.metaWidth > 0) {
          expect(cols.metaWidth).toBeLessThanOrEqual(Math.floor(width / 2));
          expect(cols.gap).toBe(1);
          expect(cols.titleWidth).toBeGreaterThanOrEqual(1);
        } else {
          expect(cols.gap).toBe(0);
        }
      }
    }
  });

  it("returns all zeros for a zero-width row", () => {
    expect(paneTitleColumns(0, 5)).toEqual({ titleWidth: 0, gap: 0, metaWidth: 0 });
  });

  it("keeps the whole row for the title when no meta is asked for", () => {
    expect(paneTitleColumns(40, 0)).toEqual({ titleWidth: 40, gap: 0, metaWidth: 0 });
  });
});
