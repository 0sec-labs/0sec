import { describe, expect, it } from "vitest";

import {
  commandMenuBoxHeight,
  computeChatLayout,
  computeCommandMenuHeight,
  computeCommandMenuLayout,
} from "./chat-layout.js";

/** Terminal sizes worth caring about, plus a dense sweep for invariants. */
const WIDTHS = [20, 24, 28, 40, 60, 72, 80, 87, 88, 100, 120, 160, 200, 400];
const HEIGHTS = [10, 19, 20, 24, 40, 60];

describe("computeChatLayout", () => {
  it("never lets the header columns claim more cells than the content width", () => {
    for (const width of WIDTHS) {
      for (const height of HEIGHTS) {
        const layout = computeChatLayout({ width, height, statusTextLength: 24 });
        const claimed =
          layout.headerTargetWidth + layout.headerGap + layout.headerScopeWidth;
        expect(
          claimed,
          `header overflowed at ${width}x${height}: ${claimed} > ${layout.contentWidth}`,
        ).toBeLessThanOrEqual(layout.contentWidth);
      }
    }
  });

  it("never lets the composer footer columns overflow, for any counter length", () => {
    for (const width of WIDTHS) {
      for (const height of HEIGHTS) {
        for (const statusTextLength of [0, 8, 24, 60, 500]) {
          const layout = computeChatLayout({ width, height, statusTextLength });
          const claimed = layout.controlsWidth + layout.statusGap + layout.statusWidth;
          expect(
            claimed,
            `footer overflowed at ${width}x${height} (status ${statusTextLength}): ` +
              `${claimed} > ${layout.contentWidth}`,
          ).toBeLessThanOrEqual(layout.contentWidth);
        }
      }
    }
  });

  it("keeps the composer text and approval panels inside the content width", () => {
    for (const width of WIDTHS) {
      for (const height of HEIGHTS) {
        const layout = computeChatLayout({ width, height, statusTextLength: 24 });
        // "› " prefix plus a one-cell cursor block.
        expect(layout.composerTextWidth + 3).toBeLessThanOrEqual(
          Math.max(layout.contentWidth, 4),
        );
        expect(layout.approvalWidth).toBeLessThanOrEqual(layout.contentWidth);
      }
    }
  });

  it("always allocates at least one cell to every visible column", () => {
    for (const width of WIDTHS) {
      for (const height of HEIGHTS) {
        const layout = computeChatLayout({ width, height, statusTextLength: 24 });
        expect(layout.controlsWidth).toBeGreaterThanOrEqual(1);
        expect(layout.composerTextWidth).toBeGreaterThanOrEqual(1);
        expect(layout.approvalWidth).toBeGreaterThanOrEqual(1);
        if (!layout.compact) {
          expect(layout.headerTargetWidth).toBeGreaterThanOrEqual(1);
          expect(layout.headerScopeWidth).toBeGreaterThanOrEqual(0);
        }
      }
    }
  });

  it("drops header metadata and the counter on a compact terminal", () => {
    const layout = computeChatLayout({ width: 80, height: 24, statusTextLength: 24 });
    expect(layout.compact).toBe(true);
    expect(layout.headerTargetWidth).toBe(0);
    expect(layout.headerScopeWidth).toBe(0);
    expect(layout.headerGap).toBe(0);
    expect(layout.statusWidth).toBe(0);
    expect(layout.statusGap).toBe(0);
    // The hint then owns the whole footer row.
    expect(layout.controlsWidth).toBe(layout.contentWidth);
  });

  it("treats a short terminal as compact even when it is wide", () => {
    expect(computeChatLayout({ width: 200, height: 12, statusTextLength: 4 }).compact).toBe(
      true,
    );
  });

  it("shows both header columns and the counter on a full-size terminal", () => {
    const layout = computeChatLayout({ width: 120, height: 40, statusTextLength: 20 });
    expect(layout.compact).toBe(false);
    expect(layout.headerTargetWidth).toBeGreaterThan(0);
    expect(layout.headerScopeWidth).toBeGreaterThan(0);
    expect(layout.statusWidth).toBe(20);
    expect(layout.headerTargetWidth + layout.headerGap + layout.headerScopeWidth).toBe(
      layout.contentWidth,
    );
  });

  it("caps an unreasonably long counter instead of starving the hint", () => {
    const layout = computeChatLayout({ width: 120, height: 40, statusTextLength: 500 });
    expect(layout.statusWidth).toBeLessThanOrEqual(Math.floor(layout.contentWidth * 0.4));
    expect(layout.controlsWidth).toBeGreaterThanOrEqual(
      layout.contentWidth - layout.statusWidth - 1,
    );
  });
});

describe("computeCommandMenuLayout", () => {
  it("never lets a command row claim more cells than the menu", () => {
    for (const width of WIDTHS) {
      for (const compact of [true, false]) {
        const layout = computeCommandMenuLayout({ width, compact });
        const claimed = layout.nameWidth + layout.nameGap + layout.metaWidth;
        expect(
          claimed,
          `command row overflowed at width ${width} (compact=${compact})`,
        ).toBeLessThanOrEqual(layout.rowWidth);
        // Row plus the selector cell and its gap must fit the menu.
        expect(layout.rowWidth + 2).toBeLessThanOrEqual(Math.max(layout.innerWidth, 2));
      }
    }
  });

  it("never lets the menu header overflow", () => {
    for (const width of WIDTHS) {
      for (const compact of [true, false]) {
        const layout = computeCommandMenuLayout({ width, compact });
        const claimed =
          layout.headerTitleWidth + layout.headerGap + layout.headerQueryWidth;
        expect(claimed).toBeLessThanOrEqual(layout.innerWidth);
      }
    }
  });

  it("degrades to zero-width columns rather than negative ones", () => {
    const layout = computeCommandMenuLayout({ width: 4, compact: true });
    expect(layout.innerWidth).toBeGreaterThanOrEqual(0);
    expect(layout.rowWidth).toBeGreaterThanOrEqual(0);
    expect(layout.nameWidth).toBeGreaterThanOrEqual(0);
    expect(layout.metaWidth).toBeGreaterThanOrEqual(0);
  });
});

describe("computeCommandMenuHeight", () => {
  it("never lets the menu plus its chrome exceed a terminal that can hold it", () => {
    for (const height of [10, 16, 20, 24, 30, 40, 60, 100]) {
      for (const compact of [true, false]) {
        const rowsPerCommand = compact ? 1 : 2;
        const { maxCommands, listRows } = computeCommandMenuHeight({
          height,
          compact,
          rowsPerCommand,
        });
        // Below this the terminal cannot hold the menu at all; that case
        // is covered by the graceful-degradation test instead.
        if (listRows < rowsPerCommand) continue;
        const boxRows = commandMenuBoxHeight(maxCommands, rowsPerCommand);
        const surrounding = 1 + 2 + 5 + 3 + 1;
        expect(
          boxRows + surrounding,
          `menu overflowed at height ${height} (compact=${compact}): ` +
            `${boxRows} + ${surrounding} > ${height}`,
        ).toBeLessThanOrEqual(height);
      }
    }
  });

  it("degrades to a single entry when the terminal is too short for the menu", () => {
    // The box is rendered with an explicit height and flexShrink disabled,
    // so an unavoidable shortfall clips the menu rather than painting its
    // border through the command rows.
    for (const height of [1, 5, 10, 14]) {
      const budget = computeCommandMenuHeight({ height, compact: true, rowsPerCommand: 1 });
      expect(budget.listRows).toBe(0);
      expect(budget.maxCommands).toBe(1);
    }
  });

  it("shows more entries as the terminal gets taller", () => {
    const short = computeCommandMenuHeight({ height: 24, compact: false, rowsPerCommand: 2 });
    const tall = computeCommandMenuHeight({ height: 60, compact: false, rowsPerCommand: 2 });
    expect(tall.maxCommands).toBeGreaterThan(short.maxCommands);
  });

  it("fits more entries when each takes a single row", () => {
    const wide = computeCommandMenuHeight({ height: 40, compact: false, rowsPerCommand: 2 });
    const dense = computeCommandMenuHeight({ height: 40, compact: false, rowsPerCommand: 1 });
    expect(dense.maxCommands).toBeGreaterThan(wide.maxCommands);
  });

  it("always offers at least one entry, even on a tiny terminal", () => {
    for (const height of [1, 5, 10, 14]) {
      expect(
        computeCommandMenuHeight({ height, compact: true, rowsPerCommand: 1 }).maxCommands,
      ).toBeGreaterThanOrEqual(1);
    }
  });

  it("counts the box as chrome plus its rows", () => {
    expect(commandMenuBoxHeight(0, 2)).toBe(4);
    expect(commandMenuBoxHeight(3, 2)).toBe(10);
    expect(commandMenuBoxHeight(3, 1)).toBe(7);
  });
});
