import { describe, expect, it } from "vitest";

import {
  actionHint,
  buildMarketItems,
  buildMarketRows,
  clampSelection,
  clipMarketDetailLines,
  computeMarketLayout,
  computeMarketWindow,
  firstSelectableIndex,
  indexOfItem,
  isFilterKey,
  lastSelectableIndex,
  marketDetailLines,
  marketEmptyLines,
  marketFooterHint,
  marketListHeading,
  marketListTitle,
  paneTitleColumns,
  moveSelection,
  stateTag,
  type MarketItem,
  type MarketLayout,
  type MarketRegistryView,
  type MarketRow,
  type MarketState,
} from "./market-layout.js";
import { shellChromeRows } from "./settings-layout.js";

const isInteger = (value: number): boolean => Number.isInteger(value) && value >= 0;

/** A representative registry: two plugins, two themes, plus noise to be dropped. */
const REGISTRY: MarketRegistryView = {
  entries: [
    {
      id: "acme.scanner",
      version: "1.2.0",
      manifest: {
        name: "Acme Scanner",
        tools: [
          { name: "scan", description: "scan a thing" },
          { name: "probe", description: "probe a thing" },
        ],
      },
      capabilities: ["network", "filesystem-read"],
      signatureState: "unverified",
    },
    {
      id: "beta.reporter",
      version: "0.3.1",
      manifest: { name: "Beta Reporter", tools: [{ name: "report", description: "write a report" }] },
      capabilities: ["findings-write"],
      signatureState: "verified",
    },
  ],
  artifacts: [
    {
      kind: "theme",
      id: "acme.midnight",
      version: "1.0.0",
      manifest: {
        name: "Acme Midnight",
        theme: { label: "Midnight", description: "A dark, low-glare palette." },
      },
      signatureState: "unverified",
    },
    {
      kind: "theme",
      id: "acme.daybreak",
      version: "2.0.0",
      manifest: { name: "Acme Daybreak", theme: { label: "Daybreak", description: "A light palette." } },
      signatureState: "verified",
    },
    // Noise: a config artifact and a malformed entry — both must be dropped.
    { kind: "config", id: "acme.config", version: "1.0.0", manifest: { name: "cfg" } },
    { kind: "theme", id: "", version: "1.0.0", manifest: { theme: { label: "nameless" } } },
  ],
};

const ITEMS = buildMarketItems(REGISTRY);
const ROWS = buildMarketRows({ view: REGISTRY });

/** Every cell and row count a layout exposes, flattened for the sweep. */
function layoutNumbers(layout: MarketLayout): [string, number][] {
  return [
    ["contentWidth", layout.contentWidth],
    ["bodyRows", layout.bodyRows],
    ["paneGap", layout.paneGap],
    ["list.width", layout.list.width],
    ["list.innerWidth", layout.list.innerWidth],
    ["list.height", layout.list.height],
    ["list.bodyRows", layout.list.bodyRows],
    ["detail.width", layout.detail.width],
    ["detail.innerWidth", layout.detail.innerWidth],
    ["detail.height", layout.detail.height],
    ["detail.bodyRows", layout.detail.bodyRows],
    ["row.width", layout.row.width],
    ["row.markerWidth", layout.row.markerWidth],
    ["row.markerGap", layout.row.markerGap],
    ["row.labelWidth", layout.row.labelWidth],
    ["row.versionGap", layout.row.versionGap],
    ["row.versionWidth", layout.row.versionWidth],
    ["row.stateGap", layout.row.stateGap],
    ["row.stateWidth", layout.row.stateWidth],
    ["heading.width", layout.heading.width],
    ["heading.labelWidth", layout.heading.labelWidth],
    ["heading.gap", layout.heading.gap],
    ["heading.countWidth", layout.heading.countWidth],
    ["visibleRows", layout.visibleRows],
  ];
}

// ---------------------------------------------------------------------------

describe("computeMarketLayout — the sweep", () => {
  /**
   * The invariant this whole module exists for: no allocation may exceed the
   * container it was carved out of, on either axis, at any terminal size. Yoga
   * does not clip; it shrinks siblings and paints them over one another, and a
   * box one row short of its content paints its own border through that content.
   * Both are silent at compile time.
   */
  it("never lets a pane, a row or a column exceed what it was given", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        for (const noticeRows of [0, 1]) {
          const layout = computeMarketLayout({ width, height, noticeRows });
          const at = `${width}x${height} (notice ${noticeRows})`;

          for (const [name, value] of layoutNumbers(layout)) {
            expect(isInteger(value), `${name} was ${value} at ${at}`).toBe(true);
          }

          // -- horizontal --
          expect(layout.contentWidth, `contentWidth exceeded width at ${at}`).toBeLessThanOrEqual(
            Math.max(0, width),
          );
          if (layout.stacked) {
            expect(layout.list.width, `stacked list too wide at ${at}`).toBeLessThanOrEqual(
              layout.contentWidth,
            );
            expect(layout.detail.width, `stacked detail too wide at ${at}`).toBeLessThanOrEqual(
              layout.contentWidth,
            );
            expect(layout.paneGap, `stacked panes had a horizontal gap at ${at}`).toBe(0);
          } else {
            const claimed = layout.list.width + layout.paneGap + layout.detail.width;
            expect(
              claimed,
              `panes claimed ${claimed} of ${layout.contentWidth} at ${at}`,
            ).toBeLessThanOrEqual(layout.contentWidth);
          }

          // -- list row columns --
          const row = layout.row;
          expect(row.width, `row wider than the list pane at ${at}`).toBe(layout.list.innerWidth);
          const rowClaimed =
            row.markerWidth +
            row.markerGap +
            row.labelWidth +
            row.versionGap +
            row.versionWidth +
            row.stateGap +
            row.stateWidth;
          expect(rowClaimed, `row claimed ${rowClaimed} of ${row.width} at ${at}`).toBe(row.width);

          // -- kind heading columns --
          const heading = layout.heading;
          expect(heading.width, `heading wider than the list pane at ${at}`).toBe(
            layout.list.innerWidth,
          );
          const headingClaimed = heading.labelWidth + heading.gap + heading.countWidth;
          expect(
            headingClaimed,
            `heading claimed ${headingClaimed} of ${heading.width} at ${at}`,
          ).toBe(heading.width);
          if (heading.countWidth > 0) {
            expect(heading.gap, `heading count had no gap at ${at}`).toBe(1);
            expect(heading.labelWidth, `heading label squeezed out at ${at}`).toBeGreaterThan(0);
          }
          if (row.versionWidth === 0) {
            expect(row.versionGap, `version gap outlived the version at ${at}`).toBe(0);
          }
          if (row.stateWidth === 0) {
            expect(row.stateGap, `state gap outlived the state at ${at}`).toBe(0);
          }

          // -- vertical --
          expect(layout.list.height, `list taller than the body at ${at}`).toBeLessThanOrEqual(
            layout.bodyRows,
          );
          expect(layout.detail.height, `detail taller than the body at ${at}`).toBeLessThanOrEqual(
            layout.bodyRows,
          );
          if (layout.stacked) {
            const rows = layout.list.height + layout.detail.height;
            expect(
              rows,
              `stacked panes claimed ${rows} of ${layout.bodyRows} rows at ${at}`,
            ).toBeLessThanOrEqual(layout.bodyRows);
          }
          expect(
            layout.visibleRows,
            `visibleRows exceeded the list body at ${at}`,
          ).toBeLessThanOrEqual(layout.list.bodyRows);

          for (const pane of [layout.list, layout.detail]) {
            if (pane.width > 0) {
              expect(pane.innerWidth, `zero-width pane at ${at}`).toBeGreaterThan(0);
            }
            if (pane.height > 0) {
              expect(pane.bodyRows, `zero-body pane at ${at}`).toBeGreaterThan(0);
            }
            expect(pane.innerWidth).toBeLessThanOrEqual(pane.width);
            expect(pane.bodyRows).toBeLessThanOrEqual(pane.height);
            if (pane.height > 0) {
              const paneChromeRows = (layout.bordered ? 2 : 0) + (pane.hasTitle ? 1 : 0);
              expect(pane.height - pane.bodyRows, `pane chrome miscounted at ${at}`).toBe(
                paneChromeRows,
              );
              expect(pane.width - pane.innerWidth).toBe(layout.bordered ? 4 : 0);
            }
          }
        }
      }
    }
  });

  it("keeps the body inside the terminal once the shell has taken its chrome", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        const layout = computeMarketLayout({ width, height, noticeRows: 1 });
        expect(
          layout.bodyRows + shellChromeRows(width),
          `body plus chrome overflowed ${width}x${height}`,
        ).toBeLessThanOrEqual(Math.max(height, shellChromeRows(width)));
      }
    }
  });

  it("survives garbage geometry without throwing or producing garbage", () => {
    for (const width of [Number.NaN, Number.POSITIVE_INFINITY, -100, 0.5, -0]) {
      for (const height of [Number.NaN, Number.POSITIVE_INFINITY, -100, 0.5, -0]) {
        const layout = computeMarketLayout({ width, height });
        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${width}x${height}`).toBe(true);
        }
      }
    }
  });

  it("stacks the detail pane under the list on a narrow terminal", () => {
    expect(computeMarketLayout({ width: 60, height: 40 }).stacked).toBe(true);
    expect(computeMarketLayout({ width: 79, height: 40 }).stacked).toBe(true);
    expect(computeMarketLayout({ width: 80, height: 40 }).stacked).toBe(false);
  });

  it("puts the detail pane beside the list once the terminal is wide enough", () => {
    const layout = computeMarketLayout({ width: 120, height: 40 });
    expect(layout.stacked).toBe(false);
    expect(layout.paneGap).toBe(1);
    expect(layout.detail.width).toBeGreaterThanOrEqual(30);
    expect(layout.list.width).toBeGreaterThan(layout.detail.width);
    expect(layout.list.width + layout.paneGap + layout.detail.width).toBe(layout.contentWidth);
  });

  it("titles the list always and the detail pane only when it sits beside it", () => {
    const wide = computeMarketLayout({ width: 120, height: 40 });
    expect(wide.list.hasTitle).toBe(true);
    expect(wide.detail.hasTitle).toBe(true);
    const narrow = computeMarketLayout({ width: 60, height: 40 });
    expect(narrow.stacked).toBe(true);
    expect(narrow.list.hasTitle).toBe(true);
    expect(narrow.detail.hasTitle).toBe(false);
  });

  it("drops pane borders before it drops rows of content", () => {
    const tall = computeMarketLayout({ width: 120, height: 40 });
    const short = computeMarketLayout({ width: 120, height: 16 });
    expect(tall.bordered).toBe(true);
    expect(short.bordered).toBe(false);
    expect(short.detailCompact).toBe(true);
    expect(short.list.innerWidth).toBe(short.list.width);
  });

  it("degrades the list row one column at a time as the pane narrows", () => {
    const at = (innerWidth: number) => computeMarketLayout({ width: innerWidth + 4, height: 40 }).row;
    const wide = at(120);
    expect(wide.markerWidth).toBe(1);
    expect(wide.versionWidth).toBeGreaterThan(0);
    expect(wide.stateWidth).toBeGreaterThan(0);

    let sawNoVersion = false;
    let sawNoState = false;
    for (let innerWidth = 60; innerWidth >= 1; innerWidth--) {
      const row = at(innerWidth);
      if (row.versionWidth === 0) sawNoVersion = true;
      if (row.stateWidth === 0) sawNoState = true;
      // The version is the first right-hand column to go; once the state tag is
      // gone the version must be gone too.
      if (sawNoState) expect(row.versionWidth, `version outlived the state at ${innerWidth}`).toBe(0);
      if (row.width > 0) {
        expect(row.labelWidth, `name column vanished at ${innerWidth}`).toBeGreaterThan(0);
      }
    }
    expect(sawNoVersion).toBe(true);
    expect(sawNoState).toBe(true);
  });

  it("gives more list rows to a taller terminal", () => {
    const short = computeMarketLayout({ width: 120, height: 24 });
    const tall = computeMarketLayout({ width: 120, height: 60 });
    expect(tall.visibleRows).toBeGreaterThan(short.visibleRows);
  });

  it("spends a row on the status line only when there is one", () => {
    const quiet = computeMarketLayout({ width: 120, height: 40, noticeRows: 0 });
    const noisy = computeMarketLayout({ width: 120, height: 40, noticeRows: 1 });
    expect(noisy.bodyRows).toBe(quiet.bodyRows - 1);
  });
});

// ---------------------------------------------------------------------------

describe("buildMarketItems", () => {
  it("normalises plugins from entries and themes from theme artifacts", () => {
    expect(ITEMS.map((item) => `${item.kind}:${item.id}`).sort()).toEqual([
      "plugin:acme.scanner",
      "plugin:beta.reporter",
      "theme:acme.daybreak",
      "theme:acme.midnight",
    ]);
  });

  it("drops config artifacts, unknown kinds and malformed rows", () => {
    expect(ITEMS.some((item) => item.id === "acme.config")).toBe(false);
    expect(ITEMS.some((item) => item.id === "")).toBe(false);
  });

  it("carries a plugin's capabilities and a theme's empty capability set", () => {
    const plugin = ITEMS.find((item) => item.id === "acme.scanner");
    expect(plugin?.capabilities).toEqual(["network", "filesystem-read"]);
    const theme = ITEMS.find((item) => item.id === "acme.midnight");
    expect(theme?.capabilities).toEqual([]);
  });

  it("derives a one-line description for a plugin and reads a theme's own", () => {
    const plugin = ITEMS.find((item) => item.id === "acme.scanner");
    expect(plugin?.description).toBe("2 tools: scan, probe");
    const theme = ITEMS.find((item) => item.id === "acme.midnight");
    expect(theme?.description).toBe("A dark, low-glare palette.");
  });

  it("maps the signature state to verified/unverified", () => {
    expect(ITEMS.find((item) => item.id === "beta.reporter")?.signature).toBe("verified");
    expect(ITEMS.find((item) => item.id === "acme.scanner")?.signature).toBe("unverified");
  });

  it("returns nothing for an absent or malformed registry", () => {
    expect(buildMarketItems(undefined)).toEqual([]);
    expect(buildMarketItems({})).toEqual([]);
    expect(buildMarketItems({ entries: [], artifacts: [] })).toEqual([]);
  });
});

// ---------------------------------------------------------------------------

describe("buildMarketRows", () => {
  it("groups plugins before themes, each under its own heading", () => {
    const headings = ROWS.filter(
      (row): row is Extract<MarketRow, { kind: "heading" }> => row.kind === "heading",
    );
    expect(headings.map((row) => row.group.id)).toEqual(["plugin", "theme"]);
    expect(headings[0]?.count).toBe(2);
    expect(headings[1]?.count).toBe(2);
  });

  it("puts every item under the heading of its own kind, with a true count", () => {
    let group = "";
    let seen = 0;
    let expected = 0;
    for (const row of ROWS) {
      if (row.kind === "heading") {
        if (group) expect(seen, `${group} miscounted`).toBe(expected);
        group = row.group.id;
        expected = row.count;
        seen = 0;
        continue;
      }
      expect(row.item.kind).toBe(group);
      seen++;
    }
    expect(seen).toBe(expected);
  });

  it("applies per-item install state from the injected accessor", () => {
    const stateFor = (item: MarketItem): MarketState =>
      item.id === "acme.scanner" ? "enabled" : item.id === "acme.midnight" ? "active" : "available";
    const rows = buildMarketRows({ view: REGISTRY, stateFor });
    const byId = new Map(
      rows
        .filter((row): row is Extract<MarketRow, { kind: "item" }> => row.kind === "item")
        .map((row) => [row.item.id, row.state]),
    );
    expect(byId.get("acme.scanner")).toBe("enabled");
    expect(byId.get("acme.midnight")).toBe("active");
    expect(byId.get("beta.reporter")).toBe("available");
  });

  it("filters on name, id, kind, description and capability across AND terms", () => {
    expect(
      buildMarketRows({ view: REGISTRY, filter: "network" }).filter((r) => r.kind === "item"),
    ).toHaveLength(1);
    expect(
      buildMarketRows({ view: REGISTRY, filter: "theme" }).filter((r) => r.kind === "item"),
    ).toHaveLength(2);
    expect(
      buildMarketRows({ view: REGISTRY, filter: "dark palette" }).filter((r) => r.kind === "item"),
    ).toHaveLength(1);
    expect(buildMarketRows({ view: REGISTRY, filter: "zzzzz" })).toEqual([]);
  });

  it("never leaves a heading with nothing under it", () => {
    for (const query of ["", "a", "theme", "plugin", "scan", "report", "network", "zzz"]) {
      const rows = buildMarketRows({ view: REGISTRY, filter: query });
      rows.forEach((row, index) => {
        if (row.kind !== "heading") return;
        expect(
          rows[index + 1]?.kind,
          `heading "${row.group.id}" had no children under filter "${query}"`,
        ).toBe("item");
      });
    }
  });

  it("is stable: the same inputs give the same order", () => {
    expect(buildMarketRows({ view: REGISTRY })).toEqual(buildMarketRows({ view: REGISTRY }));
  });
});

// ---------------------------------------------------------------------------

describe("navigation", () => {
  const itemIndexes = ROWS.map((row, index) => (row.kind === "item" ? index : -1)).filter(
    (index) => index >= 0,
  );

  it("never lands on a heading, moving down through the whole list twice", () => {
    let index = firstSelectableIndex(ROWS);
    expect(ROWS[index]?.kind).toBe("item");
    for (let step = 0; step < ROWS.length * 2; step++) {
      index = moveSelection(ROWS, index, 1);
      expect(ROWS[index]?.kind, `landed on a heading at step ${step}`).toBe("item");
    }
  });

  it("visits every item in order before repeating, then wraps", () => {
    const visited: number[] = [];
    let index = firstSelectableIndex(ROWS);
    for (let step = 0; step < itemIndexes.length; step++) {
      visited.push(index);
      index = moveSelection(ROWS, index, 1);
    }
    expect(visited).toEqual(itemIndexes);
    expect(index).toBe(itemIndexes[0]);
  });

  it("wraps from the last item to the first and back", () => {
    const first = firstSelectableIndex(ROWS);
    const last = lastSelectableIndex(ROWS);
    expect(moveSelection(ROWS, last, 1)).toBe(first);
    expect(moveSelection(ROWS, first, -1)).toBe(last);
  });

  it("terminates on a list of nothing but headings", () => {
    const headings: MarketRow[] = [
      { kind: "heading", group: { id: "plugin", label: "Plugins" }, count: 0 },
      { kind: "heading", group: { id: "theme", label: "Themes" }, count: 0 },
    ];
    expect(moveSelection(headings, 0, 1)).toBe(-1);
    expect(moveSelection(headings, 0, -1)).toBe(-1);
  });

  it("pulls an out-of-range or heading selection onto a real row", () => {
    expect(ROWS[clampSelection(ROWS, 0)]?.kind).toBe("item");
    expect(clampSelection(ROWS, -50)).toBe(firstSelectableIndex(ROWS));
    expect(clampSelection(ROWS, 9999)).toBe(lastSelectableIndex(ROWS));
    expect(ROWS[clampSelection(ROWS, Number.NaN)]?.kind).toBe("item");
  });

  it("returns -1 across the board for an empty list", () => {
    expect(firstSelectableIndex([])).toBe(-1);
    expect(clampSelection([], 3)).toBe(-1);
    expect(moveSelection([], 0, 1)).toBe(-1);
    expect(indexOfItem([], "plugin", "x")).toBe(-1);
  });

  it("finds an item by kind and id so a reload can keep the cursor", () => {
    const at = indexOfItem(ROWS, "theme", "acme.midnight");
    expect(at).toBeGreaterThanOrEqual(0);
    expect(ROWS[at]).toMatchObject({ kind: "item" });
    expect(indexOfItem(ROWS, "plugin", "acme.midnight")).toBe(-1);
    expect(indexOfItem(ROWS, undefined, "x")).toBe(-1);
  });
});

// ---------------------------------------------------------------------------

describe("computeMarketWindow", () => {
  it("keeps the highlighted row visible, from any anchor, at any capacity", () => {
    for (let visible = 0; visible <= ROWS.length + 4; visible++) {
      for (let selected = 0; selected < ROWS.length; selected++) {
        if (ROWS[selected]?.kind !== "item") continue;
        for (const anchor of [0, 2, ROWS.length, ROWS.length * 2]) {
          const win = computeMarketWindow({ rows: ROWS, selected, visible, anchor });
          expect(win.count).toBeLessThanOrEqual(Math.max(0, visible));
          expect(win.count).toBe(win.end - win.start);
          expect(win.end).toBeLessThanOrEqual(ROWS.length);
          if (win.count === 0) continue;
          expect(
            selected >= win.start && selected < win.end,
            `row ${selected} fell outside ${win.start}..${win.end}`,
          ).toBe(true);
        }
      }
    }
  });

  it("brings the kind heading along when the cursor is the first of its group", () => {
    const headingIndex = ROWS.findIndex(
      (row, index) => row.kind === "heading" && ROWS[index + 1]?.kind === "item" && index > 0,
    );
    expect(headingIndex).toBeGreaterThan(0);
    const win = computeMarketWindow({
      rows: ROWS,
      selected: headingIndex + 1,
      visible: 3,
      anchor: ROWS.length,
    });
    expect(win.start).toBe(headingIndex);
  });

  it("renders nothing rather than overflowing when the pane has no rows", () => {
    expect(computeMarketWindow({ rows: ROWS, selected: 1, visible: 0 })).toMatchObject({
      start: 0,
      end: 0,
      count: 0,
    });
  });

  it("titles the pane with the window it is showing", () => {
    expect(marketListTitle(computeMarketWindow({ rows: ROWS, selected: 1, visible: ROWS.length }))).toBe(
      `MARKETPLACE ${ROWS.length}`,
    );
    expect(
      marketListTitle(computeMarketWindow({ rows: ROWS, selected: 4, visible: 2, anchor: 3 })),
    ).toMatch(/^MARKETPLACE \d+-\d+\/\d+$/);
    expect(marketListTitle(computeMarketWindow({ rows: [], selected: -1, visible: 4 }))).toBe(
      "MARKETPLACE 0",
    );
  });
});

// ---------------------------------------------------------------------------

describe("the detail pane", () => {
  const textOf = (lines: { text: string }[]): string => lines.map((line) => line.text).join("\n");
  const rowFor = (id: string, state: MarketState = "available"): MarketRow => {
    const item = ITEMS.find((candidate) => candidate.id === id)!;
    return { kind: "item", group: { id: item.kind, label: item.kind }, item, state };
  };

  it("describes a plugin with its kind, version, description and capabilities", () => {
    const text = textOf(marketDetailLines({ row: rowFor("acme.scanner") }, 60));
    expect(text).toContain("Acme Scanner");
    expect(text).toContain("Kind: plugin");
    expect(text).toContain("Version: 1.2.0");
    expect(text).toContain("2 tools: scan, probe");
    expect(text).toContain("Capabilities requested: network, filesystem-read");
  });

  it("never offers to enable a plugin from the browser", () => {
    for (const state of ["available", "installed", "enabled"] as const) {
      const text = textOf(marketDetailLines({ row: rowFor("acme.scanner", state) }, 70)).toLowerCase();
      // The action hint may MENTION enabling as a separate explicit step, but the
      // browser never treats install as enablement.
      expect(text).not.toContain("enter to enable");
    }
    // Install of an available plugin is explicitly not enablement.
    expect(
      textOf(marketDetailLines({ row: rowFor("acme.scanner", "available") }, 70)),
    ).toContain("does NOT enable");
  });

  it("marks an installed plugin as not enabled", () => {
    const text = textOf(marketDetailLines({ row: rowFor("acme.scanner", "installed") }, 70));
    expect(text).toContain("NOT enabled");
  });

  it("describes a theme with no capability line", () => {
    const text = textOf(marketDetailLines({ row: rowFor("acme.midnight", "active") }, 60));
    expect(text).toContain("Kind: theme");
    expect(text).not.toContain("Capabilities requested");
    expect(text).toContain("active");
  });

  it("describes a heading so the cursor is never over nothing", () => {
    const heading = ROWS.find((row) => row.kind === "heading");
    const text = textOf(marketDetailLines({ row: heading }, 48));
    expect(text).toContain(heading?.kind === "heading" ? heading.group.label : "");
    expect(text).toMatch(/\d+ plugins? available/);
  });

  it("keeps every detail line inside the pane it was measured for", () => {
    for (const id of ITEMS.map((item) => item.id)) {
      for (const width of [0, 1, 8, 20, 30, 44, 60]) {
        for (const line of marketDetailLines({ row: rowFor(id) }, width)) {
          expect(line.text.length, `overflowed a ${width}-cell pane`).toBeLessThanOrEqual(width);
        }
      }
    }
    expect(marketDetailLines({}, 48)).toEqual([]);
  });

  it("spends no rows on blanks in compact mode", () => {
    const full = marketDetailLines({ row: rowFor("acme.scanner") }, 40);
    const compact = marketDetailLines({ row: rowFor("acme.scanner"), compact: true }, 40);
    expect(compact.some((line) => line.tone === "blank")).toBe(false);
    expect(compact.map((line) => line.text)).toEqual(
      full.filter((line) => line.tone !== "blank").map((line) => line.text),
    );
  });

  it("clips the detail body to the rows the pane holds, marking the cut", () => {
    const lines = marketDetailLines({ row: rowFor("acme.scanner", "installed") }, 24);
    expect(lines.length).toBeGreaterThan(4);
    expect(clipMarketDetailLines(lines, 4)).toHaveLength(4);
    expect(clipMarketDetailLines(lines, 4).at(-1)?.text).toBe("...");
    expect(clipMarketDetailLines(lines, 0)).toEqual([]);
    expect(clipMarketDetailLines(lines, lines.length + 5)).toHaveLength(lines.length);
    const inline = clipMarketDetailLines(lines, 3, 24);
    expect(inline.at(-1)?.text.endsWith(" ...")).toBe(true);
    for (const line of inline) expect(line.text.length).toBeLessThanOrEqual(24);
  });

  it("labels each state as a short tag and a full action hint", () => {
    expect(stateTag("available")).toBe("available");
    expect(stateTag("installed")).toBe("installed");
    expect(stateTag("enabled")).toBe("enabled");
    expect(stateTag("active")).toBe("active");
    for (const state of ["available", "installed", "enabled", "active"] as const) {
      expect(stateTag(state).length).toBeLessThanOrEqual(12);
    }
    expect(actionHint("plugin", "available")).toContain("install");
    expect(actionHint("plugin", "installed")).toContain("enable");
    expect(actionHint("theme", "available")).toContain("install");
    expect(actionHint("theme", "installed")).toContain("apply");
  });
});

// ---------------------------------------------------------------------------

describe("the empty / error state", () => {
  const textOf = (lines: { text: string }[]): string => lines.map((line) => line.text).join("\n");

  it("guides an unconfigured registry rather than reading as a crash", () => {
    const text = textOf(marketEmptyLines({ registryUrl: "" }, 60));
    expect(text).toContain("No marketplace registry configured");
    expect(text).toContain("0SEC_REGISTRY_URL");
    expect(text).toContain("runs nothing");
  });

  it("reports a fetch error with the URL that failed", () => {
    const text = textOf(marketEmptyLines({ registryUrl: "https://x", error: "network down" }, 60));
    expect(text).toContain("Could not reach");
    expect(text).toContain("https://x");
    expect(text).toContain("network down");
  });

  it("says plainly when a reachable registry is empty", () => {
    const text = textOf(
      marketEmptyLines({ registryUrl: "https://x", reachableButEmpty: true }, 60),
    );
    expect(text).toContain("no plugins or themes");
  });

  it("keeps every empty-state line inside its pane", () => {
    for (const width of [0, 1, 10, 30, 60]) {
      for (const input of [
        { registryUrl: "" },
        { registryUrl: "https://example.test/index.json", error: "boom" },
        { registryUrl: "https://example.test/index.json", reachableButEmpty: true },
      ]) {
        for (const line of marketEmptyLines(input, width)) {
          expect(line.text.length).toBeLessThanOrEqual(width);
        }
      }
    }
  });
});

// ---------------------------------------------------------------------------

describe("hints and keys", () => {
  it("names the real keys in the footer hint, per mode", () => {
    const browse = marketFooterHint("browse");
    for (const fragment of ["up/down", "enter install", "/ filter", "ctrl+c exit"]) {
      expect(browse).toContain(fragment);
    }
    expect(marketFooterHint("browse", false)).toContain("esc back");
    expect(marketFooterHint("browse", true)).toContain("esc clear filter");
    expect(marketFooterHint("filter")).toContain("backspace");
    // Install is confirmed, never silent.
    expect(marketFooterHint("confirm")).toContain("y install");
    expect(marketFooterHint("confirm")).toContain("cancel");
  });

  it("gives every printable character to the filter", () => {
    for (const key of ["a", "Z", " ", "r", "5", "-", "."]) {
      expect(isFilterKey(key), `${key} did not reach the filter`).toBe(true);
    }
    expect(isFilterKey("\x1b")).toBe(false);
    expect(isFilterKey("\x7f")).toBe(false);
    expect(isFilterKey("\r")).toBe(false);
    expect(isFilterKey("ab")).toBe(false);
    expect(isFilterKey(undefined)).toBe(false);
  });
});

describe("paneTitleColumns", () => {
  it("splits a header into title + meta whose cells sum to the inner width", () => {
    for (let width = 0; width <= 200; width++) {
      for (const metaLen of [0, 1, 3, 8, 20, 999]) {
        const cols = paneTitleColumns(width, metaLen);
        const claimed = cols.titleWidth + cols.gap + cols.metaWidth;
        // Every field is a non-negative integer.
        for (const [name, value] of [
          ["titleWidth", cols.titleWidth],
          ["gap", cols.gap],
          ["metaWidth", cols.metaWidth],
        ] as const) {
          expect(Number.isInteger(value) && value >= 0, `${name} was ${value} at ${width}`).toBe(true);
        }
        // The columns claim EXACTLY the inner width — never more (overlap), never
        // less (a gap the border paints through).
        expect(claimed, `claimed ${claimed} of ${width} with meta ${metaLen}`).toBe(Math.max(0, width));
        // The meta never eats the whole row: the title keeps a cell whenever there is one.
        if (width > 0) expect(cols.titleWidth, `title squeezed out at ${width}`).toBeGreaterThan(0);
        // The meta gets a gap iff it is rendered.
        expect(cols.gap === 0 || cols.metaWidth > 0).toBe(true);
      }
    }
  });

  it("drops the meta entirely rather than overflow a tiny row", () => {
    expect(paneTitleColumns(0, 5)).toEqual({ titleWidth: 0, gap: 0, metaWidth: 0 });
    expect(paneTitleColumns(2, 5)).toEqual({ titleWidth: 2, gap: 0, metaWidth: 0 });
    // No meta requested: the whole row is the title.
    expect(paneTitleColumns(40, 0)).toEqual({ titleWidth: 40, gap: 0, metaWidth: 0 });
  });
});

describe("marketListHeading", () => {
  it("names the pane and counts the roster, or the window when scrolled", () => {
    const whole = computeMarketWindow({ rows: ROWS, selected: 1, visible: ROWS.length });
    expect(marketListHeading(whole)).toEqual({
      title: "MARKETPLACE",
      meta: `${ROWS.length} items`,
    });
    const scrolled = computeMarketWindow({ rows: ROWS, selected: 4, visible: 2, anchor: 3 });
    const heading = marketListHeading(scrolled);
    expect(heading.title).toBe("MARKETPLACE");
    expect(heading.meta).toMatch(/^\d+-\d+ \/ \d+$/);
    expect(marketListHeading(computeMarketWindow({ rows: [], selected: -1, visible: 4 }))).toEqual({
      title: "MARKETPLACE",
      meta: "empty",
    });
  });
});
