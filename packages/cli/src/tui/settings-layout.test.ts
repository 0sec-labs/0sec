import { describe, expect, it } from "vitest";

import {
  buildSettingsRows,
  clampSelection,
  clipDetailLines,
  computeSettingsLayout,
  computeSettingsWindow,
  cycleSetting,
  firstSelectableIndex,
  isFilterKey,
  isSettingModified,
  lastSelectableIndex,
  moveSelection,
  resetAllSettings,
  resetSetting,
  settingValue,
  settingValueLabel,
  settingsDetailLines,
  settingsFooterHint,
  settingsListTitle,
  shellChromeRows,
  wrapCells,
  type SettingsLayout,
  type SettingsRow,
} from "./settings-layout.js";
import {
  DEFAULT_SETTINGS,
  SETTING_DEFS,
  type SettingDef,
  type TuiSettings,
} from "./settings.js";

/** A def the real table does not contain, used to prove the list is derived. */
const PROBE_DEF: SettingDef = {
  key: "__probeSetting",
  label: "Probe setting",
  description: "A setting that exists only inside this test file.",
  kind: "enum",
  default: "alpha",
  choices: ["alpha", "beta", "gamma"],
  group: "Experimental",
};

const isInteger = (value: number): boolean => Number.isInteger(value) && value >= 0;

const GROUPS = [...new Set(SETTING_DEFS.map((def) => def.group))];

const haystackOf = (def: SettingDef): string =>
  [def.key, def.label, def.group, def.description, ...(def.choices ?? [])].join(" ").toLowerCase();

/**
 * A word that appears in exactly one def's *description* and in no def's key,
 * label or group.
 *
 * Derived from the live table rather than written down, because the table is
 * edited far more often than this file: a hardcoded probe word ("lateral")
 * silently stopped matching the moment somebody reworded a description, and
 * the test then failed for a reason that had nothing to do with filtering.
 */
function descriptionOnlyTerm(): { term: string; key: string } {
  for (const def of SETTING_DEFS) {
    const identity = [def.key, def.label, def.group].join(" ").toLowerCase();
    for (const term of def.description.toLowerCase().match(/[a-z]{6,}/g) ?? []) {
      if (identity.includes(term)) continue;
      if (SETTING_DEFS.some((other) => other.key !== def.key && haystackOf(other).includes(term))) {
        continue;
      }
      return { term, key: def.key };
    }
  }
  throw new Error("SETTING_DEFS has no description-only term to filter on");
}

/** Every cell and row count a layout exposes, flattened for the sweep. */
function layoutNumbers(layout: SettingsLayout): [string, number][] {
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
    ["row.valueGap", layout.row.valueGap],
    ["row.valueWidth", layout.row.valueWidth],
    ["visibleRows", layout.visibleRows],
  ];
}

// ---------------------------------------------------------------------------

describe("computeSettingsLayout — the sweep", () => {
  /**
   * The invariant this whole module exists for: no allocation may exceed the
   * container it was carved out of, on either axis, at any terminal size.
   *
   * Yoga does not clip. A row of siblings claiming more cells than the row has
   * is shrunk, not truncated, and every sibling then paints its full string
   * into a box that is too small — the terminal shows the two strings
   * interleaved. A box claiming more rows than its column has paints its own
   * bottom border through its last line of content. Both are silent at
   * compile time and both were shipped repeatedly before `chat-layout.ts`
   * moved the arithmetic somewhere a test could reach it.
   */
  it("never lets a pane, a row or a column exceed what it was given", () => {
    for (let width = 0; width <= 200; width++) {
      for (let height = 0; height <= 80; height++) {
        for (const noticeRows of [0, 1]) {
          const layout = computeSettingsLayout({ width, height, noticeRows });
          const at = `${width}x${height} (notice ${noticeRows})`;

          for (const [name, value] of layoutNumbers(layout)) {
            expect(isInteger(value), `${name} was ${value} at ${at}`).toBe(true);
          }

          // ── horizontal ──
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
            expect(claimed, `panes claimed ${claimed} of ${layout.contentWidth} at ${at}`)
              .toBeLessThanOrEqual(layout.contentWidth);
          }

          // ── list row columns ──
          const row = layout.row;
          expect(row.width, `row wider than the list pane at ${at}`).toBe(layout.list.innerWidth);
          const rowClaimed =
            row.markerWidth + row.markerGap + row.labelWidth + row.valueGap + row.valueWidth;
          // Exactly, not merely "at most": a row that leaves cells unclaimed
          // is a row whose selection highlight stops short of its own edge.
          expect(rowClaimed, `row claimed ${rowClaimed} of ${row.width} at ${at}`)
            .toBe(row.width);

          // ── vertical ──
          expect(layout.list.height, `list taller than the body at ${at}`).toBeLessThanOrEqual(
            layout.bodyRows,
          );
          expect(layout.detail.height, `detail taller than the body at ${at}`).toBeLessThanOrEqual(
            layout.bodyRows,
          );
          if (layout.stacked) {
            const rows = layout.list.height + layout.detail.height;
            expect(rows, `stacked panes claimed ${rows} of ${layout.bodyRows} rows at ${at}`)
              .toBeLessThanOrEqual(layout.bodyRows);
          }
          expect(layout.visibleRows, `visibleRows exceeded the list body at ${at}`)
            .toBeLessThanOrEqual(layout.list.bodyRows);

          // A rendered pane always has room for at least one row of content
          // and one cell of text; a pane below that is dropped, because a box
          // one row short of its content is corruption and an absent box is
          // merely missing information.
          for (const pane of [layout.list, layout.detail]) {
            if (pane.width > 0) expect(pane.innerWidth, `zero-width pane at ${at}`).toBeGreaterThan(0);
            if (pane.height > 0) expect(pane.bodyRows, `zero-body pane at ${at}`).toBeGreaterThan(0);
            expect(pane.innerWidth).toBeLessThanOrEqual(pane.width);
            expect(pane.bodyRows).toBeLessThanOrEqual(pane.height);
            if (pane.height > 0) {
              // The pane's own rows are accounted for exactly: two border rows
              // when bordered, one more when it draws a title.
              const paneChromeRows = (layout.bordered ? 2 : 0) + (pane.hasTitle ? 1 : 0);
              expect(pane.height - pane.bodyRows, `pane chrome miscounted at ${at}`)
                .toBe(paneChromeRows);
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
        const layout = computeSettingsLayout({ width, height, noticeRows: 1 });
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
        const layout = computeSettingsLayout({ width, height });
        for (const [name, value] of layoutNumbers(layout)) {
          expect(isInteger(value), `${name} was ${value} at ${width}x${height}`).toBe(true);
        }
      }
    }
  });

  it("stacks the detail pane under the list on a narrow terminal", () => {
    expect(computeSettingsLayout({ width: 60, height: 40 }).stacked).toBe(true);
    expect(computeSettingsLayout({ width: 79, height: 40 }).stacked).toBe(true);
    expect(computeSettingsLayout({ width: 80, height: 40 }).stacked).toBe(false);
  });

  it("puts the detail pane beside the list once the terminal is wide enough", () => {
    const layout = computeSettingsLayout({ width: 120, height: 40 });
    expect(layout.stacked).toBe(false);
    expect(layout.paneGap).toBe(1);
    expect(layout.detail.width).toBeGreaterThanOrEqual(30);
    expect(layout.list.width).toBeGreaterThan(layout.detail.width);
    expect(layout.list.width + layout.paneGap + layout.detail.width).toBe(layout.contentWidth);
  });

  it("titles the list always and the detail pane only when it sits beside it", () => {
    const wide = computeSettingsLayout({ width: 120, height: 40 });
    expect(wide.list.hasTitle).toBe(true);
    expect(wide.detail.hasTitle).toBe(true);
    const narrow = computeSettingsLayout({ width: 60, height: 40 });
    expect(narrow.stacked).toBe(true);
    expect(narrow.list.hasTitle).toBe(true);
    // Stacked, the detail pane's first line is already the setting's name.
    expect(narrow.detail.hasTitle).toBe(false);
  });

  it("drops the detail pane's blank separators only when it drops its borders", () => {
    expect(computeSettingsLayout({ width: 120, height: 40 }).detailCompact).toBe(false);
    expect(computeSettingsLayout({ width: 60, height: 18 }).detailCompact).toBe(true);
  });

  it("drops pane borders before it drops rows of content", () => {
    const tall = computeSettingsLayout({ width: 120, height: 40 });
    const short = computeSettingsLayout({ width: 120, height: 16 });
    expect(tall.bordered).toBe(true);
    expect(short.bordered).toBe(false);
    // Borderless panes hand the four horizontal chrome cells back to the text.
    expect(short.list.innerWidth).toBe(short.list.width);
  });

  it("gives more list rows to a taller terminal", () => {
    const short = computeSettingsLayout({ width: 120, height: 24 });
    const tall = computeSettingsLayout({ width: 120, height: 60 });
    expect(tall.visibleRows).toBeGreaterThan(short.visibleRows);
  });

  it("spends a row on the notice line only when there is one", () => {
    const quiet = computeSettingsLayout({ width: 120, height: 40, noticeRows: 0 });
    const noisy = computeSettingsLayout({ width: 120, height: 40, noticeRows: 1 });
    expect(noisy.bodyRows).toBe(quiet.bodyRows - 1);
  });
});

// ---------------------------------------------------------------------------

describe("buildSettingsRows", () => {
  it("derives the entire list from SETTING_DEFS", () => {
    const rows = buildSettingsRows();
    const settingRows = rows.filter((row) => row.kind === "setting");
    const headingRows = rows.filter((row) => row.kind === "heading");
    const groups = [...new Set(SETTING_DEFS.map((def) => def.group))];

    expect(settingRows).toHaveLength(SETTING_DEFS.length);
    expect(headingRows).toHaveLength(groups.length);
    // Every key in the real table is reachable, so a def added tomorrow is
    // covered by this assertion without anyone editing it.
    expect(
      settingRows.map((row) => (row.kind === "setting" ? row.def.key : "")).sort(),
    ).toEqual(SETTING_DEFS.map((def) => def.key).sort());
  });

  it("orders groups by first appearance in the table, not alphabetically", () => {
    const rows = buildSettingsRows();
    const rendered = rows.filter((row) => row.kind === "heading").map((row) => row.group);
    const expected = [...new Set(SETTING_DEFS.map((def) => def.group))];
    expect(rendered).toEqual(expected);
  });

  it("puts every setting under its own group heading", () => {
    let heading = "";
    for (const row of buildSettingsRows()) {
      if (row.kind === "heading") heading = row.group;
      else expect(row.def.group).toBe(heading);
    }
  });

  it("grows when a def is added, with no change to this module", () => {
    const before = buildSettingsRows(SETTING_DEFS);
    const after = buildSettingsRows([...SETTING_DEFS, PROBE_DEF]);
    // One new setting row plus the heading for its new group.
    expect(after).toHaveLength(before.length + 2);
    expect(after.at(-2)).toEqual({ kind: "heading", group: "Experimental" });
    expect(after.at(-1)).toEqual({ kind: "setting", group: "Experimental", def: PROBE_DEF });
  });

  it("adds no heading when a new def joins an existing group", () => {
    const before = buildSettingsRows(SETTING_DEFS);
    const sameGroup: SettingDef = { ...PROBE_DEF, group: SETTING_DEFS[0]?.group ?? "Display" };
    expect(buildSettingsRows([...SETTING_DEFS, sameGroup])).toHaveLength(before.length + 1);
  });

  it("filters on key and label", () => {
    for (const def of SETTING_DEFS) {
      const byKey = buildSettingsRows(SETTING_DEFS, def.key);
      expect(
        byKey.some((row) => row.kind === "setting" && row.def.key === def.key),
        `filtering on the key ${def.key} did not find it`,
      ).toBe(true);
      const byLabel = buildSettingsRows(SETTING_DEFS, def.label);
      expect(
        byLabel.some((row) => row.kind === "setting" && row.def.key === def.key),
        `filtering on the label "${def.label}" did not find ${def.key}`,
      ).toBe(true);
    }
  });

  it("filters on description text the label never mentions", () => {
    const { term, key } = descriptionOnlyTerm();
    const matched = buildSettingsRows(SETTING_DEFS, term).filter((row) => row.kind === "setting");
    expect(matched, `"${term}" should reach exactly ${key}`).toHaveLength(1);
    expect(matched[0]?.kind === "setting" && matched[0].def.key).toBe(key);
  });

  it("filters on an enum's choice list", () => {
    const enumDef = SETTING_DEFS.find((def) => def.kind === "enum" && (def.choices?.length ?? 0) > 0);
    expect(enumDef).toBeDefined();
    const choice = enumDef?.choices?.[0] ?? "";
    expect(
      buildSettingsRows(SETTING_DEFS, choice).some(
        (row) => row.kind === "setting" && row.def.key === enumDef?.key,
      ),
    ).toBe(true);
  });

  it("narrows to a single group and heading when filtered by a key", () => {
    const all = buildSettingsRows(SETTING_DEFS, "");
    for (const def of SETTING_DEFS) {
      const narrowed = buildSettingsRows(SETTING_DEFS, def.key);
      expect(narrowed.length, `filtering on ${def.key} did not narrow the list`)
        .toBeLessThan(all.length);
      expect(narrowed[0]).toEqual({ kind: "heading", group: def.group });
      expect(narrowed.filter((row) => row.kind === "heading")).toHaveLength(1);
    }
  });

  it("never leaves a heading with nothing under it, for any filter", () => {
    const queries = [
      "",
      ...GROUPS,
      ...SETTING_DEFS.map((def) => def.key),
      ...SETTING_DEFS.map((def) => def.label),
      "o",
      "e",
      "show",
      "on",
      "zzz",
    ];
    for (const query of queries) {
      const rows = buildSettingsRows(SETTING_DEFS, query);
      rows.forEach((row, index) => {
        if (row.kind !== "heading") return;
        expect(
          rows[index + 1]?.kind,
          `heading "${row.group}" had no children under filter "${query}"`,
        ).toBe("setting");
      });
      // And no group is ever split across two headings.
      const headings = rows.filter((row) => row.kind === "heading").map((row) => row.group);
      expect(new Set(headings).size, `duplicate heading under filter "${query}"`)
        .toBe(headings.length);
    }
  });

  it("ANDs multiple filter terms", () => {
    const def = SETTING_DEFS[0];
    expect(def).toBeDefined();
    const both = buildSettingsRows(SETTING_DEFS, `${def?.group} ${def?.key}`);
    expect(both.filter((row) => row.kind === "setting")).toHaveLength(1);
    expect(buildSettingsRows(SETTING_DEFS, `${def?.group} nonsensetoken`)).toHaveLength(0);
  });

  it("returns an empty list rather than throwing when nothing matches", () => {
    const rows = buildSettingsRows(SETTING_DEFS, "zzzzz");
    expect(rows).toEqual([]);
    expect(firstSelectableIndex(rows)).toBe(-1);
    expect(clampSelection(rows, 3)).toBe(-1);
    expect(moveSelection(rows, 0, 1)).toBe(-1);
  });
});

// ---------------------------------------------------------------------------

describe("navigation", () => {
  const rows = buildSettingsRows();
  const settingIndexes = rows
    .map((row, index) => (row.kind === "setting" ? index : -1))
    .filter((index) => index >= 0);

  it("never lands on a group heading, moving down through the whole list twice", () => {
    let index = firstSelectableIndex(rows);
    expect(rows[index]?.kind).toBe("setting");
    for (let step = 0; step < rows.length * 2; step++) {
      index = moveSelection(rows, index, 1);
      expect(rows[index]?.kind, `landed on a heading at step ${step}`).toBe("setting");
    }
  });

  it("never lands on a group heading, moving up through the whole list twice", () => {
    let index = lastSelectableIndex(rows);
    for (let step = 0; step < rows.length * 2; step++) {
      index = moveSelection(rows, index, -1);
      expect(rows[index]?.kind, `landed on a heading at step ${step}`).toBe("setting");
    }
  });

  it("visits every setting in order before repeating", () => {
    const visited: number[] = [];
    let index = firstSelectableIndex(rows);
    for (let step = 0; step < settingIndexes.length; step++) {
      visited.push(index);
      index = moveSelection(rows, index, 1);
    }
    expect(visited).toEqual(settingIndexes);
    // And wraps back to the top.
    expect(index).toBe(settingIndexes[0]);
  });

  it("wraps from the last setting to the first and back", () => {
    const first = firstSelectableIndex(rows);
    const last = lastSelectableIndex(rows);
    expect(moveSelection(rows, last, 1)).toBe(first);
    expect(moveSelection(rows, first, -1)).toBe(last);
  });

  it("skips a run of consecutive headings", () => {
    const sparse: SettingsRow[] = [
      { kind: "heading", group: "A" },
      { kind: "heading", group: "B" },
      { kind: "heading", group: "C" },
      { kind: "setting", group: "C", def: PROBE_DEF },
      { kind: "heading", group: "D" },
      { kind: "heading", group: "E" },
      { kind: "setting", group: "E", def: PROBE_DEF },
    ];
    expect(moveSelection(sparse, 3, 1)).toBe(6);
    expect(moveSelection(sparse, 6, 1)).toBe(3);
    expect(moveSelection(sparse, 3, -1)).toBe(6);
    expect(moveSelection(sparse, 6, -1)).toBe(3);
  });

  it("terminates on a list of nothing but headings", () => {
    const headings: SettingsRow[] = [
      { kind: "heading", group: "A" },
      { kind: "heading", group: "B" },
    ];
    expect(moveSelection(headings, 0, 1)).toBe(-1);
    expect(moveSelection(headings, 0, -1)).toBe(-1);
  });

  it("honours a multi-row jump", () => {
    const first = firstSelectableIndex(rows);
    let stepped = first;
    for (let i = 0; i < 4; i++) stepped = moveSelection(rows, stepped, 1);
    expect(moveSelection(rows, first, 4)).toBe(stepped);
  });

  it("pulls an out-of-range or heading selection onto a real row", () => {
    expect(rows[clampSelection(rows, 0)]?.kind).toBe("setting");
    expect(clampSelection(rows, -50)).toBe(firstSelectableIndex(rows));
    expect(clampSelection(rows, 9999)).toBe(lastSelectableIndex(rows));
    expect(rows[clampSelection(rows, Number.NaN)]?.kind).toBe("setting");
  });

  it("re-clamps the selection after a filter shortens the list", () => {
    const all = buildSettingsRows(SETTING_DEFS, "");
    const selected = lastSelectableIndex(all);
    for (const group of GROUPS) {
      const filtered = buildSettingsRows(SETTING_DEFS, group);
      const reclamped = clampSelection(filtered, selected);
      expect(reclamped, `no row survived the ${group} filter`).toBeGreaterThanOrEqual(0);
      expect(reclamped).toBeLessThan(filtered.length);
      expect(filtered[reclamped]?.kind).toBe("setting");
      // And the cursor is still usable — moving from it stays on a real row.
      expect(filtered[moveSelection(filtered, reclamped, 1)]?.kind).toBe("setting");
    }
    // The narrowest possible list: one group's worth, cursor past the end.
    const narrowest = GROUPS.map((group) => buildSettingsRows(SETTING_DEFS, group)).reduce(
      (shortest, rows) => (rows.length < shortest.length ? rows : shortest),
    );
    expect(clampSelection(narrowest, 9999)).toBe(lastSelectableIndex(narrowest));
  });
});

// ---------------------------------------------------------------------------

describe("computeSettingsWindow", () => {
  const rows = buildSettingsRows();

  it("keeps the highlighted row visible, from any anchor, at any capacity", () => {
    for (let visible = 0; visible <= rows.length + 4; visible++) {
      for (let selected = 0; selected < rows.length; selected++) {
        if (rows[selected]?.kind !== "setting") continue;
        for (const anchor of [0, 3, 7, rows.length, rows.length * 2]) {
          const win = computeSettingsWindow({ rows, selected, visible, anchor });
          expect(win.count).toBeLessThanOrEqual(Math.max(0, visible));
          expect(win.count).toBe(win.end - win.start);
          expect(win.end).toBeLessThanOrEqual(rows.length);
          if (win.count === 0) continue;
          expect(
            selected >= win.start && selected < win.end,
            `row ${selected} fell outside ${win.start}..${win.end} (visible ${visible}, anchor ${anchor})`,
          ).toBe(true);
        }
      }
    }
  });

  it("brings the group heading along when the cursor is the first of its group", () => {
    const headingIndex = rows.findIndex(
      (row, index) => row.kind === "heading" && rows[index + 1]?.kind === "setting" && index > 0,
    );
    expect(headingIndex).toBeGreaterThan(0);
    const selected = headingIndex + 1;
    const win = computeSettingsWindow({ rows, selected, visible: 4, anchor: rows.length });
    expect(win.start).toBe(headingIndex);
  });

  it("scrolls from the anchor rather than re-centring", () => {
    // A cursor already inside the window leaves the window exactly where it is.
    const win = computeSettingsWindow({ rows, selected: 4, visible: 6, anchor: 2 });
    expect(win.start).toBe(2);
    expect(win.end).toBe(8);
  });

  it("scrolls down by exactly one when the cursor steps past the last row", () => {
    const win = computeSettingsWindow({ rows, selected: 8, visible: 6, anchor: 2 });
    expect(win.start).toBe(3);
    expect(win.hasAbove).toBe(true);
  });

  it("reports overflow in both directions", () => {
    const whole = computeSettingsWindow({ rows, selected: 1, visible: rows.length });
    expect(whole.hasAbove).toBe(false);
    expect(whole.hasBelow).toBe(false);
    const middle = computeSettingsWindow({ rows, selected: 5, visible: 3, anchor: 4 });
    expect(middle.hasAbove).toBe(true);
    expect(middle.hasBelow).toBe(true);
  });

  it("renders nothing rather than overflowing when the pane has no rows", () => {
    const win = computeSettingsWindow({ rows, selected: 3, visible: 0 });
    expect(win).toMatchObject({ start: 0, end: 0, count: 0 });
  });

  it("handles an empty list and a missing selection", () => {
    expect(computeSettingsWindow({ rows: [], selected: -1, visible: 10 }).count).toBe(0);
    const win = computeSettingsWindow({ rows, selected: -1, visible: 4, anchor: 2 });
    expect(win.start).toBe(2);
    expect(win.count).toBe(4);
  });

  it("titles the pane with the window it is showing", () => {
    expect(settingsListTitle(computeSettingsWindow({ rows, selected: 1, visible: rows.length })))
      .toBe(`SETTINGS ${rows.length}`);
    expect(settingsListTitle(computeSettingsWindow({ rows, selected: 5, visible: 4, anchor: 3 })))
      .toMatch(/^SETTINGS \d+-\d+\/\d+$/);
    expect(settingsListTitle(computeSettingsWindow({ rows: [], selected: -1, visible: 4 })))
      .toBe("SETTINGS 0");
  });
});

// ---------------------------------------------------------------------------

describe("text", () => {
  it("never emits a wrapped line wider than its budget", () => {
    const sample = SETTING_DEFS.map((def) => def.description).join(" ");
    for (let width = 0; width <= 80; width++) {
      for (const line of wrapCells(sample, width)) {
        expect(line.length, `line of ${line.length} exceeded ${width}`).toBeLessThanOrEqual(width);
      }
    }
  });

  it("hard-breaks a token longer than the line rather than overhanging", () => {
    expect(wrapCells("abcdefghij", 4)).toEqual(["abcd", "efgh", "ij"]);
    expect(wrapCells("hi abcdefghij", 4)).toEqual(["hi", "abcd", "efgh", "ij"]);
  });

  it("strips control sequences before wrapping", () => {
    expect(wrapCells("a[31mb\nc", 40)).toEqual(["ab c"]);
  });

  it("renders values the way the list and the detail pane show them", () => {
    const boolDef = SETTING_DEFS.find((def) => def.kind === "boolean");
    const enumDef = SETTING_DEFS.find((def) => def.kind === "enum");
    expect(settingValueLabel(boolDef, true)).toBe("on");
    expect(settingValueLabel(boolDef, false)).toBe("off");
    expect(settingValueLabel(enumDef, "compact")).toBe("compact");
    expect(settingValueLabel(undefined, true)).toBe("");
  });

  it("describes a setting with its value, default and allowed values", () => {
    const def = SETTING_DEFS.find(
      (candidate) => candidate.kind === "enum" && (candidate.choices?.length ?? 0) >= 2,
    );
    expect(def).toBeDefined();
    const other = def?.choices?.find((choice) => choice !== def.default) ?? "";
    const text = settingsDetailLines(def, other, 72).map((line) => line.text);
    expect(text[0]).toBe(def?.label);
    expect(text.join("\n")).toContain(`Current: ${other}`);
    expect(text.join("\n")).toContain(`Default: ${String(def?.default)}`);
    expect(text.join("\n")).toContain(`Allowed: ${def?.choices?.join(", ")}`);
    expect(text.join("\n")).toContain(`Key: ${def?.key}`);
  });

  it("offers on/off as the allowed values of a boolean", () => {
    const def = SETTING_DEFS.find((candidate) => candidate.kind === "boolean");
    const text = settingsDetailLines(def, true, 72).map((line) => line.text).join("\n");
    expect(text).toContain("Allowed: on, off");
    expect(text).toContain("Current: on");
  });

  it("keeps every detail line inside the pane it was measured for", () => {
    for (const def of SETTING_DEFS) {
      for (const width of [0, 1, 8, 20, 27, 48, 52]) {
        for (const line of settingsDetailLines(def, def.default, width)) {
          expect(line.text.length, `${def.key} overflowed a ${width}-cell pane`)
            .toBeLessThanOrEqual(width);
        }
      }
    }
  });

  it("spends no rows on blanks in compact mode", () => {
    const def = SETTING_DEFS[0];
    const full = settingsDetailLines(def, def?.default, 40);
    const compact = settingsDetailLines(def, def?.default, 40, { compact: true });
    expect(compact.some((line) => line.tone === "blank")).toBe(false);
    expect(compact.length).toBe(full.filter((line) => line.tone !== "blank").length);
    // The information is all still there, only the whitespace is gone.
    expect(compact.map((line) => line.text)).toEqual(
      full.filter((line) => line.tone !== "blank").map((line) => line.text),
    );
  });

  it("clips the detail body to the rows the pane holds", () => {
    // The longest description in the table, so the clip is exercised whichever
    // def happens to be the wordiest today.
    const def = [...SETTING_DEFS].sort(
      (a, b) => b.description.length - a.description.length,
    )[0];
    const lines = settingsDetailLines(def, def?.default, 24);
    expect(lines.length).toBeGreaterThan(4);
    const clipped = clipDetailLines(lines, 4);
    expect(clipped).toHaveLength(4);
    expect(clipped.at(-1)?.text).toBe("...");
    expect(clipDetailLines(lines, 0)).toEqual([]);
    expect(clipDetailLines(lines, lines.length + 5)).toHaveLength(lines.length);

    // Given the pane's width, the marker rides on the last surviving line
    // rather than costing a row of its own.
    const inline = clipDetailLines(lines, 3, 24);
    expect(inline).toHaveLength(3);
    expect(inline.at(-1)?.text.endsWith(" ...")).toBe(true);
    for (const line of inline) expect(line.text.length).toBeLessThanOrEqual(24);
    // A pane too narrow to carry the marker inline still marks the overflow.
    expect(clipDetailLines(lines, 3, 6).at(-1)?.text).toBe("...");
  });

  it("names the real keys in the footer hint", () => {
    const browse = settingsFooterHint("browse");
    for (const fragment of ["up/down", "enter/space", "left/right", "/ filter", "r reset", "shift+r"]) {
      expect(browse).toContain(fragment);
    }
    expect(settingsFooterHint("browse", false)).toContain("esc back");
    expect(settingsFooterHint("browse", true)).toContain("esc clear filter");
    expect(settingsFooterHint("confirm-reset-all")).toContain("y confirm");
    expect(settingsFooterHint("filter")).toContain("backspace");
  });

  it("reserves the reset keys from the type-to-filter path", () => {
    expect(isFilterKey("a")).toBe(true);
    expect(isFilterKey("Z")).toBe(true);
    expect(isFilterKey(" ")).toBe(true);
    expect(isFilterKey("r")).toBe(false);
    expect(isFilterKey("R")).toBe(false);
    expect(isFilterKey("")).toBe(false);
    expect(isFilterKey("")).toBe(false);
    expect(isFilterKey("ab")).toBe(false);
    expect(isFilterKey(undefined)).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe("mutation", () => {
  const read = (settings: TuiSettings, key: string): unknown =>
    (settings as unknown as Record<string, unknown>)[key];

  it("cycles every enum in the table forwards through its whole choice list", () => {
    for (const def of SETTING_DEFS) {
      if (def.kind !== "enum") continue;
      const choices = def.choices ?? [];
      let settings = { ...DEFAULT_SETTINGS };
      const seen: unknown[] = [];
      for (let step = 0; step < choices.length; step++) {
        seen.push(read(settings, def.key));
        settings = cycleSetting(settings, def.key, 1);
      }
      // A full lap visits every choice exactly once and lands back home.
      expect([...seen].sort(), `${def.key} did not visit every choice`)
        .toEqual([...choices].sort());
      expect(read(settings, def.key), `${def.key} did not wrap`).toBe(def.default);
    }
  });

  it("cycles every enum backwards as the exact inverse", () => {
    for (const def of SETTING_DEFS) {
      if (def.kind !== "enum") continue;
      const forward = cycleSetting(DEFAULT_SETTINGS, def.key, 1);
      expect(read(cycleSetting(forward, def.key, -1), def.key), `${def.key} is not reversible`)
        .toBe(def.default);
      const back = cycleSetting(DEFAULT_SETTINGS, def.key, -1);
      expect(read(back, def.key)).toBe((def.choices ?? []).at(-1));
    }
  });

  it("flips every boolean in either direction", () => {
    for (const def of SETTING_DEFS) {
      if (def.kind !== "boolean") continue;
      expect(read(cycleSetting(DEFAULT_SETTINGS, def.key, 1), def.key)).toBe(!def.default);
      expect(read(cycleSetting(DEFAULT_SETTINGS, def.key, -1), def.key)).toBe(!def.default);
    }
  });

  it("repairs a value that is not in its choice list", () => {
    const def = SETTING_DEFS.find((candidate) => candidate.kind === "enum");
    expect(def).toBeDefined();
    const corrupt = { ...DEFAULT_SETTINGS, [def?.key ?? ""]: "wat" } as unknown as TuiSettings;
    // normalizeSettings restores the default, and the cycle steps off it.
    expect(read(cycleSetting(corrupt, def?.key ?? "", 1), def?.key ?? "")).toBe(
      (def?.choices ?? [])[1],
    );
  });

  it("leaves an unknown key inert", () => {
    expect(cycleSetting(DEFAULT_SETTINGS, "nope", 1)).toEqual(DEFAULT_SETTINGS);
    expect(resetSetting(DEFAULT_SETTINGS, "nope")).toEqual(DEFAULT_SETTINGS);
  });

  it("resets one setting without disturbing the others", () => {
    // Every setting moved off its default, then one of them put back.
    let edited = { ...DEFAULT_SETTINGS };
    for (const def of SETTING_DEFS) edited = cycleSetting(edited, def.key, 1);
    for (const def of SETTING_DEFS) {
      const reset = resetSetting(edited, def.key);
      expect(read(reset, def.key), `${def.key} was not reset`).toBe(def.default);
      for (const other of SETTING_DEFS) {
        if (other.key === def.key) continue;
        expect(read(reset, other.key), `resetting ${def.key} disturbed ${other.key}`)
          .toBe(read(edited, other.key));
      }
    }
  });

  it("resets every setting to the table default", () => {
    expect(resetAllSettings()).toEqual(DEFAULT_SETTINGS);
    // A fresh object, so the caller cannot mutate the module's defaults.
    expect(resetAllSettings()).not.toBe(DEFAULT_SETTINGS);
  });

  it("marks a setting as modified only when it differs from its default", () => {
    for (const def of SETTING_DEFS) {
      expect(isSettingModified(DEFAULT_SETTINGS, def), `${def.key} was modified at defaults`)
        .toBe(false);
    }
    for (const def of SETTING_DEFS) {
      expect(
        isSettingModified(cycleSetting(DEFAULT_SETTINGS, def.key, 1), def),
        `${def.key} was not marked modified after a cycle`,
      ).toBe(true);
    }
    expect(isSettingModified(DEFAULT_SETTINGS, undefined)).toBe(false);
  });

  it("reads a value off the settings object for every def in the table", () => {
    for (const def of SETTING_DEFS) {
      expect(settingValue(DEFAULT_SETTINGS, def), `${def.key} had no value`).toBe(def.default);
    }
    expect(settingValue(DEFAULT_SETTINGS, undefined)).toBeUndefined();
  });
});
