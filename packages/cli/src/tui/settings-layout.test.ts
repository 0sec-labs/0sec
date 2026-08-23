import { describe, expect, it } from "vitest";

import {
  SETTINGS_TAB_GAP,
  buildSettingsRows,
  clipDetailLines,
  cycleSetting,
  groupsWithMatches,
  isFilterKey,
  isSettingModified,
  resetAllSettings,
  resetSetting,
  settingValue,
  settingValueLabel,
  settingsDetailLines,
  settingsFooterHint,
  settingsGroups,
  settingsTabBar,
  wrapCells,
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
  });

  // ── tabbed mode (activeGroup) ──
  it("with an activeGroup and no filter, returns only that group's rows", () => {
    for (const group of GROUPS) {
      const rows = buildSettingsRows(SETTING_DEFS, "", group);
      // Exactly one heading, and it is the requested group.
      const headings = rows.filter((row) => row.kind === "heading");
      expect(headings, `activeGroup ${group} produced the wrong headings`).toHaveLength(1);
      expect(rows[0]).toEqual({ kind: "heading", group });
      // Every setting row belongs to that group, and it is every def in it.
      const settingRows = rows.filter(
        (row): row is Extract<SettingsRow, { kind: "setting" }> => row.kind === "setting",
      );
      for (const row of settingRows) expect(row.def.group).toBe(group);
      expect(settingRows.map((row) => row.def.key).sort()).toEqual(
        SETTING_DEFS.filter((def) => def.group === group)
          .map((def) => def.key)
          .sort(),
      );
    }
  });

  it("returns an empty list for an activeGroup that no def declares", () => {
    expect(buildSettingsRows(SETTING_DEFS, "", "NoSuchGroup")).toEqual([]);
  });

  it("ignores activeGroup while a filter is active — search overrides tabs", () => {
    // A term that reaches more than one group, so the override is observable.
    const withActive = buildSettingsRows(SETTING_DEFS, "show", GROUPS[0]);
    const withoutActive = buildSettingsRows(SETTING_DEFS, "show");
    expect(withActive).toEqual(withoutActive);
  });
});

// ---------------------------------------------------------------------------

describe("settingsGroups", () => {
  it("lists every group once, in first-appearance order", () => {
    const expected = [...new Set(SETTING_DEFS.map((def) => def.group))];
    expect(settingsGroups()).toEqual(expected);
  });

  it("matches the heading order buildSettingsRows renders", () => {
    const headings = buildSettingsRows()
      .filter((row) => row.kind === "heading")
      .map((row) => row.group);
    expect(settingsGroups()).toEqual(headings);
  });

  it("picks up a def added to a brand-new group", () => {
    expect(settingsGroups([...SETTING_DEFS, PROBE_DEF]).at(-1)).toBe("Experimental");
  });
});

describe("groupsWithMatches", () => {
  it("returns every group when the filter is empty", () => {
    expect([...groupsWithMatches(SETTING_DEFS, "")].sort()).toEqual([...GROUPS].sort());
  });

  it("returns only the group a key-filter reaches", () => {
    for (const def of SETTING_DEFS) {
      const matched = groupsWithMatches(SETTING_DEFS, def.key);
      expect(matched.has(def.group), `filtering ${def.key} lost its group`).toBe(true);
      // The key is unique, so it reaches exactly the one group it lives in.
      expect(matched.size).toBe(1);
    }
  });

  it("returns no group when nothing matches", () => {
    expect(groupsWithMatches(SETTING_DEFS, "zzzzz").size).toBe(0);
  });
});

describe("settingsTabBar", () => {
  const GROUP_LIST = settingsGroups();

  it("renders one tab per group, uppercased, with the active one marked", () => {
    const active = GROUP_LIST[1] ?? GROUP_LIST[0];
    const tabs = settingsTabBar(GROUP_LIST, active, 200);
    expect(tabs.map((tab) => tab.group)).toEqual(GROUP_LIST);
    expect(tabs.map((tab) => tab.label)).toEqual(GROUP_LIST.map((g) => g.toUpperCase()));
    expect(tabs.filter((tab) => tab.active)).toHaveLength(1);
    expect(tabs.find((tab) => tab.active)?.group).toBe(active);
  });

  it("never sums its tabs and gaps past the width it was given", () => {
    for (let width = 0; width <= 120; width += 1) {
      const tabs = settingsTabBar(GROUP_LIST, GROUP_LIST[0], width);
      const gaps = tabs.length > 0 ? SETTINGS_TAB_GAP * (tabs.length - 1) : 0;
      const total = tabs.reduce((sum, tab) => sum + tab.width, 0) + gaps;
      expect(total, `tab bar overflowed ${width} cells`).toBeLessThanOrEqual(Math.max(0, width));
      // A label is never wider than the cell budget the bar handed it.
      for (const tab of tabs) expect(tab.label.length).toBeLessThanOrEqual(tab.width);
    }
  });

  it("returns nothing when there is no room or no groups", () => {
    expect(settingsTabBar(GROUP_LIST, GROUP_LIST[0], 0)).toEqual([]);
    expect(settingsTabBar([], "Display", 100)).toEqual([]);
  });

  it("marks matched groups and dims the rest in search mode", () => {
    const matched = new Set([GROUP_LIST[0]]);
    // Empty activeGroup: search owns the body, so no tab is active.
    const tabs = settingsTabBar(GROUP_LIST, "", 200, matched);
    expect(tabs.every((tab) => !tab.active)).toBe(true);
    expect(tabs.find((tab) => tab.group === GROUP_LIST[0])?.matched).toBe(true);
    for (const tab of tabs.slice(1)) expect(tab.matched).toBe(false);
  });

  it("treats every tab as matched when no match set is given", () => {
    const tabs = settingsTabBar(GROUP_LIST, GROUP_LIST[0], 200);
    expect(tabs.every((tab) => tab.matched)).toBe(true);
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
    // "tab" joins the browse hint now that tab / shift-tab (and left/right)
    // switch group tabs; the value change moved onto enter/space alone.
    for (const fragment of [
      "up/down",
      "enter/space",
      "left/right",
      "tab",
      "/ filter",
      "r reset",
      "shift+r",
    ]) {
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
