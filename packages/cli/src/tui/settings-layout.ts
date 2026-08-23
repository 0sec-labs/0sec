/**
 * Layout, navigation and windowing arithmetic for the full-screen settings
 * surface.
 *
 * Every number the settings screen renders with is computed here, for the
 * reason spelled out in `PRIMITIVES.md`: OpenTUI lays rows out with Yoga, and
 * Yoga *shrinks* siblings rather than clipping them. Two `<text>` nodes that
 * together want more cells than their row has are both painted in full into
 * boxes that are now too small, and the terminal shows the two strings
 * interleaved character by character — `runs12`, `target:cnone`,
 * `Showpavailableenslash commands`. The same failure on the vertical axis
 * makes a bordered box paint its own bottom border through its last content
 * row (`-/clear--------/new-`).
 *
 * The only durable defence found so far is to move the arithmetic out of the
 * component and into a pure function that a sweep can hammer, which is what
 * `chat-layout.ts` did for the chat surface. This module is that for
 * `settings-screen.tsx`: the component reads widths and row counts off a
 * `SettingsLayout` and never computes one.
 *
 * The second job here is the *shape* of the list. `SETTING_DEFS` is a table,
 * and the whole point of that table is that adding a toggle is one entry. So
 * the screen may not hardcode a list, a group order, or a row count — the row
 * model is derived from the table on every render, and a def added tomorrow
 * appears with its group heading, its detail text and its keybindings without
 * this file or the component changing.
 */

import {
  DEFAULT_SETTINGS,
  SETTING_DEFS,
  normalizeSettings,
  type SettingDef,
  type TuiSettings,
} from "./settings.js";
import { sanitizeTuiText } from "./text.js";

// ---------------------------------------------------------------------------
// Numeric hygiene
// ---------------------------------------------------------------------------

/**
 * Cell and row counts are non-negative integers.
 *
 * Terminal geometry arrives from `useTerminalDimensions`, which reports 0 on a
 * detached tty and can report a fractional or `NaN` size mid-resize. Yoga
 * accepts all of those and lays out sub-cell boxes that round inconsistently
 * between siblings, which is itself an overlap. Everything entering the
 * allocator is normalised here first.
 */
function cells(value: unknown, fallback = 0): number {
  const raw = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  const truncated = Math.trunc(raw);
  return truncated > 0 ? truncated : 0;
}

/**
 * `TuiSettings` by dynamic key.
 *
 * The table is keyed by string and the screen is driven by the table, so every
 * read and write here is dynamic while `TuiSettings` is a closed interface
 * with no index signature. One narrow, named cast is better than the same
 * `as unknown as` appearing at six call sites — and every write still leaves
 * through `normalizeSettings`, which is total, so a bad key or value is
 * repaired rather than trusted.
 */
function asRecord(settings: TuiSettings): Record<string, unknown> {
  return settings as unknown as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Shell chrome
// ---------------------------------------------------------------------------

/** `ShellFrame` pads two cells either side of every screen. */
const SHELL_HORIZONTAL_PADDING = 2;
/** A bordered, `paddingX={1}` panel spends four cells on itself. */
const PANEL_HORIZONTAL_CHROME = 4;
/** Below this `HeaderBar` stacks its columns, costing two extra rows. */
const HEADER_COMPACT_WIDTH = 88;
/** Below this `FooterBar` stacks hint and stamp, costing two extra rows. */
const FOOTER_INLINE_WIDTH = 64;

/**
 * Rows the shell spends before and after a screen's own content.
 *
 * This mirrors `getShellChromeHeight` and `getFooterLayout` in `run.tsx`.
 * Those live in a `.tsx` module that pulls in the whole OpenTUI renderer, so
 * importing them here would make this module — and its sweep — unloadable
 * without a terminal. The duplication is deliberate and narrow: three
 * constants and one branch, verified against the real frame by the render
 * captures rather than by a shared import.
 *
 * Two terms differ from `getShellChromeHeight`, and both were found by
 * counting rows in a real capture rather than by reading the source.
 *
 * `FooterBar` stacks below 64 content cells and then occupies three rows, not
 * one. The settings screen is the first to budget for that, because it is the
 * first to fill its column completely.
 *
 * And a compact `HeaderBar` renders four rows only when it is given a status;
 * this screen gives it none, so it renders three. Claiming the fourth would
 * leave a permanently blank row above the footer on every narrow terminal.
 */
export function shellChromeRows(width: number): number {
  const total = cells(width);
  const headerContentWidth = total - SHELL_HORIZONTAL_PADDING * 2 - PANEL_HORIZONTAL_CHROME;
  const headerContentRows = headerContentWidth < HEADER_COMPACT_WIDTH ? 3 : 2;
  const contentWidth = Math.max(1, total - SHELL_HORIZONTAL_PADDING * 2);
  const footerRows = contentWidth >= FOOTER_INLINE_WIDTH ? 1 : 3;
  // 1 row of top padding, the header box (two borders + content + margin),
  // and the footer.
  return 1 + (headerContentRows + 3) + footerRows;
}

// ---------------------------------------------------------------------------
// Row model
// ---------------------------------------------------------------------------

export type SettingsRow =
  | { readonly kind: "heading"; readonly group: string }
  | { readonly kind: "setting"; readonly group: string; readonly def: SettingDef };

/**
 * Flattens `SETTING_DEFS` into a renderable list of group headings and
 * settings, honouring an optional filter.
 *
 * Group order is order of first appearance in the table rather than an
 * alphabetical or hardcoded sort, so the author of a def controls where it
 * lands by where they put it — and a new group needs no edit here. A heading
 * is only emitted when at least one of its settings survived the filter,
 * because a heading with nothing under it is a row of noise on a screen whose
 * whole purpose is to have rows to spare.
 *
 * The filter is AND-over-terms across the key, label, group, description and
 * choice list. Matching the description matters as much as matching the label:
 * the words an operator reaches for ("colour", "lateral", "token") often
 * appear only in the prose, and a filter that misses them sends people to the
 * JSON file instead.
 */
export function buildSettingsRows(
  defs: readonly SettingDef[] = SETTING_DEFS,
  filter = "",
  activeGroup?: string,
): SettingsRow[] {
  const terms = sanitizeTuiText(filter).toLowerCase().split(" ").filter(Boolean);

  const matches = (def: SettingDef): boolean => {
    if (terms.length === 0) return true;
    const haystack = [
      def.key,
      def.label,
      def.group,
      def.description,
      ...(def.choices ?? []),
    ]
      .join(" ")
      .toLowerCase();
    return terms.every((term) => haystack.includes(term));
  };

  const order: string[] = [];
  const byGroup = new Map<string, SettingDef[]>();
  for (const def of defs) {
    if (!def || typeof def.key !== "string") continue;
    if (!matches(def)) continue;
    const group = typeof def.group === "string" && def.group.length > 0 ? def.group : "Other";
    if (!byGroup.has(group)) {
      byGroup.set(group, []);
      order.push(group);
    }
    byGroup.get(group)?.push(def);
  }

  // Tabbed mode: with no filter and a chosen tab, the body shows only that one
  // group — the tab bar is what tells the operator which group they are in, so
  // the screen no longer stacks every group into one scroll. A live filter
  // overrides the tabs (search is a cross-group operation), so `activeGroup` is
  // ignored the moment there is a term to match, and every surviving group is
  // returned exactly as before.
  const groupsToRender =
    terms.length === 0 && typeof activeGroup === "string"
      ? order.filter((group) => group === activeGroup)
      : order;

  const rows: SettingsRow[] = [];
  for (const group of groupsToRender) {
    rows.push({ kind: "heading", group });
    for (const def of byGroup.get(group) ?? []) rows.push({ kind: "setting", group, def });
  }
  return rows;
}

/**
 * The tab list: every group in first-appearance order.
 *
 * This is the row model's group order without its rows — the tab bar shows one
 * tab per group, in the order their first def appears in `SETTING_DEFS`, so the
 * author of a def still controls where its group lands and a new group needs no
 * edit here.
 */
export function settingsGroups(defs: readonly SettingDef[] = SETTING_DEFS): string[] {
  const order: string[] = [];
  const seen = new Set<string>();
  for (const def of defs) {
    if (!def || typeof def.key !== "string") continue;
    const group = typeof def.group === "string" && def.group.length > 0 ? def.group : "Other";
    if (seen.has(group)) continue;
    seen.add(group);
    order.push(group);
  }
  return order;
}

/**
 * The set of groups that have at least one setting surviving `filter`.
 *
 * Used by the tab bar in search mode to dim the tabs a query cannot reach.
 * Derived from `buildSettingsRows`, which already only emits a heading for a
 * group with matches, so the two can never disagree about what matched.
 */
export function groupsWithMatches(
  defs: readonly SettingDef[] = SETTING_DEFS,
  filter = "",
): Set<string> {
  return new Set(
    buildSettingsRows(defs, filter)
      .filter((row): row is Extract<SettingsRow, { kind: "heading" }> => row.kind === "heading")
      .map((row) => row.group),
  );
}

/** Cells the tab bar leaves between two adjacent tabs. */
export const SETTINGS_TAB_GAP = 2;

export interface SettingsTab {
  readonly group: string;
  /** The label as rendered, uppercased and already fitted to `width` cells. */
  readonly label: string;
  /** Cells this tab occupies. The bar never sums past the width it was given. */
  readonly width: number;
  /** The tab the body is currently showing. */
  readonly active: boolean;
  /** In search mode, whether this group has any rows matching the filter. */
  readonly matched: boolean;
}

/**
 * Lays the tab bar out to a fixed cell budget.
 *
 * Every width the bar renders with is decided here rather than in the
 * component, for the reason the rest of this module exists: two `<text>` nodes
 * that together want more cells than the row has are painted over each other by
 * Yoga rather than clipped. The tabs plus their `SETTINGS_TAB_GAP` separators
 * are guaranteed to sum to at most `width`. When every group fits, each tab
 * keeps its full label; when the row is too narrow even to hold one cell per
 * group plus the gaps, the bar shows a window of tabs around the active one
 * rather than overflowing — and inside that window, once the labels no longer
 * fit, the room left after the gaps is split evenly (the earliest tabs taking
 * the remainder) and each label is hard-truncated to its share.
 *
 * `matched` marks, in search mode, which groups a query can still reach; pass
 * `null` in tabbed mode and every tab reads as matched. Pass `""` as
 * `activeGroup` to render no active tab (search overrides the tab selection).
 */
export function settingsTabBar(
  groups: readonly string[],
  activeGroup: string,
  width: number,
  matched?: ReadonlySet<string> | null,
): SettingsTab[] {
  const clean = groups.filter((group) => typeof group === "string" && group.length > 0);
  const total = cells(width);
  if (clean.length === 0 || total <= 0) return [];

  // How many tabs can share the row with one cell of label apiece and a gap
  // between each. `fits(1)` is always true when total >= 1, so at least the
  // active tab is shown. Below this the bar would paint its own gaps over the
  // edge of the row, which is the overlap this module exists to prevent.
  const fits = (k: number): boolean => k >= 1 && k + SETTINGS_TAB_GAP * (k - 1) <= total;
  let count = clean.length;
  while (count > 1 && !fits(count)) count -= 1;

  // Window the shown tabs around the active one so it is never the tab that got
  // dropped. In search mode (activeGroup === "") the window opens at the start.
  const activeIndex = Math.max(0, clean.indexOf(activeGroup));
  const start = Math.max(0, Math.min(activeIndex - Math.floor(count / 2), clean.length - count));
  const shown = clean.slice(start, start + count);
  const labels = shown.map((group) => sanitizeTuiText(group).toUpperCase());

  const gaps = SETTINGS_TAB_GAP * (shown.length - 1);
  const room = Math.max(0, total - gaps);
  const natural = labels.reduce((sum, label) => sum + label.length, 0);

  let budgets: number[];
  if (natural <= room) {
    budgets = labels.map((label) => label.length);
  } else {
    const base = Math.floor(room / shown.length);
    let remainder = room - base * shown.length;
    budgets = labels.map(() => {
      const bonus = remainder > 0 ? 1 : 0;
      if (remainder > 0) remainder -= 1;
      return base + bonus;
    });
  }

  return shown.map((group, index) => {
    const budget = budgets[index] ?? 0;
    return {
      group,
      label: (labels[index] ?? "").slice(0, budget),
      width: budget,
      active: group === activeGroup,
      matched: matched ? matched.has(group) : true,
    };
  });
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

/**
 * Greedy word wrap onto `width`-cell lines.
 *
 * The input is sanitised first, so control sequences and newlines from a
 * description cannot smuggle a cursor move into the frame, and a token longer
 * than the line is hard-broken rather than allowed to overhang — an overhang
 * is the horizontal overlap this module exists to prevent.
 */
export function wrapCells(value: unknown, width: number): string[] {
  const limit = cells(width);
  const text = sanitizeTuiText(value);
  if (limit <= 0 || text.length === 0) return [];

  const lines: string[] = [];
  let line = "";
  for (const word of text.split(" ")) {
    let token = word;
    while (token.length > limit) {
      if (line.length > 0) {
        lines.push(line);
        line = "";
      }
      lines.push(token.slice(0, limit));
      token = token.slice(limit);
    }
    if (token.length === 0) continue;
    if (line.length === 0) line = token;
    else if (line.length + 1 + token.length <= limit) line = `${line} ${token}`;
    else {
      lines.push(line);
      line = token;
    }
  }
  if (line.length > 0) lines.push(line);
  return lines;
}

/** How a setting's current value reads in the list and the detail pane. */
export function settingValueLabel(def: SettingDef | undefined, value: unknown): string {
  if (!def) return "";
  if (def.kind === "boolean") return value === true ? "on" : "off";
  return sanitizeTuiText(value);
}

export type SettingsDetailTone = "title" | "text" | "muted" | "accent" | "warn" | "blank";

export interface SettingsDetailLine {
  readonly text: string;
  readonly tone: SettingsDetailTone;
}

/**
 * The detail pane's body, as flat tone-tagged lines.
 *
 * Content is decided here and colour is decided by the component, so the pane
 * can be asserted on without a renderer. Every field uses a `": "` separator
 * rather than alignment columns: `sanitizeTuiText` collapses runs of
 * whitespace, so a padded literal would be trimmed away and the label would
 * fuse to its value.
 */
export interface SettingsDetailOptions {
  /** Omit the blank separator rows. Set when the pane is short of rows. */
  compact?: boolean;
}

export function settingsDetailLines(
  def: SettingDef | undefined,
  value: unknown,
  width: number,
  { compact = false }: SettingsDetailOptions = {},
): SettingsDetailLine[] {
  const limit = cells(width);
  if (!def || limit <= 0) return [];

  const lines: SettingsDetailLine[] = [];
  const separate = () => {
    if (!compact) lines.push({ text: "", tone: "blank" });
  };

  for (const text of wrapCells(def.label, limit)) lines.push({ text, tone: "title" });
  separate();
  for (const text of wrapCells(def.description, limit)) lines.push({ text, tone: "text" });
  separate();

  const current = settingValueLabel(def, value);
  const fallback = settingValueLabel(def, def.default);
  for (const text of wrapCells(`Current: ${current}`, limit)) {
    lines.push({ text, tone: current === fallback ? "muted" : "accent" });
  }
  for (const text of wrapCells(`Default: ${fallback}`, limit)) {
    lines.push({ text, tone: "muted" });
  }
  const choices = def.kind === "enum" ? (def.choices ?? []) : ["on", "off"];
  for (const text of wrapCells(`Allowed: ${choices.join(", ")}`, limit)) {
    lines.push({ text, tone: "muted" });
  }
  separate();
  for (const text of wrapCells(`Key: ${def.key}`, limit)) lines.push({ text, tone: "muted" });

  return lines;
}

/**
 * Trims detail lines to the rows the pane actually has.
 *
 * Rendering more rows than the box holds is what pushes a border through the
 * content, so the overflow has to be cut — but it is marked rather than cut
 * silently, because a description that stops mid-sentence with no sign it was
 * truncated reads as a bug in the description.
 *
 * Given a width, the marker is appended to the last surviving line instead of
 * taking a row of its own. On the terminals where clipping actually happens
 * the pane has three rows, and spending one of them on a lone `...` throws
 * away a third of the text to say the text was thrown away.
 */
export function clipDetailLines(
  lines: readonly SettingsDetailLine[],
  rows: number,
  width = 0,
): SettingsDetailLine[] {
  const limit = cells(rows);
  if (limit <= 0) return [];
  if (lines.length <= limit) return [...lines];

  const kept = lines.slice(0, limit);
  const last = kept[limit - 1];
  const room = cells(width);
  // Four cells: a space and the three dots. Below eight there is nothing left
  // of the line once the marker is paid for, so it takes the row instead.
  if (room >= 8 && last && last.text.length > 0) {
    const head = last.text.slice(0, Math.max(0, room - 4)).trimEnd();
    kept[limit - 1] = { text: `${head} ...`, tone: last.tone };
  } else {
    kept[limit - 1] = { text: "...", tone: "muted" };
  }
  return kept;
}

// ---------------------------------------------------------------------------
// Titles, hints and mutation
// ---------------------------------------------------------------------------

export type SettingsMode = "browse" | "filter" | "confirm-reset" | "confirm-reset-all";

/**
 * The footer hint, per mode.
 *
 * These are the real bindings, not a generic "arrows to move" — a settings
 * screen that hides its own reset key behind discovery is a settings screen
 * people edit the JSON file instead of using.
 */
export function settingsFooterHint(mode: SettingsMode, hasFilter = false): string {
  switch (mode) {
    case "filter":
      return "type to filter · enter/esc done · backspace delete";
    case "confirm-reset":
    case "confirm-reset-all":
      return "y confirm · n or esc cancel";
    default:
      return [
        "up/down move",
        "tab or left/right group",
        "enter/space change",
        "/ filter",
        "r reset",
        "shift+r reset all",
        hasFilter ? "esc clear filter" : "esc back",
        "ctrl+c exit",
      ].join(" · ");
  }
}

/**
 * `r` and `shift+r` are reserved from the type-to-filter path.
 *
 * The screen wants both "start typing to filter" and a reset key, and those
 * two cannot both own the letter `r`. Reset wins, because it is destructive
 * and therefore has to be reachable without a mode change, and `/` remains the
 * explicit way to filter for anything beginning with `r`.
 */
export function isFilterKey(sequence: unknown): boolean {
  if (typeof sequence !== "string" || sequence.length !== 1) return false;
  if (sequence === "r" || sequence === "R") return false;
  const code = sequence.charCodeAt(0);
  return code >= 0x20 && code !== 0x7f;
}

/**
 * Steps one setting forwards or backwards.
 *
 * `toggleSetting` in `settings.ts` only advances, which is enough for a picker
 * bound to one key but not for ←/→ on a three-value enum. Both directions go
 * through `normalizeSettings`, so a value that fell outside its choice list —
 * a hand-edited file, a def whose choices changed between releases — is
 * repaired rather than propagated.
 */
export function cycleSetting(
  settings: TuiSettings,
  key: string,
  delta: 1 | -1 = 1,
  defs: readonly SettingDef[] = SETTING_DEFS,
): TuiSettings {
  const def = defs.find((candidate) => candidate.key === key);
  if (!def) return settings;

  const current = normalizeSettings(settings);
  if (def.kind === "boolean") {
    return normalizeSettings({
      ...current,
      [def.key]: !asRecord(current)[def.key],
    });
  }

  const choices = def.choices ?? [];
  if (choices.length === 0) return current;
  const at = choices.indexOf(String(asRecord(current)[def.key]));
  const next = choices[(((at < 0 ? 0 : at) + delta) % choices.length + choices.length) % choices.length];
  return normalizeSettings({ ...current, [def.key]: next });
}

/** Restores one setting to its table default. */
export function resetSetting(
  settings: TuiSettings,
  key: string,
  defs: readonly SettingDef[] = SETTING_DEFS,
): TuiSettings {
  const def = defs.find((candidate) => candidate.key === key);
  if (!def) return normalizeSettings(settings);
  return normalizeSettings({ ...normalizeSettings(settings), [def.key]: def.default });
}

/** Restores every setting to its table default. */
export function resetAllSettings(): TuiSettings {
  return { ...DEFAULT_SETTINGS };
}

/** True when the setting differs from the default the table ships. */
export function isSettingModified(
  settings: TuiSettings,
  def: SettingDef | undefined,
): boolean {
  if (!def) return false;
  const value = asRecord(normalizeSettings(settings))[def.key];
  return value !== def.default;
}

/** Reads one setting off a `TuiSettings` without the caller casting. */
export function settingValue(settings: TuiSettings, def: SettingDef | undefined): unknown {
  if (!def) return undefined;
  return asRecord(normalizeSettings(settings))[def.key];
}
