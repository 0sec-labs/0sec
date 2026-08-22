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

function clamp(value: number, low: number, high: number): number {
  if (high < low) return low;
  return Math.min(Math.max(value, low), high);
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

  const rows: SettingsRow[] = [];
  for (const group of order) {
    rows.push({ kind: "heading", group });
    for (const def of byGroup.get(group) ?? []) rows.push({ kind: "setting", group, def });
  }
  return rows;
}

/** Index of the first selectable row, or -1 when the list has none. */
export function firstSelectableIndex(rows: readonly SettingsRow[]): number {
  for (let index = 0; index < rows.length; index++) {
    if (rows[index]?.kind === "setting") return index;
  }
  return -1;
}

/** Index of the last selectable row, or -1 when the list has none. */
export function lastSelectableIndex(rows: readonly SettingsRow[]): number {
  for (let index = rows.length - 1; index >= 0; index--) {
    if (rows[index]?.kind === "setting") return index;
  }
  return -1;
}

/**
 * Pulls an arbitrary index onto a selectable row.
 *
 * Filtering is the reason this exists: the highlighted row can vanish from
 * under the cursor between two keystrokes, and the selection then has to land
 * somewhere sane rather than on a heading or past the end. Searching forward
 * first keeps the cursor near where the list was, which reads better than
 * snapping back to the top on every keystroke.
 */
export function clampSelection(rows: readonly SettingsRow[], current: number): number {
  if (rows.length === 0) return -1;
  const start = clamp(Math.trunc(Number.isFinite(current) ? current : 0), 0, rows.length - 1);
  for (let index = start; index < rows.length; index++) {
    if (rows[index]?.kind === "setting") return index;
  }
  for (let index = start - 1; index >= 0; index--) {
    if (rows[index]?.kind === "setting") return index;
  }
  return -1;
}

/**
 * Moves the selection by `delta` rows, skipping headings and wrapping.
 *
 * Wrapping is what makes a short grouped list usable — the Security group sits
 * at the bottom, and pressing up from the top row is the fastest way to reach
 * it. The inner guard loop is bounded by the list length so a list of nothing
 * but headings terminates instead of spinning.
 */
export function moveSelection(
  rows: readonly SettingsRow[],
  current: number,
  delta: number,
): number {
  const total = rows.length;
  if (total === 0) return -1;
  const anchor = clampSelection(rows, current);
  if (anchor < 0) return -1;

  const step = delta >= 0 ? 1 : -1;
  const truncated = Math.trunc(Number.isFinite(delta) ? delta : 0);
  const count = Math.max(1, Math.abs(truncated) || 1);

  let index = anchor;
  for (let moved = 0; moved < count; moved++) {
    let probe = index;
    for (let guard = 0; guard < total; guard++) {
      probe = (probe + step + total) % total;
      if (rows[probe]?.kind === "setting") break;
    }
    if (rows[probe]?.kind !== "setting") return anchor;
    index = probe;
  }
  return index;
}

// ---------------------------------------------------------------------------
// Windowing
// ---------------------------------------------------------------------------

export interface SettingsWindowInput {
  rows: readonly SettingsRow[];
  /** Highlighted row index, or -1 when the filter matched nothing. */
  selected: number;
  /** Rows the list body can actually paint. */
  visible: number;
  /** Previous window start, so the list scrolls instead of re-centring. */
  anchor?: number;
}

export interface SettingsWindow {
  start: number;
  /** Exclusive. `rows.slice(start, end)` is exactly what may be rendered. */
  end: number;
  /** `end - start`; never exceeds `visible` and never exceeds `rows.length`. */
  count: number;
  total: number;
  hasAbove: boolean;
  hasBelow: boolean;
}

/**
 * Scroll-into-view windowing, stateless apart from the caller's last start.
 *
 * Taking the previous start as an anchor rather than re-centring on every move
 * is the difference between a list that scrolls and a list that jumps: with
 * centring, a single ↓ shifts every visible row by one even when the cursor
 * was comfortably mid-pane.
 *
 * The heading rule is the part worth stating. When the cursor lands on the
 * first setting of a group, the window is pulled up one extra row so that
 * group's heading comes with it. A settings list scrolled to the point where
 * the highlighted row has no visible heading is a list that has stopped saying
 * which group you are editing.
 */
export function computeSettingsWindow({
  rows,
  selected,
  visible,
  anchor = 0,
}: SettingsWindowInput): SettingsWindow {
  const total = rows.length;
  const capacity = Math.min(cells(visible), total);
  if (capacity <= 0) {
    return { start: 0, end: 0, count: 0, total, hasAbove: total > 0, hasBelow: false };
  }

  const maxStart = Math.max(0, total - capacity);
  let start = clamp(cells(anchor), 0, maxStart);

  const cursor = Math.trunc(Number.isFinite(selected) ? selected : -1);
  if (cursor >= 0 && cursor < total) {
    // Reserve the group heading directly above the cursor, when there is one
    // — but only when the pane has a second row to spend on it. At a capacity
    // of one, pulling the heading in would push the cursor itself out, and a
    // window that does not contain the highlighted row is worse than a window
    // that does not say which group it belongs to.
    const wanted =
      capacity >= 2 && rows[cursor - 1]?.kind === "heading" ? cursor - 1 : cursor;
    if (cursor > start + capacity - 1) start = cursor - capacity + 1;
    if (wanted < start) start = wanted;
    start = clamp(start, 0, maxStart);
  }

  const end = Math.min(total, start + capacity);
  return {
    start,
    end,
    count: end - start,
    total,
    hasAbove: start > 0,
    hasBelow: end < total,
  };
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/** Below this the detail pane cannot sit beside the list and stacks under it. */
const TWO_PANE_MIN_WIDTH = 76;
/** A detail pane narrower than this wraps prose into confetti. */
const DETAIL_MIN_WIDTH = 30;
/** Past this the detail pane is just whitespace; give the cells to the list. */
const DETAIL_MAX_WIDTH = 52;
/** Share of the content column the detail pane asks for when it fits beside. */
const DETAIL_WIDTH_SHARE = 0.42;
/** A list narrower than this cannot show a label and a value side by side. */
const LIST_MIN_WIDTH = 34;
/** Widest the value column ever gets; the longest choice is "comfortable". */
const VALUE_MAX_WIDTH = 12;
/** Share of a list row the value column may take on a narrow screen. */
const VALUE_WIDTH_SHARE = 0.4;
/** Below this the panes drop their borders rather than their content. */
const BORDERED_MIN_ROWS = 12;
/** Share of a stacked column the detail pane takes. */
const STACKED_DETAIL_SHARE = 0.4;
/** Cap on the stacked detail pane; past this the list is the better use. */
const STACKED_DETAIL_MAX_ROWS = 9;

export interface SettingsPane {
  /** Outer cells, borders included. 0 when the pane is not rendered. */
  width: number;
  /** Cells available to text inside the pane. */
  innerWidth: number;
  /** Outer rows, borders included. 0 when the pane is not rendered. */
  height: number;
  /** Rows available to content, below the title row when there is one. */
  bodyRows: number;
  /** The pane spends a row on a title. */
  hasTitle: boolean;
}

export interface SettingsRowLayout {
  /** Total cells a list row occupies; equals the list pane's inner width. */
  width: number;
  /** Selection marker column. 0 when the row is too narrow to spare it. */
  markerWidth: number;
  markerGap: number;
  labelWidth: number;
  valueGap: number;
  /** Value column. 0 when the row can only afford a label. */
  valueWidth: number;
}

export interface SettingsLayoutInput {
  width: number;
  height: number;
  /** 1 when a notice or confirm prompt occupies a row above the footer. */
  noticeRows?: number;
}

export interface SettingsLayout {
  /** The detail pane sits under the list rather than beside it. */
  stacked: boolean;
  /** The panes draw borders. False on a short terminal, where rows cost more. */
  bordered: boolean;
  /** Usable cells across, inside the shell's padding. */
  contentWidth: number;
  /** Rows the two panes may share. */
  bodyRows: number;
  /** Cells between the panes when side by side, else 0. */
  paneGap: number;
  list: SettingsPane;
  detail: SettingsPane;
  row: SettingsRowLayout;
  /** List rows that fit in the list pane's body. */
  visibleRows: number;
  /**
   * The detail pane drops the blank separator lines between its sections.
   *
   * Whitespace is the first thing to cut when rows are scarce: on a short
   * terminal the detail pane gets three of them, and spending one on a blank
   * means the description is a single line.
   */
  detailCompact: boolean;
}

/** A bordered pane spends two columns and two rows on its border and padding. */
function borderChrome(bordered: boolean): { horizontal: number; vertical: number } {
  // Two border columns plus `paddingX={1}` either side; two border rows.
  return bordered ? { horizontal: 4, vertical: 2 } : { horizontal: 0, vertical: 0 };
}

function makePane(
  width: number,
  height: number,
  chromeH: number,
  chromeV: number,
  hasTitle: boolean,
): SettingsPane {
  const outerWidth = cells(width);
  const outerHeight = cells(height);
  const verticalChrome = chromeV + (hasTitle ? 1 : 0);
  if (outerWidth <= chromeH || outerHeight <= verticalChrome) {
    return { width: 0, innerWidth: 0, height: 0, bodyRows: 0, hasTitle };
  }
  return {
    width: outerWidth,
    innerWidth: outerWidth - chromeH,
    height: outerHeight,
    bodyRows: outerHeight - verticalChrome,
    hasTitle,
  };
}

/**
 * Splits a list row into marker, label and value columns.
 *
 * Both separators are real Yoga gaps rather than padded literals, because
 * `fitTuiText` routes through `sanitizeTuiText`, which trims — a label
 * carrying its own trailing space comes back without one and fuses onto its
 * value even when the row had cells to spare. That is the `runs12` defect, and
 * it is invisible at review time.
 *
 * The value gives way before the label: a row reading `Status bar` with no
 * value still tells you which setting you are on, while a bare `on` does not.
 */
function computeRowLayout(innerWidth: number): SettingsRowLayout {
  const width = cells(innerWidth);
  if (width <= 0) {
    return { width: 0, markerWidth: 0, markerGap: 0, labelWidth: 0, valueGap: 0, valueWidth: 0 };
  }

  const markerWidth = width >= 6 ? 1 : 0;
  const markerGap = markerWidth > 0 && width > markerWidth ? 1 : 0;
  const afterMarker = Math.max(0, width - markerWidth - markerGap);

  const valueWidth =
    afterMarker >= 14 ? Math.min(VALUE_MAX_WIDTH, Math.floor(afterMarker * VALUE_WIDTH_SHARE)) : 0;
  const valueGap = valueWidth > 0 && afterMarker > valueWidth ? 1 : 0;
  const labelWidth = Math.max(0, afterMarker - valueWidth - valueGap);

  return { width, markerWidth, markerGap, labelWidth, valueGap, valueWidth };
}

/**
 * The full geometry of the settings screen.
 *
 * Horizontally: the detail pane takes a bounded share of the content column
 * when the terminal is wide enough to hold both, and stacks underneath the
 * list otherwise. Vertically: the panes give up their borders before they give
 * up rows of content, and the detail pane is dropped entirely rather than
 * rendered at a height that would push its own border through its text.
 */
export function computeSettingsLayout({
  width,
  height,
  noticeRows = 0,
}: SettingsLayoutInput): SettingsLayout {
  const terminalWidth = cells(width);
  const contentWidth = Math.max(0, terminalWidth - SHELL_HORIZONTAL_PADDING * 2);
  const bodyRows = Math.max(
    0,
    cells(height) - shellChromeRows(terminalWidth) - Math.min(1, cells(noticeRows)),
  );

  const bordered = bodyRows >= BORDERED_MIN_ROWS && contentWidth >= DETAIL_MIN_WIDTH + 4;
  const chrome = borderChrome(bordered);
  // The list always titles itself, because the title is where the scroll
  // position lives and a windowed list that does not say "1-12/14" is a list
  // that looks like the whole list. The detail pane titles itself only when it
  // sits beside the list; stacked underneath, its first line is already the
  // setting's name and a "DETAIL" caption above it is a wasted row.
  const listMinHeight = chrome.vertical + 1 + 1;
  const detailMinHeight = chrome.vertical + 1;

  // ── horizontal split ──
  const canSplit = contentWidth >= TWO_PANE_MIN_WIDTH;
  const paneGap = canSplit ? 1 : 0;
  let detailWidth = 0;
  let listWidth = contentWidth;
  if (canSplit) {
    const available = contentWidth - paneGap;
    const wanted = clamp(
      Math.floor(available * DETAIL_WIDTH_SHARE),
      DETAIL_MIN_WIDTH,
      DETAIL_MAX_WIDTH,
    );
    // The list is the pane that must survive; the detail pane only ever gets
    // what is left after the list has been kept above its own minimum.
    detailWidth = clamp(wanted, 0, Math.max(0, available - LIST_MIN_WIDTH));
    listWidth = available - detailWidth;
  }
  const stacked = detailWidth <= 0;
  if (stacked) {
    detailWidth = contentWidth;
    listWidth = contentWidth;
  }

  // ── vertical split ──
  let listHeight = 0;
  let detailHeight = 0;
  if (bodyRows >= listMinHeight) {
    if (stacked) {
      const wanted = Math.min(
        Math.floor(bodyRows * STACKED_DETAIL_SHARE),
        STACKED_DETAIL_MAX_ROWS,
      );
      // A pane below its minimum is not a small pane, it is a corrupt one —
      // Yoga paints its border through its own last row. Drop it instead.
      detailHeight =
        wanted >= detailMinHeight + 1 && bodyRows - wanted >= listMinHeight ? wanted : 0;
      listHeight = bodyRows - detailHeight;
    } else {
      listHeight = bodyRows;
      detailHeight = bodyRows >= detailMinHeight ? bodyRows : 0;
    }
  }

  const list = makePane(listWidth, listHeight, chrome.horizontal, chrome.vertical, true);
  const detail = makePane(
    detailWidth,
    detailHeight,
    chrome.horizontal,
    chrome.vertical,
    !stacked,
  );

  return {
    stacked,
    bordered,
    contentWidth,
    bodyRows,
    paneGap: list.width > 0 && detail.width > 0 && !stacked ? paneGap : 0,
    list,
    detail,
    row: computeRowLayout(list.innerWidth),
    visibleRows: list.bodyRows,
    detailCompact: !bordered,
  };
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

/** `SETTINGS 4-15/18`, or `SETTINGS 18` when the whole list is on screen. */
export function settingsListTitle(window: SettingsWindow): string {
  if (window.total === 0) return "SETTINGS 0";
  if (!window.hasAbove && !window.hasBelow) return `SETTINGS ${window.total}`;
  return `SETTINGS ${window.start + 1}-${window.end}/${window.total}`;
}

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
        "enter/space change",
        "left/right cycle",
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
