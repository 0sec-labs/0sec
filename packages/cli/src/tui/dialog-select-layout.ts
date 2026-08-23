/**
 * Pure geometry, filtering and windowing for the modal `<DialogSelect>`.
 *
 * `<DialogSelect>` is the one floating picker the console reuses for every
 * "choose one of these" moment — theme, model, slash command, session. The
 * OpenTUI component is a dumb projection; everything that is easy to get subtly
 * wrong lives here, where a width/height sweep proves it instead of a human
 * driving a terminal:
 *
 *   - the panel width for each size, clamped so it never exceeds the terminal;
 *   - the per-row column budget, so `gutter + label + description + meta` is
 *     always `<= rowWidth <= innerWidth <= panelWidth <= terminalWidth` and no
 *     two `<text>` leaves are ever handed cells that overlap (see PRIMITIVES.md:
 *     Yoga shrinks siblings rather than clipping them);
 *   - the fuzzy filter, with the label weighted over the category so typing a
 *     model name never buries it under an incidental category hit;
 *   - the scroll window, which always contains the highlighted row.
 *
 * Nothing here imports React, OpenTUI, or touches I/O.
 */

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

export type DialogSize = "small" | "medium" | "large";

export interface DialogItem {
  /** Stable identifier returned on commit. */
  id: string;
  /** Primary text, weighted highest by the filter. */
  label: string;
  /** Muted secondary text shown inline after the label. */
  description?: string;
  /** Right-aligned metadata / keybind, e.g. "openai · $5/30" or "ctrl+k". */
  meta?: string;
  /** Group heading this row sits under. Rows keep their input order within it. */
  category?: string;
  /** Marks the row that is currently in effect — drawn with a gutter dot. */
  current?: boolean;
  /** Rendered dimmed and skipped by navigation when true. */
  disabled?: boolean;
}

/** A row in the rendered list: either a group heading or a selectable item. */
export type DialogRow =
  | { kind: "header"; category: string; key: string }
  | { kind: "item"; item: DialogItem; itemIndex: number; key: string };

// ---------------------------------------------------------------------------
// Numeric helpers
// ---------------------------------------------------------------------------

function cells(value: unknown, fallback = 0): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? Math.max(0, Math.trunc(n)) : fallback;
}

function clamp(value: number, lo: number, hi: number): number {
  if (hi < lo) return lo;
  return Math.min(Math.max(value, lo), hi);
}

// ---------------------------------------------------------------------------
// Fuzzy filter — label weighted over category, then meta/description
// ---------------------------------------------------------------------------

/**
 * Field weights. A hit in the label sorts ahead of a hit anywhere else, and a
 * substring always sorts ahead of a mere subsequence in the *same* field — so
 * "gpt5" surfaces "gpt-5" before something whose category happens to contain
 * the same letters in order. Lower is better.
 */
const FIELD_LABEL = 0;
const FIELD_CATEGORY = 1;
const FIELD_META = 2;
const FIELD_DESCRIPTION = 3;

const KIND_PREFIX = 0;
const KIND_SUBSTRING = 1;
const KIND_SUBSEQUENCE = 2;

const NO_MATCH = Number.POSITIVE_INFINITY;

function isSubsequence(needle: string, hay: string): boolean {
  let at = 0;
  for (let i = 0; i < hay.length && at < needle.length; i += 1) {
    if (hay[i] === needle[at]) at += 1;
  }
  return at === needle.length;
}

/** Match kind of `needle` within one field, or -1 for no match. */
function matchKind(field: string, needle: string): number {
  if (field.length === 0) return -1;
  const idx = field.indexOf(needle);
  if (idx === 0) return KIND_PREFIX;
  if (idx > 0) return KIND_SUBSTRING;
  return isSubsequence(needle, field) ? KIND_SUBSEQUENCE : -1;
}

/**
 * Score one item against a lowercased needle. The score packs the best field
 * (weighted) and, within it, the match kind, so ordering is a single numeric
 * comparison. Returns `NO_MATCH` when the needle appears in no field.
 */
export function rankDialogItem(item: DialogItem, needle: string): number {
  if (needle.length === 0) return 0;
  const fields: Array<[number, string | undefined]> = [
    [FIELD_LABEL, item.label],
    [FIELD_CATEGORY, item.category],
    [FIELD_META, item.meta],
    [FIELD_DESCRIPTION, item.description],
  ];
  let best = NO_MATCH;
  for (const [weight, raw] of fields) {
    if (!raw) continue;
    const kind = matchKind(raw.toLowerCase(), needle);
    if (kind < 0) continue;
    const score = weight * 4 + kind;
    if (score < best) best = score;
  }
  return best;
}

/**
 * Filtered, ranked items. An empty query keeps input order untouched; a
 * non-empty query sorts by score with the original position as the final,
 * stable tiebreak (carried explicitly rather than trusting sort stability).
 */
export function filterDialogItems(items: readonly DialogItem[], query: string): DialogItem[] {
  const needle = query.trim().toLowerCase();
  if (needle.length === 0) return items.slice();
  const ranked: Array<{ item: DialogItem; score: number; position: number }> = [];
  items.forEach((item, position) => {
    const score = rankDialogItem(item, needle);
    if (score !== NO_MATCH) ranked.push({ item, score, position });
  });
  ranked.sort((a, b) => (a.score === b.score ? a.position - b.position : a.score - b.score));
  return ranked.map((entry) => entry.item);
}

// ---------------------------------------------------------------------------
// Row assembly (headings interleaved with items)
// ---------------------------------------------------------------------------

/**
 * Flatten filtered items into render rows. Group headings are emitted, in
 * first-seen order, only when at least one item carries a category; a list with
 * no categories renders as a flat item list with no headings at all.
 *
 * `itemIndex` on each item row is its position in `items` — the value the
 * navigation cursor moves over — so the component never has to reconcile a
 * display index against a selection index.
 */
export function buildDialogRows(items: readonly DialogItem[]): DialogRow[] {
  const hasCategories = items.some((item) => typeof item.category === "string" && item.category.length > 0);
  const rows: DialogRow[] = [];
  let lastCategory: string | undefined;
  items.forEach((item, itemIndex) => {
    if (hasCategories) {
      const category = item.category ?? "";
      if (category !== lastCategory) {
        lastCategory = category;
        if (category.length > 0) rows.push({ kind: "header", category, key: `header:${category}` });
      }
    }
    rows.push({ kind: "item", item, itemIndex, key: `item:${item.id}:${itemIndex}` });
  });
  return rows;
}

/** Display-row index of the item at `itemIndex`, or -1 when it is not present. */
export function dialogDisplayIndex(rows: readonly DialogRow[], itemIndex: number): number {
  return rows.findIndex((row) => row.kind === "item" && row.itemIndex === itemIndex);
}

// ---------------------------------------------------------------------------
// Navigation over selectable items (skips disabled, wraps once)
// ---------------------------------------------------------------------------

function seekEnabled(items: readonly DialogItem[], from: number, step: 1 | -1): number {
  if (items.length === 0) return 0;
  const origin = ((from % items.length) + items.length) % items.length;
  let at = origin;
  for (let hops = 0; hops < items.length; hops += 1) {
    if (!items[at]?.disabled) return at;
    at = (at + step + items.length) % items.length;
  }
  return origin;
}

/** First enabled index at or after `from`, or 0 for an all-disabled / empty list. */
export function firstEnabled(items: readonly DialogItem[]): number {
  return seekEnabled(items, 0, 1);
}

/** Step one row in `step` direction, skipping disabled rows, wrapping once. */
export function moveDialogSelection(items: readonly DialogItem[], index: number, step: 1 | -1): number {
  if (items.length === 0) return 0;
  if (!items.some((item) => !item.disabled)) return index;
  const next = (index + step + items.length) % items.length;
  return seekEnabled(items, next, step);
}

/** Clamp a possibly-stale index onto an enabled row of the current list. */
export function clampDialogSelection(items: readonly DialogItem[], index: number): number {
  if (items.length === 0) return 0;
  const clamped = clamp(cells(index), 0, items.length - 1);
  return items[clamped]?.disabled ? seekEnabled(items, clamped, 1) : clamped;
}

// ---------------------------------------------------------------------------
// Scroll window
// ---------------------------------------------------------------------------

export interface DialogWindow {
  start: number;
  end: number;
  hasAbove: boolean;
  hasBelow: boolean;
}

/**
 * Slice bounds of `maxRows` display rows that always contain `selectedRow`.
 *
 * The selection is centred so there is context above and below it, then the
 * window is clamped flush against the ends so the last page is never padded
 * with blank rows. When the highlighted row sits directly below a heading, the
 * heading is pulled in too — but only when there is a spare row for it, because
 * a window that drops the cursor to name its group is worse than one that keeps
 * the cursor and drops the name.
 */
export function dialogWindow(
  rows: readonly DialogRow[],
  selectedRow: number,
  maxRows: number,
): DialogWindow {
  const total = rows.length;
  const capacity = Math.min(cells(maxRows), total);
  if (capacity <= 0) return { start: 0, end: 0, hasAbove: total > 0, hasBelow: false };

  const maxStart = Math.max(0, total - capacity);
  const cursor = clamp(cells(selectedRow), 0, total - 1);
  const centred = cursor - Math.floor((capacity - 1) / 2);
  let start = clamp(centred, 0, maxStart);

  if (cursor > start + capacity - 1) start = cursor - capacity + 1;
  const wantHeader = capacity >= 2 && rows[cursor - 1]?.kind === "header" ? cursor - 1 : cursor;
  if (wantHeader < start) start = wantHeader;
  start = clamp(start, 0, maxStart);

  const end = Math.min(total, start + capacity);
  return { start, end, hasAbove: start > 0, hasBelow: end < total };
}

// ---------------------------------------------------------------------------
// Panel geometry
// ---------------------------------------------------------------------------

/** Widest inner width each size asks for. Panels below this shrink to fit. */
const PANEL_MAX_WIDTH: Record<DialogSize, number> = {
  small: 60,
  large: 116,
  medium: 88,
};

/** Cells of empty terminal kept on each side of the panel. */
const H_MARGIN = 2;
/** Border (2) + horizontal padding (2). */
const PANEL_CHROME = 4;
/** A panel narrower than this cannot show a usable row; it is the floor. */
const MIN_PANEL_WIDTH = 20;

/** Non-list rows inside the panel: title, search, footer, top+bottom border. */
const VERTICAL_CHROME = 5;
/** Fraction of the terminal height the panel's top edge sits at (upper third). */
const TOP_ANCHOR = 0.15;
/** Never fewer than this many body rows, even on a very short terminal. */
const MIN_LIST_ROWS = 1;

export interface DialogPanelInput {
  width: number;
  height: number;
  size?: DialogSize;
  /** Total display rows (headers + items) the list would render. */
  totalRows: number;
}

export interface DialogPanel {
  /** Outer panel width, borders included. Always `<= width`. */
  panelWidth: number;
  /** Left offset that centres the panel horizontally. */
  left: number;
  /** Top offset (rows) anchoring the panel in the upper third. */
  top: number;
  /** Inner content width: `panelWidth - PANEL_CHROME`. */
  innerWidth: number;
  /** Cells a list row may occupy — inner width less the scrollbar column. */
  rowWidth: number;
  /** Body rows the list can hold given the terminal height. */
  capacityRows: number;
  /** Body rows actually rendered: `min(capacityRows, max(1, totalRows))`. */
  visibleRows: number;
  /** Whether the list scrolls — a scrollbar column is then reserved. */
  scrolls: boolean;
}

export function computeDialogPanel({
  width,
  height,
  size = "medium",
  totalRows,
}: DialogPanelInput): DialogPanel {
  const w = cells(width);
  const h = cells(height);
  const total = cells(totalRows);

  const available = Math.max(1, w - H_MARGIN * 2);
  const panelWidth = clamp(Math.min(PANEL_MAX_WIDTH[size], available), Math.min(MIN_PANEL_WIDTH, w), Math.max(1, w));
  const left = Math.max(0, Math.floor((w - panelWidth) / 2));
  const top = Math.max(0, Math.floor(h * TOP_ANCHOR));

  const innerWidth = Math.max(1, panelWidth - PANEL_CHROME);

  const availableHeight = Math.max(1, h - top - VERTICAL_CHROME);
  const capacityRows = Math.max(MIN_LIST_ROWS, availableHeight);
  const scrolls = total > capacityRows;
  const visibleRows = Math.max(1, Math.min(capacityRows, Math.max(1, total)));
  const rowWidth = Math.max(1, innerWidth - (scrolls ? 1 : 0));

  return { panelWidth, left, top, innerWidth, rowWidth, capacityRows, visibleRows, scrolls };
}

// ---------------------------------------------------------------------------
// Row columns
// ---------------------------------------------------------------------------

/** Gutter is a dot plus a space: "● ". Zero when the list has no current row. */
const GUTTER_WIDTH = 2;
/** The meta column never eats more than this share of the row. */
const META_SHARE = 0.4;
/** The description never eats more than this share of what the label leaves. */
const DESCRIPTION_SHARE = 0.45;
/** A label always keeps at least this many cells when a description competes. */
const MIN_LABEL_WIDTH = 6;

export interface DialogColumnsInput {
  rowWidth: number;
  /** Reserve the leading gutter for the current-value dot. */
  hasGutter: boolean;
  /** Longest meta string across the visible rows, in cells (0 = no meta). */
  metaContentWidth: number;
  /** Whether any visible row carries a description. */
  hasDescription: boolean;
}

export interface DialogColumns {
  gutterWidth: number;
  labelWidth: number;
  descGap: number;
  descWidth: number;
  metaGap: number;
  metaWidth: number;
}

/**
 * Split a row into gutter · label · description · meta so the parts sum to at
 * most `rowWidth`. Meta is content-sized but capped; the description takes a
 * bounded share of what remains; the label absorbs the rest and is the last to
 * be starved. Every field is non-negative, so a degenerate one-cell row yields
 * a label of whatever is left and zeroes elsewhere rather than a negative span.
 */
export function dialogRowColumns({
  rowWidth,
  hasGutter,
  metaContentWidth,
  hasDescription,
}: DialogColumnsInput): DialogColumns {
  const width = Math.max(0, cells(rowWidth));
  const gutterWidth = hasGutter ? Math.min(GUTTER_WIDTH, width) : 0;

  let remaining = width - gutterWidth;

  const metaWanted = Math.max(0, cells(metaContentWidth));
  const metaCap = Math.max(0, Math.floor(remaining * META_SHARE));
  let metaWidth = metaWanted > 0 ? Math.min(metaWanted, metaCap) : 0;
  let metaGap = metaWidth > 0 && remaining - metaWidth >= 1 ? 1 : 0;
  if (metaWidth + metaGap > remaining) {
    metaGap = 0;
    metaWidth = Math.min(metaWidth, remaining);
  }
  remaining -= metaWidth + metaGap;

  let descWidth = 0;
  let descGap = 0;
  if (hasDescription && remaining > MIN_LABEL_WIDTH + 1) {
    const descCap = Math.max(0, Math.floor(remaining * DESCRIPTION_SHARE));
    descWidth = Math.max(0, Math.min(descCap, remaining - MIN_LABEL_WIDTH - 1));
    descGap = descWidth > 0 ? 1 : 0;
  }
  remaining -= descWidth + descGap;

  const labelWidth = Math.max(0, remaining);
  return { gutterWidth, labelWidth, descGap, descWidth, metaGap, metaWidth };
}

/** Total cells a column set occupies — the property the sweep test pins. */
export function dialogColumnsWidth(columns: DialogColumns): number {
  return (
    columns.gutterWidth +
    columns.labelWidth +
    columns.descGap +
    columns.descWidth +
    columns.metaGap +
    columns.metaWidth
  );
}
