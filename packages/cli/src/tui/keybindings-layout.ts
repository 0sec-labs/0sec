/**
 * Layout geometry and row model for the full-screen keyboard-shortcuts
 * reference (`shortcuts-screen.tsx`).
 *
 * This is `usage-layout.ts` for `/shortcuts`, and it exists for the same reason
 * spelled out there and in `PRIMITIVES.md`: OpenTUI lays rows out with Yoga,
 * and Yoga *shrinks* siblings rather than clipping them. Two `<text>` nodes that
 * together want more cells than their row has are painted on top of each other,
 * and a bordered box asked to hold one row more than its column has paints its
 * own bottom border through its last line of content. So the component reads
 * every width, height, row count and column split off a `ShortcutsLayout` and
 * never computes one; a sweep hammers every number here across widths 0..200 and
 * heights 0..80.
 *
 * The content is derived entirely from `keybindings.ts` — the shared registry —
 * so a binding added there appears here (and on screen) with no change to this
 * file. `shellChromeRows` is reused from `settings-layout.ts` (the corrected
 * mirror of `run.tsx`'s shell-chrome height), exactly as `usage-layout.ts` does.
 */

import {
  KEYBINDINGS,
  keybindingsByCategory,
  type Keybinding,
} from "./keybindings.js";
import { shellChromeRows } from "./settings-layout.js";
import { sanitizeTuiText } from "./text.js";

export { shellChromeRows };

// ---------------------------------------------------------------------------
// Numeric hygiene (mirrors usage-layout.ts)
// ---------------------------------------------------------------------------

/**
 * Cell and row counts are non-negative integers. Terminal geometry arrives from
 * `useTerminalDimensions`, which reports 0 on a detached tty and can report a
 * fractional or `NaN` size mid-resize; everything entering the allocator is
 * normalised here first.
 */
function cells(value: unknown, fallback = 0): number {
  const raw = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  const truncated = Math.trunc(raw);
  return truncated > 0 ? truncated : 0;
}

// ---------------------------------------------------------------------------
// Row model — tone-tagged rows, decided here so the component draws no logic
// ---------------------------------------------------------------------------

export type ShortcutsTone = "heading" | "keys" | "description" | "blank";

export type ShortcutsRowKind = "heading" | "binding" | "blank";

export interface ShortcutsRow {
  kind: ShortcutsRowKind;
  /** The whole line for `heading`, unused for `binding`/`blank`. */
  label?: string;
  /** The chord column for `binding`. */
  keys?: string;
  /** The description column for `binding`. */
  description?: string;
  tone?: ShortcutsTone;
}

/**
 * The whole reference as flat rows: one heading per category, one row per
 * binding, and a blank between groups. Built from the shared registry via
 * `keybindingsByCategory`, so the order and grouping match the source of truth
 * and nothing is hand-listed here.
 */
export function buildShortcutsRows(
  bindings: readonly Keybinding[] = KEYBINDINGS,
): ShortcutsRow[] {
  const rows: ShortcutsRow[] = [];
  const grouped = keybindingsByCategory(bindings);
  let first = true;
  for (const [category, entries] of grouped) {
    if (!first) rows.push({ kind: "blank", tone: "blank" });
    first = false;
    rows.push({ kind: "heading", label: category.toUpperCase(), tone: "heading" });
    for (const binding of entries) {
      rows.push({
        kind: "binding",
        keys: sanitizeTuiText(binding.keys),
        description: sanitizeTuiText(binding.description),
        tone: "description",
      });
    }
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Columns
// ---------------------------------------------------------------------------

/** The keys column never grows past this, however long a chord label is. */
const KEYS_MAX_WIDTH = 22;
/** The description keeps at least this many cells before the keys column may grow. */
const DESCRIPTION_MIN_WIDTH = 12;
/** Below this a binding row cannot afford two columns and shows keys alone. */
const COLUMNS_MIN_ROOM = 16;

export interface ShortcutsColumns {
  /** Total cells a binding row occupies; equals the pane's inner width. */
  width: number;
  /** The chord column, sized to the widest chord (capped). */
  keysWidth: number;
  gap: number;
  /** The description column. 0 when the row can only afford the keys. */
  descriptionWidth: number;
}

/** The widest chord label across the rendered bindings, for column alignment. */
export function widestKeys(rows: readonly ShortcutsRow[]): number {
  let max = 0;
  for (const row of rows) {
    if (row.kind === "binding" && typeof row.keys === "string") {
      max = Math.max(max, row.keys.length);
    }
  }
  return max;
}

/**
 * Splits a binding row into a left keys column and a right description column.
 *
 * The keys column is sized to the widest chord (so the chords align down the
 * page) but capped at `KEYS_MAX_WIDTH` and never allowed to starve the
 * description below `DESCRIPTION_MIN_WIDTH`. Below `COLUMNS_MIN_ROOM` the row
 * keeps the keys and drops the description column — a truncated chord beside a
 * truncated sentence helps no one. The two columns plus the gap always sum to
 * exactly `innerWidth`, so a row can never overflow or fuse under pressure.
 */
export function computeShortcutsColumns(
  innerWidth: number,
  maxKeysLength: number,
): ShortcutsColumns {
  const width = cells(innerWidth);
  if (width <= 0) return { width: 0, keysWidth: 0, gap: 0, descriptionWidth: 0 };
  if (width < COLUMNS_MIN_ROOM) return { width, keysWidth: width, gap: 0, descriptionWidth: 0 };

  const wanted = cells(maxKeysLength);
  // The keys column may take what the widest chord needs, but never more than
  // the cap, and never so much that the description falls below its floor.
  const keysWidth = Math.max(
    1,
    Math.min(wanted, KEYS_MAX_WIDTH, width - DESCRIPTION_MIN_WIDTH - 1),
  );
  const gap = 1;
  const descriptionWidth = Math.max(0, width - keysWidth - gap);
  return { width, keysWidth, gap, descriptionWidth };
}

// ---------------------------------------------------------------------------
// Geometry (mirrors usage-layout.ts)
// ---------------------------------------------------------------------------

/** Below this the pane drops its border rather than a row of content. */
const BORDERED_MIN_ROWS = 10;
/** A pane narrower than this cannot afford a border and its padding. */
const BORDERED_MIN_WIDTH = 24;

export interface ShortcutsPane {
  /** Outer cells, borders included. 0 when the pane is not rendered. */
  width: number;
  /** Cells available to text inside the pane. */
  innerWidth: number;
  /** Outer rows, borders included. 0 when the pane is not rendered. */
  height: number;
  /** Rows available to content, below the title row. */
  bodyRows: number;
  /** The pane spends a row on a title. */
  hasTitle: boolean;
}

export interface ShortcutsLayoutInput {
  width: number;
  height: number;
}

export interface ShortcutsLayout {
  /** The pane draws a border. False on a short terminal, where rows cost more. */
  bordered: boolean;
  /** Usable cells across, inside the shell's padding. */
  contentWidth: number;
  /** Rows the reference body may share, after the shell has taken its chrome. */
  bodyRows: number;
  pane: ShortcutsPane;
  columns: ShortcutsColumns;
  /** Reference rows that fit in the pane's body. */
  visibleRows: number;
}

function makePane(width: number, height: number, chromeH: number, chromeV: number): ShortcutsPane {
  const outerWidth = cells(width);
  const outerHeight = cells(height);
  const verticalChrome = chromeV + 1; // always a title row
  if (outerWidth <= chromeH || outerHeight <= verticalChrome) {
    return { width: 0, innerWidth: 0, height: 0, bodyRows: 0, hasTitle: true };
  }
  return {
    width: outerWidth,
    innerWidth: outerWidth - chromeH,
    height: outerHeight,
    bodyRows: outerHeight - verticalChrome,
    hasTitle: true,
  };
}

/**
 * The full geometry of the shortcuts screen.
 *
 * One pane fills the content column. It gives up its border before it gives up
 * rows of content, and is dropped entirely rather than rendered at a height that
 * would push its own border through its text. The keys column is sized from the
 * widest chord the caller passes so the chords align down the page.
 */
export function computeShortcutsLayout(
  { width, height }: ShortcutsLayoutInput,
  maxKeysLength = 0,
): ShortcutsLayout {
  const terminalWidth = cells(width);
  // `ShellFrame` pads two cells either side of every screen.
  const contentWidth = Math.max(0, terminalWidth - 4);
  const bodyRows = Math.max(0, cells(height) - shellChromeRows(terminalWidth));

  const bordered = bodyRows >= BORDERED_MIN_ROWS && contentWidth >= BORDERED_MIN_WIDTH;
  const chromeH = bordered ? 4 : 0;
  const chromeV = bordered ? 2 : 0;
  const pane = makePane(contentWidth, bodyRows, chromeH, chromeV);

  return {
    bordered,
    contentWidth,
    bodyRows,
    pane,
    columns: computeShortcutsColumns(pane.innerWidth, maxKeysLength),
    visibleRows: pane.bodyRows,
  };
}

// ---------------------------------------------------------------------------
// Clipping, titles and hints (mirrors usage-layout.ts)
// ---------------------------------------------------------------------------

/**
 * Trims reference rows to the rows the pane actually has, marking the cut.
 *
 * Rendering more rows than the box holds is what pushes a border through the
 * content, so the overflow is cut — but the last surviving row is replaced with
 * a marker rather than dropped silently, because a reference that stops
 * mid-section with no sign it was truncated reads as a crash.
 */
export function clipShortcutsRows(rows: readonly ShortcutsRow[], visible: number): ShortcutsRow[] {
  const limit = cells(visible);
  if (limit <= 0) return [];
  if (rows.length <= limit) return [...rows];
  const kept = rows.slice(0, limit);
  const hidden = rows.length - limit + 1;
  kept[limit - 1] = { kind: "heading", label: `… ${hidden} more`, tone: "blank" };
  return kept;
}

/** The pane title. */
export function shortcutsTitle(): string {
  return "KEYBOARD SHORTCUTS";
}

/** The footer hint: this screen is read-only, so the keys are few. */
export function shortcutsFooterHint(): string {
  return ["esc back", "ctrl+c exit"].join(" · ");
}
