/**
 * Layout, navigation and windowing arithmetic for the full-screen marketplace
 * browser.
 *
 * This is `model-layout.ts` for `/market`, and it exists for the same reason
 * spelled out in `PRIMITIVES.md`: OpenTUI lays rows out with Yoga, and Yoga
 * *shrinks* siblings rather than clipping them. Two `<text>` nodes that together
 * want more cells than their row has are both painted in full into boxes that
 * are now too small, and the terminal shows the two strings interleaved
 * character by character. The same failure on the vertical axis makes a bordered
 * box paint its own bottom border through its last content row. So the component
 * reads widths and row counts off a `MarketLayout` and never computes one, and a
 * sweep hammers every number in here across widths 0..200 and heights 0..80.
 *
 * ## What the screen shows
 *
 * The marketplace index carries TWO artifact kinds this browser surfaces side by
 * side: tool PLUGINS (code that rides the install → enable → run path) and
 * THEMES (inert colour data). Both are normalised into a single {@link
 * MarketItem} shape — kind, id, name, version, a one-line description, the
 * plugin's requested capabilities, and its signature state — so the list and the
 * detail pane never branch on the wire types.
 *
 * ## The security model this module keeps
 *
 * Install is not enablement, and nothing here runs code. The row's install state
 * ({@link MarketState}) is a *statement about the filesystem*, computed by the
 * screen and handed in as data: a plugin can read `installed` (files on disk,
 * nothing running) or `enabled` (an operator recorded an approval), and a theme
 * `installed` or `active` (currently applied). The detail pane never offers to
 * enable a plugin — that is a separate, explicit operator decision — and the
 * capability list is rendered as the risk surface it is.
 *
 * ## Reuse
 *
 * `shellChromeRows` and `wrapCells` are imported from `settings-layout.ts`
 * (re-exported here) exactly as `model-layout.ts` does, and the numeric-hygiene
 * helpers mirror that module. The registry shapes are declared LOCALLY as
 * structural views so this pure module type-checks against `@0sec/core`'s
 * published surface without importing its in-flight `d.ts`.
 */

import { shellChromeRows, wrapCells } from "./settings-layout.js";
import { sanitizeTuiText } from "./text.js";

export { shellChromeRows, wrapCells };

// ---------------------------------------------------------------------------
// Numeric hygiene
// ---------------------------------------------------------------------------

/**
 * Cell and row counts are non-negative integers.
 *
 * Terminal geometry arrives from `useTerminalDimensions`, which reports 0 on a
 * detached tty and can report a fractional or `NaN` size mid-resize. Yoga
 * accepts all of those and lays out sub-cell boxes that round inconsistently
 * between siblings, which is itself an overlap.
 */
function cells(value: unknown, fallback = 0): number {
  const raw = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  const truncated = Math.trunc(raw);
  return truncated > 0 ? truncated : 0;
}

function clamp(value: number, low: number, high: number): number {
  if (high < low) return low;
  return Math.min(Math.max(value, low), high);
}

/** Byte-order compare: locale-independent so the order never shifts. */
function compareStrings(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

// ---------------------------------------------------------------------------
// Registry shapes (untrusted; declared locally so this module owns no core d.ts)
// ---------------------------------------------------------------------------

/** A tool plugin entry, as `RegistryResult.entries` reports it. */
export interface MarketPluginEntryView {
  id: string;
  version: string;
  manifest?: {
    name?: string;
    tools?: { name?: string; description?: string }[];
  };
  capabilities?: readonly string[];
  signatureState?: string;
}

/** A theme (or other data) artifact, as `RegistryResult.artifacts` reports it. */
export interface MarketArtifactView {
  kind?: string;
  id: string;
  version: string;
  manifest?: {
    name?: string;
    theme?: { label?: string; description?: string };
  };
  signatureState?: string;
}

/** The validated registry result. Either half may be absent or malformed. */
export interface MarketRegistryView {
  entries?: readonly MarketPluginEntryView[];
  artifacts?: readonly MarketArtifactView[];
}

// ---------------------------------------------------------------------------
// Normalised item model
// ---------------------------------------------------------------------------

export type MarketKind = "plugin" | "theme";
export type MarketSignature = "verified" | "unverified";

/**
 * A plugin's filesystem/enablement state, or a theme's install/active state.
 *
 * This is the honest security statement the browser makes, and it is DATA the
 * screen computes and hands in — never inferred from the registry:
 *
 * - `available` — not on this machine.
 * - `installed` — files on disk. For a plugin this is explicitly NOT enabled;
 *                 no plugin code has run.
 * - `enabled`   — a plugin an operator recorded an approval for (plugins only).
 * - `active`    — a theme currently applied as the console palette (themes only).
 */
export type MarketState = "available" | "installed" | "enabled" | "active";

export interface MarketItem {
  readonly kind: MarketKind;
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly description: string;
  /** Requested capabilities. Plugins only; always empty for a theme. */
  readonly capabilities: readonly string[];
  readonly signature: MarketSignature;
  /**
   * The original registry view, kept so the install action can write the exact
   * validated bytes without re-deriving them. Opaque here.
   */
  readonly raw: unknown;
}

function signatureOf(state: unknown): MarketSignature {
  return state === "verified" ? "verified" : "unverified";
}

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/** One-line description of a plugin, derived from its tool set. */
function pluginDescription(entry: MarketPluginEntryView): string {
  const tools = Array.isArray(entry.manifest?.tools) ? entry.manifest?.tools ?? [] : [];
  const named = tools.map((tool) => (nonEmpty(tool?.name) ? tool.name!.trim() : "")).filter(Boolean);
  if (named.length === 0) return "Tool plugin.";
  const count = named.length;
  return `${count} tool${count === 1 ? "" : "s"}: ${named.join(", ")}`;
}

/**
 * Flattens a fetched registry result into normalised items.
 *
 * Plugins come from `entries`; themes from `artifacts` whose `kind` is
 * `"theme"`. Everything else (config artifacts, unknown kinds, malformed rows)
 * is skipped rather than surfaced — an item the browser cannot describe is noise.
 */
export function buildMarketItems(view: MarketRegistryView | undefined): MarketItem[] {
  const items: MarketItem[] = [];
  if (!view || typeof view !== "object") return items;

  for (const entry of view.entries ?? []) {
    if (!entry || typeof entry.id !== "string" || entry.id.length === 0) continue;
    const version = typeof entry.version === "string" ? entry.version : "";
    items.push({
      kind: "plugin",
      id: entry.id,
      name: nonEmpty(entry.manifest?.name) ? entry.manifest!.name!.trim() : entry.id,
      version,
      description: sanitizeTuiText(pluginDescription(entry)),
      capabilities: Array.isArray(entry.capabilities)
        ? entry.capabilities.filter((cap): cap is string => nonEmpty(cap))
        : [],
      signature: signatureOf(entry.signatureState),
      raw: entry,
    });
  }

  for (const artifact of view.artifacts ?? []) {
    if (!artifact || artifact.kind !== "theme") continue;
    if (typeof artifact.id !== "string" || artifact.id.length === 0) continue;
    const theme = artifact.manifest?.theme;
    const version = typeof artifact.version === "string" ? artifact.version : "";
    const name = nonEmpty(theme?.label)
      ? theme!.label!.trim()
      : nonEmpty(artifact.manifest?.name)
        ? artifact.manifest!.name!.trim()
        : artifact.id;
    items.push({
      kind: "theme",
      id: artifact.id,
      name,
      version,
      description: sanitizeTuiText(nonEmpty(theme?.description) ? theme!.description! : "Colour theme."),
      capabilities: [],
      signature: signatureOf(artifact.signatureState),
      raw: artifact,
    });
  }

  return items;
}

// ---------------------------------------------------------------------------
// Row model
// ---------------------------------------------------------------------------

export interface MarketGroup {
  readonly id: MarketKind;
  readonly label: string;
}

export type MarketRow =
  | { readonly kind: "heading"; readonly group: MarketGroup; readonly count: number }
  | {
      readonly kind: "item";
      readonly group: MarketGroup;
      readonly item: MarketItem;
      readonly state: MarketState;
    };

const GROUP_LABEL: Record<MarketKind, string> = {
  plugin: "Plugins",
  theme: "Themes",
};

/** Plugins are listed before themes; the order is fixed so the list is stable. */
const GROUP_ORDER: MarketKind[] = ["plugin", "theme"];

export interface MarketRowsInput {
  /** A fetched registry result, or pre-normalised items. */
  view?: MarketRegistryView;
  items?: readonly MarketItem[];
  filter?: string;
  /** Per-item install/enablement state; defaults to `available`. */
  stateFor?: (item: MarketItem) => MarketState;
}

/**
 * Flattens items into kind headings and item rows, honouring an optional filter.
 *
 * A heading is only emitted when at least one item under it survived the filter:
 * a heading with nothing beneath it is a row of noise. The filter is
 * AND-over-terms across the item's name, id, kind, description and capabilities,
 * so "network" finds every plugin that requests the network capability and
 * "theme dark" narrows to dark themes named accordingly.
 */
export function buildMarketRows({
  view,
  items,
  filter = "",
  stateFor,
}: MarketRowsInput = {}): MarketRow[] {
  const source = items ?? buildMarketItems(view);
  const terms = sanitizeTuiText(filter).toLowerCase().split(" ").filter(Boolean);
  const state = stateFor ?? (() => "available" as MarketState);

  const byKind = new Map<MarketKind, MarketItem[]>();
  for (const item of source) {
    if (!item || (item.kind !== "plugin" && item.kind !== "theme")) continue;
    if (typeof item.id !== "string" || item.id.length === 0) continue;
    const haystack =
      `${item.name} ${item.id} ${item.kind} ${item.description} ${item.capabilities.join(" ")}`.toLowerCase();
    if (terms.length > 0 && !terms.every((term) => haystack.includes(term))) continue;
    const bucket = byKind.get(item.kind);
    if (bucket) bucket.push(item);
    else byKind.set(item.kind, [item]);
  }

  const rows: MarketRow[] = [];
  for (const kind of GROUP_ORDER) {
    const bucket = byKind.get(kind);
    if (!bucket || bucket.length === 0) continue;
    const group: MarketGroup = { id: kind, label: GROUP_LABEL[kind] };
    const sorted = [...bucket].sort(
      (a, b) => compareStrings(a.name.toLowerCase(), b.name.toLowerCase()) || compareStrings(a.id, b.id),
    );
    rows.push({ kind: "heading", group, count: sorted.length });
    for (const item of sorted) {
      rows.push({ kind: "item", group, item, state: state(item) });
    }
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

/** Index of the first selectable row, or -1 when the list has none. */
export function firstSelectableIndex(rows: readonly MarketRow[]): number {
  for (let index = 0; index < rows.length; index++) {
    if (rows[index]?.kind === "item") return index;
  }
  return -1;
}

/** Index of the last selectable row, or -1 when the list has none. */
export function lastSelectableIndex(rows: readonly MarketRow[]): number {
  for (let index = rows.length - 1; index >= 0; index--) {
    if (rows[index]?.kind === "item") return index;
  }
  return -1;
}

/** Index of an item by kind+id, or -1. Used to keep a selection across reloads. */
export function indexOfItem(
  rows: readonly MarketRow[],
  kind: MarketKind | undefined,
  id: string | undefined,
): number {
  if (!kind || !id) return -1;
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index];
    if (row?.kind === "item" && row.item.kind === kind && row.item.id === id) return index;
  }
  return -1;
}

/**
 * Pulls an arbitrary index onto a selectable row, searching forward then back.
 *
 * Filtering is the reason this exists: the highlighted row can vanish from under
 * the cursor between two keystrokes, and the selection then has to land on a real
 * item rather than a heading or past the end.
 */
export function clampSelection(rows: readonly MarketRow[], current: number): number {
  if (rows.length === 0) return -1;
  const start = clamp(Math.trunc(Number.isFinite(current) ? current : 0), 0, rows.length - 1);
  for (let index = start; index < rows.length; index++) {
    if (rows[index]?.kind === "item") return index;
  }
  for (let index = start - 1; index >= 0; index--) {
    if (rows[index]?.kind === "item") return index;
  }
  return -1;
}

/**
 * Moves the selection by `delta` rows, skipping kind headings and wrapping. The
 * inner guard loop is bounded by the list length so a list of nothing but
 * headings terminates instead of spinning.
 */
export function moveSelection(rows: readonly MarketRow[], current: number, delta: number): number {
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
      if (rows[probe]?.kind === "item") break;
    }
    if (rows[probe]?.kind !== "item") return anchor;
    index = probe;
  }
  return index;
}

// ---------------------------------------------------------------------------
// Windowing
// ---------------------------------------------------------------------------

export interface MarketWindowInput {
  rows: readonly MarketRow[];
  /** Highlighted row index, or -1 when the filter matched nothing. */
  selected: number;
  /** Rows the list body can actually paint. */
  visible: number;
  /** Previous window start, so the list scrolls instead of re-centring. */
  anchor?: number;
}

export interface MarketWindow {
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
 * Taking the previous start as an anchor rather than re-centring on every move is
 * the difference between a list that scrolls and a list that jumps. When the
 * cursor lands on the first item of a kind, the window is pulled up one extra row
 * so that kind's heading comes with it — a list scrolled past its own headings
 * has stopped saying whether you are looking at a plugin or a theme.
 */
export function computeMarketWindow({
  rows,
  selected,
  visible,
  anchor = 0,
}: MarketWindowInput): MarketWindow {
  const total = rows.length;
  const capacity = Math.min(cells(visible), total);
  if (capacity <= 0) {
    return { start: 0, end: 0, count: 0, total, hasAbove: total > 0, hasBelow: false };
  }

  const maxStart = Math.max(0, total - capacity);
  let start = clamp(cells(anchor), 0, maxStart);

  const cursor = Math.trunc(Number.isFinite(selected) ? selected : -1);
  if (cursor >= 0 && cursor < total) {
    const wanted = capacity >= 2 && rows[cursor - 1]?.kind === "heading" ? cursor - 1 : cursor;
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
/** A detail pane narrower than this wraps a description into confetti. */
const DETAIL_MIN_WIDTH = 30;
/** Past this the detail pane is just whitespace; give the cells to the list. */
const DETAIL_MAX_WIDTH = 60;
/** Share of the content column the detail pane asks for when it fits beside. */
const DETAIL_WIDTH_SHARE = 0.46;
/** A list narrower than this cannot show a name and a state side by side. */
const LIST_MIN_WIDTH = 30;
/** Widest a row's install-state tag ever gets; "available" is 9 cells. */
const STATE_MAX_WIDTH = 12;
/** Below this a row cannot afford a state tag at all. */
const STATE_MIN_ROOM = 18;
/** Share of a list row the state tag may take on a narrow screen. */
const STATE_WIDTH_SHARE = 0.36;
/** Widest a row's version column ever gets. */
const VERSION_MAX_WIDTH = 12;
/** Below this a row drops its version column before its state tag. */
const VERSION_MIN_ROOM = 26;
/** Share of a list row the version column may take. */
const VERSION_WIDTH_SHARE = 0.24;
/** Widest a heading's item count gets; a five-digit count is 5 cells. */
const COUNT_MAX_WIDTH = 6;
/** A heading keeps at least this much of the kind label. */
const HEADING_LABEL_MIN = 6;
/** Below this a heading drops its count column and keeps the kind label. */
const HEADING_COUNT_MIN_ROOM = 14;
/** Below this the panes drop their borders rather than their content. */
const BORDERED_MIN_ROWS = 12;
/** Share of a stacked column the detail pane takes. */
const STACKED_DETAIL_SHARE = 0.4;
/** Cap on the stacked detail pane; past this the list is the better use. */
const STACKED_DETAIL_MAX_ROWS = 12;

export interface MarketPane {
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

export interface MarketRowLayout {
  /** Total cells a list row occupies; equals the list pane's inner width. */
  width: number;
  /** Cursor marker column. 0 when the row is too narrow to spare it. */
  markerWidth: number;
  markerGap: number;
  /** The item name. Absorbs all remaining cells. */
  labelWidth: number;
  versionGap: number;
  /** Version column. 0 when the row cannot spare it (dropped first). */
  versionWidth: number;
  stateGap: number;
  /** Install-state tag. 0 when the row can only afford a name (dropped second). */
  stateWidth: number;
}

export interface MarketHeadingLayout {
  /** Total cells a heading row occupies; equals the list pane's inner width. */
  width: number;
  labelWidth: number;
  gap: number;
  /** Item count. 0 when the heading can only afford a kind label. */
  countWidth: number;
}

export interface MarketLayoutInput {
  width: number;
  height: number;
  /** 1 when the status line under the panes is rendered. */
  noticeRows?: number;
}

export interface MarketLayout {
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
  list: MarketPane;
  detail: MarketPane;
  row: MarketRowLayout;
  heading: MarketHeadingLayout;
  /** List rows that fit in the list pane's body. */
  visibleRows: number;
  /** The detail pane drops the blank separator lines between its sections. */
  detailCompact: boolean;
}

/** A bordered pane spends four columns and two rows on its border and padding. */
function borderChrome(bordered: boolean): { horizontal: number; vertical: number } {
  return bordered ? { horizontal: 4, vertical: 2 } : { horizontal: 0, vertical: 0 };
}

function makePane(
  width: number,
  height: number,
  chromeH: number,
  chromeV: number,
  hasTitle: boolean,
): MarketPane {
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
 * Splits a list row into cursor, name, version and state columns.
 *
 * Every separator is a real Yoga gap rather than a padded literal, because the
 * text helpers route through `sanitizeTuiText`, which trims — a name carrying its
 * own trailing space comes back without one and fuses onto its neighbour even
 * when the row had cells to spare.
 *
 * The degradation ladder, widest to narrowest:
 *
 *   1. cursor + name + version + state   (widest)
 *   2. cursor + name + state             (version dropped first)
 *   3. cursor + name                     (state dropped second)
 *   4. name alone                        (anything above zero)
 *
 * The version gives way before the state tag: a row reading `acme.x  enabled`
 * still says the one thing an operator scans the list for — whether it is
 * already on this machine — while a bare version says nothing.
 */
function computeRowLayout(innerWidth: number): MarketRowLayout {
  const width = cells(innerWidth);
  if (width <= 0) {
    return {
      width: 0,
      markerWidth: 0,
      markerGap: 0,
      labelWidth: 0,
      versionGap: 0,
      versionWidth: 0,
      stateGap: 0,
      stateWidth: 0,
    };
  }

  const markerWidth = width >= 6 ? 1 : 0;
  const markerGap = markerWidth > 0 && width > markerWidth ? 1 : 0;
  const afterMarker = Math.max(0, width - markerWidth - markerGap);

  // Version is the first right-hand column to go.
  const versionWidth =
    afterMarker >= VERSION_MIN_ROOM
      ? Math.min(VERSION_MAX_WIDTH, Math.floor(afterMarker * VERSION_WIDTH_SHARE))
      : 0;
  const versionGap = versionWidth > 0 && afterMarker > versionWidth ? 1 : 0;
  const afterVersion = Math.max(0, afterMarker - versionWidth - versionGap);

  // State tag is dropped second; it outlives the version.
  const stateWidth =
    afterVersion >= STATE_MIN_ROOM
      ? Math.min(STATE_MAX_WIDTH, Math.floor(afterVersion * STATE_WIDTH_SHARE))
      : 0;
  const stateGap = stateWidth > 0 && afterVersion > stateWidth ? 1 : 0;
  const labelWidth = Math.max(0, afterVersion - stateWidth - stateGap);

  return { width, markerWidth, markerGap, labelWidth, versionGap, versionWidth, stateGap, stateWidth };
}

/**
 * Splits a kind heading into its label and its item count. The count is the last
 * thing dropped, but it IS dropped below 14 cells, because a truncated count
 * beside a truncated kind label is worse than an honest bare label.
 */
function computeHeadingLayout(innerWidth: number): MarketHeadingLayout {
  const width = cells(innerWidth);
  if (width <= 0) return { width: 0, labelWidth: 0, gap: 0, countWidth: 0 };
  if (width < HEADING_COUNT_MIN_ROOM) {
    return { width, labelWidth: width, gap: 0, countWidth: 0 };
  }
  const countWidth = clamp(
    Math.min(COUNT_MAX_WIDTH, Math.floor(width * 0.3)),
    0,
    Math.max(0, width - HEADING_LABEL_MIN - 1),
  );
  const gap = countWidth > 0 ? 1 : 0;
  return { width, labelWidth: Math.max(0, width - countWidth - gap), gap, countWidth };
}

/**
 * The full geometry of the marketplace screen. Horizontally the detail pane
 * takes a bounded share of the content column when the terminal is wide enough to
 * hold both, and stacks underneath the list otherwise. Vertically the panes give
 * up their borders before they give up rows of content, and the detail pane is
 * dropped entirely rather than rendered at a height that would push its own
 * border through its text.
 */
export function computeMarketLayout({
  width,
  height,
  noticeRows = 0,
}: MarketLayoutInput): MarketLayout {
  const terminalWidth = cells(width);
  // `ShellFrame` pads two cells either side of every screen.
  const contentWidth = Math.max(0, terminalWidth - 4);
  const bodyRows = Math.max(
    0,
    cells(height) - shellChromeRows(terminalWidth) - Math.min(1, cells(noticeRows)),
  );

  const bordered = bodyRows >= BORDERED_MIN_ROWS && contentWidth >= DETAIL_MIN_WIDTH + 4;
  const chrome = borderChrome(bordered);
  const listMinHeight = chrome.vertical + 1 + 1;
  const detailMinHeight = chrome.vertical + 1;

  // -- horizontal split --
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
    detailWidth = clamp(wanted, 0, Math.max(0, available - LIST_MIN_WIDTH));
    listWidth = available - detailWidth;
  }
  const stacked = detailWidth <= 0;
  if (stacked) {
    detailWidth = contentWidth;
    listWidth = contentWidth;
  }

  // -- vertical split --
  let listHeight = 0;
  let detailHeight = 0;
  if (bodyRows >= listMinHeight) {
    if (stacked) {
      const wanted = Math.min(Math.floor(bodyRows * STACKED_DETAIL_SHARE), STACKED_DETAIL_MAX_ROWS);
      detailHeight = wanted >= detailMinHeight + 1 && bodyRows - wanted >= listMinHeight ? wanted : 0;
      listHeight = bodyRows - detailHeight;
    } else {
      listHeight = bodyRows;
      detailHeight = bodyRows >= detailMinHeight ? bodyRows : 0;
    }
  }

  const list = makePane(listWidth, listHeight, chrome.horizontal, chrome.vertical, true);
  const detail = makePane(detailWidth, detailHeight, chrome.horizontal, chrome.vertical, !stacked);

  return {
    stacked,
    bordered,
    contentWidth,
    bodyRows,
    paneGap: list.width > 0 && detail.width > 0 && !stacked ? paneGap : 0,
    list,
    detail,
    row: computeRowLayout(list.innerWidth),
    heading: computeHeadingLayout(list.innerWidth),
    visibleRows: list.bodyRows,
    detailCompact: !bordered,
  };
}

// ---------------------------------------------------------------------------
// Detail pane
// ---------------------------------------------------------------------------

export type MarketDetailTone = "title" | "text" | "muted" | "accent" | "ok" | "warn" | "blank";

export interface MarketDetailLine {
  readonly text: string;
  readonly tone: MarketDetailTone;
}

export interface MarketDetailInput {
  row?: MarketRow;
  /** Omit the blank separator rows. Set when the pane is short of rows. */
  compact?: boolean;
}

/** How an install state reads as a short inline tag. */
export function stateTag(state: MarketState): string {
  switch (state) {
    case "installed":
      return "installed";
    case "enabled":
      return "enabled";
    case "active":
      return "active";
    default:
      return "available";
  }
}

/** A full sentence describing the install state, per kind. */
function stateSentence(kind: MarketKind, state: MarketState): { text: string; tone: MarketDetailTone } {
  switch (state) {
    case "installed":
      return kind === "plugin"
        ? { text: "Installed — NOT enabled. No plugin code has run.", tone: "ok" }
        : { text: "Installed. Not the active theme.", tone: "ok" };
    case "enabled":
      return { text: "Installed and enabled for this project.", tone: "ok" };
    case "active":
      return { text: "Installed and active as the console theme.", tone: "ok" };
    default:
      return { text: "Not installed on this machine.", tone: "muted" };
  }
}

/** The action hint for the selected row, given its kind and state. */
export function actionHint(kind: MarketKind, state: MarketState): string {
  if (state === "available") {
    return kind === "plugin"
      ? "enter to install (writes files; runs nothing; does NOT enable)"
      : "enter to install this theme (writes a palette file; runs nothing)";
  }
  if (kind === "plugin") {
    return state === "enabled"
      ? "already enabled — manage with `0sec plugin`"
      : "installed — enable explicitly with `0sec plugin enable`";
  }
  return state === "active" ? "already the active theme" : "apply with `0sec theme apply`";
}

/**
 * The detail pane's body, as flat tone-tagged lines. Content is decided here and
 * colour by the component, so the pane can be asserted on without a renderer.
 */
export function marketDetailLines(
  { row, compact = false }: MarketDetailInput,
  width: number,
): MarketDetailLine[] {
  const limit = cells(width);
  if (!row || limit <= 0) return [];

  const lines: MarketDetailLine[] = [];
  const push = (value: string, tone: MarketDetailTone) => {
    for (const text of wrapCells(value, limit)) lines.push({ text, tone });
  };
  const separate = () => {
    if (!compact) lines.push({ text: "", tone: "blank" });
  };

  if (row.kind === "heading") {
    push(row.group.label, "title");
    separate();
    const count = row.count;
    push(
      `${count} ${row.group.id}${count === 1 ? "" : "s"} available in this registry`,
      "text",
    );
    return lines;
  }

  const { item, state } = row;
  push(item.name, "title");
  separate();
  push(`Kind: ${item.kind}`, "text");
  if (item.version.length > 0) push(`Version: ${item.version}`, "text");
  separate();
  push(item.description, "text");

  if (item.kind === "plugin") {
    separate();
    if (item.capabilities.length > 0) {
      push(`Capabilities requested: ${item.capabilities.join(", ")}`, "warn");
    } else {
      push("Capabilities requested: none declared", "muted");
    }
  }

  separate();
  const sentence = stateSentence(item.kind, state);
  push(sentence.text, sentence.tone);
  push(`Signature: ${item.signature}`, "muted");

  separate();
  push(actionHint(item.kind, state), "accent");

  return lines;
}

/**
 * Trims detail lines to the rows the pane actually has, marking the cut. Given a
 * width, the marker rides on the last surviving line rather than costing a row of
 * its own — on the terminals where clipping happens the pane has few rows to spare.
 */
export function clipMarketDetailLines(
  lines: readonly MarketDetailLine[],
  rows: number,
  width = 0,
): MarketDetailLine[] {
  const limit = cells(rows);
  if (limit <= 0) return [];
  if (lines.length <= limit) return [...lines];

  const kept = lines.slice(0, limit);
  const last = kept[limit - 1];
  const room = cells(width);
  if (room >= 8 && last && last.text.length > 0) {
    const head = last.text.slice(0, Math.max(0, room - 4)).trimEnd();
    kept[limit - 1] = { text: `${head} ...`, tone: last.tone };
  } else {
    kept[limit - 1] = { text: "...", tone: "muted" };
  }
  return kept;
}

// ---------------------------------------------------------------------------
// Empty / error state
// ---------------------------------------------------------------------------

export interface MarketEmptyInput {
  /** The resolved registry URL, empty when none is configured. */
  registryUrl?: string;
  /** A fetch/parse error message, when the registry was configured but failed. */
  error?: string;
  /** The registry is configured and reachable but carried nothing installable. */
  reachableButEmpty?: boolean;
}

/**
 * The honest empty/error state. No registry endpoint ships by default
 * (`DEFAULT_REGISTRY_URL` is empty), so the common case is "unconfigured", which
 * is guidance, not a crash. A configured-but-failed fetch reports the error; a
 * configured-but-empty registry says so plainly.
 */
export function marketEmptyLines(
  { registryUrl = "", error, reachableButEmpty = false }: MarketEmptyInput,
  width: number,
): MarketDetailLine[] {
  const limit = cells(width);
  if (limit <= 0) return [];
  const lines: MarketDetailLine[] = [];
  const push = (value: string, tone: MarketDetailTone) => {
    for (const text of wrapCells(value, limit)) lines.push({ text, tone });
  };
  const blank = () => lines.push({ text: "", tone: "blank" });

  const configured = registryUrl.trim().length > 0;

  if (error) {
    push("Could not reach the marketplace registry.", "warn");
    blank();
    push(`Registry: ${registryUrl}`, "muted");
    push(error, "muted");
    blank();
    push("Check the URL and your network, then reopen this screen.", "text");
    return lines;
  }

  if (!configured) {
    push("No marketplace registry configured.", "title");
    blank();
    push("Set 0SEC_REGISTRY_URL to a registry index URL you trust, then reopen this screen.", "text");
    blank();
    push("No endpoint ships by default — the marketplace is opt-in.", "muted");
    push("Installing writes files and runs nothing; it never enables a plugin.", "muted");
    return lines;
  }

  if (reachableButEmpty) {
    push("The configured registry has no plugins or themes to install.", "text");
    blank();
    push(`Registry: ${registryUrl}`, "muted");
    return lines;
  }

  push("Loading the marketplace registry…", "muted");
  return lines;
}

// ---------------------------------------------------------------------------
// Titles, hints and keys
// ---------------------------------------------------------------------------

/** `MARKETPLACE 4-15/53`, or `MARKETPLACE 53` when the whole list is on screen. */
export function marketListTitle(window: MarketWindow): string {
  if (window.total === 0) return "MARKETPLACE 0";
  if (!window.hasAbove && !window.hasBelow) return `MARKETPLACE ${window.total}`;
  return `MARKETPLACE ${window.start + 1}-${window.end}/${window.total}`;
}

/**
 * The list pane's header, split into a bold title and a right-aligned summary
 * meta — the OMP-style "NAME … count" header the console reuses (mirrors the
 * dialog picker's "Resume a session … 20 available"). The title is a stable
 * label; the meta counts the roster, or names the visible window when the list
 * is scrolled, so an operator always knows how much is off-screen.
 */
export function marketListHeading(window: MarketWindow): { title: string; meta: string } {
  if (window.total === 0) return { title: "MARKETPLACE", meta: "empty" };
  if (!window.hasAbove && !window.hasBelow) {
    const n = window.total;
    return { title: "MARKETPLACE", meta: `${n} item${n === 1 ? "" : "s"}` };
  }
  return { title: "MARKETPLACE", meta: `${window.start + 1}-${window.end} / ${window.total}` };
}

/**
 * Split a pane's single title row into a left title column and a right,
 * right-aligned meta column. The columns plus the gap always sum to EXACTLY
 * `innerWidth`, so the header can never overflow or fuse under pressure — the
 * same row-budget invariant the list rows obey. The meta never takes more than
 * half the row and the title always keeps at least one cell, so a long meta can
 * never squeeze the title out entirely.
 */
export interface PaneTitleColumns {
  /** Left title column cells. */
  titleWidth: number;
  /** Gap between title and meta. 0 when there is no meta. */
  gap: number;
  /** Right meta column cells. 0 when there is no meta or no room for one. */
  metaWidth: number;
}

export function paneTitleColumns(innerWidth: number, metaLength: number): PaneTitleColumns {
  const width = cells(innerWidth);
  if (width <= 0) return { titleWidth: 0, gap: 0, metaWidth: 0 };
  const wantMeta = cells(metaLength);
  const metaWidth =
    wantMeta > 0 ? Math.min(wantMeta, Math.max(0, width - 2), Math.floor(width / 2)) : 0;
  const gap = metaWidth > 0 && width > metaWidth ? 1 : 0;
  const titleWidth = Math.max(0, width - metaWidth - gap);
  return { titleWidth, gap, metaWidth };
}

export type MarketMode = "browse" | "filter" | "confirm";

/**
 * The footer hint, per mode. These are the real bindings: browse gives every
 * printable character to the filter, install is confirmed (never silent), and
 * nothing on this screen enables a plugin.
 */
export function marketFooterHint(mode: MarketMode, hasFilter = false): string {
  if (mode === "filter") return "type to filter · enter/esc done · backspace delete";
  if (mode === "confirm") return "y install · n/esc cancel";
  return [
    "up/down move",
    "enter install",
    "/ filter",
    hasFilter ? "esc clear filter" : "esc back",
    "ctrl+c exit",
  ].join(" · ");
}

/** Every printable character starts a filter (there is no destructive key). */
export function isFilterKey(sequence: unknown): boolean {
  if (typeof sequence !== "string" || sequence.length !== 1) return false;
  const code = sequence.charCodeAt(0);
  return code >= 0x20 && code !== 0x7f;
}
