/**
 * Shared pane-geometry primitives for the list/detail TUI screens
 * (connect, marketplace, herd, and the key/value detail panes).
 *
 * These screens historically each carried a verbatim copy of the same
 * width-budgeting and horizontal/vertical split algorithm, differing only in
 * their tuning constants. The maths is identical, so it lives here once as a set
 * of small, pure, well-typed helpers; each screen supplies its own constants and
 * keeps its own module-specific fields (rows, headings, detail bodies).
 *
 * Everything here is pure: same inputs, same outputs, no I/O, no globals.
 */

/** Cell and row counts are non-negative integers; garbage geometry degrades to 0. */
function cells(value: unknown, fallback = 0): number {
  const raw = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  const truncated = Math.trunc(raw);
  return truncated > 0 ? truncated : 0;
}

function clamp(value: number, low: number, high: number): number {
  if (high < low) return low;
  return Math.min(Math.max(value, low), high);
}

// ---------------------------------------------------------------------------
// Scroll-into-view windowing
// ---------------------------------------------------------------------------

export interface ListWindowInput<Row> {
  rows: readonly Row[];
  selected: number;
  visible: number;
  anchor?: number;
}

export interface ListWindow {
  start: number;
  end: number;
  count: number;
  total: number;
  hasAbove: boolean;
  hasBelow: boolean;
}

/**
 * Scroll-into-view windowing, anchored on the caller's last start so the list
 * scrolls rather than re-centres. When the cursor lands on the first row of a
 * group (its predecessor is a `kind: "heading"` row), the window is pulled up
 * one extra row so that group's heading comes with it — a list scrolled past its
 * own heading has stopped saying which group you are looking at.
 */
export function computeListWindow<Row extends { kind?: unknown }>({
  rows,
  selected,
  visible,
  anchor = 0,
}: ListWindowInput<Row>): ListWindow {
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
// List / detail pane split
// ---------------------------------------------------------------------------

/** Per-screen tuning for {@link computePaneSplit}. The algorithm is shared; these numbers are not. */
export interface PaneSplitConfig {
  /** Below this content width the detail pane cannot sit beside the list and stacks under it. */
  twoPaneMinWidth: number;
  detailMinWidth: number;
  detailMaxWidth: number;
  /** Fraction of the available width the detail pane wants when split. */
  detailWidthShare: number;
  listMinWidth: number;
  /** Below this many body rows the panes drop their borders. */
  borderedMinRows: number;
  /** Fraction of body rows the stacked detail pane wants. */
  stackedDetailShare: number;
  stackedDetailMaxRows: number;
}

export interface Pane {
  width: number;
  innerWidth: number;
  height: number;
  bodyRows: number;
  hasTitle: boolean;
}

export interface PaneSplit {
  stacked: boolean;
  bordered: boolean;
  contentWidth: number;
  bodyRows: number;
  paneGap: number;
  list: Pane;
  detail: Pane;
}

/** The horizontal/vertical cells a pane spends on its border, or none when unbordered. */
export function borderChrome(bordered: boolean): { horizontal: number; vertical: number } {
  return bordered ? { horizontal: 4, vertical: 2 } : { horizontal: 0, vertical: 0 };
}

/**
 * Builds a pane from an outer size and its chrome. A pane whose outer box cannot
 * hold its chrome plus one content row collapses to all-zeros rather than
 * reporting negative inner space.
 */
export function makePane(
  width: number,
  height: number,
  chromeH: number,
  chromeV: number,
  hasTitle: boolean,
): Pane {
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
 * The list/detail geometry shared by the connect, marketplace and herd screens.
 *
 * Horizontally the detail pane takes a bounded share of the content column when
 * the terminal is wide enough to hold both, and stacks underneath the list
 * otherwise. Vertically the panes give up their borders before they give up rows
 * of content, and the detail pane is dropped entirely rather than rendered at a
 * height that would push its own border through its text.
 *
 * `contentWidth` and `bodyRows` are supplied by the caller (each screen computes
 * them from its own shell chrome) and echoed back on the result for convenience.
 */
export function computePaneSplit(
  contentWidth: number,
  bodyRows: number,
  config: PaneSplitConfig,
): PaneSplit {
  const bordered =
    bodyRows >= config.borderedMinRows && contentWidth >= config.detailMinWidth + 4;
  const chrome = borderChrome(bordered);
  const listMinHeight = chrome.vertical + 1 + 1;
  const detailMinHeight = chrome.vertical + 1;

  // -- horizontal split --
  const canSplit = contentWidth >= config.twoPaneMinWidth;
  const paneGap = canSplit ? 1 : 0;
  let detailWidth = 0;
  let listWidth = contentWidth;
  if (canSplit) {
    const available = contentWidth - paneGap;
    const wanted = clamp(
      Math.floor(available * config.detailWidthShare),
      config.detailMinWidth,
      config.detailMaxWidth,
    );
    detailWidth = clamp(wanted, 0, Math.max(0, available - config.listMinWidth));
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
      const wanted = Math.min(
        Math.floor(bodyRows * config.stackedDetailShare),
        config.stackedDetailMaxRows,
      );
      detailHeight =
        wanted >= detailMinHeight + 1 && bodyRows - wanted >= listMinHeight ? wanted : 0;
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
  };
}

// ---------------------------------------------------------------------------
// Key/value row split
// ---------------------------------------------------------------------------

/** Per-screen tuning for {@link computeKvSplit}. */
export interface KvSplitConfig {
  /** Below this inner width the row keeps the label and drops the value column. */
  minRoom: number;
  labelMinWidth: number;
  labelMaxWidth: number;
  /** Fraction of the inner width the value column wants. */
  valueWidthShare: number;
}

export interface KvSplit {
  /** Total cells the row occupies; equals the pane's inner width. */
  width: number;
  labelWidth: number;
  gap: number;
  /** Value column. 0 when the row can only afford a label. */
  valueWidth: number;
}

/**
 * Splits a key/value row into its label and value columns. Every separator is a
 * real gap, never a padded literal. Below `minRoom` the row keeps the label and
 * drops the value column, because a truncated label beside a truncated value is
 * worse than a whole label. The label's leftovers (from the `labelMaxWidth` cap)
 * are handed back to the value so the row always claims exactly its width.
 */
export function computeKvSplit(innerWidth: number, config: KvSplitConfig): KvSplit {
  const width = cells(innerWidth);
  if (width <= 0) return { width: 0, labelWidth: 0, gap: 0, valueWidth: 0 };
  if (width < config.minRoom) return { width, labelWidth: width, gap: 0, valueWidth: 0 };
  const valueWidth = Math.min(
    Math.max(0, width - config.labelMinWidth - 1),
    Math.floor(width * config.valueWidthShare),
  );
  const gap = valueWidth > 0 ? 1 : 0;
  const labelWidth = Math.min(config.labelMaxWidth, Math.max(0, width - valueWidth - gap));
  const value = Math.max(0, width - labelWidth - gap);
  return { width, labelWidth, gap, valueWidth: value };
}

// ---------------------------------------------------------------------------
// Pane title columns
// ---------------------------------------------------------------------------

export interface PaneTitleColumns {
  /** Left title column cells. */
  titleWidth: number;
  /** Gap between title and meta. 0 when there is no meta. */
  gap: number;
  /** Right meta column cells. 0 when there is no meta or no room for one. */
  metaWidth: number;
}

/**
 * Split a pane's single title row into a left title column and a right,
 * right-aligned meta column. The columns plus the gap always sum to EXACTLY
 * `innerWidth`, so the header can never overflow or fuse under pressure — the
 * same row-budget invariant the list rows obey. The meta never takes more than
 * half the row and the title always keeps at least one cell, so a long meta can
 * never squeeze the title out entirely.
 */
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
