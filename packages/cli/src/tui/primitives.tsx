/** @jsxImportSource @opentui/react */
/**
 * Overflow-proof layout primitives for the TUI.
 *
 * ## The bug this file exists to delete
 *
 * OpenTUI lays rows out with Yoga, and Yoga does not clip. A row of
 * auto-width `<text>` siblings that collectively want more cells than the
 * row has is *shrunk*, not truncated — every sibling keeps painting its
 * full string into a box that is now too small, so the strings are drawn
 * on top of one another. That is where these came from:
 *
 *   "Show available slash commands"  ->  "Showpavailableenslash commands"
 *   "0sec / chat" + "target: none"   ->  "target:cnone"
 *   "runs" + "12"                    ->  "runs12"
 *
 * The same thing happens on the vertical axis: a bordered box squeezed
 * below its content height still paints its own bottom border, straight
 * through the last rows of its content — `-/clear--------/new-`.
 *
 * And there is a third, sneakier variant. `fitTuiText` routes through
 * `sanitizeTuiText`, which collapses whitespace *and trims*. So
 * `fitTuiText("runs ", 8)` is `"runs"`, not `"runs "` — a padded literal
 * used as a separator silently disappears and the label fuses to its
 * value even when the row had room to spare.
 *
 * ## The fix
 *
 * The existing cure is a convention: give every sibling an explicit
 * `width`, add `flexShrink={0}`, budget the string with `fitTuiText`
 * against that same width, use a real `gap` rather than a padded literal,
 * and hand-check that widths plus gaps never exceed the container. That
 * convention has been broken dozens of times because nothing enforces it.
 *
 * These primitives enforce it structurally:
 *
 *   - `Cells` cannot be constructed without a width, always sets
 *     `flexShrink={0}`, and always routes its text through `fitTuiText`
 *     against that exact width. There is no way to put unbounded text
 *     through it: its children are typed `string | number`, not
 *     `ReactNode`, so an unbudgeted `<text>` cannot be nested inside.
 *   - `Columns` takes the available width and a list of *intents*
 *     (`{ fixed }`, `{ flex }`, `{ content }`) and does the arithmetic
 *     itself. It has no `children` prop, so a stray auto-width sibling
 *     cannot be smuggled into the row.
 *   - `LabelValue` separates its two halves with a real `gap`, so the
 *     trimming trap above cannot occur.
 *   - `Rows` takes a `fitRows` result and renders with an explicit
 *     `height` and `flexShrink={0}`, so a border can never be pushed
 *     through its own content.
 *
 * The allocation math is pure and exported separately from the components
 * (`allocateColumns`, `allocateLabelValue`, `fitRows`), following the
 * precedent set by `chat-layout.ts`, so the invariant
 *
 *     sum(widths) + gap * (renderedColumns - 1) <= available
 *
 * is a unit test rather than a code review.
 */

import type { ReactNode } from "react";

import { fitTuiText, sanitizeTuiText, type TuiTextFitMode } from "./text.js";

// ---------------------------------------------------------------------------
// Shared numeric hygiene
// ---------------------------------------------------------------------------

/**
 * Cell counts are non-negative integers. Terminal geometry arrives from
 * `useTerminalDimensions`, from percentage math and from user config, so
 * NaN, `Infinity` and fractional widths all show up in practice. Yoga
 * accepts them and produces sub-cell layouts that round inconsistently
 * between siblings — which is itself an overlap. Everything entering the
 * allocator goes through here.
 */
export function toCells(value: unknown, fallback = 0): number {
  const raw = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  const truncated = Math.trunc(raw);
  return truncated > 0 ? truncated : 0;
}

/** Upper bounds may legitimately be "unbounded"; `undefined` means no cap. */
function toCap(value: unknown): number {
  if (value === undefined || value === null) return Number.POSITIVE_INFINITY;
  if (typeof value !== "number" || Number.isNaN(value)) return Number.POSITIVE_INFINITY;
  if (value === Number.POSITIVE_INFINITY) return Number.POSITIVE_INFINITY;
  return toCells(value);
}

/** Natural cell cost of a string once it has been sanitised for the terminal. */
export function textCells(value: unknown): number {
  return sanitizeTuiText(value).length;
}

// ---------------------------------------------------------------------------
// Column specs
// ---------------------------------------------------------------------------

export interface ColumnSpecBase {
  /**
   * Survival order when the row cannot fit every column.
   *
   * Columns are dropped lowest-priority-first, then right-to-left, and
   * grown back in the reverse order. Default 0. This is how the chat
   * header keeps the identity stamp and the autonomy mode while the long
   * engagement summary gives up its cells first.
   */
  priority?: number;
}

/** Exactly `fixed` cells, or fewer if the row is too narrow to pay for it. */
export interface FixedColumnSpec extends ColumnSpecBase {
  fixed: number;
  flex?: never;
  content?: never;
  min?: never;
  max?: never;
}

/** Takes a share of whatever is left after the sized columns are paid. */
export interface FlexColumnSpec extends ColumnSpecBase {
  flex: number;
  /** Below this the column is dropped entirely rather than rendered. */
  min?: number;
  max?: number;
  fixed?: never;
  content?: never;
}

/** Sized to its own text, clamped to `[min, max]`. */
export interface ContentColumnSpec extends ColumnSpecBase {
  content: string;
  /** Below this the column is dropped entirely rather than rendered. */
  min?: number;
  max?: number;
  fixed?: never;
  flex?: never;
}

/**
 * The `?: never` members are load-bearing: they make `{ fixed: 4, flex: 1 }`
 * a type error rather than a silent precedence question at runtime.
 */
export type ColumnSpec = FixedColumnSpec | FlexColumnSpec | ContentColumnSpec;

export interface ColumnAllocationInput {
  /** Cells the row may occupy in total, gaps included. */
  available: number;
  /** Cells between two adjacent *rendered* columns. Default 0. */
  gap?: number;
  columns: readonly ColumnSpec[];
}

export interface ColumnAllocation {
  /** One entry per input column, in input order. `0` means "dropped". */
  widths: number[];
  /** The gap actually applied between rendered columns. */
  gap: number;
  /** Cells spent on gaps: `gap * max(0, rendered.length - 1)`. */
  gapCells: number;
  /** `sum(widths) + gapCells`. Guaranteed `<= available`. */
  used: number;
  /** Indices that received at least one cell, in input order. */
  rendered: number[];
}

function isFlex(spec: ColumnSpec): spec is FlexColumnSpec {
  return typeof (spec as FlexColumnSpec).flex === "number";
}

/** Cells a column wants before any flex growth is considered. */
function baseWant(spec: ColumnSpec): number {
  if (isFlex(spec)) return toCells(spec.min);
  if (typeof (spec as FixedColumnSpec).fixed === "number") {
    return toCells((spec as FixedColumnSpec).fixed);
  }
  const content = spec as ContentColumnSpec;
  const lo = toCells(content.min);
  const hi = toCap(content.max);
  const natural = textCells(content.content);
  return Math.min(Math.max(natural, lo), Math.max(lo, hi));
}

/**
 * The fewest cells worth rendering this column in at all.
 *
 * This is what `min` means, and it is deliberately not "the width you get
 * when the row is tight". A column squeezed to one cell renders a lone
 * "." and still costs a gap; saying `min: 12` says "below twelve cells I
 * am noise, drop me". Fixed and unconstrained columns floor at one cell
 * and degrade by truncating instead.
 */
function hardMin(spec: ColumnSpec): number {
  if (isFlex(spec)) return Math.max(1, toCells(spec.min));
  if (typeof (spec as FixedColumnSpec).fixed === "number") return 1;
  return Math.max(1, toCells((spec as ContentColumnSpec).min));
}

/** Ceiling a flex column may grow to. Non-flex columns never grow. */
function growthCap(spec: ColumnSpec): number {
  if (!isFlex(spec)) return baseWant(spec);
  const lo = toCells(spec.min);
  const hi = toCap(spec.max);
  return Math.max(lo, hi);
}

/**
 * A column that can never be worth any cells.
 *
 * `{ fixed: 0 }`, `{ content: "" }` and a zero-weight flex with no minimum
 * are all "not applicable right now" — which is exactly what the
 * hand-written `width > 0 ? <text/> : null` guards at the call sites were
 * saying. Excluding them here means the caller can pass the column
 * unconditionally and neither pay a cell nor pay a gap for it.
 */
function isInert(spec: ColumnSpec): boolean {
  if (isFlex(spec)) return toCells(spec.flex) === 0 && baseWant(spec) === 0;
  return baseWant(spec) === 0;
}

/**
 * Allocate cells to a row of columns.
 *
 * Guarantees, for every input including nonsense:
 *   - every width is a non-negative integer;
 *   - `sum(widths) + gap * (rendered - 1) <= available`;
 *   - never throws, at any `available` including 0, 1 and 2.
 *
 * The shape of the algorithm is deliberately "floor first, grow second":
 * columns that cannot be paid their declared minimum are dropped whole,
 * every survivor is handed that minimum up front, and every later step
 * only ever spends from a `remaining` counter that starts at the
 * proven-affordable surplus and is never allowed below zero. Overflow is
 * therefore not something the code has to check for — it is unreachable.
 */
export function allocateColumns({
  available,
  gap = 0,
  columns,
}: ColumnAllocationInput): ColumnAllocation {
  const avail = toCells(available);
  const gapCells = toCells(gap);
  const specs = columns ?? [];
  const count = specs.length;
  const widths = new Array<number>(count).fill(0);

  if (count === 0 || avail === 0) {
    return { widths, gap: gapCells, gapCells: 0, used: 0, rendered: [] };
  }

  // Drop order: least important first, and right-to-left within a tier.
  // Growth order is exactly its reverse, so a column that would be the
  // first to be dropped is also the last to be fattened.
  const dropOrder = specs
    .map((spec, index) => ({ index, priority: spec.priority ?? 0, inert: isInert(spec) }))
    .filter((entry) => !entry.inert)
    .sort((a, b) => (a.priority - b.priority) || (b.index - a.index))
    .map((entry) => entry.index);
  const keepOrder = [...dropOrder].reverse();
  if (dropOrder.length === 0) {
    return { widths, gap: gapCells, gapCells: 0, used: 0, rendered: [] };
  }

  // Step 1: which columns can be shown at all? A rendered column costs its
  // `hardMin`, plus one gap for every column after the first. Columns are
  // dropped whole rather than rendered below the width they declared.
  const floors = specs.map(hardMin);
  const active = new Set<number>(dropOrder);
  let floorTotal = dropOrder.reduce((sum, index) => sum + floors[index]!, 0);
  let cursor = 0;
  while (active.size > 0 && floorTotal + gapCells * (active.size - 1) > avail) {
    const victim = dropOrder[cursor]!;
    active.delete(victim);
    floorTotal -= floors[victim]!;
    cursor += 1;
  }
  if (active.size === 0) {
    return { widths, gap: gapCells, gapCells: 0, used: 0, rendered: [] };
  }

  const spentOnGaps = gapCells * (active.size - 1);
  const budget = avail - spentOnGaps; // >= floorTotal, by the loop above.

  // Step 2: floor. Everything that survives is paid its declared minimum.
  for (const index of active) widths[index] = floors[index]!;
  let remaining = budget - floorTotal;

  // Step 3: pay the sized columns, most important first. `remaining` is
  // the only source of cells and it is clamped at every withdrawal, so no
  // column can ever be paid with cells the row does not have.
  for (const index of keepOrder) {
    if (!active.has(index)) continue;
    if (remaining <= 0) break;
    const want = baseWant(specs[index]!) - widths[index];
    const take = Math.max(0, Math.min(want, remaining));
    widths[index] = widths[index] + take;
    remaining -= take;
  }

  // Step 4: share the surplus among flex columns, by weight, up to their
  // caps. Weights are integers and shares are floored, so the leftover
  // from rounding is handed out one cell at a time in keep order — never
  // borrowed from a future iteration.
  const flexIndices = keepOrder.filter(
    (index) => active.has(index) && isFlex(specs[index]!),
  );
  while (remaining > 0) {
    const pool = flexIndices.filter((index) => {
      const spec = specs[index] as FlexColumnSpec;
      return toCells(spec.flex) > 0 && widths[index] < growthCap(spec);
    });
    if (pool.length === 0) break;
    const totalWeight = pool.reduce(
      (sum, index) => sum + toCells((specs[index] as FlexColumnSpec).flex),
      0,
    );
    if (totalWeight <= 0) break;

    const start = remaining;
    let handed = 0;
    for (const index of pool) {
      if (handed >= start) break;
      const spec = specs[index] as FlexColumnSpec;
      const weight = toCells(spec.flex);
      // `Math.max(1, ...)` guarantees the loop makes progress and so
      // terminates even when the weighted share floors to zero.
      const share = Math.max(1, Math.floor((start * weight) / totalWeight));
      const headroom = growthCap(spec) - widths[index];
      const give = Math.min(share, headroom, start - handed);
      if (give <= 0) continue;
      widths[index] = widths[index] + give;
      handed += give;
    }
    remaining -= handed;
    if (handed <= 0) break;
  }

  const rendered: number[] = [];
  for (let index = 0; index < count; index += 1) {
    if (widths[index] > 0) rendered.push(index);
  }
  const spent = widths.reduce((sum, width) => sum + width, 0);
  const finalGapCells = gapCells * Math.max(0, rendered.length - 1);
  return {
    widths,
    gap: gapCells,
    gapCells: finalGapCells,
    used: spent + finalGapCells,
    rendered,
  };
}

/** Convenience for callers that only want the numbers. */
export function columnWidths(input: ColumnAllocationInput): number[] {
  return allocateColumns(input).widths;
}

// ---------------------------------------------------------------------------
// Label / value pairs
// ---------------------------------------------------------------------------

export interface LabelValueAllocationInput {
  available: number;
  label: string;
  value: string | number;
  /** Cells between label and value. Default 1, and never below 1. */
  gap?: number;
  /** Optional ceiling on the label so a long caption cannot eat the row. */
  labelMax?: number;
}

export interface LabelValueAllocation {
  labelWidth: number;
  valueWidth: number;
  gap: number;
  /** `labelWidth + gap + valueWidth` when both are shown. `<= available`. */
  used: number;
}

/**
 * Budget a caption and its value.
 *
 * The separation between the two is a *gap*, never a padded literal. That
 * is the whole point: `fitTuiText("runs ", n)` returns `"runs"` because
 * `sanitizeTuiText` trims, so any design that leans on a trailing space
 * for separation produces `runs12` the moment the string is budgeted.
 *
 * The value outranks the label: at widths too small for both, the number
 * survives and the caption truncates, because "12" with no caption is
 * still information and "runs" with no number is not.
 */
export function allocateLabelValue({
  available,
  label,
  value,
  gap = 1,
  labelMax,
}: LabelValueAllocationInput): LabelValueAllocation {
  const gapCells = Math.max(1, toCells(gap, 1));
  const valueCells = textCells(value);
  const allocation = allocateColumns({
    available,
    gap: gapCells,
    columns: [
      { content: label, max: toCap(labelMax), priority: 0 },
      // `min: 1` rather than the value's natural length: a value too long
      // for the row should truncate, not vanish. Its higher priority is
      // what makes it outlive the caption. An empty value claims nothing.
      { flex: valueCells > 0 ? 1 : 0, min: valueCells > 0 ? 1 : 0, priority: 1 },
    ],
  });
  const labelWidth = allocation.widths[0] ?? 0;
  const valueWidth = allocation.widths[1] ?? 0;
  return {
    labelWidth,
    valueWidth,
    gap: labelWidth > 0 && valueWidth > 0 ? gapCells : 0,
    used: allocation.used,
  };
}

// ---------------------------------------------------------------------------
// Vertical fit
// ---------------------------------------------------------------------------

export interface RowFitInput {
  /** Rows the box may occupy in total, its own chrome included. */
  available: number;
  /** Rows the box spends on itself: borders, title row, hint footer. */
  chrome?: number;
  /** Rows each item renders. Default 1. */
  rowsPerItem?: number;
  /** How many items want to be rendered. */
  items: number;
  /** Hard ceiling on visible items, independent of the height. */
  maxItems?: number;
  /**
   * Share of `available` this box may claim, 0..1.
   *
   * Fitting is necessary but not sufficient: a box sized purely by "what
   * is left over" grows until the region above it is squeezed to nothing,
   * and *that* region then overlaps its own content instead.
   */
  maxShare?: number;
  /**
   * Best-effort floor on visible items. Honoured only when the resulting
   * box still fits; the height invariant is never traded away for it.
   */
  minItems?: number;
}

export interface RowFit {
  /** Items that can be rendered without the border crossing the content. */
  visible: number;
  /** `visible * rowsPerItem`. */
  itemRows: number;
  /** `chrome + itemRows`, or 0 when nothing fits. Guaranteed `<= available`. */
  boxHeight: number;
  /** Items that did not fit. */
  overflow: number;
  /** Whether every item is shown. */
  fits: boolean;
}

/**
 * How many items fit in a bordered box of a given height.
 *
 * A box that cannot fit even one item reports `boxHeight: 0`, and `Rows`
 * renders nothing for it. Drawing a box one row shorter than its content
 * is the failure mode — an absent box is merely missing information, a
 * squeezed box is corruption that looks like a crash.
 */
export function fitRows({
  available,
  chrome = 0,
  rowsPerItem = 1,
  items,
  maxItems,
  maxShare,
  minItems = 0,
}: RowFitInput): RowFit {
  const avail = toCells(available);
  const chromeRows = toCells(chrome);
  const perItem = Math.max(1, toCells(rowsPerItem, 1));
  const wanted = toCells(items);

  const share =
    typeof maxShare === "number" && Number.isFinite(maxShare)
      ? Math.min(1, Math.max(0, maxShare))
      : 1;
  const budget = Math.min(avail, Math.floor(avail * share));
  const rowsForItems = Math.max(0, budget - chromeRows);

  let visible = Math.min(wanted, Math.floor(rowsForItems / perItem));
  const cap = toCap(maxItems);
  if (visible > cap) visible = Math.max(0, Math.trunc(cap));

  // Best effort only: a floor that would push the border through the
  // content is not a floor, it is the bug.
  const floor = Math.min(toCells(minItems), wanted);
  if (floor > visible && chromeRows + floor * perItem <= avail) {
    visible = floor;
  }

  const itemRows = visible * perItem;
  const boxHeight = visible > 0 ? chromeRows + itemRows : 0;
  return {
    visible,
    itemRows,
    boxHeight,
    overflow: Math.max(0, wanted - visible),
    fits: visible >= wanted,
  };
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

export type CellAlign = "left" | "right" | "center";

export interface FitCellsOptions {
  align?: CellAlign;
  fit?: TuiTextFitMode;
  maxEncodedRun?: number;
}

/**
 * Fit a value to exactly `width` cells — no more, and no fewer.
 *
 * `fitTuiText` alone only guarantees "no more". A short string in a wide
 * `width={n}` box leaves the remaining cells to whatever the renderer
 * feels like, and a short string in a box that Yoga later squeezed is
 * exactly the overlap this module exists to prevent. Padding back up to
 * the allocation makes the rendered length a constant, so the leaf's
 * footprint is decided by the allocator and by nothing else.
 *
 * Exported because it is the single-cell half of the invariant and is
 * worth testing directly: `fitCells(anything, n).length === n` for n > 0.
 */
export function fitCells(
  value: unknown,
  width: number,
  { align = "left", fit, maxEncodedRun }: FitCellsOptions = {},
): string {
  const cells = toCells(width);
  if (cells <= 0) return "";
  const text = fitTuiText(value ?? "", cells, { mode: fit, maxEncodedRun });
  if (text.length >= cells) return text.slice(0, cells);
  if (align === "right") return text.padStart(cells, " ");
  if (align === "center") {
    const left = Math.floor((cells - text.length) / 2);
    return `${" ".repeat(left)}${text}`.padEnd(cells, " ");
  }
  return text.padEnd(cells, " ");
}

export interface CellStyle {
  fg?: string;
  bg?: string;
  attributes?: number;
  align?: CellAlign;
  /** `"end"` (default) or `"middle"` truncation, as per `fitTuiText`. */
  fit?: TuiTextFitMode;
  /** Forwarded to `sanitizeTuiText` for base64-ish payload collapsing. */
  maxEncodedRun?: number;
}

export interface CellsProps extends CellStyle {
  /**
   * Required. There is no default and no `"auto"`: a cell whose width is
   * decided by its content is precisely the thing that overlaps its
   * neighbours.
   */
  width: number;
  /**
   * Typed `string | number`, not `ReactNode`. An unbudgeted `<text>`
   * cannot be nested inside a `Cells`, so text always leaves this
   * component already fitted to its allocation.
   */
  children?: string | number | null;
}

/**
 * A text leaf that physically cannot overflow its allocation.
 *
 * The string is fitted to `width` and then padded back up to exactly
 * `width`, so the rendered content is neither longer nor shorter than the
 * box Yoga reserved for it. `flexShrink={0}` stops the box being squeezed
 * and `wrapMode="none"` stops a long word spilling onto a second row and
 * pushing a border down.
 */
export function Cells({
  width,
  children,
  fg,
  bg,
  attributes,
  align = "left",
  fit,
  maxEncodedRun,
}: CellsProps) {
  const cells = toCells(width);
  if (cells <= 0) return null;
  return (
    <text
      width={cells}
      flexShrink={0}
      flexGrow={0}
      wrapMode="none"
      fg={fg}
      bg={bg}
      attributes={attributes}
    >
      {fitCells(children, cells, { align, fit, maxEncodedRun })}
    </text>
  );
}

export type Column = ColumnSpec &
  CellStyle & {
    /**
     * Text for this column. Defaults to the spec's own `content` for
     * content-sized columns, so `{ content: "runs", fg: TEXT }` renders
     * the caption it was measured from.
     */
    text?: string | number | null;
    /**
     * Escape hatch for non-text columns. It is handed the cells this
     * column was actually allocated — anything rendered inside must be
     * bounded by that number, so prefer `Cells` within it.
     */
    render?: (width: number) => ReactNode;
    key?: string;
  };

export interface ColumnsProps {
  /** Cells the row may occupy, gaps included. */
  available: number;
  /** Cells between adjacent rendered columns. Default 0. */
  gap?: number;
  /**
   * Note the absence of `children`. A row cannot contain an element the
   * allocator has not budgeted for, because there is nowhere to put one.
   */
  columns: readonly Column[];
  marginTop?: number;
  marginBottom?: number;
  backgroundColor?: string;
  alignItems?: "flex-start" | "center" | "flex-end" | "stretch";
}

/**
 * A row whose children provably fit.
 *
 * The row declares `width` equal to the cells it actually allocated
 * (always `<= available`) and `flexShrink={0}`, so neither the row nor any
 * column can be compressed by a parent that ran out of room. Separation
 * between columns is a real Yoga `gap`, so no caller has to pad a literal
 * — and therefore no caller can lose that padding to `sanitizeTuiText`.
 */
export function Columns({
  available,
  gap = 0,
  columns,
  marginTop,
  marginBottom,
  backgroundColor,
  alignItems,
}: ColumnsProps) {
  const allocation = allocateColumns({ available, gap, columns });
  if (allocation.rendered.length === 0) return null;

  return (
    <box
      flexDirection="row"
      width={allocation.used}
      minWidth={0}
      flexShrink={0}
      gap={allocation.gap}
      marginTop={marginTop}
      marginBottom={marginBottom}
      backgroundColor={backgroundColor}
      alignItems={alignItems}
    >
      {allocation.rendered.map((index) => {
        const column = columns[index]!;
        const width = allocation.widths[index]!;
        const key = column.key ?? `col-${index}`;
        if (column.render) {
          return (
            <box key={key} width={width} minWidth={0} flexShrink={0}>
              {column.render(width)}
            </box>
          );
        }
        const text =
          column.text ?? (typeof column.content === "string" ? column.content : "");
        return (
          <Cells
            key={key}
            width={width}
            fg={column.fg}
            bg={column.bg}
            attributes={column.attributes}
            align={column.align}
            fit={column.fit}
            maxEncodedRun={column.maxEncodedRun}
          >
            {text}
          </Cells>
        );
      })}
    </box>
  );
}

export interface LabelValueProps {
  available: number;
  label: string;
  value: string | number;
  /** Cells between the two. Default 1, never less. */
  gap?: number;
  labelMax?: number;
  labelFg?: string;
  valueFg?: string;
  valueAlign?: CellAlign;
  valueFit?: TuiTextFitMode;
  marginTop?: number;
  marginBottom?: number;
}

/**
 * A caption and its value, separated by a gap rather than by a space
 * baked into the caption.
 *
 * This is the `runs12` regression, made unexpressible: there is no string
 * concatenation anywhere on this path, so there is no trailing space for
 * `sanitizeTuiText` to trim away.
 */
export function LabelValue({
  available,
  label,
  value,
  gap = 1,
  labelMax,
  labelFg,
  valueFg,
  valueAlign = "left",
  valueFit,
  marginTop,
  marginBottom,
}: LabelValueProps) {
  const allocation = allocateLabelValue({ available, label, value, gap, labelMax });
  const columns: Column[] = [];
  if (allocation.labelWidth > 0) {
    columns.push({ fixed: allocation.labelWidth, text: label, fg: labelFg, key: "label" });
  }
  if (allocation.valueWidth > 0) {
    columns.push({
      fixed: allocation.valueWidth,
      text: value,
      fg: valueFg,
      align: valueAlign,
      fit: valueFit,
      key: "value",
    });
  }
  if (columns.length === 0) return null;
  return (
    <Columns
      available={available}
      gap={allocation.gap > 0 ? allocation.gap : Math.max(1, toCells(gap, 1))}
      columns={columns}
      marginTop={marginTop}
      marginBottom={marginBottom}
    />
  );
}

export interface RowsProps {
  /** The result of `fitRows`. Nothing renders when it reports `boxHeight: 0`. */
  fit: RowFit;
  children?: ReactNode;
  width?: number | "auto" | `${number}%`;
  border?: boolean;
  borderColor?: string;
  backgroundColor?: string;
  title?: string;
  paddingX?: number;
  paddingY?: number;
  marginTop?: number;
  marginBottom?: number;
}

/**
 * A vertical box that states its own height.
 *
 * The `-/clear--------/new-` corruption is a bordered box whose column ran
 * out of rows: Yoga shrank the box, the box kept drawing its bottom border
 * at its new edge, and the command list kept drawing through it. Declaring
 * an explicit `height` from a budget the caller computed with `fitRows`,
 * plus `flexShrink={0}`, removes both halves of that: the box is never
 * resized behind the content's back, and the content was already limited
 * to what the height can hold.
 */
export function Rows({
  fit,
  children,
  width = "100%",
  border,
  borderColor,
  backgroundColor,
  title,
  paddingX,
  paddingY,
  marginTop,
  marginBottom,
}: RowsProps) {
  if (fit.boxHeight <= 0) return null;
  return (
    <box
      flexDirection="column"
      width={width}
      minWidth={0}
      height={fit.boxHeight}
      flexShrink={0}
      flexGrow={0}
      border={border}
      borderColor={borderColor}
      backgroundColor={backgroundColor}
      title={title}
      paddingX={paddingX}
      paddingY={paddingY}
      marginTop={marginTop}
      marginBottom={marginBottom}
    >
      {children}
    </box>
  );
}
