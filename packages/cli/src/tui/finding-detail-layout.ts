/**
 * Layout geometry and content arithmetic for the full-screen finding-detail
 * screen.
 *
 * This is `usage-layout.ts` / `model-layout.ts` for a single finding, and it
 * exists for the same reason spelled out in those files and in `PRIMITIVES.md`:
 * OpenTUI lays rows out with Yoga, and Yoga *shrinks* siblings rather than
 * clipping them. Two `<text>` nodes that together want more cells than their
 * row has are both painted in full into boxes that are now too small, and the
 * terminal shows the two strings interleaved character by character. A bordered
 * box asked to hold one row more than its column has paints its own bottom
 * border through its last line of content. So the component reads every width,
 * height, row count and column split off a `FindingDetailLayout` and never
 * computes one, and a sweep hammers every number in here across widths 0..200
 * and heights 0..80.
 *
 * ## The accuracy rule this module is built around
 *
 * Never invent a finding field. This is the same honesty rule `status-bar.ts`
 * and `usage-layout.ts` obey: a field the finding does not carry renders as an
 * em-dash, never as a plausible-looking blank or a fabricated value. Evidence
 * is only ever shown through an injected redactor, so a raw request/response
 * pasted into a finding cannot leak a bearer token onto the screen.
 *
 * ## Reuse
 *
 * `shellChromeRows` and `wrapCells` are imported from `settings-layout.ts`
 * (the same seam `usage-layout.ts` and `connect-layout.ts` use) rather than
 * re-derived: `shellChromeRows` is the corrected mirror of `run.tsx`'s shell
 * chrome height, and `wrapCells` word-wraps a string to a cell budget without
 * ever emitting a line wider than that budget.
 */

import type { Finding, Severity } from "@0sec/shared";

import { computeKvSplit } from "./pane-layout.js";
import { shellChromeRows, wrapCells } from "./settings-layout.js";
import { sanitizeTuiText } from "./text.js";

export { shellChromeRows, wrapCells };

// ---------------------------------------------------------------------------
// Numeric hygiene (mirrors usage-layout.ts / model-layout.ts)
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

/** Sanitise a caller-supplied string for the terminal. */
export function findingText(value: unknown): string {
  return sanitizeTuiText(typeof value === "string" ? value : "");
}

// ---------------------------------------------------------------------------
// Content rows
// ---------------------------------------------------------------------------

export type FindingDetailTone =
  | "title"
  | "heading"
  | "text"
  | "label"
  | "muted"
  | "accent"
  | "ok"
  | "warn"
  | "error"
  | "blank";

/**
 * One rendered row of the finding body. A discriminated union so the component
 * can render key/value rows against the layout's two-column split and heading /
 * text rows across the full inner width, while the scroll window operates over
 * one flat list.
 */
export type FindingDetailRow =
  | { kind: "blank" }
  | {
      /**
       * The strong finding header: the title paired with a severity badge on
       * one row. Rendered as a two-column line (bold title left, coloured badge
       * right), so a finding leads with its headline and its severity at a
       * glance rather than a wall of key/value rows.
       */
      kind: "header";
      title: string;
      badge: string;
      badgeTone: FindingDetailTone;
    }
  | { kind: "heading"; text: string; tone: FindingDetailTone }
  | { kind: "text"; text: string; tone: FindingDetailTone }
  | { kind: "kv"; label: string; value: string; tone: FindingDetailTone };

/** The tone a severity paints in. Red is reserved for critical/high only. */
export function severityDetailTone(severity: Severity | string | undefined): FindingDetailTone {
  switch (String(severity ?? "").toLowerCase()) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warn";
    case "low":
      return "accent";
    case "info":
      return "muted";
    default:
      return "text";
  }
}

export interface BuildFindingRowsOptions {
  /**
   * Evidence redactor. Raw request/response strings pasted into a finding are
   * passed through this before display, so a bearer token or API key never
   * reaches the screen. Defaults to identity — the caller (the screen) injects
   * `redactSensitiveHeaders` from `@0sec/core`.
   */
  redact?: (text: string) => string;
  /**
   * Pre-rendered plain CVSS line (e.g. `renderCvssSection` output with markdown
   * stripped). When absent, the line is derived from the finding's own vector
   * and score, and falls back to an em-dash when neither exists.
   */
  cvssLine?: string;
}

const EM_DASH = "—";

function pushWrapped(
  rows: FindingDetailRow[],
  value: string,
  width: number,
  tone: FindingDetailTone,
): void {
  const text = findingText(value);
  const wrapped = wrapCells(text, width);
  if (wrapped.length === 0) {
    rows.push({ kind: "text", text: EM_DASH, tone: "muted" });
    return;
  }
  for (const line of wrapped) rows.push({ kind: "text", text: line, tone });
}

/** A short, human label for the finding's location, or undefined when unknown. */
function findingLocation(finding: Finding): string | undefined {
  const annotation = finding.reviewAnnotation;
  if (annotation && typeof annotation.path === "string" && annotation.path.length > 0) {
    const start = Number.isFinite(annotation.startLine) ? annotation.startLine : undefined;
    const end = Number.isFinite(annotation.endLine as number) ? annotation.endLine : undefined;
    if (start !== undefined && end !== undefined && end !== start) {
      return `${annotation.path}:${start}-${end}`;
    }
    if (start !== undefined) return `${annotation.path}:${start}`;
    return annotation.path;
  }
  return undefined;
}

/** The evidence blob, joined from the finding's request/response/analysis. */
function findingEvidence(finding: Finding, redact: (text: string) => string): string {
  const evidence = finding.evidence;
  if (!evidence) return "";
  const parts: string[] = [];
  if (evidence.request) parts.push(`Request:\n${evidence.request}`);
  if (evidence.response) parts.push(`Response:\n${evidence.response}`);
  if (evidence.analysis) parts.push(`Analysis:\n${evidence.analysis}`);
  const joined = parts.join("\n\n");
  return joined.length > 0 ? redact(joined) : "";
}

/** The CVSS line, from the injected pre-rendered string or the finding itself. */
function findingCvssLine(finding: Finding, injected: string | undefined): string {
  if (injected && injected.trim().length > 0) return injected.trim();
  const vector = finding.cvssVector;
  const score = finding.cvssScore;
  if (vector && typeof score === "number" && Number.isFinite(score)) {
    return `${score.toFixed(1)} — ${vector}`;
  }
  if (vector) return vector;
  if (typeof score === "number" && Number.isFinite(score)) return score.toFixed(1);
  return EM_DASH;
}

/**
 * The finding body as a flat, tone-tagged row list. Content is decided here and
 * colour by the component, so the body is testable without a renderer. Every
 * missing field renders as `—` rather than a fabricated value, and evidence is
 * only ever shown through the injected redactor.
 */
export function buildFindingRows(
  finding: Finding | undefined,
  innerWidth: number,
  options: BuildFindingRowsOptions = {},
): FindingDetailRow[] {
  const width = cells(innerWidth);
  if (width <= 0) return [];
  if (!finding) {
    return [{ kind: "text", text: "No finding selected.", tone: "muted" }];
  }

  const redact = options.redact ?? ((text: string) => text);
  const rows: FindingDetailRow[] = [];
  const blank = () => rows.push({ kind: "blank" });
  const heading = (text: string) => rows.push({ kind: "heading", text, tone: "heading" });

  // Strong header: title + severity badge on one row. The severity lives in the
  // badge (red for critical/high only) rather than a key/value row, so the
  // finding leads with its headline and severity instead of a meta table.
  rows.push({
    kind: "header",
    title: findingText(finding.title || EM_DASH),
    badge: finding.severity ? String(finding.severity).toUpperCase() : EM_DASH,
    badgeTone: severityDetailTone(finding.severity),
  });
  blank();

  // Meta — key/value rows the component renders in two columns.
  rows.push({
    kind: "kv",
    label: "Category",
    value: finding.category ? findingText(finding.category) : EM_DASH,
    tone: "text",
  });
  rows.push({
    kind: "kv",
    label: "Status",
    value: finding.status ? findingText(finding.status) : EM_DASH,
    tone: "text",
  });
  if (finding.triageStatus) {
    rows.push({ kind: "kv", label: "Triage", value: findingText(finding.triageStatus), tone: "text" });
  }
  rows.push({
    kind: "kv",
    label: "Confidence",
    value:
      typeof finding.confidence === "number" && Number.isFinite(finding.confidence)
        ? `${Math.round(clamp(finding.confidence, 0, 1) * 100)}%`
        : EM_DASH,
    tone: "text",
  });

  // Location
  blank();
  heading("Location");
  pushWrapped(rows, findingLocation(finding) ?? EM_DASH, width, "text");

  // Description
  blank();
  heading("Description");
  pushWrapped(rows, finding.description || EM_DASH, width, "text");

  // Evidence (redacted)
  blank();
  heading("Evidence");
  const evidence = findingEvidence(finding, redact);
  if (evidence.length === 0) {
    rows.push({ kind: "text", text: EM_DASH, tone: "muted" });
  } else {
    for (const rawLine of evidence.split("\n")) {
      const wrapped = wrapCells(rawLine, width);
      if (wrapped.length === 0) {
        rows.push({ kind: "blank" });
        continue;
      }
      for (const line of wrapped) rows.push({ kind: "text", text: line, tone: "muted" });
    }
  }

  // Remediation
  blank();
  heading("Remediation");
  const remediation = finding.remediation;
  if (!remediation || (!remediation.summary && (remediation.steps?.length ?? 0) === 0)) {
    rows.push({ kind: "text", text: EM_DASH, tone: "muted" });
  } else {
    if (remediation.summary) pushWrapped(rows, remediation.summary, width, "text");
    for (const step of remediation.steps ?? []) {
      pushWrapped(rows, `- ${step}`, width, "text");
    }
  }

  // CVSS
  blank();
  heading("CVSS");
  pushWrapped(rows, findingCvssLine(finding, options.cvssLine), width, "text");

  // References
  blank();
  heading("References");
  const refs = [...(finding.remediation?.references ?? []), ...(finding.dedupRefs ?? [])];
  if (refs.length === 0) {
    rows.push({ kind: "text", text: EM_DASH, tone: "muted" });
  } else {
    for (const ref of refs) pushWrapped(rows, ref, width, "accent");
  }

  return rows;
}

// ---------------------------------------------------------------------------
// Scroll windowing
// ---------------------------------------------------------------------------

export interface ScrollWindowInput {
  /** Total content rows. */
  total: number;
  /** Desired top row offset. Clamped into range. */
  offset: number;
  /** Rows the body can paint. */
  visible: number;
}

export interface ScrollWindow {
  start: number;
  /** Exclusive. `rows.slice(start, end)` is exactly what may be rendered. */
  end: number;
  /** `end - start`; never exceeds `visible` and never exceeds `total`. */
  count: number;
  total: number;
  hasAbove: boolean;
  hasBelow: boolean;
}

/** The largest valid top offset for a list of `total` rows in `visible` cells. */
export function maxScrollOffset(total: number, visible: number): number {
  return Math.max(0, cells(total) - cells(visible));
}

/**
 * A plain scroll window: clamp the offset into range and slice. Unlike the
 * model picker's window this does not follow a cursor — the finding body has no
 * selection, only a scroll position the operator drives with the arrow keys.
 */
export function computeScrollWindow({ total, offset, visible }: ScrollWindowInput): ScrollWindow {
  const rowCount = cells(total);
  const capacity = Math.min(cells(visible), rowCount);
  if (capacity <= 0) {
    return { start: 0, end: 0, count: 0, total: rowCount, hasAbove: rowCount > 0, hasBelow: false };
  }
  const maxStart = Math.max(0, rowCount - capacity);
  const start = clamp(cells(offset), 0, maxStart);
  const end = Math.min(rowCount, start + capacity);
  return {
    start,
    end,
    count: end - start,
    total: rowCount,
    hasAbove: start > 0,
    hasBelow: end < rowCount,
  };
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export type FindingStatusAction = "verified" | "dismissed";

export interface FindingAction {
  /** The keybind that fires the action (single char). */
  key: string;
  /** The button label. */
  label: string;
}

export interface FindingActionsInput {
  /** Whether the Fix action is offered. */
  canFix?: boolean;
  /** Whether the Copy-report action is offered. */
  canCopy?: boolean;
  /** Whether status transitions are offered (an `onSetStatus` was wired). */
  canStatus?: boolean;
}

/**
 * The footer action buttons, in render order. The set is decided here so the
 * action-row geometry and the keyboard handler agree on how many buttons exist.
 */
export function findingActions({
  canFix = true,
  canCopy = true,
  canStatus = false,
}: FindingActionsInput = {}): FindingAction[] {
  const actions: FindingAction[] = [];
  if (canFix) actions.push({ key: "f", label: "Fix" });
  if (canCopy) actions.push({ key: "c", label: "Copy report" });
  if (canStatus) {
    actions.push({ key: "v", label: "Verify" });
    actions.push({ key: "d", label: "Dismiss" });
  }
  return actions;
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/** Below this the body pane drops its border rather than a row of content. */
const BORDERED_MIN_ROWS = 8;
/** A pane narrower than this cannot afford a border and its padding. */
const BORDERED_MIN_WIDTH = 24;
/** Below this there is no room to spend a row on the action buttons. */
const ACTION_MIN_BODY_ROWS = 3;
/** An action row narrower than this is dropped; the footer hint carries it. */
const ACTION_MIN_WIDTH = 12;
/** A key/value row splits its cells this far in favour of the value. */
const VALUE_WIDTH_SHARE = 0.6;
/** The label column never grows past this; longer labels are the value's loss. */
const LABEL_MAX_WIDTH = 12;
/** The label keeps at least this many cells before the value is allowed any. */
const LABEL_MIN_WIDTH = 6;
/** Below this a row cannot afford two columns and gives everything to the label. */
const KV_MIN_ROOM = 14;

export interface FindingDetailPane {
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

export interface FindingKvLayout {
  /** Total cells a key/value row occupies; equals the pane's inner width. */
  width: number;
  labelWidth: number;
  gap: number;
  /** Value column. 0 when the row can only afford a label. */
  valueWidth: number;
}

export interface FindingActionLayout {
  /** Total cells the action row occupies; never exceeds the content width. */
  width: number;
  /** Number of buttons the row lays out. 0 when the row is dropped. */
  count: number;
  /** Cells per button. Equal across buttons. 0 when the row is dropped. */
  cellWidth: number;
  /** Cells between adjacent buttons. */
  gap: number;
}

export interface FindingDetailLayoutInput {
  width: number;
  height: number;
  /** How many action buttons the footer offers. */
  actionCount?: number;
}

export interface FindingDetailLayout {
  /** The pane draws a border. False on a short terminal, where rows cost more. */
  bordered: boolean;
  /** Usable cells across, inside the shell's padding. */
  contentWidth: number;
  /** Rows the content column may share, after the shell has taken its chrome. */
  bodyRows: number;
  /** Rows reserved below the pane for the action buttons (0 or 1). */
  actionRows: number;
  pane: FindingDetailPane;
  kv: FindingKvLayout;
  action: FindingActionLayout;
  /** Content rows that fit in the pane's body. */
  visibleRows: number;
}

/** A bordered pane spends four columns and two rows on its border and padding. */
function borderChrome(bordered: boolean): { horizontal: number; vertical: number } {
  return bordered ? { horizontal: 4, vertical: 2 } : { horizontal: 0, vertical: 0 };
}

function makePane(width: number, height: number, chromeH: number, chromeV: number): FindingDetailPane {
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
 * Splits a key/value row into its label and value columns. Mirrors
 * `usage-layout.computeKvLayout`: every separator is a real Yoga gap, and below
 * `KV_MIN_ROOM` the row keeps the label and drops the value column, because a
 * truncated label beside a truncated value is worse than a whole label.
 */
export function computeFindingKvLayout(innerWidth: number): FindingKvLayout {
  return computeKvSplit(innerWidth, {
    minRoom: KV_MIN_ROOM,
    labelMinWidth: LABEL_MIN_WIDTH,
    labelMaxWidth: LABEL_MAX_WIDTH,
    valueWidthShare: VALUE_WIDTH_SHARE,
  });
}

/**
 * Splits the action row into `count` equal buttons with single-cell gaps.
 *
 * The gaps go first: a row that cannot afford one cell per button plus the gaps
 * between them drops the gaps, and a row that cannot afford one cell per button
 * even without gaps is dropped entirely (the footer hint still names the keys).
 * The row claims exactly `cellWidth * count + gap * (count - 1)` cells, which is
 * always `<= width`, so it can never overflow the content column.
 */
export function computeActionRow(width: number, count: number): FindingActionLayout {
  const room = cells(width);
  const buttons = cells(count);
  if (room <= 0 || buttons <= 0) return { width: 0, count: 0, cellWidth: 0, gap: 0 };
  const gaps = buttons - 1;
  const gap = gaps > 0 && room >= buttons + gaps ? 1 : 0;
  const usable = room - gap * gaps;
  const cellWidth = Math.floor(usable / buttons);
  if (cellWidth <= 0) return { width: 0, count: 0, cellWidth: 0, gap: 0 };
  const total = cellWidth * buttons + gap * gaps;
  return { width: total, count: buttons, cellWidth, gap };
}

/**
 * The full geometry of the finding-detail screen.
 *
 * One report pane fills the content column, with an action row reserved beneath
 * it when the terminal is tall and wide enough. The pane gives up its border
 * before it gives up rows of content, and is dropped entirely rather than
 * rendered at a height that would push its own border through its text.
 */
export function computeFindingDetailLayout({
  width,
  height,
  actionCount = 0,
}: FindingDetailLayoutInput): FindingDetailLayout {
  const terminalWidth = cells(width);
  // `ShellFrame` pads two cells either side of every screen.
  const contentWidth = Math.max(0, terminalWidth - 4);
  const bodyRows = Math.max(0, cells(height) - shellChromeRows(terminalWidth));

  const wantsActions = cells(actionCount) > 0;
  const actionRows =
    wantsActions && bodyRows >= ACTION_MIN_BODY_ROWS && contentWidth >= ACTION_MIN_WIDTH ? 1 : 0;
  const paneRows = Math.max(0, bodyRows - actionRows);

  const bordered = paneRows >= BORDERED_MIN_ROWS && contentWidth >= BORDERED_MIN_WIDTH;
  const chrome = borderChrome(bordered);
  const pane = makePane(contentWidth, paneRows, chrome.horizontal, chrome.vertical);

  return {
    bordered,
    contentWidth,
    bodyRows,
    actionRows,
    pane,
    kv: computeFindingKvLayout(pane.innerWidth),
    action: actionRows > 0 ? computeActionRow(contentWidth, actionCount) : { width: 0, count: 0, cellWidth: 0, gap: 0 },
    visibleRows: pane.bodyRows,
  };
}

// ---------------------------------------------------------------------------
// Titles and hints
// ---------------------------------------------------------------------------

/** The pane title, naming the finding by its id when known. */
export function findingDetailTitle(finding?: Finding): string {
  if (finding?.id) return `FINDING · ${finding.id}`;
  return "FINDING";
}

export { paneTitleColumns, type PaneTitleColumns } from "./pane-layout.js";

export interface FindingFooterHintInput {
  canFix?: boolean;
  canCopy?: boolean;
  canStatus?: boolean;
}

/** The footer hint: the keys that actually do something on this screen. */
export function findingDetailFooterHint({
  canFix = true,
  canCopy = true,
  canStatus = false,
}: FindingFooterHintInput = {}): string {
  const parts: string[] = [];
  if (canFix) parts.push("f fix");
  if (canCopy) parts.push("c copy report");
  if (canStatus) parts.push("v verify", "d dismiss");
  parts.push("↑/↓ scroll", "esc back", "ctrl+c exit");
  return parts.join(" · ");
}
