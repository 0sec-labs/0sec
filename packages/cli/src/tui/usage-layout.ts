/**
 * Layout geometry and content arithmetic for the full-screen `/usage` report.
 *
 * This is `model-layout.ts` for `/usage`, and it exists for the same reason
 * spelled out in that file and in `PRIMITIVES.md`: OpenTUI lays rows out with
 * Yoga, and Yoga *shrinks* siblings rather than clipping them. Two `<text>`
 * nodes that together want more cells than their row has are both painted in
 * full into boxes that are now too small, and the terminal shows the two
 * strings interleaved character by character. A bordered box asked to hold one
 * row more than its column has paints its own bottom border through its last
 * line of content. So the component reads every width, height, row count and
 * meter fill off a `UsageLayout` and never computes one, and a sweep hammers
 * every number in here across widths 0..200 and heights 0..80.
 *
 * ## The accuracy rule this module is built around
 *
 * Never invent a number. This is the same rule `status-bar.ts` obeys, and the
 * `/usage` screen is where it matters most: the context percentage is used to
 * decide when to compact a session, and the dollar cost is real money. A field
 * the caller did not supply renders as an em-dash, never as a plausible-looking
 * zero or a figure computed at a rate the model was not billed. `buildUsageReport`
 * emits `—` for absent tokens and `$—` for an unpriced model, and produces no
 * context meter at all unless it was given both a window and a usage reading.
 *
 * ## Reuse
 *
 * `shellChromeRows` is imported from `settings-layout.ts` (via the same barrel
 * `model-layout.ts` uses) rather than re-derived: it is the corrected mirror of
 * `run.tsx`'s shell chrome height, accounting for the footer that stacks to
 * three rows on a narrow terminal. The cost resolver mirrors the private one in
 * `status-bar.ts` — that module does not export it, and widening a file this
 * change does not own to save a dozen lines is the wrong trade (the same call
 * `model-layout.ts` makes when it re-implements `clipDetailLines`).
 */

import { MODEL_PRICING, modelProvider, type ModelRates } from "@0sec/shared";
import type { ToolHealthSummary } from "@0sec/core";

import { computeKvSplit } from "./pane-layout.js";
import { shellChromeRows } from "./settings-layout.js";
import { sanitizeTuiText } from "./text.js";

export { shellChromeRows };

// ---------------------------------------------------------------------------
// Numeric hygiene (mirrors model-layout.ts)
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

/** A finite, positive count the caller actually supplied, else 0. */
function positiveCount(value: number | undefined): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}

/** True when the caller supplied a real, finite number (0 included). */
function hasNumber(value: number | undefined): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

// ---------------------------------------------------------------------------
// Input snapshot
// ---------------------------------------------------------------------------

/** A bundle of token counts, all optional so "not tracked" reads as `—`. */
export interface UsageTokens {
  inputTokens?: number;
  outputTokens?: number;
  /** Cache-read input tokens, when the runtime tracks them. */
  cachedInputTokens?: number;
  /** Reasoning / thinking tokens, when the runtime tracks them. */
  reasoningTokens?: number;
}

/** Per-model token totals, for a session that switched model mid-run. */
export interface UsageModelTokens extends UsageTokens {
  model: string;
}

/**
 * Everything the `/usage` screen can show, all optional.
 *
 * The screen fabricates nothing: a field left `undefined` renders as an
 * em-dash, and the whole context section disappears unless both `contextUsed`
 * and `contextWindow` are present.
 */
export interface UsageSnapshot {
  /** The model the session is currently running. */
  model?: string;
  /** Provider label; derived from `model` via the pricing table when omitted. */
  provider?: string;
  /** Cumulative session token totals. */
  session?: UsageTokens;
  /** The most recent turn's token totals. */
  turn?: UsageTokens;
  /** Tokens currently held in the context window. */
  contextUsed?: number;
  /** Size of the context window, in tokens. */
  contextWindow?: number;
  /** Tool-health roll-up from the run's `ToolHealthTracker`, when there is one. */
  toolHealth?: ToolHealthSummary;
  /**
   * Per-model breakdown, when more than one model billed this session. When
   * present the cost section prices each row; when absent, the session totals
   * are priced against the active model alone.
   */
  perModel?: readonly UsageModelTokens[];
}

/**
 * The lazy default the screen reads when no snapshot is injected.
 *
 * There is no process-wide session-usage store to read from: the live counts
 * live in `chat-screen.tsx`'s component state (`sessionTokens` / `turnBudget`)
 * and reach this screen only when the chat hands them across at navigation
 * time. Until that wiring lands this returns an empty snapshot, and the screen
 * shows the model it was told about with `—` for every count — honest, and
 * never a fabricated zero. The route supplies the model it already knows.
 */
export function readCurrentUsage(): UsageSnapshot {
  return {};
}

// ---------------------------------------------------------------------------
// Formatting (mirrors status-bar.ts)
// ---------------------------------------------------------------------------

const EM_DASH = "—";

/** Round to one decimal, or to a whole number once the value reaches 100. */
function roundForDisplay(value: number): number {
  return value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
}

/**
 * Compact token counts: 999, 12.3k, 1.2M. Mirrors `status-bar.ts`'s
 * `formatTokenCount` so the two surfaces read the same number the same way.
 */
export function formatTokenCount(n: number): string {
  if (!Number.isFinite(n)) return "0";
  const value = Math.max(0, n);
  if (value < 1000) return String(Math.round(value));
  const thousands = roundForDisplay(value / 1000);
  if (thousands < 1000) return `${thousands}k`;
  return `${roundForDisplay(value / 1_000_000)}M`;
}

/** A count rendered for display, or an em-dash when it was never supplied. */
function tokenOrDash(value: number | undefined): string {
  return hasNumber(value) ? formatTokenCount(Math.max(0, value)) : EM_DASH;
}

// ── Cost (mirrors the private resolver in status-bar.ts) ────────────────────

/** Vendor prefixes shared's `normalizeModel` strips; mirrored so a
 *  "vendor/model" id resolves to the same rate row. */
const VENDOR_PREFIXES = [
  "openai/", "anthropic/", "google/", "deepseek/", "meta/", "mistral/",
  "z-ai/", "zai/", "kimi/", "moonshot/", "openrouter/", "xai/", "x-ai/",
] as const;

/**
 * Priced rate rows indexed by lower-cased id. "default" is excluded on purpose:
 * it is shared's fallback rate for an UNKNOWN model, not a model, and pricing an
 * unrecognised id at it would put a fabricated dollar figure on screen.
 */
const RATES_BY_LOWER: ReadonlyMap<string, ModelRates> = new Map(
  Object.entries(MODEL_PRICING)
    .filter(([key]) => key !== "default")
    .map(([key, rates]) => [key.toLowerCase(), rates]),
);

/**
 * Resolve a model id to its rate row, or `undefined` — the quiet, TUI-safe
 * counterpart to shared's `getRates`, which `console.warn`s on an unknown id
 * and returns the `default` row. Neither is acceptable here: the screen renders
 * inside the terminal (it must never print) and must never show a cost computed
 * at a rate the model was not billed. Resolution mirrors `getRates`: exact id,
 * then a leading "vendor/" strip, both case-insensitive.
 */
export function resolveRates(model: string | undefined): ModelRates | undefined {
  if (!model) return undefined;
  const lower = model.toLowerCase();
  const direct = RATES_BY_LOWER.get(lower);
  if (direct) return direct;
  for (const prefix of VENDOR_PREFIXES) {
    if (lower.startsWith(prefix)) return RATES_BY_LOWER.get(lower.slice(prefix.length));
  }
  return undefined;
}

/** Estimate USD spend for the usage at the given rates. Mirrors shared's
 *  `estimateCost` arithmetic exactly, but on rates we already resolved. */
export function costUsd(usage: UsageTokens, rates: ModelRates): number {
  const cachedRate = rates.cachedInput ?? rates.input;
  const input = positiveCount(usage.inputTokens);
  const output = positiveCount(usage.outputTokens);
  const cached = positiveCount(usage.cachedInputTokens);
  const uncachedInput = Math.max(0, input - cached);
  return (
    (uncachedInput / 1_000_000) * rates.input +
    (cached / 1_000_000) * cachedRate +
    (output / 1_000_000) * rates.output
  );
}

/** Render a positive cost as "$1.23", a sub-cent one as "<$0.01", zero as "$0.00". */
export function formatCost(usd: number): string {
  if (!Number.isFinite(usd) || usd <= 0) return "$0.00";
  if (usd < 0.01) return "<$0.01";
  return `$${usd.toFixed(2)}`;
}

/** Cost for one model's usage, or "$—" when the model has no known rate. */
function costOrDash(usage: UsageTokens, model: string | undefined): string {
  const rates = resolveRates(model);
  if (!rates) return "$—";
  return formatCost(costUsd(usage, rates));
}

/** Whether any token field carries a real, positive count. */
function hasAnyTokens(usage: UsageTokens | undefined): boolean {
  if (!usage) return false;
  return (
    positiveCount(usage.inputTokens) +
      positiveCount(usage.outputTokens) +
      positiveCount(usage.cachedInputTokens) +
      positiveCount(usage.reasoningTokens) >
    0
  );
}

// ---------------------------------------------------------------------------
// Report model — tone-tagged rows, decided here so the component draws no logic
// ---------------------------------------------------------------------------

export type UsageTone =
  | "title"
  | "label"
  | "value"
  | "muted"
  | "ok"
  | "warn"
  | "error"
  | "accent"
  | "blank";

export type UsageRowKind = "heading" | "kv" | "meter" | "text" | "blank";

export interface UsageReportRow {
  kind: UsageRowKind;
  /** Left column for `kv`, the whole line for `heading`/`text`. */
  label?: string;
  /** Right column for `kv`. */
  value?: string;
  tone?: UsageTone;
  /**
   * Meter fill fraction in [0, 1]. Only set for `kind === "meter"`; the caption
   * (percent + window) travels in `value`, and the bar itself is drawn by the
   * component from `usageMeterBar(fraction, layout.meter.barCells)`.
   */
  fraction?: number;
  /** The tone the caption + bar share (warn/error when over budget). */
}

/** Percentage at or above which the context reading turns red (over budget). */
export const CONTEXT_ERROR_PERCENT = 100;
/** Percentage at or above which the context reading turns amber. */
export const CONTEXT_WARN_PERCENT = 85;

function contextTone(percent: number): UsageTone {
  if (percent >= CONTEXT_ERROR_PERCENT) return "error";
  if (percent >= CONTEXT_WARN_PERCENT) return "warn";
  return "ok";
}

// ── NERD_SYMBOLS BMP icons ──────────────────────────────────────────────────
// Nerd Font glyphs are optional; adjacent text labels carry their meaning
// independently when the terminal font does not cover the Private Use Area.
const ICON_CONTEXT = "\u{e70f}";   // nf-dev-windows  → context window
const ICON_INPUT  = "\u{f090}";    // nf-fa-arrow-circle-o-left
const ICON_OUTPUT = "\u{f08b}";    // nf-fa-arrow-circle-o-right
const ICON_CACHE  = "\u{f1c0}";    // nf-fa-database
const ICON_REASON = "\u{ee9c}";    // nf-fa-brain
const ICON_COST   = "\u{f155}";    // nf-fa-dollar
const ICON_MODEL  = "\u{ec19}";    // nf-cod-symbol-class
const ICON_HOST   = "\u{f109}";    // nf-fa-laptop
const ICON_WARN   = "\u{f071}";    // nf-fa-exclamation-triangle
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The whole report as flat tone-tagged rows.
 *
 * A compact contextual inspector — no decorative section headings, no blank
 * separators, no instructional placeholders. Every real count is shown with an
 * icon-prefixed label; unknown fields still render as an em-dash. The context
 * meter (bar + percent) is the only visual flourish and only when both window
 * and used are supplied. Tool-health issues are listed when present; the
 * section is omitted entirely when there are none.
 */
export function buildUsageReport(snapshot: UsageSnapshot = {}): UsageReportRow[] {
  const rows: UsageReportRow[] = [];
  const kv = (label: string, value: string, tone: UsageTone = "value") =>
    rows.push({ kind: "kv", label, value, tone });
  const text = (label: string, tone: UsageTone = "muted") => rows.push({ kind: "text", label, tone });

  const session = snapshot.session;
  const turn = snapshot.turn;
  const both = (
    label: string,
    pick: (u: UsageTokens | undefined) => number | undefined,
  ) => {
    const turnText = tokenOrDash(pick(turn));
    const sessionText = tokenOrDash(pick(session));
    kv(label, `${turnText} / ${sessionText}`);
  };

  // ── Context ──────────────────────────────────────────────────────────────
  const window = positiveCount(snapshot.contextWindow);
  const usedGiven = hasNumber(snapshot.contextUsed);
  if (window > 0 && usedGiven) {
    const used = Math.max(0, snapshot.contextUsed as number);
    const percent = roundForDisplay((used / window) * 100);
    const fraction = Math.max(0, Math.min(1, used / window));
    const caption = `${percent}% · ${formatTokenCount(used)} / ${formatTokenCount(window)}`;
    rows.push({ kind: "meter", value: caption, fraction, tone: contextTone(percent) });
  } else {
    kv(`${ICON_CONTEXT} window`, tokenOrDash(snapshot.contextWindow), "muted");
    kv(`${ICON_CONTEXT} used`, tokenOrDash(snapshot.contextUsed), "muted");
  }

  // ── Tokens ─────────────────────────────────────────────────────────────
  kv("tokens", "turn / session", "muted");
  both(`${ICON_INPUT} input`, (u) => u?.inputTokens);
  both(`${ICON_OUTPUT} output`, (u) => u?.outputTokens);
  both(`${ICON_CACHE} cached`, (u) => u?.cachedInputTokens);
  if (hasNumber(session?.reasoningTokens) || hasNumber(turn?.reasoningTokens)) {
    both(`${ICON_REASON} reasoning`, (u) => u?.reasoningTokens);
  }

  // ── Cost ─────────────────────────────────────────────────────────────────
  text("Estimated model cost");
  const perModel = (snapshot.perModel ?? []).filter((entry) => entry && entry.model);
  if (perModel.length > 0) {
    let allPriced = true;
    let total = 0;
    for (const entry of perModel) {
      const rates = resolveRates(entry.model);
      if (rates) total += costUsd(entry, rates);
      else allPriced = false;
      kv(`${ICON_COST} ${entry.model}`, costOrDash(entry, entry.model), rates ? "value" : "muted");
    }
    kv(`${ICON_COST} total`, allPriced ? formatCost(total) : "$—", allPriced ? "accent" : "muted");
  } else if (hasAnyTokens(session)) {
    const priced = Boolean(resolveRates(snapshot.model));
    kv(`${ICON_COST} session`, costOrDash(session ?? {}, snapshot.model), priced ? "accent" : "muted");
  } else {
    kv(`${ICON_COST} session`, "$—", "muted");
  }

  // ── Model ──────────────────────────────────────────────────────────────
  const model = typeof snapshot.model === "string" ? snapshot.model.trim() : "";
  if (model) {
    kv(`${ICON_MODEL} model`, model);
    const provider =
      (typeof snapshot.provider === "string" && snapshot.provider.trim()) || modelProvider(model);
    kv(`${ICON_HOST} provider`, provider, "muted");
  } else {
    kv(`${ICON_MODEL} model`, EM_DASH, "muted");
  }

  // ── Tool health (only when there are issues) ─────────────────────────
  const health = snapshot.toolHealth;
  if (health && health.total > 0) {
    text(`${ICON_WARN} ${health.line || `${health.total} tool issue${health.total === 1 ? "" : "s"}`}`, "warn");
    for (const event of health.events.slice(0, 6)) {
      const suffix = event.count > 1 ? ` (x${event.count})` : "";
      kv(`${event.tool}`, `${event.category}${suffix}`, "muted");
    }
  }

  return rows;
}

// ---------------------------------------------------------------------------
// Meter (mirrors the bottom-bar meter in status-bar.ts)
// ---------------------------------------------------------------------------

const METER_FILLED = "▰";
const METER_EMPTY = "▱";

/**
 * A unicode fill bar of exactly `cells` characters for a fraction in [0, 1].
 *
 * The fill is clamped so a rounding artefact can never paint one cell too many
 * or a negative one, and the returned string is always exactly `cells` long, so
 * the caller can hand it straight to a `Cells` of the same width without it
 * over- or under-running its box.
 */
export function usageMeterBar(fraction: number, cellCount: number): string {
  const width = cells(cellCount);
  if (width <= 0) return "";
  const clamped = Number.isFinite(fraction) ? Math.max(0, Math.min(1, fraction)) : 0;
  const filled = Math.max(0, Math.min(width, Math.round(clamped * width)));
  return METER_FILLED.repeat(filled) + METER_EMPTY.repeat(width - filled);
}


// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/** Below this the report pane drops its border rather than a row of content. */
const BORDERED_MIN_ROWS = 10;
/** A pane narrower than this cannot afford a border and its padding. */
const BORDERED_MIN_WIDTH = 24;
/** A key/value row splits its cells this far in favour of the value. */
const VALUE_WIDTH_SHARE = 0.5;
/** The label column never grows past this; longer labels are the value's loss. */
const LABEL_MAX_WIDTH = 18;
/** The label keeps at least this many cells before the value is allowed any. */
const LABEL_MIN_WIDTH = 6;
/** Below this a row cannot afford two columns and gives everything to the label. */
const KV_MIN_ROOM = 14;
/** Widest the context bar ever gets; past this it is just a longer bar. */
const METER_MAX_CELLS = 24;
/** Share of a row the bar may take, leaving the rest for its caption. */
const METER_WIDTH_SHARE = 0.45;
/** Below this a meter row drops the bar and shows the caption alone. */
const METER_MIN_ROOM = 20;

export interface UsagePane {
  /** Outer cells, borders included. 0 when the pane is not rendered. */
  width: number;
  /** Cells available to text inside the pane. */
  innerWidth: number;
  /** Outer rows, borders included. 0 when the pane is not rendered. */
  height: number;
  /** Rows available to report content inside the border. */
  bodyRows: number;
}

export interface UsageKvLayout {
  /** Total cells a key/value row occupies; equals the pane's inner width. */
  width: number;
  labelWidth: number;
  gap: number;
  /** Value column. 0 when the row can only afford a label. */
  valueWidth: number;
}

export interface UsageMeterLayout {
  /** Total cells a meter row occupies; equals the pane's inner width. */
  width: number;
  /** The fill bar. 0 when the row can only afford a caption. */
  barCells: number;
  gap: number;
  /** The percent + window caption. */
  captionWidth: number;
}

export interface UsageLayoutInput {
  width: number;
  height: number;
}

export interface UsageLayout {
  /** The pane draws a border. False on a short terminal, where rows cost more. */
  bordered: boolean;
  /** Usable cells across, inside the shell's padding. */
  contentWidth: number;
  /** Rows the report body may share, after the shell has taken its chrome. */
  bodyRows: number;
  pane: UsagePane;
  kv: UsageKvLayout;
  meter: UsageMeterLayout;
  /** Report rows that fit in the pane's body. */
  visibleRows: number;
}

/** A bordered pane spends four columns and two rows on its border and padding. */
function borderChrome(bordered: boolean): { horizontal: number; vertical: number } {
  return bordered ? { horizontal: 4, vertical: 2 } : { horizontal: 0, vertical: 0 };
}

function makePane(width: number, height: number, chromeH: number, chromeV: number): UsagePane {
  const outerWidth = cells(width);
  const outerHeight = cells(height);
  if (outerWidth <= chromeH || outerHeight <= chromeV) {
    return { width: 0, innerWidth: 0, height: 0, bodyRows: 0 };
  }
  return {
    width: outerWidth,
    innerWidth: outerWidth - chromeH,
    height: outerHeight,
    bodyRows: outerHeight - chromeV,
  };
}

/**
 * Splits a key/value row into its label and value columns.
 *
 * Every separator is a real Yoga gap rather than a padded literal, because
 * `fitCells` routes through `sanitizeTuiText`, which trims — a label carrying
 * its own trailing space comes back without one and fuses onto its value. Below
 * `KV_MIN_ROOM` the row keeps the label and drops the value column, because a
 * truncated label beside a truncated value is worse than a whole label with the
 * value one row down (the report never actually asks for that, but the geometry
 * must stay honest for the sweep).
 */
export function computeKvLayout(innerWidth: number): UsageKvLayout {
  return computeKvSplit(innerWidth, {
    minRoom: KV_MIN_ROOM,
    labelMinWidth: LABEL_MIN_WIDTH,
    labelMaxWidth: LABEL_MAX_WIDTH,
    valueWidthShare: VALUE_WIDTH_SHARE,
  });
}

/**
 * Splits a meter row into its fill bar and caption.
 *
 * The bar is the first thing to go: below `METER_MIN_ROOM` a bar is a stub that
 * says nothing the caption does not, so the row spends every cell on the
 * `42% · 12.3k / 200k` caption instead.
 */
export function computeMeterLayout(innerWidth: number): UsageMeterLayout {
  const width = cells(innerWidth);
  if (width <= 0) return { width: 0, barCells: 0, gap: 0, captionWidth: 0 };
  const barCells =
    width >= METER_MIN_ROOM
      ? Math.min(METER_MAX_CELLS, Math.floor(width * METER_WIDTH_SHARE))
      : 0;
  const gap = barCells > 0 && width > barCells ? 1 : 0;
  const captionWidth = Math.max(0, width - barCells - gap);
  return { width, barCells, gap, captionWidth };
}

/**
 * The full geometry of the usage screen.
 *
 * One report pane fills the content column. It gives up its border before it
 * gives up rows of content, and it is dropped entirely rather than rendered at
 * a height that would push its own border through its text.
 */
export function computeUsageLayout({ width, height }: UsageLayoutInput): UsageLayout {
  const terminalWidth = cells(width);
  // `ShellFrame` pads two cells either side of every screen.
  const contentWidth = Math.max(0, terminalWidth - 4);
  const bodyRows = Math.max(0, cells(height) - shellChromeRows(terminalWidth));

  const bordered = bodyRows >= BORDERED_MIN_ROWS && contentWidth >= BORDERED_MIN_WIDTH;
  const chrome = borderChrome(bordered);
  const pane = makePane(contentWidth, bodyRows, chrome.horizontal, chrome.vertical);

  return {
    bordered,
    contentWidth,
    bodyRows,
    pane,
    kv: computeKvLayout(pane.innerWidth),
    meter: computeMeterLayout(pane.innerWidth),
    visibleRows: pane.bodyRows,
  };
}

// ---------------------------------------------------------------------------
// Clipping and hints
// ---------------------------------------------------------------------------

/**
 * Trims report rows to the rows the pane actually has, marking the cut.
 *
 * Rendering more rows than the box holds is what pushes a border through the
 * content, so the overflow is cut — but the last surviving row is replaced with
 * a marker rather than dropped silently, because a report that stops mid-section
 * with no sign it was truncated reads as a crash.
 */
export function clipUsageRows(rows: readonly UsageReportRow[], visible: number): UsageReportRow[] {
  const limit = cells(visible);
  if (limit <= 0) return [];
  if (rows.length <= limit) return [...rows];
  const kept = rows.slice(0, limit);
  const hidden = rows.length - limit + 1;
  kept[limit - 1] = { kind: "text", label: `… ${hidden} more`, tone: "muted" };
  return kept;
}

/** The footer hint: contextual inspector — read-only, keys are few. */
export function usageFooterHint(): string {
  return ["esc back", "ctrl+c exit"].join(" · ");
}

