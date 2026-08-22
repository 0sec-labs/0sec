/**
 * Data model for the single-line TUI status bar.
 *
 * The bar we are reproducing looks like this:
 *
 *     GPT-5.6-Terra · max   ~/coding/0sec-labs/0sec   publish/main-integration *54 ?29   1.4%/1M  (sub)
 *
 * Everything here is pure: segments in, string out. The renderer owns the
 * colours, the grouping and the cell allocation, because those are the parts
 * that depend on OpenTUI. Keeping the *content* decisions on this side means
 * the two rules that actually matter — "never invent a number" and "never
 * claim more columns than the terminal has" — are unit tests rather than
 * something to eyeball in a screenshot.
 *
 * Two of those rules are worth stating outright:
 *
 *  - A context percentage is only shown when the caller supplied both the
 *    window size and the tokens currently held in it. A status bar that
 *    guesses a context figure is worse than one that shows nothing: the
 *    number is used to decide when to compact a session, so a fabricated
 *    one costs the user real work.
 *  - The returned line is *always* within the given width, including the
 *    degenerate case where a single segment is wider than the terminal. A
 *    row that overflows in OpenTUI does not clip, it overprints its
 *    siblings (see chat-layout.ts), so "too long" is a corruption bug and
 *    not a cosmetic one.
 */

import { MODEL_PRICING, type ModelRates, type TokenUsageForPricing } from "@0sec/shared";

import { fitTuiText } from "./text.js";

export type StatusSegmentKind =
  | "model"
  | "effort"
  | "mode"
  | "cwd"
  | "branch"
  | "dirty"
  | "tokens"
  | "cost"
  | "context"
  | "meter"
  | "plan";

/** Where the model name is surfaced. Mirrors `TuiSettings["modelDisplay"]`; the
 *  bar shows the model only for "statusbar" (and for `undefined`, the pre-setting
 *  default), and drops it for "message" (chat-screen draws it) and "off". */
export type ModelDisplay = "statusbar" | "message" | "off";

export interface StatusSegment {
  kind: StatusSegmentKind;
  text: string;
  /** Lower drops first when the bar does not fit. 0 = never drop. */
  priority: number;
}

export interface StatusBarInput {
  model?: string;
  /** Reasoning effort, e.g. "max". Omit when unknown. */
  effort?: string;
  /** Autonomy mode label already humanized, e.g. "Standard". */
  mode?: string;
  cwd?: string;
  /** Home directory, used to abbreviate cwd to a leading "~". */
  home?: string;
  branch?: string | null;
  modified?: number;
  untracked?: number;
  /** Cumulative session tokens. */
  inputTokens?: number;
  outputTokens?: number;
  /** Cumulative cached-input tokens, for a more accurate cost estimate. */
  cachedInputTokens?: number;
  /**
   * Total context window in tokens. When omitted, NO context segment is
   * produced — the percentage must never be invented.
   */
  contextWindow?: number;
  /** Tokens currently held in context, for the percentage. */
  contextUsed?: number;
  /** Billing/plan label, e.g. "sub". Omit when unknown. */
  plan?: string;
  /**
   * Where to surface the model name. Optional so existing callers (chat-screen
   * is mid-edit by the coordinator) keep the pre-setting default of showing it
   * in the bar; the coordinator passes the operator's `modelDisplay` later.
   */
  modelDisplay?: ModelDisplay;
  /**
   * Replace the plain "N%/window" context segment with a visual meter
   * (`▰▰▰▱▱▱ 42% of 1M`). Optional and off by default, so the existing bar is
   * unchanged until the coordinator wires the `showContextMeter` setting.
   */
  showContextMeter?: boolean;
  /**
   * Add an estimated dollar-cost segment computed from the session tokens and
   * the model's rate. Optional and off by default. When the model's rate is
   * unknown the segment shows "$—" rather than a figure at a rate the model was
   * not billed — the same "never invent a number" rule the context percent obeys.
   */
  showCost?: boolean;
}

/**
 * Drop order, lowest first. 0 is reserved for "never drop".
 *
 * The ranking answers one question: at 40 columns, what is still worth a
 * cell? The model and the autonomy mode are the two facts that change what
 * happens when the user presses enter, so they survive longest — mode
 * especially, because not knowing you are in an auto-approving mode is a
 * safety problem, not an inconvenience. The identity of the model is the
 * single thing the bar exists to show, so it alone is undroppable and is
 * truncated instead.
 *
 * At the other end, the cwd is the cheapest thing to lose: it is the
 * longest segment by far and the user's terminal title, shell prompt and
 * own memory all carry the same information. The dirty counts go next as
 * detail hanging off the branch — the branch name without its counts still
 * reads correctly, the counts without the branch do not.
 */
const PRIORITY: Record<StatusSegmentKind, number> = {
  cwd: 1,
  dirty: 2,
  // Cost sits in the token band — it is the same session-usage telemetry — and
  // drops just before the raw token counts (ties break rightward, and `cost`
  // follows `tokens` in ORDER).
  cost: 3,
  tokens: 3,
  plan: 4,
  effort: 5,
  // The meter is the visual form of `context` and is never emitted alongside
  // it, so it shares that band: dropped as readily as the plain percent was.
  context: 6,
  meter: 6,
  branch: 7,
  mode: 8,
  model: 0,
};

/** Segment order on screen, independent of drop priority. */
const ORDER: StatusSegmentKind[] = [
  "model",
  "effort",
  "mode",
  "cwd",
  "branch",
  "dirty",
  "tokens",
  "cost",
  "context",
  "meter",
  "plan",
];

const DEFAULT_SEPARATOR = " · ";

/**
 * Replace a leading home directory with "~".
 *
 * The comparison is on whole path components, never on raw characters: a
 * naive `startsWith(home)` turns `/home/developer/x` into `~eloper/x` for
 * the user whose home is `/home/dev`, which is both wrong and impossible to
 * notice at a glance in a status bar.
 */
export function abbreviateHomePath(path: string, home?: string): string {
  if (!path) return "";
  if (!home) return path;

  // A trailing slash on the home value is a caller artefact, not a
  // different directory; "/" itself is dropped because rewriting the
  // filesystem root to "~" would shorten nothing and mislead.
  const base = home.length > 1 && home.endsWith("/") ? home.slice(0, -1) : home;
  if (base === "/" || base.length === 0) return path;

  if (path === base) return "~";
  if (path.startsWith(`${base}/`)) return `~${path.slice(base.length)}`;
  return path;
}

/** Round to one decimal, or to a whole number once the value reaches 100. */
function roundForDisplay(value: number): number {
  return value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
}

/**
 * Compact token counts: 999, 12.3k, 1.2M.
 *
 * Rounding is applied before the unit is chosen, so 999_999 reads as "1M"
 * rather than the technically-correct but jarring "1000k".
 */
export function formatTokenCount(n: number): string {
  if (!Number.isFinite(n)) return "0";
  const value = Math.max(0, n);
  if (value < 1000) return String(Math.round(value));

  const thousands = roundForDisplay(value / 1000);
  if (thousands < 1000) return `${thousands}k`;
  return `${roundForDisplay(value / 1_000_000)}M`;
}

/** A finite, positive number the caller actually supplied. */
function positiveCount(value: number | undefined): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}

/** A non-empty label the caller actually supplied. */
function label(value: string | null | undefined): string {
  return typeof value === "string" ? value.trim() : "";
}

// ── Context meter ─────────────────────────────────────────────────────────

/** Cells in the visual context bar; matches the `▰▰▰▱▱▱` reference width. */
const METER_CELLS = 6;
const METER_FILLED = "▰";
const METER_EMPTY = "▱";

/**
 * A compact unicode usage bar plus the percent and window, e.g.
 * `▰▰▰▱▱▱ 42% of 1M`. The fill is clamped to [0, METER_CELLS] so a rounding
 * artefact can never paint a seventh cell or a negative one. The renderer picks
 * the colour off the `meter` segment kind, matching the existing pattern.
 */
function contextMeter(percent: number, contextWindow: number): string {
  const fraction = Math.max(0, Math.min(1, percent / 100));
  const filled = Math.max(0, Math.min(METER_CELLS, Math.round(fraction * METER_CELLS)));
  const bar = METER_FILLED.repeat(filled) + METER_EMPTY.repeat(METER_CELLS - filled);
  return `${bar} ${percent}% of ${formatTokenCount(contextWindow)}`;
}

// ── Cost ──────────────────────────────────────────────────────────────────

/** Vendor prefixes shared's `normalizeModel` strips; mirrored here so a
 *  "vendor/model" id resolves to the same rate row. */
const VENDOR_PREFIXES = [
  "openai/", "anthropic/", "google/", "deepseek/", "meta/", "mistral/",
  "z-ai/", "zai/", "kimi/", "moonshot/", "openrouter/", "xai/", "x-ai/",
] as const;

/**
 * Priced rate rows indexed by lower-cased id. "default" is deliberately
 * excluded: it is shared's fallback rate for an UNKNOWN model, not a model, and
 * pricing an unrecognised id at it would put a fabricated dollar figure on
 * screen. Lower-casing lets a differently-cased id (e.g. "GPT-5.6-Terra") or an
 * Azure deployment name still find its row.
 */
const RATES_BY_LOWER: ReadonlyMap<string, ModelRates> = new Map(
  Object.entries(MODEL_PRICING)
    .filter(([key]) => key !== "default")
    .map(([key, rates]) => [key.toLowerCase(), rates]),
);

/**
 * Resolve a model id to its rate row, or `undefined` — the quiet, TUI-safe
 * counterpart to shared's `getRates`. `getRates` `console.warn`s on an unknown
 * id and then returns the `default` row; neither is acceptable in the status
 * bar, which renders inside the terminal (it must never print) and must never
 * show a cost computed at a rate the model was not billed. Resolution mirrors
 * `getRates`: exact id, then a leading "vendor/" strip, both case-insensitive.
 */
function resolveRates(model: string): ModelRates | undefined {
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
function costUsd(usage: TokenUsageForPricing, rates: ModelRates): number {
  const cachedRate = rates.cachedInput ?? rates.input;
  const cached = usage.cachedInputTokens ?? 0;
  const uncachedInput = Math.max(0, usage.inputTokens - cached);
  return (
    (uncachedInput / 1_000_000) * rates.input +
    (cached / 1_000_000) * cachedRate +
    (usage.outputTokens / 1_000_000) * rates.output
  );
}

/** Render a positive cost as "$1.23", a sub-cent one as "<$0.01". */
function formatCost(usd: number): string {
  if (!Number.isFinite(usd) || usd <= 0) return "$0.00";
  if (usd < 0.01) return "<$0.01";
  return `$${usd.toFixed(2)}`;
}

function dirtyText(modified: number, untracked: number): string {
  const parts: string[] = [];
  if (modified > 0) parts.push(`*${modified}`);
  if (untracked > 0) parts.push(`?${untracked}`);
  return parts.join(" ");
}

/**
 * Build the ordered segment list, emitting nothing for absent data.
 *
 * Every branch here is a presence check rather than a default: a bar that
 * renders "0/0" tokens or a "main" branch it never read is indistinguishable
 * from a bar reporting the truth, which makes the whole line untrustworthy.
 */
export function buildStatusSegments(input: StatusBarInput): StatusSegment[] {
  const texts = new Map<StatusSegmentKind, string>();

  // The model is kept for pricing regardless of where it is displayed, but it
  // only occupies a bar segment when `modelDisplay` is "statusbar" (or is
  // unset — the pre-setting default). "message"/"off" drop it from the bar.
  const model = label(input.model);
  const modelDisplay = input.modelDisplay ?? "statusbar";
  if (model && modelDisplay === "statusbar") texts.set("model", model);

  const effort = label(input.effort);
  if (effort) texts.set("effort", effort);

  const mode = label(input.mode);
  if (mode) texts.set("mode", mode);

  const cwd = label(input.cwd);
  if (cwd) texts.set("cwd", abbreviateHomePath(cwd, input.home));

  const branch = label(input.branch);
  if (branch) texts.set("branch", branch);

  const dirty = dirtyText(positiveCount(input.modified), positiveCount(input.untracked));
  if (dirty) texts.set("dirty", dirty);

  // Session totals are cumulative, so "nothing yet" and "not tracked" both
  // arrive as zero and both mean the same thing on screen: show nothing.
  const inputTokens = positiveCount(input.inputTokens);
  const outputTokens = positiveCount(input.outputTokens);
  if (inputTokens + outputTokens > 0) {
    // "in/out", matching the counter the sidebar already renders.
    texts.set("tokens", `${formatTokenCount(inputTokens)}/${formatTokenCount(outputTokens)}`);
  }

  // Cost is opt-in and needs real usage. When the model's rate is unknown we
  // show "$—" rather than a figure computed at the fallback rate — an honest
  // "no rate" instead of a plausible-looking lie, the same rule the context
  // percentage obeys.
  if (input.showCost && inputTokens + outputTokens > 0) {
    const rates = model ? resolveRates(model) : undefined;
    texts.set(
      "cost",
      rates
        ? formatCost(
            costUsd(
              {
                inputTokens,
                outputTokens,
                cachedInputTokens: positiveCount(input.cachedInputTokens),
              },
              rates,
            ),
          )
        : "$—",
    );
  }

  // Both halves are required. A window with no usage reading, or a usage
  // reading with no window, cannot produce an honest percentage, and a
  // zero/negative window would produce a meaningless one. When the operator
  // enabled the meter, the same figure renders as a visual bar instead of the
  // plain percent (the two are mutually exclusive, never both).
  const contextWindow = positiveCount(input.contextWindow);
  const hasUsage = typeof input.contextUsed === "number" && Number.isFinite(input.contextUsed);
  if (contextWindow > 0 && hasUsage) {
    const used = Math.max(0, input.contextUsed as number);
    const percent = roundForDisplay((used / contextWindow) * 100);
    if (input.showContextMeter) {
      texts.set("meter", contextMeter(percent, contextWindow));
    } else {
      texts.set("context", `${percent}%/${formatTokenCount(contextWindow)}`);
    }
  }

  const plan = label(input.plan);
  if (plan) texts.set("plan", `(${plan})`);

  const segments: StatusSegment[] = [];
  for (const kind of ORDER) {
    const text = texts.get(kind);
    if (text) segments.push({ kind, text, priority: PRIORITY[kind] });
  }
  return segments;
}

/**
 * Index of the next segment to sacrifice, or -1 when none may be dropped.
 *
 * Ties break towards the right-hand side: segments are ordered by
 * importance-to-context left to right within a priority band, so when two
 * are equally droppable the later one is the more incidental of the pair.
 */
function nextVictim(segments: StatusSegment[]): number {
  let victim = -1;
  let lowest = Number.POSITIVE_INFINITY;
  for (let i = 0; i < segments.length; i += 1) {
    const priority = segments[i].priority;
    if (priority <= 0) continue;
    if (priority <= lowest) {
      lowest = priority;
      victim = i;
    }
  }
  return victim;
}

/**
 * Join the segments, shedding the least important ones until they fit.
 *
 * The final `fitTuiText` is the guarantee, not the optimisation: once every
 * droppable segment is gone the remainder may still be too wide, and at that
 * point an ellipsis is the only way to honour the width contract.
 */
export function fitStatusSegments(
  segments: StatusSegment[],
  width: number,
  separator: string = DEFAULT_SEPARATOR,
): string {
  if (!Number.isFinite(width) || width <= 0) return "";

  const remaining = segments.filter((segment) => segment.text.length > 0);
  const join = (list: StatusSegment[]): string => list.map((s) => s.text).join(separator);

  while (remaining.length > 0) {
    const line = join(remaining);
    if (line.length <= width) return line;

    const victim = nextVictim(remaining);
    if (victim < 0) break;
    remaining.splice(victim, 1);
  }

  return fitTuiText(join(remaining), Math.floor(width));
}
