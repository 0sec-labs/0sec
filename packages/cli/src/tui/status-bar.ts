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

import { fitTuiText } from "./text.js";

export type StatusSegmentKind =
  | "model"
  | "effort"
  | "mode"
  | "cwd"
  | "branch"
  | "dirty"
  | "tokens"
  | "context"
  | "plan";

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
  /**
   * Total context window in tokens. When omitted, NO context segment is
   * produced — the percentage must never be invented.
   */
  contextWindow?: number;
  /** Tokens currently held in context, for the percentage. */
  contextUsed?: number;
  /** Billing/plan label, e.g. "sub". Omit when unknown. */
  plan?: string;
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
  tokens: 3,
  plan: 4,
  effort: 5,
  context: 6,
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
  "context",
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

  const model = label(input.model);
  if (model) texts.set("model", model);

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

  // Both halves are required. A window with no usage reading, or a usage
  // reading with no window, cannot produce an honest percentage, and a
  // zero/negative window would produce a meaningless one.
  const contextWindow = positiveCount(input.contextWindow);
  const hasUsage = typeof input.contextUsed === "number" && Number.isFinite(input.contextUsed);
  if (contextWindow > 0 && hasUsage) {
    const used = Math.max(0, input.contextUsed as number);
    const percent = roundForDisplay((used / contextWindow) * 100);
    texts.set("context", `${percent}%/${formatTokenCount(contextWindow)}`);
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
