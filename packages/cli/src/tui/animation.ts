/**
 * Busy-state animation frames for the operator console.
 *
 * This module is deliberately *pure*: `frameAt` is a total function of the
 * animation kind and the elapsed milliseconds the caller measured. Nothing
 * in here reads a clock, sets a timer, or prints — the React layer owns the
 * ticker and the paint, this file owns what a frame looks like. That split
 * is what makes the motion testable at all: a spinner that calls
 * `Date.now()` internally can only be checked by sleeping.
 *
 * Two invariants hold for every frame of every kind, in both glyph sets,
 * and the test file pins them:
 *
 *   1. Every frame is exactly `GLYPH_CELLS` terminal cells wide. Not "about"
 *      three — exactly three, using code points that are unambiguously
 *      single-width. A frame that renders one cell wider than its neighbour
 *      makes the whole line jitter, and inside a bordered row it pushes the
 *      right border off the grid and corrupts the frame. Width is guaranteed
 *      structurally: the only code points allowed in a frame are printable
 *      ASCII (U+0020..U+007E) and Braille Patterns (U+2800..U+28FF), and both
 *      ranges are East_Asian_Width=Na/N, i.e. one cell everywhere.
 *   2. The unicode and ASCII sets for a kind have the same frame *count*, so
 *      the cycle period does not depend on which set is active — the caller
 *      picks one ticker interval per kind and gets the same rhythm either way.
 *
 * Braille (U+2800..U+28FF) is the workhorse here because it is the only
 * block that gives sub-cell resolution — two columns and three rows inside a
 * single cell — while staying narrow in every terminal. It also gives us a
 * *blank* that is not a space: U+2800 BRAILLE PATTERN BLANK. That matters,
 * because a frame like "⠀⠤⠀" survives a trim or a `\s+ -> " "` collapse
 * unchanged, whereas " ⠤ " would not. The ASCII fallback avoids spaces for
 * the same reason and paints its unlit cells with a visible rail character.
 */

/** Terminal cells occupied by every frame of every kind. */
export const GLYPH_CELLS = 3;

/** Elapsed is hidden below this, so short turns do not flicker a counter. */
export const ELAPSED_VISIBLE_AFTER_MS = 3_000;

/** Elapsed is clamped here so the label can never grow past "99h59m". */
const MAX_ELAPSED_MS = 359_999_000;

/** A rogue tool name must not be allowed to blow out the status line. */
const MAX_LABEL_CHARS = 48;

export type AnimationKind =
  | "connecting"
  | "thinking"
  | "streaming"
  | "tool"
  | "awaiting-operator";

export const ANIMATION_KINDS: readonly AnimationKind[] = [
  "connecting",
  "thinking",
  "streaming",
  "tool",
  "awaiting-operator",
];

export interface AnimationFrame {
  /** Exactly GLYPH_CELLS cells wide. Render verbatim — do not trim or fit. */
  glyph: string;
  /** Short lower-case state word, or the caller's override (e.g. a tool name). */
  label: string;
  /** Compact elapsed ("9s", "1m04s"); omitted below ELAPSED_VISIBLE_AFTER_MS. */
  elapsedLabel?: string;
}

export interface AnimationOptions {
  /** Use the ASCII-only glyph set for terminals we cannot trust with braille. */
  ascii?: boolean;
  /** false -> the kind's frame 0, forever. Motion sensitivity, and CPU. */
  motion?: boolean;
  /** Replace the default label, e.g. with the running tool's name. */
  label?: string;
}

interface AnimationSpec {
  label: string;
  intervalMs: number;
  unicode: readonly string[];
  ascii: readonly string[];
}

/**
 * Frame tables.
 *
 * Each `intervalMs` is capped at 100ms (10 Hz). Above that the repaint cost
 * in a scrollback-heavy TUI stops being free and the motion stops reading as
 * motion — it reads as noise.
 */
const SPECS: Record<AnimationKind, AnimationSpec> = {
  /**
   * Connecting: a ping. The core flashes and a ripple travels outward, then
   * it starts over — repeated outbound attempts, which is exactly what
   * "bringing the runtime up" is. Not a sweep and not a rotation, so it can
   * never be mistaken for work in progress. 4 frames * 150ms = 600ms.
   */
  connecting: {
    label: "connecting",
    intervalMs: 150,
    unicode: ["⠀⠶⠀", "⠀⠒⠀", "⠐⠀⠂", "⠂⠀⠐"],
    ascii: [".O.", ".o.", "(.)", "<.>"],
  },
  /**
   * Thinking: a balance beam rocking. Six braille sub-columns form a beam
   * that tilts one way and then the other, centre steady. It is symmetric
   * and goes nowhere — deliberation, weighing, no direction of travel and
   * therefore no implied progress toward a finish line. This is the longest
   * wait, so it is also the slowest of the busy cycles: 8 frames * 140ms =
   * 1120ms, roughly one calm breath.
   */
  thinking: {
    label: "thinking",
    intervalMs: 140,
    unicode: ["⠠⠴⠾", "⠤⠴⠶", "⠶⠶⠶", "⠶⠦⠤", "⠷⠦⠄", "⠶⠦⠤", "⠶⠶⠶", "⠤⠴⠶"],
    ascii: ['_-"', "_--", "---", "--_", '"-_', "--_", "---", "_--"],
  },
  /**
   * Streaming: flow. Two lit dots on the *bottom* row only, marching left to
   * right through six sub-columns and wrapping. Low, fast and directional —
   * output pouring in, as opposed to the beam's stationary rocking. Fastest
   * of the set at the 10 Hz cap: 6 frames * 100ms = 600ms per traversal.
   */
  streaming: {
    label: "responding",
    intervalMs: 100,
    unicode: ["⠤⠀⠀", "⠠⠄⠀", "⠀⠤⠀", "⠀⠠⠄", "⠀⠀⠤", "⠄⠀⠠"],
    ascii: ["o--", "-o-", "--o", "O--", "-O-", "--O"],
  },
  /**
   * Tool: rotation, centred. A three-dot arc orbiting one braille cell — the
   * classic spinner, kept because rotation is the one motion every operator
   * already reads as "a machine is turning". Distinct from thinking (which
   * never rotates) and from streaming (which never stays put). 6 frames *
   * 120ms = 720ms per revolution.
   */
  tool: {
    label: "running tool",
    intervalMs: 120,
    unicode: ["⠀⠙⠀", "⠀⠸⠀", "⠀⠴⠀", "⠀⠦⠀", "⠀⠇⠀", "⠀⠋⠀"],
    ascii: ["'..", ".'.", "..'", ".._", "._.", "_.."],
  },
  /**
   * Awaiting operator: not busy. The bottleneck is the human, so this must
   * not look like the machine is straining. Two frames, no travel and no
   * rotation — a low line lifting slightly and settling, like an idle cursor
   * breathing. At 700ms per frame it is ~0.7 Hz, an order of magnitude below
   * the busy cycles, which is what carries the "we are waiting on you"
   * reading. Shares no frame string with any busy kind, by construction.
   */
  "awaiting-operator": {
    label: "waiting for you",
    intervalMs: 700,
    unicode: ["⠤⠤⠤", "⠒⠒⠒"],
    ascii: ["...", ":::"],
  },
};

function specFor(kind: AnimationKind): AnimationSpec {
  // Defensive: JS callers and deserialized state can hand us anything, and a
  // console that throws while rendering a spinner is worse than one that
  // shows the wrong spinner.
  return SPECS[kind] ?? SPECS.thinking;
}

/**
 * Labels can come from the model (a tool name), so they are cleaned here
 * rather than trusted. Kept local instead of reusing `sanitizeTuiText` so
 * this module stays dependency-free and its tests cannot be broken by an
 * unrelated change to text fitting.
 */
function sanitizeLabel(value: string): string {
  const cleaned = value
    // eslint-disable-next-line no-control-regex
    .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
    // eslint-disable-next-line no-control-regex
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x1f\x7f]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned.length > MAX_LABEL_CHARS ? cleaned.slice(0, MAX_LABEL_CHARS).trim() : cleaned;
}

/** Elapsed milliseconds, coerced into the finite, non-negative, clamped range. */
function normalizeElapsed(elapsedMs: number): number {
  if (!Number.isFinite(elapsedMs)) return 0;
  if (elapsedMs <= 0) return 0;
  return Math.min(Math.trunc(elapsedMs), MAX_ELAPSED_MS);
}

/**
 * Compact elapsed time. Deliberately not a percentage and not an ETA:
 * nothing in this process knows how long a model turn or a tool will take,
 * and a fabricated bar is worse than an honest counter.
 *
 * `9s` -> `59s` -> `1m00s` -> `59m59s` -> `1h00m` -> `99h59m`.
 */
export function formatElapsed(elapsedMs: number): string {
  const total = Math.floor(normalizeElapsed(elapsedMs) / 1000);
  if (total < 60) return `${total}s`;
  const minutes = Math.floor(total / 60);
  if (minutes < 60) return `${minutes}m${String(total % 60).padStart(2, "0")}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h${String(minutes % 60).padStart(2, "0")}m`;
}

/** Milliseconds the caller should wait between repaints for this kind. */
export function frameIntervalMs(kind: AnimationKind): number {
  return specFor(kind).intervalMs;
}

/** Number of frames in this kind's cycle (identical for both glyph sets). */
export function frameCount(kind: AnimationKind): number {
  return specFor(kind).unicode.length;
}

/** Full cycle length in milliseconds: frameCount * frameIntervalMs. */
export function framePeriodMs(kind: AnimationKind): number {
  const spec = specFor(kind);
  return spec.unicode.length * spec.intervalMs;
}

/**
 * What to draw for `kind` after `elapsedMs` of waiting.
 *
 * Total: negative, zero, NaN, Infinity and absurd elapsed values all yield a
 * valid frame. With `motion: false` the glyph is pinned to frame 0 but the
 * elapsed label still advances — elapsed is information, not animation, and
 * it is the only thing distinguishing "waiting" from "hung" once motion is
 * off.
 */
export function frameAt(
  kind: AnimationKind,
  elapsedMs: number,
  opts: AnimationOptions = {},
): AnimationFrame {
  const spec = specFor(kind);
  const frames = opts.ascii ? spec.ascii : spec.unicode;
  const elapsed = normalizeElapsed(elapsedMs);

  const index = opts.motion === false
    ? 0
    : Math.floor(elapsed / spec.intervalMs) % frames.length;

  const override = opts.label === undefined ? "" : sanitizeLabel(opts.label);
  const frame: AnimationFrame = {
    glyph: frames[index] ?? frames[0]!,
    label: override || spec.label,
  };
  if (elapsed >= ELAPSED_VISIBLE_AFTER_MS) frame.elapsedLabel = formatElapsed(elapsed);
  return frame;
}
