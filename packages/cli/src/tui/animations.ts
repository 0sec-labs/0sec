/**
 * Pure, deterministic motion helpers for the rest of the console's UI.
 *
 * Where `animation.ts` owns the busy-state *spinners* (connecting / thinking /
 * streaming / tool / awaiting-operator, each a width-checked glyph frame),
 * this module owns the smaller ambient motions the chat surface layers on top:
 * a smoother idle spinner, the mode-indicator flash when the operator switches
 * autonomy mode, the attention flash when a finding lands, the breathing pulse
 * of a running subagent glyph, and a toast's slide-and-fade lifecycle.
 *
 * The same discipline applies as everywhere in the TUI motion layer:
 *
 *   1. **Pure.** Every function is a total function of a frame index (and a few
 *      options). Nothing reads a clock, holds state, sets a timer, or paints —
 *      the React layer owns the ticker and the render; this file owns *what a
 *      frame is worth*. That is what makes each one unit-testable without
 *      sleeping.
 *   2. **Tone/step, not colour.** Helpers return a `step` in [0,1] (an
 *      interpolation amount, an alpha, an envelope value) or a small integer
 *      frame index. They never emit a theme token or an escape code — the caller
 *      blends its own colours (`lerp`-style) from the step. A step of 0 is
 *      always the *resting* end, so a caller that ignores a helper still gets a
 *      sane still frame.
 *   3. **reduceMotion collapses to rest.** Every helper takes `{ reduceMotion }`
 *      and, when set, returns its resting frame — step 0, index 0, alpha 1 for a
 *      shown toast — so a single master switch stills the whole surface without
 *      the caller special-casing each animation.
 *
 * Frame-count and loop metadata for every helper lives in `UI_ANIMATIONS`, so a
 * caller drives each with one `setInterval` at `UI_ANIMATION_INTERVAL_MS` and
 * reads the spec to know the cycle length (looping) or when a one-shot has
 * settled (frame >= frameCount - 1).
 */

/**
 * One repaint cadence for the whole module (~14 Hz), matching the logo intro
 * ticker. A caller advances a frame counter at this interval and passes it to
 * whichever helpers are live. These are low-cost ambient motions (a step, an
 * alpha, a small index), so the cadence is smooth for envelopes and pulses
 * without the per-frame cost that keeps the busy glyph spinners at/under 10 Hz.
 */
export const UI_ANIMATION_INTERVAL_MS = 70;

/** Metadata for one UI animation: its cycle length and whether it repeats. */
export interface UiAnimationSpec {
  /**
   * Distinct frames in the animation. For a looping helper this is the loop
   * *period* (frame and frame+frameCount are identical); for a one-shot it is
   * the number of frames before it rests (frame >= frameCount - 1 is settled).
   */
  readonly frameCount: number;
  /** True if the helper repeats forever; false if it plays once and rests. */
  readonly loops: boolean;
}

/** The kinds of UI animation this module drives. */
export type UiAnimationKind = "spinner" | "modeSwitch" | "findingFlash" | "subagentPulse" | "toast";

export interface UiAnimationOptions {
  /** Collapse to the resting frame (accessibility / cost master switch). */
  reduceMotion?: boolean;
}

// ---------------------------------------------------------------------------
// Easing / interpolation primitives (pure, exported for reuse and testing)
// ---------------------------------------------------------------------------

/** Clamp `x` into [lo, hi]. */
export function clamp(x: number, lo: number, hi: number): number {
  if (!Number.isFinite(x)) return lo;
  return x < lo ? lo : x > hi ? hi : x;
}

/** Clamp to the unit interval; non-finite inputs rest at 0. */
export function clamp01(x: number): number {
  return clamp(x, 0, 1);
}

/** Linear interpolation from `a` to `b` by `t` (t clamped to [0,1]). */
export function lerp(a: number, b: number, t: number): number {
  return a + (b - a) * clamp01(t);
}

/** Smoothstep ease-in-out on [0,1]: flat start, flat finish, monotonic. */
export function smoothstep(t: number): number {
  const x = clamp01(t);
  return x * x * (3 - 2 * x);
}

/**
 * A symmetric 0->1->0 hump over [0,1] (a raised cosine / Hann window). Peaks at
 * t=0.5 and returns to 0 at both ends, smoothly — the natural shape for a
 * one-shot "flash" that ramps up and back down with no seam.
 */
export function hump(t: number): number {
  const x = clamp01(t);
  return (1 - Math.cos(2 * Math.PI * x)) / 2;
}

/**
 * A seamless triangle-ish breathe in [0,1] over a loop of `period` frames,
 * driven by a cosine so frame 0 and frame `period` match exactly. `phase01`
 * shifts the start (0 begins at the trough).
 */
export function breathe(frame: number, period: number, phase01 = 0): number {
  if (period <= 0) return 0;
  const f = Number.isFinite(frame) ? frame : 0;
  const t = ((f / period + phase01) % 1 + 1) % 1;
  return (1 - Math.cos(2 * Math.PI * t)) / 2;
}

/** Normalise a possibly non-finite/negative frame into a whole number >= 0. */
function safeFrame(frame: number): number {
  if (!Number.isFinite(frame)) return 0;
  const t = Math.trunc(frame);
  return t < 0 ? 0 : t;
}

// ---------------------------------------------------------------------------
// Specs
// ---------------------------------------------------------------------------

/**
 * A smoother spinner than the 3-frame busy glyphs: an 8-frame braille ring
 * that reads as continuous rotation. Loops.
 */
const SPINNER_PERIOD = 8;

/** The mode-indicator flash on an autonomy-mode switch: a brief up-and-back. */
const MODE_SWITCH_FRAMES = 10;

/** A finding landing: a fast attack to full attention, then a longer decay. */
const FINDING_FLASH_FRAMES = 14;

/** A running subagent's ◉ breathing cycle. Loops. */
const SUBAGENT_PULSE_PERIOD = 16;

/** Toast lifecycle phase lengths (frames): slide/fade in, hold, slide/fade out. */
const TOAST_ENTER_FRAMES = 6;
const TOAST_HOLD_FRAMES = 28;
const TOAST_EXIT_FRAMES = 6;
const TOAST_TOTAL_FRAMES = TOAST_ENTER_FRAMES + TOAST_HOLD_FRAMES + TOAST_EXIT_FRAMES;

/** Frame-count + loop metadata for every helper, keyed by kind. */
export const UI_ANIMATIONS: Record<UiAnimationKind, UiAnimationSpec> = {
  spinner: { frameCount: SPINNER_PERIOD, loops: true },
  modeSwitch: { frameCount: MODE_SWITCH_FRAMES, loops: false },
  findingFlash: { frameCount: FINDING_FLASH_FRAMES, loops: false },
  subagentPulse: { frameCount: SUBAGENT_PULSE_PERIOD, loops: true },
  toast: { frameCount: TOAST_TOTAL_FRAMES, loops: false },
};

/** Look up a helper's spec; unknown kinds fall back to a single static frame. */
export function uiAnimationSpec(kind: UiAnimationKind): UiAnimationSpec {
  return UI_ANIMATIONS[kind] ?? { frameCount: 1, loops: false };
}

// ---------------------------------------------------------------------------
// Spinner
// ---------------------------------------------------------------------------

/**
 * Braille ring frames for the smooth spinner. Each is exactly one cell wide
 * (Braille Patterns are single-width everywhere), so the caller can drop them
 * in a fixed 1-cell box without jitter. Rendered verbatim — do not trim.
 */
export const SPINNER_FRAMES: readonly string[] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];

/**
 * The spinner frame INDEX for `frame` (0..SPINNER_PERIOD-1), wrapping every
 * period. Under reduceMotion it pins to frame 0. Index into `SPINNER_FRAMES`.
 */
export function spinnerFrame(frame: number, opts: UiAnimationOptions = {}): number {
  if (opts.reduceMotion) return 0;
  return safeFrame(frame) % SPINNER_PERIOD;
}

/** The spinner GLYPH for `frame` (convenience over `spinnerFrame` + the table). */
export function spinnerGlyph(frame: number, opts: UiAnimationOptions = {}): string {
  return SPINNER_FRAMES[spinnerFrame(frame, opts)] ?? SPINNER_FRAMES[0]!;
}

// ---------------------------------------------------------------------------
// Mode-switch flash
// ---------------------------------------------------------------------------

/**
 * The mode-indicator flash when the operator switches autonomy mode: a step in
 * [0,1] the caller blends the indicator colour by (0 = the mode's resting
 * colour, 1 = a bright flash toward ACCENT/BRAND). It humps up and back down
 * over `MODE_SWITCH_FRAMES` and then rests at 0; past the end (or under
 * reduceMotion) it is 0, i.e. the steady mode colour.
 */
export function modeSwitchStep(frame: number, opts: UiAnimationOptions = {}): number {
  if (opts.reduceMotion) return 0;
  const f = safeFrame(frame);
  if (f >= MODE_SWITCH_FRAMES) return 0;
  return hump(f / (MODE_SWITCH_FRAMES - 1));
}

// ---------------------------------------------------------------------------
// Finding flash
// ---------------------------------------------------------------------------

/**
 * The attention envelope when a new finding lands: a fast attack to 1 within
 * the first couple of frames, then a smooth decay back to 0 — a highlight that
 * catches the eye and fades so it does not linger as chrome. The caller blends
 * a row background or a severity colour by the returned step. Rests at 0 past
 * the end and under reduceMotion.
 */
export function findingFlashStep(frame: number, opts: UiAnimationOptions = {}): number {
  if (opts.reduceMotion) return 0;
  const f = safeFrame(frame);
  if (f >= FINDING_FLASH_FRAMES) return 0;
  const ATTACK = 2; // frames to reach full attention
  if (f <= ATTACK) return smoothstep(f / ATTACK);
  // Decay from 1 at f=ATTACK to 0 at the last frame, eased.
  const decay = (f - ATTACK) / (FINDING_FLASH_FRAMES - 1 - ATTACK);
  return 1 - smoothstep(decay);
}

// ---------------------------------------------------------------------------
// Subagent running-pulse
// ---------------------------------------------------------------------------

/** The lowest the running-pulse dips, so the ◉ never fully disappears. */
const SUBAGENT_PULSE_FLOOR = 0.35;

/**
 * A running subagent's ◉ breathing step in [SUBAGENT_PULSE_FLOOR, 1], looping
 * every `SUBAGENT_PULSE_PERIOD` frames. The caller maps the step to an
 * opacity/tone blend (e.g. MUTED -> ACCENT). It never reaches 0 — a running
 * indicator that blinks out reads as stopped — and under reduceMotion it rests
 * at 1 (fully lit), the honest "still running" resting state.
 */
export function subagentPulseStep(frame: number, opts: UiAnimationOptions = {}): number {
  if (opts.reduceMotion) return 1;
  return lerp(SUBAGENT_PULSE_FLOOR, 1, breathe(frame, SUBAGENT_PULSE_PERIOD));
}

// ---------------------------------------------------------------------------
// Toast slide/fade
// ---------------------------------------------------------------------------

/** A toast's three lifecycle phases. */
export type ToastPhase = "enter" | "hold" | "exit" | "done";

export interface ToastEnvelope {
  /** Opacity in [0,1]: 0 fully transparent, 1 fully shown. */
  readonly alpha: number;
  /**
   * Slide offset in [0,1]: 1 fully off-position (entering from / exiting to the
   * edge), 0 fully in place. The caller multiplies by its own travel distance
   * (rows or columns) and direction. 0 at rest (held / reduceMotion).
   */
  readonly offset: number;
  /** Which lifecycle phase this frame is in. */
  readonly phase: ToastPhase;
}

/**
 * A toast's slide-and-fade envelope over its enter -> hold -> exit lifecycle.
 *
 * - enter: alpha 0->1 and offset 1->0 (slides in while fading up).
 * - hold:  alpha 1, offset 0 (fully shown, still).
 * - exit:  alpha 1->0 and offset 0->1 (slides out while fading down).
 * - done:  alpha 0 (the caller should unmount).
 *
 * Under reduceMotion the toast simply shows (alpha 1, offset 0) for its whole
 * visible life and then vanishes — the information without the motion. The hold
 * length can be overridden for a stickier or a more fleeting toast; enter/exit
 * are fixed so the motion reads consistently.
 */
export function toastEnvelope(
  frame: number,
  opts: UiAnimationOptions & { holdFrames?: number } = {},
): ToastEnvelope {
  const hold = opts.holdFrames !== undefined && Number.isFinite(opts.holdFrames)
    ? Math.max(0, Math.trunc(opts.holdFrames))
    : TOAST_HOLD_FRAMES;
  const enterEnd = TOAST_ENTER_FRAMES;
  const holdEnd = enterEnd + hold;
  const exitEnd = holdEnd + TOAST_EXIT_FRAMES;
  const f = safeFrame(frame);

  if (f >= exitEnd) return { alpha: 0, offset: 0, phase: "done" };

  if (opts.reduceMotion) {
    // Shown flat for the whole visible life, then gone.
    return { alpha: 1, offset: 0, phase: f < enterEnd ? "enter" : f < holdEnd ? "hold" : "exit" };
  }

  if (f < enterEnd) {
    const t = smoothstep(f / TOAST_ENTER_FRAMES);
    return { alpha: t, offset: 1 - t, phase: "enter" };
  }
  if (f < holdEnd) {
    return { alpha: 1, offset: 0, phase: "hold" };
  }
  // exit
  const t = smoothstep((f - holdEnd) / TOAST_EXIT_FRAMES);
  return { alpha: 1 - t, offset: t, phase: "exit" };
}

/** Total frames a toast is alive for a given hold length (enter + hold + exit). */
export function toastLifetimeFrames(holdFrames: number = TOAST_HOLD_FRAMES): number {
  const hold = Number.isFinite(holdFrames) ? Math.max(0, Math.trunc(holdFrames)) : TOAST_HOLD_FRAMES;
  return TOAST_ENTER_FRAMES + hold + TOAST_EXIT_FRAMES;
}

// ---------------------------------------------------------------------------
// Text shimmer (a sweeping dim band for running LOADING/RUNNING labels)
// ---------------------------------------------------------------------------

/**
 * A skeleton-loader shimmer for a running *line of text* — the thinking
 * indicator, a running tool-call row, a running subagent row. The label sits at
 * a DIM/MUTED base, and a BRIGHT band sweeps left to right across it: each
 * character brightens to full as the band's head passes and falls back to muted
 * behind it, then the whole label rests at the muted base for a gap and the
 * sweep loops. This reads as "alive while working", the same feel as oh-my-pi's
 * loading shimmer.
 *
 * Note the polarity is the OPPOSITE of the logo comet (`shimmerFrame` in
 * logo-animation.ts), which is a DARK band on a WHITE mark: here the base is dim
 * and the head is the peak. The shared piece is only the sweep geometry (head
 * enters off-screen-left, marches right, symmetric band of half-width `tail`,
 * loops with a rest gap).
 *
 * Like every helper here it is pure and theme-free: it returns a per-character
 * *intensity* in [0,1] (0 = the muted base, 1 = the bright peak at the head) and
 * never touches a colour. The CALLER maps intensity to a tone — blend from
 * `theme.MUTED` (intensity 0) up to `theme.TEXT` (intensity 1) — so a bright
 * highlight sweeps across muted text; it paints the label as runs of adjacent
 * equal-intensity characters (coalesce like `logoRowRuns`). Drive it with one
 * frame ticker at `SHIMMER_TEXT_INTERVAL_MS`, passing the label's character count
 * as `length`; re-render the running label each tick.
 */

/**
 * Band half-width: the bright head eases back down to the muted base over this
 * many characters on EACH side (band spans `2*tail + 1` chars).
 */
export const SHIMMER_TEXT_TAIL = 5;

/**
 * Repaint cadence for the text-shimmer ticker (~12.5 Hz), matching oh-my-pi's
 * loader/spinner cadence so the sweep reads at the same speed.
 */
export const SHIMMER_TEXT_INTERVAL_MS = 80;

/** Default rest-gap frames (whole label flat at the muted base) between sweeps. */
const SHIMMER_TEXT_REST_GAP = 6;

/** Options for the text shimmer. Omitted numeric fields fall back to the constants. */
export interface ShimmerTextOptions extends UiAnimationOptions {
  /** Band half-width in characters (default `SHIMMER_TEXT_TAIL`); min 1. */
  tail?: number;
  /** Flat-base frames between sweeps (default `SHIMMER_TEXT_REST_GAP`); min 0. */
  restGap?: number;
}

/** Resolve the band half-width from opts (>= 1). */
function shimmerTail(opts?: ShimmerTextOptions): number {
  const t = opts?.tail;
  if (t === undefined || !Number.isFinite(t)) return SHIMMER_TEXT_TAIL;
  return Math.max(1, Math.trunc(t));
}

/** Resolve the rest-gap length from opts (>= 0). */
function shimmerRestGap(opts?: ShimmerTextOptions): number {
  const g = opts?.restGap;
  if (g === undefined || !Number.isFinite(g)) return SHIMMER_TEXT_REST_GAP;
  return Math.max(0, Math.trunc(g));
}

/** Normalise a possibly non-finite/negative length into a whole number >= 0. */
function shimmerLength(length: number): number {
  if (!Number.isFinite(length)) return 0;
  const n = Math.trunc(length);
  return n < 0 ? 0 : n;
}

/**
 * Loop period for a shimmer over `length` characters: the sweep span (the head
 * travelling from off-screen-left at col `-tail` to off-screen-right past the
 * last char) plus the rest gap. `shimmerText(length, frame)` and
 * `shimmerText(length, frame + period)` are identical. Zero-length labels have a
 * pure rest-gap period (there is nothing to sweep).
 */
export function shimmerTextPeriod(length: number, opts?: ShimmerTextOptions): number {
  const len = shimmerLength(length);
  return len + 2 * shimmerTail(opts) + shimmerRestGap(opts);
}

/**
 * Per-character intensities for one frame of a text shimmer of `length` chars.
 *
 * Returns an array of length `length` where each entry is in [0,1]: 0 is the
 * muted base and 1 is the bright peak. A bright band sweeps across the label
 * — its head (brightest, intensity 1) enters off-screen-left at column
 * `-tail`, marches one column per frame to off-screen-right, then the label rests
 * flat at the muted base for `restGap` frames before repeating. Within the band
 * the intensity eases (smoothstep) symmetrically DOWN from the head to 0 at both
 * edges, so `intensity[head - d] === intensity[head + d]`; characters outside the
 * band are 0 (base).
 *
 * Deterministic in `frame` (wrapped modulo `shimmerTextPeriod`); non-finite or
 * negative frames are treated as 0. `length <= 0` returns `[]`. Under
 * `reduceMotion` every entry is 0 (no shimmer, flat muted base).
 */
export function shimmerText(length: number, frame: number, opts?: ShimmerTextOptions): number[] {
  const len = shimmerLength(length);
  if (len <= 0) return [];
  const out = new Array<number>(len).fill(0);
  if (opts?.reduceMotion) return out;

  const tail = shimmerTail(opts);
  const rest = shimmerRestGap(opts);
  const period = len + 2 * tail + rest;
  const sweep = len + 2 * tail;
  const idx = ((safeFrame(frame) % period) + period) % period;
  if (idx >= sweep) return out; // rest gap: whole label flat at the muted base

  // The bright head begins OFF-SCREEN LEFT at col -tail so the band visibly
  // sweeps IN from the left edge, then marches right one column per frame.
  const head = idx - tail;
  for (let offset = -tail; offset <= tail; offset += 1) {
    const col = head + offset;
    if (col < 0 || col >= len) continue;
    // Brightest (1) at the head; easing symmetrically DOWN to the base (0) at the
    // band edges. Only |offset| matters, so the band is symmetric.
    const intensity = 1 - smoothstep(Math.abs(offset) / tail);
    if (intensity > out[col]!) out[col] = intensity;
  }
  return out;
}
