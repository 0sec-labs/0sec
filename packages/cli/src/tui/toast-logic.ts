/**
 * Pure state logic for the transient "copied" toast.
 *
 * Like `animation.ts`, this file reads no clock, sets no timer and paints
 * nothing: a toast's whole appearance is a total function of the moment it was
 * shown and the current time. The React layer (`toast.tsx`) owns the ticker
 * and the paint; this file owns what the toast looks like at time `now`. That
 * split is what makes the envelope testable without sleeping.
 *
 * A toast has a three-phase envelope — a quick `enter` ramp, a steady `hold`,
 * and a quick `exit` ramp — after which it is `hidden` and can be dropped.
 * `reduceMotion` collapses the ramps to zero so the toast simply appears at
 * full strength, holds, and vanishes: no animation, same lifetime.
 */

/** The lifecycle phase of a toast at a given instant. */
export type ToastPhase = "hidden" | "enter" | "hold" | "exit";

/** Durations, in milliseconds, of the three envelope phases. */
export interface ToastEnvelope {
  /** Fade/scale-in ramp. */
  enterMs: number;
  /** Steady, fully-visible dwell. This is the "~1.5s" the toast is readable. */
  holdMs: number;
  /** Fade/scale-out ramp. */
  exitMs: number;
}

/** Default envelope: a snappy in, ~1.5s readable, a snappy out. */
export const DEFAULT_TOAST_ENVELOPE: ToastEnvelope = {
  enterMs: 120,
  holdMs: 1500,
  exitMs: 180,
};

/** An easing/ramp curve mapping progress 0..1 -> eased 0..1. */
export type ToastEasing = (t: number) => number;

function clamp01(t: number): number {
  if (!Number.isFinite(t)) return 0;
  if (t <= 0) return 0;
  if (t >= 1) return 1;
  return t;
}

/**
 * The default ramp. `animation.ts` ships frame tables, not an easing curve, so
 * there is nothing there to reuse — this is a plain smoothstep, which reads as
 * a gentle ease rather than a mechanical linear slide. Swap it via config for
 * a strictly linear ramp: `easing: (t) => t`.
 */
export const smoothstepRamp: ToastEasing = (t) => {
  const x = clamp01(t);
  return x * x * (3 - 2 * x);
};

/** A strictly linear ramp, for callers that want no easing. */
export const linearRamp: ToastEasing = clamp01;

export interface ToastConfig {
  /** Override any of the envelope durations; unset fields use the default. */
  envelope?: Partial<ToastEnvelope>;
  /** Collapse the enter/exit ramps to instant show/hide. */
  reduceMotion?: boolean;
  /** Ramp curve for the enter/exit phases. Defaults to {@link smoothstepRamp}. */
  easing?: ToastEasing;
}

/** A shown toast: its message and the instant it was raised. */
export interface ToastShow {
  message: string;
  /** Time (ms) the toast was shown, on the same clock passed to the readers. */
  shownAt: number;
}

/** The renderable state of a toast at an instant. */
export interface ToastFrame {
  phase: ToastPhase;
  /** The message text (empty when hidden). */
  message: string;
  /**
   * Envelope strength, 0..1: 0 fully out, 1 fully in. Drives opacity/scale in
   * the component; always 1 during `hold`, and always 1 under `reduceMotion`
   * while visible.
   */
  progress: number;
  /** Convenience: `phase !== "hidden"`. When false, render nothing. */
  visible: boolean;
}

const HIDDEN_FRAME: ToastFrame = {
  phase: "hidden",
  message: "",
  progress: 0,
  visible: false,
};

/**
 * Resolve the effective envelope for a config, applying `reduceMotion` (which
 * zeroes the ramps) and clamping every duration to a finite, non-negative ms.
 */
export function resolveEnvelope(config: ToastConfig = {}): ToastEnvelope {
  const merged = { ...DEFAULT_TOAST_ENVELOPE, ...config.envelope };
  const enterMs = config.reduceMotion ? 0 : Math.max(0, coerceMs(merged.enterMs));
  const holdMs = Math.max(0, coerceMs(merged.holdMs));
  const exitMs = config.reduceMotion ? 0 : Math.max(0, coerceMs(merged.exitMs));
  return { enterMs, holdMs, exitMs };
}

function coerceMs(value: number): number {
  return Number.isFinite(value) ? value : 0;
}

/** Total on-screen lifetime of a toast, in ms, for the given config. */
export function toastDurationMs(config: ToastConfig = {}): number {
  const env = resolveEnvelope(config);
  return env.enterMs + env.holdMs + env.exitMs;
}

/**
 * Raise a toast at `now`. Pure: returns the `ToastShow` record the readers
 * below consume. `message` is coerced to a string; rendering-time sanitation
 * (control chars, width) is the component's job.
 */
export function showToast(message: unknown, now: number): ToastShow {
  return { message: String(message ?? ""), shownAt: coerceMs(now) };
}

/** True once the toast's full envelope has elapsed and it should be dropped. */
export function isToastDone(
  show: ToastShow | null,
  now: number,
  config: ToastConfig = {},
): boolean {
  if (!show) return true;
  const elapsed = coerceMs(now) - show.shownAt;
  return elapsed >= toastDurationMs(config);
}

/**
 * The toast's frame at `now`. Total: a null show, a `now` before the toast was
 * raised, and any non-finite input all yield a valid frame. Once the envelope
 * has fully elapsed the frame is `hidden`.
 */
export function toastFrameAt(
  show: ToastShow | null,
  now: number,
  config: ToastConfig = {},
): ToastFrame {
  if (!show) return HIDDEN_FRAME;

  const env = resolveEnvelope(config);
  const ease = config.easing ?? smoothstepRamp;
  const elapsed = Math.max(0, coerceMs(now) - show.shownAt);

  const enterEnd = env.enterMs;
  const holdEnd = enterEnd + env.holdMs;
  const exitEnd = holdEnd + env.exitMs;

  if (elapsed >= exitEnd) return { ...HIDDEN_FRAME, message: show.message };

  if (elapsed < enterEnd) {
    // enterMs > 0 here (elapsed >= 0 and < enterEnd implies enterEnd > 0).
    return {
      phase: "enter",
      message: show.message,
      progress: ease(elapsed / env.enterMs),
      visible: true,
    };
  }

  if (elapsed < holdEnd) {
    return { phase: "hold", message: show.message, progress: 1, visible: true };
  }

  // exit phase; env.exitMs > 0 here (else exitEnd === holdEnd and we'd be hidden).
  const exitProgress = (elapsed - holdEnd) / env.exitMs;
  return {
    phase: "exit",
    message: show.message,
    progress: ease(1 - exitProgress),
    visible: true,
  };
}
