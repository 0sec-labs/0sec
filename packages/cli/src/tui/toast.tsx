/** @jsxImportSource @opentui/react */
/**
 * The transient "copied" toast — a small bordered pill that appears, holds for
 * ~1.5s, and fades out, driven entirely by the pure envelope in
 * `toast-logic.ts`.
 *
 * Two exports:
 *
 *   - `Toast` renders a single {@link ToastFrame}. It is pure: given a frame it
 *     draws the pill (or nothing when the frame is hidden). No timers, no
 *     state — hand it a frame from `toastFrameAt` and it paints.
 *
 *   - `useToast` is the driver the chat surface will actually call: it holds
 *     the current show, ticks the clock while a toast is on screen, and hands
 *     back `{ showToast, frame }`. Point `useSelectionCopy({ onCopied })` at
 *     `showToast` and render `<Toast frame={frame} />` and copy-on-highlight
 *     has its feedback.
 *
 * Layout invariants (see `primitives.tsx`): every box is `flexShrink={0}` and
 * width-bounded, and the label is budgeted with `fitTuiText`, so the pill can
 * never be squeezed into an overlapping smear or push its own border off-grid.
 * It is positioned absolutely (bottom-right by default) with a high `zIndex`
 * so it floats over the transcript without participating in its layout.
 */

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

import { fitTuiText } from "./text.js";
import { useTheme } from "./theme-context.js";
import {
  isToastDone,
  showToast as makeShow,
  toastDurationMs,
  toastFrameAt,
  type ToastConfig,
  type ToastFrame,
  type ToastShow,
} from "./toast-logic.js";

/** How the toast is pinned to the viewport. */
export type ToastPlacement = "bottom-right" | "bottom-left" | "top-right" | "top-left";

export interface ToastProps {
  /** The current frame from `toastFrameAt`. Nothing renders when hidden. */
  frame: ToastFrame;
  /**
   * Corner to pin the pill to. Default `"bottom-right"` — above the composer's
   * right edge, out of the transcript's reading column. Chat-screen may want
   * `"top-right"` if the composer is tall.
   */
  placement?: ToastPlacement;
  /** Cells of inset from the pinned edges. Default 1. */
  margin?: number;
  /** Max cells the pill may occupy, so a long message cannot span the screen. */
  maxWidth?: number;
  /** Stacking order over the transcript. Default 50. */
  zIndex?: number;
}

/** Longest message we will render inside the pill, before the outer clamp. */
const DEFAULT_MAX_WIDTH = 40;
/** Border (2) + horizontal padding (2). */
const CHROME_CELLS = 4;

function edges(placement: ToastPlacement, margin: number) {
  const vertical = placement.startsWith("top") ? { top: margin } : { bottom: margin };
  const horizontal = placement.endsWith("left") ? { left: margin } : { right: margin };
  return { ...vertical, ...horizontal };
}

/**
 * Render a toast frame. Pure and side-effect free: safe to render every tick.
 * Returns `null` when the frame is hidden, so it costs nothing off-screen.
 */
export function Toast({
  frame,
  placement = "bottom-right",
  margin = 1,
  maxWidth = DEFAULT_MAX_WIDTH,
  zIndex = 50,
}: ToastProps): ReactNode {
  const theme = useTheme();

  if (!frame.visible || frame.message.trim().length === 0) return null;

  // Budget the label against the pill's inner width so it can never overflow
  // its border. `fitTuiText` also strips control chars from the message.
  const innerCap = Math.max(1, maxWidth - CHROME_CELLS);
  const label = fitTuiText(frame.message, innerCap);
  const innerWidth = Math.max(1, Math.min(innerCap, label.length));
  const boxWidth = innerWidth + CHROME_CELLS;

  // The envelope's `progress` is available for the caller to key motion off;
  // OpenTUI has no per-cell opacity, so the fade reads through colour — a
  // fully-in pill uses ACCENT chrome, the ramp phases dim to MUTED.
  const chrome = frame.phase === "hold" ? theme.ACCENT : theme.MUTED;

  return (
    <box
      position="absolute"
      {...edges(placement, margin)}
      width={boxWidth}
      flexShrink={0}
      flexGrow={0}
      minWidth={0}
      border
      borderColor={chrome}
      backgroundColor={theme.surface}
      paddingX={1}
      zIndex={zIndex}
    >
      <box flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
        <text fg={theme.TEXT}>{label}</text>
      </box>
    </box>
  );
}

/** Repaint cadence while a toast animates (~30fps). */
const TICK_MS = 33;

export interface UseToastResult {
  /** Raise a toast with `message`; resets the envelope if one is showing. */
  showToast: (message: string) => void;
  /** The current frame — feed straight to `<Toast frame={...} />`. */
  frame: ToastFrame;
}

/**
 * Stateful toast driver. Owns the current show record and a ticker that
 * re-renders while the toast is on screen (and stops once it is gone). Under
 * `reduceMotion` it holds still and schedules a single dismissal instead of
 * ticking.
 *
 * Wiring, from chat-screen:
 *
 *   const { showToast, frame } = useToast();
 *   useSelectionCopy({ emit, onCopied: ({ bytes }) => showToast(`Copied ${bytes} bytes`) });
 *   // ...render tree...
 *   <Toast frame={frame} />
 */
export function useToast(config: ToastConfig = {}): UseToastResult {
  const [show, setShow] = useState<ToastShow | null>(null);
  // A dummy counter whose only job is to force a re-render on each tick so the
  // frame is recomputed against a fresh `Date.now()`.
  const [, forceTick] = useState(0);

  // Keep config stable-by-value so the effect below does not thrash. Callers
  // typically pass a literal each render; memo on its serialised shape.
  const configRef = useRef(config);
  configRef.current = config;

  const showToast = useCallback((message: string) => {
    setShow(makeShow(message, Date.now()));
  }, []);

  useEffect(() => {
    if (!show) return;
    const cfg = configRef.current;

    if (cfg.reduceMotion) {
      // No animation to run: hold still, then dismiss once.
      const remaining = Math.max(0, show.shownAt + toastDurationMs(cfg) - Date.now());
      const id = setTimeout(() => setShow((cur) => (cur === show ? null : cur)), remaining);
      return () => clearTimeout(id);
    }

    const id = setInterval(() => {
      if (isToastDone(show, Date.now(), configRef.current)) {
        setShow((cur) => (cur === show ? null : cur));
      } else {
        forceTick((t) => (t + 1) % 1_000_000);
      }
    }, TICK_MS);
    return () => clearInterval(id);
  }, [show]);

  // Computed fresh every render (each tick forces one) so the frame tracks the
  // wall clock — no memo, which would pin it to a stale `Date.now()`.
  const frame = toastFrameAt(show, Date.now(), configRef.current);

  return { showToast, frame };
}
