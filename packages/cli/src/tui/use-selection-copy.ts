/**
 * Copy-on-highlight for the TUI console.
 *
 * When the operator drags a text selection in the terminal, this copies the
 * selected text to the clipboard and signals a "copied" toast — the same
 * gesture every other terminal app answers, and the one thing OpenTUI's own
 * framebuffer ownership takes away (the emulator's native mouse-selection is
 * off while the alt-screen renderer is drawing).
 *
 * The module is split in two so the interesting part is testable without a
 * renderer:
 *
 *   - `createSelectionCopyController` is a pure controller. It is fed
 *     selection text (from wherever), debounces a burst of selection-change
 *     events down to one copy, refuses empty/whitespace selections, calls the
 *     injected `copy` (defaulting to {@link copyToClipboard} from
 *     `clipboard.ts`), and fires `onCopied(bytes)` on success. Clock and
 *     scheduler are injectable, so its whole lifecycle is unit-testable with
 *     no timers and no terminal.
 *
 *   - `useSelectionCopy` is the thin React hook that wires the controller to
 *     OpenTUI's `useSelectionHandler`. It owns nothing but the subscription
 *     and the default `setTimeout` scheduler.
 *
 * This module NEVER writes raw stdout. Every clipboard byte leaves through the
 * injected `emit` (OSC 52) or the injected `spawn` (subprocess) that
 * `clipboard.ts` already knows how to drive safely — see that module's header
 * for why touching `process.stdout` here would corrupt the frame. The caller
 * (chat-screen) supplies `emit` / `spawn`; see `useSelectionCopy` for exactly
 * what to pass.
 */

import { useEffect, useRef } from "react";
// The selection subscription. Kept as a `import type` + runtime import split
// so the pure controller half of this file carries no React/OpenTUI weight.
import { useSelectionHandler } from "@opentui/react";
import type { Selection } from "@opentui/core";

import {
  copyToClipboard,
  type BuildOsc52Options,
  type ClipboardMethod,
  type ClipboardResult,
  type ClipboardSpawn,
  type ClipboardWhich,
} from "./clipboard.js";

/**
 * The clipboard writer the controller drives. Defaults to
 * {@link copyToClipboard}; injectable so tests never touch a real clipboard.
 */
export type SelectionCopyFn = (
  text: string,
  opts?: {
    emit?: (data: string) => void;
    spawn?: ClipboardSpawn;
    which?: ClipboardWhich;
    platform?: NodeJS.Platform | string;
    osc52?: BuildOsc52Options;
  },
) => Promise<ClipboardResult>;

/**
 * A one-shot timer. Returns a cancel handle. Defaults to a `setTimeout`
 * wrapper in the React hook; tests inject a deterministic fake.
 */
export type SelectionCopyScheduler = (fn: () => void, ms: number) => () => void;

/** What a successful copy reports to the toast layer. */
export interface SelectionCopyInfo {
  /** UTF-8 byte length that reached the clipboard. */
  bytes: number;
  /** Which mechanism carried it (osc52 / a subprocess tool). */
  method: ClipboardMethod;
  /** The text that was copied. */
  text: string;
}

export interface SelectionCopyOptions {
  /**
   * Safe terminal writer for the OSC 52 sequence — OpenTUI's own stdout
   * handle, NOT `process.stdout.write` (see `clipboard.ts`). Primary path
   * when present and the payload fits. Forwarded verbatim to `copy`.
   */
  emit?: (data: string) => void;
  /** Subprocess runner for the fallback clipboard path. Forwarded to `copy`. */
  spawn?: ClipboardSpawn;
  /** Executable probe for subprocess-tool detection. Forwarded to `copy`. */
  which?: ClipboardWhich;
  /** Platform id; defaults inside `clipboard.ts` to the host. Forwarded to `copy`. */
  platform?: NodeJS.Platform | string;
  /** OSC 52 build options (tmux passthrough / size handling). Forwarded to `copy`. */
  osc52?: BuildOsc52Options;

  /** Fired after a selection is copied. Wire this to the toast. */
  onCopied?: (info: SelectionCopyInfo) => void;
  /** Fired when a copy was attempted but every path failed. Optional. */
  onCopyFailed?: (info: { bytes: number }) => void;

  /**
   * Quiet period after the last selection-change before the copy fires, so a
   * drag that streams dozens of change events copies once, at the end.
   * Default 250ms. A `finalize` signal (drag release) bypasses this.
   */
  debounceMs?: number;
  /**
   * Minimum UTF-8 byte length of the (non-whitespace) selection to bother
   * copying. Default 1 — anything with real content.
   */
  minBytes?: number;
  /**
   * Skip re-copying text identical to the last successful copy, so holding a
   * selection steady does not re-toast. Default true. A cleared selection
   * resets the guard, so re-selecting the same text later copies again.
   */
  dedupe?: boolean;

  /** Clipboard writer. Defaults to {@link copyToClipboard}. */
  copy?: SelectionCopyFn;
  /** One-shot timer factory. Defaults to a `setTimeout` wrapper. */
  schedule?: SelectionCopyScheduler;
}

/** Imperative handle over a live copy-on-highlight session. */
export interface SelectionCopyController {
  /**
   * Feed the current selection text. Call on every selection-change event.
   * Empty/whitespace text cancels any pending copy (a cleared selection).
   * Pass `{ finalize: true }` when the gesture has ended (drag release) to
   * copy immediately instead of waiting out the debounce.
   */
  handleSelection(text: string | null | undefined, opts?: { finalize?: boolean }): void;
  /** Force any pending selection to be copied now. */
  finalizeNow(): void;
  /** Drop any pending copy without firing it. */
  cancelPending(): void;
  /** Cancel pending work; the controller is inert afterwards. */
  dispose(): void;
}

const DEFAULT_DEBOUNCE_MS = 250;
const DEFAULT_MIN_BYTES = 1;

/** A `setTimeout`-backed scheduler. The React hook's default. */
export const timeoutScheduler: SelectionCopyScheduler = (fn, ms) => {
  const id = setTimeout(fn, ms);
  return () => clearTimeout(id);
};

/** True when `text` has at least `minBytes` UTF-8 bytes of non-whitespace. */
function isCopyworthy(text: string | null | undefined, minBytes: number): text is string {
  if (typeof text !== "string") return false;
  if (text.trim().length === 0) return false;
  return Buffer.byteLength(text, "utf8") >= minBytes;
}

/**
 * Build a copy-on-highlight controller. Pure of React and of OpenTUI: it is
 * driven entirely through `handleSelection`, and its clock/scheduler and
 * clipboard writer are injected, so it is fully unit-testable.
 */
export function createSelectionCopyController(
  options: SelectionCopyOptions = {},
): SelectionCopyController {
  const debounceMs = Math.max(0, options.debounceMs ?? DEFAULT_DEBOUNCE_MS);
  const minBytes = Math.max(1, options.minBytes ?? DEFAULT_MIN_BYTES);
  const dedupe = options.dedupe ?? true;
  const copy = options.copy ?? copyToClipboard;
  const schedule = options.schedule ?? timeoutScheduler;

  let disposed = false;
  let cancelTimer: (() => void) | null = null;
  let pendingText: string | null = null;
  let lastCopied: string | null = null;

  function clearTimer(): void {
    if (cancelTimer) {
      cancelTimer();
      cancelTimer = null;
    }
  }

  function commit(text: string): void {
    if (disposed) return;
    if (!isCopyworthy(text, minBytes)) return;
    if (dedupe && text === lastCopied) return;

    // copyToClipboard never throws (it resolves `{ ok: false }`), but a
    // custom injected `copy` might; guard so a clipboard hiccup never
    // escapes into the render loop.
    Promise.resolve()
      .then(() =>
        copy(text, {
          emit: options.emit,
          spawn: options.spawn,
          which: options.which,
          platform: options.platform,
          osc52: options.osc52,
        }),
      )
      .then((result) => {
        if (disposed) return;
        if (result.ok) {
          lastCopied = text;
          options.onCopied?.({ bytes: result.bytes, method: result.method, text });
        } else {
          options.onCopyFailed?.({ bytes: result.bytes });
        }
      })
      .catch(() => {
        /* A failed copy is a no-op, never a crash. */
      });
  }

  function handleSelection(
    text: string | null | undefined,
    opts?: { finalize?: boolean },
  ): void {
    if (disposed) return;

    // A cleared / whitespace-only selection: forget any pending copy and let
    // the same text be copied again if it is re-selected later.
    if (!isCopyworthy(text, minBytes)) {
      clearTimer();
      pendingText = null;
      lastCopied = null;
      return;
    }

    pendingText = text;

    if (opts?.finalize || debounceMs === 0) {
      clearTimer();
      const toCopy = pendingText;
      pendingText = null;
      commit(toCopy);
      return;
    }

    clearTimer();
    cancelTimer = schedule(() => {
      cancelTimer = null;
      const toCopy = pendingText;
      pendingText = null;
      if (toCopy !== null) commit(toCopy);
    }, debounceMs);
  }

  function finalizeNow(): void {
    if (disposed) return;
    clearTimer();
    const toCopy = pendingText;
    pendingText = null;
    if (toCopy !== null) commit(toCopy);
  }

  function cancelPending(): void {
    clearTimer();
    pendingText = null;
  }

  function dispose(): void {
    disposed = true;
    clearTimer();
    pendingText = null;
  }

  return { handleSelection, finalizeNow, cancelPending, dispose };
}

/**
 * React hook: copy-on-highlight. Subscribes to OpenTUI's selection events and
 * drives a {@link SelectionCopyController} under the hood.
 *
 * Wiring, from chat-screen:
 *
 *   useSelectionCopy({
 *     emit,                       // OpenTUI's safe stdout writer (OSC 52)
 *     spawn: defaultSpawn,        // subprocess fallback (from clipboard.ts)
 *     which: defaultWhich,        // tool probe (from clipboard.ts)
 *     onCopied: ({ bytes }) => showToast(`Copied ${bytes} bytes`),
 *   });
 *
 * `emit` and/or `spawn` are what actually move bytes — pass at least one, or
 * every copy resolves `{ ok: false }` and no toast fires. The selection text
 * source is OpenTUI's `useSelectionHandler`; the hook reads it for you.
 */
export function useSelectionCopy(options: SelectionCopyOptions = {}): void {
  // Keep the latest options in a ref so the controller is created once and
  // never re-subscribes, yet always calls today's `onCopied` / `emit`.
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const controllerRef = useRef<SelectionCopyController | null>(null);
  if (controllerRef.current === null) {
    controllerRef.current = createSelectionCopyController({
      schedule: timeoutScheduler,
      // Read every field live through the ref so a re-render's new callbacks
      // and writers take effect without rebuilding the controller.
      get emit() {
        return optionsRef.current.emit;
      },
      get spawn() {
        return optionsRef.current.spawn;
      },
      get which() {
        return optionsRef.current.which;
      },
      get platform() {
        return optionsRef.current.platform;
      },
      get osc52() {
        return optionsRef.current.osc52;
      },
      get copy() {
        return optionsRef.current.copy;
      },
      debounceMs: options.debounceMs,
      minBytes: options.minBytes,
      dedupe: options.dedupe,
      onCopied: (info) => optionsRef.current.onCopied?.(info),
      onCopyFailed: (info) => optionsRef.current.onCopyFailed?.(info),
    } satisfies SelectionCopyOptions);
  }

  useEffect(() => {
    const controller = controllerRef.current;
    return () => controller?.dispose();
  }, []);

  useSelectionHandler((selection: Selection) => {
    const controller = controllerRef.current;
    if (!controller) return;
    const text = selection.getSelectedText();
    // Drag release (`isDragging` false while a selection still exists) means
    // the gesture is done — copy now rather than waiting out the debounce.
    const finalize = selection.isActive && !selection.isDragging;
    controller.handleSelection(text, { finalize });
  });
}
