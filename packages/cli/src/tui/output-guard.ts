/**
 * Terminal output guard for the OpenTUI surface.
 *
 * The renderer owns every cell on screen and repaints differentially: it
 * tracks what it believes is already displayed and only emits the changed
 * cells. Any write that reaches the terminal from outside the renderer
 * (`process.stderr.write`, a stray `console.error`, a library banner)
 * scrolls or overprints the framebuffer without the renderer knowing, so
 * every subsequent frame is diffed against a model that no longer matches
 * reality. The visible result is ghost rows, fused text, and characters
 * from one widget appearing inside another.
 *
 * `@0sec/core` has 60+ such call sites (quota notices, retry warnings,
 * scanner diagnostics). Rewriting each one to thread a logger through is
 * both invasive and permanently fragile — a single new `console.warn` in
 * any dependency reintroduces the corruption. Instead the TUI claims the
 * process-level streams while it is mounted and turns anything written to
 * them into structured lines the UI can render inside the transcript.
 *
 * Ordering matters. OpenTUI saves the real `stdout.write` when the
 * renderer is constructed and emits frames through that saved reference,
 * so this guard MUST be installed *after* `createCliRenderer` — then the
 * renderer's own output bypasses it and only application writes are
 * captured. `restore()` is defensive: it reinstalls the originals only if
 * the live functions are still the ones it installed, so a renderer
 * teardown that resets the stream first is never undone.
 *
 * Nothing is discarded silently. Captured lines are buffered (bounded) and
 * delivered to `onLine`, because an operator running an authorized
 * engagement needs to see "plan quota exhausted" — dropping it to keep the
 * screen clean would trade one bug for a worse one.
 */

import { createPresentationEvent } from "@0sec/shared";
import { presentationEventBus } from "../presentation/event-bus.js";

import { sanitizeTuiText } from "./text.js";

export type TuiOutputStream = "stdout" | "stderr";

export interface TuiOutputLine {
  stream: TuiOutputStream;
  text: string;
}

export interface TuiOutputGuardOptions {
  /** Invoked for each complete captured line. Errors are swallowed. */
  onLine?: (line: TuiOutputLine) => void;
  /** Maximum retained lines. Oldest are dropped first. Default 200. */
  maxBuffered?: number;
  /** Capture `console.*` in addition to the raw streams. Default true. */
  captureConsole?: boolean;
}

export interface TuiOutputGuard {
  /** Returns the buffered lines and clears the buffer. */
  drain(): TuiOutputLine[];
  /** Buffered lines without clearing. */
  peek(): readonly TuiOutputLine[];
  /** Lines dropped because the buffer was full. */
  droppedCount(): number;
  /** Restores the original stream/console functions. Idempotent. */
  restore(): void;
}

type StreamWrite = typeof process.stdout.write;

const CONSOLE_METHODS = ["log", "warn", "error", "info", "debug", "trace"] as const;
type ConsoleMethod = (typeof CONSOLE_METHODS)[number];

const DEFAULT_MAX_BUFFERED = 200;

/** `console.*` formats its own arguments; mirror the useful subset. */
function formatConsoleArgs(args: unknown[]): string {
  return args
    .map((arg) => {
      if (typeof arg === "string") return arg;
      if (arg instanceof Error) return arg.stack ?? `${arg.name}: ${arg.message}`;
      try {
        return JSON.stringify(arg) ?? String(arg);
      } catch {
        return String(arg);
      }
    })
    .join(" ");
}

/**
 * Process-wide subscribers for captured lines.
 *
 * The guard is installed once at the mount boundary (`mountApp`), but the
 * screen that should display a captured line is several levels down the
 * React tree and is remounted on every route change. A module-level
 * registry lets a screen subscribe on mount and unsubscribe on unmount
 * without threading a callback through every intermediate component.
 */
const outputListeners = new Set<(line: TuiOutputLine) => void>();

/** Subscribe to captured output. Returns an unsubscribe function. */
export function onTuiOutputLine(listener: (line: TuiOutputLine) => void): () => void {
  outputListeners.add(listener);
  return () => {
    outputListeners.delete(listener);
  };
}

export function installTuiOutputGuard(options: TuiOutputGuardOptions = {}): TuiOutputGuard {
  const maxBuffered = Math.max(1, options.maxBuffered ?? DEFAULT_MAX_BUFFERED);
  const captureConsole = options.captureConsole !== false;

  const buffer: TuiOutputLine[] = [];
  let dropped = 0;
  let restored = false;
  let presentationSequence = 0;

  // Partial writes are common: core emits a message and its trailing
  // newline separately, and a single write may carry several lines.
  const partial: Record<TuiOutputStream, string> = { stdout: "", stderr: "" };

  const emit = (stream: TuiOutputStream, text: string): void => {
    const clean = sanitizeTuiText(text);
    if (!clean) return;
    // Core already emitted the canonical event before writing the legacy cloud
    // relay line. Keep that wire protocol out of the TUI transcript and avoid
    // replaying it after terminal teardown.
    if (stream === "stdout" && clean.startsWith("0SEC_EVENT_")) return;
    const line: TuiOutputLine = { stream, text: clean };
    presentationEventBus.emit(createPresentationEvent({
      source: "cli",
      sequence: ++presentationSequence,
      at: new Date().toISOString(),
      eventType: `output.tui.${stream}`,
      payload: { channel: stream, text: clean },
    }));
    buffer.push(line);
    while (buffer.length > maxBuffered) {
      buffer.shift();
      dropped += 1;
    }
    try {
      options.onLine?.(line);
    } catch {
      // A failing consumer must never break the write path it replaced.
    }
    for (const listener of outputListeners) {
      try {
        listener(line);
      } catch {
        // Same contract: a broken subscriber cannot break stderr.
      }
    }
  };

  const ingest = (stream: TuiOutputStream, chunk: string): void => {
    const combined = partial[stream] + chunk;
    const segments = combined.split("\n");
    // The trailing segment has no newline yet; hold it for the next write.
    partial[stream] = segments.pop() ?? "";
    for (const segment of segments) emit(stream, segment);
  };

  const flushPartial = (): void => {
    for (const stream of ["stdout", "stderr"] as const) {
      const pending = partial[stream];
      partial[stream] = "";
      if (pending) emit(stream, pending);
    }
  };

  const originalWrites: Partial<Record<TuiOutputStream, StreamWrite>> = {};
  const patchedWrites: Partial<Record<TuiOutputStream, StreamWrite>> = {};

  for (const stream of ["stdout", "stderr"] as const) {
    const target = process[stream];
    if (!target || typeof target.write !== "function") continue;
    originalWrites[stream] = target.write as StreamWrite;

    const patched = ((
      chunk: unknown,
      encoding?: unknown,
      callback?: unknown,
    ): boolean => {
      const done = typeof encoding === "function" ? encoding : callback;
      const enc = typeof encoding === "string" ? encoding : undefined;
      let text: string;
      if (typeof chunk === "string") {
        text = chunk;
      } else if (chunk instanceof Uint8Array) {
        text = Buffer.from(chunk).toString((enc as BufferEncoding) ?? "utf8");
      } else {
        text = String(chunk ?? "");
      }
      ingest(stream, text);
      // Node contract: the callback still fires and the write "succeeds".
      if (typeof done === "function") {
        process.nextTick(done as () => void);
      }
      return true;
    }) as unknown as StreamWrite;

    patchedWrites[stream] = patched;
    target.write = patched;
  }

  const originalConsole: Partial<Record<ConsoleMethod, (...args: unknown[]) => void>> = {};
  const patchedConsole: Partial<Record<ConsoleMethod, (...args: unknown[]) => void>> = {};

  if (captureConsole) {
    for (const method of CONSOLE_METHODS) {
      const existing = console[method] as ((...args: unknown[]) => void) | undefined;
      if (typeof existing !== "function") continue;
      originalConsole[method] = existing;
      const stream: TuiOutputStream =
        method === "warn" || method === "error" || method === "trace" ? "stderr" : "stdout";
      const patched = (...args: unknown[]): void => {
        emit(stream, formatConsoleArgs(args));
      };
      patchedConsole[method] = patched;
      (console as unknown as Record<string, unknown>)[method] = patched;
    }
  }

  return {
    drain(): TuiOutputLine[] {
      const out = buffer.slice();
      buffer.length = 0;
      return out;
    },
    peek(): readonly TuiOutputLine[] {
      return buffer.slice();
    },
    droppedCount(): number {
      return dropped;
    },
    restore(): void {
      if (restored) return;
      restored = true;
      flushPartial();
      for (const stream of ["stdout", "stderr"] as const) {
        const target = process[stream];
        const original = originalWrites[stream];
        if (!target || !original) continue;
        // Only undo our own patch. If the renderer already reset the
        // stream during teardown, leave its value alone.
        if (target.write === patchedWrites[stream]) {
          target.write = original;
        }
      }
      for (const method of CONSOLE_METHODS) {
        const original = originalConsole[method];
        if (!original) continue;
        if (console[method] === patchedConsole[method]) {
          (console as unknown as Record<string, unknown>)[method] = original;
        }
      }
    },
  };
}
