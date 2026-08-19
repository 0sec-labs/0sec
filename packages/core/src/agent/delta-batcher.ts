/**
 * Token-level delta batcher.
 *
 * The Responses API streams `response.output_text.delta` events at roughly
 * one fragment per BPE token (≈ 50–100 events/sec on a fast model). Forwarding
 * each one as its own `0SEC_EVENT_DELTA` line on stdout would:
 *
 *   - Spam the cloud worker-controller's stdout parser at line-noise rates
 *     (the parser does a JSON.parse per line — quadratic worst-case if
 *     buffering is involved).
 *   - Push 50+ INSERTs/sec into `scan_events` on the dashboard side, which
 *     swamps the SSE fan-out and the React rendering tree.
 *
 * So we coalesce. Each (turn, scope) gets its own `DeltaBatcher` that
 * accumulates `text` chunks into a buffer and flushes to the bus when ANY
 * of the following bounds are crossed:
 *
 *   (a) Buffer size ≥ 256 chars (prevents unbounded memory growth on a long
 *       single-message response that keeps streaming for minutes).
 *   (b) ≥ 100 ms have elapsed since the FIRST chunk in the current buffer
 *       (caps end-to-end latency from token-on-the-wire to dashboard render
 *       at ~100 ms regardless of stream rate).
 *   (c) `flushNow()` is called explicitly — used at agent-turn boundaries
 *       so the trailing partial buffer is never left dangling when the
 *       stream ends.
 *
 * Why these specific numbers:
 *
 *   - 256 chars ≈ ~64 tokens ≈ a sentence or two — a sensible chunk for
 *     the dashboard to render in one paint, and small enough that the
 *     blinking-cursor UX doesn't feel laggy when (b) doesn't fire because
 *     the model is producing text fast.
 *   - 100 ms is below the human-perceptible-latency threshold (~150 ms),
 *     so the streaming text feels live even when (a) doesn't fire because
 *     the model is producing text slowly.
 *
 * The batcher is a tiny, dependency-free helper — it doesn't know about
 * the event bus directly. The caller passes a flush callback that does
 * the actual `eventBus.emit("delta", …)` plus seq accounting. This keeps
 * the unit tests fast (no bus state, no fake timers needed for the trivial
 * cases) and lets the agent loop own the seq counter.
 */

export const DELTA_BATCH_MAX_CHARS = 256;
export const DELTA_BATCH_MAX_MS = 100;

export interface DeltaBatcherFlushArgs {
  scope: "assistant_response" | "reasoning";
  text: string;
}

/**
 * Single-scope batcher. The agent loop creates one of these per
 * (turn, scope) pair via `DeltaBatcherSet` (below).
 *
 * Not thread-safe — the agent loop is single-threaded inside one turn,
 * and each turn gets its own batcher instances, so concurrency isn't
 * an issue here.
 */
export class DeltaBatcher {
  private buffer = "";
  private timer: ReturnType<typeof setTimeout> | null = null;
  private firstChunkAt = 0;

  constructor(
    private readonly scope: "assistant_response" | "reasoning",
    private readonly onFlush: (args: DeltaBatcherFlushArgs) => void,
    private readonly maxChars = DELTA_BATCH_MAX_CHARS,
    private readonly maxMs = DELTA_BATCH_MAX_MS,
  ) {}

  /**
   * Append a fragment. May trigger an immediate flush if the size bound is
   * crossed; otherwise arms a timer for the time bound.
   */
  push(text: string): void {
    if (!text) return;

    if (this.buffer.length === 0) {
      // First chunk in a new window — record the wall-clock time so we
      // can flush at firstChunkAt + maxMs even if more chunks arrive in
      // the meantime.
      this.firstChunkAt = Date.now();
    }
    this.buffer += text;

    if (this.buffer.length >= this.maxChars) {
      this.flushNow();
      return;
    }

    if (this.timer === null) {
      const elapsed = Date.now() - this.firstChunkAt;
      const remaining = Math.max(0, this.maxMs - elapsed);
      this.timer = setTimeout(() => {
        this.timer = null;
        this.flushNow();
      }, remaining);
      // Don't keep the Node event loop alive purely to flush a delta —
      // if everything else is shut down, the parent process is exiting
      // anyway and a missed flush is better than a hung process.
      const t = this.timer as { unref?: () => void };
      if (typeof t.unref === "function") t.unref();
    }
  }

  /**
   * Force-flush whatever is buffered. No-op if the buffer is empty. Always
   * cancels the pending timer so we don't double-flush.
   */
  flushNow(): void {
    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    if (this.buffer.length === 0) return;
    const text = this.buffer;
    this.buffer = "";
    this.firstChunkAt = 0;
    this.onFlush({ scope: this.scope, text });
  }

  /** Test/observability helper — current pending buffer length. */
  get pendingLength(): number {
    return this.buffer.length;
  }
}

/**
 * One-batcher-per-scope helper used by the agent loop. Owns the lazy
 * allocation of `DeltaBatcher` instances and the `flushAll()` call at
 * turn-end.
 */
export class DeltaBatcherSet {
  private readonly batchers = new Map<
    "assistant_response" | "reasoning",
    DeltaBatcher
  >();

  constructor(
    private readonly onFlush: (args: DeltaBatcherFlushArgs) => void,
    private readonly maxChars = DELTA_BATCH_MAX_CHARS,
    private readonly maxMs = DELTA_BATCH_MAX_MS,
  ) {}

  push(scope: "assistant_response" | "reasoning", text: string): void {
    let b = this.batchers.get(scope);
    if (!b) {
      b = new DeltaBatcher(scope, this.onFlush, this.maxChars, this.maxMs);
      this.batchers.set(scope, b);
    }
    b.push(text);
  }

  /** Drain every scope's buffer — call at agent-turn end. */
  flushAll(): void {
    for (const b of this.batchers.values()) {
      b.flushNow();
    }
  }
}
