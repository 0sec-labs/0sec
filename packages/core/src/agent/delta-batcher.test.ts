/**
 * Unit tests for the per-turn token-delta batcher.
 *
 * The batcher coalesces `response.output_text.delta` / reasoning fragments
 * into chunks before they hit the event bus. Three flush triggers must
 * each work in isolation:
 *
 *   (a) Buffer reaches `DELTA_BATCH_MAX_CHARS` (256 chars).
 *   (b) `DELTA_BATCH_MAX_MS` (100 ms) have elapsed since the first chunk.
 *   (c) `flushNow()` / `flushAll()` is called explicitly at turn-end.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  DeltaBatcher,
  DeltaBatcherSet,
  DELTA_BATCH_MAX_CHARS,
  DELTA_BATCH_MAX_MS,
} from "./delta-batcher.js";

describe("DeltaBatcher", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("flushes when the buffer reaches the size bound", () => {
    const flushed: Array<{ scope: string; text: string }> = [];
    const b = new DeltaBatcher("assistant_response", (args) => flushed.push(args));

    // Push fragments that *just* don't reach the bound.
    b.push("a".repeat(DELTA_BATCH_MAX_CHARS - 10));
    expect(flushed).toHaveLength(0);

    // The next chunk crosses the bound — flush fires synchronously.
    b.push("b".repeat(20));
    expect(flushed).toHaveLength(1);
    expect(flushed[0]!.scope).toBe("assistant_response");
    expect(flushed[0]!.text.length).toBeGreaterThanOrEqual(DELTA_BATCH_MAX_CHARS);

    // Buffer is now empty.
    expect(b.pendingLength).toBe(0);
  });

  it("flushes after the time bound elapses with no further chunks", () => {
    const flushed: Array<{ scope: string; text: string }> = [];
    const b = new DeltaBatcher("reasoning", (args) => flushed.push(args));

    b.push("incremental ");
    b.push("thoughts");
    expect(flushed).toHaveLength(0);

    // Just before the bound — still buffered.
    vi.advanceTimersByTime(DELTA_BATCH_MAX_MS - 1);
    expect(flushed).toHaveLength(0);

    // Cross the bound — timer fires and flushes.
    vi.advanceTimersByTime(2);
    expect(flushed).toHaveLength(1);
    expect(flushed[0]!.scope).toBe("reasoning");
    expect(flushed[0]!.text).toBe("incremental thoughts");
  });

  it("flushNow() drains a partial buffer and is a no-op when empty", () => {
    const flushed: Array<{ scope: string; text: string }> = [];
    const b = new DeltaBatcher("assistant_response", (args) => flushed.push(args));

    b.push("partial");
    b.flushNow();
    expect(flushed).toHaveLength(1);
    expect(flushed[0]!.text).toBe("partial");

    // Second call with nothing pending — no extra flush.
    b.flushNow();
    expect(flushed).toHaveLength(1);
  });

  it("DeltaBatcherSet.flushAll() drains every scope's buffer at turn end", () => {
    const flushed: Array<{ scope: string; text: string }> = [];
    const set = new DeltaBatcherSet((args) => flushed.push(args));

    set.push("assistant_response", "visible ");
    set.push("reasoning", "hidden ");
    set.push("assistant_response", "answer");
    set.push("reasoning", "thoughts");

    expect(flushed).toHaveLength(0);
    set.flushAll();

    expect(flushed).toHaveLength(2);
    const byScope = Object.fromEntries(flushed.map((f) => [f.scope, f.text]));
    expect(byScope.assistant_response).toBe("visible answer");
    expect(byScope.reasoning).toBe("hidden thoughts");
  });
});
