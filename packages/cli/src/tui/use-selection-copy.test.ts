import { describe, expect, it, vi } from "vitest";

import type { ClipboardResult } from "./clipboard.js";
import {
  createSelectionCopyController,
  type SelectionCopyFn,
  type SelectionCopyScheduler,
} from "./use-selection-copy.js";

/** Let the controller's copy promise chain settle. */
const settle = () => new Promise((r) => setTimeout(r, 0));

/** A scheduler whose single pending callback is fired by hand. */
function manualScheduler() {
  let pending: (() => void) | null = null;
  const schedule: SelectionCopyScheduler = (fn) => {
    pending = fn;
    return () => {
      if (pending === fn) pending = null;
    };
  };
  return {
    schedule,
    hasPending: () => pending !== null,
    flush() {
      const fn = pending;
      pending = null;
      fn?.();
    },
  };
}

/** A copy fn that records its calls and returns a canned result. */
function fakeCopy(result?: Partial<ClipboardResult>) {
  const calls: { text: string; opts: unknown }[] = [];
  const fn: SelectionCopyFn = async (text, opts) => {
    calls.push({ text, opts });
    return {
      ok: true,
      method: "osc52",
      bytes: Buffer.byteLength(text, "utf8"),
      ...result,
    } as ClipboardResult;
  };
  return { fn, calls };
}

describe("createSelectionCopyController", () => {
  it("copies a non-empty selection after the debounce and reports bytes/method/text", async () => {
    const copy = fakeCopy();
    const clock = manualScheduler();
    const onCopied = vi.fn();
    const c = createSelectionCopyController({
      copy: copy.fn,
      schedule: clock.schedule,
      onCopied,
    });

    c.handleSelection("hello");
    expect(copy.calls).toHaveLength(0); // debounced, nothing yet
    clock.flush();
    await settle();

    expect(copy.calls).toEqual([expect.objectContaining({ text: "hello" })]);
    expect(onCopied).toHaveBeenCalledWith({ bytes: 5, method: "osc52", text: "hello" });
  });

  it("never copies empty or whitespace-only selections", async () => {
    const copy = fakeCopy();
    const clock = manualScheduler();
    const onCopied = vi.fn();
    const c = createSelectionCopyController({ copy: copy.fn, schedule: clock.schedule, onCopied });

    c.handleSelection("");
    c.handleSelection("   \n\t ");
    c.handleSelection(null);
    c.handleSelection(undefined);
    expect(clock.hasPending()).toBe(false);
    c.finalizeNow();
    await settle();

    expect(copy.calls).toHaveLength(0);
    expect(onCopied).not.toHaveBeenCalled();
  });

  it("coalesces a burst of selection changes into one copy of the last text", async () => {
    const copy = fakeCopy();
    const clock = manualScheduler();
    const c = createSelectionCopyController({ copy: copy.fn, schedule: clock.schedule });

    c.handleSelection("a");
    c.handleSelection("ab");
    c.handleSelection("abc");
    clock.flush();
    await settle();

    expect(copy.calls).toEqual([expect.objectContaining({ text: "abc" })]);
  });

  it("copies immediately when finalize is set, without waiting for the debounce", async () => {
    const copy = fakeCopy();
    const clock = manualScheduler();
    const c = createSelectionCopyController({ copy: copy.fn, schedule: clock.schedule });

    c.handleSelection("done", { finalize: true });
    expect(clock.hasPending()).toBe(false); // no timer scheduled
    await settle();

    expect(copy.calls).toEqual([expect.objectContaining({ text: "done" })]);
  });

  it("dedupes identical consecutive selections but re-copies after a clear", async () => {
    const copy = fakeCopy();
    const clock = manualScheduler();
    const onCopied = vi.fn();
    const c = createSelectionCopyController({ copy: copy.fn, schedule: clock.schedule, onCopied });

    c.handleSelection("same", { finalize: true });
    await settle();
    c.handleSelection("same", { finalize: true });
    await settle();
    expect(copy.calls).toHaveLength(1); // second identical copy skipped

    // A cleared selection resets the dedupe guard.
    c.handleSelection("");
    c.handleSelection("same", { finalize: true });
    await settle();
    expect(copy.calls).toHaveLength(2);
    expect(onCopied).toHaveBeenCalledTimes(2);
  });

  it("honours minBytes: short selections are ignored", async () => {
    const copy = fakeCopy();
    const clock = manualScheduler();
    const c = createSelectionCopyController({
      copy: copy.fn,
      schedule: clock.schedule,
      minBytes: 3,
    });

    c.handleSelection("ab", { finalize: true }); // 2 bytes < 3
    await settle();
    expect(copy.calls).toHaveLength(0);

    c.handleSelection("abc", { finalize: true }); // 3 bytes
    await settle();
    expect(copy.calls).toHaveLength(1);
  });

  it("reports onCopyFailed when every clipboard path fails", async () => {
    const copy = fakeCopy({ ok: false, method: "none" });
    const clock = manualScheduler();
    const onCopied = vi.fn();
    const onCopyFailed = vi.fn();
    const c = createSelectionCopyController({
      copy: copy.fn,
      schedule: clock.schedule,
      onCopied,
      onCopyFailed,
    });

    c.handleSelection("nope", { finalize: true });
    await settle();

    expect(onCopied).not.toHaveBeenCalled();
    expect(onCopyFailed).toHaveBeenCalledWith({ bytes: 4 });
  });

  it("forwards emit/spawn/which/platform/osc52 to the copy fn", async () => {
    const copy = fakeCopy();
    const clock = manualScheduler();
    const emit = vi.fn();
    const spawn = vi.fn();
    const which = vi.fn();
    const c = createSelectionCopyController({
      copy: copy.fn,
      schedule: clock.schedule,
      emit,
      spawn,
      which,
      platform: "linux",
      osc52: { passthrough: true },
    });

    c.handleSelection("x", { finalize: true });
    await settle();

    expect(copy.calls[0]!.opts).toEqual({
      emit,
      spawn,
      which,
      platform: "linux",
      osc52: { passthrough: true },
    });
  });

  it("cancelPending drops a scheduled copy; dispose makes the controller inert", async () => {
    const copy = fakeCopy();
    const clock = manualScheduler();
    const c = createSelectionCopyController({ copy: copy.fn, schedule: clock.schedule });

    c.handleSelection("pending");
    c.cancelPending();
    expect(clock.hasPending()).toBe(false);
    clock.flush(); // nothing to fire
    await settle();
    expect(copy.calls).toHaveLength(0);

    c.dispose();
    c.handleSelection("after-dispose", { finalize: true });
    await settle();
    expect(copy.calls).toHaveLength(0);
  });

  it("copies immediately when debounceMs is 0 (no scheduler use)", async () => {
    const copy = fakeCopy();
    const clock = manualScheduler();
    const c = createSelectionCopyController({
      copy: copy.fn,
      schedule: clock.schedule,
      debounceMs: 0,
    });

    c.handleSelection("instant");
    expect(clock.hasPending()).toBe(false);
    await settle();
    expect(copy.calls).toEqual([expect.objectContaining({ text: "instant" })]);
  });
});
