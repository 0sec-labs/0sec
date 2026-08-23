import { describe, expect, it } from "vitest";

import {
  COMPOSER_QUEUE_LIMIT,
  classifyComposerInput,
  composerQueueLabel,
  dequeueComposerInput,
  enqueueComposerInput,
  shouldFlushQueuedInput,
} from "./composer-queue.js";

describe("classifyComposerInput", () => {
  const base = { input: "scan the host", isSlash: false, busy: false, hasSession: true };

  it("sends ordinary text when idle with a session", () => {
    expect(classifyComposerInput(base)).toBe("send");
  });

  it("queues ordinary text while a turn is in flight", () => {
    // The regression this module exists for: this case used to be a silent
    // `return` that dropped the message and left it in the composer.
    expect(classifyComposerInput({ ...base, busy: true })).toBe("queue");
  });

  it("queues ordinary text before a session exists", () => {
    expect(classifyComposerInput({ ...base, hasSession: false })).toBe("queue");
  });

  it("sends slash commands even mid-turn", () => {
    // `/stop` parked until the turn ends would invert its meaning.
    expect(classifyComposerInput({ ...base, input: "/stop", isSlash: true, busy: true }))
      .toBe("send");
  });

  it("sends slash commands even with no session", () => {
    expect(classifyComposerInput({
      ...base, input: "/help", isSlash: true, hasSession: false,
    })).toBe("send");
  });

  it.each(["", "   ", "\t\n"])("discards blank input %j", (input) => {
    expect(classifyComposerInput({ ...base, input })).toBe("discard");
  });

  it("discards blank input before considering busy or slash state", () => {
    expect(classifyComposerInput({ input: "  ", isSlash: true, busy: true, hasSession: false }))
      .toBe("discard");
  });
});

describe("enqueueComposerInput", () => {
  it("appends to the back and does not mutate its input", () => {
    const queue = ["first"];
    const result = enqueueComposerInput(queue, "second");
    expect(result).toEqual({ queue: ["first", "second"], accepted: true });
    expect(queue).toEqual(["first"]);
  });

  it("refuses the newest message at the limit rather than evicting an older one", () => {
    // Silently discarding an operator instruction is the bug being fixed, so a
    // full queue must refuse loudly rather than quietly drop the oldest.
    const full = Array.from({ length: 3 }, (_, i) => `m${i}`);
    const result = enqueueComposerInput(full, "overflow", 3);
    expect(result.accepted).toBe(false);
    expect(result.queue).toEqual(full);
  });

  it("defaults to a generous cap", () => {
    expect(COMPOSER_QUEUE_LIMIT).toBeGreaterThan(10);
    const full = Array.from({ length: COMPOSER_QUEUE_LIMIT }, (_, i) => `m${i}`);
    expect(enqueueComposerInput(full, "overflow").accepted).toBe(false);
  });
});

describe("dequeueComposerInput", () => {
  it("takes from the front, preserving FIFO order", () => {
    expect(dequeueComposerInput(["a", "b", "c"])).toEqual({ next: "a", rest: ["b", "c"] });
  });

  it("reports an empty queue without throwing", () => {
    expect(dequeueComposerInput([])).toEqual({ next: undefined, rest: [] });
  });

  it("does not mutate its input", () => {
    const queue = ["a", "b"];
    dequeueComposerInput(queue);
    expect(queue).toEqual(["a", "b"]);
  });

  it("round-trips a full drain in submission order", () => {
    let queue = ["one", "two", "three"];
    const drained: string[] = [];
    for (;;) {
      const { next, rest } = dequeueComposerInput(queue);
      if (next === undefined) break;
      drained.push(next);
      queue = rest;
    }
    expect(drained).toEqual(["one", "two", "three"]);
  });
});

describe("composerQueueLabel", () => {
  it("renders nothing when the queue is empty", () => {
    expect(composerQueueLabel(0)).toBeUndefined();
    expect(composerQueueLabel(-1)).toBeUndefined();
  });

  it("singularizes exactly one", () => {
    expect(composerQueueLabel(1)).toBe("1 queued");
  });

  it("pluralizes more than one", () => {
    expect(composerQueueLabel(4)).toBe("4 queued");
  });
});


describe("shouldFlushQueuedInput", () => {
  it("flushes a queued message on empty Enter when idle with a session", () => {
    expect(shouldFlushQueuedInput({ input: "", busy: false, hasSession: true, queuedCount: 1 }))
      .toBe(true);
  });

  it("does not flush while busy because turns are single-flight", () => {
    expect(shouldFlushQueuedInput({ input: "", busy: true, hasSession: true, queuedCount: 1 }))
      .toBe(false);
  });

  it("does not flush non-empty composer input or an empty queue", () => {
    expect(shouldFlushQueuedInput({ input: "new message", busy: false, hasSession: true, queuedCount: 1 }))
      .toBe(false);
    expect(shouldFlushQueuedInput({ input: "", busy: false, hasSession: true, queuedCount: 0 }))
      .toBe(false);
  });
});
