import { describe, expect, it, vi } from "vitest";

import { installTuiOutputGuard } from "./output-guard.js";
import { presentationEventBus } from "../presentation/event-bus.js";

const ESC = String.fromCharCode(27);

describe("installTuiOutputGuard", () => {
  it("captures stderr writes instead of letting them reach the terminal", () => {
    const originalWrite = process.stderr.write;
    const lines: string[] = [];
    const guard = installTuiOutputGuard({
      onLine: (line) => lines.push(`${line.stream}:${line.text}`),
    });
    try {
      expect(process.stderr.write).not.toBe(originalWrite);
      process.stderr.write("[0sec] plan quota exhausted\n");
    } finally {
      guard.restore();
    }

    expect(lines).toEqual(["stderr:[0sec] plan quota exhausted"]);
    expect(process.stderr.write).toBe(originalWrite);
  });

  it("projects captured TUI lines into the canonical event stream", () => {
    const events: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
    const unsubscribe = presentationEventBus.subscribe({
      emit(event) {
        events.push({ eventType: event.eventType, payload: event.payload });
      },
    });
    const guard = installTuiOutputGuard();
    try {
      process.stderr.write("runtime warning\n");
    } finally {
      guard.restore();
      unsubscribe();
    }

    expect(events).toEqual([
      {
        eventType: "output.tui.stderr",
        payload: { channel: "stderr", text: "runtime warning" },
      },
    ]);
  });

  it("reassembles a message split across writes", () => {
    const guard = installTuiOutputGuard();
    try {
      process.stderr.write("plan quota");
      process.stderr.write(" exhausted");
      process.stderr.write("; skipping retry\n");
    } finally {
      guard.restore();
    }
    expect(guard.drain().map((l) => l.text)).toEqual([
      "plan quota exhausted; skipping retry",
    ]);
  });

  it("splits a multi-line write into separate lines", () => {
    const guard = installTuiOutputGuard();
    try {
      process.stdout.write("first\nsecond\nthird\n");
    } finally {
      guard.restore();
    }
    expect(guard.drain().map((l) => l.text)).toEqual(["first", "second", "third"]);
  });

  it("flushes a trailing line that never received a newline", () => {
    const guard = installTuiOutputGuard();
    process.stderr.write("no trailing newline");
    guard.restore();
    expect(guard.drain().map((l) => l.text)).toEqual(["no trailing newline"]);
  });

  it("strips ANSI escapes so captured text cannot move the cursor", () => {
    const guard = installTuiOutputGuard();
    try {
      process.stderr.write(`${ESC}[2J${ESC}[H${ESC}[31mred alert${ESC}[0m\n`);
    } finally {
      guard.restore();
    }
    const [line] = guard.drain();
    expect(line.text).toBe("red alert");
    expect(line.text).not.toContain(ESC);
  });

  it("captures console methods and routes them to the right stream", () => {
    const guard = installTuiOutputGuard();
    try {
      console.log("informational");
      console.error("failed badly");
    } finally {
      guard.restore();
    }
    expect(guard.drain()).toEqual([
      { stream: "stdout", text: "informational" },
      { stream: "stderr", text: "failed badly" },
    ]);
  });

  it("accepts Buffer chunks", () => {
    const guard = installTuiOutputGuard();
    try {
      process.stderr.write(Buffer.from("buffered warning\n", "utf8"));
    } finally {
      guard.restore();
    }
    expect(guard.drain().map((l) => l.text)).toEqual(["buffered warning"]);
  });

  it("still invokes the write callback so callers are not stalled", async () => {
    const guard = installTuiOutputGuard();
    const callback = vi.fn();
    try {
      const result = process.stderr.write("with callback\n", callback);
      expect(result).toBe(true);
      await new Promise((resolve) => process.nextTick(resolve));
    } finally {
      guard.restore();
    }
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it("bounds the buffer and reports what it dropped", () => {
    const guard = installTuiOutputGuard({ maxBuffered: 2 });
    try {
      process.stderr.write("one\ntwo\nthree\n");
    } finally {
      guard.restore();
    }
    expect(guard.drain().map((l) => l.text)).toEqual(["two", "three"]);
    expect(guard.droppedCount()).toBe(1);
  });

  it("does not undo a stream the renderer already reset during teardown", () => {
    const originalWrite = process.stderr.write;
    const guard = installTuiOutputGuard();
    const rendererWrite = originalWrite;
    // Simulate opentui's destroy() restoring the stream before we unmount.
    process.stderr.write = rendererWrite;
    guard.restore();
    expect(process.stderr.write).toBe(rendererWrite);
    process.stderr.write = originalWrite;
  });

  it("is safe to restore twice", () => {
    const originalWrite = process.stderr.write;
    const guard = installTuiOutputGuard();
    guard.restore();
    guard.restore();
    expect(process.stderr.write).toBe(originalWrite);
  });

  it("keeps working when a consumer throws", () => {
    const guard = installTuiOutputGuard({
      onLine: () => {
        throw new Error("consumer exploded");
      },
    });
    try {
      expect(() => process.stderr.write("still fine\n")).not.toThrow();
    } finally {
      guard.restore();
    }
    expect(guard.drain().map((l) => l.text)).toEqual(["still fine"]);
  });
});
