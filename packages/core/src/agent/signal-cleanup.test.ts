import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let registry: typeof import("./signal-cleanup.js");
let originalInt: ReturnType<typeof process.listeners>;
let originalTerm: ReturnType<typeof process.listeners>;
beforeEach(async () => {
  originalInt = process.listeners("SIGINT");
  originalTerm = process.listeners("SIGTERM");
  vi.resetModules();
  vi.useFakeTimers();
  vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  registry = await import("./signal-cleanup.js");
});
afterEach(() => {
  for (const listener of process.listeners("SIGINT")) if (!originalInt.includes(listener)) process.removeListener("SIGINT", listener);
  for (const listener of process.listeners("SIGTERM")) if (!originalTerm.includes(listener)) process.removeListener("SIGTERM", listener);
  vi.clearAllTimers();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("signal cleanup registry", () => {
  it("shares one signal listener and removes it after the last unregister", () => {
    const release = Array.from({ length: 20 }, () => registry.registerSignalCleanup(() => {}));
    expect(process.listenerCount("SIGINT")).toBe(originalInt.length + 1);
    expect(process.listenerCount("SIGTERM")).toBe(originalTerm.length + 1);
    for (const unregister of release) unregister();
    expect(process.listenerCount("SIGINT")).toBe(originalInt.length);
    expect(process.listenerCount("SIGTERM")).toBe(originalTerm.length);
  });

  it("awaits asynchronous cleanup before exiting with the existing status", async () => {
    let release!: () => void;
    let disposed = false;
    registry.registerSignalCleanup(async () => {
      await new Promise<void>(resolve => { release = resolve; });
      disposed = true;
    });
    process.emit("SIGINT");
    await vi.advanceTimersByTimeAsync(0);
    expect(process.exit).not.toHaveBeenCalled();
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(disposed).toBe(true);
    expect(process.exit).toHaveBeenCalledExactlyOnceWith(1);
    expect(process.stderr.write).not.toHaveBeenCalled();
  });

  it("drains remaining callbacks and reports incomplete cleanup after failure", async () => {
    const disposed: string[] = [];
    registry.registerSignalCleanup(() => { throw new Error("cleanup failed"); });
    registry.registerSignalCleanup(async () => { disposed.push("remaining"); });
    process.emit("SIGTERM");
    await vi.advanceTimersByTimeAsync(0);
    expect(disposed).toEqual(["remaining"]);
    expect(process.stderr.write).toHaveBeenCalledWith(expect.stringMatching(/failed.*incomplete/));
    expect(process.exit).toHaveBeenCalledExactlyOnceWith(1);
  });

  it("bounds unresolved cleanup and reports that resources may remain open", async () => {
    registry.registerSignalCleanup(() => new Promise<void>(() => {}));
    process.emit("SIGINT");
    await vi.advanceTimersByTimeAsync(34_999);
    expect(process.exit).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(process.exit).toHaveBeenCalledExactlyOnceWith(1);
    expect(process.stderr.write).toHaveBeenCalledWith(expect.stringMatching(/deadline.*incomplete cleanup/));
  });

  it("preserves immediate repeated-signal exit when the draining callback unregisters", async () => {
    const unregister = registry.registerSignalCleanup(async () => {
      unregister();
      await new Promise<void>(() => {});
    });
    process.emit("SIGINT");
    expect(process.exit).not.toHaveBeenCalled();
    process.emit("SIGTERM");
    expect(process.exit).toHaveBeenCalledExactlyOnceWith(1);
    expect(process.stderr.write).toHaveBeenCalledWith(expect.stringMatching(/forced exit.*incomplete/));
    await vi.advanceTimersByTimeAsync(35_000);
    expect(process.exit).toHaveBeenCalledTimes(1);
  });
});
