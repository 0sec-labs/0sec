import { describe, expect, it, vi } from "vitest";
import {
  registerSignalCleanup,
  signalCleanupListenerCountForTests,
} from "./signal-cleanup.js";

describe("signal cleanup registry", () => {
  it("keeps one process listener per signal for many cleanup callbacks", () => {
    const beforeInt = process.listenerCount("SIGINT");
    const beforeTerm = process.listenerCount("SIGTERM");
    const cleanups = Array.from({ length: 20 }, () =>
      registerSignalCleanup(vi.fn()),
    );

    expect(signalCleanupListenerCountForTests()).toBe(20);
    expect(process.listenerCount("SIGINT")).toBe(beforeInt + 1);
    expect(process.listenerCount("SIGTERM")).toBe(beforeTerm + 1);

    for (const cleanup of cleanups) cleanup();

    expect(signalCleanupListenerCountForTests()).toBe(0);
    expect(process.listenerCount("SIGINT")).toBe(beforeInt);
    expect(process.listenerCount("SIGTERM")).toBe(beforeTerm);
  });
});
