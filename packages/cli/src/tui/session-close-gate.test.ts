import { describe, expect, it } from "vitest";
import { createSessionCloseGate } from "./session-close-gate.js";

describe("createSessionCloseGate", () => {
  it("resolves a registered waiter exactly once", async () => {
    const gate = createSessionCloseGate();
    const waiter = gate.wait();

    expect(gate.close()).toBe(true);
    expect(gate.close()).toBe(false);
    await expect(waiter).resolves.toBeUndefined();
    expect(gate.closed).toBe(true);
  });

  it("resolves a waiter registered after an early close", async () => {
    const gate = createSessionCloseGate();

    expect(gate.close()).toBe(true);
    await expect(gate.wait()).resolves.toBeUndefined();
  });

  it("resolves every concurrent waiter", async () => {
    const gate = createSessionCloseGate();
    const first = gate.wait();
    const second = gate.wait();

    gate.close();
    await expect(Promise.all([first, second])).resolves.toEqual([undefined, undefined]);
  });
});
