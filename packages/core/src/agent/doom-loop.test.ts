import { describe, expect, it } from "vitest";

import {
  detectDoomLoop,
  doomLoopNudge,
  toolCallSignature,
  DEFAULT_DOOM_LOOP_THRESHOLD,
} from "./doom-loop.js";

describe("toolCallSignature", () => {
  it("collides for equivalent args regardless of key order", () => {
    expect(toolCallSignature("bash", { a: 1, b: 2 })).toBe(toolCallSignature("bash", { b: 2, a: 1 }));
  });

  it("differs by tool name and by args", () => {
    expect(toolCallSignature("bash", { cmd: "ls" })).not.toBe(toolCallSignature("bash", { cmd: "pwd" }));
    expect(toolCallSignature("bash", { cmd: "ls" })).not.toBe(toolCallSignature("run_command", { cmd: "ls" }));
  });

  it("handles undefined/empty args", () => {
    expect(toolCallSignature("done", undefined)).toBe(toolCallSignature("done", {}));
  });
});

describe("detectDoomLoop", () => {
  const sig = (n: string) => toolCallSignature("bash", { cmd: n });

  it("does not fire below the threshold", () => {
    expect(detectDoomLoop([sig("x"), sig("x")]).looping).toBe(false);
  });

  it("fires on threshold identical trailing calls", () => {
    const v = detectDoomLoop([sig("x"), sig("x"), sig("x")]);
    expect(v.looping).toBe(true);
    expect(v.count).toBe(3);
    expect(v.signature).toBe(sig("x"));
  });

  it("only counts the CONTIGUOUS trailing run (a break resets it)", () => {
    // x x y x x — trailing run of x is only 2.
    expect(detectDoomLoop([sig("x"), sig("x"), sig("y"), sig("x"), sig("x")]).looping).toBe(false);
  });

  it("counts a long trailing run", () => {
    const v = detectDoomLoop([sig("a"), sig("x"), sig("x"), sig("x"), sig("x")]);
    expect(v.count).toBe(4);
    expect(v.looping).toBe(true);
  });

  it("respects a custom threshold and clamps a bad one", () => {
    expect(detectDoomLoop([sig("x"), sig("x")], 2).looping).toBe(true);
    // threshold < 2 clamps to the default (3).
    expect(detectDoomLoop([sig("x"), sig("x")], 1).looping).toBe(false);
    expect(DEFAULT_DOOM_LOOP_THRESHOLD).toBe(3);
  });

  it("is empty-safe", () => {
    expect(detectDoomLoop([]).looping).toBe(false);
  });
});

describe("doomLoopNudge", () => {
  it("names the repeated tool and tells the model to break the loop", () => {
    const msg = doomLoopNudge(toolCallSignature("run_command", { command: "ls" }), 4);
    expect(msg).toContain("run_command");
    expect(msg).toContain("4 times");
    expect(msg).toMatch(/done/);
  });
});
