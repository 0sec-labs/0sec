import { describe, expect, it } from "vitest";

import {
  SPINNER_FRAMES,
  UI_ANIMATIONS,
  UI_ANIMATION_INTERVAL_MS,
  breathe,
  clamp,
  clamp01,
  findingFlashStep,
  hump,
  lerp,
  modeSwitchStep,
  smoothstep,
  spinnerFrame,
  spinnerGlyph,
  subagentPulseStep,
  toastEnvelope,
  toastLifetimeFrames,
  uiAnimationSpec,
  type UiAnimationKind,
} from "./animations.js";

const KINDS: UiAnimationKind[] = ["spinner", "modeSwitch", "findingFlash", "subagentPulse", "toast"];

/** Cells occupied by a string (each braille/ascii code point here is one cell). */
function cellWidth(s: string): number {
  return [...s].length;
}

describe("interpolation primitives", () => {
  it("clamp bounds a value and rests at lo on non-finite input", () => {
    expect(clamp(5, 0, 10)).toBe(5);
    expect(clamp(-3, 0, 10)).toBe(0);
    expect(clamp(99, 0, 10)).toBe(10);
    expect(clamp(Number.NaN, 2, 8)).toBe(2);
    expect(clamp(Number.POSITIVE_INFINITY, 2, 8)).toBe(2);
  });

  it("clamp01 keeps values within [0,1]", () => {
    expect(clamp01(0.5)).toBe(0.5);
    expect(clamp01(-1)).toBe(0);
    expect(clamp01(2)).toBe(1);
  });

  it("lerp interpolates and clamps t", () => {
    expect(lerp(0, 10, 0)).toBe(0);
    expect(lerp(0, 10, 1)).toBe(10);
    expect(lerp(0, 10, 0.5)).toBe(5);
    expect(lerp(0, 10, -1)).toBe(0);
    expect(lerp(0, 10, 5)).toBe(10);
  });

  it("smoothstep is 0 at 0, 1 at 1, 0.5 at midpoint, and monotonic", () => {
    expect(smoothstep(0)).toBe(0);
    expect(smoothstep(1)).toBe(1);
    expect(smoothstep(0.5)).toBeCloseTo(0.5, 10);
    let prev = -1;
    for (let i = 0; i <= 20; i += 1) {
      const v = smoothstep(i / 20);
      expect(v).toBeGreaterThanOrEqual(prev);
      prev = v;
    }
  });

  it("hump is a symmetric 0->1->0 window peaking at the middle", () => {
    expect(hump(0)).toBeCloseTo(0, 10);
    expect(hump(1)).toBeCloseTo(0, 10);
    expect(hump(0.5)).toBeCloseTo(1, 10);
    expect(hump(0.25)).toBeCloseTo(hump(0.75), 10); // symmetric
  });

  it("breathe loops seamlessly and stays within [0,1]", () => {
    const period = 16;
    for (let f = 0; f < period; f += 1) {
      const v = breathe(f, period);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
      expect(breathe(f, period)).toBeCloseTo(breathe(f + period, period), 10);
    }
    expect(breathe(0, period)).toBeCloseTo(0, 10); // trough at the seam
    expect(breathe(period / 2, period)).toBeCloseTo(1, 10); // peak at half
  });
});

describe("UI_ANIMATIONS metadata", () => {
  it("interval is a sane repaint cadence", () => {
    expect(UI_ANIMATION_INTERVAL_MS).toBeGreaterThan(0);
    expect(UI_ANIMATION_INTERVAL_MS).toBeLessThanOrEqual(200);
  });

  it("declares a positive frame count and a loop flag for every kind", () => {
    for (const kind of KINDS) {
      const spec = uiAnimationSpec(kind);
      expect(spec.frameCount).toBeGreaterThanOrEqual(1);
      expect(typeof spec.loops).toBe("boolean");
      expect(UI_ANIMATIONS[kind]).toEqual(spec);
    }
  });

  it("marks the ambient effects as looping and the one-shots as not", () => {
    expect(uiAnimationSpec("spinner").loops).toBe(true);
    expect(uiAnimationSpec("subagentPulse").loops).toBe(true);
    expect(uiAnimationSpec("modeSwitch").loops).toBe(false);
    expect(uiAnimationSpec("findingFlash").loops).toBe(false);
    expect(uiAnimationSpec("toast").loops).toBe(false);
  });

  it("falls back to a single static frame for an unknown kind", () => {
    const spec = uiAnimationSpec("nope" as UiAnimationKind);
    expect(spec).toEqual({ frameCount: 1, loops: false });
  });
});

describe("spinner", () => {
  it("has a frame table matching its declared period, each one cell wide", () => {
    expect(SPINNER_FRAMES).toHaveLength(uiAnimationSpec("spinner").frameCount);
    for (const g of SPINNER_FRAMES) expect(cellWidth(g)).toBe(1);
  });

  it("wraps modulo the period", () => {
    const period = uiAnimationSpec("spinner").frameCount;
    for (const f of [0, 1, period - 1]) {
      expect(spinnerFrame(f)).toBe(f % period);
      expect(spinnerFrame(f + period)).toBe(f % period);
      expect(spinnerFrame(f + period * 3)).toBe(f % period);
    }
  });

  it("advances through every frame across one period", () => {
    const period = uiAnimationSpec("spinner").frameCount;
    const seen = new Set<number>();
    for (let f = 0; f < period; f += 1) seen.add(spinnerFrame(f));
    expect(seen.size).toBe(period);
  });

  it("pins to frame 0 under reduceMotion", () => {
    for (const f of [0, 3, 7, 31]) expect(spinnerFrame(f, { reduceMotion: true })).toBe(0);
    expect(spinnerGlyph(5, { reduceMotion: true })).toBe(SPINNER_FRAMES[0]);
  });

  it("tolerates negative and non-finite frames", () => {
    expect(spinnerFrame(-5)).toBe(0);
    expect(spinnerFrame(Number.NaN)).toBe(0);
    expect(() => spinnerGlyph(Number.POSITIVE_INFINITY)).not.toThrow();
  });
});

describe("modeSwitchStep", () => {
  const count = uiAnimationSpec("modeSwitch").frameCount;

  it("rests at 0 at both ends and peaks in the middle", () => {
    expect(modeSwitchStep(0)).toBeCloseTo(0, 6);
    expect(modeSwitchStep(count - 1)).toBeCloseTo(0, 6);
    const mid = modeSwitchStep(Math.floor((count - 1) / 2));
    expect(mid).toBeGreaterThan(0.5);
  });

  it("stays within [0,1] over its life", () => {
    for (let f = 0; f < count; f += 1) {
      const v = modeSwitchStep(f);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });

  it("rests at 0 once past the end", () => {
    expect(modeSwitchStep(count)).toBe(0);
    expect(modeSwitchStep(count + 50)).toBe(0);
  });

  it("collapses to 0 under reduceMotion", () => {
    for (const f of [0, 3, 5, 9]) expect(modeSwitchStep(f, { reduceMotion: true })).toBe(0);
  });
});

describe("findingFlashStep", () => {
  const count = uiAnimationSpec("findingFlash").frameCount;

  it("attacks fast to full then decays back to 0", () => {
    expect(findingFlashStep(0)).toBeCloseTo(0, 6);
    expect(findingFlashStep(2)).toBeCloseTo(1, 6); // peak at the end of the attack
    expect(findingFlashStep(count - 1)).toBeCloseTo(0, 6);
  });

  it("decays monotonically after the peak", () => {
    let prev = Number.POSITIVE_INFINITY;
    for (let f = 2; f < count; f += 1) {
      const v = findingFlashStep(f);
      expect(v).toBeLessThanOrEqual(prev + 1e-9);
      prev = v;
    }
  });

  it("stays within [0,1] and rests at 0 past the end", () => {
    for (let f = 0; f < count; f += 1) {
      const v = findingFlashStep(f);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
    expect(findingFlashStep(count)).toBe(0);
    expect(findingFlashStep(count + 20)).toBe(0);
  });

  it("collapses to 0 under reduceMotion", () => {
    for (const f of [0, 1, 2, 7]) expect(findingFlashStep(f, { reduceMotion: true })).toBe(0);
  });
});

describe("subagentPulseStep", () => {
  const period = uiAnimationSpec("subagentPulse").frameCount;

  it("breathes within a floor..1 band and never blinks fully out", () => {
    for (let f = 0; f < period; f += 1) {
      const v = subagentPulseStep(f);
      expect(v).toBeGreaterThan(0); // never 0 -> never reads as stopped
      expect(v).toBeLessThanOrEqual(1);
    }
  });

  it("loops seamlessly over the period", () => {
    for (const f of [0, 4, 9, 15]) {
      expect(subagentPulseStep(f)).toBeCloseTo(subagentPulseStep(f + period), 10);
    }
  });

  it("touches both ends of its band across a cycle", () => {
    let min = Number.POSITIVE_INFINITY;
    let max = Number.NEGATIVE_INFINITY;
    for (let f = 0; f < period; f += 1) {
      const v = subagentPulseStep(f);
      min = Math.min(min, v);
      max = Math.max(max, v);
    }
    expect(max).toBeCloseTo(1, 6);
    expect(min).toBeLessThan(0.5); // dips toward the floor
  });

  it("rests fully lit (1) under reduceMotion", () => {
    for (const f of [0, 4, 8, 12]) expect(subagentPulseStep(f, { reduceMotion: true })).toBe(1);
  });
});

describe("toastEnvelope", () => {
  it("runs enter -> hold -> exit -> done with the expected alpha/offset shape", () => {
    // enter: alpha rises 0->1, offset falls 1->0
    const enter = toastEnvelope(0);
    expect(enter.phase).toBe("enter");
    expect(enter.alpha).toBeCloseTo(0, 6);
    expect(enter.offset).toBeCloseTo(1, 6);

    // a hold frame: fully shown, no slide
    const hold = toastEnvelope(6 + 2); // just inside the hold window
    expect(hold.phase).toBe("hold");
    expect(hold.alpha).toBe(1);
    expect(hold.offset).toBe(0);

    // done: past the whole lifetime
    const done = toastEnvelope(toastLifetimeFrames() + 5);
    expect(done.phase).toBe("done");
    expect(done.alpha).toBe(0);
  });

  it("keeps alpha and offset within [0,1] over the whole lifetime", () => {
    const total = toastLifetimeFrames();
    for (let f = 0; f <= total + 3; f += 1) {
      const e = toastEnvelope(f);
      expect(e.alpha).toBeGreaterThanOrEqual(0);
      expect(e.alpha).toBeLessThanOrEqual(1);
      expect(e.offset).toBeGreaterThanOrEqual(0);
      expect(e.offset).toBeLessThanOrEqual(1);
    }
  });

  it("fades alpha up during enter and down during exit", () => {
    // enter alpha increases
    let prev = -1;
    for (let f = 0; f <= 6; f += 1) {
      const a = toastEnvelope(f).alpha;
      expect(a).toBeGreaterThanOrEqual(prev - 1e-9);
      prev = a;
    }
    // exit alpha decreases
    const total = toastLifetimeFrames();
    prev = Number.POSITIVE_INFINITY;
    for (let f = total - 6; f < total; f += 1) {
      const a = toastEnvelope(f).alpha;
      expect(a).toBeLessThanOrEqual(prev + 1e-9);
      prev = a;
    }
  });

  it("honours a custom hold length in its lifetime", () => {
    expect(toastLifetimeFrames(0)).toBe(6 + 0 + 6);
    expect(toastLifetimeFrames(100)).toBe(6 + 100 + 6);
    const e = toastEnvelope(6 + 50, { holdFrames: 100 });
    expect(e.phase).toBe("hold");
  });

  it("collapses to a flat shown state (alpha 1, offset 0) under reduceMotion, then vanishes", () => {
    const total = toastLifetimeFrames();
    for (let f = 0; f < total; f += 1) {
      const e = toastEnvelope(f, { reduceMotion: true });
      expect(e.alpha).toBe(1);
      expect(e.offset).toBe(0);
    }
    expect(toastEnvelope(total, { reduceMotion: true }).alpha).toBe(0);
    expect(toastEnvelope(total, { reduceMotion: true }).phase).toBe("done");
  });

  it("tolerates negative and non-finite frames (rests at the entering edge)", () => {
    const e = toastEnvelope(-5);
    expect(e.phase).toBe("enter");
    expect(() => toastEnvelope(Number.NaN)).not.toThrow();
    expect(toastEnvelope(Number.NaN).phase).toBe("enter");
  });
});

describe("determinism", () => {
  it("every helper is a pure function of its inputs", () => {
    expect(spinnerFrame(5)).toBe(spinnerFrame(5));
    expect(modeSwitchStep(4)).toBe(modeSwitchStep(4));
    expect(findingFlashStep(3)).toBe(findingFlashStep(3));
    expect(subagentPulseStep(7)).toBe(subagentPulseStep(7));
    expect(toastEnvelope(9)).toEqual(toastEnvelope(9));
  });
});
