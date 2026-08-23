import { describe, expect, it } from "vitest";

import {
  DEFAULT_TOAST_ENVELOPE,
  isToastDone,
  linearRamp,
  resolveEnvelope,
  showToast,
  smoothstepRamp,
  toastDurationMs,
  toastFrameAt,
  type ToastConfig,
} from "./toast-logic.js";

const T0 = 1000;
const at = (offset: number) => T0 + offset;

describe("showToast", () => {
  it("records the message and the show time", () => {
    expect(showToast("copied 5 bytes", T0)).toEqual({ message: "copied 5 bytes", shownAt: T0 });
  });

  it("coerces a nullish message to an empty string and a bad clock to 0", () => {
    expect(showToast(null, T0)).toEqual({ message: "", shownAt: T0 });
    expect(showToast("x", Number.NaN)).toEqual({ message: "x", shownAt: 0 });
  });
});

describe("ramps", () => {
  it("linearRamp clamps to 0..1", () => {
    expect(linearRamp(-1)).toBe(0);
    expect(linearRamp(0.5)).toBe(0.5);
    expect(linearRamp(2)).toBe(1);
    expect(linearRamp(Number.NaN)).toBe(0);
  });

  it("smoothstepRamp is a symmetric S with midpoint 0.5", () => {
    expect(smoothstepRamp(0)).toBe(0);
    expect(smoothstepRamp(0.5)).toBeCloseTo(0.5, 10);
    expect(smoothstepRamp(1)).toBe(1);
    expect(smoothstepRamp(0.25)).toBeCloseTo(0.15625, 10);
  });
});

describe("resolveEnvelope / toastDurationMs", () => {
  it("uses the default envelope when unconfigured", () => {
    expect(resolveEnvelope()).toEqual(DEFAULT_TOAST_ENVELOPE);
    expect(toastDurationMs()).toBe(120 + 1500 + 180);
  });

  it("merges partial overrides", () => {
    expect(resolveEnvelope({ envelope: { holdMs: 500 } })).toEqual({
      enterMs: 120,
      holdMs: 500,
      exitMs: 180,
    });
  });

  it("reduceMotion zeroes the enter/exit ramps but keeps the hold", () => {
    expect(resolveEnvelope({ reduceMotion: true })).toEqual({
      enterMs: 0,
      holdMs: 1500,
      exitMs: 0,
    });
    expect(toastDurationMs({ reduceMotion: true })).toBe(1500);
  });
});

describe("toastFrameAt", () => {
  it("is hidden with no active show", () => {
    expect(toastFrameAt(null, T0)).toEqual({
      phase: "hidden",
      message: "",
      progress: 0,
      visible: false,
    });
  });

  it("walks enter -> hold -> exit -> hidden with a linear ramp", () => {
    const show = showToast("done", T0);
    const cfg: ToastConfig = { easing: linearRamp };

    // enter: 0..120
    expect(toastFrameAt(show, at(0), cfg)).toMatchObject({ phase: "enter", progress: 0 });
    expect(toastFrameAt(show, at(60), cfg)).toMatchObject({ phase: "enter", progress: 0.5 });

    // hold: 120..1620
    expect(toastFrameAt(show, at(120), cfg)).toMatchObject({ phase: "hold", progress: 1 });
    expect(toastFrameAt(show, at(1000), cfg)).toMatchObject({ phase: "hold", progress: 1 });

    // exit: 1620..1800 (progress ramps back down)
    expect(toastFrameAt(show, at(1620), cfg)).toMatchObject({ phase: "exit", progress: 1 });
    expect(toastFrameAt(show, at(1710), cfg)).toMatchObject({ phase: "exit", progress: 0.5 });

    // hidden: >= 1800, message retained
    expect(toastFrameAt(show, at(1800), cfg)).toEqual({
      phase: "hidden",
      message: "done",
      progress: 0,
      visible: false,
    });
    expect(toastFrameAt(show, at(999999), cfg)).toMatchObject({ phase: "hidden", visible: false });
  });

  it("keeps the message on every visible frame", () => {
    const show = showToast("Copied 42 bytes", T0);
    expect(toastFrameAt(show, at(60)).message).toBe("Copied 42 bytes");
    expect(toastFrameAt(show, at(500)).message).toBe("Copied 42 bytes");
  });

  it("under reduceMotion, shows instantly at full strength then hides", () => {
    const show = showToast("done", T0);
    const cfg: ToastConfig = { reduceMotion: true };

    expect(toastFrameAt(show, at(0), cfg)).toMatchObject({ phase: "hold", progress: 1, visible: true });
    expect(toastFrameAt(show, at(1499), cfg)).toMatchObject({ phase: "hold", progress: 1 });
    expect(toastFrameAt(show, at(1500), cfg)).toMatchObject({ phase: "hidden", visible: false });
  });

  it("treats a now before the show time as the start of the envelope", () => {
    const show = showToast("x", T0);
    expect(toastFrameAt(show, T0 - 500)).toMatchObject({ phase: "enter", visible: true });
  });
});

describe("isToastDone", () => {
  it("is done for a null show and once the full envelope elapses", () => {
    const show = showToast("x", T0);
    expect(isToastDone(null, T0)).toBe(true);
    expect(isToastDone(show, at(1799))).toBe(false);
    expect(isToastDone(show, at(1800))).toBe(true);
  });

  it("uses the reduced duration under reduceMotion", () => {
    const show = showToast("x", T0);
    expect(isToastDone(show, at(1499), { reduceMotion: true })).toBe(false);
    expect(isToastDone(show, at(1500), { reduceMotion: true })).toBe(true);
  });
});
