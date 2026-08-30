import { describe, expect, it } from "vitest";

import type { LensSynthesisResult } from "@0sec/core";

import type {
  LensSynthWatchDeps,
  LensSynthWatchOptions,
} from "../commands/lens-synth.js";
import { DEFAULT_SETTINGS, type TuiSettings } from "./settings.js";
import {
  TUI_LENS_SYNTH_INPUT_ENV,
  createTuiLensEvolutionController,
  tuiLensEvolutionStatusLabel,
  tuiLensSynthesisInputPath,
} from "./lens-evolution.js";

const PROMOTED_RESULT: LensSynthesisResult = {
  candidatesCaptured: 1,
  clusters: 1,
  synthesized: [],
  validations: [],
  registered: [{
    id: "ssrf-url-fetch",
    uid: "appsec/ssrf-url-fetch",
    validatedAt: "2026-08-30T00:00:00.000Z",
    missRefs: ["app.py:7"],
  }],
  rejected: [],
  warnings: [],
};

describe("TUI lens evolution controller", () => {
  it("stays inert until the Security setting explicitly enables automatic evaluation", () => {
    let watchCalls = 0;
    const controller = createTuiLensEvolutionController({
      settings: () => DEFAULT_SETTINGS,
      subscribeSettings: () => () => {},
      watch: async () => { watchCalls += 1; },
    });

    expect(watchCalls).toBe(0);
    expect(controller.getStatus()).toMatchObject({ phase: "disabled", promote: false });
    expect(tuiLensEvolutionStatusLabel(controller.getStatus())).toBeUndefined();
    controller.stop();
  });

  it("starts, reports, reconfigures, and stops the configured TUI worker", async () => {
    let settings: TuiSettings = {
      ...DEFAULT_SETTINGS,
      autoEvolveFinderLenses: true,
      autoPromoteFinderLenses: false,
    };
    let notifySettings: ((next: TuiSettings) => void) | undefined;
    const calls: Array<{ options: LensSynthWatchOptions; deps: LensSynthWatchDeps }> = [];
    const watcher = async (options: LensSynthWatchOptions, deps: LensSynthWatchDeps): Promise<void> => {
      calls.push({ options, deps });
      await new Promise<void>((resolve) => {
        deps.signal?.addEventListener("abort", () => resolve(), { once: true });
      });
    };
    const controller = createTuiLensEvolutionController({
      settings: () => settings,
      subscribeSettings: (listener) => {
        notifySettings = listener;
        return () => { notifySettings = undefined; };
      },
      env: { [TUI_LENS_SYNTH_INPUT_ENV]: "/tmp/curated-misses.json" },
      watch: watcher,
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.options).toMatchObject({
      missInput: "/tmp/curated-misses.json",
      promote: false,
      pollIntervalMs: 2000,
    });
    expect(tuiLensEvolutionStatusLabel(controller.getStatus())).toBe("evolve:dry-run");

    calls[0]?.deps.onError?.(Object.assign(new Error("missing"), { code: "ENOENT" }));
    expect(controller.getStatus()).toMatchObject({ phase: "waiting_input" });
    expect(tuiLensEvolutionStatusLabel(controller.getStatus())).toBe("evolve:waiting input");

    settings = { ...settings, autoPromoteFinderLenses: true };
    notifySettings?.(settings);
    await Promise.resolve();
    expect(calls).toHaveLength(2);
    expect(calls[0]?.deps.signal?.aborted).toBe(true);
    expect(calls[1]?.options.promote).toBe(true);

    calls[1]?.deps.onResult?.(PROMOTED_RESULT);
    expect(controller.getStatus()).toMatchObject({ phase: "promoted", promote: true });
    expect(tuiLensEvolutionStatusLabel(controller.getStatus())).toBe("evolve:promoted");

    settings = { ...settings, autoEvolveFinderLenses: false };
    notifySettings?.(settings);
    expect(calls[1]?.deps.signal?.aborted).toBe(true);
    expect(controller.getStatus()).toMatchObject({ phase: "disabled" });
    controller.stop();
  });

  it("uses the documented user-state inbox by default", () => {
    expect(tuiLensSynthesisInputPath("/tmp/0sec-home")).toBe(
      "/tmp/0sec-home/.0sec/lens-synthesis/miss-input.json",
    );
  });
});
