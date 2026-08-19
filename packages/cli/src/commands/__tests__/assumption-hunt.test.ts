/**
 * CLI flag-parsing tests for `0sec assumption-hunt` — focused on the race-capable
 * witness knobs (`--witness-mode` / `--witness-race-threads` / `--witness-race-iters`).
 * The engine (`runAssumptionHunt`) is MOCKED, so these assert ONLY that the CLI parses
 * the flags and threads the right `dynamicWitness` config into the engine — not that a
 * real race triggers (that needs a live KASAN VM, out of CI scope).
 */

import { describe, expect, it, vi } from "vitest";

const { runAssumptionHuntMock, makeSkepticVerifierMock } = vi.hoisted(() => ({
  runAssumptionHuntMock: vi.fn(),
  makeSkepticVerifierMock: vi.fn(() => vi.fn()),
}));

vi.mock("@0sec/core", () => ({
  runAssumptionHunt: runAssumptionHuntMock,
  makeSkepticVerifier: makeSkepticVerifierMock,
}));

const { runAssumptionHuntCli } = await import("../assumption-hunt.js");

/** Minimal engine result so the CLI's result-builder does not throw. */
function fakeRes() {
  return {
    modelPath: "/tmp/m.json",
    modelLoaded: true,
    model: { assumptions: [] },
    crossCheck: { kept: [], dropped: [], reclassified: [] },
    contexts: [],
    dualViewContexts: [],
    plan: { candidates: [] },
    hunt: undefined,
    witness: undefined,
  };
}

/** Grab the `dynamicWitness` config the CLI passed into the engine. */
async function witnessConfigFor(opts: Record<string, unknown>): Promise<Record<string, unknown> | undefined> {
  runAssumptionHuntMock.mockReset();
  runAssumptionHuntMock.mockResolvedValue(fakeRes());
  await runAssumptionHuntCli("/src", { files: "net/unix/af_unix.c", skipHunt: true, dynamicWitness: true, ...opts });
  const arg = runAssumptionHuntMock.mock.calls[0][0] as { dynamicWitness?: Record<string, unknown> };
  return arg.dynamicWitness;
}

describe("assumption-hunt CLI — race-capable witness flags", () => {
  it("--witness-mode race threads witnessMode:'race' into the engine", async () => {
    const dw = await witnessConfigFor({ witnessMode: "race" });
    expect(dw?.witnessMode).toBe("race");
  });

  it("--witness-mode single / auto both parse", async () => {
    expect((await witnessConfigFor({ witnessMode: "single" }))?.witnessMode).toBe("single");
    expect((await witnessConfigFor({ witnessMode: "auto" }))?.witnessMode).toBe("auto");
  });

  it("no --witness-mode leaves witnessMode unset (engine default 'auto')", async () => {
    const dw = await witnessConfigFor({});
    expect(dw?.witnessMode).toBeUndefined();
  });

  it("--witness-race-threads / --witness-race-iters build a raceConfig", async () => {
    const dw = await witnessConfigFor({ witnessRaceThreads: "8", witnessRaceIters: "500000" });
    expect(dw?.raceConfig).toEqual({ threads: 8, iters: 500000 });
  });

  it("a single race knob only sets that field", async () => {
    expect((await witnessConfigFor({ witnessRaceThreads: "6" }))?.raceConfig).toEqual({ threads: 6 });
    expect((await witnessConfigFor({ witnessRaceIters: "9999" }))?.raceConfig).toEqual({ iters: 9999 });
  });

  it("an invalid --witness-mode is rejected", async () => {
    runAssumptionHuntMock.mockResolvedValue(fakeRes());
    await expect(
      runAssumptionHuntCli("/src", { files: "a.c", skipHunt: true, dynamicWitness: true, witnessMode: "concurrent" }),
    ).rejects.toThrow(/invalid --witness-mode/);
  });
});
