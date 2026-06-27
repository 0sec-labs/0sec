import { describe, expect, it } from "vitest";
import { TartVmLane, planSingleShardRun, type VmLaneConfig, type CommandRunner } from "./harness.js";
import type { FuzzInput } from "./input-gen.js";

const baseConfig: VmLaneConfig = {
  goldenImage: "macos-26-golden",
  guestBuild: "26.0 (25A000)",
  sharedDir: "/tmp/xnu-fuzz-shared",
};

function recorder(): { runner: CommandRunner; calls: { bin: string; args: string[] }[]; out: Record<string, string> } {
  const calls: { bin: string; args: string[] }[] = [];
  const out: Record<string, string> = {};
  const runner: CommandRunner = (bin, args) => {
    calls.push({ bin, args });
    // emulate panic harvest output keyed by the first matching command
    if (bin === "/bin/sh") return out["panic"] ?? "";
    return "";
  };
  return { runner, calls, out };
}

const oneCall: FuzzInput = {
  selector: 0,
  scalarInput: [1n],
  structureInput: new Uint8Array(0),
  scalarOutCnt: 0,
  structOutSize: 3176,
};

describe("TartVmLane — guardrail", () => {
  it("preflight refuses VM spawn unless allowVmSpawn is set", () => {
    const lane = new TartVmLane(baseConfig, recorder().runner);
    const pf = lane.preflight();
    expect(pf.ok).toBe(false);
    expect(pf.reason).toMatch(/RAM/);
  });

  it("cloneShard throws while spawn is disabled (host-safety)", () => {
    const lane = new TartVmLane(baseConfig, recorder().runner);
    expect(() => lane.cloneShard(0)).toThrow(/refused/);
  });

  it("runShard throws while spawn is disabled", () => {
    const lane = new TartVmLane(baseConfig, recorder().runner);
    expect(() =>
      lane.runShard({ shardId: 0, selectors: [0], privilege: "sandbox" }, [[oneCall]]),
    ).toThrow(/refused/);
  });
});

describe("TartVmLane — orchestration (allowVmSpawn, fake runner)", () => {
  it("runs clone → run → push → harvest → discard in order, no panic", () => {
    const rec = recorder();
    const lane = new TartVmLane({ ...baseConfig, allowVmSpawn: true }, rec.runner);
    const res = lane.runShard({ shardId: 3, selectors: [0, 1], privilege: "sandbox" }, [[oneCall]]);
    expect(res.panic.panicked).toBe(false);
    expect(res.programsRun).toBe(1);
    const bins = rec.calls.map((c) => `${c.bin} ${c.args[0]}`);
    expect(bins).toContain("tart clone");
    expect(bins).toContain("tart run");
    expect(bins).toContain("cp /dev/stdin");
    expect(bins).toContain("tart delete"); // discarded even on clean run
    // clone precedes delete
    expect(bins.indexOf("tart clone")).toBeLessThan(bins.lastIndexOf("tart delete"));
  });

  it("stops pushing further programs once a panic is harvested, still discards", () => {
    const rec = recorder();
    rec.out["panic"] = "panic(cpu 0): KASAN: heap-out-of-bounds ...";
    const lane = new TartVmLane({ ...baseConfig, allowVmSpawn: true }, rec.runner);
    const res = lane.runShard({ shardId: 1, selectors: [0], privilege: "sandbox" }, [
      [oneCall],
      [oneCall],
      [oneCall],
    ]);
    expect(res.panic.panicked).toBe(true);
    expect(res.panic.log).toMatch(/KASAN/);
    expect(res.programsRun).toBe(1); // broke after first program's panic
    expect(rec.calls.some((c) => c.bin === "tart" && c.args[0] === "delete")).toBe(true);
  });
});

describe("planSingleShardRun", () => {
  it("documents tart, a version-matched golden image, the opener, and the host-safety warning", () => {
    const plan = planSingleShardRun({ ...baseConfig, oracle: "kasan" });
    const prereq = plan.prerequisites.join("\n");
    expect(prereq).toMatch(/tart/);
    expect(prereq).toMatch(/macos-26-golden/);
    expect(prereq).toMatch(/26\.0 \(25A000\)/);
    expect(prereq).toMatch(/opener/);
    expect(prereq).toMatch(/KASAN/);
    expect(plan.steps.join("\n")).toMatch(/tart clone macos-26-golden/);
    expect(plan.warning).toMatch(/16GB dev host/);
    expect(plan.artifacts.programChannel).toContain("program.bin");
  });
});
