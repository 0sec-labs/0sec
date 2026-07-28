/**
 * Tests for the per-finding PROVE stage adapter.
 *
 * The point of these tests is REACHABILITY plus the anti-cross-attribution
 * invariant: the stage must bind each finding's oracle to THAT finding's own
 * reproducer. Every test injects a fake oracle factory — no QEMU is ever spawned
 * (the `makeOracles` seam exists precisely so this file stays offline).
 */

import { describe, expect, it } from "vitest";
import type { Finding } from "@pwnkit/shared";
import type { HuntCandidate } from "../stages/hunt-scan.js";
import {
  makeHuntProveStage,
  defaultReproducerFor,
  defaultDmesgFor,
  type ProveOracleInput,
  type ProveOracles,
} from "./hunt-prove-stage.js";
import { makeDiversifyOracle, type ExploitabilityVerdict } from "./exploitability-upgrade.js";

// ── Fixtures ──────────────────────────────────────────────────────────────────

/**
 * The finding's OWN splat is a benign out-of-bounds READ. This matters: the
 * GREBE diversify half only runs when the baseline is still benign (an already
 * proven write needs no diversification), so a read baseline is what exercises
 * the oracle path at all.
 */
const READ_SPLAT =
  "BUG: KASAN: slab-out-of-bounds in mwifiex_process_beacon+0x1ba/0x210\nRead of size 8 at addr ...";
/** What a MUTATED re-schedule surfaces — the upgrade the oracle is looking for. */
const UAF_WRITE_SPLAT =
  "BUG: KASAN: use-after-free in bar+0x5/0x20\nWrite of size 8 at addr ...";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    templateId: "kernel-oob",
    title: "mwifiex beacon OOB read",
    description: "",
    severity: "medium",
    category: "out-of-bounds-read" as Finding["category"],
    status: "open" as Finding["status"],
    evidence: {
      request: "```c\nint main(){ return 0; }\n```",
      response: READ_SPLAT,
      analysis: "",
    } as Finding["evidence"],
    ...overrides,
  } as Finding;
}

const CANDIDATE: HuntCandidate = { path: "drivers/foo/bar.c" };

/**
 * The REAL diversify oracle driven by a FAKE VM runner: every mutated boot
 * reports a UAF-write splat, so the oracle genuinely computes `upgraded === true`
 * off a benign read baseline. Using the real oracle (not a stubbed verdict) keeps
 * these tests honest about the logic the stage delegates to; only the VM is fake.
 */
function upgradingOracles(): ProveOracles {
  return { diversify: makeDiversifyOracle(async () => ({ dmesg: UAF_WRITE_SPLAT }), { boots: 2 }) };
}

/** Same seam, but every boot stays at the benign read baseline — no upgrade. */
function benignOracles(): ProveOracles {
  return { diversify: makeDiversifyOracle(async () => ({ dmesg: READ_SPLAT }), { boots: 2 }) };
}

// ── Extraction defaults ───────────────────────────────────────────────────────

describe("defaultReproducerFor / defaultDmesgFor", () => {
  it("pulls the first fenced C block out of the evidence", () => {
    expect(defaultReproducerFor(makeFinding())).toBe("int main(){ return 0; }");
  });

  it("returns undefined when there is no ```c block (prose is not a reproducer)", () => {
    const f = makeFinding({
      evidence: { request: "just prose", response: READ_SPLAT, analysis: "" } as Finding["evidence"],
    });
    expect(defaultReproducerFor(f)).toBeUndefined();
  });

  it("reads the splat from the evidence prose", () => {
    expect(defaultDmesgFor(makeFinding())).toContain("KASAN");
  });
});

// ── Reachability: the stage runs and stamps a verdict ─────────────────────────

describe("makeHuntProveStage — reachable and stamps a verdict", () => {
  it("runs the oracle and reports the exploitability verdict without rejecting", async () => {
    const verdicts: ExploitabilityVerdict[] = [];
    const stage = makeHuntProveStage({
      makeOracles: () => upgradingOracles(),
      onVerdict: (_f, _c, v) => verdicts.push(v),
    });

    const res = await stage(makeFinding(), CANDIDATE);

    expect(res.confirmed).toBe(true);
    expect(res.reason).toContain("maxObserved=uaf-write");
    expect(verdicts).toHaveLength(1);
    expect(verdicts[0]!.upgraded).toBe(true);
  });

  it("passes a finding through unproven when it has no bootable reproducer", async () => {
    let oracleBuilt = false;
    const stage = makeHuntProveStage({
      makeOracles: () => {
        oracleBuilt = true;
        return upgradingOracles();
      },
    });

    const f = makeFinding({
      evidence: { request: "no code here", response: READ_SPLAT, analysis: "" } as Finding["evidence"],
    });
    const res = await stage(f, CANDIDATE);

    // Honest: a bug we cannot boot is still a bug.
    expect(res.confirmed).toBe(true);
    expect(res.reason).toContain("no bootable reproducer");
    expect(oracleBuilt).toBe(false);
  });
});

// ── The invariant this module exists for ──────────────────────────────────────

describe("makeHuntProveStage — binds each finding to its OWN reproducer", () => {
  it("never cross-attributes one finding's reproducer to another", async () => {
    const seen: ProveOracleInput[] = [];
    const stage = makeHuntProveStage({
      makeOracles: (input) => {
        seen.push(input);
        return upgradingOracles();
      },
    });

    const a = makeFinding({
      id: "a",
      evidence: { request: "```c\nAAA_REPRO\n```", response: READ_SPLAT, analysis: "" } as Finding["evidence"],
    });
    const b = makeFinding({
      id: "b",
      evidence: { request: "```c\nBBB_REPRO\n```", response: READ_SPLAT, analysis: "" } as Finding["evidence"],
    });

    await stage(a, CANDIDATE);
    await stage(b, CANDIDATE);

    expect(seen).toHaveLength(2);
    expect(seen[0]!.reproducer).toBe("AAA_REPRO");
    expect(seen[1]!.reproducer).toBe("BBB_REPRO");
    // And the report handed to the oracle carries that same reproducer.
    expect(seen[0]!.report.reproducer).toBe("AAA_REPRO");
    expect(seen[1]!.report.reproducer).toBe("BBB_REPRO");
  });

  it("parses the splat into the report the oracle reads", async () => {
    const seen: ProveOracleInput[] = [];
    const stage = makeHuntProveStage({
      makeOracles: (input) => {
        seen.push(input);
        return upgradingOracles();
      },
    });

    await stage(makeFinding(), CANDIDATE);

    // Parsed from the finding's OWN splat (the benign read baseline), not from
    // whatever the mutated boots later surface.
    expect(seen[0]!.report.crashType).toBe("kasan-oob");
    expect(seen[0]!.report.accessType).toBe("read");
    expect(seen[0]!.report.accessSize).toBe(8);
    expect(seen[0]!.report.freeSite).toBeUndefined();
  });
});

// ── Weaponize budget gate reachability ────────────────────────────────────────

describe("makeHuntProveStage — gates the weaponize budget", () => {
  it("invokes the weaponize hook when the oracle proves an upgrade", async () => {
    const weaponized: string[] = [];
    const stage = makeHuntProveStage({
      makeOracles: () => upgradingOracles(),
      weaponize: async (f) => {
        weaponized.push(f.id);
      },
    });

    await stage(makeFinding(), CANDIDATE);
    expect(weaponized).toEqual(["f1"]);
  });

  it("does NOT spend the weaponize budget on a benign, non-upgrading bug", async () => {
    const weaponized: string[] = [];
    const stage = makeHuntProveStage({
      // Benign: the diversify oracle never sees anything worse than an oob-read.
      makeOracles: () => benignOracles(),
      weaponize: async (f) => {
        weaponized.push(f.id);
      },
    });

    const res = await stage(makeFinding(), CANDIDATE);
    expect(res.confirmed).toBe(true);
    expect(weaponized).toEqual([]);
  });
});
