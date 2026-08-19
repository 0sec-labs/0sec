/**
 * Offline unit tests for KCSAN race triage (issue #1112). The skeptic (LLM) and
 * the prover (QEMU) are both injected/stubbed — no VM, no model call.
 */

import { describe, it, expect } from "vitest";
import type { HuntVerifier } from "../stages/hunt-scan.js";
import type { ReproducerResult } from "./kernel-oracle.js";
import { parseKcsanReport, type KcsanRace } from "./kcsan-race.js";
import {
  kcsanRaceToBrief,
  kcsanRaceToFinding,
  raceWidenEnv,
  detectKasanSplat,
  makeRaceWidenProver,
  triageKcsanRace,
  DEFAULT_RACE_WIDEN_DELAY_MS,
} from "./kcsan-triage.js";

const REPORT = `BUG: KCSAN: data-race in crypto_aead_encrypt / crypto_larval_kill

write to 0xffff88810abcd000 of 8 bytes by task 400 on cpu 0:
 crypto_larval_kill+0x60/0x120 crypto/api.c:180
 crypto_alg_mod_lookup+0x2a0/0x400 crypto/api.c:280

read to 0xffff88810abcd000 of 8 bytes by task 401 on cpu 1:
 crypto_aead_encrypt+0x90/0x140 crypto/aead.c:90
 aead_recvmsg+0x300/0x600 crypto/algif_aead.c:200

value changed: 0xffff88810a000000 -> 0x0000000000000000
`;

function race(): KcsanRace {
  const r = parseKcsanReport(REPORT);
  if (!r) throw new Error("fixture failed to parse");
  return r;
}

const KASAN_DMESG = `
BUG: KASAN: slab-use-after-free in crypto_aead_encrypt+0x90/0x140
Read of size 8 at addr ffff88810abcd000 by task poc/401
`;

function reproResult(overrides: Partial<ReproducerResult> = {}): ReproducerResult {
  return { compiled: true, executed: true, output: "", dmesg: "", exitCode: 0, timedOut: false, ...overrides };
}

describe("kcsanRaceToBrief", () => {
  it("frames the specific race as a variant-hunt brief", () => {
    const brief = kcsanRaceToBrief(race());
    expect(brief.bugClass).toMatch(/data race/i);
    expect(brief.pattern).toContain("crypto_larval_kill");
    expect(brief.pattern).toContain("crypto_aead_encrypt");
    expect(brief.fixReference).toContain("KCSAN");
  });
});

describe("kcsanRaceToFinding", () => {
  it("builds a race-condition finding carrying both sites and the raw report", () => {
    const r = race();
    const finding = kcsanRaceToFinding(r, kcsanRaceToBrief(r));
    expect(finding.category).toBe("race-condition");
    expect(finding.title).toContain("crypto_aead_encrypt");
    expect(finding.description).toContain("crypto/api.c:180");
    expect(finding.evidence.response).toContain("KCSAN: data-race");
    expect(finding.id).not.toMatch(/[^A-Za-z0-9_-]/);
  });
});

describe("raceWidenEnv", () => {
  it("maps the racing PC (side A = first printed access block) to the kernel-vm-runner widen env", () => {
    const env = raceWidenEnv(race(), 50, 0x60);
    expect(env["0SEC_KERNEL_QEMU_WIDEN_SYMBOL"]).toBe("crypto_larval_kill");
    expect(env["0SEC_KERNEL_QEMU_WIDEN_OFFSET"]).toBe("0x60");
    expect(env["0SEC_KERNEL_QEMU_WIDEN_DELAY_MS"]).toBe("50");
  });
});

describe("detectKasanSplat", () => {
  it("recognises a KASAN splat and ignores clean output", () => {
    expect(detectKasanSplat(KASAN_DMESG)).toBeTruthy();
    expect(detectKasanSplat("no crash here")).toBeUndefined();
  });
});

describe("makeRaceWidenProver", () => {
  it("is inconclusive (not a false confirm) when no reproducer is supplied", async () => {
    const prover = makeRaceWidenProver(race(), { vmRunner: async () => reproResult() });
    const v = await prover(kcsanRaceToFinding(race(), kcsanRaceToBrief(race())), { path: "crypto/api.c" });
    expect(v.confirmed).toBe(false);
    expect(v.reason).toMatch(/no race-driving C reproducer/i);
  });

  it("confirms when the widened race becomes a KASAN splat, and sets/restores widen env", async () => {
    const before = process.env["0SEC_KERNEL_QEMU_WIDEN_SYMBOL"];
    let seenSymbol: string | undefined;
    const prover = makeRaceWidenProver(race(), {
      reproducer: "int main(){return 0;}",
      widenDelayMs: 50,
      vmRunner: async (report) => {
        seenSymbol = process.env["0SEC_KERNEL_QEMU_WIDEN_SYMBOL"];
        expect(report.crashType).toBe("kcsan-data-race");
        expect(report.reproducerLanguage).toBe("c");
        return reproResult({ dmesg: KASAN_DMESG });
      },
    });
    const v = await prover(kcsanRaceToFinding(race(), kcsanRaceToBrief(race())), { path: "crypto/api.c" });
    expect(v.confirmed).toBe(true);
    expect(v.reason).toMatch(/KASAN splat/i);
    // Env was set for the runner (widen at side A's PC = first printed block)...
    expect(seenSymbol).toBe("crypto_larval_kill");
    // ...and restored afterwards.
    expect(process.env["0SEC_KERNEL_QEMU_WIDEN_SYMBOL"]).toBe(before);
  });

  it("does not confirm a benign race (widened run, no splat)", async () => {
    const prover = makeRaceWidenProver(race(), {
      reproducer: "int main(){return 0;}",
      vmRunner: async () => reproResult({ dmesg: "clean boot, no splat" }),
    });
    const v = await prover(kcsanRaceToFinding(race(), kcsanRaceToBrief(race())), { path: "crypto/api.c" });
    expect(v.confirmed).toBe(false);
    expect(v.reason).toMatch(/no KASAN splat/i);
  });

  it("uses the default widen delay when unspecified", async () => {
    let seenDelay: string | undefined;
    const prover = makeRaceWidenProver(race(), {
      reproducer: "int main(){return 0;}",
      vmRunner: async () => {
        seenDelay = process.env["0SEC_KERNEL_QEMU_WIDEN_DELAY_MS"];
        return reproResult({ dmesg: KASAN_DMESG });
      },
    });
    await prover(kcsanRaceToFinding(race(), kcsanRaceToBrief(race())), { path: "crypto/api.c" });
    expect(seenDelay).toBe(String(DEFAULT_RACE_WIDEN_DELAY_MS));
  });
});

describe("triageKcsanRace (gate composition)", () => {
  const okSkeptic: HuntVerifier = async () => ({ confirmed: true, reason: "survived refute" });
  const refutingSkeptic: HuntVerifier = async () => ({ confirmed: false, reason: "benign counter race" });

  it("CONFIRMED when skeptic survives AND the prover gets a KASAN splat", async () => {
    const res = await triageKcsanRace({
      race: race(),
      sourceRoot: "/fake/linux",
      runtime: "api",
      skeptic: okSkeptic,
      prover: { reproducer: "int main(){return 0;}", vmRunner: async () => reproResult({ dmesg: KASAN_DMESG }) },
    });
    expect(res.confirmed).toBe(true);
    // composeGate reports a generic reason once every stage passes.
    expect(res.reason).toMatch(/gate stages/i);
    expect(res.brief.pattern).toContain("crypto_aead_encrypt");
    expect(res.finding.category).toBe("race-condition");
  });

  it("rejects at the skeptic (prover never runs) for a benign race", async () => {
    let proverRan = false;
    const res = await triageKcsanRace({
      race: race(),
      sourceRoot: "/fake/linux",
      runtime: "api",
      skeptic: refutingSkeptic,
      prover: {
        reproducer: "int main(){return 0;}",
        vmRunner: async () => {
          proverRan = true;
          return reproResult({ dmesg: KASAN_DMESG });
        },
      },
    });
    expect(res.confirmed).toBe(false);
    expect(res.reason).toMatch(/benign/i);
    expect(proverRan).toBe(false); // composeGate short-circuits on skeptic reject
  });

  it("survives the skeptic but stays unconfirmed when the prover finds no splat", async () => {
    const res = await triageKcsanRace({
      race: race(),
      sourceRoot: "/fake/linux",
      runtime: "api",
      skeptic: okSkeptic,
      prover: { reproducer: "int main(){return 0;}", vmRunner: async () => reproResult({ dmesg: "clean" }) },
    });
    expect(res.confirmed).toBe(false);
    expect(res.reason).toMatch(/no KASAN splat/i);
  });
});
