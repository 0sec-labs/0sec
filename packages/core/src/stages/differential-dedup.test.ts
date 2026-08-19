/**
 * Offline unit tests for the differential dedup gate + stack-trace crash
 * signatures (issue #1501, ATLANTIS). Everything is pure or injected (a fake
 * reproducer), so these run under plain `vitest run` with no VM, no LLM, no
 * clone.
 */

import { describe, it, expect } from "vitest";
import type { Finding } from "@0sec/shared";
import {
  normalizeFrame,
  crashSignatureFromText,
  signatureKey,
  sameCrash,
  dedupByCrashSignature,
  dedupFindingsByCrashSignature,
  makeDifferentialGate,
  type CrashRunResult,
} from "./differential-dedup.js";
import type { HuntCandidate } from "./hunt-scan.js";

// ── Fixtures ──────────────────────────────────────────────────────────────────

/** A KASAN UAF splat faulting in tipc_conn_close, freed in tipc_conn_kref_release. */
const UAF_A = `
==================================================================
BUG: KASAN: use-after-free in tipc_conn_close+0x1a4/0x200 net/tipc/topsrv.c:174
Read of size 8 at addr ffff88810a3c1a40 by task kworker/0:2/123

Call Trace:
 dump_stack+0x1b/0x30
 print_report+0x171/0x4c0
 kasan_report+0xd1/0x110
 tipc_conn_close+0x1a4/0x200 net/tipc/topsrv.c:174
 tipc_conn_recv_work+0x2ab/0x400 net/tipc/topsrv.c:210
 process_one_work+0x5a5/0xa10

Allocated by task 120:
 kasan_save_stack+0x1c/0x40
 __kmalloc+0x1a0/0x2c0
 tipc_conn_alloc+0x4a/0x220 net/tipc/topsrv.c:110

Freed by task 121:
 kasan_save_stack+0x1c/0x40
 kfree+0xba/0x1c0
 tipc_conn_kref_release+0x88/0x120 net/tipc/topsrv.c:150

The buggy address belongs to the object at ffff88810a3c1a00
==================================================================
`;

/** SAME bug as UAF_A but different build offsets and extra infra plumbing at the top. */
const UAF_A_REBUILT = `
BUG: KASAN: use-after-free in tipc_conn_close+0x2c8/0x310 net/tipc/topsrv.c:174
Read of size 8 at addr ffff88810bbb2200 by task kworker/1:0/99

Call Trace:
 __dump_stack+0x9/0x10
 kasan_report+0xff/0x140
 tipc_conn_close.cold+0x2c8/0x310 net/tipc/topsrv.c:174
 tipc_conn_recv_work+0x3aa/0x520 net/tipc/topsrv.c:210
 process_one_work+0x611/0xb00

Allocated by task 200:
 __kmalloc+0x111/0x200
 tipc_conn_alloc+0x51/0x240 net/tipc/topsrv.c:110

Freed by task 201:
 kfree+0xc1/0x1d0
 tipc_conn_kref_release+0x91/0x140 net/tipc/topsrv.c:150

The buggy address belongs to the object at ffff88810bbb2200
`;

/** A DIFFERENT bug: KASAN OOB, different subsystem entirely. */
const OOB_B = `
BUG: KASAN: slab-out-of-bounds in hci_le_meta_evt+0x3c0/0x9a0 net/bluetooth/hci_event.c:6301
Read of size 4 at addr ffff88810c0a1288 by task kworker/2:1/77

Call Trace:
 kasan_report+0xd1/0x110
 hci_le_meta_evt+0x3c0/0x9a0 net/bluetooth/hci_event.c:6301
 hci_event_packet+0x8aa/0x1200 net/bluetooth/hci_event.c:7444
`;

/** A KCSAN data-race (its BUG: header must NOT be swallowed by the generic oops matcher). */
const RACE_C = `
==================================================================
BUG: KCSAN: data-race in ext4_free_inode / ext4_mark_iloc_dirty

write to 0xffff8881033c1a40 of 8 bytes by task 6398 on cpu 0:
 ext4_mark_iloc_dirty+0x2d4/0x680 fs/ext4/inode.c:5876
 __ext4_mark_inode_dirty+0x1a0/0x4c0 fs/ext4/inode.c:6132

read to 0xffff8881033c1a40 of 8 bytes by task 6403 on cpu 1:
 ext4_free_inode+0x33c/0x8d0 fs/ext4/ialloc.c:320

value changed: 0x0000000000000001 -> 0x0000000000000000
==================================================================
`;

function findingWith(id: string, report: string): Finding {
  return {
    id,
    templateId: "kernel-test",
    title: id,
    description: "",
    severity: "high",
    category: "use-after-free",
    status: "discovered",
    evidence: { request: "N/A", response: report, analysis: "" },
  } as Finding;
}

const CAND: HuntCandidate = { path: "net/tipc/topsrv.c" };

// ── normalizeFrame ──────────────────────────────────────────────────────────

describe("normalizeFrame", () => {
  it("strips address offsets, module tags, file:line, and compiler clones", () => {
    expect(normalizeFrame("tipc_conn_close+0x1a4/0x200 net/tipc/topsrv.c:174")).toBe("tipc_conn_close");
    expect(normalizeFrame("hci_le_meta_evt+0x3c0/0x9a0 [bluetooth]")).toBe("hci_le_meta_evt");
    expect(normalizeFrame("tipc_conn_close.cold+0x2c8/0x310")).toBe("tipc_conn_close");
    expect(normalizeFrame("foo.part.0+0x10/0x20")).toBe("foo");
    expect(normalizeFrame("? bar+0x1/0x2")).toBe("bar");
  });
});

// ── Signature identity / separation ─────────────────────────────────────────

describe("crash signatures", () => {
  it("gives the SAME signature to the same UAF across different builds/offsets", () => {
    const a = crashSignatureFromText(UAF_A)!;
    const b = crashSignatureFromText(UAF_A_REBUILT)!;
    expect(a.sanitizerClass).toBe("kasan-uaf");
    expect(a.allocSite).toBe("tipc_conn_alloc");
    expect(a.freeSite).toBe("tipc_conn_kref_release");
    expect(sameCrash(a, b)).toBe(true);
    expect(signatureKey(a)).toBe(signatureKey(b));
  });

  it("separates a UAF from an OOB and from a race (per-class scoping)", () => {
    const uaf = crashSignatureFromText(UAF_A)!;
    const oob = crashSignatureFromText(OOB_B)!;
    const race = crashSignatureFromText(RACE_C)!;
    expect(oob.sanitizerClass).toBe("kasan-oob");
    expect(race.sanitizerClass).toBe("kcsan-race");
    expect(sameCrash(uaf, oob)).toBe(false);
    expect(sameCrash(uaf, race)).toBe(false);
  });

  it("parses a KCSAN race and makes its signature order-independent", () => {
    const race = crashSignatureFromText(RACE_C)!;
    expect(race.racePair).toEqual(["ext4_free_inode", "ext4_mark_iloc_dirty"]); // sorted
  });

  it("returns undefined on text with no recognizable crash", () => {
    expect(crashSignatureFromText("just some log lines, nothing here")).toBeUndefined();
  });
});

// ── Dedup ───────────────────────────────────────────────────────────────────

describe("dedupByCrashSignature", () => {
  it("collapses same-signature crashes and keeps distinct ones", () => {
    const items = [
      { id: "a1", text: UAF_A },
      { id: "a2", text: UAF_A_REBUILT }, // dup of a1
      { id: "b", text: OOB_B },
      { id: "c", text: RACE_C },
    ];
    const { groups, undeduped } = dedupByCrashSignature(items, (i) => i.text);
    expect(undeduped).toHaveLength(0);
    expect(groups).toHaveLength(3); // one UAF group (2 members), one OOB, one race
    const uafGroup = groups.find((g) => g.signature.sanitizerClass === "kasan-uaf")!;
    expect(uafGroup.members.map((m) => m.id)).toEqual(["a1", "a2"]);
    expect(uafGroup.representative.id).toBe("a1");
  });

  it("dedups Findings via evidence.response and reports the dropped duplicates", () => {
    const findings = [
      findingWith("f-uaf-1", UAF_A),
      findingWith("f-uaf-2", UAF_A_REBUILT),
      findingWith("f-oob", OOB_B),
    ];
    const { unique, duplicates } = dedupFindingsByCrashSignature(findings);
    expect(unique.map((f) => f.id).sort()).toEqual(["f-oob", "f-uaf-1"]);
    expect(duplicates).toHaveLength(1);
    expect(duplicates[0].finding.id).toBe("f-uaf-2");
    expect(duplicates[0].duplicateOf.id).toBe("f-uaf-1");
  });
});

// ── Differential gate ─────────────────────────────────────────────────────────

/** Build a fake reproducer from a per-version outcome map, recording call order. */
function fakeReproducer(
  outcomes: Partial<Record<"base" | "target", CrashRunResult>>,
  calls: string[] = [],
) {
  return async (_f: Finding, _c: HuntCandidate, version: "base" | "target"): Promise<CrashRunResult> => {
    calls.push(version);
    return outcomes[version] ?? { crashed: false };
  };
}

describe("makeDifferentialGate", () => {
  const finding = findingWith("f", UAF_A);

  it("CONFIRMS when target crashes and base is clean (bug lives in the changed code)", async () => {
    const gate = makeDifferentialGate({
      reproduce: fakeReproducer({ target: { crashed: true, report: UAF_A }, base: { crashed: false } }),
    });
    const v = await gate(finding, CAND);
    expect(v.confirmed).toBe(true);
    expect(v.reason).toMatch(/BASE clean/);
  });

  it("REJECTS when the reproducer crashes on the base too (pre-existing bug)", async () => {
    const gate = makeDifferentialGate({
      reproduce: fakeReproducer({ target: { crashed: true, report: UAF_A }, base: { crashed: true, report: UAF_A_REBUILT } }),
    });
    const v = await gate(finding, CAND);
    expect(v.confirmed).toBe(false);
    expect(v.reason).toMatch(/BASE build too/);
  });

  it("REJECTS (short-circuit) when the target does not crash, without paying for the base build", async () => {
    const calls: string[] = [];
    const gate = makeDifferentialGate({ reproduce: fakeReproducer({ target: { crashed: false } }, calls) });
    const v = await gate(finding, CAND);
    expect(v.confirmed).toBe(false);
    expect(v.reason).toMatch(/did not crash on the TARGET/);
    expect(calls).toEqual(["target"]); // base build never attempted
  });

  it("CONFIRMS when base crashes with a DIFFERENT signature (unrelated pre-existing bug)", async () => {
    const gate = makeDifferentialGate({
      reproduce: fakeReproducer({ target: { crashed: true, report: UAF_A }, base: { crashed: true, report: OOB_B } }),
    });
    const v = await gate(finding, CAND);
    expect(v.confirmed).toBe(true);
    expect(v.reason).toMatch(/unrelated/);
  });

  it("with requireSameSignature=false, ANY base crash vetoes", async () => {
    const gate = makeDifferentialGate({
      requireSameSignature: false,
      reproduce: fakeReproducer({ target: { crashed: true, report: UAF_A }, base: { crashed: true, report: OOB_B } }),
    });
    const v = await gate(finding, CAND);
    expect(v.confirmed).toBe(false);
  });
});
