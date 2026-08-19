import { describe, expect, it } from "vitest";
import type { CrashReport } from "@0sec/shared";
import type {
  NativeRuntime,
  NativeRuntimeResult,
} from "../runtime/types.js";
import {
  assessEscalation,
  shouldWeaponize,
  describeEscalation,
  maxCeiling,
  parseLlmEscalation,
  type ImpactCeiling,
} from "./escalation-gate.js";

function makeReport(overrides: Partial<CrashReport>): CrashReport {
  return {
    rawText: "",
    crashType: "unknown",
    faultingFunction: "unknown",
    callStack: [],
    subsystem: "unknown",
    ...overrides,
  };
}

/** A NativeRuntime stub that returns one fixed text block (or an error). */
function stubRuntime(reply: string, error?: string): NativeRuntime {
  return {
    type: "api",
    async isAvailable() {
      return true;
    },
    async executeNative(): Promise<NativeRuntimeResult> {
      return {
        content: error ? [] : [{ type: "text", text: reply }],
        stopReason: error ? "error" : "end_turn",
        durationMs: 1,
        ...(error ? { error } : {}),
      };
    },
  };
}

// A realistic slab-out-of-bounds READ splat whose call stack also contains a
// write/copy path on the SAME object — the SyzScope "low-risk read hides a
// write" shape. Grounded in the real KASAN report format.
const OOB_READ_ADJACENT_WRITE = `BUG: KASAN: slab-out-of-bounds in tipc_nl_compat_dumpit+0x42a/0x5b0
Read of size 84 of size 16 at addr ffff88810a3d2b30 by task syz-executor/4123

CPU: 0 PID: 4123 Comm: syz-executor Not tainted 6.1.0 #1
Call Trace:
 dump_stack_lvl+0x57/0x7d
 print_address_description+0x2c/0x230
 kasan_report+0x11c/0x130
 tipc_nl_compat_dumpit+0x42a/0x5b0
 __tipc_nl_compat_doit+0x110/0x2a0
 memcpy+0x20/0x60
 tipc_nl_compat_recv+0x2e0/0x430
 genl_rcv_msg+0x4f0/0x7c0

Allocated by task 4123:
 kasan_save_stack+0x1e/0x40
 __kmalloc+0x186/0x340
 tipc_nl_compat_recv+0x9c/0x430

The buggy address belongs to the object at ffff88810a3d2b20
 which belongs to the cache kmalloc-16 of size 16
`;

// A pure NULL pointer dereference — no allocation, no attacker-controlled
// object. The DoS-only baseline.
const NULL_DEREF = `BUG: kernel NULL pointer dereference, address: 0000000000000000
#PF: supervisor read access in kernel mode
RIP: 0010:tcp_v4_rcv+0x88/0x1f0
Call Trace:
 ip_protocol_deliver_rcu+0x4e/0x2c0
 ip_local_deliver+0x1c0/0x250
`;

describe("assessEscalation", () => {
  it("escalates an OOB-read adjacent to a write path to an oob-write ceiling", async () => {
    const verdict = await assessEscalation(
      makeReport({
        crashType: "kasan-oob",
        accessType: "read",
        accessSize: 84,
        faultingFunction: "tipc_nl_compat_dumpit",
        callStack: [
          "tipc_nl_compat_dumpit",
          "__tipc_nl_compat_doit",
          "memcpy",
          "tipc_nl_compat_recv",
        ],
        allocSite: "tipc_nl_compat_recv",
        slabCache: "kmalloc-16",
        rawText: OOB_READ_ADJACENT_WRITE,
      }),
    );

    // Splat alone only proves an info-leak (OOB read)...
    expect(verdict.splatCeiling).toBe("info-leak");
    // ...but the adjacent write/copy path escalates the ceiling to oob-write.
    expect(verdict.ceiling).toBe("oob-write");
    expect(verdict.escalated).toBe(true);
    expect(verdict.basis).toBe("heuristic");
    expect(verdict.llmUsed).toBe(false);
    expect(verdict.rationale.join(" ")).toMatch(/write path/i);
  });

  it("classifies a pure null-deref as dos-only with no escalation", async () => {
    const verdict = await assessEscalation(
      makeReport({
        crashType: "kasan-null",
        faultingFunction: "tcp_v4_rcv",
        callStack: ["tcp_v4_rcv", "ip_protocol_deliver_rcu", "ip_local_deliver"],
        rawText: NULL_DEREF,
      }),
    );

    expect(verdict.splatCeiling).toBe("dos-only");
    expect(verdict.ceiling).toBe("dos-only");
    expect(verdict.escalated).toBe(false);
    expect(verdict.basis).toBe("splat-only");
  });

  it("escalates an OOB-read next to a control object to uaf-control", async () => {
    const verdict = await assessEscalation(
      makeReport({
        crashType: "kasan-oob",
        accessType: "read",
        faultingFunction: "snd_seq_oss_synth_make_info",
        // call stack references an ops table → control-object cue
        callStack: ["snd_seq_oss_synth_make_info", "->ops", "file_operations"],
        rawText: "BUG: KASAN: slab-out-of-bounds ... file_operations ->ops",
      }),
    );
    expect(verdict.splatCeiling).toBe("info-leak");
    expect(verdict.ceiling).toBe("uaf-control");
    expect(verdict.escalated).toBe(true);
  });

  it("does not escalate a bare OOB-read with no adjacency cues", async () => {
    const verdict = await assessEscalation(
      makeReport({
        crashType: "kasan-oob",
        accessType: "read",
        faultingFunction: "some_pure_read",
        callStack: ["some_pure_read", "do_something_benign"],
        rawText: "BUG: KASAN: slab-out-of-bounds in some_pure_read",
      }),
    );
    expect(verdict.ceiling).toBe("info-leak");
    expect(verdict.escalated).toBe(false);
    expect(verdict.basis).toBe("splat-only");
  });

  it("keeps a write-UAF at the uaf-control ceiling (splat floor is already top)", async () => {
    const verdict = await assessEscalation(
      makeReport({
        crashType: "kasan-uaf",
        accessType: "write",
        allocSite: "a",
        freeSite: "f",
        rawText: "BUG: KASAN: slab-use-after-free Write of size 8",
      }),
    );
    expect(verdict.splatCeiling).toBe("uaf-control");
    expect(verdict.ceiling).toBe("uaf-control");
    expect(verdict.escalated).toBe(false);
  });
});

describe("assessEscalation — optional LLM pass", () => {
  it("lets the LLM raise the ceiling above the heuristic verdict", async () => {
    const runtime = stubRuntime(
      '{"ceiling": "uaf-control", "confidence": 0.8, "reason": "victim object embeds a callback pointer"}',
    );
    const verdict = await assessEscalation(
      makeReport({
        crashType: "kasan-oob",
        accessType: "read",
        callStack: ["benign_read"],
        rawText: "BUG: KASAN: slab-out-of-bounds in benign_read",
      }),
      { runtime },
    );
    // Heuristic alone would stay at info-leak; the LLM raises it.
    expect(verdict.llmUsed).toBe(true);
    expect(verdict.ceiling).toBe("uaf-control");
    expect(verdict.basis).toBe("llm");
    expect(verdict.rationale.join(" ")).toMatch(/callback pointer/);
  });

  it("never lets the LLM lower the splat-proven ceiling", async () => {
    const runtime = stubRuntime(
      '{"ceiling": "dos-only", "confidence": 0.9, "reason": "looks benign"}',
    );
    const verdict = await assessEscalation(
      makeReport({
        crashType: "kasan-uaf",
        accessType: "write",
        rawText: "BUG: KASAN: slab-use-after-free Write of size 8",
      }),
      { runtime },
    );
    expect(verdict.ceiling).toBe("uaf-control");
    expect(verdict.basis).not.toBe("llm");
  });

  it("falls back to the heuristic verdict when the LLM errors", async () => {
    const runtime = stubRuntime("", "runtime unavailable");
    const verdict = await assessEscalation(
      makeReport({
        crashType: "kasan-oob",
        accessType: "read",
        callStack: ["some_read", "memcpy"],
        rawText: "BUG: KASAN: slab-out-of-bounds Read",
      }),
      { runtime },
    );
    expect(verdict.ceiling).toBe("oob-write"); // heuristic escalation stands
    expect(verdict.basis).toBe("heuristic");
    expect(verdict.rationale.join(" ")).toMatch(/errored/i);
  });
});

describe("shouldWeaponize (verify → weaponize gate)", () => {
  it("filters out dos-only by default and admits everything escalatable", () => {
    const dos = { ceiling: "dos-only" } as ReturnType<typeof makeVerdict>;
    expect(shouldWeaponize(dos)).toBe(false);
    expect(shouldWeaponize(makeVerdict("info-leak"))).toBe(true);
    expect(shouldWeaponize(makeVerdict("oob-write"))).toBe(true);
    expect(shouldWeaponize(makeVerdict("uaf-control"))).toBe(true);
  });

  it("respects a stricter minimum ceiling", () => {
    expect(shouldWeaponize(makeVerdict("info-leak"), "oob-write")).toBe(false);
    expect(shouldWeaponize(makeVerdict("oob-write"), "oob-write")).toBe(true);
  });
});

describe("helpers", () => {
  it("maxCeiling returns the more dangerous ceiling", () => {
    expect(maxCeiling("info-leak", "uaf-control")).toBe("uaf-control");
    expect(maxCeiling("oob-write", "dos-only")).toBe("oob-write");
  });

  it("parseLlmEscalation tolerates markdown-fenced JSON", () => {
    const p = parseLlmEscalation(
      'Here is my verdict:\n```json\n{"ceiling": "oob-write", "confidence": 0.7, "reason": "ok"}\n```',
    );
    expect(p.ceiling).toBe("oob-write");
    expect(p.confidence).toBeCloseTo(0.7);
  });

  it("parseLlmEscalation returns null ceiling on garbage", () => {
    expect(parseLlmEscalation("no json here").ceiling).toBeNull();
    expect(parseLlmEscalation('{"ceiling": "bogus"}').ceiling).toBeNull();
  });

  it("describeEscalation renders the ceiling, floor, and rationale", () => {
    const lines = describeEscalation(makeVerdict("oob-write"));
    expect(lines[0]).toMatch(/Impact ceiling: oob-write/);
    expect(lines.some((l) => /floor/i.test(l))).toBe(true);
  });
});

function makeVerdict(ceiling: ImpactCeiling) {
  return {
    ceiling,
    confidence: 0.7,
    splatCeiling: "info-leak" as ImpactCeiling,
    escalated: ceiling !== "info-leak",
    basis: "heuristic" as const,
    llmUsed: false,
    rationale: ["test"],
  };
}
