import { describe, expect, it } from "vitest";
import type { CrashReport } from "@pwnkit/shared";
import {
  classifyKernelPrimitive,
  classifyPrimitiveFromDmesg,
  attemptControlDemo,
  exploitabilityAdjustedSeverity,
  describeKernelPrimitive,
  maxSeverity,
} from "./kernel-primitive.js";

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

describe("classifyKernelPrimitive", () => {
  it("labels a write UAF with known alloc+free as a high-exploitability object-overwrite", () => {
    const p = classifyKernelPrimitive(
      makeReport({
        crashType: "kasan-uaf",
        accessType: "write",
        accessSize: 8,
        allocSite: "nfsd_alloc",
        freeSite: "nfsd_free",
      }),
    );
    expect(p.kind).toBe("use-after-free");
    expect(p.control).toBe("write");
    expect(p.controlDemo.kind).toBe("object-overwrite");
    expect(p.controlDemo.demonstrated).toBe(false);
    expect(p.exploitability).toBeGreaterThanOrEqual(0.85);
    // alloc+free known boosts classification confidence above the base 0.8.
    expect(p.confidence).toBeGreaterThan(0.8);
    expect(p.objectHint).toBe("nfsd_alloc");
  });

  it("labels a read UAF as a lower-exploitability oob-read-leak", () => {
    const p = classifyKernelPrimitive(
      makeReport({ crashType: "kasan-uaf", accessType: "read" }),
    );
    expect(p.kind).toBe("use-after-free");
    expect(p.control).toBe("read");
    expect(p.controlDemo.kind).toBe("oob-read-leak");
    expect(p.exploitability).toBeLessThan(0.8);
  });

  it("distinguishes OOB write (write-what-where) from OOB read (leak)", () => {
    const write = classifyKernelPrimitive(
      makeReport({ crashType: "kasan-oob", accessType: "write" }),
    );
    expect(write.kind).toBe("out-of-bounds-write");
    expect(write.control).toBe("write");
    expect(write.controlDemo.kind).toBe("write-what-where");

    const read = classifyKernelPrimitive(
      makeReport({ crashType: "kasan-oob", accessType: "read" }),
    );
    expect(read.kind).toBe("out-of-bounds-read");
    expect(read.control).toBe("read");
    expect(read.controlDemo.kind).toBe("oob-read-leak");
    expect(write.exploitability).toBeGreaterThan(read.exploitability);
  });

  it("labels double-free as a free-confusion primitive", () => {
    const p = classifyKernelPrimitive(
      makeReport({ crashType: "kasan-double-free", freeSite: "kfree_skb" }),
    );
    expect(p.kind).toBe("double-free");
    expect(p.control).toBe("free");
    expect(p.controlDemo.kind).toBe("free-confusion");
  });

  it("treats null-deref / oops as low-exploitability DoS with no control demo", () => {
    const p = classifyKernelPrimitive(makeReport({ crashType: "kernel-oops" }));
    expect(p.kind).toBe("null-deref");
    expect(p.control).toBe("none");
    expect(p.controlDemo.kind).toBe("none");
    expect(p.exploitability).toBeLessThan(0.3);
  });
});

describe("exploitabilityAdjustedSeverity", () => {
  it("escalates a write primitive (exploitability>=0.8) to critical", () => {
    const p = classifyKernelPrimitive(
      makeReport({ crashType: "kasan-oob", accessType: "write" }),
    );
    expect(exploitabilityAdjustedSeverity("medium", p)).toBe("critical");
  });

  it("escalates a moderate primitive to at least high", () => {
    const p = classifyKernelPrimitive(
      makeReport({ crashType: "kasan-double-free" }),
    );
    expect(exploitabilityAdjustedSeverity("low", p)).toBe("high");
  });

  it("never downgrades below the base severity", () => {
    const p = classifyKernelPrimitive(makeReport({ crashType: "kernel-oops" }));
    expect(exploitabilityAdjustedSeverity("critical", p)).toBe("critical");
  });

  it("maxSeverity picks the higher rank", () => {
    expect(maxSeverity("low", "high")).toBe("high");
    expect(maxSeverity("critical", "medium")).toBe("critical");
  });
});

describe("attemptControlDemo", () => {
  it("flips demonstrated=true and bumps exploitability when a probe confirms control", async () => {
    const p = classifyKernelPrimitive(
      makeReport({ crashType: "kasan-uaf", accessType: "write" }),
    );
    const before = p.exploitability;
    const out = await attemptControlDemo(p, async () => ({
      controlled: true,
      evidence: "reclaimed object showed 0x4141 marker",
    }));
    expect(out.controlDemo.demonstrated).toBe(true);
    expect(out.controlDemo.evidence).toMatch(/0x4141/);
    expect(out.exploitability).toBeGreaterThan(before);
  });

  it("leaves demonstrated=false when the probe fails to confirm control", async () => {
    const p = classifyKernelPrimitive(
      makeReport({ crashType: "kasan-uaf", accessType: "write" }),
    );
    const out = await attemptControlDemo(p, async () => ({ controlled: false }));
    expect(out.controlDemo.demonstrated).toBe(false);
    expect(out.exploitability).toBe(p.exploitability);
  });
});

describe("classifyPrimitiveFromDmesg", () => {
  it("recovers a write-UAF primitive from raw KASAN dmesg", () => {
    const dmesg = [
      "BUG: KASAN: slab-use-after-free in tcp_close+0x10/0x20",
      "Write of size 8 at addr ffff8880aabbccdd by task poc/123",
      "Allocated by task 122:",
      "Freed by task 123:",
    ].join("\n");
    const p = classifyPrimitiveFromDmesg(dmesg, "kasan-uaf");
    expect(p.kind).toBe("use-after-free");
    expect(p.control).toBe("write");
    expect(p.exploitability).toBeGreaterThanOrEqual(0.85);
  });
});

describe("describeKernelPrimitive", () => {
  it("renders primitive, exploitability and a labelled control demo", () => {
    const p = classifyKernelPrimitive(
      makeReport({ crashType: "kasan-uaf", accessType: "write" }),
    );
    const lines = describeKernelPrimitive(p).join("\n");
    expect(lines).toMatch(/Primitive: use-after-free/);
    expect(lines).toMatch(/Exploitability:/);
    expect(lines).toMatch(/Control demo \[object-overwrite, candidate\]/);
  });
});
