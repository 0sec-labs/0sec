import { describe, expect, it, vi } from "vitest";
import {
  KERNEL_RUN_PROGRAM_MAX_BYTES,
  KERNEL_RUN_TOOL_DEFINITION,
  executeKernelRun,
  kernelRunArgsSchema,
  validateKernelRunArgs,
} from "./kernel-run.js";
import type { Finding } from "@pwnkit/shared";
import type { KernelVerifyOracleResult } from "../../verify/kernel-verify-types.js";

function fakeFinding(): Finding {
  return {
    id: "f-1",
    templateId: "kernel-review-test",
    title: "tcp_input: missing skb_unshare before in-place decrypt",
    description: "static-only hypothesis",
    severity: "high",
    category: "use-after-free",
    status: "discovered",
    evidence: {
      request: "net/ipv4/tcp_input.c:1234",
      response: "static-only",
      analysis: "Found by review agent\nSubsystem: net/tcp\nHypothesis: true",
    },
    confidence: 0.4,
    timestamp: 0,
  };
}

describe("validateKernelRunArgs", () => {
  it("accepts a well-formed syz program", () => {
    const r = validateKernelRunArgs({
      program: "socket$inet(0x2, 0x1, 0x0)\nbind$inet(...)\n",
      program_lang: "syz",
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args.program_lang).toBe("syz");
      expect(r.args.expected_signature).toBeUndefined();
    }
  });

  it("accepts a C program with expected_signature", () => {
    const r = validateKernelRunArgs({
      program: "#include <unistd.h>\nint main(void){return 0;}",
      program_lang: "c",
      expected_signature: "  slab-use-after-free  ",
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args.expected_signature).toBe("slab-use-after-free");
    }
  });

  it("rejects when arguments are not an object", () => {
    expect(validateKernelRunArgs(null).ok).toBe(false);
    expect(validateKernelRunArgs("string").ok).toBe(false);
    expect(validateKernelRunArgs(42).ok).toBe(false);
  });

  it("rejects when program is missing or empty", () => {
    const a = validateKernelRunArgs({ program_lang: "syz" });
    expect(a.ok).toBe(false);
    if (!a.ok) expect(a.error).toMatch(/program.*non-empty/);
    const b = validateKernelRunArgs({ program: "", program_lang: "syz" });
    expect(b.ok).toBe(false);
  });

  it("rejects oversized programs", () => {
    const huge = "a".repeat(KERNEL_RUN_PROGRAM_MAX_BYTES + 1);
    const r = validateKernelRunArgs({ program: huge, program_lang: "c" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/exceeds/);
  });

  it("rejects invalid program_lang", () => {
    const r = validateKernelRunArgs({ program: "p", program_lang: "rust" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/program_lang/);
  });

  it("rejects non-string expected_signature", () => {
    const r = validateKernelRunArgs({
      program: "p",
      program_lang: "syz",
      expected_signature: 12,
    });
    expect(r.ok).toBe(false);
  });

  it("strips extra fields so they cannot leak downstream", () => {
    const r = validateKernelRunArgs({
      program: "p",
      program_lang: "syz",
      argv: ["rm", "-rf", "/"],
      cwd: "/tmp/escape",
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(Object.keys(r.args).sort()).toEqual(["program", "program_lang"]);
    }
  });
});

describe("kernelRunArgsSchema (AIxCC T9 structured output)", () => {
  it("rejects a missing program_lang with the contract message", () => {
    const r = validateKernelRunArgs({ program: "p" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/program_lang/);
  });

  it("collapses a whitespace-only expected_signature to undefined", () => {
    const r = validateKernelRunArgs({
      program: "p",
      program_lang: "syz",
      expected_signature: "   ",
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.args.expected_signature).toBeUndefined();
  });

  it("accepts a null expected_signature (model omission idiom)", () => {
    const r = validateKernelRunArgs({
      program: "p",
      program_lang: "c",
      expected_signature: null,
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.args.expected_signature).toBeUndefined();
  });

  it("the schema itself strips unknown keys (single source of truth)", () => {
    const parsed = kernelRunArgsSchema.safeParse({
      program: "p",
      program_lang: "syz",
      cwd: "/tmp/escape",
      argv: ["x"],
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(Object.keys(parsed.data).sort()).toEqual(["program", "program_lang"]);
    }
  });
});

describe("KERNEL_RUN_TOOL_DEFINITION", () => {
  it("declares program + program_lang as required", () => {
    expect(KERNEL_RUN_TOOL_DEFINITION.required).toEqual(["program", "program_lang"]);
  });
  it("constrains program_lang to syz|c via enum", () => {
    expect(KERNEL_RUN_TOOL_DEFINITION.parameters.program_lang?.enum).toEqual(["syz", "c"]);
  });
});

describe("executeKernelRun", () => {
  it("forwards validated args to the injected runner and returns its result", async () => {
    const oracle: KernelVerifyOracleResult = {
      ran: true,
      crashed: true,
      signatureMatched: true,
      detectedCrashType: "kasan-uaf",
      dmesgExcerpt: "[ 12.345 ] BUG: KASAN: slab-use-after-free",
      reason: "ok",
      oracleConfidence: 0.95,
      buildStatus: "hit",
    };
    const runner = vi.fn(async () => oracle);
    const result = await executeKernelRun({
      args: { program: "socket$inet(0x2,0x1,0x0)", program_lang: "syz" },
      finding: fakeFinding(),
      runner,
      kernelTree: "/tmp/linux",
    });
    expect(result.ok).toBe(true);
    expect(result.oracle).toBe(oracle);
    expect(runner).toHaveBeenCalledOnce();
    const call = runner.mock.calls[0]![0];
    expect(call.program).toBe("socket$inet(0x2,0x1,0x0)");
    expect(call.programLang).toBe("syz");
    expect(call.kernelTree).toBe("/tmp/linux");
  });

  it("captures runner exceptions as { ok: false, error }", async () => {
    const runner = vi.fn(async () => {
      throw new Error("qemu binary not found");
    });
    const result = await executeKernelRun({
      args: { program: "p", program_lang: "c" },
      finding: fakeFinding(),
      runner,
      kernelTree: "/tmp/linux",
    });
    expect(result.ok).toBe(false);
    expect(result.error).toBe("qemu binary not found");
  });
});
