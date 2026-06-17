import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyVerificationToFinding,
  tier1VerdictToOracleResult,
  verifyStaticKernelFinding,
  type KernelVerifyAgentInvoker,
  type KernelVerifyOracleResult,
  type KernelVerifyRunner,
} from "./kernel-verify.js";
import {
  buildKernelVerifyInitialPrompt,
  buildKernelVerifySystemPrompt,
  extractKernelFindingMetadata,
} from "./kernel-prompts.js";
import type { Finding } from "@pwnkit/shared";
import type { NativeContentBlock } from "../runtime/types.js";

function staticKernelFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "00000000-finding-0001",
    templateId: "kernel-review-test",
    title: "tcp_input: signed/unsigned compare in copy_from_user length check",
    description: "static-only kernel-review hypothesis",
    severity: "high",
    category: "use-after-free",
    status: "discovered",
    evidence: {
      request: "net/ipv4/tcp_input.c:4321",
      response: "static-only — see hypothesis flag",
      analysis: "Found by review agent\nSubsystem: net/tcp\nHypothesis: true",
    },
    confidence: 0.4,
    timestamp: 0,
    ...overrides,
  };
}

/**
 * Build an agent invoker that returns a queued sequence of assistant message
 * contents. Each call to the loop's invoker shifts one off the queue. The
 * test fails fast if the queue is empty when the loop calls in.
 */
function queueInvoker(queue: NativeContentBlock[][]): KernelVerifyAgentInvoker {
  const pending = [...queue];
  return async () => {
    const next = pending.shift();
    if (!next) throw new Error("invoker queue exhausted (unexpected extra call)");
    return next;
  };
}

function toolUse(id: string, input: Record<string, unknown>): NativeContentBlock {
  return { type: "tool_use", id, name: "kernel_run", input };
}

function fakeOracle(partial: Partial<KernelVerifyOracleResult>): KernelVerifyOracleResult {
  return {
    ran: true,
    crashed: false,
    signatureMatched: false,
    dmesgExcerpt: "",
    reason: "",
    oracleConfidence: 0.5,
    ...partial,
  };
}

describe("verifyStaticKernelFinding", () => {
  let runner: ReturnType<typeof vi.fn> & KernelVerifyRunner;

  beforeEach(() => {
    runner = vi.fn() as unknown as ReturnType<typeof vi.fn> & KernelVerifyRunner;
  });
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("confirms on the first kernel_run when signature matches", async () => {
    const winningOracle = fakeOracle({
      crashed: true,
      signatureMatched: true,
      detectedCrashType: "kasan-uaf",
      dmesgExcerpt: "BUG: KASAN: use-after-free in tcp_input+0x123",
      reason: "matched",
      oracleConfidence: 0.95,
      buildStatus: "hit",
    });
    runner = vi.fn(async () => winningOracle) as unknown as typeof runner;

    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 5,
      runner,
      agentInvoker: queueInvoker([
        [toolUse("u1", { program: "socket$inet(0x2,0x1,0x0)\n", program_lang: "syz", expected_signature: "kasan-uaf" })],
      ]),
    });

    expect(result.status).toBe("confirmed");
    expect(result.new_confidence).toBe(1.0);
    expect(result.generated_program).toContain("socket");
    expect(result.generated_program_lang).toBe("syz");
    expect(result.signature).toBe("kasan-uaf");
    expect(result.attempts).toHaveLength(1);
    expect(runner).toHaveBeenCalledOnce();
  });

  it("returns soft_hit when KASAN fires but signature mismatches", async () => {
    runner = vi.fn(async () =>
      fakeOracle({
        crashed: true,
        signatureMatched: false,
        detectedCrashType: "kasan-oob",
        dmesgExcerpt: "BUG: KASAN: slab-out-of-bounds in something_else",
        reason: "kasan fired but not the expected function",
      }),
    ) as unknown as typeof runner;

    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 1, // force budget exhaustion → soft_hit takes precedence
      runner,
      agentInvoker: queueInvoker([
        [toolUse("u1", { program: "p", program_lang: "syz", expected_signature: "tcp_input" })],
        // After budget hit, the loop terminates; this fallback is never consumed.
        [{ type: "text", text: "GIVE_UP" }],
      ]),
    });

    expect(result.status).toBe("soft_hit");
    expect(result.new_confidence).toBe(0.7);
    expect(result.signature).toBe("kasan-oob");
    expect(result.attempts.length).toBeGreaterThan(0);
  });

  it("returns budget_exhausted when no crashes fire within the attempt cap", async () => {
    runner = vi.fn(async () =>
      fakeOracle({ crashed: false, signatureMatched: false, reason: "no signal" }),
    ) as unknown as typeof runner;

    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 2,
      runner,
      agentInvoker: queueInvoker([
        [toolUse("u1", { program: "p1", program_lang: "syz" })],
        [toolUse("u2", { program: "p2", program_lang: "syz" })],
        [toolUse("u3", { program: "p3", program_lang: "syz" })],
      ]),
    });

    expect(result.status).toBe("budget_exhausted");
    expect(result.new_confidence).toBe(0.4);
    expect(result.attempts).toHaveLength(2); // attempts cap honoured
    expect(runner).toHaveBeenCalledTimes(2);
  });

  it("records malformed-program rejections without burning oracle calls", async () => {
    runner = vi.fn(async () =>
      fakeOracle({ crashed: true, signatureMatched: true, detectedCrashType: "kasan-uaf" }),
    ) as unknown as typeof runner;

    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 3,
      runner,
      agentInvoker: queueInvoker([
        // First call: malformed program_lang.
        [toolUse("u1", { program: "p", program_lang: "rust" })],
        // Second call: empty program.
        [toolUse("u2", { program: "", program_lang: "syz" })],
        // Third call: valid → confirmed.
        [toolUse("u3", { program: "real-program", program_lang: "syz", expected_signature: "kasan-uaf" })],
      ]),
    });

    expect(result.status).toBe("confirmed");
    expect(result.attempts.length).toBe(3);
    const rejected = result.attempts.filter((a) => a.rejected);
    expect(rejected).toHaveLength(2);
    expect(runner).toHaveBeenCalledOnce(); // only the valid program reached the oracle
  });

  it("terminates with no_signal when the agent emits GIVE_UP", async () => {
    runner = vi.fn(async () => fakeOracle({})) as unknown as typeof runner;
    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 5,
      runner,
      agentInvoker: queueInvoker([
        [{ type: "text", text: "I cannot find a reproducer. GIVE_UP" }],
      ]),
    });
    expect(result.status).toBe("no_signal");
    expect(result.new_confidence).toBe(0.4);
    expect(runner).not.toHaveBeenCalled();
  });

  it("rejects non-kernel_run tool calls without crashing the loop", async () => {
    runner = vi.fn(async () =>
      fakeOracle({
        crashed: true,
        signatureMatched: true,
        detectedCrashType: "kasan-uaf",
      }),
    ) as unknown as typeof runner;

    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 5,
      runner,
      agentInvoker: queueInvoker([
        // Agent tries to call a disallowed tool.
        [{ type: "tool_use", id: "u1", name: "bash", input: { cmd: "rm -rf /" } }],
        // Agent recovers and calls kernel_run.
        [toolUse("u2", { program: "p", program_lang: "syz", expected_signature: "kasan-uaf" })],
      ]),
    });
    expect(result.status).toBe("confirmed");
  });

  it("returns status=error and preserves confidence when the loop throws", async () => {
    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 5,
      runner: async () => {
        throw new Error("unexpected build failure");
      },
      // The agent immediately calls kernel_run; the runner throws, surfaced as
      // a tool error, not as a thrown loop-level exception. Force a thrown
      // exception path via the invoker itself.
      agentInvoker: async () => {
        throw new Error("runtime explosion");
      },
    });
    expect(result.status).toBe("error");
    expect(result.new_confidence).toBe(0.4);
    expect(result.errorMessage).toMatch(/runtime explosion/);
  });
});

describe("verifyStaticKernelFinding — two-phase trigger (AIxCC T3)", () => {
  it("escalates reach→refine: phase-1 lands the path, phase-2 confirms KASAN", async () => {
    const seenConfigs: Array<string | undefined> = [];
    // Mock runner that keys off the per-phase kernelConfig the loop passes:
    //   - phase 1 (kernelConfig="reach"): cheap build → crash (path reached)
    //     but no KASAN signature match.
    //   - phase 2 (kernelConfig="kasan"): sanitizer build → signature match.
    const runner: KernelVerifyRunner = vi.fn(async (input) => {
      seenConfigs.push(input.kernelConfig);
      if (input.kernelConfig === "reach") {
        return fakeOracle({
          crashed: true,
          signatureMatched: false,
          detectedCrashType: "general-protection",
          dmesgExcerpt: "general protection fault in tcp_input",
          reason: "reached under cheap build",
        });
      }
      return fakeOracle({
        crashed: true,
        signatureMatched: true,
        detectedCrashType: "kasan-uaf",
        dmesgExcerpt: "BUG: KASAN: use-after-free in tcp_input+0x123",
        reason: "matched under KASAN",
      });
    }) as unknown as KernelVerifyRunner;

    const sameProgram = {
      program: "socket$inet(0x2,0x1,0x0)\n",
      program_lang: "syz",
      expected_signature: "kasan-uaf",
    };

    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 5,
      runner,
      twoPhase: true,
      agentInvoker: queueInvoker([
        [toolUse("u1", sameProgram)], // phase 1 (reach)
        [toolUse("u2", sameProgram)], // phase 2 (refine)
      ]),
    });

    expect(result.status).toBe("confirmed");
    expect(result.signature).toBe("kasan-uaf");
    // Two attempts: the reach probe then the refine confirm.
    expect(result.attempts).toHaveLength(2);
    expect(result.attempts[0]?.oracle?.phase).toBe("reach");
    expect(result.attempts[1]?.oracle?.phase).toBe("refine");
    // The loop passed the cheap reach config first, then the KASAN config.
    expect(seenConfigs).toEqual(["reach", "kasan"]);
  });

  it("does not confirm in phase 1 even when the crude build reports a signature match", async () => {
    // A signature match under the cheap reach build is NOT trusted — it only
    // escalates to refine. Phase 2 then refuses (no_signal) so the loop must NOT
    // have confirmed on the phase-1 'match'.
    const runner: KernelVerifyRunner = vi.fn(async (input) => {
      if (input.kernelConfig === "reach") {
        return fakeOracle({
          crashed: true,
          signatureMatched: true, // crude build "matched" — must be distrusted
          detectedCrashType: "kasan-uaf",
          dmesgExcerpt: "looks like KASAN but cheap build",
          reason: "crude match",
        });
      }
      return fakeOracle({ crashed: false, signatureMatched: false, reason: "clean under KASAN" });
    }) as unknown as KernelVerifyRunner;

    const prog = { program: "x\n", program_lang: "syz", expected_signature: "kasan-uaf" };
    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 3,
      runner,
      twoPhase: true,
      agentInvoker: queueInvoker([
        [toolUse("u1", prog)], // phase 1 reach → escalates
        [toolUse("u2", prog)], // phase 2 refine → no signal
        [{ type: "text", text: "GIVE_UP" }],
      ]),
    });

    expect(result.status).not.toBe("confirmed");
    expect(result.attempts[0]?.oracle?.phase).toBe("reach");
    expect(result.attempts[1]?.oracle?.phase).toBe("refine");
  });

  it("single-phase (default) runs every attempt in refine with the kasan config", async () => {
    const seenConfigs: Array<string | undefined> = [];
    const runner: KernelVerifyRunner = vi.fn(async (input) => {
      seenConfigs.push(input.kernelConfig);
      return fakeOracle({
        crashed: true,
        signatureMatched: true,
        detectedCrashType: "kasan-uaf",
        dmesgExcerpt: "BUG: KASAN: use-after-free",
        reason: "matched",
      });
    }) as unknown as KernelVerifyRunner;

    const result = await verifyStaticKernelFinding(staticKernelFinding(), {
      kernelTree: "/tmp/linux",
      sourceSlice: [],
      attempts: 5,
      runner,
      agentInvoker: queueInvoker([
        [toolUse("u1", { program: "x\n", program_lang: "syz", expected_signature: "kasan-uaf" })],
      ]),
    });

    expect(result.status).toBe("confirmed");
    expect(result.attempts[0]?.oracle?.phase).toBe("refine");
    expect(seenConfigs).toEqual(["kasan"]);
  });
});

describe("applyVerificationToFinding (confidence promotion)", () => {
  it("promotes to confirmed with confidence=1.0 and flips Hypothesis flag", () => {
    const f = staticKernelFinding();
    const promoted = applyVerificationToFinding(f, {
      status: "confirmed",
      new_confidence: 1.0,
      signature: "kasan-uaf",
      generated_program: "REAL_PROGRAM",
      generated_program_lang: "syz",
      attempts: [
        {
          index: 0,
          program: "REAL_PROGRAM",
          programLang: "syz",
          durationMs: 100,
        },
      ],
    });
    expect(promoted.confidence).toBe(1.0);
    expect(promoted.status).toBe("confirmed");
    expect(promoted.evidence.analysis).toMatch(/Hypothesis: false/);
    expect(promoted.evidence.analysis).toMatch(/Kernel verification: confirmed/);
    expect(promoted.evidence.response).toBe("REAL_PROGRAM");
  });

  it("promotes soft_hit to confidence=0.7 and attaches observed signature", () => {
    const f = staticKernelFinding();
    const promoted = applyVerificationToFinding(f, {
      status: "soft_hit",
      new_confidence: 0.7,
      signature: "kasan-oob",
      generated_program: "PARTIAL",
      generated_program_lang: "c",
      attempts: [],
      reason: "crash signature mismatch",
    });
    expect(promoted.confidence).toBe(0.7);
    expect(promoted.status).toBe("discovered"); // unchanged
    expect(promoted.evidence.analysis).toMatch(/Observed signature: kasan-oob/);
    expect(promoted.evidence.analysis).toMatch(/Hypothesis: false/);
    expect(promoted.evidence.response).toBe("PARTIAL");
  });

  it("keeps original confidence on budget_exhausted but records the failure", () => {
    const f = staticKernelFinding();
    const promoted = applyVerificationToFinding(f, {
      status: "budget_exhausted",
      new_confidence: 0.4,
      attempts: [
        { index: 0, program: "p1", programLang: "syz", durationMs: 10 },
        { index: 1, program: "p2", programLang: "syz", durationMs: 12 },
      ],
      reason: "5 attempts exhausted",
    });
    expect(promoted.confidence).toBe(0.4);
    expect(promoted.status).toBe("discovered");
    expect(promoted.evidence.analysis).toMatch(/Kernel verification: budget_exhausted/);
    expect(promoted.evidence.analysis).toMatch(/Attempts: 2/);
    // Hypothesis flag stays as-is for unconfirmed findings.
    expect(promoted.evidence.analysis).toMatch(/Hypothesis: true/);
  });
});

describe("kernel-prompts subsystem-slice + metadata", () => {
  it("extracts subsystem + hypothesis + cited file from a static finding", () => {
    const f = staticKernelFinding();
    const meta = extractKernelFindingMetadata(f);
    expect(meta.subsystem).toBe("net/tcp");
    expect(meta.hypothesis).toBe(true);
    expect(meta.filePath).toBe("net/ipv4/tcp_input.c");
    expect(meta.fileLine).toBe(4321);
    // Faulting function is grabbed from the title's leading identifier.
    expect(meta.faultingFunction).toBe("tcp_input");
  });

  it("buildKernelVerifyInitialPrompt names the finding, subsystem, and cap", () => {
    const finding = staticKernelFinding();
    const meta = extractKernelFindingMetadata(finding);
    const prompt = buildKernelVerifyInitialPrompt({
      finding,
      metadata: meta,
      subsystemSlice: [{ relativePath: "net/ipv4/tcp_input.c", content: "/* tcp source */" }],
      attempts: 5,
      wallClockMs: 30 * 60 * 1000,
    });
    expect(prompt).toContain(finding.title);
    expect(prompt).toContain("net/tcp");
    expect(prompt).toContain("net/ipv4/tcp_input.c");
    expect(prompt).toContain("kernel_run");
    expect(prompt).toContain("5 reproducer attempts");
    expect(prompt).toContain("30 minutes wall-clock");
  });

  it("system prompt mentions the constrained tool surface", () => {
    const sys = buildKernelVerifySystemPrompt();
    expect(sys).toContain("kernel_run");
    expect(sys).toContain("read_file");
    expect(sys).toContain("run_command");
    expect(sys).toContain("GIVE_UP");
  });
});

describe("tier1VerdictToOracleResult", () => {
  function writeDmesg(text: string): string {
    const dir = mkdtempSync(join(tmpdir(), "pwnkit-tier1-test-"));
    const p = join(dir, "verify.dmesg");
    writeFileSync(p, text, "utf8");
    return p;
  }

  it("maps Tier-1 reproduced → signatureMatched=true with the detected crash type", () => {
    const path = writeDmesg("[ 12.1 ] BUG: KASAN: slab-use-after-free in tcp_input+0x123\n");
    const oracle = tier1VerdictToOracleResult({
      status: "reproduced",
      signature: "kasan-uaf",
      dmesg_path: path,
      build_cache_hit: true,
    });
    expect(oracle.crashed).toBe(true);
    expect(oracle.signatureMatched).toBe(true);
    expect(oracle.detectedCrashType).toBe("kasan-uaf");
    expect(oracle.buildStatus).toBe("hit");
    rmSync(path, { force: true });
  });

  it("maps Tier-1 run_failed-with-signature → soft hit (crashed=true, matched=false)", () => {
    const path = writeDmesg("BUG: KASAN: slab-out-of-bounds in other_fn");
    const oracle = tier1VerdictToOracleResult({
      status: "run_failed",
      signature: "kasan-oob",
      dmesg_path: path,
      build_cache_hit: false,
    });
    expect(oracle.crashed).toBe(true);
    expect(oracle.signatureMatched).toBe(false);
    expect(oracle.detectedCrashType).toBe("kasan-oob");
    expect(oracle.buildStatus).toBe("miss");
    rmSync(path, { force: true });
  });

  it("maps Tier-1 run_failed-without-signature → compile/exec failure (crashed=false)", () => {
    const path = writeDmesg("[run_failed] compiler error");
    const oracle = tier1VerdictToOracleResult({
      status: "run_failed",
      dmesg_path: path,
      build_cache_hit: false,
    });
    expect(oracle.crashed).toBe(false);
    expect(oracle.signatureMatched).toBe(false);
    expect(oracle.reason).toMatch(/compile|execute/i);
    rmSync(path, { force: true });
  });

  it("maps Tier-1 no_signal → ran=true, crashed=false, oracleConfidence=0", () => {
    const path = writeDmesg("no crash here");
    const oracle = tier1VerdictToOracleResult({
      status: "no_signal",
      dmesg_path: path,
      build_cache_hit: true,
    });
    expect(oracle.ran).toBe(true);
    expect(oracle.crashed).toBe(false);
    expect(oracle.oracleConfidence).toBe(0);
    rmSync(path, { force: true });
  });

  it("maps Tier-1 build_failed → ran=false, buildStatus=miss", () => {
    const path = writeDmesg("[build_failed] something");
    const oracle = tier1VerdictToOracleResult({
      status: "build_failed",
      dmesg_path: path,
      build_cache_hit: false,
    });
    expect(oracle.ran).toBe(false);
    expect(oracle.buildStatus).toBe("miss");
    expect(oracle.reason).toMatch(/build failed/i);
    rmSync(path, { force: true });
  });
});
