/**
 * Tier-3 QEMU validation runner tests.
 *
 * We never boot a real QEMU here. The runner is parameterised on a
 * `spawnImpl` so tests can return a stub child process that simulates
 * VM completion by writing the marker files Tier-3 polls for. This
 * keeps the tests deterministic and CI-safe.
 *
 * Real VM tests live in `c-cpp-tier3-e2e.test.ts` and are gated on
 * `0SEC_KERNEL_QEMU=1`.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import type { Finding } from "@0sec/shared";
import {
  runTier3Validation,
  promoteFindingsWithTier3Result,
  type Tier3ValidationResult,
} from "./c-cpp-tier3.js";
import type { Tier2HarnessArtifact } from "./c-cpp-tier2.js";
import type { KernelVmConfig } from "../triage/kernel-vm-runner.js";

/**
 * Tier-2 artifact factory. Produces a tiny on-disk shape that Tier-3
 * can stage without compiling anything.
 */
function makeTier2Artifact(): Tier2HarnessArtifact {
  const dir = mkdtempSync(join(tmpdir(), "0sec-tier3-fixture-"));
  const harnessPath = join(dir, "harness.c");
  const objPath = join(dir, "lib.c");
  writeFileSync(harnessPath, "/* fixture harness */\nint main(){return 0;}\n");
  writeFileSync(objPath, "/* fixture lib */\n");
  return {
    harness_path: harnessPath,
    linked_objects: [objPath],
    compile_command: `clang -O1 -g -fsanitize=address,undefined,fuzzer ${harnessPath} ${objPath} -o ${dir}/harness`,
    run_command: `${dir}/harness -runs=100`,
    sanitizers_enabled: ["asan", "ubsan"],
    detected_build_system: "autotools",
    linker_script_path: join(dir, "link.sh"),
    makefile_fragment_path: join(dir, "harness.mk"),
  };
}

/**
 * Make a stub kernel VM config — Tier-3 only cares about the fields
 * it forwards to `buildQemuCommand`.
 */
function makeKernelVmConfig(): KernelVmConfig {
  return {
    qemuBinary: "qemu-system-x86_64",
    kernelImage: "/tmp/fake-bzImage",
    diskImage: "/tmp/fake-rootfs.img",
    diskFormat: "raw",
    bootTimeoutSec: 30,
    memoryMb: 1024,
    smp: 1,
    kernelAppend: "console=ttyS0",
    timeoutSec: 30,
    shareTag: "osecshare",
  };
}

/**
 * Build a fake `spawn` that immediately resolves by writing the marker
 * files Tier-3 polls. The `behavior` argument controls what the
 * "guest" produced.
 */
function makeStubSpawn(behavior: {
  compiled: boolean;
  compileLog?: string;
  runLog?: string;
  dmesg?: string;
  exitCode?: number;
  delayMs?: number;
}): { spawnImpl: import("node:child_process").spawn; lastSharedDir: () => string | null } {
  let sharedDir: string | null = null;
  // We have to match buildQemuCommand's argument layout: it places
  // `-virtfs local,path=<sharedDir>,...` somewhere in argv. We sniff
  // for it.
  const stub = ((_command: string, args: readonly string[]) => {
    for (let i = 0; i < args.length; i += 1) {
      if (args[i] === "-virtfs") {
        const next = args[i + 1] ?? "";
        const m = next.match(/path=([^,]+)/);
        if (m) {
          sharedDir = m[1]!;
          break;
        }
      }
    }
    const proc = new EventEmitter() as unknown as import("node:child_process").ChildProcess & {
      exitCode: number | null;
      kill: (signal?: string) => boolean;
    };
    proc.exitCode = null;
    proc.kill = () => true;
    setTimeout(() => {
      if (sharedDir && existsSync(sharedDir)) {
        if (behavior.compileLog !== undefined) {
          writeFileSync(join(sharedDir, "compile.log"), behavior.compileLog);
        }
        if (behavior.runLog !== undefined) {
          writeFileSync(join(sharedDir, "run.log"), behavior.runLog);
        }
        if (behavior.dmesg !== undefined) {
          writeFileSync(join(sharedDir, "dmesg.log"), behavior.dmesg);
        }
        writeFileSync(join(sharedDir, "compiled.ok"), behavior.compiled ? "1\n" : "0\n");
        writeFileSync(join(sharedDir, "executed.ok"), behavior.compiled ? "1\n" : "0\n");
        writeFileSync(join(sharedDir, "exit_code"), String(behavior.exitCode ?? 0));
      }
      proc.exitCode = behavior.exitCode ?? 0;
      proc.emit("exit", proc.exitCode);
    }, behavior.delayMs ?? 5);
    return proc;
  }) as unknown as import("node:child_process").spawn;
  return { spawnImpl: stub, lastSharedDir: () => sharedDir };
}

describe("runTier3Validation — dry-run / env probe", () => {
  const originalEnv = { ...process.env };
  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env["0SEC_KERNEL_QEMU_KERNEL"];
    delete process.env["0SEC_KERNEL_QEMU_DISK"];
  });
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("returns qemu_failed with a clear reason when env vars are unset", async () => {
    const artifact = makeTier2Artifact();
    const result = await runTier3Validation(artifact, {});
    expect(result.status).toBe("qemu_failed");
    expect(result.reason).toMatch(/0SEC_KERNEL_QEMU_KERNEL/);
    expect(result.corpus_inputs_consumed).toBe(0);
    expect(result.run_duration_ms).toBeGreaterThanOrEqual(0);
  });

  it("returns qemu_failed when the kernel image path does not exist", async () => {
    const artifact = makeTier2Artifact();
    const result = await runTier3Validation(artifact, {
      qemuKernel: "/tmp/does-not-exist-bzImage-0sec-test",
      qemuDisk: "/tmp/does-not-exist-rootfs-0sec-test",
    });
    expect(result.status).toBe("qemu_failed");
    expect(result.reason).toMatch(/does not exist/);
  });
});

describe("runTier3Validation — mocked QEMU", () => {
  function stageKernelDisk(): { kernel: string; disk: string } {
    const dir = mkdtempSync(join(tmpdir(), "0sec-tier3-vm-"));
    const kernel = join(dir, "bzImage");
    const disk = join(dir, "rootfs.img");
    writeFileSync(kernel, "fake-kernel");
    writeFileSync(disk, "fake-disk");
    return { kernel, disk };
  }

  it("crash_reproduced: parses ASan heap-buffer-overflow from run.log", async () => {
    const artifact = makeTier2Artifact();
    const { kernel, disk } = stageKernelDisk();
    const asanLog = [
      "==90673==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000fb at pc 0x108868a95",
      "READ of size 1 at 0x6020000000fb thread T0",
      "    #0 0x108868a94 in osec_tier2_decoder_run decoder.c:35:10",
      "0x6020000000fb is located 0 bytes to the right of 11-byte region [0x6020000000f0,0x6020000000fb)",
      "SUMMARY: AddressSanitizer: heap-buffer-overflow decoder.c:35:10 in osec_tier2_decoder_run",
      "",
    ].join("\n");
    const { spawnImpl } = makeStubSpawn({
      compiled: true,
      compileLog: "",
      runLog: asanLog,
      exitCode: 1,
    });

    const result = await runTier3Validation(artifact, {
      qemuKernel: kernel,
      qemuDisk: disk,
      spawnImpl,
      loadConfigImpl: makeKernelVmConfig,
      wallClockMs: 10_000,
    });

    expect(result.status).toBe("crash_reproduced");
    expect(result.sanitizer_signature).toBeDefined();
    expect(result.sanitizer_signature?.kind).toBe("heap-buffer-overflow");
    expect(result.sanitizer_signature?.category).toBe("out-of-bounds-read");
    expect(result.sanitizer_log_path).toBeTruthy();
    expect(result.run_duration_ms).toBeGreaterThanOrEqual(0);
  });

  it("no_crash: harness completes without a sanitizer report", async () => {
    const artifact = makeTier2Artifact();
    const { kernel, disk } = stageKernelDisk();
    const { spawnImpl } = makeStubSpawn({
      compiled: true,
      compileLog: "",
      runLog: "Done 100000 runs in 5 second(s)",
      exitCode: 0,
    });

    const result = await runTier3Validation(artifact, {
      qemuKernel: kernel,
      qemuDisk: disk,
      spawnImpl,
      loadConfigImpl: makeKernelVmConfig,
      wallClockMs: 10_000,
    });

    expect(result.status).toBe("no_crash");
    expect(result.sanitizer_signature).toBeUndefined();
  });

  it("compile_failed: guest reports compiled.ok=0 and a compile.log", async () => {
    const artifact = makeTier2Artifact();
    const { kernel, disk } = stageKernelDisk();
    const { spawnImpl } = makeStubSpawn({
      compiled: false,
      compileLog: "fixture.c:1:1: error: missing symbol foo_decode",
      runLog: "",
      exitCode: 1,
    });

    const result = await runTier3Validation(artifact, {
      qemuKernel: kernel,
      qemuDisk: disk,
      spawnImpl,
      loadConfigImpl: makeKernelVmConfig,
      wallClockMs: 10_000,
    });

    expect(result.status).toBe("compile_failed");
    expect(result.reason).toMatch(/missing symbol foo_decode/);
  });

  it("counts the corpus inputs that were staged into the VM share", async () => {
    const artifact = makeTier2Artifact();
    const { kernel, disk } = stageKernelDisk();
    const corpusDir = mkdtempSync(join(tmpdir(), "0sec-tier3-corpus-"));
    const seedA = join(corpusDir, "seed-a");
    const seedB = join(corpusDir, "seed-b");
    writeFileSync(seedA, "AAA");
    writeFileSync(seedB, "BBB");
    const { spawnImpl } = makeStubSpawn({
      compiled: true,
      runLog: "Done 1 run",
      exitCode: 0,
    });

    const result = await runTier3Validation(artifact, {
      qemuKernel: kernel,
      qemuDisk: disk,
      runCorpus: [seedA, seedB, "/tmp/does-not-exist-seed-0sec-test"],
      spawnImpl,
      loadConfigImpl: makeKernelVmConfig,
      wallClockMs: 10_000,
    });

    expect(result.corpus_inputs_consumed).toBe(2);
  });

  it("returns qemu_failed when the wall-clock budget elapses without compiled.ok", async () => {
    const artifact = makeTier2Artifact();
    const { kernel, disk } = stageKernelDisk();
    // Build a spawn that never produces compiled.ok.
    const stubSpawn = ((_cmd: string, _args: readonly string[]) => {
      const proc = new EventEmitter() as unknown as import("node:child_process").ChildProcess & {
        exitCode: number | null;
        kill: (signal?: string) => boolean;
      };
      proc.exitCode = null;
      proc.kill = () => {
        proc.exitCode = 143;
        return true;
      };
      return proc;
    }) as unknown as import("node:child_process").spawn;

    const result = await runTier3Validation(artifact, {
      qemuKernel: kernel,
      qemuDisk: disk,
      spawnImpl: stubSpawn,
      loadConfigImpl: makeKernelVmConfig,
      wallClockMs: 1_200,
    });

    expect(result.status).toBe("qemu_failed");
    expect(result.reason).toMatch(/timed out/);
  }, 20_000);
});

describe("promoteFindingsWithTier3Result — confidence promotion", () => {
  function staticFinding(category: Finding["category"]): Finding {
    return {
      id: "finding-1",
      templateId: "tier1-hypothesis",
      title: "Static-only: possible integer truncation on alloc path",
      description: "static hypothesis",
      severity: "high",
      category,
      status: "discovered",
      confidence: 0.4,
      evidence: {
        request: "",
        response: "",
        analysis: "static-only static review hypothesis",
      } as Finding["evidence"],
      timestamp: 0,
    };
  }

  it("promotes a matching integer-truncation hypothesis when UBSan fires", () => {
    const finding = staticFinding("integer-truncation");
    const result: Tier3ValidationResult = {
      status: "crash_reproduced",
      sanitizer_signature: {
        sanitizer: "ubsan",
        kind: "signed-integer-overflow",
        category: "integer-overflow",
        primitive: "unknown",
        sourceFile: "decoder.c",
        sourceLine: 35,
        summary: "signed integer overflow",
        frames: [],
      },
      sanitizer_log_path: "/tmp/sanitizer.log",
      run_duration_ms: 100,
      corpus_inputs_consumed: 1,
    };
    const [promoted] = promoteFindingsWithTier3Result([finding], result);
    expect(promoted.status).toBe("confirmed");
    expect(promoted.confidence).toBe(1.0);
    expect(promoted.triageNote).toMatch(/tier3:sanitizer:ubsan:signed-integer-overflow/);
    expect(promoted.evidence.analysis).toMatch(/0sec tier-3/);
  });

  it("promotes an out-of-bounds-read hypothesis when ASan heap-buffer-overflow READ fires", () => {
    const finding = staticFinding("out-of-bounds-read");
    const result: Tier3ValidationResult = {
      status: "crash_reproduced",
      sanitizer_signature: {
        sanitizer: "asan",
        kind: "heap-buffer-overflow",
        category: "out-of-bounds-read",
        primitive: "read",
        sourceFile: "decoder.c",
        sourceLine: 35,
        summary: "heap-buffer-overflow",
        frames: [],
      },
      sanitizer_log_path: "/tmp/sanitizer.log",
      run_duration_ms: 100,
      corpus_inputs_consumed: 1,
    };
    const [promoted] = promoteFindingsWithTier3Result([finding], result);
    expect(promoted.status).toBe("confirmed");
    expect(promoted.confidence).toBe(1.0);
  });

  it("promotes a heap-overflow hypothesis when ASan heap-buffer-overflow WRITE fires (broader alias)", () => {
    const finding = staticFinding("heap-overflow");
    const result: Tier3ValidationResult = {
      status: "crash_reproduced",
      sanitizer_signature: {
        sanitizer: "asan",
        kind: "heap-buffer-overflow",
        category: "out-of-bounds-write",
        primitive: "write",
        sourceFile: "decoder.c",
        sourceLine: 35,
        summary: "heap-buffer-overflow",
        frames: [],
      },
      sanitizer_log_path: "/tmp/sanitizer.log",
      run_duration_ms: 100,
      corpus_inputs_consumed: 1,
    };
    const [promoted] = promoteFindingsWithTier3Result([finding], result);
    expect(promoted.status).toBe("confirmed");
  });

  it("leaves non-matching findings untouched", () => {
    const finding = staticFinding("sql-injection");
    const result: Tier3ValidationResult = {
      status: "crash_reproduced",
      sanitizer_signature: {
        sanitizer: "asan",
        kind: "heap-buffer-overflow",
        category: "out-of-bounds-read",
        primitive: "read",
        summary: "heap-buffer-overflow",
        frames: [],
      },
      sanitizer_log_path: "/tmp/sanitizer.log",
      run_duration_ms: 100,
      corpus_inputs_consumed: 1,
    };
    const [unchanged] = promoteFindingsWithTier3Result([finding], result);
    expect(unchanged.status).toBe("discovered");
    expect(unchanged.confidence).toBe(0.4);
  });

  it("is a no-op when status is not crash_reproduced", () => {
    const finding = staticFinding("integer-truncation");
    const result: Tier3ValidationResult = {
      status: "no_crash",
      sanitizer_log_path: "/tmp/sanitizer.log",
      run_duration_ms: 100,
      corpus_inputs_consumed: 1,
    };
    const promoted = promoteFindingsWithTier3Result([finding], result);
    expect(promoted[0]).toEqual(finding);
  });
});
