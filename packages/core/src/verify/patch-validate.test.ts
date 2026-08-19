import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  validatePatchRemovesCrash,
  type CandidatePatch,
  type PatchGenerator,
} from "./patch-validate.js";
import type { Finding } from "@pwnkit/shared";
import type { ReproducerResult } from "../triage/kernel-oracle.js";

function reproducedFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "00000000-finding-0009",
    templateId: "kernel-review-test",
    title: "tcp_input: UAF in input path",
    description: "reproduced KASAN UAF",
    severity: "high",
    category: "use-after-free",
    status: "confirmed",
    evidence: {
      request: "net/ipv4/tcp_input.c:4321",
      response: "syz repro",
      analysis: "Subsystem: net/tcp",
    },
    confidence: 1.0,
    timestamp: 0,
    ...overrides,
  };
}

const PATCH: CandidatePatch = {
  diff: "--- a/net/ipv4/tcp_input.c\n+++ b/net/ipv4/tcp_input.c\n@@ -1 +1 @@\n-bad\n+good\n",
  rationale: "guard the freed pointer before re-use",
};

describe("validatePatchRemovesCrash (AIxCC T7 patch-as-oracle)", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.PWNKIT_KERNEL_QEMU_KERNEL;
    delete process.env.PWNKIT_KERNEL_QEMU_DISK;
    delete process.env.PWNKIT_KERNEL_QEMU_CONFIG;
  });
  afterEach(() => {
    process.env = { ...originalEnv };
    vi.clearAllMocks();
  });

  function makeTree(): string {
    const tree = mkdtempSync(join(tmpdir(), "pwnkit-patch-tree-"));
    writeFileSync(join(tree, "Makefile"), "VERSION = 6\nPATCHLEVEL = 8\n");
    return tree;
  }

  function makeReproducer(name = "poc.c"): string {
    const dir = mkdtempSync(join(tmpdir(), "pwnkit-patch-repro-"));
    const repro = join(dir, name);
    writeFileSync(repro, "int main(void){return 0;}\n");
    return repro;
  }

  const reproResult = (dmesg: string): ReproducerResult => ({
    compiled: true,
    executed: true,
    output: "ran",
    dmesg,
    exitCode: 0,
    timedOut: false,
  });

  const generator = (patch: CandidatePatch | null): PatchGenerator =>
    vi.fn(async () => patch) as unknown as PatchGenerator;

  it("confirms root cause when the patched build no longer trips KASAN", async () => {
    const tree = makeTree();
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-patch-cache-"));
    const applier = vi.fn();
    const reverter = vi.fn();

    const result = await validatePatchRemovesCrash({
      finding: reproducedFinding(),
      kernelTree: tree,
      cacheDir,
      reproducer: "repro",
      reproducerLang: "c",
      reproducerPath: makeReproducer(),
      crashDmesg: "BUG: KASAN: slab-use-after-free in tcp_input",
      patchGenerator: generator(PATCH),
      patchApplier: applier,
      patchReverter: reverter,
      logger: () => undefined,
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "patched-kernel");
        writeFileSync(join(outDir, "rootfs.img"), "disk");
        writeFileSync(join(outDir, "kernel.config"), "config");
      },
      // Patched build → clean run, no KASAN signature.
      vmRunner: async () => reproResult("[ 0.0 ] clean boot, no crash\n"),
    });

    expect(result.status).toBe("root_cause_confirmed");
    expect(result.patchValidated).toBe(true);
    expect(result.rerunStatus).toBe("no_signal");
    expect(result.patch).toBe(PATCH);
    expect(result.patchedCacheKey).toMatch(/^[A-Za-z0-9._-]+-[0-9a-f]{12}$/);
    // The patch was applied and then reverted (tree left clean).
    expect(applier).toHaveBeenCalledOnce();
    expect(reverter).toHaveBeenCalledOnce();
  });

  it("reports not_root_cause when KASAN still fires under the patched build", async () => {
    const tree = makeTree();
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-patch-cache-"));
    const reverter = vi.fn();

    const result = await validatePatchRemovesCrash({
      finding: reproducedFinding(),
      kernelTree: tree,
      cacheDir,
      reproducer: "repro",
      reproducerLang: "c",
      reproducerPath: makeReproducer(),
      crashDmesg: "BUG: KASAN: slab-use-after-free in tcp_input",
      expectedSignature: "KASAN: slab-use-after-free",
      patchGenerator: generator(PATCH),
      patchApplier: vi.fn(),
      patchReverter: reverter,
      logger: () => undefined,
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "patched-kernel");
        writeFileSync(join(outDir, "rootfs.img"), "disk");
        writeFileSync(join(outDir, "kernel.config"), "config");
      },
      // The "fix" didn't fix it — KASAN still fires.
      vmRunner: async () =>
        reproResult("BUG: KASAN: slab-use-after-free in tcp_input+0x10/0x20"),
    });

    expect(result.status).toBe("not_root_cause");
    expect(result.patchValidated).toBe(false);
    expect(result.rerunStatus).toBe("reproduced");
    // Tree still reverted even on the negative path.
    expect(reverter).toHaveBeenCalledOnce();
  });

  it("reports patch_generation_failed when no diff is produced (no apply/build)", async () => {
    const tree = makeTree();
    const applier = vi.fn();

    const result = await validatePatchRemovesCrash({
      finding: reproducedFinding(),
      kernelTree: tree,
      reproducer: "repro",
      reproducerLang: "c",
      reproducerPath: makeReproducer(),
      crashDmesg: "BUG: KASAN: slab-use-after-free",
      patchGenerator: generator(null),
      patchApplier: applier,
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("should not build without a patch");
      },
    });

    expect(result.status).toBe("patch_generation_failed");
    expect(result.patchValidated).toBe(false);
    expect(applier).not.toHaveBeenCalled();
  });

  it("reports patch_apply_failed when git apply throws (no rebuild)", async () => {
    const tree = makeTree();
    const result = await validatePatchRemovesCrash({
      finding: reproducedFinding(),
      kernelTree: tree,
      reproducer: "repro",
      reproducerLang: "c",
      reproducerPath: makeReproducer(),
      crashDmesg: "BUG: KASAN: slab-use-after-free",
      patchGenerator: generator(PATCH),
      patchApplier: () => {
        throw new Error("patch does not apply");
      },
      patchReverter: vi.fn(),
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("should not build when apply failed");
      },
    });

    expect(result.status).toBe("patch_apply_failed");
    expect(result.patchValidated).toBe(false);
  });
});
