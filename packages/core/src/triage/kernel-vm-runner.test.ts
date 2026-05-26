import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  prepareKernelVmArtifacts,
  verifyKernelFinding,
} from "./kernel-vm-runner.js";

describe("prepareKernelVmArtifacts", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.PWNKIT_KERNEL_QEMU_KERNEL;
    delete process.env.PWNKIT_KERNEL_QEMU_DISK;
    delete process.env.PWNKIT_KERNEL_QEMU_CONFIG;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  function makeTree(): string {
    const tree = mkdtempSync(join(tmpdir(), "pwnkit-kernel-tree-"));
    writeFileSync(join(tree, "Makefile"), "VERSION = 6\nPATCHLEVEL = 8\n");
    return tree;
  }

  it("uses configured VM artifacts as the fastest cache hit", () => {
    const dir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-env-"));
    const kernel = join(dir, "bzImage");
    const disk = join(dir, "rootfs.img");
    const config = join(dir, "kernel.config");
    writeFileSync(kernel, "kernel");
    writeFileSync(disk, "disk");
    writeFileSync(config, "config");
    process.env.PWNKIT_KERNEL_QEMU_KERNEL = kernel;
    process.env.PWNKIT_KERNEL_QEMU_DISK = disk;
    process.env.PWNKIT_KERNEL_QEMU_CONFIG = config;

    const artifacts = prepareKernelVmArtifacts({
      kernelTree: makeTree(),
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("should not build when env artifacts exist");
      },
    });

    expect(artifacts.cacheStatus).toBe("env");
    expect(artifacts.kernelImage).toBe(kernel);
    expect(artifacts.diskImage).toBe(disk);
    expect(artifacts.kernelConfig).toBe(config);
  });

  it("builds a cache miss and reuses it as a cache hit", () => {
    const tree = makeTree();
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));

    const logLines: string[] = [];
    const miss = prepareKernelVmArtifacts({
      kernelTree: tree,
      cacheDir,
      logger: (line) => logLines.push(line),
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "kernel");
        writeFileSync(join(outDir, "rootfs.img"), "disk");
        writeFileSync(join(outDir, "kernel.config"), "config");
      },
    });

    expect(miss.cacheStatus).toBe("miss");
    // New cache-key shape (issue #271): <rev-or-hash>-<config-hash>
    expect(miss.cacheKey).toMatch(/^[A-Za-z0-9._-]+-[0-9a-f]{12}$/);
    expect(logLines.some((l) => l.includes("[kernel-cache] miss"))).toBe(true);

    const hit = prepareKernelVmArtifacts({
      kernelTree: tree,
      cacheDir,
      logger: (line) => logLines.push(line),
      buildRunner: () => {
        throw new Error("cache hit should not rebuild");
      },
    });

    expect(hit.cacheStatus).toBe("hit");
    expect(hit.cacheKey).toBe(miss.cacheKey);
    expect(hit.kernelImage).toBe(miss.kernelImage);
    expect(logLines.some((l) => l.includes("[kernel-cache] hit"))).toBe(true);
  });

  it("keys the cache by config name so kasan and defconfig+kasan diverge", () => {
    const tree = makeTree();
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));

    const a = prepareKernelVmArtifacts({
      kernelTree: tree,
      cacheDir,
      configProfile: "kasan",
      logger: () => undefined,
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "kernel-a");
        writeFileSync(join(outDir, "rootfs.img"), "disk-a");
        writeFileSync(join(outDir, "kernel.config"), "config-a");
      },
    });
    const b = prepareKernelVmArtifacts({
      kernelTree: tree,
      cacheDir,
      configProfile: "defconfig+kasan",
      logger: () => undefined,
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "kernel-b");
        writeFileSync(join(outDir, "rootfs.img"), "disk-b");
        writeFileSync(join(outDir, "kernel.config"), "config-b");
      },
    });

    expect(a.cacheKey).not.toBe(b.cacheKey);
    expect(a.cacheDir).not.toBe(b.cacheDir);
  });
});

describe("verifyKernelFinding", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.PWNKIT_KERNEL_QEMU_KERNEL;
    delete process.env.PWNKIT_KERNEL_QEMU_DISK;
    delete process.env.PWNKIT_KERNEL_QEMU_CONFIG;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  function makeTree(): string {
    const tree = mkdtempSync(join(tmpdir(), "pwnkit-kernel-tree-"));
    writeFileSync(join(tree, "Makefile"), "VERSION = 6\nPATCHLEVEL = 8\n");
    return tree;
  }

  function makeReproducer(name: string, content = "int main(void) { return 0; }\n"): string {
    const dir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-repro-"));
    const repro = join(dir, name);
    writeFileSync(repro, content, "utf-8");
    return repro;
  }

  it("reports build_cache_hit=true on cache reuse + reproduced signature match", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));
    const tree = makeTree();
    // First call populates the cache.
    primeCacheForTree(tree, cacheDir);
    const reproPath = makeReproducer("poc.c");
    const dmesgOut = join(mkdtempSync(join(tmpdir(), "pwnkit-verify-")), "dmesg.log");

    const result = await verifyKernelFinding({
      reproducerPath: reproPath,
      kernelTree: tree,
      cacheDir,
      dmesgOutPath: dmesgOut,
      expectedSignature: "KASAN: slab-use-after-free",
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("cache hit should not rebuild");
      },
      vmRunner: async () => ({
        compiled: true,
        executed: true,
        output: "ran",
        dmesg: "BUG: KASAN: slab-use-after-free in vulnerable_path+0x10/0x20",
        exitCode: 0,
        timedOut: false,
      }),
    });

    expect(result.status).toBe("reproduced");
    expect(result.signature).toBe("KASAN: slab-use-after-free");
    expect(result.build_cache_hit).toBe(true);
    expect(existsSync(result.dmesg_path)).toBe(true);
    expect(readFileSync(result.dmesg_path, "utf-8")).toContain("KASAN: slab-use-after-free");
  });

  it("detects an unexpected-but-recognised crash as no-match when expectedSignature mismatches", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);
    const reproPath = makeReproducer("poc.syz", "r0 = openat$sysfs(0)\n");

    const result = await verifyKernelFinding({
      syzProgramPath: reproPath,
      kernelTree: tree,
      cacheDir,
      expectedSignature: "general protection fault",
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("cache hit should not rebuild");
      },
      vmRunner: async () => ({
        compiled: true,
        executed: true,
        output: "ran",
        // KASAN OOB instead of the expected GPF.
        dmesg: "BUG: KASAN: slab-out-of-bounds in foo+0x1/0x2",
        exitCode: 0,
        timedOut: false,
      }),
    });

    expect(result.status).toBe("run_failed");
    expect(result.signature).toBe("kasan-oob");
    expect(result.build_cache_hit).toBe(true);
  });

  it("returns no_signal when the reproducer ran but dmesg has no crash markers", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);
    const reproPath = makeReproducer("poc.c");

    const result = await verifyKernelFinding({
      reproducerPath: reproPath,
      kernelTree: tree,
      cacheDir,
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("cache hit should not rebuild");
      },
      vmRunner: async () => ({
        compiled: true,
        executed: true,
        output: "ran cleanly",
        dmesg: "[    0.000000] Linux version 6.8.0\n[    1.234] hello world\n",
        exitCode: 0,
        timedOut: false,
      }),
    });

    expect(result.status).toBe("no_signal");
    expect(result.signature).toBeUndefined();
    expect(result.build_cache_hit).toBe(true);
  });

  it("returns build_failed when the build runner throws", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));
    const tree = makeTree();
    const reproPath = makeReproducer("poc.c");

    const result = await verifyKernelFinding({
      reproducerPath: reproPath,
      kernelTree: tree,
      cacheDir,
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("docker build exploded");
      },
      vmRunner: async () => {
        throw new Error("should not run");
      },
    });

    expect(result.status).toBe("build_failed");
    expect(result.build_cache_hit).toBe(false);
    expect(existsSync(result.dmesg_path)).toBe(true);
    expect(readFileSync(result.dmesg_path, "utf-8")).toContain("docker build exploded");
  });

  it("returns run_failed when the VM runner throws", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);
    const reproPath = makeReproducer("poc.c");

    const result = await verifyKernelFinding({
      reproducerPath: reproPath,
      kernelTree: tree,
      cacheDir,
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("cache hit should not rebuild");
      },
      vmRunner: async () => {
        throw new Error("qemu segfaulted");
      },
    });

    expect(result.status).toBe("run_failed");
    expect(result.build_cache_hit).toBe(true);
    expect(readFileSync(result.dmesg_path, "utf-8")).toContain("qemu segfaulted");
  });

  it("rejects passing both --syz and --reproducer paths", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);
    const reproPath = makeReproducer("poc.c");

    await expect(
      verifyKernelFinding({
        reproducerPath: reproPath,
        syzProgramPath: reproPath,
        kernelTree: tree,
        cacheDir,
        logger: () => undefined,
        buildRunner: () => undefined,
        vmRunner: async () => ({
          compiled: true,
          executed: true,
          output: "",
          dmesg: "",
          exitCode: 0,
          timedOut: false,
        }),
      }),
    ).rejects.toThrow(/only one of/);
  });

  function primeCacheForTree(tree: string, cacheDir: string, configProfile = "kasan"): void {
    prepareKernelVmArtifacts({
      kernelTree: tree,
      cacheDir,
      configProfile,
      logger: () => undefined,
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "kernel");
        writeFileSync(join(outDir, "rootfs.img"), "disk");
        writeFileSync(join(outDir, "kernel.config"), "config");
      },
    });
  }
});
