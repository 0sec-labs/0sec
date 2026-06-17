import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, statSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  prepareKernelVmArtifacts,
  verifyKernelFinding,
  verifyAcrossBoots,
  buildKernelAppend,
  renderRaceWidenModuleSource,
  defaultDmesgOutPath,
  writeProofFileReadOnly,
  parseCoveragePcs,
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

describe("verifyAcrossBoots — N-boot reproducibility gate (AIxCC T2)", () => {
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

  function makeReproducer(name: string): string {
    const dir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-repro-"));
    const repro = join(dir, name);
    writeFileSync(repro, "int main(void) { return 0; }\n", "utf-8");
    return repro;
  }

  function primeCacheForTree(tree: string, cacheDir: string): void {
    prepareKernelVmArtifacts({
      kernelTree: tree,
      cacheDir,
      configProfile: "kasan",
      logger: () => undefined,
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "kernel");
        writeFileSync(join(outDir, "rootfs.img"), "disk");
        writeFileSync(join(outDir, "kernel.config"), "config");
      },
    });
  }

  /**
   * vmRunner that reproduces (KASAN splat) on a fixed set of boot indices and
   * comes back clean otherwise. Lets us assert the M-of-K threshold logic.
   */
  function bootPatternRunner(hitsOn: Set<number>) {
    let boot = 0;
    return async () => {
      const fires = hitsOn.has(boot);
      boot++;
      return {
        compiled: true,
        executed: true,
        output: "ran",
        dmesg: fires
          ? "BUG: KASAN: slab-use-after-free in vulnerable_path+0x10/0x20"
          : "[    0.000000] Linux version 6.8.0\nclean boot\n",
        exitCode: 0,
        timedOut: false,
      };
    };
  }

  it("declares reproduced + nbootStable when the signature fires in 2 of 3 boots", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);

    const result = await verifyAcrossBoots({
      reproducerPath: makeReproducer("poc.c"),
      kernelTree: tree,
      cacheDir,
      boots: 3,
      minHits: 2,
      expectedSignature: "KASAN: slab-use-after-free",
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("cache hit should not rebuild");
      },
      // Fires on boots 0 and 2, clean on boot 1 → 2/3 hits.
      vmRunner: bootPatternRunner(new Set([0, 2])),
    });

    expect(result.bootTotal).toBe(3);
    expect(result.bootHits).toBe(2);
    expect(result.nbootStable).toBe(true);
    expect(result.status).toBe("reproduced");
    expect(result.signature).toBe("KASAN: slab-use-after-free");
    expect(result.bootStatuses).toEqual(["reproduced", "no_signal", "reproduced"]);
  });

  it("declares NOT stable when the signature fires in only 1 of 3 boots", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);

    const result = await verifyAcrossBoots({
      reproducerPath: makeReproducer("poc.c"),
      kernelTree: tree,
      cacheDir,
      boots: 3,
      minHits: 2,
      expectedSignature: "KASAN: slab-use-after-free",
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("cache hit should not rebuild");
      },
      // Fires only on boot 0 → 1/3 hits, below the threshold.
      vmRunner: bootPatternRunner(new Set([0])),
    });

    expect(result.bootHits).toBe(1);
    expect(result.nbootStable).toBe(false);
    // A one-off splat is not a reproduction — surfaced as the worst per-boot
    // status (no_signal here), never silently promoted to `reproduced`.
    expect(result.status).toBe("no_signal");
  });

  it("stops early once the M-of-K threshold is unreachable", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "pwnkit-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);

    let calls = 0;
    const result = await verifyAcrossBoots({
      reproducerPath: makeReproducer("poc.c"),
      kernelTree: tree,
      cacheDir,
      boots: 5,
      minHits: 4,
      expectedSignature: "KASAN: slab-use-after-free",
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("cache hit should not rebuild");
      },
      // Never fires — after 2 clean boots, 4-of-5 is impossible (5-2=3 < 4).
      vmRunner: async () => {
        calls++;
        return {
          compiled: true,
          executed: true,
          output: "ran",
          dmesg: "clean boot\n",
          exitCode: 0,
          timedOut: false,
        };
      },
    });

    expect(result.nbootStable).toBe(false);
    // boot0: hits=0, remaining=4 → 0+4=4 >= 4, continue
    // boot1: hits=0, remaining=3 → 0+3=3 < 4, stop
    expect(calls).toBe(2);
  });
});

describe("parseCoveragePcs — KCOV coverage parsing (AIxCC T1)", () => {
  it("parses hex and decimal PCs as normalized hex strings, dedupes, and sorts", () => {
    const raw = [
      "0xffffffff81234560",
      "0xffffffff81234560", // dup
      "4096",
      "0xffffffff81234500",
      "",
      "  0xffffffff81234540  trailing junk",
    ].join("\n");
    const pcs = parseCoveragePcs(raw);
    // Full 64-bit kernel PCs are preserved as strings (a number rep collapses
    // them past Number.MAX_SAFE_INTEGER).
    expect(pcs).toEqual([
      "0x1000", // 4096
      "0xffffffff81234500",
      "0xffffffff81234540",
      "0xffffffff81234560",
    ]);
  });

  it("skips garbage lines and returns empty for no PCs", () => {
    expect(parseCoveragePcs("not-a-pc\n#comment\n\n")).toEqual([]);
    expect(parseCoveragePcs("")).toEqual([]);
  });
});

describe("buildKernelAppend — KASLR knob", () => {
  it("boots nokaslr by default (stable verification addresses)", () => {
    const append = buildKernelAppend(false);
    expect(append).toContain("nokaslr");
    expect(append).not.toMatch(/\bkaslr\b(?<!nokaslr)/);
    // historical contract preserved otherwise.
    expect(append).toContain("init=/sbin/pwnkit-init");
    expect(append).toContain("root=/dev/vda");
  });

  it("boots with KASLR on when the kaslr flag is set", () => {
    const append = buildKernelAppend(true);
    expect(append).toContain(" kaslr ");
    expect(append).not.toContain("nokaslr");
  });
});

describe("renderRaceWidenModuleSource — kprobe widen module", () => {
  it("injects mdelay at the faulting symbol+offset", () => {
    const src = renderRaceWidenModuleSource("snd_rawmidi_kernel_write1", 0x1ba, 50);
    // contains the mdelay widen + the faulting symbol + the offset.
    expect(src).toContain("mdelay(widen_delay_ms)");
    expect(src).toContain('.symbol_name = "snd_rawmidi_kernel_write1"');
    expect(src).toContain(".offset = 0x1ba");
    expect(src).toContain("register_kprobe");
    expect(src).toContain("widen_delay_ms = 50");
    // it is a real, buildable kprobe module skeleton.
    expect(src).toContain("#include <linux/kprobes.h>");
    expect(src).toContain("MODULE_LICENSE(\"GPL\")");
  });
});

describe("defaultDmesgOutPath — collision-free proof filenames", () => {
  it("returns DISTINCT paths for several calls in the same millisecond", () => {
    const before = Date.now();
    const paths = new Set<string>();
    for (let i = 0; i < 1000; i++) paths.add(defaultDmesgOutPath());
    const after = Date.now();
    // Sanity: the loop completed inside (at most) a few ms — the old Date.now()
    // stamp would have collided heavily here. hrtime.bigint() keeps them unique.
    expect(after - before).toBeLessThan(50);
    expect(paths.size).toBe(1000);
  });
});

describe("writeProofFileReadOnly — read-only proof artifact", () => {
  it("writes the proof and makes it mode 0444", () => {
    const path = defaultDmesgOutPath();
    try {
      writeProofFileReadOnly(path, "BUG: KASAN: use-after-free proof\n");
      expect(existsSync(path)).toBe(true);
      expect(readFileSync(path, "utf-8")).toContain("use-after-free proof");
      // Mode is read-only (0444): mask off the file-type bits.
      const mode = statSync(path).mode & 0o777;
      expect(mode).toBe(0o444);
    } finally {
      // Read-only files need force removal.
      rmSync(path, { force: true });
    }
  });
});
