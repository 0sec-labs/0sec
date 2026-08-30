import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, writeFileSync, readFileSync, existsSync, statSync, rmSync } from "node:fs";
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
  buildInitramfsKernelAppend,
  renderInitramfsInitScript,
  buildInitramfsQemuCommand,
  buildQemuCommand,
  loadKernelVmConfigFromEnv,
  renderRealIpiRaceHarness,
  buildFlagsForProfile,
  kcsanConfigSupported,
  RECOGNIZED_CONFIG_PROFILES,
  parseKernelExecutionAttestation,
  bindKernelExecutionAttestation,
  renderKernelExecutionLauncherSource,
  detectOutOfBandModuleLoad,
  scanHardcodedKernelAddresses,
  assertBugAttribution,
  type KernelVmConfig,
} from "./kernel-vm-runner.js";

const provenance = {
  expectedKernelRelease: "6.8.0-0sec",
  kernelImageSha256: "c".repeat(64),
  kernelConfigSha256: "d".repeat(64),
};
const request = (nonce = "a".repeat(32), reproducerSha256 = "b".repeat(64), drop = true) => ({ nonce, reproducerSha256, ...provenance, ...(drop ? { dropUid: 65534, dropGid: 65534 } : {}) });
const receiptText = (nonce = "a".repeat(32), sha = "b".repeat(64), uid = 65534, bootId = "00000000-0000-4000-8000-000000000001") => `schema=2\nnonce=${nonce}\nreproducer_sha256=${sha}\nexpected_kernel_release=${provenance.expectedKernelRelease}\nobserved_kernel_release=${provenance.expectedKernelRelease}\nboot_id=${bootId}\nkernel_image_sha256=${provenance.kernelImageSha256}\nkernel_config_sha256=${provenance.kernelConfigSha256}\nruid=${uid}\neuid=${uid}\nsuid=${uid}\nrgid=${uid}\negid=${uid}\nsgid=${uid}\ngroups=\ncap_inh=0000000000000000\ncap_prm=0000000000000000\ncap_eff=0000000000000000\ncap_amb=0000000000000000\nsecurebits=0\nuserns_max=0\ninitial_userns=1\nno_new_privs=1\n`;
const receiptForRequest = (req: NonNullable<Parameters<typeof bindKernelExecutionAttestation>[1]>, bootId = "00000000-0000-4000-8000-000000000001") => receiptText(req.nonce, req.reproducerSha256, req.dropUid ?? 0, bootId)
  .replaceAll(provenance.expectedKernelRelease, req.expectedKernelRelease)
  .replace(provenance.kernelImageSha256, req.kernelImageSha256)
  .replace(provenance.kernelConfigSha256, req.kernelConfigSha256);

describe("kernel execution attestation", () => {
  it("strictly parses and binds a zero-cap pre-exec receipt", () => {
    const receipt = parseKernelExecutionAttestation(receiptText());
    bindKernelExecutionAttestation(receipt, request());
    expect(receipt).toMatchObject({ realUid: 65534, effectiveUid: 65534, savedUid: 65534, noNewPrivileges: true });
  });

  it("rejects duplicate, unknown, and incorrectly bound receipt fields", () => {
    expect(() => parseKernelExecutionAttestation(`${receiptText()}euid=65534\n`)).toThrow(/duplicate/);
    expect(() => parseKernelExecutionAttestation(`${receiptText()}extra=x\n`)).toThrow(/unknown/);
    expect(() => parseKernelExecutionAttestation(receiptText().replace("nonce=", "reproducer_sha256="))).toThrow();
    const reordered = receiptText().replace(/schema=2\nnonce=([^\n]+)\n/, "nonce=$1\nschema=2\n");
    expect(() => parseKernelExecutionAttestation(reordered)).toThrow(/canonical/);
    const receipt = parseKernelExecutionAttestation(receiptText());
    expect(() => bindKernelExecutionAttestation(receipt, request("c".repeat(32)))).toThrow(/binding or runtime/);
  });

  it("rejects legacy, malformed, or host-mismatched kernel provenance", () => {
    expect(() => parseKernelExecutionAttestation(receiptText().replace("schema=2", "schema=1"))).toThrow(/invalid/);
    expect(() => parseKernelExecutionAttestation(receiptText().replace("boot_id=00000000-0000-4000-8000-000000000001", "boot_id=not-a-uuid"))).toThrow(/invalid/);
    const expected = request();
    for (const raw of [
      receiptText().replace("observed_kernel_release=6.8.0-0sec", "observed_kernel_release=6.12.93"),
      receiptText().replace(provenance.kernelImageSha256, "e".repeat(64)),
      receiptText().replace(provenance.kernelConfigSha256, "f".repeat(64)),
    ]) expect(() => bindKernelExecutionAttestation(parseKernelExecutionAttestation(raw), expected)).toThrow(/runtime kernel identity/);
  });

  it("generates a launcher that drops saved IDs, sets NNP, captures CapEff, and execs", () => {
    const source = renderKernelExecutionLauncherSource();
    expect(source).toContain("setresuid(uid,uid,uid)");
    expect(source).toContain("setgroups(0,NULL)");
    expect(source).toContain("PR_SET_NO_NEW_PRIVS");
    expect(source).toContain("CapEff:");
    expect(source).toContain('open("/proc/1/ns/user",O_RDONLY|O_CLOEXEC)');
    expect(source.indexOf('open("/proc/1/ns/user"')).toBeLessThan(source.indexOf("setresuid(uid,uid,uid)"));
    expect(source).toContain('stat("/proc/self/ns/user"');
    expect(source).toContain("execvp");
  });

  it("rejects a partial UID/GID drop contract", () => {
    const receipt = parseKernelExecutionAttestation(receiptText());
    expect(() => bindKernelExecutionAttestation(receipt, { ...request(), dropGid: undefined })).toThrow(/UID and GID together/);
  });

  it("rejects residual groups, capabilities, NNP, and user-namespace escape state", () => {
    const expected = request();
    for (const raw of [
      receiptText().replace("groups=\n", "groups=0\n"),
      receiptText().replace("cap_prm=0000000000000000", "cap_prm=0000000000000001"),
      receiptText().replace("no_new_privs=1", "no_new_privs=0"),
      receiptText().replace("userns_max=0", "userns_max=1"),
      receiptText().replace("initial_userns=1", "initial_userns=0"),
    ]) {
      expect(() => bindKernelExecutionAttestation(parseKernelExecutionAttestation(raw), expected)).toThrow(/did not prove/);
    }
  });

  it.skipIf(process.platform !== "linux")("compiles the launcher and proves a successful exec handshake", () => {
    // Build under the checkout so the test does not depend on system temp
    // mount policy and always exercises the compiled launcher via exec.
    const root = mkdtempSync(join(process.cwd(), ".0sec-attest-launcher-"));
    try {
      const source = join(root, "launcher.c");
      const binary = join(root, "launcher");
      const receiptPath = join(root, "receipt");
      const markerPath = join(root, "started");
      writeFileSync(source, renderKernelExecutionLauncherSource());
      expect(spawnSync("cc", ["-O2", "-Wall", "-Wextra", "-o", binary, source], { stdio: "pipe" }).status).toBe(0);
      const release = readFileSync("/proc/sys/kernel/osrelease", "utf8").trim();
      expect(spawnSync("/usr/bin/env", [binary, receiptPath, "a".repeat(32), "b".repeat(64), release, provenance.kernelImageSha256, provenance.kernelConfigSha256, "-", "-", markerPath, "/bin/true"], { stdio: "pipe" }).status).toBe(0);
      expect(existsSync(markerPath)).toBe(true);
      const receipt = parseKernelExecutionAttestation(readFileSync(receiptPath, "utf8"));
      bindKernelExecutionAttestation(receipt, { ...request("a".repeat(32), "b".repeat(64), false), expectedKernelRelease: release });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

describe("prepareKernelVmArtifacts", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env["0SEC_KERNEL_QEMU_KERNEL"];
    delete process.env["0SEC_KERNEL_QEMU_DISK"];
    delete process.env["0SEC_KERNEL_QEMU_CONFIG"];
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  function makeTree(): string {
    const tree = mkdtempSync(join(tmpdir(), "0sec-kernel-tree-"));
    writeFileSync(join(tree, "Makefile"), "VERSION = 6\nPATCHLEVEL = 8\n");
    return tree;
  }

  it("uses configured VM artifacts as the fastest cache hit", () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-kernel-env-"));
    const kernel = join(dir, "bzImage");
    const disk = join(dir, "rootfs.img");
    const config = join(dir, "kernel.config");
    writeFileSync(kernel, "kernel");
    writeFileSync(disk, "disk");
    writeFileSync(config, "config");
    process.env["0SEC_KERNEL_QEMU_KERNEL"] = kernel;
    process.env["0SEC_KERNEL_QEMU_DISK"] = disk;
    process.env["0SEC_KERNEL_QEMU_CONFIG"] = config;

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
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));

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
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));

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
    delete process.env["0SEC_KERNEL_QEMU_KERNEL"];
    delete process.env["0SEC_KERNEL_QEMU_DISK"];
    delete process.env["0SEC_KERNEL_QEMU_CONFIG"];
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  function makeTree(): string {
    const tree = mkdtempSync(join(tmpdir(), "0sec-kernel-tree-"));
    writeFileSync(join(tree, "Makefile"), "VERSION = 6\nPATCHLEVEL = 8\n");
    return tree;
  }

  function makeReproducer(name: string, content = "int main(void) { return 0; }\n"): string {
    const dir = mkdtempSync(join(tmpdir(), "0sec-kernel-repro-"));
    const repro = join(dir, name);
    writeFileSync(repro, content, "utf-8");
    return repro;
  }

  it("reports build_cache_hit=true on cache reuse + reproduced signature match", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
    const tree = makeTree();
    // First call populates the cache.
    primeCacheForTree(tree, cacheDir);
    const reproPath = makeReproducer("poc.c");
    const dmesgOut = join(mkdtempSync(join(tmpdir(), "0sec-verify-")), "dmesg.log");

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

  it("binds and persists a requested zero-cap receipt", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
    const tree = makeTree(); primeCacheForTree(tree, cacheDir);
    const reproPath = makeReproducer("poc.c");
    const dmesgOut = join(mkdtempSync(join(tmpdir(), "0sec-attest-")), "dmesg.log");
    const result = await verifyKernelFinding({ reproducerPath: reproPath, kernelTree: tree, cacheDir, dmesgOutPath: dmesgOut, expectedSignature: "KASAN: uaf", executionIdentity: { uid: 65534, gid: 65534 }, logger: () => undefined, buildRunner: () => { throw new Error("cache hit"); }, vmRunner: async (report) => ({ compiled: true, executed: true, output: "", dmesg: "KASAN: uaf", exitCode: 0, timedOut: false, executionAttestation: parseKernelExecutionAttestation(receiptForRequest(report.executionAttestationRequest!)) }) });
    expect(result.status).toBe("reproduced");
    expect(result.executionAttestation?.effectiveUid).toBe(65534);
    expect(result.executionAttestationSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(existsSync(result.executionAttestationPath!)).toBe(true);
  });

  it("fails closed when an explicit drop produces no receipt", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-")); const tree = makeTree(); primeCacheForTree(tree, cacheDir); const reproPath = makeReproducer("poc.c");
    const result = await verifyKernelFinding({ reproducerPath: reproPath, kernelTree: tree, cacheDir, executionIdentity: { uid: 65534, gid: 65534 }, logger: () => undefined, buildRunner: () => { throw new Error("cache hit"); }, vmRunner: async () => ({ compiled: true, executed: true, output: "", dmesg: "KASAN: uaf", exitCode: 0, timedOut: false }) });
    expect(result.status).toBe("run_failed");
  });

  it("fails closed if the host kernel image changes while the VM is running", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-")); const tree = makeTree(); primeCacheForTree(tree, cacheDir); const reproPath = makeReproducer("poc.c");
    const result = await verifyKernelFinding({ reproducerPath: reproPath, kernelTree: tree, cacheDir, executionIdentity: { uid: 65534, gid: 65534 }, logger: () => undefined, buildRunner: () => { throw new Error("cache hit"); }, vmRunner: async (report) => {
      const image = process.env["0SEC_KERNEL_QEMU_KERNEL"]!;
      chmodSync(image, 0o644);
      writeFileSync(image, "mutated-after-launch");
      return { compiled: true, executed: true, output: "", dmesg: "KASAN: uaf", exitCode: 0, timedOut: false, executionAttestation: parseKernelExecutionAttestation(receiptForRequest(report.executionAttestationRequest!)) };
    } });
    expect(result.status).toBe("run_failed");
    expect(result.executionAttestation).toBeUndefined();
  });

  it("launches from a private staged image so mutation of the cache artifact cannot swap the boot", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-")); const tree = makeTree(); primeCacheForTree(tree, cacheDir); const reproPath = makeReproducer("poc.c");
    const artifacts = prepareKernelVmArtifacts({ kernelTree: tree, cacheDir, logger: () => undefined, buildRunner: () => { throw new Error("cache hit"); } });
    let launchedPath = "";
    const result = await verifyKernelFinding({ reproducerPath: reproPath, kernelTree: tree, cacheDir, expectedSignature: "KASAN: uaf", executionIdentity: { uid: 65534, gid: 65534 }, logger: () => undefined, buildRunner: () => { throw new Error("cache hit"); }, vmRunner: async (report) => {
      launchedPath = process.env["0SEC_KERNEL_QEMU_KERNEL"]!;
      writeFileSync(artifacts.kernelImage, "swapped-original-cache-image");
      return { compiled: true, executed: true, output: "", dmesg: "KASAN: uaf", exitCode: 0, timedOut: false, executionAttestation: parseKernelExecutionAttestation(receiptForRequest(report.executionAttestationRequest!)) };
    } });
    expect(launchedPath).not.toBe(artifacts.kernelImage);
    expect(result.status).toBe("reproduced");
  });

  it("converts malformed runtime receipts to run_failed instead of throwing", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-")); const tree = makeTree(); primeCacheForTree(tree, cacheDir); const reproPath = makeReproducer("poc.c");
    const result = await verifyKernelFinding({ reproducerPath: reproPath, kernelTree: tree, cacheDir, executionIdentity: { uid: 65534, gid: 65534 }, logger: () => undefined, buildRunner: () => { throw new Error("cache hit"); }, vmRunner: async (report) => {
      const receipt = parseKernelExecutionAttestation(receiptForRequest(report.executionAttestationRequest!));
      return { compiled: true, executed: true, output: "", dmesg: "KASAN: uaf", exitCode: 0, timedOut: false, executionAttestation: { ...receipt, observedKernelRelease: "6.12.93" } };
    } });
    expect(result.status).toBe("run_failed");
  });

  it("detects an unexpected-but-recognised crash as no-match when expectedSignature mismatches", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
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
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
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
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
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
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
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
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
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

  it("matches a widened KCSAN data-race splat and confirms (closes the race loop)", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);
    const reproPath = makeReproducer("race.c");

    // No expectedSignature → the detectKernelSignature table must recognize the
    // KCSAN report on its own. This is the loop kcsan-race.ts + patch-to-poc.ts
    // could not close before (KASAN table was blind to data-races).
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
        output: "ran",
        dmesg: [
          "==================================================================",
          "BUG: KCSAN: data-race in ep_poll / ep_free",
          "",
          "write to 0xffff8881033c1a40 of 8 bytes by task 6398 on cpu 0:",
          " ep_free+0x33c/0x8d0 fs/eventpoll.c:900",
          "read to 0xffff8881033c1a40 of 8 bytes by task 6403 on cpu 1:",
          " ep_poll+0x1c/0x680 fs/eventpoll.c:1900",
          "==================================================================",
        ].join("\n"),
        exitCode: 0,
        timedOut: false,
      }),
    });

    expect(result.status).toBe("reproduced");
    expect(result.signature).toBe("kcsan-data-race");
  });

  it("confirms a KCSAN race against the patch-to-poc expected signature", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);
    const reproPath = makeReproducer("race.c");

    const result = await verifyKernelFinding({
      reproducerPath: reproPath,
      kernelTree: tree,
      cacheDir,
      // The exact string patch-to-poc.ts emits for a race finding.
      expectedSignature: "KCSAN: data-race",
      logger: () => undefined,
      buildRunner: () => {
        throw new Error("cache hit should not rebuild");
      },
      vmRunner: async () => ({
        compiled: true,
        executed: true,
        output: "ran",
        dmesg: "BUG: KCSAN: data-race in ext4_free_inode / ext4_mark_iloc_dirty",
        exitCode: 0,
        timedOut: false,
      }),
    });

    expect(result.status).toBe("reproduced");
    expect(result.signature).toBe("KCSAN: data-race");
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
    delete process.env["0SEC_KERNEL_QEMU_KERNEL"];
    delete process.env["0SEC_KERNEL_QEMU_DISK"];
    delete process.env["0SEC_KERNEL_QEMU_CONFIG"];
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  function makeTree(): string {
    const tree = mkdtempSync(join(tmpdir(), "0sec-kernel-tree-"));
    writeFileSync(join(tree, "Makefile"), "VERSION = 6\nPATCHLEVEL = 8\n");
    return tree;
  }

  function makeReproducer(name: string): string {
    const dir = mkdtempSync(join(tmpdir(), "0sec-kernel-repro-"));
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
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
    const tree = makeTree();
    primeCacheForTree(tree, cacheDir);

    const result = await verifyAcrossBoots({
      reproducerPath: makeReproducer("poc.c"),
      kernelTree: tree,
      cacheDir,
      boots: 3,
      minHits: 2,
      expectedSignature: "KASAN: slab-use-after-free",
      dmesgOutPath: join(cacheDir, "nboot-evidence.dmesg"),
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
    expect(result.bootResults).toHaveLength(3);
    expect(result.bootResults.every((boot) => existsSync(boot.dmesg_path))).toBe(true);
    expect(new Set(result.bootResults.map((boot) => boot.dmesg_path)).size).toBe(3);
    expect(result.bootResults.map((boot) => boot.dmesg_path)).toEqual([
      join(cacheDir, "nboot-evidence.dmesg"),
      join(cacheDir, "nboot-evidence.dmesg.boot-2"),
      join(cacheDir, "nboot-evidence.dmesg.boot-3"),
    ]);
  });

  it("writes a schema-v2 manifest only for invariant provenance and distinct fresh boots", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
    const tree = makeTree(); primeCacheForTree(tree, cacheDir);
    let boot = 0;
    const result = await verifyAcrossBoots({
      reproducerPath: makeReproducer("poc.c"), kernelTree: tree, cacheDir, boots: 2, minHits: 2,
      expectedSignature: "KASAN: uaf", executionIdentity: { uid: 65534, gid: 65534 }, dmesgOutPath: join(cacheDir, "proof.dmesg"), logger: () => undefined,
      buildRunner: () => { throw new Error("cache hit"); },
      vmRunner: async (report) => ({ compiled: true, executed: true, output: "", dmesg: "KASAN: uaf", exitCode: 0, timedOut: false, executionAttestation: parseKernelExecutionAttestation(receiptForRequest(report.executionAttestationRequest!, `00000000-0000-4000-8000-${String(++boot).padStart(12, "0")}`)) }),
    });
    expect(result.status).toBe("reproduced");
    expect(result.nbootStable).toBe(true);
    const manifest = JSON.parse(readFileSync(result.executionAttestationManifestPath!, "utf8"));
    expect(manifest).toMatchObject({ schemaVersion: 2, expectedKernelRelease: "6.8.0", executionIdentity: { uid: 65534, gid: 65534 } });
    expect(manifest.boots).toHaveLength(2);
    expect(new Set(manifest.boots.map((item: { bootId: string }) => item.bootId)).size).toBe(2);
    expect(manifest.boots.every((item: { dmesgSha256: string }) => /^[a-f0-9]{64}$/.test(item.dmesgSha256))).toBe(true);
  });

  it("revokes N-boot stability when two hits claim the same boot ID", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
    const tree = makeTree(); primeCacheForTree(tree, cacheDir);
    const result = await verifyAcrossBoots({
      reproducerPath: makeReproducer("poc.c"), kernelTree: tree, cacheDir, boots: 2, minHits: 2,
      expectedSignature: "KASAN: uaf", executionIdentity: { uid: 65534, gid: 65534 }, logger: () => undefined,
      buildRunner: () => { throw new Error("cache hit"); },
      vmRunner: async (report) => ({ compiled: true, executed: true, output: "", dmesg: "KASAN: uaf", exitCode: 0, timedOut: false, executionAttestation: parseKernelExecutionAttestation(receiptForRequest(report.executionAttestationRequest!)) }),
    });
    expect(result.bootHits).toBe(2);
    expect(result.nbootStable).toBe(false);
    expect(result.status).toBe("run_failed");
    expect(result.executionAttestationManifestPath).toBeUndefined();
  });

  it("declares NOT stable when the signature fires in only 1 of 3 boots", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
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
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
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

  it("collects and dedupes PCs across per-program coverage_prog* shards", () => {
    // syz-execprog -coverfile=<prefix> writes per-program/per-call shards named
    // `coverage_prog<N>.<call>` (e.g. coverage_prog0.0). The guest cats every
    // shard into coverage.log; parseCoveragePcs dedupes PCs across them. This
    // simulates that concatenation end-to-end so #948's feedback loop sees PCs.
    const share = mkdtempSync(join(tmpdir(), "0sec-cov-shards-"));
    try {
      writeFileSync(
        join(share, "coverage_prog0.0"),
        "0xffffffff81234500\n0xffffffff81234540\n",
      );
      writeFileSync(
        join(share, "coverage_prog0.1"),
        "0xffffffff81234540\n0xffffffff81234560\n", // overlaps prog0.0
      );
      writeFileSync(
        join(share, "coverage_prog1.0"),
        "0xffffffff81234560\n0x1000\n", // overlaps prog0.1
      );

      // Mirror the guest cat over the coverage_prog* shards.
      const shards = ["coverage_prog0.0", "coverage_prog0.1", "coverage_prog1.0"]
        .map((f) => readFileSync(join(share, f), "utf-8"))
        .join("");
      const pcs = parseCoveragePcs(shards);

      expect(pcs).toEqual([
        "0x1000",
        "0xffffffff81234500",
        "0xffffffff81234540",
        "0xffffffff81234560",
      ]);
    } finally {
      rmSync(share, { recursive: true, force: true });
    }
  });
});

describe("buildKernelAppend — KASLR knob", () => {
  it("boots nokaslr by default (stable verification addresses)", () => {
    const append = buildKernelAppend(false);
    expect(append).toContain("nokaslr");
    expect(append).not.toMatch(/\bkaslr\b(?<!nokaslr)/);
    // historical contract preserved otherwise.
    expect(append).toContain("init=/sbin/0sec-init");
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

describe("weaponize-initramfs lane", () => {
  const originalEnv = { ...process.env };
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("buildInitramfsKernelAppend boots rdinit=/init, NO 9p root disk", () => {
    const append = buildInitramfsKernelAppend(false);
    expect(append).toContain("rdinit=/init");
    expect(append).toContain("kasan_multi_shot=1"); // count every UAF, not just the first
    expect(append).toContain("nokaslr");
    expect(append).toContain("panic=-1");
    // The rootfs IS the initramfs — there is no disk to mount.
    expect(append).not.toContain("root=/dev/vda");
    // KASLR knob mirrors the 9p lane.
    expect(buildInitramfsKernelAppend(true)).toContain(" kaslr ");
  });

  it("renderInitramfsInitScript insmods modules and passes race env through busybox env", () => {
    const init = renderInitramfsInitScript(
      ["snd-mtpav.ko"],
      { "0SEC_RACE_SECONDS": "35", "0SEC_RACE_FLOOD_THREADS": "4" },
      30,
    );
    expect(init).toContain("#!/bin/busybox sh");
    expect(init).toContain("mount -t proc none /proc");
    // the module the snd-seq-midi UAF needs (the midisynth port) is insmod'd
    expect(init).toContain("insmod /lib/modules/snd-mtpav.ko");
    // Shell identifiers cannot start with a digit, so these must be argv
    // assignments to busybox env rather than broken `export 0SEC_...` lines.
    expect(init).toContain("/bin/busybox env 0SEC_RACE_SECONDS='35' 0SEC_RACE_FLOOD_THREADS='4'");
    expect(init).not.toContain("export 0SEC_RACE_");
    // the host-compiled static exploit is run under busybox `timeout` (positional
    // SECS arg — NOT GNU `-t SECS`, which busybox rejects). Caps a hung flood.
    // Its high-volume marker output goes to a tmpfs file during the race (so the
    // slow UART does not wedge the CPU and starve the race), then is cat'd to
    // serial after — the oracle reads the same markers either way.
    expect(init).toContain("timeout 30 /exploit > /tmp/run.log");
    expect(init).toContain("cat /tmp/run.log");
    expect(init).not.toContain("timeout -t");
    // poweroff so the host's QEMU-exit wait returns
    expect(init).toContain("poweroff -f");
    expect(init).toContain("0SEC-INITRAMFS done");
  });

  it("forwards only validated race environment keys into the guest command", () => {
    const init = renderInitramfsInitScript(
      [],
      { "0SEC_RACE_SECONDS": "35", "bad; poweroff": "now" },
      30,
    );
    expect(init).toContain("0SEC_RACE_SECONDS='35'");
    expect(init).not.toContain("bad; poweroff");
  });

  it("buildInitramfsQemuCommand uses -initrd with NO -drive/-virtfs (9p)", () => {
    const config: KernelVmConfig = {
      qemuBinary: "qemu-system-x86_64",
      kernelImage: "/k/bzImage",
      diskImage: "/k/rootfs.img",
      diskFormat: "raw",
      bootTimeoutSec: 120,
      memoryMb: 2048,
      smp: 2,
      kernelAppend: "ignored",
      timeoutSec: 60,
      shareTag: "osecshare",
      qemuAccel: "kvm",
    };
    const { command, args } = buildInitramfsQemuCommand(
      config,
      "/tmp/serial.log",
      "/tmp/initramfs.cpio.gz",
      buildInitramfsKernelAppend(false),
    );
    expect(command).toBe("qemu-system-x86_64");
    const joined = args.join(" ");
    expect(joined).toContain("-initrd /tmp/initramfs.cpio.gz");
    expect(joined).toContain("-kernel /k/bzImage");
    expect(joined).toContain("rdinit=/init");
    expect(joined).toContain("-accel kvm");
    // NO heavy 9p root disk in this lane.
    expect(joined).not.toContain("-drive");
    expect(joined).not.toContain("-virtfs");
  });

  it("buildQemuCommand snapshots the root disk for independent verification boots", () => {
    const config: KernelVmConfig = {
      qemuBinary: "qemu-system-x86_64",
      kernelImage: "/k/bzImage",
      diskImage: "/k/rootfs.img",
      diskFormat: "raw",
      bootTimeoutSec: 120,
      memoryMb: 2048,
      smp: 2,
      kernelAppend: "root=/dev/vda",
      timeoutSec: 60,
      shareTag: "osecshare",
    };
    const { args } = buildQemuCommand(config, "/tmp/serial.log", "/tmp/share");
    expect(args).toContain("-snapshot");
    expect(args.join(" ")).toContain("-drive file=/k/rootfs.img,format=raw,if=virtio");
  });

  it("loadKernelVmConfigFromEnv enables the lane via USE_KERNEL_WEAPONIZE / INITRAMFS env", () => {
    process.env["0SEC_KERNEL_QEMU_KERNEL"] = "/k/bzImage";
    process.env["0SEC_KERNEL_QEMU_DISK"] = "/k/rootfs.img";
    delete process.env["0SEC_KERNEL_QEMU_INITRAMFS"];
    delete process.env.USE_KERNEL_WEAPONIZE;
    expect(loadKernelVmConfigFromEnv().weaponizeInitramfs).toBe(false);

    process.env.USE_KERNEL_WEAPONIZE = "1";
    process.env["0SEC_KERNEL_QEMU_INITRAMFS_MODULES"] = "/a/snd-mtpav.ko:/b/kdelay.ko";
    const cfg = loadKernelVmConfigFromEnv();
    expect(cfg.weaponizeInitramfs).toBe(true);
    expect(cfg.initramfsModules).toEqual(["/a/snd-mtpav.ko", "/b/kdelay.ko"]);
  });
});

describe("renderRealIpiRaceHarness — ExpRace userspace race harness", () => {
  it("renders a compilable racer with the non-crashing retry loop and env budget", () => {
    const c = renderRealIpiRaceHarness({
      raceOpA: "close(fd);",
      raceOpB: "ioctl(fd, 0, 0);",
      maxIters: 12345,
      seconds: 30,
    });
    // _GNU_SOURCE must precede includes (affinity macros).
    expect(c.indexOf("#define _GNU_SOURCE")).toBe(0);
    expect(c).toContain("#include <pthread.h>");
    // two CPU-pinned racer threads carrying the supplied ops.
    expect(c).toContain("osec_pin_cpu(0)");
    expect(c).toContain("osec_pin_cpu(1)"); // different CPUs by default
    expect(c).toContain("close(fd);");
    expect(c).toContain("ioctl(fd, 0, 0);");
    // Bad Epoll non-crashing retry loop, budget overridable via env.
    expect(c).toContain('osec_env_long("0SEC_RACE_RETRIES", 12345)');
    expect(c).toContain('osec_env_long("0SEC_RACE_SECONDS", 30)');
    expect(c).toContain("time(NULL) < deadline");
    expect(c).toContain("0SEC-RACE");
  });

  it("splices the composed gadget setup C once, before the race loop", () => {
    const c = renderRealIpiRaceHarness({
      raceOpA: "a();",
      raceOpB: "b();",
      setupC: "/* SENTINEL_TACTIC */ membarrier_burst();",
    });
    expect(c).toContain("/* SENTINEL_TACTIC */ membarrier_burst();");
    // setup precedes the retry loop.
    expect(c.indexOf("SENTINEL_TACTIC")).toBeLessThan(c.indexOf("for (long iter"));
  });

  it("pins both racers to CPU 0 when sameCpu is set", () => {
    const c = renderRealIpiRaceHarness({ raceOpA: "a();", raceOpB: "b();", sameCpu: true });
    // both racer pin calls target CPU 0.
    expect(c.match(/osec_pin_cpu\(1\)/)).toBeNull();
  });

  it("merges tactic headers without duplicating _GNU_SOURCE", () => {
    const c = renderRealIpiRaceHarness({
      raceOpA: "a();",
      raceOpB: "b();",
      headers: ["#define _GNU_SOURCE", "#include <sys/mman.h>", "#include <sys/mman.h>"],
    });
    expect((c.match(/#define _GNU_SOURCE/g) ?? []).length).toBe(1);
    expect((c.match(/#include <sys\/mman.h>/g) ?? []).length).toBe(1);
  });
});

describe("buildFlagsForProfile — KCSAN build profile", () => {
  it("kasan profile enables the KASAN/UBSAN sanitizer set", () => {
    const flags = buildFlagsForProfile("kasan");
    expect(flags).toContain("--enable CONFIG_KASAN");
    expect(flags).toContain("--enable CONFIG_UBSAN");
    expect(flags.some((f) => f.includes("CONFIG_KCSAN"))).toBe(false);
  });

  it("kcsan profile enables KCSAN + PREEMPT and turns KASAN off", () => {
    const flags = buildFlagsForProfile("kcsan");
    expect(flags).toContain("--enable CONFIG_KCSAN");
    expect(flags).toContain("--enable CONFIG_PREEMPT");
    expect(flags).toContain("--disable CONFIG_KASAN");
    // races should report every time, not once.
    expect(flags).toContain("--set-val CONFIG_KCSAN_REPORT_ONCE_IN_MS 0");
    // the two heavyweight sanitizers are not co-built.
    expect(flags.some((f) => f.includes("--enable CONFIG_KASAN"))).toBe(false);
  });

  it("plain profile turns BOTH sanitizers off (the non-KASAN reclaim-aliasing lane)", () => {
    const flags = buildFlagsForProfile("plain");
    expect(flags).toContain("--disable CONFIG_KASAN");
    expect(flags).toContain("--disable CONFIG_KCSAN");
    expect(flags.some((f) => f.startsWith("--enable CONFIG_KASAN"))).toBe(false);
  });

  it("throws loudly for an unrecognized profile", () => {
    expect(() => buildFlagsForProfile("defconfig+kasan")).toThrow(/unrecognized kernel config profile/);
    expect(RECOGNIZED_CONFIG_PROFILES).toEqual(["kasan", "kcsan", "plain"]);
  });
});

describe("kcsanConfigSupported — .config gate", () => {
  it("is true only when CONFIG_KCSAN=y is present", () => {
    expect(kcsanConfigSupported("CONFIG_KCSAN=y\nCONFIG_PREEMPT=y\n")).toBe(true);
    expect(kcsanConfigSupported("# CONFIG_KCSAN is not set\n")).toBe(false);
    expect(kcsanConfigSupported("CONFIG_KASAN=y\n")).toBe(false);
  });
});

describe("prepareKernelVmArtifacts — KCSAN fail-soft config gate", () => {
  const originalEnv = { ...process.env };
  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env["0SEC_KERNEL_QEMU_KERNEL"];
    delete process.env["0SEC_KERNEL_QEMU_DISK"];
  });
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  function makeTree(): string {
    const tree = mkdtempSync(join(tmpdir(), "0sec-kernel-tree-"));
    writeFileSync(join(tree, "Makefile"), "VERSION = 6\nPATCHLEVEL = 8\n");
    return tree;
  }

  it("WARNS (fail-soft) when the kcsan build produced a .config without CONFIG_KCSAN", () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
    const logs: string[] = [];
    prepareKernelVmArtifacts({
      kernelTree: makeTree(),
      cacheDir,
      configProfile: "kcsan",
      logger: (l) => logs.push(l),
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "kernel");
        writeFileSync(join(outDir, "rootfs.img"), "disk");
        // KCSAN did NOT land (arch/toolchain can't support it).
        writeFileSync(join(outDir, "kernel.config"), "# CONFIG_KCSAN is not set\n");
      },
    });
    expect(logs.some((l) => l.includes("[kcsan-gate] WARN") && l.includes("CONFIG_KCSAN"))).toBe(true);
  });

  it("does NOT warn when CONFIG_KCSAN is present, and never warns for kasan", () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "0sec-kernel-cache-"));
    const logs: string[] = [];
    prepareKernelVmArtifacts({
      kernelTree: makeTree(),
      cacheDir,
      configProfile: "kcsan",
      logger: (l) => logs.push(l),
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "kernel");
        writeFileSync(join(outDir, "rootfs.img"), "disk");
        writeFileSync(join(outDir, "kernel.config"), "CONFIG_KCSAN=y\nCONFIG_PREEMPT=y\n");
      },
    });
    expect(logs.some((l) => l.includes("[kcsan-gate] WARN"))).toBe(false);

    const logs2: string[] = [];
    prepareKernelVmArtifacts({
      kernelTree: makeTree(),
      cacheDir: mkdtempSync(join(tmpdir(), "0sec-kernel-cache-")),
      configProfile: "kasan",
      logger: (l) => logs2.push(l),
      buildRunner: ({ outDir }) => {
        writeFileSync(join(outDir, "bzImage"), "kernel");
        writeFileSync(join(outDir, "rootfs.img"), "disk");
        writeFileSync(join(outDir, "kernel.config"), "# CONFIG_KCSAN is not set\n");
      },
    });
    expect(logs2.some((l) => l.includes("[kcsan-gate]"))).toBe(false);
  });
});

describe("bug-attribution guard — out-of-band module-load denier", () => {
  const CANARY = "wk-cafef00dbabe";

  it("passes a legit insmod of the sanctioned target module", () => {
    const serial = [
      "=== 0SEC-INITRAMFS weaponize lane up ===",
      "insmod snd-mtpav.ko ok",
      `0SEC-CANARY:${CANARY}:ROOT uid=0`,
    ].join("\n");
    const v = detectOutOfBandModuleLoad(serial, ["snd-mtpav.ko"]);
    expect(v.denied).toBe(false);
    // dash/underscore + basename equivalence: target passed as a full host path.
    expect(detectOutOfBandModuleLoad("insmod snd_mtpav.ko ok", ["/root/mods/snd-mtpav.ko"]).denied).toBe(false);
  });

  it("denies an exploit that insmods a NON-target module to supply a primitive", () => {
    const src = 'int main(){ system("insmod /tmp/evil.ko"); printf("uid=0\\n"); }';
    const v = detectOutOfBandModuleLoad(src, ["snd-mtpav.ko"]);
    expect(v.denied).toBe(true);
    expect(v.method).toBe("insmod");
    expect(v.offendingModule).toContain("evil.ko");
  });

  it("denies a modprobe of a non-target module and any *_module syscall", () => {
    expect(detectOutOfBandModuleLoad("modprobe evilmod", []).denied).toBe(true);
    expect(detectOutOfBandModuleLoad("syscall(__NR_finit_module, fd, \"\", 0);", ["x.ko"]).method).toBe("finit_module");
    expect(detectOutOfBandModuleLoad("init_module(buf, len, \"\");", []).method).toBe("init_module");
  });

  it("does not false-trip on prose that merely mentions insmod without a .ko", () => {
    expect(detectOutOfBandModuleLoad("// we never insmod anything here", []).denied).toBe(false);
  });
});

describe("bug-attribution guard — hardcoded kernel-address static scan", () => {
  const KADDR = "0xffffffff81234567";

  it("flags a baked kernel address and REFUSES it under a KASLR-on claim with no leak", () => {
    const src = `unsigned long target = ${KADDR};`;
    const v = scanHardcodedKernelAddresses(src, "ran, no leak observed", { kaslrOn: true });
    expect(v.flagged).toBe(true);
    expect(v.addresses).toContain(KADDR);
    expect(v.leakProvenance).toBe(false);
    expect(v.verdict).toBe("refuse");
  });

  it("allows a baked static-symbol address under a sanctioned nokaslr climb (flagged only)", () => {
    const v = scanHardcodedKernelAddresses(`unsigned long t = ${KADDR};`, "no leak", { kaslrOn: false });
    expect(v.flagged).toBe(true);
    expect(v.verdict).toBe("allow");
  });

  it("allows a leak-derived address (ARB-READ marker present) even under KASLR-on", () => {
    const out = `0SEC-CANARY:x:ARB-READ:${KADDR}\nleaked kernel base ${KADDR}`;
    const v = scanHardcodedKernelAddresses(`unsigned long base = ${KADDR};`, out, { kaslrOn: true });
    expect(v.flagged).toBe(true);
    expect(v.leakProvenance).toBe(true);
    expect(v.verdict).toBe("allow");
  });

  it("does not flag a source with no canonical kernel-pointer literal", () => {
    const v = scanHardcodedKernelAddresses("int x = 0x41414141; long y = 0xdeadbeef;", "", { kaslrOn: true });
    expect(v.flagged).toBe(false);
    expect(v.verdict).toBe("allow");
  });
});

describe("assertBugAttribution — throws on a denial like a failed attestation binding", () => {
  it("throws on an out-of-band module load", () => {
    expect(() =>
      assertBugAttribution({
        exploitSource: 'system("insmod /tmp/evil.ko");',
        runOutput: "uid=0",
        targetModules: ["snd-mtpav.ko"],
        kaslrOn: false,
      }),
    ).toThrow(/out-of-band kernel module load/);
  });

  it("throws on an unprovenanced hardcoded address under KASLR-on", () => {
    expect(() =>
      assertBugAttribution({
        exploitSource: "unsigned long t = 0xffffffff81abcdef;",
        runOutput: "no leak here",
        targetModules: [],
        kaslrOn: true,
      }),
    ).toThrow(/hardcoded kernel address without leak provenance/);
  });

  it("passes a legit target insmod + leak-derived address", () => {
    expect(() =>
      assertBugAttribution({
        exploitSource: "unsigned long base = 0xffffffff81abcdef;",
        runOutput: "insmod snd-mtpav.ko ok\nARB-READ leaked 0xffffffff81abcdef\nuid=0",
        targetModules: ["snd-mtpav.ko"],
        kaslrOn: true,
      }),
    ).not.toThrow();
  });
});
