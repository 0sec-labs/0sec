import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, realpathSync, statSync, chmodSync } from "node:fs";
import type { ReproducerResult, CrashReport } from "./kernel-oracle.js";

export interface KernelVmConfig {
  qemuBinary: string;
  kernelImage: string;
  diskImage: string;
  diskFormat: "raw" | "qcow2";
  bootTimeoutSec: number;
  memoryMb: number;
  smp: number;
  kernelAppend: string;
  qemuAccel?: string;
  initrdPath?: string;
  timeoutSec: number;
  shareTag: string;
  artifactDir?: string;
  /**
   * KASLR control. Default `false` keeps the historical `nokaslr` boot (stable
   * symbol addresses for verification). Set `true` (PWNKIT_KERNEL_QEMU_KASLR=1)
   * to boot with KASLR ON — exercises a leak-dependent exploit under randomized
   * base. Only meaningful when the env append does not already pin (no)kaslr.
   */
  kaslr?: boolean;
  /**
   * Race-widening: inject `mdelay(<delayMs>)` at `<widenSymbol>+<widenOffset>`
   * via a kprobe module so the UAF/race window is best-effort widened. Wired
   * only when a kernel build tree is present in the guest; FAIL-SOFT otherwise
   * (the runner boots without widening and notes it). Parameterized here so the
   * harness can pass the finding's faulting PC + a delay.
   */
  widenSymbol?: string;
  widenOffset?: number;
  widenDelayMs?: number;
  /**
   * Guest kernel build tree (e.g. `/usr/src/linux`) used to compile the
   * race-widening kprobe module in-guest. Absent ⇒ widening is skipped.
   */
  guestKernelBuildDir?: string;
}

/**
 * Kernel build config profile name.
 *
 * Tier-1 verify (issue #271) lets callers pass arbitrary profile names that
 * the build script understands — e.g. `kasan`, `defconfig+kasan`. The
 * built-in build runner today only recognises `kasan`; custom names require
 * a custom `buildRunner` or an out-of-band script that maps the name to
 * a kernel `.config`.
 */
export type KernelConfigProfile = string;

export interface KernelBuildOptions {
  kernelTree: string;
  configProfile?: KernelConfigProfile;
  cacheDir?: string;
  force?: boolean;
  /** Optional logger for cache-hit / cache-miss diagnostics. */
  logger?: (line: string) => void;
  buildRunner?: (input: { kernelTree: string; outDir: string; configProfile: KernelConfigProfile }) => void;
}

export interface KernelVmArtifacts {
  kernelImage: string;
  diskImage: string;
  kernelConfig: string;
  cacheKey: string;
  cacheDir: string;
  cacheStatus: "hit" | "miss" | "env";
  configProfile: KernelConfigProfile;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function inferDiskFormat(diskImage: string): "raw" | "qcow2" {
  return diskImage.endsWith(".qcow2") || diskImage.endsWith(".qcow") ? "qcow2" : "raw";
}

function defaultKernelCacheDir(): string {
  return process.env.PWNKIT_KERNEL_BUILD_CACHE?.trim() ||
    join(homedir(), ".pwnkit", "kernel-cache");
}

/**
 * Identify the kernel tree for cache keying. Prefers the closest git tag
 * (so two checkouts of v6.8 share a cache entry), then HEAD rev, then a
 * realpath:mtime fingerprint for non-git trees.
 */
function kernelTreeFingerprint(kernelTree: string): string {
  try {
    const described = execFileSync("git", ["describe", "--tags", "--always", "--dirty"], {
      cwd: kernelTree,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (described) return described;
  } catch {
    // fall through
  }
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: kernelTree,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    const stat = statSync(kernelTree);
    return `${realpathSync(kernelTree)}:${Math.trunc(stat.mtimeMs)}`;
  }
}

function sanitizeForPath(value: string): string {
  // Keep cache directory names filesystem-safe across platforms.
  return value.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 64) || "rev";
}

function configNameHash(configProfile: KernelConfigProfile): string {
  return createHash("sha256").update(configProfile).digest("hex").slice(0, 12);
}

/**
 * Cache key shape per issue #271: `<rev-or-tag>-<config-hash>`.
 *
 * The rev component is sanitized (e.g. `v6.8` becomes `v6.8`, a dirty tree
 * `v6.8-dirty` keeps the suffix). A non-git tree falls back to the
 * legacy realpath:mtime fingerprint, hashed for compactness.
 */
function kernelBuildCacheKey(kernelTree: string, configProfile: KernelConfigProfile): string {
  const fingerprint = kernelTreeFingerprint(kernelTree);
  const revPart = fingerprint.includes(":")
    ? createHash("sha256").update(fingerprint).digest("hex").slice(0, 16)
    : sanitizeForPath(fingerprint);
  return `${revPart}-${configNameHash(configProfile)}`;
}

function artifactsExist(outDir: string): boolean {
  return existsSync(join(outDir, "bzImage")) &&
    existsSync(join(outDir, "rootfs.img")) &&
    existsSync(join(outDir, "kernel.config"));
}

function defaultBuildRunner(input: { kernelTree: string; outDir: string; configProfile: KernelConfigProfile }): void {
  const here = dirname(fileURLToPath(import.meta.url));
  const script = [
    join(here, "kernel-vm", "build-from-tree.sh"),
    join(process.cwd(), "packages/core/src/triage/kernel-vm/build-from-tree.sh"),
    join(process.cwd(), "src/triage/kernel-vm/build-from-tree.sh"),
  ].find((candidate) => existsSync(candidate));
  if (!script) {
    throw new Error(
      "kernel build script not found; set PWNKIT_KERNEL_QEMU_KERNEL/PWNKIT_KERNEL_QEMU_DISK to prebuilt artifacts or run from a source checkout",
    );
  }
  execFileSync("bash", [script, input.kernelTree, input.outDir, input.configProfile], {
    stdio: "inherit",
  });
}

export function prepareKernelVmArtifacts(opts: KernelBuildOptions): KernelVmArtifacts {
  const configProfile: KernelConfigProfile = opts.configProfile ?? "kasan";
  const log = opts.logger ?? ((line: string) => console.log(line));
  const envKernel = process.env.PWNKIT_KERNEL_QEMU_KERNEL?.trim();
  const envDisk = process.env.PWNKIT_KERNEL_QEMU_DISK?.trim();
  if (!opts.force && envKernel && envDisk && existsSync(envKernel) && existsSync(envDisk)) {
    log(`[kernel-cache] env-override: using PWNKIT_KERNEL_QEMU_KERNEL/DISK (skipping build)`);
    return {
      kernelImage: envKernel,
      diskImage: envDisk,
      kernelConfig: process.env.PWNKIT_KERNEL_QEMU_CONFIG?.trim() || "",
      cacheKey: "env",
      cacheDir: "",
      cacheStatus: "env",
      configProfile,
    };
  }

  const kernelTree = realpathSync(resolve(opts.kernelTree));
  const cacheRoot = resolve(opts.cacheDir ?? defaultKernelCacheDir());
  const cacheKey = kernelBuildCacheKey(kernelTree, configProfile);
  const outDir = join(cacheRoot, cacheKey);
  mkdirSync(outDir, { recursive: true });

  if (!opts.force && artifactsExist(outDir)) {
    log(`[kernel-cache] hit: ${outDir} (config=${configProfile})`);
    return {
      kernelImage: join(outDir, "bzImage"),
      diskImage: join(outDir, "rootfs.img"),
      kernelConfig: join(outDir, "kernel.config"),
      cacheKey,
      cacheDir: outDir,
      cacheStatus: "hit",
      configProfile,
    };
  }

  log(`[kernel-cache] miss: building into ${outDir} (config=${configProfile})`);
  const runner = opts.buildRunner ?? defaultBuildRunner;
  runner({ kernelTree, outDir, configProfile });
  if (!artifactsExist(outDir)) {
    throw new Error(`kernel build did not produce bzImage/rootfs.img/kernel.config in ${outDir}`);
  }

  return {
    kernelImage: join(outDir, "bzImage"),
    diskImage: join(outDir, "rootfs.img"),
    kernelConfig: join(outDir, "kernel.config"),
    cacheKey,
    cacheDir: outDir,
    cacheStatus: "miss",
    configProfile,
  };
}

export function loadKernelVmConfigFromEnv(): KernelVmConfig {
  const kernelImage = process.env.PWNKIT_KERNEL_QEMU_KERNEL?.trim();
  const diskImage = process.env.PWNKIT_KERNEL_QEMU_DISK?.trim();

  const missing = [
    !kernelImage ? "PWNKIT_KERNEL_QEMU_KERNEL" : "",
    !diskImage ? "PWNKIT_KERNEL_QEMU_DISK" : "",
  ].filter(Boolean);

  if (missing.length > 0) {
    throw new Error(
      `kernel VM runner is enabled but missing required env vars: ${missing.join(", ")}`,
    );
  }

  const resolvedKernelImage = kernelImage!;
  const resolvedDiskImage = diskImage!;

  // KASLR knob: default OFF (nokaslr) for stable verification; opt in with
  // PWNKIT_KERNEL_QEMU_KASLR=1. An explicit env append always wins (the operator
  // pinned the cmdline by hand), so we only inject (no)kaslr into the default.
  const kaslr = /^(1|true|on|yes)$/i.test(process.env.PWNKIT_KERNEL_QEMU_KASLR?.trim() ?? "");
  const explicitAppend = process.env.PWNKIT_KERNEL_QEMU_APPEND?.trim();
  const kernelAppend = explicitAppend || buildKernelAppend(kaslr);

  const widenSymbol = process.env.PWNKIT_KERNEL_QEMU_WIDEN_SYMBOL?.trim() || undefined;
  const widenOffsetRaw = process.env.PWNKIT_KERNEL_QEMU_WIDEN_OFFSET?.trim();
  const widenDelayRaw = process.env.PWNKIT_KERNEL_QEMU_WIDEN_DELAY_MS?.trim();

  return {
    qemuBinary: process.env.PWNKIT_KERNEL_QEMU_BINARY?.trim() || "qemu-system-x86_64",
    kernelImage: resolvedKernelImage,
    diskImage: resolvedDiskImage,
    diskFormat: (process.env.PWNKIT_KERNEL_QEMU_DISK_FORMAT?.trim() as "raw" | "qcow2" | undefined) || inferDiskFormat(resolvedDiskImage),
    bootTimeoutSec: parseInt(process.env.PWNKIT_KERNEL_QEMU_BOOT_TIMEOUT_SEC?.trim() || "120", 10),
    memoryMb: parseInt(process.env.PWNKIT_KERNEL_QEMU_MEMORY_MB?.trim() || "2048", 10),
    smp: parseInt(process.env.PWNKIT_KERNEL_QEMU_SMP?.trim() || "2", 10),
    kernelAppend,
    qemuAccel: process.env.PWNKIT_KERNEL_QEMU_ACCEL?.trim() || undefined,
    initrdPath: process.env.PWNKIT_KERNEL_QEMU_INITRD?.trim() || undefined,
    timeoutSec: parseInt(process.env.PWNKIT_KERNEL_QEMU_TIMEOUT_SEC?.trim() || "60", 10),
    shareTag: process.env.PWNKIT_KERNEL_QEMU_SHARE_TAG?.trim() || "pwnkitshare",
    artifactDir: process.env.PWNKIT_KERNEL_QEMU_ARTIFACT_DIR?.trim() || undefined,
    kaslr,
    ...(widenSymbol ? { widenSymbol } : {}),
    ...(widenOffsetRaw && Number.isFinite(parseInt(widenOffsetRaw, 16))
      ? { widenOffset: parseInt(widenOffsetRaw, 16) }
      : {}),
    ...(widenDelayRaw && Number.isFinite(parseInt(widenDelayRaw, 10))
      ? { widenDelayMs: parseInt(widenDelayRaw, 10) }
      : {}),
    ...(process.env.PWNKIT_KERNEL_QEMU_GUEST_BUILD_DIR?.trim()
      ? { guestKernelBuildDir: process.env.PWNKIT_KERNEL_QEMU_GUEST_BUILD_DIR!.trim() }
      : {}),
  };
}

/**
 * Build the default kernel cmdline, parameterized by the KASLR knob. The only
 * difference from the historical default is `nokaslr` (off) vs `kaslr` (on);
 * everything else (console, root, panic, init) is unchanged.
 */
export function buildKernelAppend(kaslr: boolean): string {
  const base = "console=ttyS0 root=/dev/vda rw";
  const tail = "panic=-1 init=/sbin/pwnkit-init";
  return `${base} ${kaslr ? "kaslr" : "nokaslr"} ${tail}`;
}

/**
 * Source of a minimal kprobe module that injects `mdelay(<delayMs>)` at the
 * faulting `<symbol>+<offset>` to best-effort widen a UAF/race window. Returns
 * the C source; the guest runner compiles + insmods it against an in-guest
 * kernel build tree, and FAILS SOFT (boots without widening) when no tree is
 * present. Pure string builder — exposed for unit testing the emitted source.
 */
export function renderRaceWidenModuleSource(
  symbol: string,
  offset: number,
  delayMs: number,
): string {
  const off = `0x${offset.toString(16)}`;
  return [
    "// pwnkit race-widening kprobe: inject mdelay() at the faulting PC to widen",
    "// the UAF/race window. Best-effort; harmless if the probe fails to register.",
    "#include <linux/module.h>",
    "#include <linux/kernel.h>",
    "#include <linux/kprobes.h>",
    "#include <linux/delay.h>",
    "",
    "MODULE_LICENSE(\"GPL\");",
    "",
    `static unsigned long widen_delay_ms = ${delayMs};`,
    "module_param(widen_delay_ms, ulong, 0644);",
    "",
    "static struct kprobe kp = {",
    `    .symbol_name = "${symbol}",`,
    `    .offset = ${off},`,
    "};",
    "",
    "static int handler_pre(struct kprobe *p, struct pt_regs *regs) {",
    "    mdelay(widen_delay_ms);",
    "    return 0;",
    "}",
    "",
    "static int __init widen_init(void) {",
    "    kp.pre_handler = handler_pre;",
    `    pr_info("pwnkit-widen: probing ${symbol}+${off} delay=%lums\\n", widen_delay_ms);`,
    "    return register_kprobe(&kp);",
    "}",
    "",
    "static void __exit widen_exit(void) { unregister_kprobe(&kp); }",
    "",
    "module_init(widen_init);",
    "module_exit(widen_exit);",
  ].join("\n");
}

export function buildQemuCommand(
  config: KernelVmConfig,
  serialLogPath: string,
  sharedDir: string,
): { command: string; args: string[] } {
  const args = [
    "-m", String(config.memoryMb),
    "-smp", String(config.smp),
    "-kernel", config.kernelImage,
    "-drive", `file=${config.diskImage},format=${config.diskFormat},if=virtio`,
    "-append", config.kernelAppend,
    "-virtfs", `local,path=${sharedDir},mount_tag=${config.shareTag},security_model=none,id=hostshare`,
    "-nographic",
    "-monitor", "none",
    "-serial", `file:${serialLogPath}`,
    "-no-reboot",
  ];

  if (config.qemuAccel) {
    args.push("-accel", config.qemuAccel);
  }
  if (config.initrdPath) {
    args.push("-initrd", config.initrdPath);
  }

  return { command: config.qemuBinary, args };
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function stopVm(proc: ReturnType<typeof spawn>): Promise<void> {
  if (proc.exitCode !== null || proc.killed) return;
  proc.kill("SIGTERM");
  const deadline = Date.now() + 10_000;
  while (proc.exitCode === null && Date.now() < deadline) {
    await sleep(250);
  }
  if (proc.exitCode === null) {
    proc.kill("SIGKILL");
  }
}

function renderGuestRunnerScript(config: KernelVmConfig, language: "c" | "syz" | "bash"): string {
  if (language === "syz") {
    return [
      "#!/bin/sh",
      "set -eu",
      "SHARE_DIR=/mnt/pwnkit",
      "WORK_DIR=/tmp/pwnkit-run",
      "mkdir -p \"$WORK_DIR\"",
      "compiled=0",
      "executed=0",
      "exit_code=0",
      "timed_out=0",
      "cp \"$SHARE_DIR/repro.syz\" \"$WORK_DIR/repro.syz\"",
      "if command -v syz-execprog >/dev/null 2>&1; then",
      "  compiled=1",
      "  : > \"$SHARE_DIR/compile.log\"",
      "else",
      "  printf '%s\\n' 'syz-execprog not found in guest' > \"$SHARE_DIR/compile.log\"",
      "  exit_code=127",
      "fi",
      "if [ \"$compiled\" = \"1\" ]; then",
      "  dmesg -C 2>/dev/null || true",
      `  if timeout ${shellQuote(String(config.timeoutSec))}s syz-execprog "$WORK_DIR/repro.syz" >"$SHARE_DIR/run.log" 2>&1; then`,
      "    executed=1",
      "    exit_code=0",
      "  else",
      "    exit_code=$?",
      "    if [ \"$exit_code\" = \"124\" ]; then",
      "      timed_out=1",
      "    else",
      "      executed=1",
      "    fi",
      "  fi",
      "else",
      "  : > \"$SHARE_DIR/run.log\"",
      "fi",
      "dmesg 2>/dev/null > \"$SHARE_DIR/dmesg.log\" || true",
      "printf '%s\\n' \"$compiled\" > \"$SHARE_DIR/compiled.ok\"",
      "printf '%s\\n' \"$executed\" > \"$SHARE_DIR/executed.ok\"",
      "printf '%s\\n' \"$exit_code\" > \"$SHARE_DIR/exit_code\"",
      "printf '%s\\n' \"$timed_out\" > \"$SHARE_DIR/timed_out\"",
      "sync",
    ].join("\n");
  }

  // Optional race-widening prologue: compile + insmod a kprobe module that
  // injects mdelay() at the faulting PC. FAIL-SOFT — every failure path notes it
  // in widen.log and proceeds without widening (the run still happens).
  const widenLines: string[] =
    config.widenSymbol !== undefined &&
    config.widenOffset !== undefined &&
    config.widenDelayMs !== undefined &&
    config.guestKernelBuildDir
      ? [
          "# ── Race-widening (best-effort, fail-soft) ─────────────────────────",
          `KBUILD_DIR=${shellQuote(config.guestKernelBuildDir)}`,
          "widened=0",
          'if [ -d "$KBUILD_DIR" ] && command -v make >/dev/null 2>&1; then',
          '  cp "$SHARE_DIR/pwnkit_widen.c" "$WORK_DIR/pwnkit_widen.c" 2>/dev/null || true',
          '  printf "obj-m += pwnkit_widen.o\\n" > "$WORK_DIR/Makefile"',
          '  if make -C "$KBUILD_DIR" M="$WORK_DIR" modules >"$SHARE_DIR/widen.log" 2>&1 \\',
          '     && insmod "$WORK_DIR/pwnkit_widen.ko" >>"$SHARE_DIR/widen.log" 2>&1; then',
          "    widened=1",
          '    printf "%s\\n" "pwnkit-widen: insmod ok" >> "$SHARE_DIR/widen.log"',
          "  else",
          '    printf "%s\\n" "pwnkit-widen: build/insmod failed — running WITHOUT widening" >> "$SHARE_DIR/widen.log"',
          "  fi",
          "else",
          '  printf "%s\\n" "pwnkit-widen: no kernel build tree in guest — running WITHOUT widening" > "$SHARE_DIR/widen.log"',
          "fi",
          'printf "%s\\n" "$widened" > "$SHARE_DIR/widened.ok"',
        ]
      : [];

  return [
    "#!/bin/sh",
    "set -eu",
    "# uid-drop exec contract: this runner executes the reproducer as the guest",
    "# init (uid 0). A weaponization exploit drops to an unprivileged uid itself",
    "# (setuid(65534)) BEFORE firing its root tail, then re-checks getuid()==0",
    "# after — so the captured output carries an ordered DROP(uid!=0)→ROOT(uid=0)",
    "# witness the oracle uses to confirm a genuine escalation. We must therefore",
    "# run it directly (as root), NOT via su/sudo to a lower uid.",
    "SHARE_DIR=/mnt/pwnkit",
    "WORK_DIR=/tmp/pwnkit-run",
    "mkdir -p \"$WORK_DIR\"",
    "compiled=0",
    "executed=0",
    "exit_code=0",
    "timed_out=0",
    "cp \"$SHARE_DIR/repro.c\" \"$WORK_DIR/repro.c\"",
    ...widenLines,
    `if /usr/bin/gcc -B/usr/bin/ -O0 -g -o "$WORK_DIR/repro" "$WORK_DIR/repro.c" -lpthread >"$SHARE_DIR/compile.log" 2>&1; then`,
    "  compiled=1",
    "else",
    "  exit_code=$?",
    "fi",
    "if [ \"$compiled\" = \"1\" ]; then",
    "  dmesg -C 2>/dev/null || true",
    `  if timeout ${shellQuote(String(config.timeoutSec))}s "$WORK_DIR/repro" >"$SHARE_DIR/run.log" 2>&1; then`,
    "    executed=1",
    "    exit_code=0",
    "  else",
    "    exit_code=$?",
    "    if [ \"$exit_code\" = \"124\" ]; then",
    "      timed_out=1",
    "    else",
    "      executed=1",
    "    fi",
    "  fi",
    "else",
    "  : > \"$SHARE_DIR/run.log\"",
    "fi",
    "dmesg 2>/dev/null > \"$SHARE_DIR/dmesg.log\" || true",
    "printf '%s\\n' \"$compiled\" > \"$SHARE_DIR/compiled.ok\"",
    "printf '%s\\n' \"$executed\" > \"$SHARE_DIR/executed.ok\"",
    "printf '%s\\n' \"$exit_code\" > \"$SHARE_DIR/exit_code\"",
    "printf '%s\\n' \"$timed_out\" > \"$SHARE_DIR/timed_out\"",
    "sync",
  ].join("\n");
}

async function waitForVmResult(
  config: KernelVmConfig,
  proc: ReturnType<typeof spawn>,
  hostTmpDir: string,
  bootLogPath: string,
): Promise<void> {
  const totalBudgetSec = config.bootTimeoutSec + config.timeoutSec + 60;
  const deadline = Date.now() + totalBudgetSec * 1000;
  const compiledMarker = join(hostTmpDir, "compiled.ok");

  while (Date.now() < deadline) {
    if (existsSync(compiledMarker)) {
      return;
    }
    if (proc.exitCode !== null) {
      const bootLog = existsSync(bootLogPath) ? readFileSync(bootLogPath, "utf-8").slice(-4000) : "";
      throw new Error(`kernel VM exited before producing results (exit=${proc.exitCode}).\n${bootLog}`);
    }
    await sleep(2_000);
  }

  const bootLog = existsSync(bootLogPath) ? readFileSync(bootLogPath, "utf-8").slice(-4000) : "";
  throw new Error(`timed out waiting for kernel VM results in shared dir ${hostTmpDir} after ${totalBudgetSec}s.\n${bootLog}`);
}

export async function runReproducerInKernelVm(report: CrashReport): Promise<ReproducerResult> {
  if (!report.reproducer) {
    return {
      compiled: false,
      executed: false,
      output: "",
      dmesg: "",
      exitCode: -1,
      timedOut: false,
    };
  }

  const config = loadKernelVmConfigFromEnv();
  const hostTmpDir = config.artifactDir
    ? (() => {
        mkdirSync(config.artifactDir!, { recursive: true });
        return mkdtempSync(join(config.artifactDir!, "pwnkit-kvm-"));
      })()
    : mkdtempSync(join(tmpdir(), "pwnkit-kvm-"));
  const language = report.reproducerLanguage ?? "c";
  const sourcePath = join(hostTmpDir, language === "syz" ? "repro.syz" : "repro.c");
  const runnerScriptPath = join(hostTmpDir, "runner.sh");
  const serialLogPath = join(hostTmpDir, "serial.log");
  writeFileSync(sourcePath, report.reproducer, "utf-8");
  writeFileSync(runnerScriptPath, renderGuestRunnerScript(config, language), "utf-8");

  // Stage the race-widening kprobe module source for the guest to (best-effort)
  // build + insmod. Only written when fully parameterized; the guest fails soft
  // when its kernel build tree is absent.
  if (
    config.widenSymbol !== undefined &&
    config.widenOffset !== undefined &&
    config.widenDelayMs !== undefined
  ) {
    writeFileSync(
      join(hostTmpDir, "pwnkit_widen.c"),
      renderRaceWidenModuleSource(config.widenSymbol, config.widenOffset, config.widenDelayMs),
      "utf-8",
    );
  }

  const { command, args } = buildQemuCommand(config, serialLogPath, hostTmpDir);
  const vmProc = spawn(command, args, {
    stdio: "ignore",
  });

  try {
    await waitForVmResult(config, vmProc, hostTmpDir, serialLogPath);

    const compiled = readFileSync(join(hostTmpDir, "compiled.ok"), "utf-8").trim() === "1";
    const executed = existsSync(join(hostTmpDir, "executed.ok"))
      ? readFileSync(join(hostTmpDir, "executed.ok"), "utf-8").trim() === "1"
      : false;
    const exitCode = existsSync(join(hostTmpDir, "exit_code"))
      ? parseInt(readFileSync(join(hostTmpDir, "exit_code"), "utf-8").trim(), 10)
      : 1;
    const timedOut = existsSync(join(hostTmpDir, "timed_out"))
      ? readFileSync(join(hostTmpDir, "timed_out"), "utf-8").trim() === "1"
      : false;
    const compileLog = existsSync(join(hostTmpDir, "compile.log"))
      ? readFileSync(join(hostTmpDir, "compile.log"), "utf-8").trim()
      : "";
    const runLog = existsSync(join(hostTmpDir, "run.log"))
      ? readFileSync(join(hostTmpDir, "run.log"), "utf-8").trim()
      : "";
    const dmesg = existsSync(join(hostTmpDir, "dmesg.log"))
      ? readFileSync(join(hostTmpDir, "dmesg.log"), "utf-8").trim()
      : "";

    return {
      compiled,
      executed,
      output: compiled ? runLog : compileLog,
      dmesg,
      exitCode: Number.isFinite(exitCode) ? exitCode : 1,
      timedOut,
    };
  } finally {
    await stopVm(vmProc);
    if (!config.artifactDir) {
      rmSync(hostTmpDir, { recursive: true, force: true });
    }
  }
}

// ────────────────────────────────────────────────────────────────────
// Tier-1 verify (issue #271)
// ────────────────────────────────────────────────────────────────────

/**
 * Verdict of a Tier-1 kernel verification run.
 *
 * - `reproduced`     — VM booted, reproducer ran, dmesg matched the expected
 *                       signature (or any recognisable KASAN/UBSAN/oops
 *                       signature when no expectation was supplied).
 * - `no_signal`      — VM booted, reproducer ran, but no crash signature in
 *                       dmesg (the "didn't trigger" case).
 * - `build_failed`   — Kernel build threw before producing artifacts.
 * - `run_failed`     — Reproducer failed to compile/execute, VM crashed, or
 *                       the expected-vs-actual signature compare mismatched.
 */
export type KernelFindingStatus = "reproduced" | "no_signal" | "build_failed" | "run_failed";

export interface KernelFindingVerification {
  status: KernelFindingStatus;
  signature?: string;
  dmesg_path: string;
  build_cache_hit: boolean;
}

export interface VerifyKernelFindingOptions {
  /** Path to a syzkaller `.syz` program. Mutually exclusive with `reproducerPath`. */
  syzProgramPath?: string;
  /** Path to a C reproducer source. Mutually exclusive with `syzProgramPath`. */
  reproducerPath?: string;
  /** Linux source tree the kernel will be built from. */
  kernelTree: string;
  /** Kernel build profile (`kasan`, `defconfig+kasan`, ...). */
  kernelConfig?: KernelConfigProfile;
  /** Override the default cache root (`~/.pwnkit/kernel-cache/`). */
  cacheDir?: string;
  /** Force a fresh build even on cache hit. */
  forceBuild?: boolean;
  /**
   * Expected crash signature substring (case-insensitive). When set, dmesg
   * must contain this string for `status` to be `reproduced`; otherwise the
   * status falls back to `run_failed`.
   *
   * When omitted, any recognised KASAN/UBSAN/oops marker counts.
   */
  expectedSignature?: string;
  /**
   * Where to persist the captured dmesg log. Defaults to
   * `<os.tmpdir()>/pwnkit-verify-<rand>.dmesg`. The file is written even on
   * `build_failed` / `run_failed`, with the available context.
   */
  dmesgOutPath?: string;
  /** Custom logger; defaults to `console.log`. */
  logger?: (line: string) => void;
  /** Injection point for tests / alternate build executors. */
  buildRunner?: KernelBuildOptions["buildRunner"];
  /** Injection point for tests; defaults to the real QEMU runner. */
  vmRunner?: (report: CrashReport) => Promise<ReproducerResult>;
}

const KERNEL_CRASH_SIGNATURES: { pattern: RegExp; signature: string }[] = [
  { pattern: /KASAN:\s+slab-use-after-free|KASAN.*use-after-free/i, signature: "kasan-uaf" },
  { pattern: /KASAN:\s+slab-out-of-bounds|KASAN.*out-of-bounds/i, signature: "kasan-oob" },
  { pattern: /KASAN.*double-free/i, signature: "kasan-double-free" },
  { pattern: /KASAN.*invalid-free/i, signature: "kasan-invalid-free" },
  { pattern: /KASAN.*stack-out-of-bounds/i, signature: "kasan-stack-oob" },
  { pattern: /UBSAN.*shift/i, signature: "ubsan-shift" },
  { pattern: /UBSAN.*overflow/i, signature: "ubsan-overflow" },
  { pattern: /UBSAN.*(out-of-bounds|index)/i, signature: "ubsan-bounds" },
  { pattern: /UBSAN/i, signature: "ubsan" },
  { pattern: /NULL pointer dereference|kernel NULL pointer/i, signature: "null-deref" },
  { pattern: /general protection fault/i, signature: "general-protection" },
];

function detectKernelSignature(dmesg: string): string | undefined {
  for (const { pattern, signature } of KERNEL_CRASH_SIGNATURES) {
    if (pattern.test(dmesg)) return signature;
  }
  return undefined;
}

export function defaultDmesgOutPath(): string {
  // Nanosecond-unique: several proofs written within the same millisecond must
  // not collide on the same filename (the old `Date.now()` ms stamp could).
  const ns = process.hrtime.bigint().toString();
  const random = Math.random().toString(36).slice(2, 10);
  return join(tmpdir(), `pwnkit-verify-${ns}-${random}.dmesg`);
}

/**
 * Write a proof artifact and make it READ-ONLY (mode 0444) so a preserved proof
 * cannot be silently mutated after the fact. Fail-soft on chmod (some
 * filesystems reject it) — the proof is still written.
 */
export function writeProofFileReadOnly(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, "utf-8");
  try {
    chmodSync(path, 0o444);
  } catch {
    // chmod can fail on exotic filesystems; the proof bytes are already on disk.
  }
}

/**
 * Tier-1 verification entry point for `pwnkit ingest --syz / --reproducer`.
 *
 * Builds the requested kernel config (cached), runs the reproducer in QEMU,
 * captures dmesg, and matches it against `expectedSignature` (when set).
 *
 * Returns `{ status, signature?, dmesg_path, build_cache_hit }`. Always
 * writes `dmesg_path` — callers can read it for archival / agent context.
 */
export async function verifyKernelFinding(
  opts: VerifyKernelFindingOptions,
): Promise<KernelFindingVerification> {
  const log = opts.logger ?? ((line: string) => console.log(line));
  const dmesgOutPath = opts.dmesgOutPath ?? defaultDmesgOutPath();

  if (!opts.syzProgramPath && !opts.reproducerPath) {
    throw new Error("verifyKernelFinding requires either syzProgramPath or reproducerPath");
  }
  if (opts.syzProgramPath && opts.reproducerPath) {
    throw new Error("verifyKernelFinding: pass only one of syzProgramPath or reproducerPath");
  }

  const reproPath = (opts.syzProgramPath ?? opts.reproducerPath)!;
  const reproducerLanguage: "syz" | "c" = opts.syzProgramPath ? "syz" : "c";
  if (!existsSync(reproPath)) {
    throw new Error(`reproducer not found: ${reproPath}`);
  }

  // ── Build (or cache-hit) ─────────────────────────────────────
  let artifacts: KernelVmArtifacts;
  try {
    artifacts = prepareKernelVmArtifacts({
      kernelTree: opts.kernelTree,
      configProfile: opts.kernelConfig ?? "kasan",
      cacheDir: opts.cacheDir,
      force: opts.forceBuild,
      logger: log,
      buildRunner: opts.buildRunner,
    });
  } catch (err) {
    writeProofFileReadOnly(
      dmesgOutPath,
      `[build_failed] ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return {
      status: "build_failed",
      dmesg_path: dmesgOutPath,
      build_cache_hit: false,
    };
  }

  const build_cache_hit = artifacts.cacheStatus === "hit" || artifacts.cacheStatus === "env";

  // Make the runner pick up the freshly built artifacts.
  const previousEnv = {
    qemu: process.env.PWNKIT_KERNEL_QEMU,
    kernel: process.env.PWNKIT_KERNEL_QEMU_KERNEL,
    disk: process.env.PWNKIT_KERNEL_QEMU_DISK,
    cfg: process.env.PWNKIT_KERNEL_QEMU_CONFIG,
    cacheKey: process.env.PWNKIT_KERNEL_QEMU_CACHEKEY,
  };
  process.env.PWNKIT_KERNEL_QEMU = "1";
  process.env.PWNKIT_KERNEL_QEMU_KERNEL = artifacts.kernelImage;
  process.env.PWNKIT_KERNEL_QEMU_DISK = artifacts.diskImage;
  if (artifacts.kernelConfig) {
    process.env.PWNKIT_KERNEL_QEMU_CONFIG = artifacts.kernelConfig;
  }
  // Booted-image identity for the weaponization oracle's wrong-kernel binding.
  if (artifacts.cacheKey) {
    process.env.PWNKIT_KERNEL_QEMU_CACHEKEY = artifacts.cacheKey;
  }

  let runResult: ReproducerResult;
  try {
    const report: CrashReport = {
      raw: "",
      crashType: "unknown",
      faultingFunction: "unknown",
      stackFrames: [],
      reproducer: readFileSync(reproPath, "utf-8"),
      reproducerLanguage,
    };
    const runner = opts.vmRunner ?? runReproducerInKernelVm;
    runResult = await runner(report);
  } catch (err) {
    writeProofFileReadOnly(
      dmesgOutPath,
      `[run_failed] ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return {
      status: "run_failed",
      dmesg_path: dmesgOutPath,
      build_cache_hit,
    };
  } finally {
    process.env.PWNKIT_KERNEL_QEMU = previousEnv.qemu;
    process.env.PWNKIT_KERNEL_QEMU_KERNEL = previousEnv.kernel;
    process.env.PWNKIT_KERNEL_QEMU_DISK = previousEnv.disk;
    process.env.PWNKIT_KERNEL_QEMU_CONFIG = previousEnv.cfg;
    process.env.PWNKIT_KERNEL_QEMU_CACHEKEY = previousEnv.cacheKey;
  }

  // ── Persist dmesg + decide verdict ──────────────────────────
  const dmesgContent = runResult.dmesg || runResult.output || "";
  writeProofFileReadOnly(dmesgOutPath, dmesgContent);

  if (!runResult.compiled || !runResult.executed) {
    return {
      status: "run_failed",
      dmesg_path: dmesgOutPath,
      build_cache_hit,
    };
  }

  if (opts.expectedSignature) {
    const haystack = dmesgContent.toLowerCase();
    const needle = opts.expectedSignature.toLowerCase();
    if (haystack.includes(needle)) {
      return {
        status: "reproduced",
        signature: opts.expectedSignature,
        dmesg_path: dmesgOutPath,
        build_cache_hit,
      };
    }
    const detected = detectKernelSignature(dmesgContent);
    if (detected) {
      // Reproducer crashed the kernel but with a different signature.
      return {
        status: "run_failed",
        signature: detected,
        dmesg_path: dmesgOutPath,
        build_cache_hit,
      };
    }
    return {
      status: "no_signal",
      dmesg_path: dmesgOutPath,
      build_cache_hit,
    };
  }

  const detected = detectKernelSignature(dmesgContent);
  if (detected) {
    return {
      status: "reproduced",
      signature: detected,
      dmesg_path: dmesgOutPath,
      build_cache_hit,
    };
  }

  return {
    status: "no_signal",
    dmesg_path: dmesgOutPath,
    build_cache_hit,
  };
}
