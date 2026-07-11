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
  /**
   * Weaponization lane: boot a LIGHTWEIGHT busybox initramfs (`rdinit=/init`,
   * NO heavy 9p root disk) instead of the 9p-shared disk image. Mirrors the
   * proven manual `run_v6.sh` harness — the lightweight environment removes the
   * scheduler/IO noise that wedges the 9p-disk flood thread, so the UAF flood
   * reaches the manual ~225-UAF/boot rate that actually wins the reclaim.
   *
   * The exploit C is compiled STATICALLY on the host (the initramfs has no
   * toolchain) and packed as `/init`'s payload. Gated by
   * `PWNKIT_KERNEL_QEMU_INITRAMFS=1` (set by `USE_KERNEL_WEAPONIZE=1`). When
   * false the historical 9p verify/repro lane is used unchanged.
   */
  weaponizeInitramfs?: boolean;
  /**
   * Host paths to vulnerable-kernel `.ko` modules the initramfs `/init` must
   * `insmod` before running the exploit (e.g. `snd-mtpav.ko`, which provides the
   * `midisynth` rawmidi port the snd-seq-midi UAF subscribes/opens). Packed into
   * the initramfs and insmod'd in order. Only consulted in the initramfs lane.
   */
  initramfsModules?: string[];
  /**
   * Host path to a STATIC busybox binary packed into the initramfs as
   * `/bin/busybox` (the only userspace the `/init` shell needs). Defaults to a
   * `busybox` discovered on PATH; the lane errors clearly if none is static.
   */
  busyboxPath?: string;
}

/**
 * Kernel build config profile name.
 *
 * Tier-1 verify (issue #271) lets callers pass arbitrary profile names that
 * the build script understands — e.g. `kasan`, `defconfig+kasan`. The
 * built-in build runner recognises `kasan` (KASAN/UBSAN) and `kcsan`
 * (Kernel Concurrency Sanitizer + full preemption — the race-detection lane
 * KASAN is blind to). Custom names require a custom `buildRunner` or an
 * out-of-band script that maps the name to a kernel `.config`.
 */
export type KernelConfigProfile = string;

/** Config profiles the built-in `build-from-tree.sh` runner understands. */
export const RECOGNIZED_CONFIG_PROFILES = ["kasan", "kcsan"] as const;

/**
 * `scripts/config` toggles for a build profile. This is the ENGINE source of
 * truth for what each profile enables; `build-from-tree.sh` mirrors these two
 * sets (kept in sync — see the cross-reference comment there). Exposed so a
 * unit test can assert the KCSAN profile enables `CONFIG_KCSAN` + `CONFIG_PREEMPT`
 * and does NOT carry the KASAN inline set (the two heavyweight sanitizers are
 * not co-built — KCSAN is the point of this profile).
 *
 * Throws for an unrecognized profile so a typo fails loudly rather than
 * silently building a bare defconfig.
 */
export function buildFlagsForProfile(profile: KernelConfigProfile): string[] {
  if (profile === "kasan") {
    return [
      "--enable CONFIG_KASAN",
      "--set-str CONFIG_KASAN_MODE generic",
      "--enable CONFIG_KASAN_GENERIC",
      "--enable CONFIG_KASAN_INLINE",
      "--enable CONFIG_KASAN_STACK",
      "--enable CONFIG_KASAN_VMALLOC",
      "--enable CONFIG_UBSAN",
      "--enable CONFIG_UBSAN_BOUNDS",
      "--enable CONFIG_UBSAN_SHIFT",
    ];
  }
  if (profile === "kcsan") {
    // KCSAN=y + full preemption (PREEMPT=y) so the ExpRace reschedule-IPI
    // widener can actually preempt the racing worker mid-window. KASAN is left
    // OFF: co-instrumenting both sanitizers is not supported/sane, and races
    // are what this lane is for. `KCSAN_REPORT_ONCE_IN_MS=0` + interrupt-watch
    // so a widened race reports every time, not just the first.
    return [
      "--enable CONFIG_KCSAN",
      "--enable CONFIG_KCSAN_EARLY_ENABLE",
      "--set-val CONFIG_KCSAN_REPORT_ONCE_IN_MS 0",
      "--enable CONFIG_KCSAN_INTERRUPT_WATCHER",
      "--enable CONFIG_PREEMPT",
      "--disable CONFIG_KASAN",
      "--enable CONFIG_DEBUG_INFO",
      "--enable CONFIG_DEBUG_KERNEL",
    ];
  }
  throw new Error(
    `unrecognized kernel config profile: ${profile} (known: ${RECOGNIZED_CONFIG_PROFILES.join(", ")})`,
  );
}

/**
 * Config-gate for the KCSAN profile: is `CONFIG_KCSAN` actually enabled in the
 * (built or target) `.config`? Fail-soft callers use this to detect a kernel
 * that cannot support KCSAN (e.g. an arch/toolchain without the sanitizer) and
 * skip the race lane rather than silently "verifying" on a race-blind kernel.
 */
export function kcsanConfigSupported(kernelConfigText: string): boolean {
  return /^CONFIG_KCSAN=y\s*$/m.test(kernelConfigText);
}

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
    warnIfKcsanUnsupported(configProfile, join(outDir, "kernel.config"), log);
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
  warnIfKcsanUnsupported(configProfile, join(outDir, "kernel.config"), log);

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

/**
 * FAIL-SOFT KCSAN config-gate. When the `kcsan` profile was requested but the
 * produced `.config` does not actually carry `CONFIG_KCSAN=y` (arch/toolchain
 * can't support it), log a loud warning rather than throwing — the caller still
 * gets bootable artifacts, it just won't observe data races on this kernel. A
 * no-op for every other profile.
 */
function warnIfKcsanUnsupported(
  configProfile: KernelConfigProfile,
  kernelConfigPath: string,
  log: (line: string) => void,
): void {
  if (configProfile !== "kcsan") return;
  let text = "";
  try {
    text = readFileSync(kernelConfigPath, "utf-8");
  } catch {
    log(`[kcsan-gate] WARN: could not read ${kernelConfigPath} to verify CONFIG_KCSAN — race lane may be blind`);
    return;
  }
  if (!kcsanConfigSupported(text)) {
    log(`[kcsan-gate] WARN: CONFIG_KCSAN not enabled in ${kernelConfigPath} — data races will NOT be observed (fail-soft)`);
  }
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

  // Weaponization lane (lightweight busybox initramfs). `USE_KERNEL_WEAPONIZE=1`
  // is the operator-facing alias; `PWNKIT_KERNEL_QEMU_INITRAMFS=1` is the
  // explicit knob. Either enables it.
  const weaponizeInitramfs =
    /^(1|true|on|yes)$/i.test(process.env.PWNKIT_KERNEL_QEMU_INITRAMFS?.trim() ?? "") ||
    /^(1|true|on|yes)$/i.test(process.env.USE_KERNEL_WEAPONIZE?.trim() ?? "");
  const initramfsModules = (process.env.PWNKIT_KERNEL_QEMU_INITRAMFS_MODULES?.trim() || "")
    .split(/[:,\s]+/)
    .map((m) => m.trim())
    .filter(Boolean);
  const busyboxPath = process.env.PWNKIT_KERNEL_QEMU_BUSYBOX?.trim() || undefined;

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
    weaponizeInitramfs,
    ...(initramfsModules.length > 0 ? { initramfsModules } : {}),
    ...(busyboxPath ? { busyboxPath } : {}),
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

/**
 * Spec for {@link renderRealIpiRaceHarness} — the ExpRace-style userspace race
 * driver. The two racing sides are supplied by the caller as C statement bodies
 * (e.g. `close(fd);` on the free side, `ioctl(fd, ...);` on the use side); the
 * widening TACTICS come pre-composed as `setupC` (from `race-gadgets.ts`), and
 * the harness wraps everything in Bad Epoll's non-crashing retry loop.
 */
export interface RealIpiRaceHarnessSpec {
  /** C body of racer thread A (typically the free/reuse side). */
  raceOpA: string;
  /** C body of racer thread B (typically the use side). */
  raceOpB: string;
  /** Composed gadget/tactic setup C, armed once before the race. */
  setupC?: string;
  /** Extra headers the tactics need (deduped; `_GNU_SOURCE` is forced first). */
  headers?: readonly string[];
  /** Non-crashing retry-loop cap (iterations). Also read from env at runtime. */
  maxIters?: number;
  /** Wall-clock budget in seconds. Also read from env at runtime. */
  seconds?: number;
  /** Pin both racers to the same CPU (default false → CPUs 0 and 1). */
  sameCpu?: boolean;
}

const RACE_HARNESS_BASE_HEADERS: readonly string[] = [
  "#include <stdio.h>",
  "#include <stdlib.h>",
  "#include <string.h>",
  "#include <unistd.h>",
  "#include <pthread.h>",
  "#include <sched.h>",
  "#include <time.h>",
  "#include <fcntl.h>",
  "#include <sys/types.h>",
];

/**
 * Render the ExpRace-style userspace race harness as a full, compilable C
 * program (contrast `renderRaceWidenModuleSource`, which builds an in-guest
 * *kprobe* — this is pure userspace, no debug gate). It:
 *
 *  - merges the widening tactics' headers (`_GNU_SOURCE` forced to line 1),
 *  - arms the composed gadget `setupC` ONCE (waitqueue freeze / membarrier
 *    register + the IPI bursts),
 *  - spins two CPU-pinned racer threads looping their `raceOp{A,B}` bodies,
 *  - wraps them in **Bad Epoll's non-crashing retry loop**: it re-races up to
 *    `maxIters` / `seconds` (both overridable via `PWNKIT_RACE_RETRIES` /
 *    `PWNKIT_RACE_SECONDS`) and NEVER dereferences freed memory or aborts —
 *    only the in-kernel KASAN/KCSAN splat (on the serial console) terminates
 *    the run. Prints a `PWNKIT-RACE` progress marker so the oracle sees liveness.
 *
 * Pure string builder — no I/O — so it unit-tests offline.
 */
export function renderRealIpiRaceHarness(spec: RealIpiRaceHarnessSpec): string {
  const maxIters = Number.isFinite(spec.maxIters) ? Math.max(1, Math.trunc(spec.maxIters!)) : 200_000;
  const seconds = Number.isFinite(spec.seconds) ? Math.max(1, Math.trunc(spec.seconds!)) : 40;
  const cpuA = 0;
  const cpuB = spec.sameCpu ? 0 : 1;

  // Merge headers: `_GNU_SOURCE` must precede every include (sched affinity
  // macros, MAP_SHARED, etc.); then base headers; then tactic headers; deduped
  // in first-seen order. A tactic may itself carry a `#define _GNU_SOURCE`.
  const seen = new Set<string>();
  const headerLines: string[] = [];
  const push = (h: string) => {
    const t = h.trim();
    if (!t || seen.has(t)) return;
    seen.add(t);
    headerLines.push(t);
  };
  push("#define _GNU_SOURCE");
  for (const h of RACE_HARNESS_BASE_HEADERS) push(h);
  for (const h of spec.headers ?? []) {
    // A tactic's `#define _GNU_SOURCE` is already emitted first; skip dupes.
    push(h);
  }

  const setupC = spec.setupC?.trim()
    ? spec.setupC
    : "/* no widening tactics composed */";

  return [
    ...headerLines,
    "",
    "static volatile int g_stop = 0;",
    "",
    "static void pwnkit_pin_cpu(int cpu) {",
    "  cpu_set_t set;",
    "  CPU_ZERO(&set);",
    "  CPU_SET(cpu, &set);",
    "  sched_setaffinity(0, sizeof(set), &set);",
    "}",
    "",
    "static long pwnkit_env_long(const char *name, long dflt) {",
    "  const char *v = getenv(name);",
    "  if (!v || !*v) return dflt;",
    "  char *end = NULL;",
    "  long n = strtol(v, &end, 10);",
    "  return (end && *end == '\\0' && n > 0) ? n : dflt;",
    "}",
    "",
    `static void *pwnkit_racer_a(void *arg) {`,
    "  (void)arg;",
    `  pwnkit_pin_cpu(${cpuA});`,
    "  while (!g_stop) {",
    `    ${spec.raceOpA}`,
    "  }",
    "  return NULL;",
    "}",
    "",
    `static void *pwnkit_racer_b(void *arg) {`,
    "  (void)arg;",
    `  pwnkit_pin_cpu(${cpuB});`,
    "  while (!g_stop) {",
    `    ${spec.raceOpB}`,
    "  }",
    "  return NULL;",
    "}",
    "",
    "int main(void) {",
    `  long retries = pwnkit_env_long("PWNKIT_RACE_RETRIES", ${maxIters});`,
    `  long seconds = pwnkit_env_long("PWNKIT_RACE_SECONDS", ${seconds});`,
    "  time_t deadline = time(NULL) + seconds;",
    "",
    "  /* Arm the widening tactics ONCE (freeze/register + IPI bursts). */",
    setupC,
    "",
    "  /* Bad Epoll non-crashing retry loop: re-race until the sanitizer fires.",
    "     The harness itself never touches freed memory — the kernel splat on the",
    "     serial console is the only terminator; here we just exhaust the budget. */",
    "  for (long iter = 0; iter < retries && time(NULL) < deadline; iter++) {",
    "    g_stop = 0;",
    "    pthread_t ta, tb;",
    "    if (pthread_create(&ta, NULL, pwnkit_racer_a, NULL) != 0) break;",
    "    if (pthread_create(&tb, NULL, pwnkit_racer_b, NULL) != 0) { g_stop = 1; pthread_join(ta, NULL); break; }",
    "    usleep(200);",
    "    g_stop = 1;",
    "    pthread_join(ta, NULL);",
    "    pthread_join(tb, NULL);",
    "    if ((iter & 0x3ff) == 0) { printf(\"PWNKIT-RACE iter=%ld\\n\", iter); fflush(stdout); }",
    "  }",
    "  printf(\"PWNKIT-RACE done (budget exhausted, no splat)\\n\");",
    "  fflush(stdout);",
    "  return 0;",
    "}",
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

// ────────────────────────────────────────────────────────────────────
// Weaponization lane: lightweight busybox-initramfs boot (issue: snd-midi
// initramfs weaponization lane). Mirrors the proven manual `run_v6.sh` harness.
// ────────────────────────────────────────────────────────────────────

/**
 * Build the kernel cmdline for the initramfs weaponization lane. Mirrors the
 * proven manual `run_v6.sh` append: `rdinit=/init` + `kasan_multi_shot=1`
 * (every UAF write splats, not just the first — so we can COUNT UAF events/boot)
 * + the KASLR knob + `panic=-1` (a splat-stall must not wedge the whole boot).
 * NO `root=/dev/vda` — there is no disk; the rootfs IS the initramfs.
 */
export function buildInitramfsKernelAppend(kaslr: boolean): string {
  return [
    "console=ttyS0",
    "earlyprintk=serial",
    "rdinit=/init",
    "kasan_multi_shot=1",
    kaslr ? "kaslr" : "nokaslr",
    "panic=-1",
  ].join(" ");
}

/**
 * Render the initramfs `/init` (busybox sh). Mounts proc/sys/dev, insmods the
 * staged `.ko` modules (e.g. `snd-mtpav.ko` — the midisynth port the snd-seq UAF
 * needs), runs the host-compiled exploit, then harvests the SAME oracle markers
 * the 9p lane harvests (the exploit prints DROP/ROOT/RECLAIM/MODPROBE_HELPER_RAN
 * to stdout; KASAN splats land on the serial console). `run.log` is echoed back
 * to the serial console (the only channel out of an initramfs with no share) so
 * the host can scrape one stream for both the run output and the dmesg splats.
 *
 * `raceEnv` is the `PWNKIT_RACE_*` knob set the emitted exploit reads via
 * getenv at runtime — exported into the exploit's environment here so the lane
 * can drive RACE_SECONDS/FLOOD_THREADS/etc. without recompiling.
 */
export function renderInitramfsInitScript(
  moduleNames: string[],
  raceEnv: Record<string, string>,
  timeoutSec: number,
): string {
  const envExports = Object.entries(raceEnv)
    .map(([k, v]) => `export ${k}=${shellQuote(v)}`)
    .join("\n");
  const insmods = moduleNames
    .map((m) => `insmod /lib/modules/${m} 2>&1 && echo "insmod ${m} ok" || echo "insmod ${m} rc=$?"`)
    .join("\n");
  return [
    "#!/bin/busybox sh",
    "/bin/busybox mkdir -p /proc /sys /dev /tmp /lib/modules",
    "/bin/busybox mount -t proc none /proc",
    "/bin/busybox mount -t sysfs none /sys",
    "/bin/busybox mount -t devtmpfs none /dev 2>/dev/null",
    "/bin/busybox --install -s /bin 2>/dev/null",
    'echo "=== PWNKIT-INITRAMFS weaponize lane up ==="',
    "cat /proc/version",
    insmods,
    envExports,
    'echo "=== PWNKIT-INITRAMFS run (env: ' +
      Object.keys(raceEnv).join(",") +
      ') ==="',
    // CRITICAL: the engine's emitted exploit prints a RECLAIM marker on EVERY
    // spray-loop iteration (thousands/sec). Streaming that to the slow 8250 UART
    // wedges the CPU in io_serial_in and STARVES the race (NMI watchdog fires,
    // KASAN never gets a window). So redirect the exploit's stdout/stderr to a
    // tmpfs file (fast, no UART blocking) during the race, then `cat` it to the
    // serial console AFTER the race completes — the oracle reads the full serial
    // stream either way, and the KASAN splats (kernel printk, a separate path)
    // still interleave live. `timeout` caps a hung flood; busybox `timeout` takes
    // the seconds as a POSITIONAL arg (`timeout SECS PROG`), NOT GNU `-t SECS`.
    `/bin/busybox timeout ${timeoutSec} /exploit > /tmp/run.log 2>&1 || echo "PWNKIT-INITRAMFS exploit exit=$?" >> /tmp/run.log`,
    'echo "=== PWNKIT-INITRAMFS exploit output (batched off the UART hot path) ==="',
    "cat /tmp/run.log",
    'echo "=== PWNKIT-INITRAMFS post-run ==="',
    "sync",
    "cat /tmp/pwned 2>/dev/null && echo PWNKIT-INITRAMFS-PWNED-FILE-PRESENT",
    'echo "=== PWNKIT-INITRAMFS done; powering off ==="',
    "/bin/busybox poweroff -f",
  ].join("\n");
}

/**
 * Compile the exploit C STATICALLY on the host and pack a minimal busybox
 * initramfs (`/init`, `/bin/busybox`, `/exploit`, staged `.ko` modules) into a
 * `initramfs.cpio.gz`. Returns its path. Throws with a clear message when the
 * toolchain / busybox prerequisites are missing — the lane is opt-in, so a
 * misconfigured box must fail loudly, not silently fall back to 9p.
 *
 * Static linking is mandatory: the initramfs ships no shared libs or dynamic
 * loader, so the exploit (pthread) must be a self-contained static binary.
 */
export function buildWeaponizeInitramfs(
  config: KernelVmConfig,
  exploitC: string,
  workDir: string,
  raceEnv: Record<string, string>,
): string {
  const rootDir = join(workDir, "initramfs-root");
  mkdirSync(join(rootDir, "bin"), { recursive: true });
  mkdirSync(join(rootDir, "lib", "modules"), { recursive: true });
  for (const sub of ["proc", "sys", "dev", "tmp"]) {
    mkdirSync(join(rootDir, sub), { recursive: true });
  }

  // 1. Static busybox — the only userspace the /init shell needs.
  const busybox =
    config.busyboxPath ||
    (() => {
      try {
        return execFileSync("sh", ["-c", "command -v busybox"], { encoding: "utf8" }).trim();
      } catch {
        return "";
      }
    })();
  if (!busybox || !existsSync(busybox)) {
    throw new Error(
      "weaponize-initramfs lane: no busybox found (set PWNKIT_KERNEL_QEMU_BUSYBOX to a STATIC busybox)",
    );
  }
  execFileSync("cp", [busybox, join(rootDir, "bin", "busybox")]);
  chmodSync(join(rootDir, "bin", "busybox"), 0o755);

  // 2. Compile the exploit STATICALLY on the host.
  const srcPath = join(workDir, "exploit.c");
  writeFileSync(srcPath, exploitC, "utf-8");
  const binPath = join(rootDir, "exploit");
  const compileLog = join(workDir, "compile.log");
  try {
    execFileSync(
      "gcc",
      ["-O0", "-g", "-static", "-o", binPath, srcPath, "-lpthread"],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (err) {
    const msg = err instanceof Error && "stderr" in err ? String((err as { stderr: unknown }).stderr) : String(err);
    writeFileSync(compileLog, msg, "utf-8");
    throw new Error(`weaponize-initramfs lane: static exploit compile failed:\n${msg.slice(0, 1500)}`);
  }
  chmodSync(binPath, 0o755);

  // 3. Stage the .ko modules (basename → /lib/modules/<name>).
  const moduleNames: string[] = [];
  for (const koPath of config.initramfsModules ?? []) {
    if (!existsSync(koPath)) {
      throw new Error(`weaponize-initramfs lane: module not found: ${koPath}`);
    }
    const name = koPath.split("/").pop()!;
    execFileSync("cp", [koPath, join(rootDir, "lib", "modules", name)]);
    moduleNames.push(name);
  }

  // 4. /init.
  const initPath = join(rootDir, "init");
  writeFileSync(initPath, renderInitramfsInitScript(moduleNames, raceEnv, config.timeoutSec), "utf-8");
  chmodSync(initPath, 0o755);

  // 5. Pack the cpio.gz (find | cpio newc | gzip), run from inside rootDir so
  // paths are relative (`./init`, not `/abs/.../init`).
  const cpioPath = join(workDir, "initramfs.cpio.gz");
  execFileSync(
    "sh",
    ["-c", `cd ${shellQuote(rootDir)} && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -9 > ${shellQuote(cpioPath)}`],
  );
  if (!existsSync(cpioPath) || statSync(cpioPath).size === 0) {
    throw new Error("weaponize-initramfs lane: cpio packing produced an empty initramfs");
  }
  return cpioPath;
}

/**
 * QEMU command for the initramfs weaponization lane: `-initrd <cpio>` +
 * `rdinit=/init`, NO `-drive` and NO 9p `-virtfs` (the rootfs IS the
 * initramfs). Otherwise mirrors `buildQemuCommand` (serial→file, no-reboot,
 * optional accel). The cmdline comes from `buildInitramfsKernelAppend`.
 */
export function buildInitramfsQemuCommand(
  config: KernelVmConfig,
  serialLogPath: string,
  initramfsPath: string,
  kernelAppend: string,
): { command: string; args: string[] } {
  const args = [
    "-m", String(config.memoryMb),
    "-smp", String(config.smp),
    "-kernel", config.kernelImage,
    "-initrd", initramfsPath,
    "-append", kernelAppend,
    "-nographic",
    "-monitor", "none",
    "-serial", `file:${serialLogPath}`,
    "-no-reboot",
  ];
  if (config.qemuAccel) {
    args.push("-accel", config.qemuAccel);
  }
  return { command: config.qemuBinary, args };
}

/**
 * The `PWNKIT_RACE_*` knob set the emitted exploit reads at runtime, sourced
 * from the process env so the lane can be tuned without a rebuild. Only keys
 * that are actually set are forwarded (the exploit applies its own defaults).
 */
export function collectRaceEnv(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const key of [
    "PWNKIT_RACE_FLOOD_THREADS",
    "PWNKIT_RACE_SPRAY_THREADS",
    "PWNKIT_RACE_PARK_US",
    "PWNKIT_RACE_SECONDS",
    "PWNKIT_RACE_SAME_CPU",
  ]) {
    const v = process.env[key]?.trim();
    if (v) out[key] = v;
  }
  return out;
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
      // KCOV coverage collection (AIxCC T1): ask syz-execprog to collect coverage
      // and dump the per-call PC set to coverage_prog* shards on the share.
      // `-cover=1` enables KCOV; `-coverfile` is the shard prefix. Both flags are no-ops
      // (or rejected) on a non-KCOV kernel / older syz-execprog — fail-soft so a
      // run without coverage still records its crash result.
      `  if timeout ${shellQuote(String(config.timeoutSec))}s syz-execprog -cover=1 -coverfile="$SHARE_DIR/coverage" "$WORK_DIR/repro.syz" >"$SHARE_DIR/run.log" 2>&1; then`,
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
      "  # Consolidate coverage: syz-execprog -coverfile writes the PC set to",
      "  # per-program/per-call shards named `coverage_prog<N>.<call>` (e.g.",
      "  # `coverage_prog0.0`), and may also leave a bare `coverage` / `coverage.N`.",
      "  # Concatenate every shard into coverage.log for the host to parse; PCs are",
      "  # deduped downstream by parseCoveragePcs (fail-soft if none landed).",
      "  cat \"$SHARE_DIR/coverage\" \"$SHARE_DIR/coverage.\"* \"$SHARE_DIR/coverage_prog\"* > \"$SHARE_DIR/coverage.log\" 2>/dev/null || true",
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

/**
 * Parse a syz-execprog / KCOV coverage dump into a deduped, sorted PC set
 * (AIxCC T1). The dump is one program counter per line — hex (`0xffffffff…`)
 * or decimal — possibly with surrounding whitespace or trailing comments.
 *
 * PCs are returned as NORMALIZED HEX STRINGS (`0x…`), not numbers: kernel PCs
 * are full 64-bit values (`0xffffffff8…`) that exceed `Number.MAX_SAFE_INTEGER`,
 * so a number representation silently collapses distinct edges. Strings keep the
 * edge set exact. Lines that don't parse are skipped (fail-soft). Exported for
 * unit testing the parser without booting a VM.
 */
export function parseCoveragePcs(raw: string): string[] {
  const pcs = new Set<string>();
  for (const line of raw.split(/\r?\n/)) {
    const token = line.trim().split(/\s+/)[0];
    if (!token) continue;
    let value: bigint;
    try {
      value =
        token.startsWith("0x") || token.startsWith("0X")
          ? BigInt(token)
          : /^[0-9]+$/.test(token)
            ? BigInt(token)
            : -1n;
    } catch {
      continue;
    }
    if (value > 0n) pcs.add(`0x${value.toString(16)}`);
  }
  return [...pcs].sort((a, b) => {
    const av = BigInt(a);
    const bv = BigInt(b);
    return av < bv ? -1 : av > bv ? 1 : 0;
  });
}

/**
 * Wait for the initramfs VM to finish: it has no 9p share to drop a marker on,
 * so we wait for QEMU to exit (the `/init` poweroffs after the run) or a
 * deadline, whichever comes first. The single serial log carries everything.
 */
async function waitForInitramfsVm(
  config: KernelVmConfig,
  proc: ReturnType<typeof spawn>,
  serialLogPath: string,
): Promise<{ poweredOff: boolean }> {
  const totalBudgetSec = config.bootTimeoutSec + config.timeoutSec + 60;
  const deadline = Date.now() + totalBudgetSec * 1000;
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) return { poweredOff: true };
    // Fast-path: the /init's terminal banner is on serial — exit as soon as the
    // run is provably done, without waiting on QEMU's own teardown.
    if (existsSync(serialLogPath)) {
      const tail = readFileSync(serialLogPath, "utf-8").slice(-2000);
      if (tail.includes("PWNKIT-INITRAMFS done")) return { poweredOff: true };
    }
    await sleep(1_000);
  }
  return { poweredOff: false };
}

/**
 * Run the engine-emitted exploit in the lightweight busybox initramfs lane.
 *
 * Builds a minimal initramfs (static busybox + host-compiled static exploit +
 * staged `.ko` modules + `/init`), boots `rdinit=/init` with NO heavy 9p root
 * disk, and harvests the SAME markers the 9p lane produces from the single
 * serial stream (the exploit's stdout markers AND the KASAN splats both land
 * there). The returned `ReproducerResult` is shape-identical to the 9p lane's,
 * so the oracle/adjudicator sees no difference — only a far healthier flood.
 */
async function runWeaponizeInitramfs(
  config: KernelVmConfig,
  exploitC: string,
): Promise<ReproducerResult> {
  const hostTmpDir = config.artifactDir
    ? (() => {
        mkdirSync(config.artifactDir!, { recursive: true });
        return mkdtempSync(join(config.artifactDir!, "pwnkit-initramfs-"));
      })()
    : mkdtempSync(join(tmpdir(), "pwnkit-initramfs-"));
  const serialLogPath = join(hostTmpDir, "serial.log");
  const raceEnv = collectRaceEnv();

  let initramfsPath: string;
  try {
    initramfsPath = buildWeaponizeInitramfs(config, exploitC, hostTmpDir, raceEnv);
  } catch (err) {
    // A build/compile failure is reported like a 9p compile failure: not
    // compiled, no execution. The message carries the gcc/cpio error.
    if (!config.artifactDir) rmSync(hostTmpDir, { recursive: true, force: true });
    return {
      compiled: false,
      executed: false,
      output: err instanceof Error ? err.message : String(err),
      dmesg: "",
      exitCode: -1,
      timedOut: false,
    };
  }

  const kernelAppend = buildInitramfsKernelAppend(config.kaslr ?? false);
  const { command, args } = buildInitramfsQemuCommand(config, serialLogPath, initramfsPath, kernelAppend);
  const vmProc = spawn(command, args, { stdio: "ignore" });

  try {
    const { poweredOff } = await waitForInitramfsVm(config, vmProc, serialLogPath);
    const serial = existsSync(serialLogPath) ? readFileSync(serialLogPath, "utf-8") : "";
    // Execution is proven by the run banner; the exploit always reaches at least
    // its first print once /init runs it.
    const executed = serial.includes("PWNKIT-INITRAMFS run");
    const timedOut = !poweredOff;
    // Both channels live in `serial`. Hand the WHOLE serial stream as both the
    // run output (markers) and the dmesg (KASAN splats) — the adjudicator
    // substring-matches each independently, so duplicating is harmless and the
    // single stream guarantees the DROP/ROOT witness and its KASAN splat are
    // adjudicated from the SAME boot.
    return {
      compiled: true,
      executed,
      output: serial,
      dmesg: serial,
      exitCode: executed ? 0 : 1,
      timedOut,
    };
  } finally {
    await stopVm(vmProc);
    if (!config.artifactDir) {
      rmSync(hostTmpDir, { recursive: true, force: true });
    }
  }
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

  // Weaponization lane: boot the lightweight busybox initramfs instead of the
  // 9p disk. Only for C reproducers (the syz path is verify-only). The 9p verify
  // /repro behaviour below is unchanged when the lane is off.
  if (config.weaponizeInitramfs && (report.reproducerLanguage ?? "c") === "c") {
    return runWeaponizeInitramfs(config, report.reproducer);
  }

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
    const coveragePcs = existsSync(join(hostTmpDir, "coverage.log"))
      ? parseCoveragePcs(readFileSync(join(hostTmpDir, "coverage.log"), "utf-8"))
      : undefined;

    return {
      compiled,
      executed,
      output: compiled ? runLog : compileLog,
      dmesg,
      exitCode: Number.isFinite(exitCode) ? exitCode : 1,
      timedOut,
      ...(coveragePcs && coveragePcs.length > 0 ? { coveragePcs } : {}),
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
  /**
   * KCOV / syz-execprog coverage PCs collected during the run (AIxCC T1 — LLM
   * PoV-gen with real coverage feedback). Deduped, sorted program counters the
   * reproducer exercised. Undefined when no coverage was collected (C path, no
   * KCOV kernel, build/run failure). Threaded up to the verify loop so it can
   * diff against previously-seen edges and feed coverage back to the LLM.
   */
  coveragePcs?: string[];
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
  // KCSAN data-race — the race class KASAN is structurally blind to. Matched
  // first so a widened data-race under the `kcsan` build profile is recognized
  // (closes the loop with kcsan-race.ts's parser + patch-to-poc.ts's
  // "KCSAN: data-race" expected signature).
  { pattern: /BUG:\s*KCSAN:\s*data-race|KCSAN:\s*data-race/i, signature: "kcsan-data-race" },
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

  // KCOV coverage threaded through to every post-run verdict (AIxCC T1) so the
  // verify loop can compute new edges and feed them back to the LLM. Spread
  // additively — undefined when no coverage was collected.
  const cov: Pick<KernelFindingVerification, "coveragePcs"> =
    runResult.coveragePcs && runResult.coveragePcs.length > 0
      ? { coveragePcs: runResult.coveragePcs }
      : {};

  if (!runResult.compiled || !runResult.executed) {
    return {
      status: "run_failed",
      dmesg_path: dmesgOutPath,
      build_cache_hit,
      ...cov,
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
        ...cov,
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
        ...cov,
      };
    }
    return {
      status: "no_signal",
      dmesg_path: dmesgOutPath,
      build_cache_hit,
      ...cov,
    };
  }

  const detected = detectKernelSignature(dmesgContent);
  if (detected) {
    return {
      status: "reproduced",
      signature: detected,
      dmesg_path: dmesgOutPath,
      build_cache_hit,
      ...cov,
    };
  }

  return {
    status: "no_signal",
    dmesg_path: dmesgOutPath,
    build_cache_hit,
    ...cov,
  };
}

// ────────────────────────────────────────────────────────────────────
// N-boot reproducibility gate (AIxCC T2: PoV-mandatory + reproducibility)
// ────────────────────────────────────────────────────────────────────

/**
 * Per-boot verification across K fresh boots (AIxCC / Shellphish T2).
 *
 * A single KASAN hit can be a one-off (boot-order luck, an ambient sanitizer
 * splat, a flaky race). The AIxCC PoV-mandatory rule treats a finding as
 * *reproducible* only when the SAME crash signature fires in at least `M` of
 * `K` independent boots. Because the kernel-VM runs with `snapshot=on`, every
 * boot gets a fresh ephemeral rootfs overlay — so each `verifyKernelFinding`
 * call is a genuinely independent trial, not a re-read of one dirty disk.
 *
 * This wraps {@link verifyKernelFinding}: it runs it `K` times and counts how
 * many boots came back `reproduced`. The aggregate verdict is `reproduced` ONLY
 * when `bootHits >= M`; otherwise the worst observed per-boot status is surfaced
 * (so a build failure or a run failure is not silently downgraded to
 * `no_signal`). The `nbootStable` flag records whether the threshold was met,
 * for the disclosure gate.
 */
export interface VerifyAcrossBootsOptions extends VerifyKernelFindingOptions {
  /** Total number of fresh boots to attempt. Default 3. */
  boots?: number;
  /** Minimum boots that must reproduce the signature. Default 2. */
  minHits?: number;
}

export interface KernelFindingNbootVerification extends KernelFindingVerification {
  /** How many of the `bootTotal` boots reproduced the signature. */
  bootHits: number;
  /** Total boots attempted. */
  bootTotal: number;
  /**
   * True when `bootHits >= minHits` — the finding cleared the N-boot
   * reproducibility threshold and is stable enough to disclose (AIxCC T2).
   */
  nbootStable: boolean;
  /** Per-boot statuses, in boot order, for the audit trail. */
  bootStatuses: KernelFindingStatus[];
  /** Full per-boot records, including the independently captured dmesg path. */
  bootResults: KernelFindingVerification[];
}

/**
 * Run {@link verifyKernelFinding} across `K` fresh boots and require the crash
 * signature in at least `M` of them before declaring `reproduced` (AIxCC T2).
 *
 * Each boot gets its own `dmesgOutPath` (the caller's `dmesgOutPath`, when set,
 * is used for the winning/first boot only) so a per-boot proof is preserved. The
 * winning boot's `signature` / `dmesg_path` are surfaced on the aggregate.
 */
export async function verifyAcrossBoots(
  opts: VerifyAcrossBootsOptions,
): Promise<KernelFindingNbootVerification> {
  const log = opts.logger ?? ((line: string) => console.log(line));
  const bootTotal = Math.max(1, opts.boots ?? 3);
  const minHits = Math.max(1, Math.min(opts.minHits ?? 2, bootTotal));

  const { boots: _boots, minHits: _minHits, dmesgOutPath, ...baseOpts } = opts;

  const bootStatuses: KernelFindingStatus[] = [];
  const bootResults: KernelFindingVerification[] = [];
  let bootHits = 0;
  let firstReproduced: KernelFindingVerification | undefined;
  let lastResult: KernelFindingVerification | undefined;

  for (let i = 0; i < bootTotal; i++) {
    // Each boot writes its own proof; reuse the caller's path only for boot 0 so
    // a single-shot caller still gets the file it asked for.
    const perBootDmesg = i === 0 ? dmesgOutPath : undefined;
    const result = await verifyKernelFinding({
      ...baseOpts,
      ...(perBootDmesg ? { dmesgOutPath: perBootDmesg } : {}),
    });
    lastResult = result;
    bootResults.push(result);
    bootStatuses.push(result.status);
    if (result.status === "reproduced") {
      bootHits++;
      if (!firstReproduced) firstReproduced = result;
    }
    log(
      `[nboot] boot ${i + 1}/${bootTotal}: ${result.status}` +
        ` (hits=${bootHits}/${minHits} required)`,
    );
    // Early-exit once the threshold is mathematically unreachable — no point
    // booting the remaining VMs if even all-pass can't reach `minHits`.
    if (bootHits + (bootTotal - i - 1) < minHits && bootHits < minHits) {
      log(`[nboot] threshold ${minHits} unreachable — stopping early`);
      break;
    }
  }

  const nbootStable = bootHits >= minHits;
  const winning = firstReproduced ?? lastResult!;

  // When the threshold isn't met, surface the most informative per-boot status
  // (a build/run failure outranks a no_signal) so the caller sees WHY it failed.
  const aggregateStatus: KernelFindingStatus = nbootStable
    ? "reproduced"
    : pickWorstStatus(bootStatuses);

  return {
    status: aggregateStatus,
    ...(winning.signature ? { signature: winning.signature } : {}),
    dmesg_path: winning.dmesg_path,
    build_cache_hit: winning.build_cache_hit,
    bootHits,
    bootTotal,
    nbootStable,
    bootStatuses,
    bootResults,
  };
}

/** Status precedence (worst first) for a non-stable aggregate verdict. */
const STATUS_PRECEDENCE: KernelFindingStatus[] = [
  "build_failed",
  "run_failed",
  "no_signal",
  "reproduced",
];

function pickWorstStatus(statuses: KernelFindingStatus[]): KernelFindingStatus {
  for (const candidate of STATUS_PRECEDENCE) {
    if (statuses.includes(candidate)) return candidate;
  }
  return "no_signal";
}
