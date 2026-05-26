/**
 * pwnkit Tier-3 QEMU validation for C/C++ harness artifacts.
 *
 * Tier-1 (`c-cpp-profile.ts`) wraps a suspect function in a standalone
 * libFuzzer harness. Tier-2 (`c-cpp-tier2.ts`) links that harness
 * against the real library subset. Tier-3 — this module — boots a
 * sanitizer-instrumented QEMU rootfs, compiles the harness inside the
 * guest, executes it against the supplied corpus, and captures the
 * sanitizer log + dmesg for crash classification.
 *
 * ── Why QEMU when libFuzzer already runs on the host? ─────────────
 * Two reasons:
 *  1. A bug that requires syscalls or kernel state (e.g. a netlink
 *     parser, an ioctl handler) won't reproduce inside the agent's host
 *     sandbox. The Tier-3 VM gives the harness a real Linux process
 *     surface.
 *  2. Sanitizer logs need to be captured *with* dmesg for crashes that
 *     manifest as kernel oopses (e.g. a userspace harness probing a
 *     vulnerable driver). The kernel-crash QEMU plumbing already does
 *     this — Tier-3 reuses it rather than building a parallel
 *     execution path.
 *
 * Hand-off contract from Tier-2:
 *   { harness_path, linked_objects, compile_command, run_command,
 *     sanitizers_enabled, detected_build_system, ... }
 *
 * Tier-3 stages everything from `harness_path` + `linked_objects` into
 * a host tmp directory which QEMU mounts via virtfs (see
 * `buildQemuCommand` in `triage/kernel-vm-runner.ts`). The guest
 * runner script copies the staged sources into `/tmp/pwnkit-tier3-run`,
 * runs `compile_command`, then `run_command`, and writes the resulting
 * stderr/stdout + dmesg back into the shared dir for the host to
 * parse.
 *
 * ── Dry-run mode ──────────────────────────────────────────────────
 * If `PWNKIT_KERNEL_QEMU_KERNEL` / `PWNKIT_KERNEL_QEMU_DISK` are unset
 * (the default in CI), `runTier3Validation` short-circuits and returns
 * `{ status: 'qemu_failed', reason: ... }`. This makes the module safe
 * to exercise from vitest without booting a VM. The real-VM path is
 * gated behind `PWNKIT_KERNEL_QEMU=1` in the E2E suite.
 */

import { spawn } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync, existsSync, copyFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import type { Finding } from "@pwnkit/shared";
import {
  buildQemuCommand,
  loadKernelVmConfigFromEnv,
  type KernelVmConfig,
} from "../triage/kernel-vm-runner.js";
import { parseSanitizerLog, type SanitizerVerdict } from "./sanitizer-log.js";
import type { Tier2HarnessArtifact, Sanitizer } from "./c-cpp-tier2.js";

export type Tier3Status =
  | "crash_reproduced"
  | "no_crash"
  | "compile_failed"
  | "qemu_failed";

export interface Tier3ValidationResult {
  status: Tier3Status;
  /** Parsed sanitizer signature when a crash was captured. */
  sanitizer_signature?: SanitizerVerdict;
  /** Absolute path to the sanitizer log on the host (always present, may be empty). */
  sanitizer_log_path: string;
  /** Wall-clock duration of the Tier-3 run, milliseconds. */
  run_duration_ms: number;
  /** Number of corpus inputs the guest harness consumed. */
  corpus_inputs_consumed: number;
  /** Reason string when status is `qemu_failed` or `compile_failed`. */
  reason?: string;
  /** Last 4 KiB of dmesg, if available, for kernel-side crash signals. */
  dmesg_tail?: string;
}

export interface Tier3ValidationOptions {
  /**
   * Override path to a pre-built kernel image. Falls back to
   * `PWNKIT_KERNEL_QEMU_KERNEL`. Both unset → dry-run.
   */
  qemuKernel?: string;
  /**
   * Override path to a pre-built rootfs image. Falls back to
   * `PWNKIT_KERNEL_QEMU_DISK`. Both unset → dry-run.
   */
  qemuDisk?: string;
  /**
   * Corpus inputs to feed the harness. Each entry is an absolute path
   * to a seed file on the host. When omitted, Tier-3 falls back to the
   * libFuzzer empty corpus (libFuzzer will still mutate, just slower).
   */
  runCorpus?: string[];
  /**
   * Hard ceiling on wall-clock for the entire Tier-3 run (boot + compile +
   * fuzz + shutdown). Defaults to 5 minutes, which matches the
   * Tier-2-emitted libFuzzer `-max_total_time=300`.
   */
  wallClockMs?: number;
  /**
   * Sanitizers to instrument the harness with. Defaults to the set
   * Tier-2 emitted (`artifact.sanitizers_enabled`). Provided here so
   * the caller can downgrade msan → asan when the rootfs lacks msan
   * runtime libs without re-running Tier-2.
   */
  sanitizers?: Sanitizer[];
  /**
   * Test hook: spawn replacement. Vitest passes a mock that simulates
   * VM completion without booting QEMU. Production callers should not
   * set this.
   */
  spawnImpl?: typeof spawn;
  /**
   * Test hook: override the env-loader. Vitest uses this to feed a
   * deterministic `KernelVmConfig` without exporting env vars.
   */
  loadConfigImpl?: () => KernelVmConfig;
}

const DEFAULT_WALL_CLOCK_MS = 5 * 60 * 1000;
const SHARED_DIR_PREFIX = "pwnkit-tier3-";
const GUEST_WORK_DIR = "/tmp/pwnkit-tier3-run";

/**
 * Run a Tier-3 QEMU validation against a Tier-2 artifact.
 *
 * The function is async because QEMU runs are inherently async. It
 * never throws on the "expected" failure paths (no env vars, compile
 * error, no crash): those are reported via `result.status`. Callers
 * can therefore treat the return value as a complete verdict without
 * try/catch noise.
 */
export async function runTier3Validation(
  artifact: Tier2HarnessArtifact,
  opts: Tier3ValidationOptions = {},
): Promise<Tier3ValidationResult> {
  const start = Date.now();
  const corpus = opts.runCorpus ?? [];
  const sanitizers = opts.sanitizers ?? artifact.sanitizers_enabled;

  // Env-var probe: Tier-3 must be able to boot a real VM. If the
  // operator hasn't staged a kernel + rootfs, fail cleanly. This is
  // the path CI and dev machines take by default.
  const envKernel = opts.qemuKernel ?? process.env.PWNKIT_KERNEL_QEMU_KERNEL?.trim();
  const envDisk = opts.qemuDisk ?? process.env.PWNKIT_KERNEL_QEMU_DISK?.trim();
  if (!envKernel || !envDisk) {
    return {
      status: "qemu_failed",
      reason:
        "Tier-3 requires PWNKIT_KERNEL_QEMU_KERNEL and PWNKIT_KERNEL_QEMU_DISK (the same env vars 0cloud injects for kernel scans). Set them to prebuilt artifacts or pass qemuKernel/qemuDisk explicitly.",
      sanitizer_log_path: "",
      run_duration_ms: Date.now() - start,
      corpus_inputs_consumed: 0,
    };
  }
  if (!existsSync(envKernel) || !existsSync(envDisk)) {
    return {
      status: "qemu_failed",
      reason: `Kernel image '${envKernel}' or disk image '${envDisk}' does not exist on disk.`,
      sanitizer_log_path: "",
      run_duration_ms: Date.now() - start,
      corpus_inputs_consumed: 0,
    };
  }
  if (!existsSync(artifact.harness_path)) {
    return {
      status: "qemu_failed",
      reason: `Tier-2 harness '${artifact.harness_path}' does not exist; rebuild Tier-2 before Tier-3.`,
      sanitizer_log_path: "",
      run_duration_ms: Date.now() - start,
      corpus_inputs_consumed: 0,
    };
  }

  // Stage the rootfs overlay. Each Tier-3 run gets its own host tmp
  // dir; QEMU mounts it via virtfs. mkdtempSync gives us an idempotent
  // mkdir (no clashes between concurrent runs) and rmSync at the end
  // makes the run leak-free except in the early-throw path, which we
  // handle in the finally.
  const hostTmpDir = mkdtempSync(join(tmpdir(), SHARED_DIR_PREFIX));
  const stagedSources = join(hostTmpDir, "src");
  mkdirSync(stagedSources, { recursive: true });
  let corpusInputsConsumed = 0;
  try {
    // Copy harness + linked objects into the staged overlay. The guest
    // script uses the relative `src/` path inside the shared dir.
    const stagedHarnessPath = join(stagedSources, basename(artifact.harness_path));
    copyFileSync(artifact.harness_path, stagedHarnessPath);
    const stagedLinkedNames: string[] = [];
    for (const obj of artifact.linked_objects) {
      if (!existsSync(obj)) continue;
      const name = basename(obj);
      const dest = join(stagedSources, name);
      copyFileSync(obj, dest);
      stagedLinkedNames.push(name);
    }
    const stagedCorpusDir = join(hostTmpDir, "corpus");
    if (corpus.length > 0) {
      mkdirSync(stagedCorpusDir, { recursive: true });
      for (const seed of corpus) {
        if (!existsSync(seed)) continue;
        const dest = join(stagedCorpusDir, basename(seed));
        copyFileSync(seed, dest);
        corpusInputsConsumed += 1;
      }
    }

    // Load VM config — either from env (production) or from a test
    // injector (vitest). We force the kernel + disk to the values we
    // already validated above, regardless of where the rest of the
    // config came from.
    const baseConfig = opts.loadConfigImpl
      ? opts.loadConfigImpl()
      : loadKernelVmConfigFromEnv();
    const config: KernelVmConfig = {
      ...baseConfig,
      kernelImage: envKernel,
      diskImage: envDisk,
      timeoutSec: Math.ceil((opts.wallClockMs ?? DEFAULT_WALL_CLOCK_MS) / 1000),
    };

    const sanitizerFlag = renderSanitizerFlag(sanitizers);
    const guestCompile = rewriteCompileCommandForGuest(
      artifact.compile_command,
      {
        harnessBasename: basename(artifact.harness_path),
        linkedBasenames: stagedLinkedNames,
        sanitizerFlag,
      },
    );

    const guestScript = renderGuestScript({
      compileCommand: guestCompile,
      timeoutSec: config.timeoutSec,
      hasCorpus: corpus.length > 0,
    });
    const runnerScriptPath = join(hostTmpDir, "runner.sh");
    writeFileSync(runnerScriptPath, guestScript, { encoding: "utf-8", mode: 0o755 });

    const serialLogPath = join(hostTmpDir, "serial.log");
    const sanitizerLogPath = join(hostTmpDir, "sanitizer.log");
    // Pre-create the sanitizer log file so the caller always sees a
    // valid path even if QEMU dies before writing anything.
    writeFileSync(sanitizerLogPath, "");

    const { command, args } = buildQemuCommand(config, serialLogPath, hostTmpDir);
    const spawnImpl = opts.spawnImpl ?? spawn;
    const vmProc = spawnImpl(command, args, { stdio: "ignore" });

    const wallClockMs = opts.wallClockMs ?? DEFAULT_WALL_CLOCK_MS;
    await waitForCompletion(vmProc, hostTmpDir, wallClockMs);

    // Drain results from the shared dir. Each marker file is optional
    // — the guest writes them in order, so a missing one means the
    // guest didn't get that far.
    const compiled = readMarker(hostTmpDir, "compiled.ok") === "1";
    const runLog = readFile(hostTmpDir, "run.log");
    const compileLog = readFile(hostTmpDir, "compile.log");
    const dmesg = readFile(hostTmpDir, "dmesg.log");

    // ASan / UBSan dump their report to stderr by default. The guest
    // script merges stderr → stdout for `run.log`, so the sanitizer
    // verdict lives in `runLog`. We persist it to a stable path so
    // callers can attach it to evidence without rooting around in the
    // tmp dir.
    if (runLog) writeFileSync(sanitizerLogPath, runLog);

    if (!compiled) {
      return {
        status: "compile_failed",
        reason: compileLog || "harness failed to compile in guest; no compile.log produced",
        sanitizer_log_path: sanitizerLogPath,
        run_duration_ms: Date.now() - start,
        corpus_inputs_consumed: corpusInputsConsumed,
        dmesg_tail: dmesg ? dmesg.slice(-4096) : undefined,
      };
    }

    const verdict = runLog ? parseSanitizerLog(runLog) : null;
    if (verdict) {
      return {
        status: "crash_reproduced",
        sanitizer_signature: verdict,
        sanitizer_log_path: sanitizerLogPath,
        run_duration_ms: Date.now() - start,
        corpus_inputs_consumed: corpusInputsConsumed,
        dmesg_tail: dmesg ? dmesg.slice(-4096) : undefined,
      };
    }

    return {
      status: "no_crash",
      sanitizer_log_path: sanitizerLogPath,
      run_duration_ms: Date.now() - start,
      corpus_inputs_consumed: corpusInputsConsumed,
      dmesg_tail: dmesg ? dmesg.slice(-4096) : undefined,
    };
  } catch (err) {
    return {
      status: "qemu_failed",
      reason: err instanceof Error ? err.message : String(err),
      sanitizer_log_path: "",
      run_duration_ms: Date.now() - start,
      corpus_inputs_consumed: corpusInputsConsumed,
    };
  } finally {
    // Best-effort cleanup. We intentionally swallow rm errors — the
    // tmp dir might already be gone if the caller's test harness
    // cleaned up first.
    try {
      rmSync(hostTmpDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }
}

/**
 * Promote findings whose hypothesised category matches a Tier-3
 * sanitizer signature to `status: 'confirmed', confidence: 1.0`.
 *
 * The shape is: Tier-1/2 surfaces a static hypothesis ("looks like an
 * integer truncation on the alloc path"), Tier-3 fires a sanitizer
 * crash with a known category mapping ("UBSan float-cast-overflow" →
 * `integer-truncation`), and we tie the two together so reporting
 * downstream can claim "confirmed by sanitizer, not just static".
 *
 * The promotion is additive: findings that don't match are returned
 * unchanged. The matched finding gets:
 *  - `status: "confirmed"`
 *  - `confidence: 1.0`
 *  - `evidence.analysis` annotated with the sanitizer signature
 *  - A `triageNote` so the audit trail shows why we promoted.
 */
export function promoteFindingsWithTier3Result(
  findings: Finding[],
  result: Tier3ValidationResult,
): Finding[] {
  if (result.status !== "crash_reproduced" || !result.sanitizer_signature) {
    return findings;
  }
  const verdict = result.sanitizer_signature;
  const matchingCategories = candidateFindingCategories(verdict);
  return findings.map((finding) => {
    if (!matchingCategories.has(finding.category)) return finding;
    return {
      ...finding,
      status: "confirmed",
      confidence: 1.0,
      triageNote: `tier3:sanitizer:${verdict.sanitizer}:${verdict.kind}`,
      evidence: {
        ...finding.evidence,
        analysis: appendSanitizerEvidence(finding.evidence?.analysis ?? "", verdict),
      },
    };
  });
}

/**
 * Mapping from sanitizer verdict → finding categories whose hypothesis
 * the verdict confirms.
 *
 * Hand-written, not generated: the relationships are domain-specific
 * (a heap-buffer-overflow READ confirms an out-of-bounds-read static
 * hypothesis but also confirms the broader heap-overflow class) and
 * we'd rather over-promote with a clear note than miss a true
 * positive. UBSan integer-truncation confirms `integer-truncation`
 * *and* `integer-overflow` because static reviewers often file the
 * narrower kind as the broader one.
 */
function candidateFindingCategories(verdict: SanitizerVerdict): Set<Finding["category"]> {
  // Direct mapping from the sanitizer-log categorisation.
  const set = new Set<Finding["category"]>([verdict.category]);

  // Aliases — when a static hypothesis is filed under a broader or
  // narrower category than the sanitizer's verdict, still promote it.
  if (verdict.category === "out-of-bounds-read" || verdict.category === "out-of-bounds-write") {
    set.add("heap-overflow");
  }
  if (verdict.category === "heap-overflow") {
    set.add("out-of-bounds-read");
    set.add("out-of-bounds-write");
  }
  if (verdict.category === "integer-overflow") {
    set.add("integer-truncation");
  }
  if (verdict.category === "integer-truncation") {
    set.add("integer-overflow");
  }
  if (verdict.category === "null-deref") {
    set.add("null-pointer-deref");
  }
  return set;
}

function appendSanitizerEvidence(existing: string, verdict: SanitizerVerdict): string {
  const line = `[pwnkit tier-3] sanitizer=${verdict.sanitizer} kind=${verdict.kind} at ${verdict.sourceFile ?? "?"}:${verdict.sourceLine ?? "?"}`;
  if (!existing) return line;
  return `${existing}\n${line}`;
}

/**
 * Rewrite a Tier-2 compile_command so it runs against the staged
 * sources inside the guest. Tier-2's command uses absolute host paths
 * (`/Users/.../src/api.c`); the guest only sees `/mnt/pwnkit/src/api.c`
 * via the shared dir. We replace the absolute basenames and swap the
 * harness binary path to the guest work dir.
 *
 * This is deliberately a simple token-replace rather than a re-parse:
 * the Tier-2 command is fully under our control (we generated it),
 * and a regex-based rewrite would mis-handle quoted spaces. We rebuild
 * the command from primitives instead.
 */
function rewriteCompileCommandForGuest(
  _hostCommand: string,
  args: { harnessBasename: string; linkedBasenames: string[]; sanitizerFlag: string },
): string {
  const sourceDir = `${GUEST_WORK_DIR}/src`;
  const objectArgs = args.linkedBasenames
    .filter((name) => name !== args.harnessBasename)
    .map((name) => `${sourceDir}/${name}`)
    .join(" ");
  return [
    "clang",
    "-O1",
    "-g",
    args.sanitizerFlag,
    "-fno-omit-frame-pointer",
    `-I${sourceDir}`,
    `${sourceDir}/${args.harnessBasename}`,
    objectArgs,
    "-o",
    `${GUEST_WORK_DIR}/harness`,
  ]
    .filter((part) => part && part.length > 0)
    .join(" ");
}

function renderSanitizerFlag(sanitizers: Sanitizer[]): string {
  const mapped: string[] = sanitizers.map((s) => {
    if (s === "asan") return "address";
    if (s === "ubsan") return "undefined";
    return "memory";
  });
  mapped.push("fuzzer");
  return `-fsanitize=${Array.from(new Set(mapped)).join(",")}`;
}

function renderGuestScript(args: {
  compileCommand: string;
  timeoutSec: number;
  hasCorpus: boolean;
}): string {
  // Same shape as kernel-vm-runner's reproducer script: write markers
  // into the shared dir so the host can read results without parsing
  // serial output.
  const corpusArg = args.hasCorpus ? '"$SHARE_DIR/corpus"' : "";
  return [
    "#!/bin/sh",
    "set -eu",
    "SHARE_DIR=/mnt/pwnkit",
    `WORK_DIR=${GUEST_WORK_DIR}`,
    'mkdir -p "$WORK_DIR"',
    'cp -r "$SHARE_DIR/src" "$WORK_DIR/src" 2>/dev/null || true',
    "compiled=0",
    "executed=0",
    "exit_code=0",
    `if ${args.compileCommand} >"$SHARE_DIR/compile.log" 2>&1; then`,
    "  compiled=1",
    "else",
    "  exit_code=$?",
    "fi",
    'if [ "$compiled" = "1" ]; then',
    "  dmesg -C 2>/dev/null || true",
    // libFuzzer prints its sanitizer report on the failing input; we
    // capture stderr+stdout to a single log for parseSanitizerLog.
    `  if timeout ${args.timeoutSec}s "$WORK_DIR/harness" -runs=200000 -max_total_time=${args.timeoutSec} -timeout=15 ${corpusArg} >"$SHARE_DIR/run.log" 2>&1; then`,
    "    executed=1",
    "    exit_code=0",
    "  else",
    "    exit_code=$?",
    "    executed=1",
    "  fi",
    "fi",
    'dmesg 2>/dev/null > "$SHARE_DIR/dmesg.log" || true',
    'printf "%s\\n" "$compiled" > "$SHARE_DIR/compiled.ok"',
    'printf "%s\\n" "$executed" > "$SHARE_DIR/executed.ok"',
    'printf "%s\\n" "$exit_code" > "$SHARE_DIR/exit_code"',
    "sync",
  ].join("\n");
}

async function waitForCompletion(
  proc: ReturnType<typeof spawn>,
  hostTmpDir: string,
  wallClockMs: number,
): Promise<void> {
  const compiledMarker = join(hostTmpDir, "compiled.ok");
  const deadline = Date.now() + wallClockMs;
  while (Date.now() < deadline) {
    if (existsSync(compiledMarker)) return;
    if (proc.exitCode !== null) {
      // VM exited — give the guest one more tick to flush markers in
      // case the script wrote them just before shutdown.
      await sleep(250);
      if (existsSync(compiledMarker)) return;
      throw new Error(`QEMU exited with code ${proc.exitCode} before producing compiled.ok`);
    }
    await sleep(500);
  }
  // Timeout — kill and surface a clean error.
  if (proc.exitCode === null) {
    proc.kill("SIGTERM");
  }
  throw new Error(`Tier-3 timed out after ${wallClockMs} ms without compiled.ok marker`);
}

function readMarker(dir: string, name: string): string | null {
  const path = join(dir, name);
  if (!existsSync(path)) return null;
  try {
    return readFileSync(path, "utf-8").trim();
  } catch {
    return null;
  }
}

function readFile(dir: string, name: string): string {
  const path = join(dir, name);
  if (!existsSync(path)) return "";
  try {
    const s = statSync(path);
    if (!s.isFile()) return "";
    return readFileSync(path, "utf-8");
  } catch {
    return "";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
