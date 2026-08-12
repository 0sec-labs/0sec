/**
 * Closed userspace / Rust fuzz loop (Monty-mode Gap 2).
 *
 * The kernel pipeline (`kernel-vm-runner.ts`) builds a kernel, boots it in
 * QEMU, runs a reproducer, and captures the crash. This module is the
 * **userspace** analogue: given a `MemSafetyTarget`, it closes the loop that
 * `c-cpp-tier2.ts` deliberately leaves open — compile, run, capture the
 * crash, dedup by a stack signature, and (best-effort) minimise the input.
 *
 * Two execution paths:
 *   - **Rust**: drive `cargo fuzz run <target>` (libFuzzer) and an optional
 *     `cargo +nightly miri` UB run mode.
 *   - **C/C++**: execute the `compile_command` / `run_command` that
 *     `buildTier2Harness` already produces.
 *
 * Like `kernel-vm-runner`, this **degrades gracefully when tooling is
 * absent**. cargo-fuzz and miri are not installed on the dev box today; when
 * a required tool is missing we record it in `FuzzLoopResult.toolingMissing`
 * with an actionable install hint and return an empty-but-honest result
 * rather than fabricating a crash or a clean run.
 *
 * Side-effect discipline: the only writes happen under a per-run artifact
 * directory (an `mkdtemp` under `os.tmpdir()` unless an `artifactDir` is
 * supplied), mirroring the kernel runner. We never write into the target
 * source tree.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { parseSanitizerLog } from "../review/sanitizer-log.js";
import type { Tier2HarnessArtifact } from "../review/c-cpp-tier2.js";
import type {
  CrashArtifact,
  FuzzLoopResult,
  MemPrimitive,
  MemSafetyTarget,
} from "./memsafety-types.js";

// ────────────────────────────────────────────────────────────────────
// Options
// ────────────────────────────────────────────────────────────────────

export interface UserspaceFuzzOptions {
  /** The build under test. */
  target: MemSafetyTarget;
  /**
   * For the C/C++ path: the artifact emitted by `buildTier2Harness`. We
   * consume its `compile_command` / `run_command` verbatim — this is the
   * seam that finally closes Tier-2's "does not compile/run" gap.
   */
  tier2Artifact?: Tier2HarnessArtifact;
  /**
   * Total wall-clock budget for the fuzz run, seconds. Maps to libFuzzer's
   * `-max_total_time` on the Rust path and bounds the child process on both.
   * Defaults to `PWNKIT_USERSPACE_FUZZ_TIMEOUT_SEC` or 60s.
   */
  timeoutSec?: number;
  /**
   * Whether to additionally run `cargo +nightly miri` for UB detection on
   * the Rust path. Defaults to false — miri is slow and not always wanted.
   */
  runMiri?: boolean;
  /**
   * Persist artifacts (crash inputs, logs) under this directory instead of a
   * throwaway tmp dir. Mirrors `KernelVmConfig.artifactDir`.
   */
  artifactDir?: string;
  /** Custom logger; defaults to `console.log`. Matches the kernel runner. */
  logger?: (line: string) => void;
}

// ────────────────────────────────────────────────────────────────────
// Tooling detection (degrade-when-absent, like QEMU/kernel-build inputs)
// ────────────────────────────────────────────────────────────────────

/** Install hints surfaced when a required tool is missing. */
const TOOLING_HINTS: Record<string, string> = {
  cargo: "cargo not found — install the Rust toolchain via https://rustup.rs",
  "cargo-fuzz":
    "cargo-fuzz not found — install with `cargo install cargo-fuzz` (requires a nightly toolchain for `cargo fuzz run`)",
  "cargo-fuzz-harness":
    "cargo-fuzz needs exactly one harness — pass `--harness <name>` or provide a source tree with one cargo-fuzz target",
  miri: "miri not found — install with `rustup +nightly component add miri`",
  clang: "clang not found — install LLVM/clang to compile the libFuzzer harness",
};

/**
 * Probe for an executable on PATH without throwing. We shell out to the tool
 * with a cheap version/help flag rather than parsing PATH ourselves, since
 * cargo subcommands (`cargo fuzz`) are not standalone binaries.
 */
function commandAvailable(
  command: string,
  args: string[],
): Promise<boolean> {
  return new Promise((resolveProbe) => {
    execFile(command, args, { timeout: 10_000 }, (error) => {
      resolveProbe(!error);
    });
  });
}

async function cargoAvailable(): Promise<boolean> {
  return commandAvailable("cargo", ["--version"]);
}

async function cargoFuzzAvailable(): Promise<boolean> {
  // `cargo fuzz --help` exits 0 only when the cargo-fuzz subcommand exists.
  return commandAvailable("cargo", ["fuzz", "--help"]);
}

async function miriAvailable(): Promise<boolean> {
  // miri is a nightly component; `cargo +nightly miri --version` is the
  // canonical probe and exits non-zero if the component is missing.
  return commandAvailable("cargo", ["+nightly", "miri", "--version"]);
}

async function clangAvailable(): Promise<boolean> {
  return commandAvailable("clang", ["--version"]);
}

// ────────────────────────────────────────────────────────────────────
// Crash parsing → CrashArtifact
// ────────────────────────────────────────────────────────────────────

/** ASAN error kind → userspace MemPrimitive. */
const ASAN_PRIMITIVE: Record<string, MemPrimitive> = {
  "heap-use-after-free": "use-after-free",
  "stack-use-after-return": "use-after-free",
  "stack-use-after-scope": "use-after-free",
  "double-free": "double-free",
  "attempting-double-free": "double-free",
  "stack-buffer-overflow": "stack-oob",
};

/** Map an ASAN/UBSAN sanitizer verdict onto a userspace primitive. */
function primitiveFromSanitizerKind(
  kind: string,
  rw: "read" | "write" | "both" | "unknown",
): MemPrimitive {
  if (kind === "heap-buffer-overflow" || kind === "global-buffer-overflow") {
    return rw === "write" ? "heap-oob-write" : "heap-oob-read";
  }
  const direct = ASAN_PRIMITIVE[kind];
  if (direct) return direct;
  // UBSAN kinds emitted by sanitizer-log.ts.
  if (kind === "signed-integer-overflow" || kind === "shift-exponent") {
    return "integer-overflow";
  }
  if (kind === "null-pointer-use") return "null-deref";
  return "unknown";
}

/**
 * Stable dedup signature over the *normalised* top stack frames, mirroring
 * the kernel-oracle KASAN hashing approach (function names, offsets stripped).
 * Falls back to a hash of the crash kind + first lines when no frames parse.
 */
function signatureFromFrames(
  kind: string,
  frames: string[],
  rawOutput: string,
): string {
  const top = frames
    .map((f) => normaliseFrame(f))
    .filter(Boolean)
    .slice(0, 5);
  const basis =
    top.length > 0
      ? `${kind}\n${top.join("\n")}`
      : `${kind}\n${rawOutput.trim().split("\n").slice(0, 3).join("\n")}`;
  return createHash("sha256").update(basis).digest("hex").slice(0, 16);
}

/** Strip addresses, offsets, and PIDs so the same bug hashes identically. */
function normaliseFrame(frame: string): string {
  return frame
    .replace(/0x[0-9a-fA-F]+/g, "")
    .replace(/\+0x[0-9a-fA-F]+(\/0x[0-9a-fA-F]+)?/g, "")
    .replace(/:\d+(:\d+)?\b/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Parse a single run's combined stdout/stderr into a CrashArtifact, or null
 * if nothing crash-like was found. Order matters: sanitizer reports are the
 * richest, then miri, then panic, then a bare segfault/oom/timeout.
 */
export function parseCrashOutput(
  output: string,
  hint?: { kind?: CrashArtifact["kind"]; inputPath?: string },
): CrashArtifact | null {
  const text = output.trim();
  if (!text) return null;

  // ── ASAN / UBSAN (reuse the existing review-layer parser) ──────────
  const sanitizer = parseSanitizerLog(text);
  if (sanitizer) {
    const frames = sanitizer.frames.map((f) =>
      [f.functionName, f.file && `${f.file}:${f.line ?? ""}`]
        .filter(Boolean)
        .join(" "),
    );
    const kind: CrashArtifact["kind"] =
      sanitizer.sanitizer === "asan" ? "asan" : "ubsan";
    const rw =
      sanitizer.primitive === "read" || sanitizer.primitive === "write"
        ? sanitizer.primitive
        : "unknown";
    return {
      kind,
      signature: signatureFromFrames(sanitizer.kind, frames, text),
      rawOutput: text,
      inputPath: hint?.inputPath,
      stack: frames.length > 0 ? frames : undefined,
      primitive: primitiveFromSanitizerKind(sanitizer.kind, rw),
    };
  }

  // ── Miri (Rust UB interpreter) ─────────────────────────────────────
  if (/error: Undefined Behavior|Miri caught|error\[E\d+\].*unsafe/i.test(text)) {
    const frames = parseMiriFrames(text);
    return {
      kind: "miri",
      signature: signatureFromFrames("miri", frames, text),
      rawOutput: text,
      inputPath: hint?.inputPath,
      stack: frames.length > 0 ? frames : undefined,
      primitive: primitiveFromMiri(text),
    };
  }

  // ── Rust panic (assertion / unwrap / index OOB) ────────────────────
  if (/thread '.*' panicked at|panicked at/i.test(text)) {
    const frames = parseRustBacktrace(text);
    return {
      kind: "panic",
      signature: signatureFromFrames("panic", frames, text),
      rawOutput: text,
      inputPath: hint?.inputPath,
      stack: frames.length > 0 ? frames : undefined,
      primitive: primitiveFromPanic(text),
    };
  }

  // ── Bare process-level failures ────────────────────────────────────
  if (hint?.kind === "timeout") {
    return {
      kind: "timeout",
      signature: signatureFromFrames("timeout", [], text),
      rawOutput: text,
      inputPath: hint?.inputPath,
      primitive: "unknown",
    };
  }
  if (/out-of-memory|libFuzzer: out-of-memory|rss limit exceeded/i.test(text)) {
    return {
      kind: "oom",
      signature: signatureFromFrames("oom", [], text),
      rawOutput: text,
      inputPath: hint?.inputPath,
      primitive: "unknown",
    };
  }
  if (
    hint?.kind === "segfault" ||
    /SEGV|segmentation fault|deadly signal|SIGSEGV/i.test(text)
  ) {
    return {
      kind: "segfault",
      signature: signatureFromFrames("segfault", parseRustBacktrace(text), text),
      rawOutput: text,
      inputPath: hint?.inputPath,
      primitive: "null-deref",
    };
  }

  return null;
}

function parseMiriFrames(text: string): string[] {
  // Miri prints `--> src/lib.rs:42:5` location lines plus a backtrace.
  const frames: string[] = [];
  const locRe = /-->\s+(.+?:\d+(?::\d+)?)/g;
  let m: RegExpExecArray | null;
  while ((m = locRe.exec(text)) !== null) frames.push(m[1]!);
  return frames.length > 0 ? frames : parseRustBacktrace(text);
}

function parseRustBacktrace(text: string): string[] {
  // RUST_BACKTRACE frames look like `  N: <symbol>` followed by `at file:line`.
  const frames: string[] = [];
  const symRe = /^\s*\d+:\s+(.+)$/gm;
  let m: RegExpExecArray | null;
  while ((m = symRe.exec(text)) !== null) frames.push(m[1]!.trim());
  return frames;
}

function primitiveFromMiri(text: string): MemPrimitive {
  const lower = text.toLowerCase();
  if (lower.includes("use-after-free") || lower.includes("dangling")) {
    return "use-after-free";
  }
  if (lower.includes("uninitialized")) return "uninit-read";
  if (lower.includes("out-of-bounds") || lower.includes("out of bounds")) {
    return "heap-oob-read";
  }
  if (lower.includes("null pointer") || lower.includes("null reference")) {
    return "null-deref";
  }
  if (lower.includes("type") && lower.includes("validity")) return "type-confusion";
  return "unknown";
}

function primitiveFromPanic(text: string): MemPrimitive {
  const lower = text.toLowerCase();
  if (lower.includes("index out of bounds")) return "heap-oob-read";
  if (lower.includes("overflow")) return "integer-overflow";
  // A plain panic is a controlled abort, not a memory-safety primitive.
  return "unknown";
}

// ────────────────────────────────────────────────────────────────────
// Loop driver
// ────────────────────────────────────────────────────────────────────

interface RunResult {
  output: string;
  stdout: string;
  timedOut: boolean;
  signalled: boolean;
  failed: boolean;
}

/** Run a child process under a wall-clock budget, capturing combined output. */
function runChild(
  command: string,
  args: string[],
  cwd: string,
  timeoutMs: number,
): Promise<RunResult> {
  return new Promise((resolveRun) => {
    execFile(
      command,
      args,
      { cwd, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024, killSignal: "SIGKILL" },
      (error, stdout, stderr) => {
        const stdoutText = String(stdout ?? "");
        const output = `${stdoutText}${String(stderr ?? "")}`;
        const timedOut = Boolean(
          error && (error as NodeJS.ErrnoException & { killed?: boolean }).killed,
        );
        const signalled = Boolean(error && (error as { signal?: string }).signal);
        resolveRun({
          output,
          stdout: stdoutText,
          timedOut,
          signalled,
          failed: Boolean(error),
        });
      },
    );
  });
}

function dedupeBySignature(crashes: CrashArtifact[]): CrashArtifact[] {
  const seen = new Map<string, CrashArtifact>();
  for (const crash of crashes) {
    if (!seen.has(crash.signature)) seen.set(crash.signature, crash);
  }
  return Array.from(seen.values());
}

function makeArtifactDir(artifactDir: string | undefined): {
  dir: string;
  ephemeral: boolean;
} {
  if (artifactDir) {
    mkdirSync(artifactDir, { recursive: true });
    return { dir: mkdtempSync(join(artifactDir, "pwnkit-uf-")), ephemeral: false };
  }
  return { dir: mkdtempSync(join(tmpdir(), "pwnkit-uf-")), ephemeral: true };
}

/** Count files under a corpus dir, tolerating its absence. */
function corpusCount(dir: string): number {
  try {
    return readdirSync(dir).filter((name) => {
      try {
        return statSync(join(dir, name)).isFile();
      } catch {
        return false;
      }
    }).length;
  } catch {
    return 0;
  }
}

/**
 * Run the closed userspace fuzz loop for a `MemSafetyTarget`.
 *
 * Returns an honest `FuzzLoopResult`: when required tooling is missing the
 * result has `iterations: 0`, no crashes, and a populated `toolingMissing`
 * list — never a fabricated success.
 */
export async function runUserspaceFuzzLoop(
  opts: UserspaceFuzzOptions,
): Promise<FuzzLoopResult> {
  const log = opts.logger ?? ((line: string) => console.log(line));
  const start = Date.now();
  const timeoutSec =
    opts.timeoutSec ??
    parseInt(process.env.PWNKIT_USERSPACE_FUZZ_TIMEOUT_SEC?.trim() || "60", 10);
  const timeoutMs = Math.max(1, timeoutSec) * 1000;

  const { dir: workDir, ephemeral } = makeArtifactDir(opts.artifactDir);
  const toolingMissing: string[] = [];

  try {
    if (opts.target.language === "rust") {
      return await runRustLoop(opts, { workDir, timeoutMs, toolingMissing, log, start });
    }
    return await runCLoop(opts, { workDir, timeoutMs, toolingMissing, log, start });
  } finally {
    if (ephemeral) rmSync(workDir, { recursive: true, force: true });
  }
}

interface LoopCtx {
  workDir: string;
  timeoutMs: number;
  toolingMissing: string[];
  log: (line: string) => void;
  start: number;
}

/**
 * Build the `cargo fuzz run` argument vector. Pure + exported so the
 * `--fuzz-dir` routing is unit-testable. `--fuzz-dir` lets projects keep
 * their fuzz crate off the conventional `fuzz/` path (e.g. Monty's
 * `crates/fuzz`); omitted → cargo-fuzz default.
 */
export function cargoFuzzRunArgs(
  harnessEntry: string,
  fuzzDir: string | undefined,
  timeoutSec: number,
): string[] {
  const fuzzDirArgs = fuzzDir ? ["--fuzz-dir", fuzzDir] : [];
  return [
    "fuzz",
    "run",
    ...fuzzDirArgs,
    harnessEntry,
    "--",
    `-max_total_time=${Math.floor(timeoutSec)}`,
  ];
}

/** Build the `cargo fuzz list` argument vector for harness discovery. */
function cargoFuzzListArgs(fuzzDir: string | undefined): string[] {
  return ["fuzz", "list", ...(fuzzDir ? ["--fuzz-dir", fuzzDir] : [])];
}

type HarnessDiscovery =
  | { harnessEntry: string }
  | { reason: string };

/**
 * Discover a cargo-fuzz target only when the source tree makes the choice
 * unambiguous. Selecting an arbitrary harness would make scan evidence
 * non-repeatable and can hide the relevant attack surface.
 */
async function discoverCargoFuzzHarness(
  sourceRoot: string,
  fuzzDir: string | undefined,
  timeoutMs: number,
): Promise<HarnessDiscovery> {
  if (!existsSync(join(sourceRoot, fuzzDir ?? "fuzz", "Cargo.toml"))) {
    return { reason: `no cargo-fuzz manifest at ${fuzzDir ?? "fuzz"}/Cargo.toml` };
  }

  const res = await runChild(
    "cargo",
    cargoFuzzListArgs(fuzzDir),
    sourceRoot,
    timeoutMs,
  );
  if (res.failed) return { reason: "cargo fuzz list failed" };

  const harnesses = Array.from(
    new Set(
      res.stdout
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    ),
  );
  if (harnesses.length === 1) return { harnessEntry: harnesses[0]! };
  if (harnesses.length === 0) return { reason: "no cargo-fuzz harnesses found" };
  return {
    reason: `multiple cargo-fuzz harnesses found (${harnesses.join(", ")})`,
  };
}

async function runRustLoop(
  opts: UserspaceFuzzOptions,
  ctx: LoopCtx,
): Promise<FuzzLoopResult> {
  const { target } = opts;
  const sourceRoot = resolve(target.sourceRoot);
  const fuzzBase = target.fuzzDir ?? "fuzz";
  const crashes: CrashArtifact[] = [];
  let iterations = 0;
  let harnessEntry = target.harnessEntry;
  let executedHarness: string | undefined;

  // cargo is the floor requirement for any Rust path.
  if (!(await cargoAvailable())) {
    ctx.toolingMissing.push("cargo");
    ctx.log(`[userspace-fuzz] ${TOOLING_HINTS.cargo}`);
    return finish(crashes, iterations, sourceRoot, ctx, "fuzz");
  }

  // ── cargo-fuzz (libFuzzer) ─────────────────────────────────────────
  if (!(await cargoFuzzAvailable())) {
    ctx.toolingMissing.push("cargo-fuzz");
    ctx.log(`[userspace-fuzz] ${TOOLING_HINTS["cargo-fuzz"]}`);
  } else {
    if (!harnessEntry) {
      const discovery = await discoverCargoFuzzHarness(
        sourceRoot,
        target.fuzzDir,
        ctx.timeoutMs,
      );
      if ("reason" in discovery) {
        ctx.toolingMissing.push("cargo-fuzz-harness");
        ctx.log(
          `[userspace-fuzz] ${discovery.reason}; ${TOOLING_HINTS["cargo-fuzz-harness"]}`,
        );
      } else {
        harnessEntry = discovery.harnessEntry;
        ctx.log(`[userspace-fuzz] auto-selected cargo-fuzz harness ${harnessEntry}`);
      }
    }

    if (harnessEntry) {
      ctx.log(`[userspace-fuzz] cargo fuzz run ${harnessEntry} (<=${ctx.timeoutMs / 1000}s)`);
      const res = await runChild(
        "cargo",
        cargoFuzzRunArgs(harnessEntry, target.fuzzDir, ctx.timeoutMs / 1000),
        sourceRoot,
        ctx.timeoutMs + 30_000, // grace beyond libFuzzer's own budget
      );
      executedHarness = harnessEntry;
      iterations += 1;
      const crash = parseCrashOutput(res.output, {
        kind: res.timedOut ? "timeout" : undefined,
        inputPath: findLibfuzzerCrashInput(
          join(sourceRoot, fuzzBase, "artifacts", harnessEntry),
        ),
      });
      if (crash) crashes.push(crash);
    }
  }

  // ── miri UB run ────────────────────────────────────────────────────
  if (opts.runMiri) {
    if (!(await miriAvailable())) {
      ctx.toolingMissing.push("miri");
      ctx.log(`[userspace-fuzz] ${TOOLING_HINTS.miri}`);
    } else {
      ctx.log("[userspace-fuzz] cargo +nightly miri test (UB run)");
      const res = await runChild(
        "cargo",
        ["+nightly", "miri", "test"],
        sourceRoot,
        ctx.timeoutMs + 30_000,
      );
      iterations += 1;
      const crash = parseCrashOutput(res.output, {
        kind: res.timedOut ? "timeout" : undefined,
      });
      if (crash) crashes.push(crash);
    }
  }

  // cargo-fuzz stores its corpus under <fuzzDir>/corpus/<target> (default `fuzz`).
  const corpusDir = harnessEntry
    ? join(sourceRoot, fuzzBase, "corpus", harnessEntry)
    : join(sourceRoot, fuzzBase, "corpus");
  const result = finishWithCorpus(crashes, iterations, corpusDir, ctx);
  if (executedHarness) result.executedHarness = executedHarness;
  return result;
}

async function runCLoop(
  opts: UserspaceFuzzOptions,
  ctx: LoopCtx,
): Promise<FuzzLoopResult> {
  const crashes: CrashArtifact[] = [];
  let iterations = 0;

  if (!opts.tier2Artifact) {
    ctx.log(
      "[userspace-fuzz] C/C++ path requires a tier2Artifact (from buildTier2Harness); nothing to run",
    );
    return finish(crashes, iterations, resolve(opts.target.sourceRoot), ctx, "tier2");
  }

  // The Tier-2 harness compiles with clang's libFuzzer + sanitizers.
  if (!(await clangAvailable())) {
    ctx.toolingMissing.push("clang");
    ctx.log(`[userspace-fuzz] ${TOOLING_HINTS.clang}`);
    return finish(crashes, iterations, resolve(opts.target.sourceRoot), ctx, "tier2");
  }

  const { compile_command, run_command } = opts.tier2Artifact;
  const sourceRoot = resolve(opts.target.sourceRoot);

  // ── Compile ────────────────────────────────────────────────────────
  ctx.log(`[userspace-fuzz] compiling Tier-2 harness: ${compile_command}`);
  const compileRes = await runChild("sh", ["-c", compile_command], sourceRoot, ctx.timeoutMs);
  if (compileRes.signalled || /error:|fatal error:/i.test(compileRes.output)) {
    // A compile failure is not a crash — surface it as a log line and bail
    // honestly rather than inventing a finding.
    ctx.log(`[userspace-fuzz] Tier-2 harness failed to compile:\n${compileRes.output.slice(-2000)}`);
    return finish(crashes, iterations, sourceRoot, ctx, "tier2");
  }

  // ── Run ────────────────────────────────────────────────────────────
  ctx.log(`[userspace-fuzz] running Tier-2 harness: ${run_command}`);
  const runRes = await runChild(
    "sh",
    ["-c", run_command],
    sourceRoot,
    ctx.timeoutMs + 30_000,
  );
  iterations += 1;
  const crash = parseCrashOutput(runRes.output, {
    kind: runRes.timedOut ? "timeout" : runRes.signalled ? "segfault" : undefined,
  });
  if (crash) {
    // libFuzzer writes the reproducing input as `crash-<sha1>` in cwd.
    crash.inputPath = findLibfuzzerCrashInput(sourceRoot) ?? crash.inputPath;
    crashes.push(crash);
  }

  return finishWithCorpus(crashes, iterations, sourceRoot, ctx);
}

/** libFuzzer drops `crash-*` / `oom-*` / `timeout-*` reproducers in cwd. */
function findLibfuzzerCrashInput(dir: string): string | undefined {
  try {
    const hit = readdirSync(dir).find((name) =>
      /^(crash|oom|timeout|leak)-[0-9a-f]+$/i.test(name),
    );
    return hit ? join(dir, hit) : undefined;
  } catch {
    return undefined;
  }
}

function finish(
  crashes: CrashArtifact[],
  iterations: number,
  corpusDir: string,
  ctx: LoopCtx,
  _phase: string,
): FuzzLoopResult {
  return finishWithCorpus(crashes, iterations, corpusDir, ctx);
}

function finishWithCorpus(
  crashes: CrashArtifact[],
  iterations: number,
  corpusDir: string,
  ctx: LoopCtx,
): FuzzLoopResult {
  const deduped = dedupeBySignature(crashes);
  const result: FuzzLoopResult = {
    iterations,
    crashes: deduped,
    corpusSize: corpusCount(corpusDir),
    durationMs: Date.now() - ctx.start,
  };
  if (ctx.toolingMissing.length > 0) {
    result.toolingMissing = Array.from(new Set(ctx.toolingMissing));
  }
  ctx.log(
    `[userspace-fuzz] done: iterations=${result.iterations} crashes=${result.crashes.length}` +
      ` corpus=${result.corpusSize}` +
      (result.toolingMissing ? ` toolingMissing=[${result.toolingMissing.join(",")}]` : ""),
  );
  return result;
}
