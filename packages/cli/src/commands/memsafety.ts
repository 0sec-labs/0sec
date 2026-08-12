/**
 * `pwnkit memsafety <source>` — the userspace / Rust memory-safety scan role
 * ("Monty-mode", docs/pwnkit-rust-memsafety-pipeline.md) exposed as a
 * dispatchable CLI entrypoint.
 *
 * This is the standalone command the cloud `memsafety` scan_mode gate
 * (services/worker-controller/src/runners/args.ts, #1279) was waiting on: it
 * clones/prepares a source tree, builds a `MemSafetyTarget` from it (language +
 * build system, auto-detected or forced), runs the in-process `runMemSafetyScan`
 * stage (Track A playbook → Track B closed fuzz loop → Track C classify/verdict),
 * and posts the resulting `Finding[]` to the cloud-sink — mirroring how
 * `deep-review` clones via `prepare()` and emits via `postFinding()`.
 *
 * HONESTY — this wires the ROLE INVOCATION, not a proven repro. The fuzz loop
 * degrades to ZERO findings when the cargo-fuzz / miri / clang toolchain is
 * absent (the stage's `toolingMissing` contract). That is an honest "could not
 * run", NOT a clean pass — we surface it and exit 2 (skipped) so a dashboard
 * scan that never actually fuzzed is never reported as a clean green result.
 * Live memory-corruption-repro validation of this pipeline is still pending
 * (0sec-labs/pwnkit#702); this command does not fabricate a crash or a repro.
 *
 * Exit codes (aligned with `deep-review`):
 *   0 → the fuzz loop RAN (with or without captured crashes/findings). A clean
 *       0-crash run is a valid outcome, not proof of memory safety.
 *   2 → skipped: no detectable build system, or the sandbox lacked the fuzz
 *       toolchain so the loop ran zero real iterations (`toolingMissing`).
 *   3 → error (bad flags, unreadable/unclonable target, subsystem escape).
 */

import type { Command } from "commander";
import { existsSync } from "node:fs";
import { resolve, join, sep } from "node:path";
import type { RuntimeMode } from "@pwnkit/shared";
import type { MemSafetyTarget } from "@pwnkit/core";

type MemLanguage = MemSafetyTarget["language"];
type MemBuildSystem = MemSafetyTarget["buildSystem"];

const VALID_LANGUAGES: ReadonlySet<MemLanguage> = new Set(["c", "cpp", "rust"]);
const VALID_BUILD_SYSTEMS: ReadonlySet<MemBuildSystem> = new Set([
  "cargo",
  "cmake",
  "autotools",
  "meson",
  "make",
]);

export interface DetectedBuild {
  language: MemLanguage;
  buildSystem: MemBuildSystem;
}

/**
 * Infer the (language, buildSystem) pair from marker files in the source root,
 * mirroring the `MemSafetyTarget` shape the fuzz runner consumes. Cargo wins
 * first (a Rust crate is unambiguous); the C/C++ build systems are checked
 * most-specific-first. Returns null when nothing recognisable is present so the
 * caller can ask the operator to force `--language`/`--build-system`. Pure over
 * its injected `exists` probe so it is unit-testable without a real tree.
 */
export function detectMemSafetyBuild(
  sourceRoot: string,
  exists: (path: string) => boolean = existsSync,
): DetectedBuild | null {
  const has = (rel: string): boolean => exists(join(sourceRoot, rel));
  if (has("Cargo.toml")) return { language: "rust", buildSystem: "cargo" };
  if (has("CMakeLists.txt")) return { language: "cpp", buildSystem: "cmake" };
  if (has("meson.build")) return { language: "c", buildSystem: "meson" };
  if (has("configure.ac") || has("configure.in") || has("configure")) {
    return { language: "c", buildSystem: "autotools" };
  }
  if (has("Makefile") || has("makefile") || has("GNUmakefile")) {
    return { language: "c", buildSystem: "make" };
  }
  return null;
}

export interface RunMemSafetyOptions {
  /** Source tree to fuzz — a local path or a git URL (resolved via prepare). */
  target: string;
  /** Narrow the scanned root to a subdirectory (must stay inside the tree). */
  subsystem?: string;
  /** Force the language when auto-detection is wrong/ambiguous. */
  language?: MemLanguage;
  /** Force the build system when auto-detection is wrong/ambiguous. */
  buildSystem?: MemBuildSystem;
  /**
   * libFuzzer / cargo-fuzz harness target name. When omitted, the runner
   * selects the sole existing cargo-fuzz target and otherwise fails closed.
   */
  harnessEntry?: string;
  /** Non-standard cargo-fuzz directory relative to the source root. */
  fuzzDir?: string;
  /** Additionally run `cargo +nightly miri` for UB detection (Rust path). */
  runMiri?: boolean;
  /** Fuzz wall-clock budget in seconds (maps to libFuzzer -max_total_time). */
  fuzzTimeoutSec?: number;
  runtime?: RuntimeMode;
  /** Clone timeout budget in ms, forwarded to prepare(). */
  timeoutMs?: number;
  log?: (msg: string) => void;
}

export interface MemSafetyOutcome {
  exitCode: number;
  result: Record<string, unknown>;
}

/**
 * Run the memory-safety scan role over a prepared source tree and return a
 * JSON-ready outcome. Exposed for testing. Posts findings to the cloud-sink
 * when the sink env is set (the stage itself posts nothing), same as
 * `deep-review`.
 */
export async function runMemSafety(opts: RunMemSafetyOptions): Promise<MemSafetyOutcome> {
  const { prepare, runMemSafetyScan, getCloudSinkConfig, postFinding } = await import(
    "@pwnkit/core"
  );
  const log = opts.log ?? (() => {});

  // Resolve a local path or a git URL into a local tree (same prepare() path
  // deep-review / hunt / review use; a git URL is shallow-cloned).
  const prepared = await prepare(
    opts.target,
    "source-code",
    { ...(opts.timeoutMs ? { timeout: opts.timeoutMs } : {}) },
    (e) => {
      if (e.message) log(`[memsafety:source] ${e.message}`);
    },
  );
  const sourceRoot = resolve(prepared.resolvedTarget);

  try {
    // Subsystem scoping — must stay inside the prepared tree (no path escape).
    let scopeRoot = sourceRoot;
    if (opts.subsystem && opts.subsystem.trim() !== "") {
      const scoped = resolve(join(sourceRoot, opts.subsystem));
      if (scoped !== sourceRoot && !scoped.startsWith(sourceRoot + sep)) {
        throw new Error(`--subsystem '${opts.subsystem}' escapes the source tree`);
      }
      scopeRoot = scoped;
    }

    // Build the MemSafetyTarget: flags override auto-detection. When only one of
    // language/buildSystem is forced, the detector fills the other.
    const detected = detectMemSafetyBuild(scopeRoot);
    const language = opts.language ?? detected?.language;
    const buildSystem = opts.buildSystem ?? detected?.buildSystem;
    if (!language || !buildSystem) {
      return {
        exitCode: 2,
        result: {
          mode: "memsafety",
          source: scopeRoot,
          note:
            "could not detect a Rust/C/C++ build system (no Cargo.toml / " +
            "CMakeLists.txt / meson.build / configure / Makefile under the scope). " +
            "Pass --language and --build-system to force it.",
        },
      };
    }

    const target: MemSafetyTarget = {
      language,
      buildSystem,
      sourceRoot: scopeRoot,
      ...(opts.harnessEntry ? { harnessEntry: opts.harnessEntry } : {}),
      ...(opts.fuzzDir ? { fuzzDir: opts.fuzzDir } : {}),
    };

    // Capture the cloud-sink config; the stage does NO I/O (posts nothing), so
    // we post its findings ourselves — the same discovered-candidate path
    // deep-review uses. No-op when not in cloud mode (sinkCfg null).
    const sinkCfg = getCloudSinkConfig();

    const scan = await runMemSafetyScan({
      target,
      fuzz: {
        ...(opts.runMiri != null ? { runMiri: opts.runMiri } : {}),
        ...(opts.fuzzTimeoutSec ? { timeoutSec: opts.fuzzTimeoutSec } : {}),
      },
      logger: log,
    });

    let ingested = 0;
    if (sinkCfg) {
      for (const finding of scan.findings) {
        await postFinding(finding, sinkCfg);
        ingested++;
      }
      log(`[memsafety] posted ${ingested} finding(s) to the cloud-sink`);
    }

    const reproduced = scan.details.filter((d) => d.verdict.verdict === "confirmed").length;

    // Incomplete-loop contract: unavailable tooling or an ambiguous/missing
    // harness is never a clean pass. Exit 2 so callers cannot report the
    // zero-finding result as completed coverage.
    if (scan.toolingMissing.length > 0) {
      return {
        exitCode: 2,
        result: {
          mode: "memsafety",
          source: scopeRoot,
          language,
          build_system: buildSystem,
          harness: scan.loop.executedHarness ?? null,
          tooling_missing: scan.toolingMissing,
          findings: 0,
          note:
            "fuzz/sanitizer loop could not complete because an execution prerequisite " +
            "was unavailable; emitted ZERO findings (honest degradation, NOT a clean pass). " +
            "Live memcorruption-repro validation of this role is pending (#702).",
          warnings: scan.warnings.slice(0, 10),
        },
      };
    }

    return {
      exitCode: 0,
      result: {
        mode: "memsafety",
        source: scopeRoot,
        language,
        build_system: buildSystem,
        harness: scan.loop.executedHarness ?? null,
        iterations: scan.loop.iterations,
        findings: scan.findings.length,
        reproduced_memcorruption: reproduced,
        tooling_missing: scan.toolingMissing,
        details: scan.details.map((d) => ({
          title: d.finding.title,
          severity: d.finding.severity,
          primitive: d.exploitability.primitive,
          verdict: d.verdict.verdict,
        })),
        ingested: sinkCfg ? ingested : null,
        warnings: scan.warnings.slice(0, 10),
        note:
          reproduced > 0
            ? "reproduced memory-corruption PoC(s) captured under the sanitizer/Miri build."
            : scan.findings.length > 0
              ? "fuzz loop captured crash candidate(s), but no saved reproducer met the memory-corruption PoC gate."
              : "fuzz loop ran; no crashes captured. This is NOT a proof of memory safety.",
      },
    };
  } finally {
    prepared.cleanup();
  }
}

interface MemSafetyCliOpts {
  subsystem?: string;
  language?: string;
  buildSystem?: string;
  harness?: string;
  fuzzDir?: string;
  miri?: boolean;
  fuzzTimeout?: string;
  runtime?: string;
  format?: string;
  output?: string;
  timeout?: string;
}

function parsePositive(flag: string, raw: string | undefined, dflt: number): number {
  if (raw === undefined) return dflt;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`invalid ${flag} '${raw}' (expected positive integer)`);
  }
  return n;
}

function parseLanguage(raw: string | undefined): MemLanguage | undefined {
  if (raw === undefined) return undefined;
  const v = raw.trim().toLowerCase();
  if (!VALID_LANGUAGES.has(v as MemLanguage)) {
    throw new Error(`invalid --language '${raw}' (expected one of: c, cpp, rust)`);
  }
  return v as MemLanguage;
}

function parseBuildSystem(raw: string | undefined): MemBuildSystem | undefined {
  if (raw === undefined) return undefined;
  const v = raw.trim().toLowerCase();
  if (!VALID_BUILD_SYSTEMS.has(v as MemBuildSystem)) {
    throw new Error(
      `invalid --build-system '${raw}' (expected one of: cargo, cmake, autotools, meson, make)`,
    );
  }
  return v as MemBuildSystem;
}

async function memsafetyAction(target: string, opts: MemSafetyCliOpts): Promise<void> {
  if (!target || target.trim() === "") {
    throw new Error("missing required argument: <source> (source tree path or git URL)");
  }
  const { writeFileSync } = await import("node:fs");
  const outcome = await runMemSafety({
    target,
    ...(opts.subsystem ? { subsystem: opts.subsystem } : {}),
    ...(parseLanguage(opts.language) ? { language: parseLanguage(opts.language) } : {}),
    ...(parseBuildSystem(opts.buildSystem)
      ? { buildSystem: parseBuildSystem(opts.buildSystem) }
      : {}),
    ...(opts.harness ? { harnessEntry: opts.harness } : {}),
    ...(opts.fuzzDir ? { fuzzDir: opts.fuzzDir } : {}),
    ...(opts.miri ? { runMiri: true } : {}),
    ...(opts.fuzzTimeout
      ? { fuzzTimeoutSec: parsePositive("--fuzz-timeout", opts.fuzzTimeout, 60) }
      : {}),
    ...(opts.runtime ? { runtime: opts.runtime as RuntimeMode } : {}),
    timeoutMs: parsePositive("--timeout", opts.timeout, 600_000),
    log: (m) => process.stderr.write(m + "\n"),
  });

  const json = JSON.stringify(outcome.result, null, 2);
  if (opts.output) writeFileSync(resolve(opts.output), json + "\n", "utf8");
  else process.stdout.write(json + "\n");
  process.exitCode = outcome.exitCode;
}

export function registerMemsafetyCommand(program: Command): void {
  program
    .command("memsafety")
    .description(
      "Userspace / Rust memory-safety scan (Monty-mode): clone a source tree, " +
        "build a fuzz/sanitizer harness, run the closed fuzz loop, and emit " +
        "reproduced-memcorruption findings. Exit 0=loop completed (with or without " +
        "crashes), 2=skipped (no build system detected or execution prerequisite " +
        "unavailable), 3=error (bad flags / unreadable target).",
    )
    .argument("<source>", "Source tree to fuzz (a local path or a git URL)")
    .option("--subsystem <path>", "Narrow the scanned root to a subdirectory")
    .option("--language <lang>", "Force the language: c | cpp | rust (else auto-detected)")
    .option(
      "--build-system <sys>",
      "Force the build system: cargo | cmake | autotools | meson | make (else auto-detected)",
    )
    .option("--harness <name>", "libFuzzer / cargo-fuzz harness target name")
    .option("--fuzz-dir <path>", "Non-standard cargo-fuzz directory (relative to source root)")
    .option("--miri", "Additionally run `cargo +nightly miri` for UB detection (Rust)", false)
    .option("--fuzz-timeout <sec>", "Fuzz wall-clock budget in seconds (default 60)")
    .option("--format <fmt>", "Output format (json)", "json")
    .option("--output <path>", "Write the result JSON to this path instead of stdout")
    .option("--runtime <mode>", "Engine runtime (default api)")
    .option("--timeout <ms>", "Clone/prepare timeout budget in milliseconds", "600000")
    .action(async (source: string, opts: MemSafetyCliOpts) => {
      try {
        await memsafetyAction(source, opts);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        const json = JSON.stringify({ mode: "memsafety", error: reason }, null, 2);
        if (opts.output) {
          const { writeFileSync } = await import("node:fs");
          try {
            writeFileSync(resolve(opts.output), json + "\n", "utf8");
          } catch {
            process.stderr.write(json + "\n");
          }
        } else process.stdout.write(json + "\n");
        process.exitCode = 3;
      }
    });
}
