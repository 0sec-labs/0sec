import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Command } from "commander";

/**
 * `0sec binary <target>` — delegate to **0verse**, the in-repo binary-native /
 * no-source analysis engine (a Python project under `0verse/`). This makes
 * "0sec does binary analysis too" literally true: we locate the engine
 * checkout, sanity-check the toolchain (`uv` + the `0verse/` dir), then hand
 * off to `uv run --frozen 0verse <mode> <target> …` with live stdio so the user
 * sees the engine's own output and inherits its exit code.
 *
 * We deliberately do NOT reimplement any of 0verse here — this is a thin,
 * dependency-light launcher over Node built-ins.
 */

/** The 0verse subcommands this launcher exposes via `--mode`. */
export const BINARY_MODES = ["triage", "run", "scan"] as const;
export type BinaryMode = (typeof BINARY_MODES)[number];

export interface BinaryOptions {
  mode: string;
  format?: string;
  backend?: string;
  llm?: string;
}

/**
 * Walk up from the compiled/module directory looking for the `0verse/` engine
 * checkout (identified by its `pyproject.toml`). Robust whether the CLI runs
 * from `dist/commands/` or `src/commands/` — both sit the same depth below the
 * repo root — and tolerant of being invoked from any cwd.
 */
export function locateOverseDir(startDir?: string): string | null {
  let dir = startDir ?? dirname(fileURLToPath(import.meta.url));
  // Bounded walk to the filesystem root.
  for (let i = 0; i < 12; i++) {
    const candidate = join(dir, "0verse");
    if (existsSync(join(candidate, "pyproject.toml"))) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/** True when a runnable `uv` is on PATH. */
export function isUvAvailable(): boolean {
  try {
    const result = spawnSync("uv", ["--version"], {
      stdio: "ignore",
      timeout: 10_000,
    });
    return result.status === 0;
  } catch {
    return false;
  }
}

function normalizeMode(value: string): BinaryMode {
  const mode = value.trim().toLowerCase();
  if (!(BINARY_MODES as readonly string[]).includes(mode)) {
    throw new Error(
      `invalid --mode '${value}'; supported: ${BINARY_MODES.join(", ")}`,
    );
  }
  return mode as BinaryMode;
}

/** Build the `0verse` argv (everything after `uv run --frozen 0verse`). */
export function buildOverseArgv(
  mode: BinaryMode,
  target: string,
  opts: Pick<BinaryOptions, "format" | "backend" | "llm">,
  passthrough: string[] = [],
): string[] {
  const argv = [mode, target];
  if (opts.format) argv.push("--format", opts.format);
  if (opts.backend) argv.push("--backend", opts.backend);
  if (opts.llm) argv.push("--llm", opts.llm);
  argv.push(...passthrough);
  return argv;
}

/**
 * Friendly, actionable guidance printed when the launcher can't proceed. Kept
 * pure (returns the lines) so tests can assert on it without capturing stdout.
 */
export function setupGuidanceLines(reason: {
  uvMissing: boolean;
  overseDir: string | null;
}): string[] {
  const lines: string[] = [];
  lines.push("0sec binary analysis delegates to the 0verse engine, but it isn't ready yet.");
  lines.push("");
  if (reason.overseDir === null) {
    lines.push("  • Could not find the 0verse/ engine checkout next to the 0sec CLI.");
    lines.push("    Make sure the 0verse/ directory exists at the repo root.");
    lines.push("");
  }
  if (reason.uvMissing) {
    lines.push("  • `uv` (the Python package manager 0verse uses) is not on your PATH.");
    lines.push("    Install it with:");
    lines.push("      curl -LsSf https://astral.sh/uv/install.sh | sh");
    lines.push("");
  }
  lines.push("Then sync the engine's locked dependencies:");
  const dir = reason.overseDir ?? "0verse";
  lines.push(`  cd ${dir} && uv sync --frozen`);
  lines.push("");
  lines.push("Once that succeeds, re-run your command, e.g.:");
  lines.push("  0sec binary ./target --mode triage");
  return lines;
}

export interface BinaryResolution {
  ok: boolean;
  /** Non-zero when the launcher refuses to proceed. */
  exitCode: number;
  /** Present only on the failure path. */
  guidance?: string[];
  /** Present only on the success path. */
  overseDir?: string;
  argv?: string[];
}

/**
 * Pure precheck + argv assembly, split out from the subprocess so it is unit
 * testable without a real 0verse run. Returns either a failure (with guidance
 * + non-zero exit code) or the resolved engine dir and argv to spawn.
 */
export function resolveBinaryRun(
  target: string,
  opts: BinaryOptions,
  passthrough: string[],
  deps: {
    isUvAvailable: () => boolean;
    locateOverseDir: () => string | null;
  } = { isUvAvailable, locateOverseDir },
): BinaryResolution {
  const mode = normalizeMode(opts.mode);
  const overseDir = deps.locateOverseDir();
  const uvAvailable = deps.isUvAvailable();

  if (overseDir === null || !uvAvailable) {
    return {
      ok: false,
      exitCode: 1,
      guidance: setupGuidanceLines({ uvMissing: !uvAvailable, overseDir }),
    };
  }

  return {
    ok: true,
    exitCode: 0,
    overseDir,
    argv: buildOverseArgv(mode, target, opts, passthrough),
  };
}

export function registerBinaryCommand(program: Command): void {
  program
    .command("binary")
    .description(
      "Analyze a compiled binary by delegating to the in-repo 0verse engine (uv run --frozen 0verse)",
    )
    .argument("<target>", "Path to the target artifact (e.g. an ELF) to analyze")
    .argument("[passthrough...]", "Extra positional args forwarded verbatim to 0verse")
    .option("--mode <mode>", `0verse subcommand: ${BINARY_MODES.join("|")}`, "triage")
    .option("--format <format>", "Forward --format to 0verse (e.g. ndjson)")
    .option("--backend <backend>", "Forward --backend to 0verse (e.g. rizin, ghidra, angr)")
    .option("--llm <llm>", "Forward --llm to 0verse (e.g. codex, claude)")
    .allowUnknownOption(true)
    .action((target: string, passthrough: string[], opts: BinaryOptions) => {
      const resolution = resolveBinaryRun(target, opts, passthrough ?? []);

      if (!resolution.ok) {
        for (const line of resolution.guidance ?? []) {
          console.error(line);
        }
        process.exitCode = resolution.exitCode;
        return;
      }

      const overseDir = resolution.overseDir!;
      const argv = ["run", "--frozen", "0verse", ...(resolution.argv ?? [])];

      const child = spawn("uv", argv, {
        cwd: resolve(overseDir),
        stdio: "inherit",
        shell: false,
      });

      child.on("error", (err) => {
        console.error(
          `Failed to launch 0verse: ${err instanceof Error ? err.message : String(err)}`,
        );
        process.exitCode = 1;
      });

      child.on("exit", (code, signal) => {
        if (signal) {
          process.exitCode = 1;
          return;
        }
        process.exitCode = code ?? 1;
      });
    });
}
