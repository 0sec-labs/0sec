/**
 * kernel/syz-check-validator.ts
 *
 * Concrete opt-in semantic syzkaller validation adapter — the `syz-check`
 * follow-up the spec-gen.ts file header promises. Builds on the existing
 * structural {@link SyzlangValidator} contract: accepts a syzlang spec string,
 * writes it to an isolated temp file, invokes a configured syz-check binary
 * (with argument arrays, never shell interpolation), and returns a
 * discriminated result.
 *
 * Structural validation is a mandatory prerequisite — if the spec fails
 * structural checks the semantic validator never shells out.
 *
 * This is a VALIDATION TOOL ONLY. It cannot turn a candidate into a confirmed
 * finding, trigger a VM runner, or produce a disclosure bundle.
 *
 * The existing verifier opts in by passing this validator as the `validator`
 * option to {@link generateSyzlangSpec} (from spec-gen.ts) without changing
 * its confirmation semantics — the loop continues to treat any
 * `valid: false` result as a repair signal.
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { structurallyValidateSyzlang } from "./spec-gen.js";
import type { SyzlangValidationError, SyzlangValidationResult, SyzlangValidator } from "./spec-gen.js";

// ── Result types ──

/**
 * Discriminated semantic validation results. Every variant satisfies
 * {@link SyzlangValidationResult} structurally (`valid` + `errors`), so it
 * is a valid return for a {@link SyzlangValidator}.
 *
 * - `"valid"` — syz-check compiled/validated the spec successfully.
 * - `"invalid"` — syz-check rejected the spec as invalid.
 * - `"toolchain-unavailable"` — the configured syz-check binary could not be
 *   found (ENOENT) or executed.
 * - `"execution-error"` — the binary ran but exited abnormally (signal,
 *   non-zero exit unrelated to syz-check rejection).
 */
export type SyzkallerSemanticResult =
  | { status: "valid"; valid: true; errors: [] }
  | { status: "invalid"; valid: false; errors: SyzlangValidationError[] }
  | { status: "toolchain-unavailable"; valid: false; errors: [{ line: 0; message: string }] }
  | { status: "execution-error"; valid: false; errors: [{ line: 0; message: string }] };

/**
 * Narrow a {@link SyzlangValidationResult} to {@link SyzkallerSemanticResult}
 * when you know it came from the semantic validator. Throws if the result
 * does not carry a `status` discriminant.
 */
export function assertSemanticResult(
  r: SyzlangValidationResult,
): asserts r is SyzkallerSemanticResult {
  if (!("status" in r)) {
    throw new Error(
      "result is not a SyzkallerSemanticResult (missing `status` discriminant)",
    );
  }
}

/**
 * Default status message mapped from `status` for display use.
 */
export function statusMessage(result: SyzkallerSemanticResult): string {
  switch (result.status) {
    case "valid":
      return "syz-check: spec is valid";
    case "invalid":
      return result.errors.length > 0
        ? result.errors[0].message
        : "syz-check: spec rejected (no error detail)";
    case "toolchain-unavailable":
      return `syz-check binary unavailable: ${result.errors[0].message}`;
    case "execution-error":
      return `syz-check execution error: ${result.errors[0].message}`;
  }
}

// ── Process executor seam (injectable for tests) ──

/** The structured result a {@link SyzProcessExecutor} returns. */
export interface SyzExecResult {
  stdout: string;
  stderr: string;
  status: number | null;
}

/**
 * A synchronous process-execution callback. Returns a structured result
 * unconditionally — throws ONLY when the binary itself could not be
 * launched (ENOENT, EACCES). Non-zero exit codes are reflected in `status`,
 * not thrown.
 *
 * Tests substitute a pure fake that returns the desired {@link SyzExecResult}
 * without spawning a real process.
 */
export type SyzProcessExecutor = (
  file: string,
  args: string[],
  options: { cwd: string; encoding: BufferEncoding; maxBuffer: number; timeout: number },
) => SyzExecResult;

/**
 * Default process executor: shells real `syz-check` (or any configured
 * binary) via {@link spawnSync}.
 *
 * Uses argument arrays exclusively — never shell interpolation.
 * Throws only on ENOENT/EACCES (binary cannot be launched); non-zero exit
 * codes are returned in the result's `status` field.
 */
export const defaultSyzProcessExecutor: SyzProcessExecutor = (file, args, options) => {
  const result = spawnSync(file, args, {
    cwd: options.cwd,
    encoding: options.encoding,
    maxBuffer: options.maxBuffer,
    timeout: options.timeout,
    stdio: ["ignore", "pipe", "pipe"],
  });

  // spawnSync sets .error on ENOENT, EACCES, etc.
  if (result.error) {
    throw result.error;
  }

  return {
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : "",
    status: result.status,
  };
};

// ── Temp-file lifecycle ──

interface TempSpec {
  dir: string;
  path: string;
}

function createTempSpec(spec: string): TempSpec {
  const dir = mkdtempSync(join(tmpdir(), "syz-check-"));
  const path = join(dir, "input.txt");
  writeFileSync(path, spec, "utf-8");
  return { dir, path };
}

function destroyTempSpec(tmp: TempSpec): void {
  try {
    rmSync(tmp.dir, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup — temp dirs will be reaped by the OS.
  }
}

/**
 * Try to parse syz-check's stderr for structured error lines.
 * syz-check emits lines like:
 *   foo.txt:5: undefined type "foo"
 *   foo.txt:12: unknown field bar
 */
const SYZ_ERROR_LINE = /^.*?:(\d+):\s*(.+)$/;

function parseSyzErrors(stderr: string): SyzlangValidationError[] {
  const errors: SyzlangValidationError[] = [];
  for (const line of stderr.split("\n")) {
    const m = line.match(SYZ_ERROR_LINE);
    if (m) {
      errors.push({ line: Number(m[1]), message: m[2].trim() });
    }
  }
  return errors;
}

// ── Semantic validator ──

/**
 * Options for {@link createSyzCheckValidator}.
 */
export interface SyzkallerSemanticOptions {
  /**
   * Path to the syz-check (or equivalent) binary.
   * Default: `"syz-check"` (resolved via `PATH`).
   */
  binary?: string;
  /**
   * Extra argument array appended to the invocation.
   * The temp-file path is always the final argument.
   */
  extraArgs?: string[];
  /**
   * Synchronous process executor. Defaults to {@link defaultSyzProcessExecutor}
   * which wraps `spawnSync`. Tests inject a fake here.
   */
  executor?: SyzProcessExecutor;
  /**
   * Timeout (milliseconds) for each syz-check invocation. Default 60_000.
   */
  timeoutMs?: number;
  /**
   * Max buffer for stdout/stderr. Default 1 MiB.
   */
  maxBuffer?: number;
}

const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_BUFFER = 1024 * 1024;

/**
 * Create a {@link SyzlangValidator} that runs syz-check through a configured
 * binary.
 *
 * The returned validator:
 *   1. Runs structural validation first (no shell-out).
 *   2. Only if structural passes, writes the spec to an isolated temp file.
 *   3. Invokes the configured binary with argument arrays (never shell
 *      interpolation), passing the temp-file path as the final arg.
 *   4. Maps the outcome to a {@link SyzkallerSemanticResult}.
 *   5. Cleans up the temp file.
 *
 * This is a pure validation tool. It does not confirm findings, run VMs, or
 * produce disclosures.
 */
export function createSyzCheckValidator(
  opts: SyzkallerSemanticOptions = {},
): SyzlangValidator {
  const binary = opts.binary ?? "syz-check";
  const extraArgs = opts.extraArgs ?? [];
  const exec = opts.executor ?? defaultSyzProcessExecutor;
  const timeout = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBuffer = opts.maxBuffer ?? DEFAULT_MAX_BUFFER;

  return (spec: string): SyzkallerSemanticResult => {
    // Step 1: structural prerequisite — never shells out.
    const structural = structurallyValidateSyzlang(spec);
    if (!structural.valid) {
      return { status: "invalid", valid: false, errors: structural.errors };
    }

    // Step 2: write spec to isolated temp file.
    const tmp = createTempSpec(spec);
    try {
      // Step 3: invoke binary with argument arrays — no shell interpolation.
      const args = [...extraArgs, tmp.path];
      const result = exec(binary, args, {
        cwd: tmp.dir,
        encoding: "utf-8",
        maxBuffer,
        timeout,
      });

      // syz-check exits 0 on success (spec is semantically valid).
      if (result.status === 0) {
        return { status: "valid", valid: true, errors: [] };
      }

      // Non-zero exit: try to parse stderr as structured rejection errors.
      const errors = parseSyzErrors(result.stderr);
      if (errors.length === 0) {
        // Stderr had no parseable error lines — wrap it in a single message.
        errors.push({
          line: 0,
          message:
            `syz-check rejected spec (exit ${result.status}): ${result.stderr.slice(0, 400).trim() || "no detail"}`,
        });
      }
      return { status: "invalid", valid: false, errors };
    } catch (err: unknown) {
      // Step 4: map launch/IO failures to the correct discriminant.
      const nodeErr = err as NodeJS.ErrnoException & {
        status?: number | null;
        signal?: string;
      };

      if (nodeErr.code === "ENOENT" || nodeErr.code === "EACCES") {
        return {
          status: "toolchain-unavailable",
          valid: false,
          errors: [{ line: 0, message: `cannot execute ${binary}: ${nodeErr.message}` }],
        };
      }

      if (nodeErr.signal) {
        return {
          status: "execution-error",
          valid: false,
          errors: [{ line: 0, message: `syz-check terminated by signal: ${nodeErr.signal}` }],
        };
      }

      return {
        status: "execution-error",
        valid: false,
        errors: [{ line: 0, message: `syz-check invocation failed: ${nodeErr.message}` }],
      };
    } finally {
      // Step 5: cleanup temp files.
      destroyTempSpec(tmp);
    }
  };
}