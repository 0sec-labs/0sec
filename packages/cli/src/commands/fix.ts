import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import type { Command } from "commander";
import type { Finding } from "@0sec/shared";
import {
  createRuntime,
  runSourceFix,
  type NativeRuntime,
  type RuntimeType,
  type SourceFixResult,
} from "@0sec/core";
import { z } from "zod";
import { findingSchema, formatZodError } from "./schemas.js";

type FixRuntimeType = Extract<RuntimeType, "api">;

const FIX_RUNTIMES: Record<FixRuntimeType, true> = {
  api: true,
};

interface FixOptions {
  finding: string;
  verificationResult?: string;
  testCommand: string;
  runtime: string;
  model?: string;
  apiKey?: string;
  timeout: string;
  testTimeout: string;
  maxAttempts: string;
  apply?: boolean;
  output?: string;
}

function parsePositiveInteger(value: string, option: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${option} must be a positive integer`);
  }
  return parsed;
}

function isNativeRuntime(runtime: unknown): runtime is NativeRuntime {
  return typeof (runtime as Partial<NativeRuntime>)?.executeNative === "function";
}

async function loadFinding(path: string): Promise<Finding> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(resolve(path), "utf8"));
  } catch (error) {
    throw new Error(`failed to read finding JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  try {
    return findingSchema.parse(raw) as Finding;
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(formatZodError(error, "finding JSON"));
    }
    throw error;
  }
}

async function loadVerificationResult(path: string): Promise<Record<string, unknown>> {
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(resolve(path), "utf8"));
  } catch (error) {
    throw new Error(`failed to read verification result JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  const parsed = z.object({ status: z.string().min(1) }).passthrough().safeParse(raw);
  if (!parsed.success) {
    throw new Error(formatZodError(parsed.error, "verification result JSON"));
  }
  return parsed.data;
}

function selectedRuntime(value: string): FixRuntimeType {
  const resolved = value === "auto" ? "api" : value;
  if (!Object.hasOwn(FIX_RUNTIMES, resolved)) {
    throw new Error(`invalid --runtime '${value}'; supported: auto, ${Object.keys(FIX_RUNTIMES).join(", ")}`);
  }
  return resolved as FixRuntimeType;
}

function createFixRuntime(
  type: FixRuntimeType,
  opts: { timeout: number; model?: string; apiKey?: string },
): NativeRuntime {
  const runtime = createRuntime({
    type,
    timeout: opts.timeout,
    model: opts.model,
    apiKey: opts.apiKey,
  });
  if (!isNativeRuntime(runtime)) {
    throw new Error(`runtime '${type}' does not support structured source remediation`);
  }
  return runtime;
}

async function writePatch(path: string, patch: string): Promise<void> {
  const resolved = resolve(path);
  await mkdir(dirname(resolved), { recursive: true });
  await writeFile(resolved, `${patch}\n`, "utf8");
}

function exitCodeFor(result: SourceFixResult): number {
  switch (result.status) {
    case "validated_candidate":
    case "applied_and_retested":
      return 0;
    case "not_fixed":
      return 1;
    case "precondition_failed":
    case "error":
      return 2;
  }
}

export function registerFixCommand(program: Command): void {
  program
    .command("fix")
    .description("Generate, source-retest, and optionally apply a scoped fix for one reproduced source finding")
    .argument("<repo>", "Clean local Git worktree containing the affected source file")
    .requiredOption("--finding <path>", "Path to finding JSON with verificationSpec")
    .option("--verification-result <path>", "Optional verification_result JSON from `0sec verify`; required when the finding does not already carry one")
    .requiredOption("--test-command <command>", "Explicit regression command to run in the isolated candidate worktree")
    .option("--runtime <runtime>", "Fix runtime: auto or api", "auto")
    .option("--model <model>", "Model identifier for the selected runtime")
    .option("--api-key <key>", "API key for the selected runtime")
    .option("--timeout <ms>", "Per-model-call timeout in milliseconds", "600000")
    .option("--test-timeout <ms>", "Regression-command timeout in milliseconds", "300000")
    .option("--max-attempts <n>", "Maximum candidate patches; capped at 3", "3")
    .option("--apply", "Apply only a patch that passed isolated source recheck and regression command", false)
    .option("--output <path>", "Write the validated apply_patch DSL to this path")
    .action(async (repo: string, opts: FixOptions) => {
      const runtimeType = selectedRuntime(opts.runtime);
      const timeout = parsePositiveInteger(opts.timeout, "--timeout");
      const testTimeoutMs = parsePositiveInteger(opts.testTimeout, "--test-timeout");
      const maxAttempts = parsePositiveInteger(opts.maxAttempts, "--max-attempts");
      const finding = await loadFinding(opts.finding);
      if (opts.verificationResult) {
        Object.assign(finding as unknown as Record<string, unknown>, {
          verification_result: await loadVerificationResult(opts.verificationResult),
        });
      }
      const runtime = createFixRuntime(runtimeType, {
        timeout,
        model: opts.model,
        apiKey: opts.apiKey,
      });
      if (!(await runtime.isAvailable())) {
        throw new Error(`runtime '${runtimeType}' is not available`);
      }

      const result = await runSourceFix({
        repoRoot: resolve(repo),
        finding,
        runtime,
        testCommand: opts.testCommand,
        apply: opts.apply,
        maxAttempts,
        testTimeoutMs,
      });

      if (opts.output && result.patch) {
        await writePatch(opts.output, result.patch);
      }

      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      process.exitCode = exitCodeFor(result);
    });
}
