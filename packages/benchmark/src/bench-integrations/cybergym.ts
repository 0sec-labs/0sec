import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  parseManifest,
  withVariantFeatureFlags,
  type BenchIntegration,
  type BenchManifest,
  type BenchEvaluatorAttestation,
  type BenchOracle,
  type BenchOracleInput,
  type BenchOracleOutcome,
  type BenchScanResult,
  type BenchVariant,
  type TargetProvisioner,
} from "@0sec/core";

import {
  cleanupOwnedTaskDir,
  generateTask,
  runEngineDefault,
  runTaskOnce,
  submitToOracle,
  type CyberGymResult,
  type CyberGymTask,
  type EngineRunner,
  type Submitter,
} from "../cybergym-runner.js";

export const CYBERGYM_BENCH_ORACLE_ID = "cybergym-differential-v1";

const CYBERGYM_ORACLE_CONFIG = {
  schemaVersion: 1,
  oracle: CYBERGYM_BENCH_ORACLE_ID,
  version: 1,
};

function sha256(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

/** Hash the exact CyberGym oracle adapter and its fixed grading configuration. */
export function cyberGymBenchOracleEvaluatorAttestation(): BenchEvaluatorAttestation {
  const codeDigest = sha256(readFileSync(fileURLToPath(import.meta.url)));
  const configDigest = sha256(Buffer.from(`${JSON.stringify(CYBERGYM_ORACLE_CONFIG)}\n`));
  const bundleDigest = sha256(Buffer.from(`${JSON.stringify({ schemaVersion: 1, codeDigest, configDigest })}\n`));
  return { bundleDigest, codeDigest, configDigest };
}

function isCyberGymTask(value: unknown): value is CyberGymTask {
  return (
    value !== null &&
    typeof value === "object" &&
    "taskId" in value &&
    "taskDir" in value &&
    "repoRoot" in value &&
    "description" in value &&
    "difficulty" in value &&
    typeof value.taskId === "string" &&
    typeof value.taskDir === "string" &&
    typeof value.repoRoot === "string" &&
    typeof value.description === "string" &&
    typeof value.difficulty === "string"
  );
}

export interface CreateCyberGymManifestOptions {
  id?: string;
  difficulty?: string;
}

/** Build a canonical manifest from a pre-registered CyberGym task-id list. */
export function createCyberGymManifest(
  taskIds: readonly string[],
  opts: CreateCyberGymManifestOptions = {},
): BenchManifest {
  const difficulty = opts.difficulty ?? "level1";
  return parseManifest({
    id: opts.id ?? "cybergym-v1",
    cases: taskIds.map((taskId) => ({
      id: `cybergym-${taskId.replace(/[^a-zA-Z0-9_.-]/g, "-")}`,
      name: `CyberGym ${taskId}`,
      target: {
        kind: "suite-task",
        suite: "cybergym",
        taskRef: taskId,
        difficulty,
      },
      objective: { type: "suite-oracle", suite: "cybergym" },
      tags: ["cybergym", difficulty],
    })),
  });
}

/** Read a pre-registered task-id list, preserving its declared order. */
export function loadCyberGymTaskIds(subsetPath: string): string[] {
  const taskIds = readFileSync(subsetPath, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  const seen = new Set<string>();
  for (const taskId of taskIds) {
    if (seen.has(taskId)) throw new Error(`CyberGym subset contains duplicate task id: ${taskId}`);
    seen.add(taskId);
  }
  if (taskIds.length === 0) throw new Error(`CyberGym subset has no task ids: ${subsetPath}`);
  return taskIds;
}

export interface CyberGymTaskFactory {
  (taskId: string, difficulty: string, harnessDir: string): CyberGymTask;
}

export interface CyberGymBenchIntegrationOptions {
  harnessDir?: string;
  difficulty?: string;
  /** Strict pass@1 by default; an ensemble is an explicit separate variant. */
  bestOfN?: number;
  /** Official differential submissions per task; defaults to strict one-shot. */
  maxSubmits?: number;
  generateTask?: CyberGymTaskFactory;
  cleanupTask?: (taskDir: string) => void;
  runEngine?: EngineRunner;
  submit?: Submitter;
  version?: string;
}

/**
 * Trusted bridge from an official CyberGym differential verdict into the common
 * bench verdict vocabulary. It accepts only receipts created by this adapter.
 */
export class CyberGymBenchOracle implements BenchOracle {
  evaluate({ case: c, report }: BenchOracleInput): BenchOracleOutcome {
    if (report.error) {
      return {
        status: "inconclusive",
        confidence: null,
        notes: `[cybergym] task did not complete: ${report.error}`,
      };
    }
    if (
      c.target.kind !== "suite-task" ||
      c.target.suite !== "cybergym" ||
      c.objective.type !== "suite-oracle" ||
      c.objective.suite !== "cybergym"
    ) {
      return {
        status: "inconclusive",
        confidence: null,
        notes: "[cybergym] manifest case is not bound to the CyberGym suite oracle",
      };
    }
    const verification = report.verification;
    if (!verification || verification.oracleId !== CYBERGYM_BENCH_ORACLE_ID) {
      return {
        status: "inconclusive",
        confidence: null,
        notes: "[cybergym] integration did not return an official differential receipt",
      };
    }
    return {
      status: verification.status,
      confidence: verification.status === "verified" ? 0.95 : verification.status === "refuted" ? 0 : null,
      notes: verification.notes ?? "[cybergym] official differential verdict",
    };
  }
}

/** Convert a trusted CyberGym result into the generic runner's structural receipt. */
export function cyberGymResultToBenchScanResult(
  result: CyberGymResult,
  variant: Readonly<BenchVariant>,
): BenchScanResult {
  const benchmarkMeta = {
    attackTurns: result.steps,
    estimatedCostUsd: result.estimatedCostUsd ?? 0,
    inputTokens: result.inputTokens ?? 0,
    outputTokens: result.outputTokens ?? 0,
    totalTokens: (result.inputTokens ?? 0) + (result.outputTokens ?? 0),
    execution: {
      harnessId: variant.harnessId ?? "0sec-agentic",
      model: result.model,
      ...(variant.runtime ? { runtime: variant.runtime } : {}),
    },
  };
  if (result.verdict === "error" || result.costCeilingExceeded) {
    const reason = result.error ?? result.refusedReason ?? result.warnings?.at(-1) ?? "CyberGym returned an unscoreable result";
    return { benchmarkMeta, durationMs: result.durationMs, error: reason };
  }
  const status: "verified" | "refuted" = result.passed ? "verified" : "refuted";
  return {
    benchmarkMeta,
    durationMs: result.durationMs,
    verification: {
      oracleId: CYBERGYM_BENCH_ORACLE_ID,
      status,
      notes: result.passed
        ? `[cybergym] official differential pass${result.pocSha256 ? ` (${result.pocSha256})` : ""}`
        : `[cybergym] official differential fail${result.refusedReason ? `: ${result.refusedReason}` : ""}`,
      ...(result.pocSha256 ? { evidenceRef: `sha256:${result.pocSha256}` } : {}),
    },
  };
}

/**
 * Integrates CyberGym task generation, isolated task cleanup, and its official
 * differential oracle into the one core bench execution protocol.
 */
export function createCyberGymBenchIntegration(
  opts: CyberGymBenchIntegrationOptions = {},
): BenchIntegration {
  const harnessDir = opts.harnessDir ?? process.env.CYBERGYM_HARNESS ?? "/root/cybergym";
  const difficulty = opts.difficulty ?? "level1";
  const bestOfN = opts.bestOfN ?? 1;
  const maxSubmits = opts.maxSubmits ?? 1;
  if (!Number.isSafeInteger(bestOfN) || bestOfN < 1) {
    throw new Error("CyberGym bench bestOfN must be a positive integer");
  }
  if (!Number.isSafeInteger(maxSubmits) || maxSubmits < 1) {
    throw new Error("CyberGym bench maxSubmits must be a positive integer");
  }
  const makeTask = opts.generateTask ?? generateTask;
  const cleanupTask = opts.cleanupTask ?? cleanupOwnedTaskDir;
  const runEngine = opts.runEngine ?? runEngineDefault;
  const submit = opts.submit ?? submitToOracle;
  const oracle = new CyberGymBenchOracle();

  const provisioner: TargetProvisioner = {
    async up(c) {
      if (c.target.kind !== "suite-task" || c.target.suite !== "cybergym") {
        throw new Error(`CyberGym integration only provisions cybergym suite tasks; got ${c.id}`);
      }
      const task = makeTask(c.target.taskRef, c.target.difficulty ?? difficulty, harnessDir);
      return { target: task.repoRoot, handle: task };
    },
    async down(_c, provisioned) {
      if (isCyberGymTask(provisioned.handle)) cleanupTask(provisioned.handle.taskDir);
    },
  };

  return {
    id: "cybergym",
    version: opts.version ?? "1",
    evaluatorAttestation: cyberGymBenchOracleEvaluatorAttestation,
    createExecution(variant: Readonly<BenchVariant>) {
      return {
        provisioner,
        oracle,
        executionMetadata: {
          harnessId: variant.harnessId ?? "0sec-agentic",
          ...(variant.model ? { model: variant.model } : {}),
          ...(variant.runtime ? { runtime: variant.runtime } : {}),
        },
        scan: async (input) =>
          withVariantFeatureFlags(variant.featureFlags, async () => {
            const task = input.provisioned.handle;
            if (!isCyberGymTask(task)) {
              return { error: `CyberGym provisioner did not supply task state for ${input.case.id}` };
            }
            const result = await runTaskOnce(task, {
              runEngine,
              submit,
              ...(variant.model ? { model: variant.model } : {}),
              runtime: variant.runtime ?? "auto",
              maxSteps: input.maxTurns,
              bestOfN,
              maxSubmits,
              ...(variant.costCeilingUsdPerAttempt !== undefined
                ? { costCeilingUsd: variant.costCeilingUsdPerAttempt }
                : {}),
            });
            return cyberGymResultToBenchScanResult(result, variant);
          }),
      };
    },
  };
}
