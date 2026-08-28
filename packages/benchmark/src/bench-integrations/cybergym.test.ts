import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  createBenchIntegrationRegistry,
  createVariantExecutionFactory,
  runTournament,
} from "@0sec/core";

import {
  createCyberGymBenchIntegration,
  createCyberGymManifest,
  cyberGymBenchOracleEvaluatorAttestation,
} from "./cybergym.js";
import type {
  CyberGymTask,
  EngineRunner,
  Submitter,
} from "../cybergym-runner.js";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function makeTask(taskId: string): CyberGymTask {
  const taskDir = mkdtempSync(join(tmpdir(), "cybergym-bench-integration-"));
  roots.push(taskDir);
  const repoRoot = join(taskDir, "repo-vul");
  writeFileSync(join(taskDir, "candidate.poc"), "fixture");
  return {
    taskId,
    description: "Fixture memory-safety task",
    taskDir,
    repoRoot,
    difficulty: "level1",
  };
}

describe("CyberGym bench integration", () => {
  it("maps an official differential pass into the canonical verified receipt", async () => {
    let cleaned = 0;
    let observedSteps = 0;
    let observedSubmits = 0;
    const runEngine: EngineRunner = async (task, opts) => {
      observedSteps = opts.maxSteps;
      observedSubmits = opts.maxSubmits ?? 0;
      return {
        pocPath: join(task.taskDir, "candidate.poc"),
        model: "fixture-model",
        steps: 6,
        inputTokens: 20,
        outputTokens: 8,
        estimatedCostUsd: 0.3,
        craftPassed: true,
        craftFirstSubmitPassed: true,
      };
    };
    const submit: Submitter = async () => ({ verdict: "pass", raw: "unused" });
    const integration = createCyberGymBenchIntegration({
      generateTask: (taskId) => makeTask(taskId),
      cleanupTask: () => {
        cleaned++;
      },
      runEngine,
      submit,
      version: "fixture-v1",
    });
    const registry = createBenchIntegrationRegistry([integration]);
    const tournament = await runTournament(createCyberGymManifest(["arvo:10400"]), {
      variants: [{ id: "candidate", model: "requested-model", runtime: "api" }],
      executionFactory: createVariantExecutionFactory(registry, "cybergym"),
      maxTurns: 17,
    });

    expect(observedSteps).toBe(17);
    expect(observedSubmits).toBe(1);
    expect(cleaned).toBe(1);
    const attempt = tournament.variants[0].scorecard.cases[0].attempts[0];
    expect(attempt.status).toBe("verified");
    expect(attempt.totalTokens).toBe(28);
    expect(attempt.verification?.oracleId).toBe("cybergym-differential-v1");
    expect(attempt.execution).toMatchObject({
      integrationId: "cybergym",
      integrationVersion: "fixture-v1",
      model: "fixture-model",
      runtime: "api",
    });
  });

  it("maps an unavailable provider to inconclusive instead of a capability miss", async () => {
    const runEngine: EngineRunner = async () => ({
      model: "fixture-model",
      steps: 0,
      warnings: ["LLM UNAVAILABLE: provider rate limited"],
    });
    const submit: Submitter = async () => ({ verdict: "pass", raw: "unused" });
    const integration = createCyberGymBenchIntegration({
      generateTask: (taskId) => makeTask(taskId),
      cleanupTask: () => {},
      runEngine,
      submit,
    });
    const registry = createBenchIntegrationRegistry([integration]);
    const tournament = await runTournament(createCyberGymManifest(["arvo:10401"]), {
      variants: [{ id: "candidate" }],
      executionFactory: createVariantExecutionFactory(registry, "cybergym"),
    });
    expect(tournament.variants[0].scorecard.totals.inconclusive).toBe(1);
  });

  it("attests the suite oracle code and fixed configuration", () => {
    const attestation = cyberGymBenchOracleEvaluatorAttestation();
    expect(attestation.bundleDigest).toMatch(/^sha256:/);
    expect(attestation.codeDigest).toMatch(/^sha256:/);
    expect(attestation.configDigest).toMatch(/^sha256:/);
  });
});
