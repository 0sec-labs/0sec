import { randomUUID } from "node:crypto";
import { join, resolve } from "node:path";
import { canonicalEvolutionJson, parseEvolutionConfig } from "./config.js";
import { publishEvolutionArtifact, readEvolutionArtifact } from "./artifacts.js";
import { evaluateEvolutionCandidate } from "./evaluation.js";
import {
  createEvolutionCandidate, evolutionDigest, loadEvolutionRegistry, pinEvolutionVersion,
  promoteEvolutionVersion, recordEvolutionVersion, rollbackEvolutionVersion,
  snapshotEvolutionSource, startEvolutionCanary, verifyEvolutionSnapshot,
} from "./registry.js";
import { EvolutionGenerationError, proposeEvolutionEdits } from "./rewrite.js";
import { createDockerEvolutionSandbox, resolveEvolutionImage } from "./sandbox.js";
import { acquireEvolutionController } from "./controller-lock.js";
import type {
  EvolutionAttempt, EvolutionConfig, EvolutionDependencies, EvolutionEvaluation,
  EvolutionExecution, EvolutionProposal, EvolutionRunResult, EvolutionVersion,
} from "./types.js";

/** Autonomous iterations learn only from development observations, never held-out answers. */
function developmentFeedback(evaluation: EvolutionEvaluation, proposal: EvolutionProposal): string {
  const summarize = (attempt: EvolutionAttempt) => ({
    caseId: attempt.caseId,
    repeat: attempt.repeat,
    matched: attempt.matched,
    inconclusive: attempt.inconclusive,
    stdout: attempt.execution.stdout.slice(0, 4096),
    stderr: attempt.execution.stderr.slice(0, 2048),
  });
  return canonicalEvolutionJson({
    previousProposal: { rationale: proposal.rationale, edits: proposal.edits },
    baseline: evaluation.attempts.baseline.filter((entry) => entry.lane === "development").map(summarize),
    candidate: evaluation.attempts.candidate.filter((entry) => entry.lane === "development").map(summarize),
  });
}

export async function runEvolution(rawConfig: EvolutionConfig, deps: EvolutionDependencies = {}): Promise<EvolutionRunResult> {
  const config = parseEvolutionConfig(rawConfig);
  if (!config.allowModelSourceAccess) throw new Error("source rewriting requires explicit allowModelSourceAccess consent");
  if (!deps.sandbox) config.image = await resolveEvolutionImage(config.image);
  const release = acquireEvolutionController(config.storePath);
  try {
    return await runEvolutionPass(config, deps);
  } finally {
    release();
  }
}

async function runEvolutionPass(config: EvolutionConfig, deps: EvolutionDependencies): Promise<EvolutionRunResult> {
  const configDigest = evolutionDigest(config);
  publishEvolutionArtifact(join(config.storePath, "configs", `${configDigest.replace(/^sha256:/, "")}.json`), config);
  let registry = loadEvolutionRegistry(config.storePath);
  if (registry.canaryId !== null) {
    // A previous controller may have stopped during rollout. No unproven canary becomes active.
    await rollbackEvolutionVersion(config.storePath, registry.canaryId, "interrupted canary recovered before next evolution pass");
    registry = loadEvolutionRegistry(config.storePath);
  }
  if (registry.activeId === null) {
    const snapshot = await snapshotEvolutionSource(config);
    await recordEvolutionVersion(config.storePath, {
      schemaVersion: 1,
      id: snapshot.id,
      kind: config.kind,
      snapshot,
      parentId: null,
      createdAt: new Date().toISOString(),
      configDigest,
      receiptDigest: null,
      status: "baseline",
    });
    registry = loadEvolutionRegistry(config.storePath);
  }
  let active = registry.versions.find((version) => version.id === registry.activeId);
  if (!active) throw new Error("evolution registry has no active baseline");
  if (active.kind !== config.kind) throw new Error("an evolution store cannot change artifact kind; use a separate store");
  verifyEvolutionSnapshot(active.snapshot);
  const result: EvolutionRunResult = {
    iterations: [], activeVersionId: active.id, modelCostUsd: 0, evaluationCostUsd: 0,
  };
  let feedback = "No previous candidate. Improve the stated objective using development inputs; hidden evaluation is independent.";
  const runId = randomUUID();
  const sandbox = deps.sandbox ?? createDockerEvolutionSandbox();
  const budgetedSandbox: NonNullable<EvolutionDependencies["sandbox"]> = async (request) => {
    const reserve = config.timeoutMs / 1000 * config.computeUsdPerSecond;
    if (result.evaluationCostUsd + reserve > config.maxEvaluationCostUsd) throw new Error("run evaluation budget cannot cover another execution");
    const execution = await sandbox(request);
    if (!Number.isFinite(execution.durationMs) || execution.durationMs < 0) throw new Error("sandbox returned invalid elapsed time");
    result.evaluationCostUsd += execution.durationMs / 1000 * config.computeUsdPerSecond;
    if (result.evaluationCostUsd > config.maxEvaluationCostUsd) throw new Error("run evaluation cost ceiling exceeded");
    return execution;
  };
  const evaluationDeps = { ...deps, sandbox: budgetedSandbox };
  try {
    for (let iteration = 0; iteration < config.maxIterations; iteration++) {
      deps.signal?.throwIfAborted();
      const remaining = config.maxModelCostUsd - result.modelCostUsd;
      if (remaining <= 0) break;
      const proposal = await proposeEvolutionEdits(active.snapshot, { ...config, maxModelCostUsd: remaining }, feedback, deps);
      if (!Number.isFinite(proposal.modelCostUsd) || proposal.modelCostUsd < 0) throw new Error("invalid model cost receipt");
      result.modelCostUsd += proposal.modelCostUsd;
      if (result.modelCostUsd > config.maxModelCostUsd) throw new Error("source rewriting model cost ceiling exceeded");
      if (proposal.edits.length === 0) {
        deps.log?.("[evolve] model proposed no further changes");
        break;
      }
      const candidate = await createEvolutionCandidate(active.snapshot, proposal, config);
      deps.log?.(`[evolve] evaluating source version ${candidate.id} against ${active.id}`);
      const evaluation = await evaluateEvolutionCandidate(active.snapshot, candidate, config, evaluationDeps);
      feedback = developmentFeedback(evaluation, proposal);
      const receiptPath = join(config.storePath, "receipts", `${candidate.id}.json`);
      publishEvolutionArtifact(receiptPath, evaluation);
      const version: EvolutionVersion = {
        schemaVersion: 1,
        id: candidate.id,
        kind: config.kind,
        snapshot: candidate,
        parentId: active.id,
        createdAt: new Date().toISOString(),
        configDigest,
        receiptDigest: evaluation.receiptDigest,
        status: "candidate",
      };
      await recordEvolutionVersion(config.storePath, version);
      const item: EvolutionRunResult["iterations"][number] = {
        candidateId: candidate.id,
        rationale: proposal.rationale,
        decision: evaluation.decision,
        state: "rejected",
        receiptPath,
      };
      result.iterations.push(item);
      if (evaluation.decision.status === "rejected") continue;
      if (!config.autoPromote) {
        item.state = "awaiting_approval";
        continue;
      }
      await startEvolutionCanary(config.storePath, candidate.id, active.id);
      try {
        const canaryPassed = await evaluateCanaryTrials(config, active, version, evaluationDeps);
        if (!canaryPassed) {
          await rollbackEvolutionVersion(config.storePath, candidate.id, "independent canary evaluation regressed");
          item.state = "rolled_back";
          continue;
        }
        await promoteEvolutionVersion(config.storePath, candidate.id, active.id);
        item.state = "promoted";
        active = { ...version, status: "active" };
        result.activeVersionId = active.id;
      } catch (error) {
        await rollbackEvolutionVersion(config.storePath, candidate.id, `canary interrupted: ${error instanceof Error ? error.message : String(error)}`);
        item.state = "rolled_back";
        throw error;
      }
    }
    publishEvolutionArtifact(join(config.storePath, "history", `${runId}.json`), { schemaVersion: 1, configDigest, completedAt: new Date().toISOString(), result });
    return result;
  } catch (error) {
    if (error instanceof EvolutionGenerationError) result.modelCostUsd += error.modelCostUsd;
    publishEvolutionArtifact(join(config.storePath, "history", `${runId}.json`), {
      schemaVersion: 1, configDigest, completedAt: new Date().toISOString(), result,
      error: error instanceof Error ? error.message : String(error),
      modelCostMeteringIncomplete: error instanceof EvolutionGenerationError && error.meteringIncomplete,
    });
    throw error;
  }
}

async function evaluateCanaryTrials(
  config: EvolutionConfig,
  baseline: EvolutionVersion,
  candidate: EvolutionVersion,
  deps: EvolutionDependencies,
): Promise<boolean> {
  for (let trial = 0; trial < config.canaryTrials; trial++) {
    deps.signal?.throwIfAborted();
    const receipt = await evaluateEvolutionCandidate(baseline.snapshot, candidate.snapshot, config, deps);
    publishEvolutionArtifact(join(config.storePath, "receipts", `${candidate.id}.canary-${trial}.json`), receipt);
    if (receipt.decision.status === "rejected") return false;
  }
  return true;
}

/** Explicit operator approval evaluates the exact staged bytes, without regenerating a candidate. */
export async function approveEvolutionCandidate(
  storePath: string,
  versionId: string,
  deps: EvolutionDependencies = {},
): Promise<{ versionId: string; evaluationCostUsd: number }> {
  const root = resolve(storePath);
  const release = acquireEvolutionController(root);
  try {
    const registry = loadEvolutionRegistry(root);
    if (registry.canaryId !== null) throw new Error("another canary is already pending");
    const candidate = registry.versions.find((version) => version.id === versionId);
    const baseline = registry.versions.find((version) => version.id === registry.activeId);
    if (!candidate || candidate.status !== "candidate") throw new Error("approval requires a staged candidate");
    if (!baseline || candidate.parentId !== baseline.id) throw new Error("candidate baseline is no longer active; evaluate a fresh candidate");
    const stored = readEvolutionArtifact(join(root, "configs", `${candidate.configDigest.replace(/^sha256:/, "")}.json`));
    if (evolutionDigest(stored) !== candidate.configDigest) throw new Error("candidate configuration digest mismatch");
    const config = parseEvolutionConfig(stored);
    if (config.storePath !== root) throw new Error("candidate belongs to a different store");
    if (!deps.sandbox && !/^sha256:[a-f0-9]{64}$/.test(config.image)) throw new Error("candidate is missing an immutable sandbox image identity");
    const sandbox = deps.sandbox ?? createDockerEvolutionSandbox();
    let evaluationCostUsd = 0;
    const budgetedSandbox: NonNullable<EvolutionDependencies["sandbox"]> = async (request) => {
      const reserve = config.timeoutMs / 1000 * config.computeUsdPerSecond;
      if (evaluationCostUsd + reserve > config.maxEvaluationCostUsd) throw new Error("approval evaluation budget cannot cover another execution");
      const execution = await sandbox(request);
      if (!Number.isFinite(execution.durationMs) || execution.durationMs < 0) throw new Error("sandbox returned invalid elapsed time");
      evaluationCostUsd += execution.durationMs / 1000 * config.computeUsdPerSecond;
      if (evaluationCostUsd > config.maxEvaluationCostUsd) throw new Error("approval evaluation cost ceiling exceeded");
      return execution;
    };
    await startEvolutionCanary(root, candidate.id, baseline.id, deps.signal);
    let approved = false;
    try {
      if (!await evaluateCanaryTrials(config, baseline, candidate, { ...deps, sandbox: budgetedSandbox })) {
        throw new Error("independent canary evaluation regressed");
      }
      await promoteEvolutionVersion(root, candidate.id, baseline.id, deps.signal);
      approved = true;
      return { versionId: candidate.id, evaluationCostUsd };
    } catch (error) {
      await rollbackEvolutionVersion(root, candidate.id, `operator approval failed: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    } finally {
      publishEvolutionArtifact(join(root, "history", `${randomUUID()}.json`), {
        schemaVersion: 1, kind: "operator-approval", versionId: candidate.id,
        configDigest: candidate.configDigest, completedAt: new Date().toISOString(),
        approved, evaluationCostUsd,
      });
    }
  } finally {
    release();
  }
}

/** Launch a future worker from a durable version pin; subsequent calls reuse the same code and input. */
export async function executeEvolutionVersion(
  rawConfig: EvolutionConfig,
  runId: string,
  input: unknown,
  deps: EvolutionDependencies = {},
): Promise<{ versionId: string; execution: EvolutionExecution }> {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(runId)) throw new Error("invalid evolution run id");
  canonicalEvolutionJson(input);
  const requested = parseEvolutionConfig(rawConfig);
  const version = await pinEvolutionVersion(requested.storePath, runId, deps.signal, deps.parentRunId);
  const stored = readEvolutionArtifact(join(requested.storePath, "configs", `${version.configDigest.replace(/^sha256:/, "")}.json`));
  if (evolutionDigest(stored) !== version.configDigest) throw new Error("pinned worker configuration digest mismatch");
  const config = parseEvolutionConfig(stored);
  if (config.storePath !== requested.storePath) throw new Error("pinned worker belongs to a different store");
  if (canonicalEvolutionJson(requested.command) !== canonicalEvolutionJson(config.command)
    || canonicalEvolutionJson(requested.buildCommand ?? null) !== canonicalEvolutionJson(config.buildCommand ?? null)) {
    throw new Error("requested execution command differs from the pinned worker contract");
  }
  if (!deps.sandbox && !/^sha256:[a-f0-9]{64}$/.test(config.image)) {
    throw new Error("pinned worker is missing an immutable sandbox image identity");
  }
  publishEvolutionArtifact(join(config.storePath, "inputs", `${runId}.json`), { versionId: version.id, inputDigest: evolutionDigest(input) });
  verifyEvolutionSnapshot(version.snapshot);
  const execution = await (deps.sandbox ?? createDockerEvolutionSandbox())({ snapshot: version.snapshot, config, input, signal: deps.signal });
  verifyEvolutionSnapshot(version.snapshot);
  if (execution.exitCode === 0 && !execution.error && !execution.timedOut) {
    try {
      const parsed = JSON.parse(execution.stdout);
      const observed = canonicalEvolutionJson(parsed);
      const inputJson = canonicalEvolutionJson(input);
      const knownCase = config.cases.find((entry) => canonicalEvolutionJson(entry.input) === inputJson);
      if (knownCase && observed !== canonicalEvolutionJson(knownCase.expected)) {
        execution.error = `worker regressed independently specified case ${knownCase.id}`;
      } else if (deps.validateExecutionOutput) {
        deps.validateExecutionOutput(parsed);
      }
    } catch (err) {
      execution.error = err instanceof Error ? err.message : "worker output validation failed";
    }
  }
  const record = { versionId: version.id, inputDigest: evolutionDigest(input), execution };
  publishEvolutionArtifact(join(config.storePath, "executions", `${runId}-${randomUUID()}.json`), record);
  if (!deps.signal?.aborted && (execution.exitCode !== 0 || execution.error || execution.timedOut) && version.parentId !== null) {
    const latest = loadEvolutionRegistry(config.storePath);
    if (latest.activeId === version.id) await rollbackEvolutionVersion(config.storePath, version.id, "future worker execution failed; restoring last accepted parent");
  }
  return { versionId: version.id, execution };
}
