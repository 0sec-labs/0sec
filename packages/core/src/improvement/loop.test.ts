import { chmodSync, mkdtempSync, mkdirSync, readdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseEvolutionConfig } from "./config.js";
import { publishEvolutionArtifact } from "./artifacts.js";
import { evaluateEvolutionCandidate } from "./evaluation.js";
import {
  createEvolutionCandidate, evolutionDigest, loadEvolutionRegistry,
  recordEvolutionVersion, snapshotEvolutionSource,
} from "./registry.js";
import { tryRecoverPreviousFeedback } from "./loop.js";
import type { EvolutionConfig, EvolutionEvaluation, EvolutionProposal, EvolutionSandbox, EvolutionVersion } from "./types.js";

let root: string;
let config: EvolutionConfig;
const original = 'console.log("baseline");\n';
const improved = 'console.log("improved");\n';

function makeWritable(path: string): void {
  chmodSync(path, 0o700);
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.isDirectory()) makeWritable(join(path, entry.name));
  }
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "0sec-feedback-"));
  const sourceRoot = join(root, "source");
  mkdirSync(join(sourceRoot, "src"), { recursive: true });
  writeFileSync(join(sourceRoot, "src/worker.cjs"), original);
  config = parseEvolutionConfig({
    schemaVersion: 1, sourceRoot, storePath: join(root, "store"),
    image: "node:22-alpine", sourcePaths: ["src"], editablePaths: ["src"],
    command: ["node", "src/worker.cjs"], objective: "Detect unsafe inputs without false positives.",
    computeUsdPerSecond: 0.001, repeats: 2, canaryTrials: 2,
    promotionPolicy: { minimumCases: 3, maximumCostMultiplier: 10 },
    cases: ["development", "held-out", "negative-control"].flatMap((lane, group) =>
      [0, 1, 2].map((index) => ({
        id: `${lane}-${index}`, lane,
        input: { index: group * 3 + index, unsafe: group !== 2 },
        expected: { unsafe: group !== 2 },
      }))),
  });
});

afterEach(() => {
  makeWritable(root);
  rmSync(root, { recursive: true, force: true });
});

/** Deterministic sandbox that varies output by candidate identity. */
function makeSandbox(candidateId: string): EvolutionSandbox {
  return async ({ snapshot, input }) => {
    const value = input as { index: number; unsafe: boolean };
    const isCandidate = snapshot.id === candidateId;
    // Candidate always matches development cases; baseline matches some
    return {
      exitCode: 0,
      stdout: JSON.stringify({ unsafe: value.unsafe && (isCandidate || value.index % 3 !== 0) }),
      stderr: "", durationMs: 1, timedOut: false,
    };
  };
}

/** Seed a store with a baseline + rejected candidate (with stored proposal, receipt, and registry events). */
async function seedRejectedCandidate(cfg: EvolutionConfig) {
  const configDigest = evolutionDigest(cfg);
  const snapshot = await snapshotEvolutionSource(cfg);
  const baseline: EvolutionVersion = {
    schemaVersion: 1, id: snapshot.id, kind: "source", snapshot,
    parentId: null, createdAt: new Date().toISOString(),
    configDigest, receiptDigest: null, status: "baseline",
  };
  await recordEvolutionVersion(cfg.storePath, baseline, cfg);

  const file = snapshot.files.find((f) => f.path === "src/worker.cjs")!;
  const candidate = await createEvolutionCandidate(snapshot, {
    rationale: "Improve detection logic", modelCostUsd: 0.01,
    edits: [{ path: "src/worker.cjs", beforeDigest: file.digest, content: improved }],
  }, cfg);
  const evaluation = await evaluateEvolutionCandidate(snapshot, candidate, cfg, {
    sandbox: makeSandbox(candidate.id),
  });
  const proposal: EvolutionProposal = {
    rationale: "Improve detection logic", modelCostUsd: 0.01,
    edits: [{ path: "src/worker.cjs", beforeDigest: file.digest, content: improved }],
  };
  const version: EvolutionVersion = {
    schemaVersion: 1, id: candidate.id, kind: "source", snapshot: candidate,
    parentId: baseline.id, createdAt: new Date().toISOString(),
    configDigest, receiptDigest: evaluation.receiptDigest, status: "candidate",
    proposalDigest: evolutionDigest(proposal),
  };
  // recordEvolutionVersion publishes the config + evaluation receipt via publishEvolutionArtifact.
  await recordEvolutionVersion(cfg.storePath, version, undefined, evaluation);
  // Store the proposal alongside for feedback recovery
  publishEvolutionArtifact(join(cfg.storePath, "receipts", `${candidate.id}.proposal.json`), proposal);
  return { baseline, candidate, evaluation, proposal, configDigest };
}

// ---------------------------------------------------------------------------
// Cross-invocation feedback recovery
// ---------------------------------------------------------------------------

describe("cross-invocation feedback recovery", () => {
  it("recovers feedback from the most recent compatible rejected candidate", async () => {
    const { proposal } = await seedRejectedCandidate(config);
    const registry = loadEvolutionRegistry(config.storePath);
    const feedback = tryRecoverPreviousFeedback(config, registry, config.storePath);
    expect(feedback).not.toBeNull();

    const parsed = JSON.parse(feedback!);
    expect(parsed).toHaveProperty("previousProposal");
    expect(parsed.previousProposal.rationale).toBe(proposal.rationale);
    expect(parsed.previousProposal.edits).toEqual(proposal.edits);
    expect(parsed).toHaveProperty("baseline");
    expect(parsed).toHaveProperty("candidate");

    // Baseline and candidate must only contain development-lane attempts
    for (const lane of ["baseline", "candidate"] as const) {
      const laneIds = new Set(parsed[lane].map((a: { caseId: string }) => a.caseId));
      for (const id of laneIds) {
        expect(id.startsWith("development-")).toBe(true);
      }
    }
  });

  it("returns null when no candidates exist in the registry", () => {
    const registry = loadEvolutionRegistry(config.storePath);
    expect(tryRecoverPreviousFeedback(config, registry, config.storePath)).toBeNull();
  });

  it("returns null when the only versions are baselines", async () => {
    const configDigest = evolutionDigest(config);
    const snapshot = await snapshotEvolutionSource(config);
    const baseline: EvolutionVersion = {
      schemaVersion: 1, id: snapshot.id, kind: "source", snapshot,
      parentId: null, createdAt: new Date().toISOString(),
      configDigest, receiptDigest: null, status: "baseline",
    };
    await recordEvolutionVersion(config.storePath, baseline, config);
    const registry = loadEvolutionRegistry(config.storePath);
    expect(tryRecoverPreviousFeedback(config, registry, config.storePath)).toBeNull();
  });

  it("recovers development feedback when the evaluated version is now active", async () => {
    await seedRejectedCandidate(config);
    const registry = loadEvolutionRegistry(config.storePath);
    const candidate = registry.versions.find((version) => version.status === "candidate")!;
    candidate.status = "active";
    registry.activeId = candidate.id;
    const feedback = tryRecoverPreviousFeedback(config, registry, config.storePath);
    expect(feedback).not.toBeNull();
    expect(JSON.parse(feedback!).candidate.every((attempt: { caseId: string }) => attempt.caseId.startsWith("development-"))).toBe(true);
  });

});

// ---------------------------------------------------------------------------
// Budget-only changes remain compatible
// ---------------------------------------------------------------------------

describe("budget-only compatibility", () => {
  it("recovers feedback when only model/evaluation budget changed", async () => {
    await seedRejectedCandidate(config);
    const budgetChangedConfig = parseEvolutionConfig({
      ...config,
      maxModelCostUsd: config.maxModelCostUsd * 2,
      maxEvaluationCostUsd: config.maxEvaluationCostUsd * 3,
      computeUsdPerSecond: config.computeUsdPerSecond * 0.5,
    });
    const registry = loadEvolutionRegistry(config.storePath);
    const feedback = tryRecoverPreviousFeedback(budgetChangedConfig, registry, config.storePath);
    expect(feedback).not.toBeNull();
    const parsed = JSON.parse(feedback!);
    expect(parsed.previousProposal.rationale).toBe("Improve detection logic");
  });

  it("recovers feedback when only model field changed", async () => {
    await seedRejectedCandidate(config);
    const modelChangedConfig = parseEvolutionConfig({
      ...config, model: "anthropic/claude-sonnet-4-20250514",
    });
    const registry = loadEvolutionRegistry(config.storePath);
    const feedback = tryRecoverPreviousFeedback(modelChangedConfig, registry, config.storePath);
    expect(feedback).not.toBeNull();
  });

  it("recovers feedback when canaryTrials changed", async () => {
    await seedRejectedCandidate(config);
    const changedTrials = parseEvolutionConfig({
      ...config, canaryTrials: 5,
    });
    const registry = loadEvolutionRegistry(config.storePath);
    const feedback = tryRecoverPreviousFeedback(changedTrials, registry, config.storePath);
    expect(feedback).not.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Incompatible objective/corpus
// ---------------------------------------------------------------------------

describe("incompatible history rejection", () => {
  it.each([
    { image: "node:24-alpine" },
    { timeoutMs: 100 },
  ])("does not reuse evaluation feedback across runtime changes: %j", async (change) => {
    await seedRejectedCandidate(config);
    const changed = parseEvolutionConfig({ ...config, ...change });
    expect(tryRecoverPreviousFeedback(changed, loadEvolutionRegistry(config.storePath), config.storePath)).toBeNull();
  });

  it("returns null when the objective changed", async () => {
    await seedRejectedCandidate(config);
    const changedConfig = parseEvolutionConfig({
      ...config, objective: "A completely different objective for a different task.",
    });
    const registry = loadEvolutionRegistry(config.storePath);
    expect(tryRecoverPreviousFeedback(changedConfig, registry, config.storePath)).toBeNull();
  });

  it("returns null when the source paths changed", async () => {
    await seedRejectedCandidate(config);
    // Need a matching source directory
    mkdirSync(join(config.sourceRoot, "lib"), { recursive: true });
    writeFileSync(join(config.sourceRoot, "lib/helper.cjs"), "module.exports = () => {};\n");
    const changedConfig = parseEvolutionConfig({
      ...config, sourcePaths: ["src", "lib"], editablePaths: ["src", "lib"],
    });
    const registry = loadEvolutionRegistry(config.storePath);
    expect(tryRecoverPreviousFeedback(changedConfig, registry, config.storePath)).toBeNull();
  });

  it("returns null when the evaluation cases changed", async () => {
    await seedRejectedCandidate(config);
    // Modify case inputs while keeping the same count per lane
    const modifiedCases = config.cases.map((c) => {
      if (c.lane === "development") {
        return { ...c, input: { ...c.input as Record<string, unknown>, modified: true } };
      }
      return { ...c, input: { ...c.input as Record<string, unknown>, modified: true } };
    });
    const changedConfig = parseEvolutionConfig({ ...config, cases: modifiedCases });
    const registry = loadEvolutionRegistry(config.storePath);
    expect(tryRecoverPreviousFeedback(changedConfig, registry, config.storePath)).toBeNull();
  });

  it("returns null when the kind changed", async () => {
    await seedRejectedCandidate(config);
    const changedConfig = parseEvolutionConfig({
      ...config, kind: "skill" as const,
      sourcePaths: ["src"], editablePaths: ["src"],
    });
    const registry = loadEvolutionRegistry(config.storePath);
    expect(tryRecoverPreviousFeedback(changedConfig, registry, config.storePath)).toBeNull();
  });

  it("returns null when repeats changed", async () => {
    await seedRejectedCandidate(config);
    const changedConfig = parseEvolutionConfig({
      ...config, repeats: 4,
    });
    const registry = loadEvolutionRegistry(config.storePath);
    expect(tryRecoverPreviousFeedback(changedConfig, registry, config.storePath)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Tampered history rejection
// ---------------------------------------------------------------------------

describe("tampered history rejection", () => {
  it("returns null when the stored proposal is tampered", async () => {
    await seedRejectedCandidate(config);
    const registry = loadEvolutionRegistry(config.storePath);
    const candidate = registry.versions.find((v) => v.status === "candidate")!;

    // Valid JSON with changed semantics must fail, not only malformed JSON.
    const proposalPath = join(config.storePath, "receipts", `${candidate.id}.proposal.json`);
    chmodSync(proposalPath, 0o600);
    const proposal = JSON.parse(readFileSync(proposalPath, "utf8"));
    proposal.rationale = "Substituted historical rationale";
    writeFileSync(proposalPath, JSON.stringify(proposal));

    expect(tryRecoverPreviousFeedback(config, registry, config.storePath)).toBeNull();
  });


  it("rejects a self-consistent receipt that no longer matches the recorded version", async () => {
    await seedRejectedCandidate(config);
    const registry = loadEvolutionRegistry(config.storePath);
    const candidate = registry.versions.find((version) => version.status === "candidate")!;
    const path = join(config.storePath, "receipts", `${candidate.id}.json`);
    const receipt = JSON.parse(readFileSync(path, "utf8"));
    receipt.attempts.candidate[0].execution.stdout = "Substituted development observation";
    const { receiptDigest: _digest, ...unsigned } = receipt;
    receipt.receiptDigest = evolutionDigest(unsigned);
    chmodSync(path, 0o600);
    writeFileSync(path, JSON.stringify(receipt));
    expect(tryRecoverPreviousFeedback(config, registry, config.storePath)).toBeNull();
  });
  it("returns null when the evaluation receipt is tampered", async () => {
    await seedRejectedCandidate(config);
    const registry = loadEvolutionRegistry(config.storePath);
    const candidate = registry.versions.find((v) => v.status === "candidate")!;

    // Tamper with the stored receipt (change a decision field)
    const receiptPath = join(config.storePath, "receipts", `${candidate.id}.json`);
    chmodSync(receiptPath, 0o600);
    const raw = JSON.parse(readFileSync(receiptPath, "utf8"));
    // Re-wrap: set a field so receiptDigest won't match
    raw.decision.checks[0]!.passed = false;
    writeFileSync(receiptPath, JSON.stringify(raw));

    expect(tryRecoverPreviousFeedback(config, registry, config.storePath)).toBeNull();
  });

  it("returns null when the stored config artifact is tampered", async () => {
    await seedRejectedCandidate(config);
    const registry = loadEvolutionRegistry(config.storePath);
    const prior = registry.versions.find((v) => v.status === "candidate")!;
    const configHex = prior.configDigest.replace(/^sha256:/, "");

    // Tamper with the published config
    const configPath = join(config.storePath, "configs", `${configHex}.json`);
    chmodSync(configPath, 0o600);
    const raw = JSON.parse(readFileSync(configPath, "utf8"));
    raw.objective = "Tampered objective injected into stored config";
    writeFileSync(configPath, JSON.stringify(raw));

    expect(tryRecoverPreviousFeedback(config, registry, config.storePath)).toBeNull();
  });

  it("returns null when the candidate snapshot files are missing", async () => {
    await seedRejectedCandidate(config);
    const registry = loadEvolutionRegistry(config.storePath);
    const candidate = registry.versions.find((v) => v.status === "candidate")!;

    // Delete the snapshot directory
    makeWritable(candidate.snapshot.root);
    rmSync(candidate.snapshot.root, { recursive: true, force: true });

    expect(tryRecoverPreviousFeedback(config, registry, config.storePath)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Hidden-lane non-disclosure
// ---------------------------------------------------------------------------

describe("hidden-lane non-disclosure", () => {
  it("never includes held-out or negative-control attempts in feedback", async () => {
    const { evaluation } = await seedRejectedCandidate(config);

    // Verify the original evaluation has held-out and negative-control data
    expect(evaluation.attempts.baseline.some((a) => a.lane === "held-out")).toBe(true);
    expect(evaluation.attempts.baseline.some((a) => a.lane === "negative-control")).toBe(true);
    expect(evaluation.attempts.candidate.some((a) => a.lane === "held-out")).toBe(true);
    expect(evaluation.attempts.candidate.some((a) => a.lane === "negative-control")).toBe(true);

    // Now verify the recovered feedback excludes them
    const registry = loadEvolutionRegistry(config.storePath);
    const feedback = tryRecoverPreviousFeedback(config, registry, config.storePath);
    expect(feedback).not.toBeNull();
    const parsed = JSON.parse(feedback!);

    for (const lane of ["baseline", "candidate"] as const) {
      for (const attempt of parsed[lane]) {
        expect(attempt.caseId.startsWith("development-")).toBe(true);
      }
    }

    // Verify no held-out or negative-control case IDs appear anywhere
    const allIds: string[] = [
      ...parsed.baseline.map((a: { caseId: string }) => a.caseId),
      ...parsed.candidate.map((a: { caseId: string }) => a.caseId),
    ];
    expect(allIds.every((id: string) => id.startsWith("development-"))).toBe(true);
  });
});