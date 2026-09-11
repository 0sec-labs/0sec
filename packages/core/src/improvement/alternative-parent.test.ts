import { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseEvolutionConfig } from "./config.js";
import { publishEvolutionArtifact } from "./artifacts.js";
import { evaluateEvolutionCandidate } from "./evaluation.js";
import {
  configsDir, createEvolutionCandidate, evolutionDigest,
  loadEvolutionReceipt, loadEvolutionRegistry,
  promoteEvolutionVersion, recordEvolutionVersion,
  rollbackEvolutionVersion, snapshotEvolutionSource,
  startEvolutionCanary, verifyEvolutionSnapshot,
} from "./registry.js";
import { selectEvolutionAlternativeParent } from "./loop.js";
import type { EvolutionConfig, EvolutionEvaluation, EvolutionSandbox, EvolutionVersion } from "./types.js";

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

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
  root = mkdtempSync(join(tmpdir(), "0sec-alt-parent-"));
  const sourceRoot = join(root, "source");
  mkdirSync(join(sourceRoot, "src"), { recursive: true });
  writeFileSync(join(sourceRoot, "src/worker.cjs"), original);
  config = parseEvolutionConfig({
    schemaVersion: 1, sourceRoot, storePath: join(root, "store"),
    image: "node:22-alpine", sourcePaths: ["src"], editablePaths: ["src"],
    command: ["node", "src/worker.cjs"], objective: "Detect unsafe inputs without false positives.",
    computeUsdPerSecond: 0.001, repeats: 2, canaryTrials: 2,
    promotionPolicy: { minimumCases: 3, maximumCostMultiplier: 10 },
    maxAlternativeParents: 3,
    // Every case input must be JSON-unique across lanes to pass config validation
    cases: ["development", "held-out", "negative-control"].flatMap((lane) =>
      [0, 1, 2].map((index) => ({
        id: `${lane}-${index}`, lane,
        input: { index, lane, unsafe: lane !== "negative-control" },
        expected: { unsafe: lane !== "negative-control" },
      }))),
  });
});

afterEach(() => {
  makeWritable(root);
  rmSync(root, { recursive: true, force: true });
});

/** Candidate sandbox: development cases improve over baseline for the matched candidate. */
function makeImprovingSandbox(candidateId: string): EvolutionSandbox {
  return async ({ snapshot, input }) => {
    const value = input as { index: number; lane: string; unsafe: boolean };
    const isCandidate = snapshot.id === candidateId;
    const devOk = isCandidate || value.index % 2 === 0;
    const allOk = devOk;
    return {
      exitCode: 0,
      stdout: JSON.stringify({ unsafe: value.unsafe && allOk }),
      stderr: "", durationMs: 1, timedOut: false,
    };
  };
}

/** Sandbox where candidate only mildly improves development, for relative ranking. */
function makeWeakDevSandbox(candidateId: string): EvolutionSandbox {
  return async ({ snapshot, input }) => {
    const value = input as { index: number; lane: string; unsafe: boolean };
    const isCandidate = snapshot.id === candidateId;
    const devOk = isCandidate ? value.index !== 0 : value.index === 1;
    const allOk = value.lane === "held-out" && isCandidate ? true : devOk;
    return {
      exitCode: 0,
      stdout: JSON.stringify({ unsafe: value.unsafe && allOk }),
      stderr: "", durationMs: 1, timedOut: false,
    };
  };
}

/** Sandbox with some inconclusive development attempts. */
function makePartialInconclusiveSandbox(candidateId: string): EvolutionSandbox {
  return async ({ snapshot, input }) => {
    const value = input as { index: number; lane: string; unsafe: boolean };
    const isCandidate = snapshot.id === candidateId;
    const devOk = isCandidate || value.index % 2 === 0;
    const allOk = value.lane === "held-out" ? true : devOk;
    // A candidate failure after two successes must reduce its archive rank.
    if (isCandidate && value.lane === "development" && value.index === 2) {
      return {
        exitCode: 1, stdout: "", stderr: "timeout",
        durationMs: 1000, timedOut: true,
      };
    }
    return {
      exitCode: 0,
      stdout: JSON.stringify({ unsafe: value.unsafe && allOk }),
      stderr: "", durationMs: 1, timedOut: false,
    };
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function createBaseline(cfg: EvolutionConfig): Promise<EvolutionVersion> {
  const snapshot = await snapshotEvolutionSource(cfg);
  const baseline: EvolutionVersion = {
    schemaVersion: 1, id: snapshot.id, kind: cfg.kind, snapshot,
    parentId: null, createdAt: new Date().toISOString(),
    configDigest: evolutionDigest(cfg), receiptDigest: null, status: "baseline",
  };
  await recordEvolutionVersion(cfg.storePath, baseline, cfg);
  return baseline;
}

async function createAndRecordCandidate(
  cfg: EvolutionConfig,
  baseSnapshot: EvolutionVersion,
  content: string,
  makeSandbox: (candidateId: string) => EvolutionSandbox,
): Promise<{ version: EvolutionVersion; evaluation: EvolutionEvaluation }> {
  const file = baseSnapshot.snapshot.files.find((f) => f.path === "src/worker.cjs")!;
  const snapshot = await createEvolutionCandidate(baseSnapshot.snapshot, {
    rationale: "candidate", modelCostUsd: 0.01,
    edits: [{ path: "src/worker.cjs", beforeDigest: file.digest, content }],
  }, cfg);
  const sandbox = makeSandbox(snapshot.id);
  const evaluation = await evaluateEvolutionCandidate(baseSnapshot.snapshot, snapshot, cfg, { sandbox });
  const configDigest = evolutionDigest(cfg);
  const version: EvolutionVersion = {
    schemaVersion: 1, id: snapshot.id, kind: cfg.kind, snapshot,
    parentId: baseSnapshot.id, createdAt: new Date().toISOString(),
    configDigest, receiptDigest: evaluation.receiptDigest,
    proposalDigest: evolutionDigest({ rationale: "candidate", modelCostUsd: 0.01,
      edits: [{ path: "src/worker.cjs", beforeDigest: file.digest, content }] }),
    status: "candidate",
  };
  await recordEvolutionVersion(cfg.storePath, version, undefined, evaluation);
  publishEvolutionArtifact(join(cfg.storePath, "receipts", `${snapshot.id}.proposal.json`),
    { rationale: "candidate", modelCostUsd: 0.01,
      edits: [{ path: "src/worker.cjs", beforeDigest: file.digest, content }] });
  return { version, evaluation };
}

async function promote(
  cfg: EvolutionConfig, id: string, expectedActiveId: string | null, evaluation: EvolutionEvaluation,
): Promise<void> {
  for (let t = 0; t < cfg.canaryTrials; t++) {
    publishEvolutionArtifact(join(cfg.storePath, "receipts", `${id}.canary-${t}.json`), evaluation);
  }
  await startEvolutionCanary(cfg.storePath, id, expectedActiveId);
  await promoteEvolutionVersion(cfg.storePath, id, expectedActiveId);
}

// ---------------------------------------------------------------------------
// selectEvolutionAlternativeParent — disabled or empty
// ---------------------------------------------------------------------------

describe("selectEvolutionAlternativeParent — disabled or empty", () => {
  it("returns null when maxAlternativeParents is 0 or undefined", async () => {
    const disabled = parseEvolutionConfig({ ...config, maxAlternativeParents: 0 });
    await createBaseline(disabled);
    const registry = loadEvolutionRegistry(disabled.storePath);
    expect(selectEvolutionAlternativeParent(disabled, registry)).toBeNull();

    const absent = parseEvolutionConfig({ ...config, maxAlternativeParents: undefined });
    expect(selectEvolutionAlternativeParent(absent, registry)).toBeNull();
  });

  it("returns null when the registry has only a baseline", async () => {
    await createBaseline(config);
    const registry = loadEvolutionRegistry(config.storePath);
    expect(selectEvolutionAlternativeParent(config, registry)).toBeNull();
  });

  it("does not select the active version", async () => {
    const baseline = await createBaseline(config);
    const { version, evaluation } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    // Promote — version is now active, not selectable
    await promote(config, version.id, baseline.id, evaluation);
    const registry = loadEvolutionRegistry(config.storePath);
    expect(selectEvolutionAlternativeParent(config, registry)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// selectEvolutionAlternativeParent — integrity checks
// ---------------------------------------------------------------------------

describe("selectEvolutionAlternativeParent — integrity checks", () => {
  it("selects a retired candidate with valid receipt and snapshot", async () => {
    const baseline = await createBaseline(config);
    const { version, evaluation } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    await promote(config, version.id, baseline.id, evaluation);
    const { version: v2, evaluation: e2 } = await createAndRecordCandidate(
      config, version, 'console.log("second");\n', makeImprovingSandbox,
    );
    await promote(config, v2.id, version.id, e2);
    const registry = loadEvolutionRegistry(config.storePath);
    expect(registry.versions.find(item => item.id === version.id)?.status).toBe("retired");
    const selected = selectEvolutionAlternativeParent(config, registry);
    expect(selected).not.toBeNull();
    expect(selected!.id).toBe(version.id);
  });

  it("selects a candidate-status version (pending approval) as offline stepping stone", async () => {
    const baseline = await createBaseline(config);
    const { version } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    // Candidate with full receipt, not promoted — still selectable
    const registry = loadEvolutionRegistry(config.storePath);
    const selected = selectEvolutionAlternativeParent(config, registry);
    expect(selected).not.toBeNull();
    expect(selected!.id).toBe(version.id);
  });

  it("rejects a candidate with a tampered snapshot on disk", async () => {
    const baseline = await createBaseline(config);
    const { version } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    const workerPath = join(version.snapshot.root, "src/worker.cjs");
    chmodSync(workerPath, 0o600);
    writeFileSync(workerPath, 'console.log("tampered");\n');
    chmodSync(workerPath, 0o444);

    const registry = loadEvolutionRegistry(config.storePath);
    expect(selectEvolutionAlternativeParent(config, registry)).toBeNull();
  });

  it("rejects a candidate with a missing evaluation receipt", async () => {
    const baseline = await createBaseline(config);
    const { version } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    const receiptPath = join(config.storePath, "receipts", `${version.id}.json`);
    chmodSync(receiptPath, 0o600);
    rmSync(receiptPath);

    const registry = loadEvolutionRegistry(config.storePath);
    expect(selectEvolutionAlternativeParent(config, registry)).toBeNull();
  });

  it("rejects a candidate whose receiptDigest no longer matches the stored receipt", async () => {
    const baseline = await createBaseline(config);
    const { version } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    const receiptPath = join(config.storePath, "receipts", `${version.id}.json`);
    chmodSync(receiptPath, 0o600);
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8"));
    receipt.decision.checks[0]!.passed = false;
    writeFileSync(receiptPath, JSON.stringify(receipt));

    const registry = loadEvolutionRegistry(config.storePath);
    expect(selectEvolutionAlternativeParent(config, registry)).toBeNull();
  });

  it("rejects a candidate with missing snapshot directory", async () => {
    const baseline = await createBaseline(config);
    const { version } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    makeWritable(version.snapshot.root);
    rmSync(version.snapshot.root, { recursive: true, force: true });

    const registry = loadEvolutionRegistry(config.storePath);
    expect(selectEvolutionAlternativeParent(config, registry)).toBeNull();
  });

  it("rejects a candidate whose stored config artifact digest mismatches version.configDigest", async () => {
    const baseline = await createBaseline(config);
    const { version } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    const configHex = version.configDigest.replace(/^sha256:/, "");
    const cfgPath = join(configsDir(config.storePath), `${configHex}.json`);
    chmodSync(cfgPath, 0o600);
    const stored = JSON.parse(readFileSync(cfgPath, "utf8"));
    stored.objective = "Tampered objective";
    writeFileSync(cfgPath, JSON.stringify(stored));

    const registry = loadEvolutionRegistry(config.storePath);
    expect(selectEvolutionAlternativeParent(config, registry)).toBeNull();
  });

  it("rejects a candidate whose receipt baselineDigest does not match the parent snapshot digest", async () => {
    const baseline = await createBaseline(config);
    const snapshot = baseline.snapshot;
    const file = snapshot.files.find((f) => f.path === "src/worker.cjs")!;
    const csnapshot = await createEvolutionCandidate(snapshot, {
      rationale: "bad baseline", modelCostUsd: 0,
      edits: [{ path: "src/worker.cjs", beforeDigest: file.digest, content: improved }],
    }, config);
    const evaluation = await evaluateEvolutionCandidate(snapshot, csnapshot, config, {
      sandbox: makeImprovingSandbox(csnapshot.id),
    });
    // Swap baselineDigest to a wrong value
    const wrongBaseline = { ...evaluation, baselineDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000" };
    const { receiptDigest: _, ...clean } = wrongBaseline;
    const tampered = { ...clean, receiptDigest: evolutionDigest(clean) };

    const version: EvolutionVersion = {
      schemaVersion: 1, id: csnapshot.id, kind: "source", snapshot: csnapshot,
      parentId: baseline.id, createdAt: new Date().toISOString(),
      configDigest: evolutionDigest(config), receiptDigest: tampered.receiptDigest,
      status: "candidate",
    };
    await recordEvolutionVersion(config.storePath, version, config, tampered);
    const registry = loadEvolutionRegistry(config.storePath);
    expect(selectEvolutionAlternativeParent(config, registry)).toBeNull();
  });

  it("skips candidates with no development-lane attempts in receipt", async () => {
    const baseline = await createBaseline(config);
    const snapshot = baseline.snapshot;
    const file = snapshot.files.find((f) => f.path === "src/worker.cjs")!;
    const csnapshot = await createEvolutionCandidate(snapshot, {
      rationale: "held-out only", modelCostUsd: 0,
      edits: [{ path: "src/worker.cjs", beforeDigest: file.digest, content: improved }],
    }, config);
    const evaluation = await evaluateEvolutionCandidate(snapshot, csnapshot, config, {
      sandbox: makeImprovingSandbox(csnapshot.id),
    });
    // Strip development attempts from receipt
    const noDev: EvolutionEvaluation = {
      ...evaluation,
      attempts: {
        baseline: evaluation.attempts.baseline.filter((a) => a.lane !== "development"),
        candidate: evaluation.attempts.candidate.filter((a) => a.lane !== "development"),
      },
    };
    const { receiptDigest: _, ...unsigned } = noDev;
    const altered = { ...unsigned, receiptDigest: evolutionDigest(unsigned) };
    const version: EvolutionVersion = {
      schemaVersion: 1, id: csnapshot.id, kind: "source", snapshot: csnapshot,
      parentId: baseline.id, createdAt: new Date().toISOString(),
      configDigest: evolutionDigest(config), receiptDigest: altered.receiptDigest,
      status: "candidate",
    };
    await recordEvolutionVersion(config.storePath, version, config, altered);
    const registry = loadEvolutionRegistry(config.storePath);
    expect(selectEvolutionAlternativeParent(config, registry)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Development-only scoring
// ---------------------------------------------------------------------------

describe("selectEvolutionAlternativeParent — development-only scoring", () => {
  it("prefers the candidate with the highest development matched fraction", async () => {
    const baseline = await createBaseline(config);
    const { version: weak } = await createAndRecordCandidate(
      config, baseline, improved, makeWeakDevSandbox,
    );
    const { version: strong } = await createAndRecordCandidate(
      config, baseline, 'console.log("strong");\n', makeImprovingSandbox,
    );
    // Both are candidate status — newest-first traversal inspects strong first,
    // but strong has higher dev fraction
    const registry = loadEvolutionRegistry(config.storePath);
    const selected = selectEvolutionAlternativeParent(config, registry);
    expect(selected).not.toBeNull();
    expect(selected!.id).toBe(strong.id);
  });

  it("prefers strong development despite reversed held-out outcomes (no private lane influence)", async () => {
    // GoodDevPoorHeld: candidate great on development, held-out regresses
    // WeakDev: candidate modest improvement on development, no held-out regression
    const goodDevSandbox = (candidateId: string): EvolutionSandbox => async ({ snapshot, input }) => {
      const value = input as { index: number; lane: string; unsafe: boolean };
      const isCandidate = snapshot.id === candidateId;
      const onDev = value.lane === "development";
      const devOk = isCandidate || value.index % 3 === 0;       // candidate good on dev
      const heldOk = value.lane === "held-out" ? value.index % 2 !== 0 : true; // regresses
      const allOk = isCandidate ? (onDev ? true : heldOk) : devOk;
      return {
        exitCode: 0,
        stdout: JSON.stringify({ unsafe: value.unsafe && allOk }),
        stderr: "", durationMs: 1, timedOut: false,
      };
    };

    const baseline = await createBaseline(config);
    const { version: goodDev, evaluation: evalGoodDev } = await createAndRecordCandidate(
      config, baseline, 'console.log("good-dev");\n', goodDevSandbox,
    );
    const { version: weakDev, evaluation: evalWeakDev } = await createAndRecordCandidate(
      config, baseline, 'console.log("weak-dev");\n', makeWeakDevSandbox,
    );

    // Verify dev fractions differ
    const gdDev = evalGoodDev.attempts.candidate.filter((a) => a.lane === "development" && !a.inconclusive);
    const gdMatched = gdDev.filter((a) => a.matched).length;
    const wdDev = evalWeakDev.attempts.candidate.filter((a) => a.lane === "development" && !a.inconclusive);
    const wdMatched = wdDev.filter((a) => a.matched).length;
    expect(gdDev.length).toBeGreaterThan(0);
    expect(wdDev.length).toBeGreaterThan(0);
    const gdFrac = gdMatched / gdDev.length;
    const wdFrac = wdMatched / wdDev.length;
    expect(gdFrac).toBeGreaterThan(wdFrac);

    const registry = loadEvolutionRegistry(config.storePath);
    const selected = selectEvolutionAlternativeParent(config, registry);
    expect(selected).not.toBeNull();
    // Selected should be good-dev (higher development fraction), despite held-out regressions
    expect(selected!.id).toBe(goodDev.id);
  });

  it("breaks ties by newest-first (later recorded version wins with equal scores)", async () => {
    const baseline = await createBaseline(config);
    const { version: first } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    const { version: second } = await createAndRecordCandidate(
      config, baseline, 'console.log("second");\n', makeImprovingSandbox,
    );
    const registry = loadEvolutionRegistry(config.storePath);
    const selected = selectEvolutionAlternativeParent(config, registry);
    expect(selected).not.toBeNull();
    // Both use the same improving sandbox → equal dev scores → newest (second) wins
    expect(selected!.id).toBe(second.id);
  });

  it("respects maxAlternativeParents limit on candidates inspected (newest-first)", async () => {
    const limited = parseEvolutionConfig({ ...config, maxAlternativeParents: 1 });
    const baseline = await createBaseline(limited);
    const { version: first } = await createAndRecordCandidate(
      limited, baseline, improved, makeImprovingSandbox,
    );
    const { version: second } = await createAndRecordCandidate(
      limited, baseline, 'console.log("second");\n', makeImprovingSandbox,
    );
    const registry = loadEvolutionRegistry(limited.storePath);
    const selected = selectEvolutionAlternativeParent(limited, registry);
    // With limit=1, only the newest (second) is inspected. Since it has no competitor,
    // it wins regardless of absolute fraction.
    expect(selected).not.toBeNull();
    expect(selected!.id).toBe(second.id);
  });


  it("prefers a candidate with higher fraction even after counting inconclusive as failures", async () => {
    const baseline = await createBaseline(config);
    // Candidate A: normal improving sandbox
    const { version: high } = await createAndRecordCandidate(
      config, baseline, 'console.log("high");\n', makeImprovingSandbox,
    );
    // The newer partial candidate would tie and win if inconclusives were discarded.
    const { version: low } = await createAndRecordCandidate(
      config, baseline, 'console.log("low");\n', makePartialInconclusiveSandbox,
    );
    const registry = loadEvolutionRegistry(config.storePath);
    const selected = selectEvolutionAlternativeParent(config, registry);
    expect(selected).not.toBeNull();
    // The older complete candidate must beat the newer partial candidate.
    expect(selected!.id).toBe(high.id);
  });
});

// ---------------------------------------------------------------------------
// Alternative-parent rollback semantics
// ---------------------------------------------------------------------------

describe("alternative-parent rollback", () => {
  it("rolls back to parentId (deployed predecessor), not alternativeParentId (archive source)", async () => {
    const baseline = await createBaseline(config);

    // Create an "archive source" candidate in the same registry (must exist before B)
    const { version: archiveSource } = await createAndRecordCandidate(
      config, baseline, 'console.log("archive");\n', makeImprovingSandbox,
    );

    // Create and promote A (active deployment baseline)
    const { version: aVer, evaluation: aEval } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    await promote(config, aVer.id, baseline.id, aEval);

    // Create B with parentId=A.id, alternativeParentId=archiveSource.id
    const file = aVer.snapshot.files.find((f) => f.path === "src/worker.cjs")!;
    const snapB = await createEvolutionCandidate(aVer.snapshot, {
      rationale: "candidate B", modelCostUsd: 0.01,
      edits: [{ path: "src/worker.cjs", beforeDigest: file.digest, content: 'console.log("version-b");\n' }],
    }, config);
    const evalB = await evaluateEvolutionCandidate(aVer.snapshot, snapB, config, {
      sandbox: makeImprovingSandbox(snapB.id),
    });
    const versionB: EvolutionVersion = {
      schemaVersion: 1, id: snapB.id, kind: "source", snapshot: snapB,
      parentId: aVer.id,                     // deployed predecessor
      alternativeParentId: archiveSource.id, // archive provenance marker
      createdAt: new Date().toISOString(),
      configDigest: evolutionDigest(config), receiptDigest: evalB.receiptDigest, status: "candidate",
    };
    await recordEvolutionVersion(config.storePath, versionB, undefined, evalB);

    // Promote B
    await promote(config, snapB.id, aVer.id, evalB);
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(snapB.id);

    // Rollback B — should restore A (parentId = deployed predecessor), not archiveSource
    await rollbackEvolutionVersion(config.storePath, snapB.id, "regression");
    const registry = loadEvolutionRegistry(config.storePath);
    expect(registry.activeId).toBe(aVer.id);           // restored to deployed predecessor
    expect(registry.activeId).not.toBe(baseline.id);   // not the original baseline
    expect(registry.activeId).not.toBe(archiveSource.id); // not the archive
  });

  it("rolls back to parentId when alternativeParentId is absent (standard linear)", async () => {
    const baseline = await createBaseline(config);
    const { version, evaluation } = await createAndRecordCandidate(
      config, baseline, improved, makeImprovingSandbox,
    );
    expect(version.alternativeParentId).toBeUndefined();
    await promote(config, version.id, baseline.id, evaluation);
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(version.id);

    await rollbackEvolutionVersion(config.storePath, version.id, "linear rollback");
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(baseline.id);
  });

});
