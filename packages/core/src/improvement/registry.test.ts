import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { chmodSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseEvolutionConfig } from "./config.js";
import { publishEvolutionArtifact } from "./artifacts.js";
import { evaluateEvolutionCandidate } from "./evaluation.js";
import { authorizeEvolutionArtifact } from "./artifact-authorization.js";
import { executeEvolutionVersion } from "./loop.js";
import { createEvolutionCandidate, evolutionDigest, loadEvolutionRegistry, pinEvolutionVersion, promoteEvolutionVersion, recordEvolutionVersion, rollbackEvolutionVersion, snapshotEvolutionSource, startEvolutionCanary, verifyEvolutionSnapshot } from "./registry.js";
import type { EvolutionConfig, EvolutionEvaluation, EvolutionVersion } from "./types.js";

let root: string;
let config: EvolutionConfig;
const original = 'console.log("baseline");\n';
const improved = 'console.log("candidate");\n';

function makeWritable(path: string): void {
  chmodSync(path, 0o700);
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.isDirectory()) makeWritable(join(path, entry.name));
  }
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "0sec-registry-"));
  const sourceRoot = join(root, "source");
  mkdirSync(join(sourceRoot, "src"), { recursive: true });
  writeFileSync(join(sourceRoot, "src/worker.cjs"), original);
  config = parseEvolutionConfig({
    schemaVersion: 1, sourceRoot, storePath: join(root, "store"),
    image: "node:22-alpine", sourcePaths: ["src"], editablePaths: ["src"],
    command: ["node", "src/worker.cjs"], objective: "Identify unsafe inputs",
    computeUsdPerSecond: 0.001, repeats: 2, canaryTrials: 2,
    promotionPolicy: { minimumCases: 3, maximumCostMultiplier: 10 },
    cases: ["development", "held-out", "negative-control"].flatMap((lane, group) => [0, 1, 2].map((index) => ({
      id: `${lane}-${index}`, lane, input: { index: group * 3 + index, unsafe: group !== 2 }, expected: { unsafe: group !== 2 },
    }))),
  });
});
afterEach(() => {
  makeWritable(root);
  rmSync(root, { recursive: true, force: true });
});

async function staged(recordCandidate = true) {
  const snapshot = await snapshotEvolutionSource(config);
  const baseline: EvolutionVersion = { schemaVersion: 1, id: snapshot.id, kind: "source", snapshot, parentId: null,
    configDigest: evolutionDigest(config), receiptDigest: null, status: "baseline", createdAt: new Date().toISOString() };
  await recordEvolutionVersion(config.storePath, baseline, config);
  const candidate = await createEvolutionCandidate(snapshot, { rationale: "Improve detection", modelCostUsd: 0,
    edits: [{ path: "src/worker.cjs", beforeDigest: snapshot.files[0]!.digest, content: improved }] }, config);
  const evaluation = await evaluateEvolutionCandidate(snapshot, candidate, config, { sandbox: async ({ snapshot: variant, input }) => {
    const value = input as { index: number; unsafe: boolean };
    return { exitCode: 0, stdout: JSON.stringify({ unsafe: value.unsafe && (variant.id === candidate.id || value.index % 3 !== 2) }),
      stderr: "", durationMs: 1, timedOut: false };
  } });
  const version: EvolutionVersion = { ...baseline, id: candidate.id, snapshot: candidate, parentId: baseline.id,
    receiptDigest: evaluation.receiptDigest, status: "candidate" };
  if (recordCandidate) await recordEvolutionVersion(config.storePath, version, undefined, evaluation);
  return { baseline, version, evaluation };
}

function retainCanaries(version: EvolutionVersion, evaluation: EvolutionEvaluation): void {
  for (let trial = 0; trial < config.canaryTrials; trial++) {
    publishEvolutionArtifact(join(config.storePath, "receipts", `${version.id}.canary-${trial}.json`), evaluation);
  }
}
function reseal(evaluation: EvolutionEvaluation): EvolutionEvaluation {
  const { receiptDigest: _, ...unsigned } = evaluation;
  return { ...unsigned, receiptDigest: evolutionDigest(unsigned) };
}

describe("evolution snapshot boundaries", () => {
  it("rejects source aliases rather than uploading files outside the selected tree", async () => {
    const path = join(config.sourceRoot, "src/alias.cjs");
    symlinkSync(join(config.sourceRoot, "src/worker.cjs"), path);
    await expect(snapshotEvolutionSource(config)).rejects.toThrow();
    unlinkSync(path);
    linkSync(join(config.sourceRoot, "src/worker.cjs"), path);
    await expect(snapshotEvolutionSource(config)).rejects.toThrow();
  });

  it("rejects plural credential filenames", async () => {
    writeFileSync(join(config.sourceRoot, "src/credentials.json"), '{"secret":"private"}');
    await expect(snapshotEvolutionSource(config)).rejects.toThrow();
  });

  it("changes only the copied candidate and detects unindexed files", async () => {
    const { baseline, version } = await staged();
    expect(readFileSync(join(baseline.snapshot.root, "src/worker.cjs"), "utf8")).toBe(original);
    expect(readFileSync(join(version.snapshot.root, "src/worker.cjs"), "utf8")).toBe(improved);
    expect(readFileSync(join(config.sourceRoot, "src/worker.cjs"), "utf8")).toBe(original);
    chmodSync(join(version.snapshot.root, "src"), 0o700);
    writeFileSync(join(version.snapshot.root, "src/unindexed.cjs"), "unreviewed code");
    expect(() => verifyEvolutionSnapshot(version.snapshot)).toThrow();
  });

  it("rejects a same-content symlink substituted into a sealed snapshot", async () => {
    const snapshot = await snapshotEvolutionSource(config);
    chmodSync(join(snapshot.root, "src"), 0o700);
    const path = join(snapshot.root, "src/worker.cjs");
    unlinkSync(path);
    symlinkSync(join(config.sourceRoot, "src/worker.cjs"), path);
    expect(() => verifyEvolutionSnapshot(snapshot)).toThrow();
  });

  it("rejects stale edit preconditions without changing the original source", async () => {
    const snapshot = await snapshotEvolutionSource(config);
    await expect(createEvolutionCandidate(snapshot, { rationale: "stale", modelCostUsd: 0,
      edits: [{ path: "src/worker.cjs", beforeDigest: evolutionDigest("wrong bytes"), content: improved }] }, config)).rejects.toThrow();
    expect(readFileSync(join(config.sourceRoot, "src/worker.cjs"), "utf8")).toBe(original);
  });

  it("protects evaluator paths even when they start at the selected source root", async () => {
    const snapshot = await snapshotEvolutionSource(config);
    const broad = { ...config, editablePaths: ["improvement"] };
    await expect(createEvolutionCandidate(snapshot, { rationale: "change acceptance", modelCostUsd: 0,
      edits: [{ path: "improvement/evaluation.ts", beforeDigest: null, content: "accept everything" }] }, broad)).rejects.toThrow();
  });

  it("enforces non-source artifact kind boundaries", async () => {
    const snapshot = await snapshotEvolutionSource(config);
    await expect(createEvolutionCandidate(snapshot, { rationale: "executable router change", modelCostUsd: 0,
      edits: [{ path: "src/worker.cjs", beforeDigest: snapshot.files[0]!.digest, content: improved }] },
    { ...config, kind: "router" })).rejects.toThrow();
    expect(readFileSync(join(snapshot.root, "src/worker.cjs"), "utf8")).toBe(original);
  });

  it("charges multibyte edit content against the byte limit", async () => {
    const snapshot = await snapshotEvolutionSource(config);
    await expect(createEvolutionCandidate(snapshot, { rationale: "oversized", modelCostUsd: 0,
      edits: [{ path: "src/worker.cjs", beforeDigest: snapshot.files[0]!.digest, content: "é".repeat(80) }] },
    { ...config, maxChangedBytes: 128 })).rejects.toThrow();
  });

  it("content-addresses overlapping selections without double-counting files", async () => {
    const single = await snapshotEvolutionSource(config);
    const overlapping = await snapshotEvolutionSource({ ...config, sourcePaths: ["src", "src/worker.cjs"] });
    expect(overlapping.digest).toBe(single.digest);
  });
});

describe("evolution promotion and replay", () => {
  it("requires every canary, preserves prior worker pins, and restores the accepted parent", async () => {
    const { baseline, version, evaluation } = await staged();
    expect((await pinEvolutionVersion(config.storePath, "existing-worker")).id).toBe(baseline.id);
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    await expect(promoteEvolutionVersion(config.storePath, version.id, baseline.id)).rejects.toThrow();
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(baseline.id);
    retainCanaries(version, evaluation);
    await promoteEvolutionVersion(config.storePath, version.id, baseline.id);
    expect((await pinEvolutionVersion(config.storePath, "new-worker")).id).toBe(version.id);
    expect((await pinEvolutionVersion(config.storePath, "existing-worker")).id).toBe(baseline.id);
    await rollbackEvolutionVersion(config.storePath, version.id, "worker regression");
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(baseline.id);
    expect((await pinEvolutionVersion(config.storePath, "new-worker")).id).toBe(version.id);
    expect((await pinEvolutionVersion(config.storePath, "after-rollback")).id).toBe(baseline.id);
  });

  it("rejects an approving label when a recorded promotion check failed", async () => {
    const { baseline, version, evaluation } = await staged(false);
    evaluation.decision.checks[0]!.passed = false;
    const invalid = reseal(evaluation);
    await recordEvolutionVersion(config.storePath, { ...version, receiptDigest: invalid.receiptDigest }, undefined, invalid);
    await expect(startEvolutionCanary(config.storePath, version.id, baseline.id)).rejects.toThrow();
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(baseline.id);
  });

  it("rejects a validly rehashed receipt not bound to the recorded version", async () => {
    const { baseline, version, evaluation } = await staged();
    const replacement = reseal({ ...evaluation, decision: { ...evaluation.decision, checks: evaluation.decision.checks.map((check) => ({ ...check, detail: "replaced" })) } });
    const path = join(config.storePath, "receipts", `${version.id}.json`);
    chmodSync(path, 0o600);
    writeFileSync(path, JSON.stringify(replacement));
    await expect(startEvolutionCanary(config.storePath, version.id, baseline.id)).rejects.toThrow();
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(baseline.id);
  });

  it("rejects failed canary proofs even when the main evaluation passed", async () => {
    const { baseline, version, evaluation } = await staged();
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    evaluation.decision.checks[0]!.passed = false;
    retainCanaries(version, reseal(evaluation));
    await expect(promoteEvolutionVersion(config.storePath, version.id, baseline.id)).rejects.toThrow();
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(baseline.id);
  });

  it("rejects stale compare-and-swap requests and a second pending canary", async () => {
    const { baseline, version } = await staged();
    await expect(startEvolutionCanary(config.storePath, version.id, "not-the-active-version")).rejects.toThrow();
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    await expect(startEvolutionCanary(config.storePath, version.id, baseline.id)).rejects.toThrow();
    expect(loadEvolutionRegistry(config.storePath).canaryId).toBe(version.id);
  });

  it("rejects null-pointer and status tampering despite an intact event hash chain", async () => {
    const { version } = await staged();
    const path = join(config.storePath, "registry.json");
    const originalRegistry = readFileSync(path, "utf8");
    const registry = JSON.parse(originalRegistry);
    registry.activeId = null;
    writeFileSync(path, JSON.stringify(registry));
    expect(() => loadEvolutionRegistry(config.storePath)).toThrow();
    const restored = JSON.parse(originalRegistry);
    restored.versions.find((entry: EvolutionVersion) => entry.id === version.id).status = "active";
    writeFileSync(path, JSON.stringify(restored));
    expect(() => loadEvolutionRegistry(config.storePath)).toThrow();
  });

  it("serializes simultaneous registry writes from the same process", async () => {
    const { baseline, version } = await staged(false);
    const candidates = await Promise.all(Array.from({ length: 4 }, async () => {
      const snapshot = await createEvolutionCandidate(baseline.snapshot, { rationale: "parallel candidate", modelCostUsd: 0,
        edits: [{ path: "src/worker.cjs", beforeDigest: baseline.snapshot.files[0]!.digest, content: improved }] }, config);
      return { ...version, id: snapshot.id, snapshot, receiptDigest: null };
    }));
    await Promise.all(candidates.map((candidate) => recordEvolutionVersion(config.storePath, candidate)));
    const registry = loadEvolutionRegistry(config.storePath);
    expect(new Set(registry.versions.map((entry) => entry.id))).toEqual(new Set([baseline.id, ...candidates.map((entry) => entry.id)]));
    expect(registry.activeId).toBe(baseline.id);
  });

  it("never substitutes defaults when the retained promotion config is missing", async () => {
    const { baseline, version, evaluation } = await staged();
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    retainCanaries(version, evaluation);
    unlinkSync(join(config.storePath, "configs", `${version.configDigest.slice("sha256:".length)}.json`));
    await expect(promoteEvolutionVersion(config.storePath, version.id, baseline.id)).rejects.toThrow();
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(baseline.id);
  });

  it("authorizes exact candidate bytes only while their evaluated version remains active", async () => {
    const { baseline, version, evaluation } = await staged();
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    retainCanaries(version, evaluation);
    await promoteEvolutionVersion(config.storePath, version.id, baseline.id);
    const proposed = join(root, "proposed.cjs");
    writeFileSync(proposed, improved);
    const authorize = () => authorizeEvolutionArtifact(config.storePath, version.id, proposed, "src/worker.cjs", "source");
    expect(authorize().authorized).toBe(true);
    writeFileSync(proposed, improved.replace("candidate", "candidaTe"));
    expect(authorize().authorized).toBe(false);
    writeFileSync(proposed, improved);
    await rollbackEvolutionVersion(config.storePath, version.id, "withdraw artifact");
    expect(authorize().authorized).toBe(false);
  });

  it("refuses installation when an active version has lost a required canary receipt", async () => {
    const { baseline, version, evaluation } = await staged();
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    retainCanaries(version, evaluation);
    await promoteEvolutionVersion(config.storePath, version.id, baseline.id);
    unlinkSync(join(config.storePath, "receipts", `${version.id}.canary-0.json`));
    expect(authorizeEvolutionArtifact(config.storePath, version.id, join(version.snapshot.root, "src/worker.cjs"), "src/worker.cjs", "source").authorized).toBe(false);
  });

  it("requires an existing parent pin before executing an engagement child", async () => {
    await staged();
    await expect(executeEvolutionVersion(config, "orphan-child", config.cases[0]!.input, {
      parentRunId: "missing-parent",
      sandbox: async () => ({ exitCode: 0, stdout: JSON.stringify(config.cases[0]!.expected), stderr: "", durationMs: 1, timedOut: false }),
    })).rejects.toThrow();
  });

  it("refuses to reuse a child execution under a different parent engagement", async () => {
    const { baseline, version, evaluation } = await staged();
    await pinEvolutionVersion(config.storePath, "first-parent");
    const sandbox = async () => ({ exitCode: 0, stdout: JSON.stringify(config.cases[0]!.expected), stderr: "", durationMs: 1, timedOut: false });
    await executeEvolutionVersion(config, "bound-child", config.cases[0]!.input, { parentRunId: "first-parent", sandbox });
    retainCanaries(version, evaluation);
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    await promoteEvolutionVersion(config.storePath, version.id, baseline.id);
    await pinEvolutionVersion(config.storePath, "second-parent");
    await expect(executeEvolutionVersion(config, "bound-child", config.cases[0]!.input, {
      parentRunId: "second-parent", sandbox,
    })).rejects.toThrow();
  });

  it("rejects a persisted worker pin for a candidate that was never activated", async () => {
    const { version } = await staged();
    publishEvolutionArtifact(join(config.storePath, "pins", "unapproved-worker.json"), {
      runId: "unapproved-worker", versionId: version.id,
      versionDigest: version.snapshot.digest, pinnedAt: new Date().toISOString(),
    });
    await expect(pinEvolutionVersion(config.storePath, "unapproved-worker")).rejects.toThrow(/never active/);
  });

  it("rolls back a deployed version when its consumer rejects otherwise valid JSON", async () => {
    const { baseline, version, evaluation } = await staged();
    retainCanaries(version, evaluation);
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    await promoteEvolutionVersion(config.storePath, version.id, baseline.id);
    const result = await executeEvolutionVersion(config, "rejected-output", { index: 99, unsafe: true }, {
      sandbox: async () => ({ exitCode: 0, stdout: '{"unsafe":true,"status":"confirmed"}', stderr: "", durationMs: 1, timedOut: false }),
      validateExecutionOutput(output) {
        if (output && typeof output === "object" && Object.hasOwn(output, "status")) throw new Error("self-grading is not an accepted worker output");
      },
    });
    expect(result.execution.error).toBeDefined();
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(baseline.id);
    expect((await pinEvolutionVersion(config.storePath, "rejected-output")).id).toBe(version.id);
  });

  it("does not retire an accepted version when its worker is cancelled", async () => {
    const { baseline, version, evaluation } = await staged();
    retainCanaries(version, evaluation);
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    await promoteEvolutionVersion(config.storePath, version.id, baseline.id);
    const controller = new AbortController();
    await executeEvolutionVersion(config, "cancelled-worker", config.cases[0]!.input, {
      signal: controller.signal,
      sandbox: async () => {
        controller.abort();
        return { exitCode: null, stdout: "", stderr: "", durationMs: 1, timedOut: false, error: "cancelled" };
      },
    });
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(version.id);
  });

  it("derives child pins from an immutable parent runId across mid-scan promotion and rollback", async () => {
    const { baseline, version, evaluation } = await staged();

    // Parent pins the current active baseline
    const parent = await pinEvolutionVersion(config.storePath, "engagement-parent");
    expect(parent.id).toBe(baseline.id);

    // Children pin the same version as the parent, not independently re-resolving
    const child1 = await pinEvolutionVersion(config.storePath, "engagement-child-1", undefined, "engagement-parent");
    expect(child1.id).toBe(baseline.id);

    // Promote candidate to active (requires canary proofs)
    retainCanaries(version, evaluation);
    await startEvolutionCanary(config.storePath, version.id, baseline.id);
    await promoteEvolutionVersion(config.storePath, version.id, baseline.id);
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(version.id);

    // Children pinned before promotion still resolve to baseline, not the new active
    expect((await pinEvolutionVersion(config.storePath, "engagement-child-1")).id).toBe(baseline.id);

    // New children with the same parentRunId also pin baseline
    const afterPromotion = await pinEvolutionVersion(config.storePath, "engagement-child-3", undefined, "engagement-parent");
    expect(afterPromotion.id).toBe(baseline.id);

    // A fresh run without a parent gets the new active version
    expect((await pinEvolutionVersion(config.storePath, "fresh-after-promotion")).id).toBe(version.id);

    // Rollback candidate, restoring baseline as active
    await rollbackEvolutionVersion(config.storePath, version.id, "test rollback");
    expect(loadEvolutionRegistry(config.storePath).activeId).toBe(baseline.id);

    // All parent-child pins survive registry changes
    expect((await pinEvolutionVersion(config.storePath, "engagement-parent")).id).toBe(baseline.id);
    expect((await pinEvolutionVersion(config.storePath, "engagement-child-1")).id).toBe(baseline.id);
    expect((await pinEvolutionVersion(config.storePath, "engagement-child-3")).id).toBe(baseline.id);

    // A fresh pin after rollback also resolves to baseline (now active again)
    expect((await pinEvolutionVersion(config.storePath, "fresh-after-rollback")).id).toBe(baseline.id);
  });

  it("rejects a canary start when the candidate snapshot has been tampered on disk despite a valid receipt", async () => {
    const { baseline, version } = await staged();
    const worker = join(version.snapshot.root, "src/worker.cjs");
    chmodSync(worker, 0o600);
    writeFileSync(worker, 'console.log("tampered");\n');
    chmodSync(worker, 0o444);
    await expect(startEvolutionCanary(config.storePath, version.id, baseline.id)).rejects.toThrow(/digest/);
    const registry = loadEvolutionRegistry(config.storePath);
    const v = registry.versions.find((entry) => entry.id === version.id)!;
    expect(v.status).toBe("candidate");
    expect(registry.canaryId).toBeNull();
    expect(registry.activeId).toBe(baseline.id);
  });
});
