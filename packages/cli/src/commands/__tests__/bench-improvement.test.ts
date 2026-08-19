import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  aggregateScorecard,
  digestBenchManifest,
  pairwiseDeltas,
  pickChampion,
  type BenchManifest,
} from "@pwnkit/core";
import {
  canonicalResultJson,
  parseCandidateMetadata,
  parseCiEvidence,
  parseEvaluationManifest,
  parseEvaluatorBundle,
  parseTournamentPair,
  projectImprovementBundleFromArtifacts,
  projectImprovementFromArtifacts,
  readArtifactJson,
  readArtifactJsonWithDigest,
  sha256Bytes,
  writeImprovementBundleAtomic,
  writeResultAtomic,
} from "../bench-improvement.js";

const roots: string[] = [];
const evaluatorCodeDigest = `sha256:${"f".repeat(64)}`;
const evaluatorConfigDigest = `sha256:${"a".repeat(64)}`;
const evaluatorBundleDigest = sha256Bytes(
  Buffer.from(
    `${JSON.stringify({
      schemaVersion: 1,
      codeDigest: evaluatorCodeDigest,
      configDigest: evaluatorConfigDigest,
    })}\n`,
  ),
);
const producer = {
  repository: "0sec-labs/0sec",
  commitSha: "a".repeat(40),
  treeDigest: `sha256:${"7".repeat(64)}`,
};
const requiredChecks = [
  "build",
  "ecosystem-audit-smoke (cargo)",
  "ecosystem-audit-smoke (npm)",
  "ecosystem-audit-smoke (oci)",
  "ecosystem-audit-smoke (pypi)",
  "install-smoke (bun)",
  "install-smoke (docker)",
  "install-smoke (node 24)",
  "install-smoke (node 25)",
  "test",
];

function strictCiEvidence(candidateId: string) {
  return parseCiEvidence({
    schemaVersion: 1,
    provider: "github-actions",
    candidateId,
    repository: producer.repository,
    headSha: producer.commitSha,
    treeDigest: producer.treeDigest,
    passed: true,
    evidenceRefs: ["artifact:ci"],
    checks: requiredChecks.map((name) => ({ name, conclusion: "success" })),
  });
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "pwnkit-improvement-project-"));
  roots.push(value);
  return value;
}

function manifest(id: string, knownNegative = false): BenchManifest {
  return {
    id,
    version: 1,
    cases: Array.from({ length: 5 }, (_, index) =>
      ({
        id: `${id}-case-${index}`,
        target: { kind: "source-audit", package: "fixture", version: "1.0.0", ecosystem: "npm" },
        objective: { type: "finding-match", vulnClass: "path-traversal", sinkMarkers: ["sink"] },
        knownNegative,
        ci: false,
        tags: [],
      }),
    ),
  };
}

function scorecard(corpus: BenchManifest, successRate: number) {
  const verified = Math.round(corpus.cases.length * successRate);
  const cases = corpus.cases.map((entry, index) => ({
    id: entry.id,
    kind: entry.target.kind,
    objective: entry.objective.type,
    knownNegative: entry.knownNegative,
    tags: entry.tags,
    passAtK: 1,
    attempts: [{
      attemptIndex: 0,
      status: index < verified ? "verified" as const : "refuted" as const,
      confidence: 1,
      notes: "fixture",
      costUsd: 8,
      attackTurns: 20,
      durationMs: 10,
    }],
    verdict: index < verified ? "verified" as const : "refuted" as const,
    falsePositive: entry.knownNegative && index < verified,
    costUsd: 8,
    attackTurns: 20,
  }));
  return aggregateScorecard({
    manifestId: corpus.id,
    ciSubset: false,
    passAtK: 1,
    maxTurns: 20,
    costCeilingUsd: 10,
    cases,
  });
}

function pair(corpus: BenchManifest, championSuccess: number, challengerSuccess: number) {
  const variants = [
    { variant: { id: "champion" }, scorecard: scorecard(corpus, championSuccess) },
    {
      variant: {
        id: "challenger",
        promptOverrides: { "source_audit.hypothesis": "Inspect parser state transitions." },
      },
      scorecard: scorecard(corpus, challengerSuccess),
    },
  ];
  return {
    schemaVersion: 1,
    elapsedMs: 1_000,
    evaluatorBefore: {
      bundleDigest: evaluatorBundleDigest,
      codeDigest: evaluatorCodeDigest,
      configDigest: evaluatorConfigDigest,
    },
    evaluatorAfter: {
      bundleDigest: evaluatorBundleDigest,
      codeDigest: evaluatorCodeDigest,
      configDigest: evaluatorConfigDigest,
    },
    manifest: corpus,
    tournament: {
      manifestId: corpus.id,
      config: {
        passAtK: 1,
        maxTurns: 20,
        costCeilingUsd: 10,
        ciSubset: false,
        variantIds: ["champion", "challenger"],
      },
      variants,
      pairwise: pairwiseDeltas(variants),
      championId: pickChampion(variants),
    },
  };
}

function fixtures() {
  const development = pair(manifest("development"), 0.4, 0.8);
  const heldOut = pair(manifest("held-out"), 0.4, 0.8);
  const controls = pair(manifest("controls", true), 0, 0);
  const candidate = {
    schemaVersion: 1,
    id: "pwnkit_source_hypothesis_001",
    project: "pwnkit",
    change: {
      kind: "prompt",
      knobs: { "source_audit.hypothesis": "Inspect parser state transitions." },
    },
    budget: { maxRuns: 100, maxUsd: 1_000, maxWallClockMinutes: 60 },
    evaluation: {
      manifestId: "research-run-v1",
      manifestDigest: `sha256:${"d".repeat(64)}`,
      evaluatorDigest: evaluatorBundleDigest,
      developmentCorpusDigest: digestBenchManifest(development.manifest),
      heldOutCorpusDigest: digestBenchManifest(heldOut.manifest),
      negativeControlCorpusDigest: digestBenchManifest(controls.manifest),
      developmentCaseIds: development.manifest.cases.map((entry) => entry.id),
      heldOutCaseIds: heldOut.manifest.cases.map((entry) => entry.id),
      negativeControlCaseIds: controls.manifest.cases.map((entry) => entry.id),
    },
  };
  return { development, heldOut, controls, candidate };
}

function project() {
  const values = fixtures();
  return projectImprovementFromArtifacts({
    candidate: parseCandidateMetadata(values.candidate),
    championVariantId: "champion",
    challengerVariantId: "challenger",
    development: parseTournamentPair(values.development, "development"),
    heldOut: parseTournamentPair(values.heldOut, "held-out"),
    negativeControls: parseTournamentPair(values.controls, "controls"),
    evaluatorDigestBefore: evaluatorBundleDigest,
    evaluatorDigestAfter: evaluatorBundleDigest,
    ciEvidence: strictCiEvidence(values.candidate.id),
    evidenceRefs: ["artifact:tournaments", "artifact:ci"],
  });
}

function bundleInputs() {
  const values = fixtures();
  const candidate = parseCandidateMetadata(values.candidate);
  return {
    candidate,
    championVariantId: "champion",
    challengerVariantId: "challenger",
    development: {
      run: parseTournamentPair(values.development, "development"),
      digest: `sha256:${"1".repeat(64)}`,
      artifactRef: "artifact:development.json",
    },
    heldOut: {
      run: parseTournamentPair(values.heldOut, "held-out"),
      digest: `sha256:${"2".repeat(64)}`,
      artifactRef: "artifact:held-out.json",
    },
    negativeControls: {
      run: parseTournamentPair(values.controls, "controls"),
      digest: `sha256:${"3".repeat(64)}`,
      artifactRef: "artifact:controls.json",
    },
    evaluationManifest: parseEvaluationManifest({
      schemaVersion: 1,
      id: candidate.evaluation.manifestId,
      developmentCaseIds: candidate.evaluation.developmentCaseIds,
      heldOutCaseIds: candidate.evaluation.heldOutCaseIds,
      negativeControlCaseIds: candidate.evaluation.negativeControlCaseIds,
    }, candidate.evaluation.manifestDigest, "artifact:evaluation-manifest.json"),
    evaluator: parseEvaluatorBundle({
      schemaVersion: 1,
      codeDigest: evaluatorCodeDigest,
      configDigest: evaluatorConfigDigest,
    }, candidate.evaluation.evaluatorDigest, evaluatorCodeDigest, evaluatorConfigDigest,
      "artifact:evaluator-bundle.json",
      "artifact:evaluator-code.js",
      "artifact:evaluator-config.json",
    ),
    ciEvidence: strictCiEvidence(candidate.id),
    evidenceRefs: [],
  };
}

function projectBundle() {
  return projectImprovementBundleFromArtifacts(bundleInputs());
}

describe("offline 0research improvement projection", () => {
  it("rejects calibration evidence from the ordinary projector and forbids mixed lanes", () => {
    const values = fixtures();
    const calibration = {
      schemaVersion: 1,
      mode: "zero-cost-no-uplift",
      networkAllowed: false,
      providerAllowed: false,
      expectedOutcome: "reject",
    };
    const inputs = bundleInputs();
    inputs.negativeControls.run = parseTournamentPair(
      { ...values.controls, calibration },
      "calibration controls",
    );
    expect(() => projectImprovementBundleFromArtifacts(inputs))
      .toThrow("calibration evidence requires the explicit rejection-only calibration projector");
    expect(() => projectImprovementBundleFromArtifacts({ ...inputs, calibration: true }))
      .toThrow("calibration projection requires all three lanes");
  });

  it("requires calibration CI evidence to remain explicitly non-promotable", () => {
    const inputs = { ...bundleInputs(), calibration: true };
    inputs.championVariantId = "calibration-champion";
    inputs.challengerVariantId = "calibration-challenger";
    inputs.candidate.calibrationEmptyFindings = true;
    inputs.candidate.budget.maxUsd = 0;
    inputs.development.run.calibrationMode = "zero-cost-no-uplift";
    inputs.heldOut.run.calibrationMode = "zero-cost-no-uplift";
    inputs.negativeControls.run.calibrationMode = "zero-cost-no-uplift";
    inputs.ciEvidence.passed = true;
    expect(() => projectImprovementBundleFromArtifacts(inputs))
      .toThrow("calibration projection requires non-promotable CI evidence");
  });

  it("emits the exact portable v1 result with deduplicated evidence", () => {
    const result = project();
    expect(result.schemaVersion).toBe(1);
    expect(result.candidateId).toBe("pwnkit_source_hypothesis_001");
    expect(result.manifestId).toBe("research-run-v1");
    expect(result.heldOut.challenger.successRate).toBe(0.8);
    expect(result.negativeControls.challenger).toEqual({
      cases: 5,
      falsePositiveRate: 0,
      inconclusiveRate: 0,
    });
    expect(result.evidenceRefs).toEqual(["artifact:ci", "artifact:tournaments"]);
    expect(Object.keys(result).sort()).toEqual([
      "candidateId",
      "ciPassed",
      "development",
      "developmentCorpusDigest",
      "evaluatorDigestAfter",
      "evaluatorDigestBefore",
      "evidenceRefs",
      "heldOut",
      "heldOutCorpusDigest",
      "manifestId",
      "negativeControlCorpusDigest",
      "negativeControls",
      "schemaVersion",
    ]);
  });

  it("emits a schema-v3 receipt binding producer, change, and executed variants", () => {
    const bundle = projectBundle();
    const evidence = bundle.executionEvidence;
    expect(evidence.schemaVersion).toBe(3);
    expect(evidence.producer).toEqual(producer);
    expect(evidence.variantBinding).toMatchObject({
      mode: "candidate_change",
      champion: { id: "champion" },
      challenger: { id: "challenger" },
    });
    expect(evidence.evaluator).toMatchObject({
      bundleArtifactRef: "artifact:evaluator-bundle.json",
      codeArtifactRef: "artifact:evaluator-code.js",
      configArtifactRef: "artifact:evaluator-config.json",
    });
    expect(bundle.result.evidenceRefs).toEqual(expect.arrayContaining([
      "artifact:evaluator-bundle.json",
      "artifact:evaluator-code.js",
      "artifact:evaluator-config.json",
    ]));
  });

  it("writes deterministic canonical JSON once and refuses replacement", () => {
    const output = join(root(), "nested", "result.json");
    const result = project();
    writeResultAtomic(output, result);
    expect(readFileSync(output, "utf8")).toBe(canonicalResultJson(result));
    expect(() => writeResultAtomic(output, result)).toThrow(/already exists/);
  });

  it("rejects evaluator and corpus drift", () => {
    const values = fixtures();
    const inputs = {
      candidate: parseCandidateMetadata(values.candidate),
      championVariantId: "champion",
      challengerVariantId: "challenger",
      development: parseTournamentPair(values.development, "development"),
      heldOut: parseTournamentPair(values.heldOut, "held-out"),
      negativeControls: parseTournamentPair(values.controls, "controls"),
      evaluatorDigestBefore: evaluatorBundleDigest,
      evaluatorDigestAfter: `sha256:${"f".repeat(64)}`,
      ciEvidence: { passed: true, evidenceRefs: ["artifact:ci"] },
      evidenceRefs: [],
    };
    expect(() => projectImprovementFromArtifacts(inputs)).toThrow(/evaluator changed/);
    inputs.evaluatorDigestAfter = evaluatorBundleDigest;
    inputs.candidate.evaluation.heldOutCorpusDigest = `sha256:${"0".repeat(64)}`;
    expect(() => projectImprovementFromArtifacts(inputs)).toThrow(/held-out corpus digest/);
  });

  it("rejects malformed tournament identity and score counts", () => {
    const values = fixtures();
    values.development.tournament.config.variantIds.reverse();
    expect(() => parseTournamentPair(values.development, "development")).toThrow(
      /configured variant ids/,
    );
    values.development.tournament.config.variantIds.reverse();
    values.development.tournament.variants[0].scorecard.totals.inconclusive = 2;
    expect(() => parseTournamentPair(values.development, "development")).toThrow(
      /verdict counts disagree|summary does not match/,
    );
  });

  it("rejects tournament entry fields that authoritative replay would reject", () => {
    const values = fixtures();
    (values.development.tournament.variants[0] as any).unbound = true;
    expect(() => parseTournamentPair(values.development, "development"))
      .toThrow(/unsupported or missing fields/);
  });

  it("validates the exact controller-required CI receipt before projection", () => {
    expect(parseCiEvidence({
      schemaVersion: 1,
      passed: false,
      evidenceRefs: ["artifact:calibration-ci"],
      calibration: true,
      promotionEligible: false,
    })).toEqual({ passed: false, evidenceRefs: ["artifact:calibration-ci"] });
    expect(strictCiEvidence("candidate_one")).toMatchObject({
      provider: "github-actions",
      candidateId: "candidate_one",
      passed: true,
      producer,
    });
    const missing = requiredChecks.slice(1).map((name) => ({ name, conclusion: "success" }));
    expect(() => parseCiEvidence({
      schemaVersion: 1,
      provider: "github-actions",
      candidateId: "candidate_one",
      repository: producer.repository,
      headSha: producer.commitSha,
      treeDigest: producer.treeDigest,
      passed: true,
      evidenceRefs: ["artifact:ci"],
      checks: missing,
    })).toThrow(/controller-required check set/);
    const multipleRefs = {
      schemaVersion: 1,
      provider: "github-actions",
      candidateId: "candidate_one",
      repository: producer.repository,
      headSha: producer.commitSha,
      treeDigest: producer.treeDigest,
      passed: true,
      evidenceRefs: ["artifact:ci", "artifact:other"],
      checks: requiredChecks.map((name) => ({ name, conclusion: "success" })),
    };
    expect(() => parseCiEvidence(multipleRefs)).toThrow(/exactly its retained artifact/);
    const inputs = bundleInputs();
    inputs.ciEvidence.candidateId = "different_candidate";
    expect(() => projectImprovementBundleFromArtifacts(inputs)).toThrow(/candidate id/);
  });

  it("rejects forged summaries and non-SHA evaluator labels", () => {
    const values = fixtures();
    values.development.tournament.variants[0].scorecard.successRate = 0.5;
    expect(() => parseTournamentPair(values.development, "development")).toThrow(
      /summary does not match its raw cases/,
    );
    values.candidate.evaluation.evaluatorDigest = "sha256:evaluator";
    expect(() => parseCandidateMetadata(values.candidate)).toThrow(/lowercase SHA-256/);
  });

  it("recomputes case verdicts from the oracle attempt receipts", () => {
    const values = fixtures();
    const forged = values.development.tournament.variants[0].scorecard.cases[0];
    expect(forged.verdict).toBe("verified");
    forged.attempts[0].status = "refuted";
    expect(() => parseTournamentPair(values.development, "development")).toThrow(
      /verdict does not match its attempt receipts/,
    );
  });

  it("rejects evaluator drift during execution and artifact-ref collisions", () => {
    const drifted = bundleInputs();
    drifted.development.run.evaluatorAfter!.codeDigest = `sha256:${"0".repeat(64)}`;
    expect(() => projectImprovementBundleFromArtifacts(drifted)).toThrow(
      /evaluator changed during tournament execution/,
    );

    const collided = bundleInputs();
    collided.heldOut.artifactRef = collided.development.artifactRef;
    expect(() => projectImprovementBundleFromArtifacts(collided)).toThrow(
      /artifact references must be unique/,
    );
  });

  it("binds exact artifact bytes and rejects forged attempt or evaluator totals", () => {
    const dir = root();
    const artifact = join(dir, "artifact.json");
    writeFileSync(artifact, "{\"schemaVersion\":1}\n");
    const first = readArtifactJsonWithDigest(artifact, "artifact");
    writeFileSync(artifact, "{ \"schemaVersion\": 1 }\n");
    const second = readArtifactJsonWithDigest(artifact, "artifact");
    expect(first.value).toEqual(second.value);
    expect(first.digest).not.toBe(second.digest);

    const values = fixtures();
    values.development.tournament.variants[0].scorecard.cases[0].costUsd = 9;
    expect(() => parseTournamentPair(values.development, "development")).toThrow(
      /does not equal attempt costs/,
    );
    expect(() => parseEvaluatorBundle({
      schemaVersion: 1,
      codeDigest: `sha256:${"1".repeat(64)}`,
      configDigest: `sha256:${"2".repeat(64)}`,
    }, `sha256:${"3".repeat(64)}`, `sha256:${"4".repeat(64)}`, `sha256:${"2".repeat(64)}`,
      "artifact:bundle", "artifact:code", "artifact:config",
    )).toThrow(/code bytes/);
  });

  it("rejects a semantically correct but noncanonical evaluator bundle", () => {
    const noncanonical = Buffer.from(
      `${JSON.stringify(
        { configDigest: evaluatorConfigDigest, codeDigest: evaluatorCodeDigest, schemaVersion: 1 },
        null,
        2,
      )}\n`,
    );
    expect(() => parseEvaluatorBundle(
      JSON.parse(noncanonical.toString("utf8")),
      sha256Bytes(noncanonical),
      evaluatorCodeDigest,
      evaluatorConfigDigest,
      "artifact:bundle",
      "artifact:code",
      "artifact:config",
    )).toThrow(/canonical v1 form/);
  });

  it("rejects symlinked evidence inputs", () => {
    const dir = root();
    const target = join(dir, "candidate.json");
    const link = join(dir, "link.json");
    writeFileSync(target, JSON.stringify(fixtures().candidate));
    symlinkSync(target, link);
    expect(() => readArtifactJson(link, "candidate")).toThrow(/non-symlink/);
  });

  it("atomically publishes a bound result and execution receipt once", () => {
    const output = join(root(), "bundle");
    const bundle = projectBundle();
    writeImprovementBundleAtomic(output, bundle);
    expect(JSON.parse(readFileSync(join(output, "result.json"), "utf8"))).toEqual(bundle.result);
    expect(JSON.parse(readFileSync(join(output, "execution-evidence.json"), "utf8"))).toEqual(
      bundle.executionEvidence,
    );
    expect(JSON.parse(readFileSync(join(output, "COMPLETE"), "utf8"))).toEqual({
      schemaVersion: 1,
    });
    expect(bundle.executionEvidence.measured).toEqual({
      totalRuns: 30,
      totalCostUsd: 240,
      elapsedMs: 3_000,
    });
    expect(bundle.result.evidenceRefs).toContainEqual(
      expect.stringMatching(/^execution-evidence:sha256:/),
    );
    expect(() => writeImprovementBundleAtomic(output, bundle)).toThrow(/already exists/);
    const raced = join(root(), "raced-bundle");
    mkdirSync(raced);
    expect(() => writeImprovementBundleAtomic(raced, bundle)).toThrow(/already exists/);
    expect(readFileSync(join(output, "result.json"), "utf8")).not.toBe("");
  });
});
