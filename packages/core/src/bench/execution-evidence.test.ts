import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import type { BenchManifest } from "./manifest.js";
import { aggregateScorecard } from "./scorecard.js";
import { pairwiseDeltas, pickChampion, type TournamentResult } from "./tournament.js";
import {
  projectResearchExecutionEvidence,
  researchExecutionEvidenceDigest,
  researchExecutionEvidenceRef,
  type ResearchExecutionEvidence,
} from "./execution-evidence.js";

function manifest(id: string, knownNegative = false): BenchManifest {
  return {
    id,
    version: 1,
    cases: [0, 1].map((index) => ({
      id: `${id}-${index}`,
      target: { kind: "source-audit", package: "fixture", version: "1.0.0", ecosystem: "npm" },
      objective: { type: "finding-match", vulnClass: "path-traversal", sinkMarkers: ["sink"] },
      knownNegative,
      ci: false,
      tags: [],
    })),
  };
}

function pair(corpus: BenchManifest) {
  const scorecard = (variant: string) => aggregateScorecard({
    manifestId: corpus.id,
    ciSubset: false,
    passAtK: 1,
    maxTurns: 10,
    costCeilingUsd: 5,
    cases: corpus.cases.map((entry, index) => ({
      id: entry.id,
      kind: entry.target.kind,
      objective: entry.objective.type,
      knownNegative: entry.knownNegative,
      tags: entry.tags,
      passAtK: 1,
      attempts: [{
        attemptIndex: 0,
        status: "refuted",
        confidence: 1,
        notes: `${variant}-${index}`,
        costUsd: 0.5,
        attackTurns: 1,
        durationMs: 100,
      }],
      verdict: "refuted",
      falsePositive: false,
      costUsd: 0.5,
      attackTurns: 1,
    })),
  });
  const variants = [
    { variant: { id: "champion" }, scorecard: scorecard("champion") },
    { variant: { id: "challenger" }, scorecard: scorecard("challenger") },
  ];
  const tournament: TournamentResult = {
    manifestId: corpus.id,
    config: { passAtK: 1, maxTurns: 10, costCeilingUsd: 5, ciSubset: false, variantIds: ["champion", "challenger"] },
    variants,
    pairwise: pairwiseDeltas(variants),
    championId: pickChampion(variants),
  };
  return { manifest: corpus, tournament, elapsedMs: 500 };
}

function inputs() {
  const development = pair(manifest("dev"));
  const heldOut = pair(manifest("held"));
  const negativeControls = pair(manifest("neg", true));
  return {
    candidateId: "candidate_one",
    championVariantId: "champion",
    challengerVariantId: "challenger",
    manifest: {
      id: "evaluation-v1",
      digest: `sha256:${"1".repeat(64)}`,
      artifactRef: "artifact:evaluation-manifest.json",
    },
    evaluator: {
      bundleDigest: `sha256:${"2".repeat(64)}`,
      codeDigest: `sha256:${"3".repeat(64)}`,
      configDigest: `sha256:${"4".repeat(64)}`,
      bundleArtifactRef: "artifact:evaluator-bundle.json",
      codeArtifactRef: "artifact:evaluator-code.js",
      configArtifactRef: "artifact:evaluator-config.json",
    },
    development: {
      run: development,
      artifactRef: "artifact:development.json",
      tournamentDigest: `sha256:${"5".repeat(64)}`,
      corpusDigest: `sha256:${"8".repeat(64)}`,
      expectedCaseIds: development.manifest.cases.map((entry) => entry.id),
      requireKnownNegative: false,
    },
    heldOut: {
      run: heldOut,
      artifactRef: "artifact:held-out.json",
      tournamentDigest: `sha256:${"6".repeat(64)}`,
      corpusDigest: `sha256:${"9".repeat(64)}`,
      expectedCaseIds: heldOut.manifest.cases.map((entry) => entry.id),
      requireKnownNegative: false,
    },
    negativeControls: {
      run: negativeControls,
      artifactRef: "artifact:negative-controls.json",
      tournamentDigest: `sha256:${"7".repeat(64)}`,
      corpusDigest: `sha256:${"a".repeat(64)}`,
      expectedCaseIds: negativeControls.manifest.cases.map((entry) => entry.id),
      requireKnownNegative: true,
    },
    elapsedMs: 1_500,
  };
}

describe("0research execution evidence projection", () => {
  it("matches the exact canonical digest independently computed by 0brain", () => {
    const fixture = JSON.parse(
      readFileSync(new URL("./improvement-execution-evidence.fixture.json", import.meta.url), "utf8"),
    ) as ResearchExecutionEvidence;
    expect(researchExecutionEvidenceDigest(fixture)).toBe(
      "sha256:01f5053276ccb475eecd4b36d02ada8b1c1ae4d2b6278a63339322c51446c9fd",
    );
  });

  it("binds exact attempts, costs, time, corpora, and artifacts", () => {
    const evidence = projectResearchExecutionEvidence(inputs());
    expect(evidence.measured).toEqual({ totalRuns: 12, totalCostUsd: 6, elapsedMs: 1_500 });
    expect(evidence.lanes.heldOut.caseIds).toEqual(["held-0", "held-1"]);
    expect(researchExecutionEvidenceDigest(evidence)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(researchExecutionEvidenceRef(evidence)).toMatch(/^execution-evidence:sha256:/);
  });

  it("rejects case substitution and capability/control mixing", () => {
    const substituted = inputs();
    substituted.heldOut.expectedCaseIds = ["held-0", "substitute"];
    expect(() => projectResearchExecutionEvidence(substituted)).toThrow(/case ids/);

    const mixed = inputs();
    mixed.negativeControls.requireKnownNegative = false;
    expect(() => projectResearchExecutionEvidence(mixed)).toThrow(/capability cases/);
  });

  it("rejects artifact-role collisions", () => {
    const colliding = inputs();
    colliding.evaluator.configArtifactRef = colliding.evaluator.codeArtifactRef;
    expect(() => projectResearchExecutionEvidence(colliding)).toThrow(/role artifact references/);
  });

  it("rejects underreported wall time and missing attempt receipts", () => {
    const underreported = inputs();
    underreported.elapsedMs = 1;
    expect(() => projectResearchExecutionEvidence(underreported)).toThrow(/sum of the sealed/);

    const missing = inputs();
    missing.development.run.tournament.variants[0].scorecard.cases[0].attempts = [];
    expect(() => projectResearchExecutionEvidence(missing)).toThrow(/cost|cover.*bound case/);

    const hidden = inputs();
    const cases = hidden.development.run.tournament.variants[0].scorecard.cases;
    cases[0].attempts = [];
    cases[0].costUsd = 0;
    cases[1].passAtK = 2;
    cases[1].attempts.push({ ...cases[1].attempts[0], attemptIndex: 1 });
    cases[1].costUsd = 1;
    expect(() => projectResearchExecutionEvidence(hidden)).toThrow(/cover their bound case/);
  });
});
