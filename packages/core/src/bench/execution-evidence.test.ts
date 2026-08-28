import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";

import type { BenchManifest } from "./manifest.js";
import { aggregateScorecard } from "./scorecard.js";
import { pairwiseDeltas, pickChampion, type TournamentResult } from "./tournament.js";
import {
  projectResearchExecutionEvidence,
  researchCandidateChangeDigest,
  researchExecutionEvidenceDigest,
  researchExecutionEvidenceRef,
  researchVariantDescriptorDigest,
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
  it("matches the exact canonical digest independently computed by 0brain (re-pinned 2026-08-19 for the pwnkit → 0sec candidateId rename)", () => {
    const fixture = JSON.parse(
      readFileSync(new URL("./improvement-execution-evidence.fixture.json", import.meta.url), "utf8"),
    ) as ResearchExecutionEvidence;
    expect(researchExecutionEvidenceDigest(fixture)).toBe(
      "sha256:3aefd68fb65588cc9bc27653c6739289fa075a6aaa99da2115228d23470eb864",
    );
  });

  it("binds exact attempts, costs, time, corpora, and artifacts", () => {
    const evidence = projectResearchExecutionEvidence(inputs());
    expect(evidence.measured).toEqual({ totalRuns: 12, totalCostUsd: 6, elapsedMs: 1_500 });
    expect(evidence.lanes.heldOut.caseIds).toEqual(["held-0", "held-1"]);
    expect(researchExecutionEvidenceDigest(evidence)).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(researchExecutionEvidenceRef(evidence)).toMatch(/^execution-evidence:sha256:/);
  });

  it("matches the non-promotable synthetic schema-v3 contract when the candidate matches executed variants", () => {
    const options = inputs();
    for (const lane of [options.development, options.heldOut, options.negativeControls]) {
      lane.run.tournament.variants[1].variant.promptOverrides = {
        "source_audit.hypothesis": "Inspect parser state transitions.",
      };
    }
    const candidateChange = {
      kind: "prompt",
      knobs: { "source_audit.hypothesis": "Inspect parser state transitions." },
    };
    const evidence = projectResearchExecutionEvidence({
      ...options,
      candidateChange,
      producer: {
        repository: "0sec-labs/0sec",
        commitSha: "a".repeat(40),
        treeDigest: `sha256:${"7".repeat(64)}`,
      },
    });
    const contract = JSON.parse(
      readFileSync(new URL("./improvement-execution-evidence-v3.synthetic-fixture.json", import.meta.url), "utf8"),
    ) as {
      schemaVersion: 1;
      contract: string;
      promotable: false;
      evidence: ResearchExecutionEvidence;
    };
    expect(Object.keys(contract).sort()).toEqual(["contract", "evidence", "promotable", "schemaVersion"]);
    expect(contract.contract).toBe("0sec-0brain-execution-evidence-v3-synthetic-golden-v1");
    expect(contract.promotable).toBe(false);
    const golden = contract.evidence;
    expect(evidence).toEqual(golden);
    expect(researchExecutionEvidenceDigest(evidence)).toBe(
      "sha256:3986f9883f5ed4be76488db503eb47c174771f9b099750924742b6a83803cd1b",
    );
    expect(evidence.schemaVersion).toBe(3);
    expect(evidence.variantBinding).toEqual({
      mode: "candidate_change",
      candidateChangeDigest: researchCandidateChangeDigest(candidateChange),
      champion: {
        id: "champion",
        descriptorDigest: researchVariantDescriptorDigest({ id: "champion" }),
      },
      challenger: {
        id: "challenger",
        descriptorDigest: researchVariantDescriptorDigest({
          id: "challenger",
          promptOverrides: { "source_audit.hypothesis": "Inspect parser state transitions." },
        }),
      },
    });
    expect(evidence.variantBinding?.candidateChangeDigest).toBe("sha256:4359282a157b33e32a555db67d0812e5e3fa3fd685d329b1d73b1e0ab8f42089");
    expect(evidence.variantBinding?.champion.descriptorDigest).toBe("sha256:f4aa0a3098a314183c52fe937b59fb7abdd91836ec66646da32050ee59d25b53");
    expect(evidence.variantBinding?.challenger.descriptorDigest).toBe("sha256:6a27c1bc66e5e707b87c79bdab418f81018a3bc9eb47a737e98eb30f85980b72");
  });

  it("rejects lane drift and undeclared executed knobs", () => {
    const drift = inputs();
    drift.development.run.tournament.variants[1].variant.promptOverrides = {
      "source_audit.hypothesis": "Inspect parser state transitions.",
    };
    for (const lane of [drift.heldOut, drift.negativeControls]) {
      lane.run.tournament.variants[1].variant.promptOverrides = {
        "source_audit.hypothesis": "Different prompt.",
      };
    }
    expect(() => projectResearchExecutionEvidence({
      ...drift,
      candidateChange: { kind: "prompt", knobs: { "source_audit.hypothesis": "Inspect parser state transitions." } },
      producer: { repository: "0sec-labs/0sec", commitSha: "a".repeat(40), treeDigest: `sha256:${"7".repeat(64)}` },
    })).toThrow(/drift/);

    const hidden = inputs();
    for (const lane of [hidden.development, hidden.heldOut, hidden.negativeControls]) {
      lane.run.tournament.variants[1].variant.promptOverrides = {
        "source_audit.hypothesis": "Inspect parser state transitions.",
      };
      lane.run.tournament.variants[1].variant.runtime = "codex";
    }
    expect(() => projectResearchExecutionEvidence({
      ...hidden,
      candidateChange: { kind: "prompt", knobs: { "source_audit.hypothesis": "Inspect parser state transitions." } },
      producer: { repository: "0sec-labs/0sec", commitSha: "a".repeat(40), treeDigest: `sha256:${"7".repeat(64)}` },
    })).toThrow(/not exactly/);
  });

  it("rejects unknown flags and requires an explicit champion baseline", () => {
    const options = inputs();
    for (const lane of [options.development, options.heldOut, options.negativeControls]) {
      lane.run.tournament.variants[1].variant.featureFlags = { invented_flag: true };
    }
    expect(() => projectResearchExecutionEvidence({
      ...options,
      candidateChange: { kind: "feature_flag", knobs: { invented_flag: true } },
      producer: { repository: "0sec-labs/0sec", commitSha: "a".repeat(40), treeDigest: `sha256:${"7".repeat(64)}` },
    })).toThrow(/unsupported/);

    const baseline = inputs();
    for (const lane of [baseline.development, baseline.heldOut, baseline.negativeControls]) {
      lane.run.tournament.variants[1].variant.featureFlags = { web_search: true };
    }
    expect(() => projectResearchExecutionEvidence({
      ...baseline,
      candidateChange: { kind: "feature_flag", knobs: { web_search: true } },
      producer: { repository: "0sec-labs/0sec", commitSha: "a".repeat(40), treeDigest: `sha256:${"7".repeat(64)}` },
    })).toThrow(/explicitly bind/);
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
