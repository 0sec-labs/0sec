import { describe, expect, it } from "vitest";

import { parseManifest } from "./manifest.js";
import {
  digestBenchManifest,
  projectResearchImprovementResult,
  type ResearchTournamentRun,
} from "./improvement.js";
import type { BenchScorecard } from "./scorecard.js";
import type { TournamentResult } from "./tournament.js";

function manifest(id: string, knownNegative = false) {
  return parseManifest({
    id,
    cases: [{
      id: `${id}-case`,
      target: { kind: "source-audit", package: id, version: "1.0.0" },
      objective: {
        type: "finding-match",
        vulnClass: "sql-injection",
        sinkMarkers: ["sink"],
      },
      knownNegative,
    }],
  });
}

function scorecard(
  manifestId: string,
  successRate: number,
  fpRate: number,
): BenchScorecard {
  return {
    schemaVersion: 1,
    manifestId,
    config: { passAtK: 1, maxTurns: 10, costCeilingUsd: 1, ciSubset: false },
    totals: {
      cases: 20,
      positives: 20,
      knownNegatives: 0,
      verified: Math.round(successRate * 20),
      refuted: 20 - Math.round(successRate * 20),
      inconclusive: 0,
    },
    successRate,
    successRateCI95: successRate > 0.5 ? [0.6, 0.9] : [0.2, 0.5],
    falsePositives: Math.round(fpRate * 20),
    fpRate,
    totalCostUsd: 20,
    costPerSuccessUsd: successRate === 0 ? null : 2,
    totalAttackTurns: 100,
    byObjective: {},
    cases: [],
  };
}

function run(
  id: string,
  championSuccess: number,
  challengerSuccess: number,
  championFp = 0,
  challengerFp = 0,
  knownNegative = false,
): ResearchTournamentRun {
  const corpus = manifest(id, knownNegative);
  const tournament: TournamentResult = {
    manifestId: id,
    config: {
      passAtK: 1,
      maxTurns: 10,
      costCeilingUsd: 1,
      ciSubset: false,
      variantIds: ["champion", "challenger"],
    },
    variants: [
      { variant: { id: "champion" }, scorecard: scorecard(id, championSuccess, championFp) },
      { variant: { id: "challenger" }, scorecard: scorecard(id, challengerSuccess, challengerFp) },
    ],
    pairwise: [],
    championId: "challenger",
  };
  return { manifest: corpus, tournament };
}

describe("projectResearchImprovementResult", () => {
  it("projects sealed capability and negative-control tournaments separately", () => {
    const development = run("dev", 0.4, 0.8);
    const heldOut = run("held", 0.4, 0.75, 0.9, 0.9);
    const negativeControls = run("negative", 0, 0, 0, 0.1, true);
    const result = projectResearchImprovementResult({
      candidateId: "candidate-1",
      manifestId: "program-v1",
      championVariantId: "champion",
      challengerVariantId: "challenger",
      development,
      heldOut,
      negativeControls,
      evaluatorDigestBefore: "sha256:evaluator",
      evaluatorDigestAfter: "sha256:evaluator",
      ciPassed: true,
      evidenceRefs: ["artifact:tournament.json"],
    });

    expect(result.heldOut.challenger.successRate).toBe(0.75);
    expect(result.negativeControls.challenger.falsePositiveRate).toBe(0.1);
    expect(result.negativeControls.challenger.falsePositiveRate)
      .not.toBe(result.heldOut.challenger.falsePositiveRate);
    expect(result.developmentCorpusDigest).toBe(digestBenchManifest(development.manifest));
  });

  it("fails closed when scorecards are paired with the wrong corpus", () => {
    const development = run("dev", 0.4, 0.8);
    development.tournament.manifestId = "other";
    expect(() => projectResearchImprovementResult({
      candidateId: "candidate-1",
      manifestId: "program-v1",
      championVariantId: "champion",
      challengerVariantId: "challenger",
      development,
      heldOut: run("held", 0.4, 0.8),
      negativeControls: run("negative", 0, 0, 0, 0, true),
      evaluatorDigestBefore: "sha256:evaluator",
      evaluatorDigestAfter: "sha256:evaluator",
      ciPassed: true,
      evidenceRefs: ["artifact:tournament.json"],
    })).toThrow(/does not match/);
  });
});
