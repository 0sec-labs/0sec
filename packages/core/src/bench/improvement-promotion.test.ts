import { describe, expect, it } from "vitest";

import {
  appendImprovementLedgerEntry,
  DEFAULT_IMPROVEMENT_PROMOTION_POLICY,
  evaluateImprovementPromotion,
  verifyImprovementLedger,
  type ImprovementCandidate,
} from "./improvement-promotion.js";
import type { ResearchImprovementResult, ResearchScoreSnapshot } from "./improvement.js";

const BASE_DIGEST = `sha256:${"a".repeat(64)}`;
const CANDIDATE_DIGEST = `sha256:${"b".repeat(64)}`;
const EVALUATOR_DIGEST = `sha256:${"c".repeat(64)}`;

function score(successRate: number, falsePositiveRate: number, costPerSuccessUsd = 1): ResearchScoreSnapshot {
  return {
    cases: 10,
    successRate,
    successRateCI95: [Math.max(0, successRate - 0.1), Math.min(1, successRate + 0.1)],
    falsePositiveRate,
    costPerSuccessUsd,
    inconclusiveRate: 0,
  };
}

function result(overrides: Partial<ResearchImprovementResult> = {}): ResearchImprovementResult {
  return {
    schemaVersion: 1,
    candidateId: "candidate-1",
    manifestId: "improvement-v1",
    developmentCorpusDigest: BASE_DIGEST,
    heldOutCorpusDigest: BASE_DIGEST,
    negativeControlCorpusDigest: BASE_DIGEST,
    evaluatorDigestBefore: EVALUATOR_DIGEST,
    evaluatorDigestAfter: EVALUATOR_DIGEST,
    ciPassed: true,
    development: {
      champion: score(0.5, 0.02),
      challenger: score(0.56, 0.02),
    },
    heldOut: {
      champion: score(0.5, 0.02),
      challenger: score(0.54, 0.02, 1.2),
    },
    negativeControls: {
      champion: { cases: 10, falsePositiveRate: 0.02, inconclusiveRate: 0 },
      challenger: { cases: 10, falsePositiveRate: 0.03, inconclusiveRate: 0 },
    },
    evidenceRefs: ["artifact:sealed-evaluation.json"],
    ...overrides,
  };
}

function candidate(kind: ImprovementCandidate["kind"], sealedResult = result()): ImprovementCandidate {
  return {
    schemaVersion: 1,
    candidateId: "candidate-1",
    kind,
    baseArtifactDigest: BASE_DIGEST,
    candidateArtifactDigest: CANDIDATE_DIGEST,
    result: sealedResult,
  };
}

describe("evaluateImprovementPromotion", () => {
  it("makes policy candidates eligible only for a later canary", () => {
    const decision = evaluateImprovementPromotion(candidate("policy"));

    expect(decision.status).toBe("eligible_for_canary");
    expect(decision.checks.every((check) => check.passed)).toBe(true);
    expect(decision.decisionDigest).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("never auto-promotes executable source candidates", () => {
    const decision = evaluateImprovementPromotion(candidate("source"));

    expect(decision.status).toBe("requires_human_approval");
    expect(decision.checks.every((check) => check.passed)).toBe(true);
  });

  it("fails closed on held-out regression, precision loss, or evaluator drift", () => {
    const rejectedResult = result({
      evaluatorDigestAfter: CANDIDATE_DIGEST,
      heldOut: {
        champion: score(0.5, 0.02),
        challenger: score(0.45, 0.02, 1.2),
      },
      negativeControls: {
        champion: { cases: 10, falsePositiveRate: 0.02, inconclusiveRate: 0 },
        challenger: { cases: 10, falsePositiveRate: 0.12, inconclusiveRate: 0 },
      },
    });

    const decision = evaluateImprovementPromotion(candidate("policy", rejectedResult));

    expect(decision.status).toBe("rejected");
    expect(decision.checks.find((check) => check.id === "evaluator_stability")?.passed).toBe(false);
    expect(decision.checks.find((check) => check.id === "held_out_lift")?.passed).toBe(false);
    expect(decision.checks.find((check) => check.id === "negative_control_precision")?.passed).toBe(false);
  });

  it("requires enough sealed observations in every lane", () => {
    const undersized = result({
      development: {
        champion: { ...score(0.5, 0.02), cases: DEFAULT_IMPROVEMENT_PROMOTION_POLICY.minimumCases - 1 },
        challenger: score(0.56, 0.02),
      },
    });

    const decision = evaluateImprovementPromotion(candidate("policy", undersized));

    expect(decision.status).toBe("rejected");
    expect(decision.checks.find((check) => check.id === "sample_size")?.passed).toBe(false);
  });
});

describe("improvement ledger", () => {
  it("chains candidate and decision records and detects tampering", () => {
    const recorded = appendImprovementLedgerEntry([], {
      occurredAt: "2026-08-21T00:00:00.000Z",
      type: "candidate_recorded",
      candidateId: "candidate-1",
      payloadDigest: BASE_DIGEST,
    });
    const decided = appendImprovementLedgerEntry([recorded], {
      occurredAt: "2026-08-21T00:01:00.000Z",
      type: "promotion_decided",
      candidateId: "candidate-1",
      payloadDigest: CANDIDATE_DIGEST,
    });

    expect(verifyImprovementLedger([recorded, decided])).toEqual({ valid: true });
    expect(verifyImprovementLedger([recorded, { ...decided, candidateId: "tampered" }])).toMatchObject({
      valid: false,
      reason: "invalid entry digest at 1",
    });
  });
});
