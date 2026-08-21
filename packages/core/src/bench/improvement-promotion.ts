import { createHash } from "node:crypto";

import type { ResearchImprovementResult } from "./improvement.js";

export type ImprovementCandidateKind = "policy" | "source";
export type ImprovementPromotionStatus =
  | "rejected"
  | "eligible_for_canary"
  | "requires_human_approval";

export interface ImprovementPromotionPolicy {
  minimumCases: number;
  minimumDevelopmentLift: number;
  minimumHeldOutLift: number;
  maximumNegativeControlFpDelta: number;
  maximumCostMultiplier: number;
}

/**
 * Conservative initial policy. A candidate is never deployed by this module:
 * policy changes can become eligible for a separately controlled canary, while
 * executable source changes always require an explicit human promotion.
 */
export const DEFAULT_IMPROVEMENT_PROMOTION_POLICY: Readonly<ImprovementPromotionPolicy> = Object.freeze({
  minimumCases: 10,
  minimumDevelopmentLift: 0.05,
  minimumHeldOutLift: 0.03,
  maximumNegativeControlFpDelta: 0.02,
  maximumCostMultiplier: 1.5,
});

export interface ImprovementCandidate {
  schemaVersion: 1;
  candidateId: string;
  kind: ImprovementCandidateKind;
  baseArtifactDigest: string;
  candidateArtifactDigest: string;
  result: ResearchImprovementResult;
}

export interface ImprovementPromotionCheck {
  id:
    | "candidate_identity"
    | "artifact_digests"
    | "ci"
    | "evaluator_stability"
    | "evidence"
    | "sample_size"
    | "development_lift"
    | "held_out_lift"
    | "negative_control_precision"
    | "cost_discipline";
  passed: boolean;
  detail: string;
}

export interface ImprovementPromotionDecision {
  schemaVersion: 1;
  candidateId: string;
  status: ImprovementPromotionStatus;
  checks: ImprovementPromotionCheck[];
  decisionDigest: string;
}

export type ImprovementLedgerEventType = "candidate_recorded" | "promotion_decided";

/**
 * Hash chaining is tamper-evident only when the terminal digest is retained by
 * an independent store. This module intentionally does not claim signatures or
 * immutable storage on its own.
 */
export interface ImprovementLedgerEntry {
  schemaVersion: 1;
  sequence: number;
  occurredAt: string;
  type: ImprovementLedgerEventType;
  candidateId: string;
  payloadDigest: string;
  previousDigest: string | null;
  entryDigest: string;
}

export interface ImprovementLedgerVerification {
  valid: boolean;
  reason?: string;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function isSha256(value: string): boolean {
  return /^sha256:[a-f0-9]{64}$/i.test(value);
}


function metricSampleIsSufficient(result: ResearchImprovementResult, minimumCases: number): boolean {
  return result.development.champion.cases >= minimumCases
    && result.development.challenger.cases >= minimumCases
    && result.heldOut.champion.cases >= minimumCases
    && result.heldOut.challenger.cases >= minimumCases
    && result.negativeControls.champion.cases >= minimumCases
    && result.negativeControls.challenger.cases >= minimumCases;
}

function resultRatesAreFinite(result: ResearchImprovementResult): boolean {
  return [
    result.development.champion.successRate,
    result.development.challenger.successRate,
    result.heldOut.champion.successRate,
    result.heldOut.challenger.successRate,
    result.negativeControls.champion.falsePositiveRate,
    result.negativeControls.challenger.falsePositiveRate,
  ].every((value) => Number.isFinite(value) && value >= 0 && value <= 1);
}

function makeDecision(
  candidateId: string,
  status: ImprovementPromotionStatus,
  checks: ImprovementPromotionCheck[],
): ImprovementPromotionDecision {
  const unsigned = {
    schemaVersion: 1 as const,
    candidateId,
    status,
    checks,
  };
  return {
    ...unsigned,
    decisionDigest: digest(unsigned),
  };
}

/**
 * Evaluate a sealed benchmark result without executing or deploying the
 * candidate. This function is deliberately pure so an untrusted candidate
 * cannot affect the evaluator, its policy, or an active engagement worker.
 */
export function evaluateImprovementPromotion(
  candidate: ImprovementCandidate,
  policy: ImprovementPromotionPolicy = DEFAULT_IMPROVEMENT_PROMOTION_POLICY,
): ImprovementPromotionDecision {
  const result = candidate.result;
  const checks: ImprovementPromotionCheck[] = [];

  checks.push({
    id: "candidate_identity",
    passed: candidate.candidateId.length > 0 && candidate.candidateId === result.candidateId,
    detail: "candidate id must be non-empty and match the sealed research result",
  });
  checks.push({
    id: "artifact_digests",
    passed: isSha256(candidate.baseArtifactDigest)
      && isSha256(candidate.candidateArtifactDigest)
      && candidate.baseArtifactDigest !== candidate.candidateArtifactDigest,
    detail: "base and candidate artifacts must be distinct sha256 digests",
  });
  checks.push({
    id: "ci",
    passed: result.ciPassed,
    detail: "candidate evaluation must carry a passing CI attestation",
  });
  checks.push({
    id: "evaluator_stability",
    passed: isSha256(result.evaluatorDigestBefore)
      && result.evaluatorDigestBefore === result.evaluatorDigestAfter,
    detail: "the evaluator digest must remain stable across the candidate evaluation",
  });
  checks.push({
    id: "evidence",
    passed: result.evidenceRefs.length > 0,
    detail: "candidate evaluation must retain at least one evidence reference",
  });
  checks.push({
    id: "sample_size",
    passed: resultRatesAreFinite(result) && metricSampleIsSufficient(result, policy.minimumCases),
    detail: `every sealed lane must contain at least ${policy.minimumCases} finite observations`,
  });

  const developmentLift = result.development.challenger.successRate - result.development.champion.successRate;
  checks.push({
    id: "development_lift",
    passed: developmentLift >= policy.minimumDevelopmentLift,
    detail: `development success lift ${developmentLift.toFixed(4)} must be at least ${policy.minimumDevelopmentLift.toFixed(4)}`,
  });

  const heldOutLift = result.heldOut.challenger.successRate - result.heldOut.champion.successRate;
  checks.push({
    id: "held_out_lift",
    passed: heldOutLift >= policy.minimumHeldOutLift,
    detail: `held-out success lift ${heldOutLift.toFixed(4)} must be at least ${policy.minimumHeldOutLift.toFixed(4)}`,
  });

  const fpDelta = result.negativeControls.challenger.falsePositiveRate
    - result.negativeControls.champion.falsePositiveRate;
  checks.push({
    id: "negative_control_precision",
    passed: fpDelta <= policy.maximumNegativeControlFpDelta,
    detail: `negative-control FP delta ${fpDelta.toFixed(4)} must not exceed ${policy.maximumNegativeControlFpDelta.toFixed(4)}`,
  });

  const championCost = result.heldOut.champion.costPerSuccessUsd;
  const challengerCost = result.heldOut.challenger.costPerSuccessUsd;
  const costPasses = championCost !== null
    && challengerCost !== null
    && Number.isFinite(championCost)
    && Number.isFinite(challengerCost)
    && challengerCost <= championCost * policy.maximumCostMultiplier;
  checks.push({
    id: "cost_discipline",
    passed: costPasses,
    detail: `held-out cost per success must be available and no more than ${policy.maximumCostMultiplier.toFixed(2)}x champion cost`,
  });

  if (checks.some((check) => !check.passed)) {
    return makeDecision(candidate.candidateId, "rejected", checks);
  }
  return makeDecision(
    candidate.candidateId,
    candidate.kind === "source" ? "requires_human_approval" : "eligible_for_canary",
    checks,
  );
}

export function appendImprovementLedgerEntry(
  entries: readonly ImprovementLedgerEntry[],
  event: Omit<ImprovementLedgerEntry, "schemaVersion" | "sequence" | "previousDigest" | "entryDigest">,
): ImprovementLedgerEntry {
  const verification = verifyImprovementLedger(entries);
  if (!verification.valid) throw new Error(`cannot append to invalid improvement ledger: ${verification.reason}`);
  if (!isSha256(event.payloadDigest)) throw new Error("ledger payloadDigest must be a sha256 digest");

  const previousDigest = entries.length === 0 ? null : entries[entries.length - 1]!.entryDigest;
  const unsigned = {
    schemaVersion: 1 as const,
    sequence: entries.length,
    occurredAt: event.occurredAt,
    type: event.type,
    candidateId: event.candidateId,
    payloadDigest: event.payloadDigest,
    previousDigest,
  };
  return {
    ...unsigned,
    entryDigest: digest(unsigned),
  };
}

export function verifyImprovementLedger(entries: readonly ImprovementLedgerEntry[]): ImprovementLedgerVerification {
  let previousDigest: string | null = null;
  for (const [sequence, entry] of entries.entries()) {
    if (entry.sequence !== sequence) return { valid: false, reason: `unexpected sequence at ${sequence}` };
    if (entry.previousDigest !== previousDigest) return { valid: false, reason: `broken predecessor at ${sequence}` };
    if (!isSha256(entry.payloadDigest)) return { valid: false, reason: `invalid payload digest at ${sequence}` };
    const unsigned = {
      schemaVersion: entry.schemaVersion,
      sequence: entry.sequence,
      occurredAt: entry.occurredAt,
      type: entry.type,
      candidateId: entry.candidateId,
      payloadDigest: entry.payloadDigest,
      previousDigest: entry.previousDigest,
    };
    if (entry.entryDigest !== digest(unsigned)) return { valid: false, reason: `invalid entry digest at ${sequence}` };
    previousDigest = entry.entryDigest;
  }
  return { valid: true };
}
