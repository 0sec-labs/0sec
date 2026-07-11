import type { EvidenceArtifact, VerificationResult } from "./verification.js";

/** Monotone proof strength. Novelty and disclosure policy are intentionally orthogonal. */
export type ResearchPromotionGrade =
  | "candidate"
  | "reachable"
  | "observed"
  | "reproduced"
  | "impact-proven";

export type ResearchNoveltyState = "unchecked" | "novel" | "duplicate" | "inconclusive";

export interface ResearchTargetIdentity {
  kind: string;
  locator: string;
  version?: string;
  buildId?: string;
  configDigest?: string;
}

export interface ResearchProvenance {
  producer: string;
  runId: string;
  startedAt: string;
  completedAt?: string;
  candidateId?: string;
  candidatePath?: string;
  model?: string;
  attempt?: number;
}

export interface ResearchNoveltyReceipt {
  state: ResearchNoveltyState;
  checkedAt?: string;
  sources?: string[];
  refs?: string[];
  scanned?: number;
}

/**
 * Compatibility envelope around native engine results. Truth strength, novelty,
 * impact and disclosure workflow remain separate dimensions.
 */
export interface ResearchEvidenceEnvelope {
  schemaVersion: 1;
  evidenceId: string;
  findingId: string;
  target: ResearchTargetIdentity;
  provenance: ResearchProvenance;
  grade: ResearchPromotionGrade;
  novelty: ResearchNoveltyReceipt;
  verificationResult?: VerificationResult;
  artifacts: EvidenceArtifact[];
  native?: {
    oracleKind?: string;
    oraclePayload?: unknown;
    huntRecordRef?: string;
    noveltyPayload?: unknown;
    impactPayload?: unknown;
  };
  supersedes?: string[];
}

const GRADE_ORDER: Record<ResearchPromotionGrade, number> = {
  candidate: 0,
  reachable: 1,
  observed: 2,
  reproduced: 3,
  "impact-proven": 4,
};

export function researchGradeAtLeast(
  actual: ResearchPromotionGrade,
  required: ResearchPromotionGrade,
): boolean {
  return GRADE_ORDER[actual] >= GRADE_ORDER[required];
}

/** Fail-closed novelty: zero queried records can never support `novel`. */
export function normalizeResearchNovelty(receipt: ResearchNoveltyReceipt): ResearchNoveltyReceipt {
  if (receipt.state === "novel" && (!receipt.sources?.length || (receipt.scanned ?? 0) <= 0)) {
    return { ...receipt, state: "unchecked" };
  }
  return receipt;
}

export function researchDisclosureReady(envelope: ResearchEvidenceEnvelope): boolean {
  const novelty = normalizeResearchNovelty(envelope.novelty);
  return researchGradeAtLeast(envelope.grade, "reproduced") && novelty.state === "novel";
}
