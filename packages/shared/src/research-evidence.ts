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

/** Privilege boundary under which dynamic evidence was produced. */
export interface ResearchExecutionContext {
  privilege: "zero-cap" | "privileged" | "unknown";
  basis: "runtime-attested" | "runner-contract" | "campaign-config" | "declared";
  realUid?: number;
  effectiveUid?: number;
  /** Linux CapEff-style hexadecimal bitmap, when runtime-attested. */
  effectiveCapabilities?: string;
  /** True only when PR_SET_NO_NEW_PRIVS was observed at the execution boundary. */
  noNewPrivileges?: boolean;
  /** Artifact containing the runtime identity/capability capture. */
  attestationArtifact?: { ref: string; sha256: string };
  sandbox?: string;
  campaignId?: string;
  configDigest?: string;
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
  executionContext?: ResearchExecutionContext;
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

/** Fail-closed: configured sandboxes are not proof of a zero-cap trigger. */
export function researchZeroCapProven(envelope: ResearchEvidenceEnvelope): boolean {
  const context = envelope.executionContext;
  return context?.privilege === "zero-cap"
    && context.basis === "runtime-attested"
    && researchGradeAtLeast(envelope.grade, "reproduced")
    && Number.isSafeInteger(context.realUid)
    && (context.realUid ?? 0) > 0
    && Number.isSafeInteger(context.effectiveUid)
    && (context.effectiveUid ?? 0) > 0
    && /^[0]{16}$/.test(context.effectiveCapabilities ?? "")
    && context.noNewPrivileges === true
    && Boolean(context.attestationArtifact?.ref)
    && /^[a-f0-9]{64}$/.test(context.attestationArtifact?.sha256 ?? "");
}

/** LPE-specific publication gate: proof, novelty, and zero-cap context must all pass. */
export function researchLpeDisclosureReady(envelope: ResearchEvidenceEnvelope): boolean {
  return researchDisclosureReady(envelope) && researchZeroCapProven(envelope);
}
