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

export interface WindowsTokenSnapshot {
  /** Per-capture opaque identity; distinct start/end values prove two snapshots. */
  tokenId: string;
  userSid: string;
  integrityRid: number;
  elevationType: "default" | "limited" | "full";
  elevated: boolean;
  adminGroup: "absent" | "deny-only" | "enabled";
  appContainer: boolean;
  restrictedSidCount: number;
  enabledPrivileges: string[];
}

/**
 * Normalized facts from a retained Windows token-transition attestation.
 * This is evidence metadata, never executable material. The referenced
 * attestation and receipt must also appear in the envelope artifact list.
 */
export interface WindowsTokenTransitionAttestation {
  buildLabEx: string;
  campaignId: string;
  workerId: string;
  startingContext: "standard-user" | "appcontainer" | "lpac" | "eligible-sandbox";
  finishingPrincipal: "elevated-user" | "local-system";
  startToken: WindowsTokenSnapshot;
  finishToken: WindowsTokenSnapshot;
  scopeManifestSha256: string;
  receiptArtifact: { ref: string; sha256: string };
  targetTrials: number;
  cleanControls: number;
  claimEligible: boolean;
  fixture: boolean;
}

export interface ResearchReportingPolicy {
  /** Research evidence may enter human review, but must never submit itself. */
  automaticDisclosure: false;
  humanReviewRequired: true;
  /** Benchmark and public-regression cases are never bounty candidates. */
  benchmarkCase: boolean;
}

/** Privilege boundary under which dynamic evidence was produced. */
export interface ResearchExecutionContext {
  platform?: "linux" | "windows";
  privilege: "zero-cap" | "windows-restricted" | "privileged" | "unknown";
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
  windowsTokenTransition?: WindowsTokenTransitionAttestation;
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
  reportingPolicy?: ResearchReportingPolicy;
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
  return (context?.platform === undefined || context.platform === "linux")
    && context?.privilege === "zero-cap"
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

const SHA256 = /^[a-f0-9]{64}$/;

function retainedArtifact(
  envelope: ResearchEvidenceEnvelope,
  artifact: { ref: string; sha256: string } | undefined,
): boolean {
  if (!artifact?.ref || !SHA256.test(artifact.sha256)) return false;
  return envelope.artifacts.filter((candidate) => candidate.path === artifact.ref
    && candidate.sha256.toLowerCase() === artifact.sha256).length === 1;
}

const SID = /^S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}$/;
const TOKEN_ID = /^[A-Za-z0-9_-]{16,128}$/;
const PRIVILEGE = /^Se[A-Za-z0-9]+Privilege$/;
const DANGEROUS_WINDOWS_PRIVILEGES = new Set([
  "SeDebugPrivilege",
  "SeImpersonatePrivilege",
  "SeAssignPrimaryTokenPrivilege",
  "SeTcbPrivilege",
  "SeBackupPrivilege",
  "SeRestorePrivilege",
  "SeTakeOwnershipPrivilege",
  "SeLoadDriverPrivilege",
]);

function coherentTokenSnapshot(token: WindowsTokenSnapshot): boolean {
  return TOKEN_ID.test(token.tokenId)
    && SID.test(token.userSid)
    && Number.isSafeInteger(token.integrityRid)
    && token.integrityRid >= 0
    && (["default", "limited", "full"] as unknown[]).includes(token.elevationType)
    && typeof token.elevated === "boolean"
    && (["absent", "deny-only", "enabled"] as unknown[]).includes(token.adminGroup)
    && typeof token.appContainer === "boolean"
    && Number.isSafeInteger(token.restrictedSidCount)
    && token.restrictedSidCount >= 0
    && Array.isArray(token.enabledPrivileges)
    && token.enabledPrivileges.length <= 128
    && token.enabledPrivileges.every((privilege) => PRIVILEGE.test(privilege))
    && new Set(token.enabledPrivileges).size === token.enabledPrivileges.length;
}

/**
 * Proves only the Windows token transition. Novelty and reporting policy are
 * deliberately evaluated by the disclosure helper below.
 */
export function researchWindowsTokenTransitionProven(
  envelope: ResearchEvidenceEnvelope,
): boolean {
  const context = envelope.executionContext;
  const transition = context?.windowsTokenTransition;
  if (context?.platform !== "windows"
    || context.privilege !== "windows-restricted"
    || context.basis !== "runtime-attested"
    || !researchGradeAtLeast(envelope.grade, "reproduced")
    || !transition
    || transition.claimEligible !== true
    || transition.fixture !== false
    || !envelope.target.kind.startsWith("windows.")
    || !context.campaignId
    || transition.campaignId !== context.campaignId
    || !SHA256.test(context.configDigest ?? "")
    || !transition.buildLabEx.trim()
    || transition.buildLabEx.length > 256
    || transition.buildLabEx !== envelope.target.buildId
    || !transition.workerId.trim()
    || transition.workerId.length > 256
    || !(["standard-user", "appcontainer", "lpac", "eligible-sandbox"] as unknown[])
      .includes(transition.startingContext)
    || !(["elevated-user", "local-system"] as unknown[]).includes(transition.finishingPrincipal)
    || !SHA256.test(transition.scopeManifestSha256)
    || !Number.isSafeInteger(transition.targetTrials)
    || transition.targetTrials < 2
    || !Number.isSafeInteger(transition.cleanControls)
    || transition.cleanControls < 2
    || !coherentTokenSnapshot(transition.startToken)
    || !coherentTokenSnapshot(transition.finishToken)
    || transition.startToken.tokenId === transition.finishToken.tokenId
    || context.attestationArtifact?.ref === transition.receiptArtifact.ref
    || !retainedArtifact(envelope, context.attestationArtifact)
    || !retainedArtifact(envelope, transition.receiptArtifact)) {
    return false;
  }
  const start = transition.startToken;
  const finish = transition.finishToken;
  const dangerousStartPrivilege = start.enabledPrivileges.some((privilege) => (
    DANGEROUS_WINDOWS_PRIVILEGES.has(privilege)
  ));
  const validStart = transition.startingContext === "standard-user"
    ? !start.appContainer
    : start.appContainer || start.restrictedSidCount > 0;
  const unprivilegedStart = start.integrityRid <= 0x2100
    && !start.elevated
    && start.elevationType !== "full"
    && start.adminGroup !== "enabled"
    && (start.appContainer || start.restrictedSidCount > 0 || start.adminGroup === "absent")
    && !dangerousStartPrivilege;
  const validFinish = transition.finishingPrincipal === "local-system"
    ? finish.userSid === "S-1-5-18" && finish.integrityRid >= 0x4000
    : finish.userSid === start.userSid && finish.adminGroup === "enabled";
  const elevatedFinish = finish.integrityRid >= 0x3000
    && finish.elevated
    && finish.elevationType === "full"
    && (finish.userSid === "S-1-5-18" || finish.adminGroup === "enabled");
  return validStart && unprivilegedStart && validFinish && elevatedFinish;
}

/** Windows LPE report-review gate: proof, novelty, token transition and policy. */
export function researchWindowsLpeDisclosureReady(
  envelope: ResearchEvidenceEnvelope,
): boolean {
  const policy = envelope.reportingPolicy;
  return researchDisclosureReady(envelope)
    && researchWindowsTokenTransitionProven(envelope)
    && policy?.automaticDisclosure === false
    && policy.humanReviewRequired === true
    && policy.benchmarkCase === false;
}

/** Explicit-platform dispatcher. Missing/unknown platform always fails closed. */
export function researchPlatformLpeDisclosureReady(
  envelope: ResearchEvidenceEnvelope,
  platform: "linux" | "windows",
): boolean {
  if (platform !== envelope.executionContext?.platform) return false;
  if (platform === "linux") return researchLpeDisclosureReady(envelope);
  if (platform === "windows") return researchWindowsLpeDisclosureReady(envelope);
  return false;
}
