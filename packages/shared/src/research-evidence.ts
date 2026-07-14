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

export interface WindowsTokenRunCapture {
  case: "target" | "control";
  trial: number;
  runNonce: string;
  captureNonce: string;
  buildLabEx: string;
  campaignId: string;
  workerId: string;
  configDigest: string;
  scopeManifestSha256: string;
  workerAcceptanceSha256: string;
  workerAcceptanceNonce: string;
  executionGrantNonce: string;
  captureArtifact: { ref: string; sha256: string };
  startToken: WindowsTokenSnapshot;
  finishToken: WindowsTokenSnapshot;
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
  workerAcceptanceArtifact: { ref: string; sha256: string };
  /** Raw per-run captures; aggregate counts below must be derived from these rows. */
  runCaptures: WindowsTokenRunCapture[];
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
  expectedKind?: string,
): boolean {
  if (typeof artifact !== "object" || artifact === null
    || typeof artifact.ref !== "string" || !artifact.ref
    || typeof artifact.sha256 !== "string" || !SHA256.test(artifact.sha256)
    || !Array.isArray(envelope.artifacts)) return false;
  const candidates = envelope.artifacts.filter((candidate) => (
    typeof candidate === "object" && candidate !== null
      && typeof candidate.path === "string"
      && typeof candidate.sha256 === "string"
      && typeof candidate.kind === "string"
  ));
  const matchingPath = candidates.filter((candidate) => candidate.path === artifact.ref);
  return matchingPath.length === 1
    && matchingPath[0]!.sha256.toLowerCase() === artifact.sha256
    && (expectedKind === undefined || matchingPath[0]!.kind === expectedKind)
    && candidates.filter((candidate) => (
      candidate.sha256.toLowerCase() === artifact.sha256
    )).length === 1;
}

const SID = /^S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}$/;
const TOKEN_ID = /^[A-Za-z0-9_-]{16,128}$/;
const RUN_NONCE = /^[A-Za-z0-9_-]{32,128}$/;
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

function coherentTokenSnapshot(token: unknown): token is WindowsTokenSnapshot {
  if (typeof token !== "object" || token === null) return false;
  const candidate = token as WindowsTokenSnapshot;
  return TOKEN_ID.test(candidate.tokenId)
    && SID.test(candidate.userSid)
    && Number.isSafeInteger(candidate.integrityRid)
    && candidate.integrityRid >= 0
    && (["default", "limited", "full"] as unknown[]).includes(candidate.elevationType)
    && typeof candidate.elevated === "boolean"
    && (["absent", "deny-only", "enabled"] as unknown[]).includes(candidate.adminGroup)
    && typeof candidate.appContainer === "boolean"
    && Number.isSafeInteger(candidate.restrictedSidCount)
    && candidate.restrictedSidCount >= 0
    && Array.isArray(candidate.enabledPrivileges)
    && candidate.enabledPrivileges.length <= 128
    && candidate.enabledPrivileges.every((privilege) => (
      typeof privilege === "string" && PRIVILEGE.test(privilege)
    ))
    && new Set(candidate.enabledPrivileges).size === candidate.enabledPrivileges.length;
}

function equalTokenSnapshot(left: WindowsTokenSnapshot, right: WindowsTokenSnapshot): boolean {
  return left.tokenId === right.tokenId
    && left.userSid === right.userSid
    && left.integrityRid === right.integrityRid
    && left.elevationType === right.elevationType
    && left.elevated === right.elevated
    && left.adminGroup === right.adminGroup
    && left.appContainer === right.appContainer
    && left.restrictedSidCount === right.restrictedSidCount
    && left.enabledPrivileges.length === right.enabledPrivileges.length
    && left.enabledPrivileges.every((privilege, index) => privilege === right.enabledPrivileges[index]);
}

function unprivilegedWindowsToken(token: WindowsTokenSnapshot): boolean {
  return token.integrityRid <= 0x2100
    && !token.elevated
    && token.elevationType !== "full"
    && token.adminGroup !== "enabled"
    && (token.appContainer || token.restrictedSidCount > 0 || token.adminGroup === "absent")
    && !token.enabledPrivileges.some((privilege) => DANGEROUS_WINDOWS_PRIVILEGES.has(privilege));
}

function validWindowsStart(
  startingContext: WindowsTokenTransitionAttestation["startingContext"],
  token: WindowsTokenSnapshot,
): boolean {
  if (startingContext === "lpac") return false;
  if (startingContext === "standard-user") {
    return !token.appContainer && token.restrictedSidCount === 0;
  }
  if (startingContext === "appcontainer") return token.appContainer;
  return token.appContainer || token.restrictedSidCount > 0;
}

function validWindowsFinish(
  principal: WindowsTokenTransitionAttestation["finishingPrincipal"],
  start: WindowsTokenSnapshot,
  finish: WindowsTokenSnapshot,
): boolean {
  if (finish.appContainer || finish.restrictedSidCount !== 0) return false;
  if (principal === "local-system") {
    return finish.userSid === "S-1-5-18"
      && finish.integrityRid >= 0x4000
      && finish.elevated
      && finish.elevationType === "default";
  }
  return finish.userSid === start.userSid
    && finish.integrityRid >= 0x3000
    && finish.elevated
    && finish.elevationType === "full"
    && finish.adminGroup === "enabled";
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
    || typeof transition !== "object"
    || transition === null
    || transition.claimEligible !== true
    || transition.fixture !== false
    || !envelope.target.kind.startsWith("windows.")
    || !context.campaignId
    || transition.campaignId !== context.campaignId
    || !SHA256.test(context.configDigest ?? "")
    || envelope.target.configDigest !== context.configDigest
    || typeof transition.buildLabEx !== "string"
    || !transition.buildLabEx.trim()
    || transition.buildLabEx.length > 256
    || transition.buildLabEx !== envelope.target.buildId
    || typeof transition.workerId !== "string"
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
    || !Array.isArray(transition.runCaptures)
    || transition.runCaptures.length < 4
    || transition.runCaptures.length > 128
    || !coherentTokenSnapshot(transition.startToken)
    || !coherentTokenSnapshot(transition.finishToken)
    || transition.startToken.tokenId === transition.finishToken.tokenId
    || context.attestationArtifact?.ref === transition.receiptArtifact?.ref
    || context.attestationArtifact?.ref === transition.workerAcceptanceArtifact?.ref
    || transition.receiptArtifact?.ref === transition.workerAcceptanceArtifact?.ref
    || !retainedArtifact(envelope, context.attestationArtifact, "windows_token_transition")
    || !retainedArtifact(envelope, transition.receiptArtifact, "windows_evidence_receipt")
    || !retainedArtifact(
      envelope,
      transition.workerAcceptanceArtifact,
      "windows_worker_acceptance",
    )) {
    return false;
  }
  const start = transition.startToken;
  const finish = transition.finishToken;
  const runNonces = new Set<string>();
  const captureNonces = new Set<string>();
  const tokenIds = new Set<string>();
  const captureDigests = new Set<string>();
  const caseTrials = new Set<string>();
  let targetTrials = 0;
  let cleanControls = 0;
  let acceptanceSha = "";
  let acceptanceNonce = "";
  let grantNonce = "";
  for (const rawCapture of transition.runCaptures) {
    if (typeof rawCapture !== "object" || rawCapture === null) return false;
    const capture = rawCapture as WindowsTokenRunCapture;
    if (!(capture.case === "target" || capture.case === "control")
      || !Number.isSafeInteger(capture.trial)
      || capture.trial < 1
      || !RUN_NONCE.test(capture.runNonce)
      || !RUN_NONCE.test(capture.captureNonce)
      || !RUN_NONCE.test(capture.workerAcceptanceNonce)
      || !RUN_NONCE.test(capture.executionGrantNonce)
      || capture.runNonce === capture.captureNonce
      || capture.workerAcceptanceNonce === capture.executionGrantNonce
      || capture.runNonce === capture.workerAcceptanceNonce
      || capture.runNonce === capture.executionGrantNonce
      || capture.captureNonce === capture.workerAcceptanceNonce
      || capture.captureNonce === capture.executionGrantNonce
      || capture.buildLabEx !== transition.buildLabEx
      || capture.campaignId !== transition.campaignId
      || capture.workerId !== transition.workerId
      || capture.configDigest !== context.configDigest
      || capture.scopeManifestSha256 !== transition.scopeManifestSha256
      || capture.workerAcceptanceSha256 !== transition.workerAcceptanceArtifact.sha256
      || !coherentTokenSnapshot(capture.startToken)
      || !coherentTokenSnapshot(capture.finishToken)
      || capture.startToken.tokenId === capture.finishToken.tokenId
      || !retainedArtifact(envelope, capture.captureArtifact, "windows_token_capture")
      || runNonces.has(capture.runNonce)
      || runNonces.has(capture.captureNonce)
      || captureNonces.has(capture.captureNonce)
      || captureNonces.has(capture.runNonce)
      || captureDigests.has(capture.captureArtifact.sha256)
      || caseTrials.has(`${capture.case}:${capture.trial}`)
      || tokenIds.has(capture.startToken.tokenId)
      || tokenIds.has(capture.finishToken.tokenId)
      || !validWindowsStart(transition.startingContext, capture.startToken)
      || !unprivilegedWindowsToken(capture.startToken)) {
      return false;
    }
    if (acceptanceSha && acceptanceSha !== capture.workerAcceptanceSha256) return false;
    if (acceptanceNonce && acceptanceNonce !== capture.workerAcceptanceNonce) return false;
    if (grantNonce && grantNonce !== capture.executionGrantNonce) return false;
    acceptanceSha = capture.workerAcceptanceSha256;
    acceptanceNonce = capture.workerAcceptanceNonce;
    grantNonce = capture.executionGrantNonce;
    runNonces.add(capture.runNonce);
    captureNonces.add(capture.captureNonce);
    captureDigests.add(capture.captureArtifact.sha256);
    caseTrials.add(`${capture.case}:${capture.trial}`);
    tokenIds.add(capture.startToken.tokenId);
    tokenIds.add(capture.finishToken.tokenId);
    if (capture.case === "target") {
      if (!validWindowsFinish(
        transition.finishingPrincipal,
        capture.startToken,
        capture.finishToken,
      )) return false;
      targetTrials += 1;
    } else {
      if (!validWindowsStart(transition.startingContext, capture.finishToken)
        || !unprivilegedWindowsToken(capture.finishToken)
        || capture.finishToken.userSid !== capture.startToken.userSid) return false;
      cleanControls += 1;
    }
  }
  const targets = transition.runCaptures
    .filter((capture) => capture.case === "target")
    .sort((left, right) => left.trial - right.trial);
  const controls = transition.runCaptures
    .filter((capture) => capture.case === "control")
    .sort((left, right) => left.trial - right.trial);
  if (!targets.every((capture, index) => capture.trial === index + 1)
    || !controls.every((capture, index) => capture.trial === index + 1)) return false;
  const firstTarget = targets[0];
  return targetTrials === transition.targetTrials
    && cleanControls === transition.cleanControls
    && targetTrials >= 2
    && cleanControls >= 2
    && Boolean(firstTarget)
    && equalTokenSnapshot(start, firstTarget!.startToken)
    && equalTokenSnapshot(finish, firstTarget!.finishToken);
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
