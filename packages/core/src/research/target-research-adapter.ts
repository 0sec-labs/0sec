import type {
  Finding,
  ResearchEvidenceEnvelope,
  ResearchExecutionContext,
  ResearchNoveltyReceipt,
  ResearchPromotionGrade,
  ResearchReportingPolicy,
} from "@0sec/shared";

export type ResearchStage =
  | "discover"
  | "reachability"
  | "harness"
  | "execute"
  | "verify"
  | "novelty"
  | "impact"
  | "handoff";

export type ResearchStageStatus = "passed" | "failed" | "inconclusive" | "skipped";

export interface ResearchTarget<K extends string = string, C = unknown> {
  kind: K;
  id: string;
  location: string;
  config: C;
  version?: string;
  buildId?: string;
  configDigest?: string;
}

export interface ResearchCandidate<P = unknown> {
  id: string;
  title: string;
  location?: string;
  hypothesis?: string;
  payload: P;
}

/** Additive interoperability record. Native engine payloads remain lossless in data. */
export interface ResearchEvidence<D = unknown> {
  stage: ResearchStage;
  status: ResearchStageStatus;
  summary: string;
  data?: D;
  artifacts?: string[];
  startedAt?: string;
  completedAt?: string;
}

export interface ResearchFinding {
  finding: Finding;
  candidateId: string;
  evidence: ResearchEvidence[];
  grade?: ResearchPromotionGrade;
  novelty?: ResearchNoveltyReceipt;
  executionContext?: ResearchExecutionContext;
  reportingPolicy?: ResearchReportingPolicy;
}

/** A scoped downstream target derived from intake; never a vulnerability finding. */
export interface ResearchHandoff<T extends ResearchTarget = ResearchTarget> {
  sourceCandidateId: string;
  target: T;
  reason: string;
  evidence: ResearchEvidence[];
}

export interface ResearchContext {
  runId: string;
  artifactDir: string;
  signal?: AbortSignal;
  log(message: string): void;
}

export interface ResearchStageResult<T> {
  items: T[];
  evidence?: ResearchEvidence[];
  warnings?: string[];
}

/**
 * Target-specific research capability plugged into the shared stage runner.
 * Discovery and verification are mandatory; every other stage is additive.
 * An adapter must never promote discovery output without verification evidence.
 */
export interface TargetResearchAdapter<
  T extends ResearchTarget = ResearchTarget,
  C extends ResearchCandidate = ResearchCandidate,
  H = unknown,
  X = unknown,
> {
  readonly kind: T["kind"];
  discover(target: T, ctx: ResearchContext): Promise<ResearchStageResult<C>>;
  assessReachability?(target: T, candidates: C[], ctx: ResearchContext): Promise<ResearchStageResult<C>>;
  buildHarness?(target: T, candidates: C[], ctx: ResearchContext): Promise<ResearchStageResult<H>>;
  execute?(target: T, harnesses: H[], ctx: ResearchContext): Promise<ResearchStageResult<X>>;
  verify(
    target: T,
    input: { candidates: C[]; harnesses?: H[]; executions?: X[] },
    ctx: ResearchContext,
  ): Promise<ResearchStageResult<ResearchFinding>>;
  checkNovelty?(target: T, findings: ResearchFinding[], ctx: ResearchContext): Promise<ResearchStageResult<ResearchFinding>>;
  assessImpact?(target: T, findings: ResearchFinding[], ctx: ResearchContext): Promise<ResearchStageResult<ResearchFinding>>;
  deriveTargets?(target: T, candidates: C[], ctx: ResearchContext): Promise<ResearchStageResult<ResearchHandoff>>;
  dispose?(ctx: ResearchContext): Promise<void>;
}

export interface ResearchRunResult<C extends ResearchCandidate = ResearchCandidate> {
  runId: string;
  target: ResearchTarget;
  candidates: C[];
  findings: ResearchFinding[];
  handoffs: ResearchHandoff[];
  envelopes: ResearchEvidenceEnvelope[];
  envelopePath?: string;
  evidence: ResearchEvidence[];
  warnings: string[];
  completed: boolean;
}
