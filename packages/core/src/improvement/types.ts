import type { NativeMessage, NativeRuntimeResult, NativeToolDef } from "../runtime/types.js";
import type { ImprovementPromotionDecision, ImprovementPromotionPolicy } from "../bench/improvement-promotion.js";
import type { ResearchImprovementResult } from "../bench/improvement.js";

export type EvolutionLane = "development" | "held-out" | "negative-control";
export type EvolutionArtifactKind = "source" | "skill" | "router" | "lens";

/** Expected answers remain in the controller, never in candidate/model input. */
export interface EvolutionCase {
  id: string;
  lane: EvolutionLane;
  input: unknown;
  expected: unknown;
}

/** Operator-owned contract. Neither a generated patch nor a target can edit it. */
export interface EvolutionConfig {
  schemaVersion: 1;
  sourceRoot: string;
  storePath: string;
  image: string;
  sourcePaths: string[];
  editablePaths: string[];
  kind: EvolutionArtifactKind;
  command: string[];
  buildCommand?: string[];
  cases: EvolutionCase[];
  repeats: number;
  maxIterations: number;
  maxModelTurns: number;
  maxModelCostUsd: number;
  maxEvaluationCostUsd: number;
  computeUsdPerSecond: number;
  timeoutMs: number;
  memoryMb: number;
  cpus: number;
  maxOutputBytes: number;
  maxSourceBytes: number;
  maxChangedBytes: number;
  model?: string;
  objective: string;
  /** Explicit permission to submit the selected engine source to the configured model. */
  allowModelSourceAccess: boolean;
  /** Allows passing source candidates to advance without per-candidate approval. */
  autoPromote: boolean;
  canaryTrials: number;
  promotionPolicy: ImprovementPromotionPolicy;
}

export interface EvolutionFile {
  path: string;
  digest: string;
  bytes: number;
}

export interface EvolutionSnapshot {
  id: string;
  root: string;
  digest: string;
  files: EvolutionFile[];
}

export interface EvolutionEdit {
  path: string;
  /** Null only when creating a new file. */
  beforeDigest: string | null;
  /** Null deletes an existing allowlisted file. */
  content: string | null;
}

export interface EvolutionProposal {
  rationale: string;
  edits: EvolutionEdit[];
  modelCostUsd: number;
}

export interface EvolutionExecution {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  error?: string;
}

export interface EvolutionSandboxRequest {
  snapshot: EvolutionSnapshot;
  config: EvolutionConfig;
  input: unknown;
  signal?: AbortSignal;
}

export type EvolutionSandbox = (request: EvolutionSandboxRequest) => Promise<EvolutionExecution>;
export type EvolutionModel = (
  system: string,
  messages: NativeMessage[],
  tools: NativeToolDef[],
  signal?: AbortSignal,
) => Promise<NativeRuntimeResult>;

export interface EvolutionAttempt {
  caseId: string;
  lane: EvolutionLane;
  repeat: number;
  matched: boolean;
  inconclusive: boolean;
  costUsd: number;
  execution: EvolutionExecution;
}

export interface EvolutionEvaluation {
  schemaVersion: 1;
  candidateId: string;
  baselineDigest: string;
  candidateDigest: string;
  configDigest: string;
  attempts: { baseline: EvolutionAttempt[]; candidate: EvolutionAttempt[] };
  result: ResearchImprovementResult;
  decision: ImprovementPromotionDecision;
  receiptDigest: string;
}

export interface EvolutionVersion {
  schemaVersion: 1;
  id: string;
  kind: EvolutionArtifactKind;
  snapshot: EvolutionSnapshot;
  parentId: string | null;
  createdAt: string;
  configDigest: string;
  receiptDigest: string | null;
  status: "baseline" | "candidate" | "canary" | "active" | "retired";
}

export interface EvolutionRegistry {
  schemaVersion: 1;
  activeId: string | null;
  canaryId: string | null;
  versions: EvolutionVersion[];
  events: EvolutionRegistryEvent[];
}

export interface EvolutionRegistryEvent {
  sequence: number;
  at: string;
  type: "recorded" | "canary_started" | "promoted" | "rolled_back";
  versionId: string;
  reason: string;
  previousDigest: string | null;
  digest: string;
}

export interface EvolutionRunResult {
  iterations: Array<{
    candidateId: string;
    rationale: string;
    decision: ImprovementPromotionDecision;
    state: "rejected" | "awaiting_approval" | "promoted" | "rolled_back";
    receiptPath: string;
  }>;
  activeVersionId: string;
  modelCostUsd: number;
  evaluationCostUsd: number;
}

export interface EvolutionDependencies {
  model?: EvolutionModel;
  sandbox?: EvolutionSandbox;
  signal?: AbortSignal;
  log?: (message: string) => void;
  /** Parent run pins the version once; child runIds reuse the same pinned version across the engagement. */
  parentRunId?: string;
  /** Controller-owned output validation invoked on parsed JSON before execution record publication. Throw to record failure — no findings. */
  validateExecutionOutput?: (output: unknown) => void;
}
