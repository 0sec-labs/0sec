export type SpecInvariantKind =
  | "range"
  | "length"
  | "ordering"
  | "state"
  | "rejection"
  | "canonicalization"
  | "requirement";

export interface SpecCitation {
  spec: string;
  section?: string;
  lineStart: number;
  lineEnd: number;
  text: string;
}

export interface SpecInvariant {
  id: string;
  kind: SpecInvariantKind;
  summary: string;
  rule: string;
  subject?: string;
  citations: SpecCitation[];
  securityRelevance: "low" | "medium" | "high";
}

export interface SpecdriftExtractResult {
  mode: "specdrift";
  stage: "extract";
  spec: string;
  invariants: SpecInvariant[];
  warnings: string[];
}

export interface ImplementationCandidate {
  invariantId: string;
  file: string;
  lineStart: number;
  lineEnd: number;
  snippet: string;
  matchedTerms: string[];
  reason: string;
  confidence: number;
  status: "candidate";
}

export interface SpecdriftScanResult {
  mode: "specdrift";
  stage: "scan";
  spec: string;
  source: string;
  invariants: SpecInvariant[];
  candidates: ImplementationCandidate[];
  warnings: string[];
}

export type SpecdriftAdapterKind = "raw-bytes" | "request-response" | "stateful-transcript" | "kernel-repro" | "unit-test";

export interface DriftHypothesis {
  id: string;
  invariantId: string;
  candidateFile: string;
  candidateLineStart: number;
  candidateLineEnd: number;
  question: string;
  suggestedAdapter: SpecdriftAdapterKind;
  rationale: string;
  status: "hypothesis";
  confidence: number;
}

export interface SpecdriftPlanResult extends Omit<SpecdriftScanResult, "stage"> {
  stage: "plan";
  hypotheses: DriftHypothesis[];
}

export interface ExtractSpecInvariantsOptions {
  specName: string;
  specText: string;
  maxInvariants?: number;
}

export interface MapInvariantsToImplementationOptions {
  sourceRoot: string;
  invariants: SpecInvariant[];
  maxFiles?: number;
  maxCandidatesPerInvariant?: number;
}

export interface RunSpecdriftScanOptions {
  specName: string;
  specText: string;
  sourceRoot: string;
  maxInvariants?: number;
  maxFiles?: number;
  maxCandidatesPerInvariant?: number;
}

export interface PlanSpecdriftHypothesesOptions {
  scan: SpecdriftScanResult;
  maxHypotheses?: number;
}

export interface RunSpecdriftPlanOptions extends RunSpecdriftScanOptions {
  maxHypotheses?: number;
}
