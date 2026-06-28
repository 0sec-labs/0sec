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
