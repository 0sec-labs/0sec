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

export interface ExtractSpecInvariantsOptions {
  specName: string;
  specText: string;
  maxInvariants?: number;
}
