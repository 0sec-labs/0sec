export type IntelSeverity = "critical" | "high" | "medium" | "low" | "info";

export type IntelSource = "osv" | "nvd" | "cisa-kev" | "github";

export interface IntelReference {
  url: string;
  kind?: string;
  source?: IntelSource;
}

export interface IntelPackage {
  ecosystem: string;
  name: string;
}

export interface IntelCvss {
  score?: number;
  vector?: string;
  version?: string;
}

export interface IntelKev {
  knownExploited: boolean;
  dateAdded?: string;
  dueDate?: string;
  requiredAction?: string;
  ransomwareUse?: string;
  vulnerabilityName?: string;
}

export interface VulnerabilityIntel {
  id: string;
  aliases: string[];
  source: IntelSource;
  sources: IntelSource[];
  summary?: string;
  details?: string;
  package?: IntelPackage;
  affectedRanges: string[];
  fixedVersions: string[];
  severity: IntelSeverity;
  cvss?: IntelCvss;
  cwes: string[];
  references: IntelReference[];
  kev?: IntelKev;
  publishedAt?: string;
  modifiedAt?: string;
  fetchedAt: string;
}

export interface AdvisorySearchInput {
  ecosystem: string;
  packageName: string;
  version?: string;
  enrich?: boolean;
  cacheDir?: string;
  offline?: boolean;
  ttlMs?: number;
}

export interface IntelDossierInput extends AdvisorySearchInput {
  keywords?: string[];
  similarLimit?: number;
  includeSimilar?: boolean;
}

export interface CveLookupInput {
  cveId: string;
  cacheDir?: string;
  offline?: boolean;
  ttlMs?: number;
}

export interface SimilarSearchInput {
  cwe?: string;
  ecosystem?: string;
  keywords?: string[];
  limit?: number;
  cacheDir?: string;
  offline?: boolean;
  ttlMs?: number;
}

export interface TargetHistorySearchInput {
  target?: string;
  repoPath?: string;
  repository?: string;
  ecosystem?: string;
  packageName?: string;
  product?: string;
  vendor?: string;
  keywords?: string[];
  limit?: number;
  cacheDir?: string;
  offline?: boolean;
  ttlMs?: number;
}

export interface IntelGraphNode {
  id: string;
  kind: "advisory" | "package" | "version" | "cwe" | "reference" | "kev";
  key: string;
  title?: string;
  data?: Record<string, unknown>;
}

export interface IntelGraphEdge {
  from: string;
  to: string;
  kind:
    | "HAS_ALIAS"
    | "AFFECTS_PACKAGE"
    | "FIXED_IN"
    | "MAPS_TO_CWE"
    | "REFERENCES"
    | "KNOWN_EXPLOITED";
  data?: Record<string, unknown>;
}

export interface IntelGraphSnapshot {
  nodes: IntelGraphNode[];
  edges: IntelGraphEdge[];
}

export interface IntelVariantLead {
  id: string;
  aliases: string[];
  severity: IntelSeverity;
  cwes: string[];
  summary?: string;
  reason: string;
  references: IntelReference[];
}

export interface IntelInvestigationStep {
  id: string;
  title: string;
  rationale: string;
  actions: string[];
  expectedEvidence: string[];
}

export interface IntelPriorVulnerabilityPlaybook {
  id: string;
  bugClass: string;
  cwes: string[];
  priorVulnerabilityIds: string[];
  relevance: string;
  steps: IntelInvestigationStep[];
}

export interface IntelPriorVulnerabilityAuditNode {
  id: string;
  kind: "prior_vulnerability" | "bug_class" | "investigation_step" | "evidence_query";
  key: string;
  title?: string;
  data?: Record<string, unknown>;
}

export interface IntelPriorVulnerabilityAuditEdge {
  from: string;
  to: string;
  kind: "INFORMS" | "HAS_STEP" | "NEXT_STEP" | "SEEKS_EVIDENCE";
  data?: Record<string, unknown>;
}

export interface IntelPriorVulnerabilityAuditGraph {
  entrypointNodeIds: string[];
  nodes: IntelPriorVulnerabilityAuditNode[];
  edges: IntelPriorVulnerabilityAuditEdge[];
}

export interface IntelDossierSummary {
  advisoryCount: number;
  variantLeadCount: number;
  playbookCount: number;
  criticalCount: number;
  highCount: number;
  kevCount: number;
  cweCount: number;
  topSeverity: IntelSeverity;
  riskScore: number;
  riskLevel: "none" | "low" | "medium" | "high" | "critical";
  recommendedFocus: string[];
}

export interface IntelDossier {
  package: IntelPackage;
  version?: string;
  generatedAt: string;
  summary: IntelDossierSummary;
  advisories: VulnerabilityIntel[];
  variantLeads: IntelVariantLead[];
  playbooks: IntelPriorVulnerabilityPlaybook[];
  auditGraph: IntelPriorVulnerabilityAuditGraph;
  graph: IntelGraphSnapshot;
  provenance: {
    sources: IntelSource[];
    offline?: boolean;
  };
}

export interface IntelTargetHistorySummary {
  advisoryCount: number;
  playbookCount: number;
  criticalCount: number;
  highCount: number;
  kevCount: number;
  cweCount: number;
  topSeverity: IntelSeverity;
  matchedHints: string[];
}

export interface IntelTargetHistory {
  target: {
    target?: string;
    repoPath?: string;
    repository?: string;
    ecosystem?: string;
    packageName?: string;
    product?: string;
    vendor?: string;
    keywords: string[];
  };
  generatedAt: string;
  summary: IntelTargetHistorySummary;
  advisories: VulnerabilityIntel[];
  playbooks: IntelPriorVulnerabilityPlaybook[];
  auditGraph: IntelPriorVulnerabilityAuditGraph;
  graph: IntelGraphSnapshot;
  provenance: {
    sources: IntelSource[];
    offline?: boolean;
  };
}

export interface FetchOptions {
  timeoutMs?: number;
  headers?: Record<string, string>;
  fetchImpl?: typeof fetch;
}
