// Active Directory attack-path analysis.
//
// Offline only: this module reads BloodHound CE / SharpHound JSON that already
// exists on disk and computes attack paths from it. It never collects, never
// authenticates, and never touches a network. See ./types.ts for the full
// scope boundary.

import {
  AD_ANALYZERS,
  findAclAbuseChains,
  findAdcsEscalation,
  findDcsyncPrincipals,
  findKerberoastablePaths,
  findPathsToDomainAdmin,
  findUnconstrainedDelegation,
} from "./analyzers.js";
import type { AdAnalyzerOptions } from "./analyzers.js";
import type {
  AdAnalyzerId,
  AdFinding,
  AdGraph,
  AdGraphAnalysis,
  AdGraphAnalysisSummary,
  AdSeverity,
} from "./types.js";

export type {
  AdAnalyzerId,
  AdEdge,
  AdEdgeKind,
  AdFinding,
  AdGraph,
  AdGraphAnalysis,
  AdGraphAnalysisSummary,
  AdGraphMeta,
  AdNode,
  AdNodeKind,
  AdProperties,
  AdSeverity,
  AttackPath,
  AttackPathStep,
  KnownAdEdgeKind,
  KnownAdNodeKind,
} from "./types.js";

export type { AdIngestChunk } from "./ingest.js";
export { buildAdGraph, ingestBloodHoundFiles, ingestBloodHoundJson, parseBloodHoundFile } from "./ingest.js";

export type { TraversalOptions } from "./paths.js";
export {
  AD_EDGE_TECHNIQUES,
  buildAttackPath,
  describeEdgeTechnique,
  nodeOrStub,
  reachableFrom,
  reachableTo,
  shortestPaths,
} from "./paths.js";

export type { AdAnalyzerOptions } from "./analyzers.js";
export {
  AD_ANALYZERS,
  domainAdminGroupIds,
  findAclAbuseChains,
  findAdcsEscalation,
  findDcsyncPrincipals,
  findKerberoastablePaths,
  findPathsToDomainAdmin,
  findUnconstrainedDelegation,
  highValueTargetIds,
} from "./analyzers.js";

const SEVERITY_RANK: Record<AdSeverity, number> = { info: 1, low: 2, medium: 3, high: 4, critical: 5 };

function summarize(findings: AdFinding[]): AdGraphAnalysisSummary {
  const principals = new Set<string>();
  const analyzersFired = new Set<AdAnalyzerId>();
  let topSeverity: AdSeverity = "info";
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  for (const item of findings) {
    analyzersFired.add(item.analyzer);
    for (const principal of item.affectedPrincipals) principals.add(principal);
    if (SEVERITY_RANK[item.severity] > SEVERITY_RANK[topSeverity]) topSeverity = item.severity;
    if (item.severity === "critical") criticalCount += 1;
    else if (item.severity === "high") highCount += 1;
    else if (item.severity === "medium") mediumCount += 1;
    else if (item.severity === "low") lowCount += 1;
  }

  return {
    findingCount: findings.length,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    topSeverity,
    analyzersFired: [...analyzersFired],
    affectedPrincipalCount: principals.size,
  };
}

/**
 * Run every analyzer over an already-ingested graph and return a single sorted
 * report. Pure: the same graph and options always produce the same findings,
 * modulo `generatedAt`.
 *
 * An analyzer that throws is contained — the failure is recorded on the graph
 * metadata and the remaining analyzers still run, because a single malformed
 * corner of a collection should not cost the whole report.
 */
export function runAdGraphAnalysis(graph: AdGraph, opts: AdAnalyzerOptions = {}): AdGraphAnalysis {
  const findings: AdFinding[] = [];
  const warnings = [...graph.meta.warnings];

  for (const analyzer of AD_ANALYZERS) {
    try {
      findings.push(...analyzer(graph, opts));
    } catch (error) {
      warnings.push(`analyzer ${analyzer.name} failed: ${(error as Error).message}`);
    }
  }

  findings.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      (a.paths[0]?.length ?? Number.MAX_SAFE_INTEGER) - (b.paths[0]?.length ?? Number.MAX_SAFE_INTEGER) ||
      a.id.localeCompare(b.id),
  );

  return {
    generatedAt: new Date().toISOString(),
    graph: { ...graph.meta, warnings },
    summary: summarize(findings),
    findings,
  };
}

/** Convenience: the analyzers keyed by id, for callers that select a subset. */
export const AD_ANALYZERS_BY_ID: Record<AdAnalyzerId, (graph: AdGraph, opts?: AdAnalyzerOptions) => AdFinding[]> = {
  "paths-to-domain-admin": findPathsToDomainAdmin,
  "kerberoastable-paths": findKerberoastablePaths,
  "unconstrained-delegation": findUnconstrainedDelegation,
  "dcsync-principals": findDcsyncPrincipals,
  "acl-abuse-chains": findAclAbuseChains,
  "adcs-escalation": findAdcsEscalation,
};
