// Entra ID attack-path analysis — public surface.
//
// The 27 posture checks in `../analyzers.ts` answer "what is misconfigured".
// This module answers "what can an attacker reach, and how" — the same
// distinction `../../adgraph/` draws for on-premises Active Directory, and the
// reason both exist: a list of misconfigurations is a backlog, whereas a path
// from a guest account to Global Administrator is a finding someone acts on
// this week.
//
// Two input routes, deliberately:
//   - a live read-only tenant snapshot (`buildEntraGraph`)
//   - an offline AzureHound export (`buildEntraGraphFromAzureHound`)
//
// Neither analysis path touches a network.

import type { IdentitySeverity } from "../types.js";
import { ENTRA_PATH_ANALYZERS, type EntraPathAnalyzerOptions } from "./analyzers.js";
import type {
  EntraGraph,
  EntraPathAnalysis,
  EntraPathAnalyzerId,
  EntraPathFinding,
  EntraPathAnalysisSummary,
} from "./types.js";

export type {
  EntraAttackPath,
  EntraAttackPathStep,
  EntraEdge,
  EntraEdgeKind,
  EntraGraph,
  EntraGraphMeta,
  EntraNode,
  EntraNodeKind,
  EntraPathAnalysis,
  EntraPathAnalysisSummary,
  EntraPathAnalyzerId,
  EntraPathFinding,
  KnownEntraEdgeKind,
  KnownEntraNodeKind,
} from "./types.js";

export { AZ_EDGE_TECHNIQUES, describeEntraEdge, describeEntraEdgeTechnique } from "./edges.js";

export {
  buildEntraGraph,
  grantedPermissionNames,
  holdsHighImpactPermission,
  holdsTier0Permission,
  indexGraph,
  normalizeId,
  roleNodeId,
  tenantNodeId,
  type BuildEntraGraphOptions,
} from "./build.js";

export {
  ENTRA_PATH_ANALYZERS,
  ENTRA_PATH_ANALYZERS_BY_ID,
  findEntraConsentGrantEscalation,
  findEntraGuestEscalation,
  findEntraOwnerChainAbuse,
  findEntraPathsToGlobalAdmin,
  findEntraServicePrincipalEscalation,
  principalOf,
  privilegedPrincipalIds,
  privilegedRoleIds,
  tier0TargetIds,
  type EntraPathAnalyzerOptions,
} from "./analyzers.js";

export {
  buildEntraGraphFromAzureHound,
  ingestAzureHound,
  type AzureHoundIngestResult,
} from "./ingest.js";

const SEVERITY_ORDER: readonly IdentitySeverity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Run every path analyzer and wrap the findings in a report envelope.
 *
 * Findings are ordered by severity so the first thing a reader sees is the
 * worst thing found. The summary carries `shortestPathLength` because hop count
 * is the single best proxy for "how close is this to being exploited" — a
 * two-hop path to Global Administrator is a different conversation from a
 * six-hop one, and a severity label alone does not carry that.
 */
export function runEntraPathAnalysis(
  graph: EntraGraph,
  opts: EntraPathAnalyzerOptions = {},
  now: () => Date = () => new Date(),
): EntraPathAnalysis {
  const findings: EntraPathFinding[] = [];
  for (const analyzer of ENTRA_PATH_ANALYZERS) {
    findings.push(...analyzer(graph, opts));
  }

  const rank = (s: IdentitySeverity): number => {
    const i = SEVERITY_ORDER.indexOf(s);
    return i === -1 ? SEVERITY_ORDER.length : i;
  };
  findings.sort((a, b) => {
    const bySeverity = rank(a.severity) - rank(b.severity);
    if (bySeverity !== 0) return bySeverity;
    // Then shortest path first — the most immediately actionable finding leads.
    const aLen = a.paths[0]?.length ?? Number.MAX_SAFE_INTEGER;
    const bLen = b.paths[0]?.length ?? Number.MAX_SAFE_INTEGER;
    return aLen - bLen;
  });

  const bySeverity = SEVERITY_ORDER.reduce(
    (acc, s) => ({ ...acc, [s]: 0 }),
    {} as Record<IdentitySeverity, number>,
  );
  const principals = new Set<string>();
  const analyzersFired = new Set<EntraPathAnalyzerId>();
  let pathCount = 0;
  let shortestPathLength: number | undefined;

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    analyzersFired.add(f.analyzer);
    for (const p of f.affectedPrincipals) principals.add(p.id);
    pathCount += f.paths.length;
    for (const p of f.paths) {
      if (shortestPathLength === undefined || p.length < shortestPathLength) {
        shortestPathLength = p.length;
      }
    }
  }

  const summary: EntraPathAnalysisSummary = {
    findingCount: findings.length,
    bySeverity,
    topSeverity: findings[0]?.severity ?? "info",
    analyzersFired: [...analyzersFired],
    affectedPrincipalCount: principals.size,
    pathCount,
    ...(shortestPathLength !== undefined ? { shortestPathLength } : {}),
  };

  return { generatedAt: now().toISOString(), graph: graph.meta, summary, findings };
}
