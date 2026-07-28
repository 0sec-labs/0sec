// Hybrid identity attack-path analysis — public surface.
//
// `../analyzers.ts` answers "what is misconfigured in the tenant".
// `../entra-graph/` answers "what can be reached in the cloud, and how".
// `../../adgraph/` answers the same question for on-premises Active Directory.
// This module answers the one neither of them can: what can be reached by
// starting in one directory and finishing in the other.
//
// That gap is not academic. In a hybrid estate the on-premises engagement ends
// at the synchronisation boundary and the tenant engagement starts on the far
// side of it, so a path that crosses is invisible to both — each half looks like
// an accepted risk in isolation. Joining the two graphs is the only way the path
// becomes a finding.
//
// Offline by construction: both input graphs were built offline, the join
// compares attributes already present on them, and every analyzer is a pure
// function over the merged result. Nothing here touches a network, runs a
// collector, or authenticates to a domain or a tenant.

import type { IdentitySeverity } from "../types.js";
import { HYBRID_PATH_ANALYZERS, type HybridPathAnalyzerOptions } from "./analyzers.js";
import type {
  HybridGraph,
  HybridPathAnalysis,
  HybridPathAnalysisSummary,
  HybridPathAnalyzerId,
  HybridPathFinding,
} from "./types.js";

export type {
  HybridAttackPath,
  HybridAttackPathStep,
  HybridCorrespondence,
  HybridEdge,
  HybridEdgeKind,
  HybridGraph,
  HybridGraphMeta,
  HybridJoinConfidence,
  HybridJoinConflict,
  HybridJoinReport,
  HybridJoinSignal,
  HybridNode,
  HybridPathAnalysis,
  HybridPathAnalysisSummary,
  HybridPathAnalyzerId,
  HybridPathFinding,
  HybridSignalCoverage,
  HybridSyncAccount,
  HybridSyncRole,
  HybridWritebackState,
  IdentityPlane,
  KnownHybridEdgeKind,
} from "./types.js";

export { describeHybridEdge, describeHybridEdgeTechnique, HYBRID_EDGE_TECHNIQUES } from "./edges.js";

export {
  adAnchors,
  decodeImmutableId,
  entraAnchors,
  joinDirectories,
  normalizeGuid,
  type HybridJoinOptions,
} from "./join.js";

export {
  detectWriteback,
  findCloudSyncAccounts,
  findOnPremSyncAccounts,
  writebackEnabled,
  type HybridSyncOptions,
} from "./sync.js";

export {
  adNodeId,
  boundaryCrossings,
  buildHybridGraph,
  entraNodeId,
  indexHybridGraph,
  splitHybridId,
  type BuildHybridGraphOptions,
} from "./build.js";

export {
  findHybridCloudToOnPremWriteback,
  findHybridCorrespondenceGaps,
  findHybridMultiBoundaryCrossings,
  findHybridOnPremToCloudAdmin,
  findHybridSyncAccountCompromise,
  hybridCloudPrivilegedRoleIds,
  hybridCloudTier0Ids,
  hybridOnPremHighValueIds,
  hybridPrincipalOf,
  HYBRID_PATH_ANALYZERS,
  HYBRID_PATH_ANALYZERS_BY_ID,
  pathJoinConfidence,
  type HybridPathAnalyzerOptions,
} from "./analyzers.js";

const SEVERITY_ORDER: readonly IdentitySeverity[] = ["critical", "high", "medium", "low", "info"];

/**
 * Run every hybrid path analyzer and wrap the findings in a report envelope.
 *
 * Same contract as `runEntraPathAnalysis`: findings ordered by severity so the
 * worst thing found leads, ties broken by shortest path because hop count is the
 * best proxy for how close a path is to being exploited. The clock is injectable
 * so a fixture is reproducible.
 *
 * Two additions the boundary makes necessary.
 *
 * `summary.heuristicFindingCount` counts findings whose evidence rests on a
 * `low`-confidence correspondence. A consumer that renders a hybrid section
 * needs to know, before it renders anything, whether the section is built on
 * directory-synchronisation anchors or on user-principal-name guesses.
 *
 * `correspondence` lifts `graph.meta.join` to the top level. It is duplicated on
 * purpose: a consumer that renders `findings` and ignores everything else must
 * still be handed the reason an empty finding list might not mean a clean
 * estate. An empty hybrid section reads as "no cross-boundary attack paths
 * exist", and this module is never in a position to assert that.
 */
export function runHybridPathAnalysis(
  graph: HybridGraph,
  opts: HybridPathAnalyzerOptions = {},
  now: () => Date = () => new Date(),
): HybridPathAnalysis {
  const findings: HybridPathFinding[] = [];
  for (const analyzer of HYBRID_PATH_ANALYZERS) {
    findings.push(...analyzer(graph, opts));
  }

  const rank = (s: IdentitySeverity): number => {
    const i = SEVERITY_ORDER.indexOf(s);
    return i === -1 ? SEVERITY_ORDER.length : i;
  };
  findings.sort((a, b) => {
    const bySeverity = rank(a.severity) - rank(b.severity);
    if (bySeverity !== 0) return bySeverity;
    const aLen = a.paths[0]?.length ?? Number.MAX_SAFE_INTEGER;
    const bLen = b.paths[0]?.length ?? Number.MAX_SAFE_INTEGER;
    return aLen - bLen || a.id.localeCompare(b.id);
  });

  const bySeverity = SEVERITY_ORDER.reduce(
    (acc, s) => ({ ...acc, [s]: 0 }),
    {} as Record<IdentitySeverity, number>,
  );
  const principals = new Set<string>();
  const analyzersFired = new Set<HybridPathAnalyzerId>();
  let pathCount = 0;
  let shortestPathLength: number | undefined;
  let heuristicFindingCount = 0;

  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    analyzersFired.add(f.analyzer);
    for (const p of f.affectedPrincipals) principals.add(p.id);
    if (f.joinConfidence === "low") heuristicFindingCount += 1;
    pathCount += f.paths.length;
    for (const p of f.paths) {
      if (shortestPathLength === undefined || p.length < shortestPathLength) {
        shortestPathLength = p.length;
      }
    }
  }

  const summary: HybridPathAnalysisSummary = {
    findingCount: findings.length,
    bySeverity,
    topSeverity: findings[0]?.severity ?? "info",
    analyzersFired: [...analyzersFired],
    affectedPrincipalCount: principals.size,
    pathCount,
    ...(shortestPathLength !== undefined ? { shortestPathLength } : {}),
    heuristicFindingCount,
  };

  return {
    generatedAt: now().toISOString(),
    graph: graph.meta,
    summary,
    findings,
    correspondence: graph.meta.join,
  };
}
