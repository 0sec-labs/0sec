// Microsoft Entra ID attack-path graph — node/edge taxonomy.
//
// The traversal engine is NOT reimplemented here. `../../adgraph/paths.ts` is a
// multi-source/multi-target label-setting search that was already generic over
// its node and edge types in everything but the type parameters; adding those
// parameters (with the AD shapes as defaults) let this module reuse it verbatim
// rather than fork a second Dijkstra. So:
//
//   - `EntraNode` / `EntraEdge` extend `AdNode` / `AdEdge`. The base types
//     already accept any `string` kind, so the extension only narrows the kind
//     unions — no field is redefined and no AD code path changes.
//   - `EntraGraph` is `AdGraph<EntraNode, EntraEdge>` with richer metadata.
//   - `EntraAttackPath` is `AttackPath<EntraNode, EntraEdge>`.
//
// The written abuse technique per edge kind lives in `./edges.ts`, mirroring
// `AD_EDGE_TECHNIQUES`.

import type { AdEdge, AdGraph, AdGraphMeta, AdNode, AttackPath, AttackPathStep } from "../../adgraph/types.js";
import type { AffectedPrincipal, IdentitySeverity } from "../types.js";

/**
 * Node kinds, named after the AzureHound / BloodHound CE Azure taxonomy so an
 * operator who knows one reads the other without a translation table.
 *
 * `AZTenant` is the terminal target: reaching it means tenant-wide control.
 * `AZRole` covers directory roles; an AU-scoped assignment gets its own role
 * node (see `EntraNode.scopeId`) so a scoped admin never inherits the
 * tenant-wide role's abuse edges.
 */
export type KnownEntraNodeKind =
  | "AZUser"
  | "AZGroup"
  | "AZServicePrincipal"
  | "AZApp"
  | "AZDevice"
  | "AZAdministrativeUnit"
  | "AZRole"
  | "AZTenant";

/** Same tolerance rationale as `AdNodeKind`: unknown kinds stay addressable. */
export type EntraNodeKind = KnownEntraNodeKind | (string & {});

/**
 * Edge kinds. Every one is directional `source -> target` and means "the source
 * can take the target over, or inherits what the target holds". Getting a
 * direction backwards inverts every path, so each is documented in
 * `AZ_EDGE_TECHNIQUES`.
 */
export type KnownEntraEdgeKind =
  // structure
  | "AZMemberOf"
  | "AZHasRole"
  | "AZContains"
  | "AZOwns"
  | "AZRunsAs"
  // object takeover
  | "AZAddSecret"
  | "AZAddOwner"
  | "AZAddMember"
  | "AZResetPassword"
  // role-derived control
  | "AZGlobalAdmin"
  | "AZPrivilegedRoleAdmin"
  | "AZPrivilegedAuthAdmin"
  | "AZAppAdmin"
  | "AZCloudAppAdmin"
  // consent / app-role grant abuse
  | "AZGrantRole";

export type EntraEdgeKind = KnownEntraEdgeKind | (string & {});

/**
 * A directory object. `objectId` is the Graph object id, lower-cased — Graph
 * emits lower-case GUIDs and AzureHound emits upper-case ones, and a graph that
 * mixes the two silently loses every edge that crosses the boundary.
 *
 * Role nodes are keyed on the role *template* id (stable across every tenant,
 * and the id `TIER0_ROLE_TEMPLATE_IDS` is written against), falling back to the
 * definition id for custom roles.
 */
export interface EntraNode extends AdNode {
  kind: EntraNodeKind;
  /**
   * Set on role nodes that are scoped to an administrative unit. A scoped role
   * node deliberately carries none of the tenant-wide abuse edges its unscoped
   * twin does.
   */
  scopeId?: string;
}

export interface EntraEdge extends AdEdge {
  kind: EntraEdgeKind;
}

export interface EntraGraphMeta extends AdGraphMeta {
  tenantId: string;
  tenantDisplayName?: string;
  /** Where the graph came from — a live snapshot or an offline export. */
  origin: "tenant-snapshot" | "azurehound";
  /**
   * False when the snapshot carried no `relationships`. Membership and
   * ownership edges are then absent, so an empty path list is a gap in
   * collection, not a clean tenant — every consumer has to say so.
   */
  relationshipsCollected: boolean;
  counts: {
    users: number;
    groups: number;
    servicePrincipals: number;
    applications: number;
    devices: number;
    administrativeUnits: number;
    roles: number;
  };
}

export type EntraGraph = AdGraph<EntraNode, EntraEdge> & { meta: EntraGraphMeta };

export type EntraAttackPath = AttackPath<EntraNode, EntraEdge>;
export type EntraAttackPathStep = AttackPathStep<EntraNode, EntraEdge>;

/** One per analyzer in `./analyzers.ts`. Mirrors `AdAnalyzerId`. */
export type EntraPathAnalyzerId =
  | "entra-paths-to-global-admin"
  | "entra-service-principal-escalation"
  | "entra-consent-grant-escalation"
  | "entra-owner-chain-abuse"
  | "entra-guest-escalation";

/**
 * A path-analysis finding. Deliberately shaped like `AdFinding` (an attack path
 * is the evidence) but carrying the identity module's `IdentitySeverity` and
 * `AffectedPrincipal`, so a report can merge these with the 27 posture checks
 * without a second severity vocabulary.
 */
export interface EntraPathFinding {
  /** Stable, content-derived id — safe to dedupe across runs. */
  id: string;
  analyzer: EntraPathAnalyzerId;
  title: string;
  severity: IdentitySeverity;
  description: string;
  /** Supporting attack paths, shortest first. */
  paths: EntraAttackPath[];
  affectedPrincipals: AffectedPrincipal[];
  remediation: string;
  evidence?: Record<string, unknown>;
}

export interface EntraPathAnalysisSummary {
  findingCount: number;
  bySeverity: Record<IdentitySeverity, number>;
  topSeverity: IdentitySeverity;
  analyzersFired: EntraPathAnalyzerId[];
  affectedPrincipalCount: number;
  /** Distinct attack paths across every finding. */
  pathCount: number;
  /** Hop count of the shortest path in the whole report, if any. */
  shortestPathLength?: number;
}

export interface EntraPathAnalysis {
  generatedAt: string;
  graph: EntraGraphMeta;
  summary: EntraPathAnalysisSummary;
  findings: EntraPathFinding[];
}
