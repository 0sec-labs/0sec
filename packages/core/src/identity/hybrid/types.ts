// Hybrid identity attack-path graph — node/edge taxonomy for the seam between
// on-premises Active Directory and Microsoft Entra ID.
//
// Scope boundary (deliberate, do not widen without an ADR): this module never
// touches a network, never runs a collector, and never authenticates to a
// domain or a tenant. It joins two graphs that were each built offline —
// `../../adgraph/` from SharpHound/BloodHound JSON, `../entra-graph/` from a
// tenant snapshot or an AzureHound export — and computes attack paths across
// the join. Everything here is a pure function over two in-memory graphs.
//
// The traversal engine is NOT reimplemented. `../../adgraph/paths.ts` is already
// generic over its node and edge types, and `../entra-graph/` established the
// pattern of instantiating it with a second directory model. This module is the
// third instantiation, and the first one whose graph spans both:
//
//   - `HybridNode` / `HybridEdge` extend `AdNode` / `AdEdge`, so `AdGraph`,
//     `shortestPaths`, `reachableTo` and `buildAttackPath` all apply verbatim.
//   - `HybridGraph` is `AdGraph<HybridNode, HybridEdge>` with join metadata.
//
// Node ids are re-keyed on merge. An AD objectId (`S-1-5-21-…`, upper-cased) and
// an Entra objectId (a lower-cased GUID) cannot literally collide today, but
// depending on letter case to keep two directories apart is not a property worth
// betting a client report on — and a reader of a path needs to see which side of
// the boundary each hop is on. So every id is prefixed: `ad:<objectId>` and
// `aad:<objectId>`. `HybridNode.plane` and `HybridNode.sourceObjectId` carry the
// decomposition for anyone correlating back to the source graph.

import type { AdEdge, AdGraph, AdGraphMeta, AdNode, AttackPath, AttackPathStep } from "../../adgraph/types.js";
import type { AffectedPrincipal, IdentitySeverity } from "../types.js";

/** Which directory a node was collected from. */
export type IdentityPlane = "on-prem" | "cloud";

/**
 * Edge kinds this module contributes. Every AD edge kind and every Entra edge
 * kind also appears in a hybrid graph, unchanged — these are only the ones that
 * span the boundary.
 *
 * Direction is `source -> target` and means "control of the source yields
 * control of the target", exactly as in the two source modules.
 */
export type KnownHybridEdgeKind =
  /** On-premises principal -> the cloud object it is synchronised to. */
  | "SyncsTo"
  /**
   * Cloud object -> the on-premises principal it was synchronised from. This is
   * the correspondence read backwards, and it is NOT freely traversable:
   * compromising a cloud account does not by itself yield the on-premises one.
   * It becomes a real hop only where writeback is configured, which is why the
   * default traversal profile denies it and `HybridGraph.meta.writeback` records
   * whether anything justified enabling it.
   */
  | "SyncedFrom"
  /**
   * On-premises Entra Connect connector account -> the cloud identity it
   * authenticates as. The cloud credential is stored on the Connect server and
   * is recoverable by whoever controls that account.
   */
  | "SyncAccountFor"
  /**
   * On-premises sync account -> the tenant. Password-hash sync means this
   * account can replicate every credential in the domain and assert them into
   * the tenant. Emitted only when the account was identified on strong evidence.
   */
  | "PasswordHashSync"
  /**
   * The `AZUREADSSOACC$` computer account -> the tenant. Its Kerberos key signs
   * seamless-SSO service tickets, so holding it forges cloud authentication for
   * any synchronised user. The key is never rotated by default.
   */
  | "SeamlessSsoForge";

export type HybridEdgeKind = KnownHybridEdgeKind | (string & {});

/**
 * The attribute that established a correspondence, ordered by how much weight it
 * carries. The distinction is load-bearing: `immutable-id` is the anchor Entra
 * Connect itself joins on, whereas `upn` is a guess that a forest-boundary
 * collision can turn into an attack path that does not exist.
 */
export type HybridJoinSignal =
  | "immutable-id"
  | "security-identifier"
  | "distinguished-name"
  | "upn"
  | "mail";

/**
 * How much a correspondence can be relied on.
 *
 * `high` — a directory-synchronisation anchor (`onPremisesImmutableId` matched
 *   to `objectGUID`/`mS-DS-ConsistencyGuid`, or `onPremisesSecurityIdentifier`
 *   matched to `objectSid`). Entra populated the attribute from the on-premises
 *   object itself; the join is a fact, not an inference.
 * `medium` — the on-premises distinguished name. Authoritative in practice but
 *   stale after an object move, and not what Connect keys on.
 * `low` — a UPN or mail-address match and nothing else. A heuristic. UPN
 *   collision across a forest boundary is real, and a false join here invents a
 *   hybrid attack path. Findings built on `low` correspondences say so in their
 *   text; consumers must not render them identically to the rest.
 */
export type HybridJoinConfidence = "high" | "medium" | "low";

/** One established on-premises <-> cloud identity correspondence. */
export interface HybridCorrespondence {
  /** AD objectId, as it appears in the source AD graph (not prefixed). */
  adObjectId: string;
  /** Entra objectId, as it appears in the source Entra graph (not prefixed). */
  entraObjectId: string;
  adLabel: string;
  entraLabel: string;
  confidence: HybridJoinConfidence;
  /** Every signal that agreed, best first. Never empty. */
  signals: HybridJoinSignal[];
  /**
   * True when the only supporting signal is a heuristic one (`upn` / `mail`).
   * The single flag a report renderer needs in order to caveat this row.
   */
  heuristic: boolean;
  /** `onPremisesSyncEnabled` as reported on the cloud object, when collected. */
  syncEnabled?: boolean;
  /** Human-readable justification, e.g. `onPremisesImmutableId -> objectGUID`. */
  rationale: string;
}

/**
 * A correspondence that was found but deliberately NOT turned into an edge.
 *
 * These are reported, not discarded. "Three cloud accounts share a UPN with the
 * same on-premises user, so no join was made" is a materially different sentence
 * from silence, and it is the sentence that stops a reader concluding the two
 * directories are unrelated.
 */
export interface HybridJoinConflict {
  signal: HybridJoinSignal;
  /** The attribute value that matched more than once, or matched nothing usable. */
  value: string;
  adObjectIds: string[];
  entraObjectIds: string[];
  reason: string;
}

/** Per-signal collection coverage — the "not collected" vs "not present" split. */
export interface HybridSignalCoverage {
  /** AD objects carrying the on-premises half of this signal. */
  adObjectsCarrying: number;
  /** Entra objects carrying the cloud half of this signal. */
  entraObjectsCarrying: number;
  /** Correspondences this signal supported. */
  matches: number;
}

/**
 * Everything the join did and could not do.
 *
 * `../entra-graph/ingest.ts` sets the precedent this follows: an empty result
 * that reads as "no hybrid paths exist" is a false negative in a client report,
 * so an absent correspondence signal is stated loudly rather than inferred away.
 */
export interface HybridJoinReport {
  /** True when at least one correspondence was established. */
  joined: boolean;
  correspondences: HybridCorrespondence[];
  byConfidence: Record<HybridJoinConfidence, number>;
  /** Matches rejected as ambiguous or contradicted, with the reason. */
  conflicts: HybridJoinConflict[];
  signalCoverage: Record<HybridJoinSignal, HybridSignalCoverage>;
  /**
   * Prominent statements about what could not be determined. Rendered verbatim.
   * When `joined` is false this is never empty.
   */
  gaps: string[];
  warnings: string[];
}

/** An account on the sync path between the two directories. */
export type HybridSyncRole =
  /** `MSOL_*` / `AAD_*` — the AD DS connector account Connect uses on-premises. */
  | "ad-connector"
  /** `Sync_<host>_<hex>` — the cloud identity Connect authenticates to Entra as. */
  | "cloud-sync-identity"
  /** `AZUREADSSOACC$` — the seamless-SSO computer account. */
  | "seamless-sso";

export interface HybridSyncAccount {
  /** Prefixed hybrid node id. */
  nodeId: string;
  plane: IdentityPlane;
  label: string;
  role: HybridSyncRole;
  /** Why this object was classified as a sync account. Never empty. */
  evidence: string[];
  /**
   * True when the classification rests on naming convention alone. A renamed
   * connector account is missed and a decoy named `MSOL_x` is a false positive,
   * so the distinction is carried rather than flattened.
   */
  nameOnly: boolean;
}

/** Writeback directions, and how each was established. */
export interface HybridWritebackState {
  password: boolean;
  group: boolean;
  device: boolean;
  /** How each enabled direction was determined. Empty when none are enabled. */
  evidence: string[];
}

export interface HybridNode extends AdNode {
  plane: IdentityPlane;
  /** The objectId in the source graph, before the `ad:` / `aad:` prefix. */
  sourceObjectId: string;
}

export interface HybridEdge extends AdEdge {
  kind: HybridEdgeKind;
}

export interface HybridGraphMeta extends AdGraphMeta {
  /** Metadata of the two graphs that were merged, verbatim. */
  onPrem: AdGraphMeta;
  cloud: AdGraphMeta;
  tenantId?: string;
  join: HybridJoinReport;
  syncAccounts: HybridSyncAccount[];
  writeback: HybridWritebackState;
  counts: {
    onPremNodes: number;
    cloudNodes: number;
    /** Edges that cross the boundary. Zero means the join found nothing. */
    bridgeEdges: number;
  };
}

export type HybridGraph = AdGraph<HybridNode, HybridEdge> & { meta: HybridGraphMeta };

export type HybridAttackPath = AttackPath<HybridNode, HybridEdge>;
export type HybridAttackPathStep = AttackPathStep<HybridNode, HybridEdge>;

/** One per analyzer in `./analyzers.ts`. Mirrors `EntraPathAnalyzerId`. */
export type HybridPathAnalyzerId =
  | "hybrid-onprem-to-cloud-admin"
  | "hybrid-cloud-to-onprem-writeback"
  | "hybrid-sync-account-compromise"
  | "hybrid-multi-boundary-crossing"
  | "hybrid-correspondence-gap";

/**
 * A hybrid finding. Shaped like `EntraPathFinding` so the three attack-path
 * modules and the 27 posture checks share one severity vocabulary and one
 * principal shape, with two additions the boundary makes necessary.
 */
export interface HybridPathFinding {
  id: string;
  analyzer: HybridPathAnalyzerId;
  title: string;
  severity: IdentitySeverity;
  description: string;
  paths: HybridAttackPath[];
  affectedPrincipals: AffectedPrincipal[];
  remediation: string;
  /**
   * The weakest correspondence any supporting path depends on. `low` means the
   * finding rests on a UPN guess and must be rendered with that caveat.
   * Undefined when the finding crosses no correspondence edge.
   */
  joinConfidence?: HybridJoinConfidence;
  /** Boundary crossings in the shortest supporting path. */
  boundaryCrossings?: number;
  evidence?: Record<string, unknown>;
}

export interface HybridPathAnalysisSummary {
  findingCount: number;
  bySeverity: Record<IdentitySeverity, number>;
  topSeverity: IdentitySeverity;
  analyzersFired: HybridPathAnalyzerId[];
  affectedPrincipalCount: number;
  pathCount: number;
  shortestPathLength?: number;
  /** Findings resting on a `low`-confidence (heuristic) correspondence. */
  heuristicFindingCount: number;
}

export interface HybridPathAnalysis {
  generatedAt: string;
  graph: HybridGraphMeta;
  summary: HybridPathAnalysisSummary;
  findings: HybridPathFinding[];
  /**
   * Lifted out of `graph.join` to the top level on purpose. A consumer that
   * renders `findings` and ignores everything else must still be handed the
   * reason an empty finding list might not mean a clean environment.
   */
  correspondence: HybridJoinReport;
}
