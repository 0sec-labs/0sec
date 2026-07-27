// Active Directory attack-path graph — OFFLINE analysis of collector output.
//
// Scope boundary (deliberate, do not widen without an ADR): this module never
// touches a network, never runs a collector, and never authenticates to a
// domain. It ingests JSON a collector (SharpHound / BloodHound CE) already
// produced and computes attack paths from it. Everything here is a pure
// function over an in-memory graph.

/** Node kinds emitted by BloodHound CE for on-prem AD. */
export type KnownAdNodeKind =
  | "User"
  | "Computer"
  | "Group"
  | "Domain"
  | "GPO"
  | "OU"
  | "Container"
  | "CertTemplate"
  | "CertAuthority"
  | "EnterpriseCA"
  | "RootCA"
  | "AIACA"
  | "NTAuthStore"
  | "IssuancePolicy"
  | "Base";

/**
 * Collectors add node kinds faster than we can enumerate them. The `string`
 * arm keeps unknown kinds addressable instead of dropping them on ingest,
 * while the union arm preserves autocomplete for the known set.
 */
export type AdNodeKind = KnownAdNodeKind | (string & {});

/** Edge kinds from the BloodHound CE taxonomy, grouped by abuse family. */
export type KnownAdEdgeKind =
  // structure / membership
  | "MemberOf"
  | "Contains"
  | "GPLink"
  | "TrustedBy"
  | "DCFor"
  | "HasSIDHistory"
  // lateral movement + execution
  | "AdminTo"
  | "HasSession"
  | "CanRDP"
  | "CanPSRemote"
  | "ExecuteDCOM"
  | "SQLAdmin"
  // object-control ACLs
  | "GenericAll"
  | "GenericWrite"
  | "WriteDacl"
  | "WriteOwner"
  | "Owns"
  | "WriteSPN"
  | "AllExtendedRights"
  | "ForceChangePassword"
  | "AddMember"
  | "AddSelf"
  | "AddKeyCredentialLink"
  | "WriteAccountRestrictions"
  | "WriteGPLink"
  // credential exposure
  | "ReadLAPSPassword"
  | "ReadGMSAPassword"
  | "SyncLAPSPassword"
  | "DumpSMSAPassword"
  // delegation
  | "AllowedToDelegate"
  | "AllowedToAct"
  | "AddAllowedToAct"
  // replication / DCSync
  | "DCSync"
  | "GetChanges"
  | "GetChangesAll"
  | "GetChangesInFilteredSet"
  // ADCS
  | "ADCSESC1"
  | "ADCSESC3"
  | "ADCSESC4"
  | "ADCSESC5"
  | "ADCSESC6a"
  | "ADCSESC6b"
  | "ADCSESC7"
  | "ADCSESC9a"
  | "ADCSESC9b"
  | "ADCSESC10a"
  | "ADCSESC10b"
  | "ADCSESC13"
  | "GoldenCert"
  | "Enroll"
  | "ManageCA"
  | "ManageCertificates"
  | "WritePKIEnrollmentFlag"
  | "WritePKINameFlag"
  | "EnrollOnBehalfOf"
  | "DelegatedEnrollmentAgent"
  | "IssuedSignedBy"
  | "EnterpriseCAFor"
  | "RootCAFor"
  | "NTAuthStoreFor"
  | "TrustedForNTAuth"
  | "HostsCAService"
  | "CanAbuseUPNCertMapping"
  | "CanAbuseWeakCertBinding"
  // coercion relay
  | "CoerceToTGT"
  | "CoerceAndRelayNTLMToADCS"
  | "CoerceAndRelayNTLMToLDAP"
  | "CoerceAndRelayNTLMToLDAPS"
  | "CoerceAndRelayNTLMToSMB";

/** Same tolerance rationale as {@link AdNodeKind}. */
export type AdEdgeKind = KnownAdEdgeKind | (string & {});

/** Free-form collector properties, keys lower-cased on ingest. */
export type AdProperties = Record<string, unknown>;

export interface AdNode {
  /** Security identifier or GUID — the graph's primary key. */
  objectId: string;
  /** Display name, usually `SAMACCOUNTNAME@DOMAIN.TLD`. */
  label: string;
  kind: AdNodeKind;
  /** Domain SID this object belongs to, when the collector reported one. */
  domainSid?: string;
  properties: AdProperties;
  /**
   * True when the node was only ever referenced by another object (a group
   * member, an ACE principal) and never collected in its own right. Stubs are
   * traversable but their properties are empty.
   */
  stub?: boolean;
}

export interface AdEdge {
  /** Traversal origin — the principal that holds the right. */
  source: string;
  /** Traversal destination — the object the right applies to. */
  target: string;
  kind: AdEdgeKind;
  properties?: AdProperties;
}

/**
 * Indexed AD graph. Adjacency is stored as edge *indices* into `edges` rather
 * than edge copies so a 100k-node / 1M-edge graph stays flat in memory and
 * neighbour lookup is O(degree) with no per-hop allocation.
 */
export interface AdGraph {
  nodes: Map<string, AdNode>;
  edges: AdEdge[];
  /** objectId -> indices of edges leaving that node. */
  outbound: Map<string, number[]>;
  /** objectId -> indices of edges entering that node. */
  inbound: Map<string, number[]>;
  /** node kind -> objectIds, so analyzers never scan all nodes per query. */
  nodesByKind: Map<AdNodeKind, string[]>;
  /** edge kind -> indices into `edges`. */
  edgesByKind: Map<AdEdgeKind, number[]>;
  meta: AdGraphMeta;
}

export interface AdGraphMeta {
  /** Collector file types folded into this graph (`users`, `computers`, ...). */
  sourceTypes: string[];
  /** Highest `meta.version` seen across ingested files. */
  collectorVersion?: number;
  nodeCount: number;
  edgeCount: number;
  /** Non-fatal ingest problems — unknown kinds, dropped records, bad shapes. */
  warnings: string[];
  ingestedAt: string;
}

export interface AttackPathStep {
  from: AdNode;
  edge: AdEdge;
  to: AdNode;
  /** One-line description of how this hop is abused. */
  technique: string;
}

export interface AttackPath {
  sourceId: string;
  targetId: string;
  steps: AttackPathStep[];
  /** Hop count. Always `steps.length`; carried explicitly for sorting. */
  length: number;
  /** Sum of edge costs. Equals `length` under the default uniform costing. */
  cost: number;
  /** Ordered edge kinds, e.g. `MemberOf -> GenericAll -> DCSync`. */
  technique: string;
}

export type AdSeverity = "critical" | "high" | "medium" | "low" | "info";

export type AdAnalyzerId =
  | "paths-to-domain-admin"
  | "kerberoastable-paths"
  | "unconstrained-delegation"
  | "dcsync-principals"
  | "acl-abuse-chains"
  | "adcs-escalation";

export interface AdFinding {
  /** Stable, content-derived id — safe to dedupe across runs. */
  id: string;
  analyzer: AdAnalyzerId;
  title: string;
  severity: AdSeverity;
  description: string;
  /** Supporting attack paths, shortest first. May be empty for edge-local findings. */
  paths: AttackPath[];
  /** objectIds of principals implicated by the finding. */
  affectedPrincipals: string[];
  remediation: string;
  evidence?: AdProperties;
}

export interface AdGraphAnalysisSummary {
  findingCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  topSeverity: AdSeverity;
  /** Analyzers that produced at least one finding. */
  analyzersFired: AdAnalyzerId[];
  /** Distinct principals appearing in any finding. */
  affectedPrincipalCount: number;
}

export interface AdGraphAnalysis {
  generatedAt: string;
  graph: AdGraphMeta;
  summary: AdGraphAnalysisSummary;
  findings: AdFinding[];
}
