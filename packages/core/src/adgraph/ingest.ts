import type {
  AdEdge,
  AdEdgeKind,
  AdGraph,
  AdGraphMeta,
  AdNode,
  AdNodeKind,
  AdProperties,
} from "./types.js";

// ---------------------------------------------------------------------------
// Collector file shapes
// ---------------------------------------------------------------------------

/**
 * Two real BloodHound CE JSON shapes are accepted:
 *
 * 1. **Collector output** — one file per object type, each
 *    `{ "data": [ ...objects ], "meta": { "type": "users", "count": n, "version": 6 } }`.
 *    Edges are derived from each object's `Aces`, `Members`, `Sessions`,
 *    `LocalAdmins`, `Trusts`, `ChildObjects`, `Links`, and so on.
 *
 * 2. **Graph export** — the shape the CE API returns for a path query,
 *    `{ "data": { "nodes": { "<gid>": {...} }, "edges": [ { "source": "<gid>", ... } ] } }`.
 *    This is the only route by which post-processed edges (`ADCSESC*`, `DCSync`)
 *    reach us, because the collector never computes them.
 *
 * Anything else parses to an empty chunk plus a warning rather than throwing.
 */
export interface AdIngestChunk {
  nodes: AdNode[];
  edges: AdEdge[];
  sourceType?: string;
  collectorVersion?: number;
  warnings: string[];
}

/** `meta.type` values as emitted by SharpHound / AzureHound file names. */
const FILE_TYPE_TO_NODE_KIND: Record<string, AdNodeKind> = {
  users: "User",
  computers: "Computer",
  groups: "Group",
  domains: "Domain",
  gpos: "GPO",
  ous: "OU",
  containers: "Container",
  certtemplates: "CertTemplate",
  enterprisecas: "EnterpriseCA",
  rootcas: "RootCA",
  aiacas: "AIACA",
  ntauthstores: "NTAuthStore",
  issuancepolicies: "IssuancePolicy",
};

/**
 * Legacy / non-canonical ACE right names. Anything not listed passes through
 * untouched so a new right becomes a first-class edge kind on day one.
 */
const ACE_RIGHT_ALIASES: Record<string, AdEdgeKind> = {
  owner: "Owns",
  all: "GenericAll",
  extendedright: "AllExtendedRights",
  "ds-replication-get-changes": "GetChanges",
  "ds-replication-get-changes-all": "GetChangesAll",
  "ds-replication-get-changes-in-filtered-set": "GetChangesInFilteredSet",
  "user-force-change-password": "ForceChangePassword",
};

/** `Results`-wrapped collections and their edge kind, source-side = principal. */
const PRINCIPAL_TO_COMPUTER_COLLECTIONS: Array<[field: string, kind: AdEdgeKind]> = [
  ["LocalAdmins", "AdminTo"],
  ["RemoteDesktopUsers", "CanRDP"],
  ["DcomUsers", "ExecuteDCOM"],
  ["PSRemoteUsers", "CanPSRemote"],
  ["AllowedToAct", "AllowedToAct"],
];

// ---------------------------------------------------------------------------
// Defensive readers — collector output is user-supplied data, never trusted
// ---------------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim().length > 0) return value.trim();
  return undefined;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/**
 * SharpHound wraps some collections as `{ Collected, FailureReason, Results }`
 * and emits others as bare arrays, depending on collector version. Accept both.
 */
function readResultList(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (isRecord(value)) return asArray(value.Results ?? value.results);
  return [];
}

/** Case-insensitive field read — collector casing drifts between versions. */
function field(record: Record<string, unknown>, ...names: string[]): unknown {
  for (const name of names) {
    if (name in record) return record[name];
    const lower = name.toLowerCase();
    for (const key of Object.keys(record)) {
      if (key.toLowerCase() === lower) return record[key];
    }
  }
  return undefined;
}

/** Lower-case property keys so analyzers can rely on `hasspn`, `admincount`, ... */
function normalizeProperties(value: unknown): AdProperties {
  if (!isRecord(value)) return {};
  const out: AdProperties = {};
  for (const [key, raw] of Object.entries(value)) {
    out[key.toLowerCase()] = raw;
  }
  return out;
}

/** SIDs are case-insensitive; GUID-keyed objects are upper-cased by SharpHound. */
function normalizeObjectId(value: unknown): string | undefined {
  const id = asString(value);
  return id ? id.toUpperCase() : undefined;
}

function normalizeNodeKind(value: unknown, fallback: AdNodeKind): AdNodeKind {
  const kind = asString(value);
  if (!kind) return fallback;
  if (kind.toLowerCase() === "base") return fallback;
  return kind;
}

function normalizeEdgeKind(value: unknown): AdEdgeKind | undefined {
  const kind = asString(value);
  if (!kind) return undefined;
  return ACE_RIGHT_ALIASES[kind.toLowerCase()] ?? kind;
}

// ---------------------------------------------------------------------------
// Chunk accumulation
// ---------------------------------------------------------------------------

class ChunkBuilder {
  readonly nodes: AdNode[] = [];
  readonly edges: AdEdge[] = [];
  readonly warnings: string[] = [];

  node(node: AdNode): void {
    this.nodes.push(node);
  }

  /**
   * Reference to an object we may not have collected. Emitted as a stub node so
   * traversal never dead-ends on a member SID whose own file is missing; a real
   * record for the same id wins during {@link buildAdGraph} merge.
   */
  reference(objectId: string, kind: AdNodeKind, label?: string): void {
    this.nodes.push({
      objectId,
      label: label ?? objectId,
      kind,
      properties: {},
      stub: true,
    });
  }

  edge(source: string, target: string, kind: AdEdgeKind, properties?: AdProperties): void {
    this.edges.push(properties ? { source, target, kind, properties } : { source, target, kind });
  }

  warn(message: string): void {
    if (this.warnings.length < 200) this.warnings.push(message);
  }
}

/**
 * Read an `{ObjectIdentifier, ObjectType}` reference, register a stub for it and
 * return the normalized id.
 */
function readReference(
  builder: ChunkBuilder,
  value: unknown,
  fallbackKind: AdNodeKind,
  idFields: string[] = ["ObjectIdentifier"],
): string | undefined {
  if (typeof value === "string") {
    const id = normalizeObjectId(value);
    if (id) builder.reference(id, fallbackKind);
    return id;
  }
  if (!isRecord(value)) return undefined;
  const id = normalizeObjectId(field(value, ...idFields));
  if (!id) return undefined;
  builder.reference(id, normalizeNodeKind(field(value, "ObjectType", "kind"), fallbackKind));
  return id;
}

// ---------------------------------------------------------------------------
// Collector-object parsing
// ---------------------------------------------------------------------------

function parseCollectorObject(
  builder: ChunkBuilder,
  raw: unknown,
  defaultKind: AdNodeKind,
  index: number,
  sourceType: string,
): void {
  if (!isRecord(raw)) {
    builder.warn(`${sourceType}[${index}]: not an object, skipped`);
    return;
  }
  const objectId = normalizeObjectId(field(raw, "ObjectIdentifier", "objectid"));
  if (!objectId) {
    builder.warn(`${sourceType}[${index}]: missing ObjectIdentifier, skipped`);
    return;
  }

  const properties = normalizeProperties(field(raw, "Properties"));
  const label = asString(properties.name) ?? asString(properties.distinguishedname) ?? objectId;
  const domainSid = normalizeObjectId(properties.domainsid) ?? (defaultKind === "Domain" ? objectId : undefined);

  builder.node({
    objectId,
    label,
    kind: normalizeNodeKind(field(raw, "ObjectType"), defaultKind),
    ...(domainSid ? { domainSid } : {}),
    properties,
  });

  parseAces(builder, raw, objectId, sourceType, index);
  parseMembership(builder, raw, objectId);
  parseComputerCollections(builder, raw, objectId);
  parseDelegation(builder, raw, objectId);
  parseContainment(builder, raw, objectId, defaultKind);
  parseTrusts(builder, raw, objectId);
}

function parseAces(
  builder: ChunkBuilder,
  raw: Record<string, unknown>,
  objectId: string,
  sourceType: string,
  index: number,
): void {
  for (const ace of asArray(field(raw, "Aces"))) {
    if (!isRecord(ace)) continue;
    const principal = normalizeObjectId(field(ace, "PrincipalSID", "principalsid"));
    const kind = normalizeEdgeKind(field(ace, "RightName", "rightname"));
    if (!principal || !kind) {
      builder.warn(`${sourceType}[${index}]: ACE missing PrincipalSID or RightName, skipped`);
      continue;
    }
    builder.reference(principal, normalizeNodeKind(field(ace, "PrincipalType"), "Base"));
    // An ACE grants the principal rights *over* this object, so traversal runs
    // principal -> object. Getting this backwards inverts every attack path.
    builder.edge(principal, objectId, kind, { isinherited: field(ace, "IsInherited") === true });
  }
}

function parseMembership(builder: ChunkBuilder, raw: Record<string, unknown>, objectId: string): void {
  for (const member of readResultList(field(raw, "Members"))) {
    const memberId = readReference(builder, member, "Base");
    if (memberId) builder.edge(memberId, objectId, "MemberOf");
  }
  const primaryGroup = normalizeObjectId(field(raw, "PrimaryGroupSID"));
  if (primaryGroup) {
    builder.reference(primaryGroup, "Group");
    builder.edge(objectId, primaryGroup, "MemberOf");
  }
  for (const sidHistory of readResultList(field(raw, "HasSIDHistory"))) {
    const targetId = readReference(builder, sidHistory, "Base");
    if (targetId) builder.edge(objectId, targetId, "HasSIDHistory");
  }
}

function parseComputerCollections(
  builder: ChunkBuilder,
  raw: Record<string, unknown>,
  objectId: string,
): void {
  for (const [name, kind] of PRINCIPAL_TO_COMPUTER_COLLECTIONS) {
    for (const entry of readResultList(field(raw, name))) {
      const principalId = readReference(builder, entry, "Base");
      if (principalId) builder.edge(principalId, objectId, kind);
    }
  }
  // Sessions run computer -> user: a logged-on user's credentials are
  // recoverable by whoever controls the machine.
  for (const session of readResultList(field(raw, "Sessions", "PrivilegedSessions", "RegistrySessions"))) {
    if (!isRecord(session)) continue;
    const userSid = normalizeObjectId(field(session, "UserSID"));
    const computerSid = normalizeObjectId(field(session, "ComputerSID")) ?? objectId;
    if (!userSid) continue;
    builder.reference(userSid, "User");
    builder.reference(computerSid, "Computer");
    builder.edge(computerSid, userSid, "HasSession");
  }
  for (const smsa of readResultList(field(raw, "DumpSMSAPassword"))) {
    const principalId = readReference(builder, smsa, "User");
    if (principalId) builder.edge(objectId, principalId, "DumpSMSAPassword");
  }
}

function parseDelegation(builder: ChunkBuilder, raw: Record<string, unknown>, objectId: string): void {
  for (const target of readResultList(field(raw, "AllowedToDelegate"))) {
    const targetId = readReference(builder, target, "Computer");
    if (targetId) builder.edge(objectId, targetId, "AllowedToDelegate");
  }
  for (const spnTarget of asArray(field(raw, "SPNTargets"))) {
    if (!isRecord(spnTarget)) continue;
    const computerSid = normalizeObjectId(field(spnTarget, "ComputerSID"));
    if (!computerSid) continue;
    const service = asString(field(spnTarget, "Service")) ?? "";
    if (service.toLowerCase() !== "sqladmin") continue;
    builder.reference(computerSid, "Computer");
    builder.edge(objectId, computerSid, "SQLAdmin", { port: field(spnTarget, "Port") });
  }
}

function parseContainment(
  builder: ChunkBuilder,
  raw: Record<string, unknown>,
  objectId: string,
  defaultKind: AdNodeKind,
): void {
  for (const child of readResultList(field(raw, "ChildObjects"))) {
    const childId = readReference(builder, child, "Base");
    if (childId) builder.edge(objectId, childId, "Contains");
  }
  // `Links` sit on the OU/Domain but name the GPO; the abuse direction is
  // GPO -> linked container, so the edge is emitted reversed.
  for (const link of readResultList(field(raw, "Links"))) {
    if (!isRecord(link)) continue;
    const gpoId = normalizeObjectId(field(link, "Guid", "GUID", "ObjectIdentifier"));
    if (!gpoId) continue;
    builder.reference(gpoId, "GPO");
    builder.edge(gpoId, objectId, "GPLink", { isenforced: field(link, "IsEnforced") === true });
  }
  if (defaultKind === "Computer") {
    const containedBy = field(raw, "ContainedBy");
    const parentId = readReference(builder, containedBy, "Container");
    if (parentId) builder.edge(parentId, objectId, "Contains");
  }
}

/**
 * `trustDirection` per MS-ADTS: 0 disabled, 1 inbound, 2 outbound, 3 bidirectional.
 *
 * `TrustedBy` is traversable source -> target. An **inbound** trust means the
 * target domain trusts this one, so this domain's principals can reach into the
 * target: `local -> target`. An **outbound** trust is the mirror image.
 */
function parseTrusts(builder: ChunkBuilder, raw: Record<string, unknown>, objectId: string): void {
  for (const trust of asArray(field(raw, "Trusts"))) {
    if (!isRecord(trust)) continue;
    const targetSid = normalizeObjectId(field(trust, "TargetDomainSid"));
    if (!targetSid) continue;
    builder.reference(targetSid, "Domain", asString(field(trust, "TargetDomainName")));
    const direction = Number(field(trust, "TrustDirection") ?? 0);
    const properties: AdProperties = {
      istransitive: field(trust, "IsTransitive") === true,
      sidfilteringenabled: field(trust, "SidFilteringEnabled") === true,
      trusttype: field(trust, "TrustType"),
    };
    if (direction === 1 || direction === 3) builder.edge(objectId, targetSid, "TrustedBy", properties);
    if (direction === 2 || direction === 3) builder.edge(targetSid, objectId, "TrustedBy", properties);
  }
}

// ---------------------------------------------------------------------------
// Graph-export parsing (post-processed edges: ADCSESC*, DCSync, ...)
// ---------------------------------------------------------------------------

function parseGraphExport(
  builder: ChunkBuilder,
  nodesRaw: Record<string, unknown>,
  edgesRaw: unknown[],
): void {
  // Export nodes are keyed by an internal graph id; edges reference that id,
  // not the objectId, so a translation table is required.
  const byGraphId = new Map<string, string>();
  for (const [graphId, value] of Object.entries(nodesRaw)) {
    if (!isRecord(value)) continue;
    const objectId = normalizeObjectId(field(value, "objectId", "ObjectIdentifier", "objectid")) ?? graphId.toUpperCase();
    byGraphId.set(graphId, objectId);
    builder.node({
      objectId,
      label: asString(field(value, "label", "name")) ?? objectId,
      kind: normalizeNodeKind(field(value, "kind", "ObjectType"), "Base"),
      properties: normalizeProperties(field(value, "properties", "Properties")),
    });
  }
  for (const [index, value] of edgesRaw.entries()) {
    if (!isRecord(value)) continue;
    const kind = normalizeEdgeKind(field(value, "kind", "label", "RightName"));
    const rawSource = asString(field(value, "source"));
    const rawTarget = asString(field(value, "target"));
    if (!kind || !rawSource || !rawTarget) {
      builder.warn(`graph export edge[${index}]: missing source, target or kind, skipped`);
      continue;
    }
    const source = byGraphId.get(rawSource) ?? rawSource.toUpperCase();
    const target = byGraphId.get(rawTarget) ?? rawTarget.toUpperCase();
    builder.reference(source, "Base");
    builder.reference(target, "Base");
    builder.edge(source, target, kind);
  }
}

// ---------------------------------------------------------------------------
// Public ingest API
// ---------------------------------------------------------------------------

/** Parse one already-`JSON.parse`d BloodHound file. Never throws. */
export function parseBloodHoundFile(raw: unknown): AdIngestChunk {
  const builder = new ChunkBuilder();
  if (!isRecord(raw)) {
    builder.warn("file is not a JSON object, skipped");
    return { nodes: [], edges: [], warnings: builder.warnings };
  }

  const meta = isRecord(raw.meta) ? raw.meta : {};
  const sourceType = asString(meta.type)?.toLowerCase();
  const versionValue = Number(meta.version);
  const collectorVersion = Number.isFinite(versionValue) ? versionValue : undefined;
  const data = raw.data ?? raw.Data;

  if (isRecord(data) && (isRecord(data.nodes) || Array.isArray(data.edges))) {
    parseGraphExport(builder, isRecord(data.nodes) ? data.nodes : {}, asArray(data.edges));
    return {
      nodes: builder.nodes,
      edges: builder.edges,
      sourceType: sourceType ?? "graph-export",
      collectorVersion,
      warnings: builder.warnings,
    };
  }

  if (!Array.isArray(data)) {
    builder.warn(`file has no usable "data" array (meta.type=${sourceType ?? "unknown"})`);
    return { nodes: [], edges: [], sourceType, collectorVersion, warnings: builder.warnings };
  }

  const defaultKind = (sourceType && FILE_TYPE_TO_NODE_KIND[sourceType]) ?? "Base";
  if (sourceType && !FILE_TYPE_TO_NODE_KIND[sourceType]) {
    // Unknown collection type: keep the records, fall back to per-object
    // ObjectType. Dropping them would silently shrink the attack surface.
    builder.warn(`unknown collector type "${sourceType}", nodes kept with ObjectType fallback`);
  }
  for (const [index, entry] of data.entries()) {
    parseCollectorObject(builder, entry, defaultKind, index, sourceType ?? "unknown");
  }

  return {
    nodes: builder.nodes,
    edges: builder.edges,
    sourceType,
    collectorVersion,
    warnings: builder.warnings,
  };
}

/**
 * Index a node/edge set into a traversable {@link AdGraph}.
 *
 * Real records beat stubs on merge, duplicate edges collapse on
 * `source|kind|target`, and edges naming an unknown node get a stub so the
 * adjacency index is never dangling. O(N + E).
 */
export function buildAdGraph(
  nodes: AdNode[],
  edges: AdEdge[],
  meta: Partial<AdGraphMeta> = {},
): AdGraph {
  const nodeMap = new Map<string, AdNode>();
  for (const node of nodes) {
    if (!node.objectId) continue;
    const existing = nodeMap.get(node.objectId);
    if (!existing) {
      nodeMap.set(node.objectId, node);
      continue;
    }
    if (existing.stub && !node.stub) {
      nodeMap.set(node.objectId, node);
      continue;
    }
    // Same-tier duplicate: keep the record but recover any detail the other
    // copy carried (a stub often knows a better kind than "Base").
    if (existing.kind === "Base" && node.kind !== "Base") existing.kind = node.kind;
    if (existing.label === existing.objectId && node.label !== node.objectId) existing.label = node.label;
    if (!existing.domainSid && node.domainSid) existing.domainSid = node.domainSid;
    if (existing.stub && node.stub && Object.keys(node.properties).length > 0) {
      existing.properties = { ...node.properties, ...existing.properties };
    }
  }

  const outbound = new Map<string, number[]>();
  const inbound = new Map<string, number[]>();
  const edgesByKind = new Map<AdEdgeKind, number[]>();
  const dedupedEdges: AdEdge[] = [];
  const seenEdges = new Set<string>();

  const push = <K, V>(index: Map<K, V[]>, key: K, value: V): void => {
    const bucket = index.get(key);
    if (bucket) bucket.push(value);
    else index.set(key, [value]);
  };

  for (const edge of edges) {
    if (!edge.source || !edge.target || !edge.kind) continue;
    const key = `${edge.source} ${edge.kind} ${edge.target}`;
    if (seenEdges.has(key)) continue;
    seenEdges.add(key);

    if (!nodeMap.has(edge.source)) {
      nodeMap.set(edge.source, { objectId: edge.source, label: edge.source, kind: "Base", properties: {}, stub: true });
    }
    if (!nodeMap.has(edge.target)) {
      nodeMap.set(edge.target, { objectId: edge.target, label: edge.target, kind: "Base", properties: {}, stub: true });
    }

    const index = dedupedEdges.length;
    dedupedEdges.push(edge);
    push(outbound, edge.source, index);
    push(inbound, edge.target, index);
    push(edgesByKind, edge.kind, index);
  }

  const nodesByKind = new Map<AdNodeKind, string[]>();
  for (const node of nodeMap.values()) push(nodesByKind, node.kind, node.objectId);

  return {
    nodes: nodeMap,
    edges: dedupedEdges,
    outbound,
    inbound,
    nodesByKind,
    edgesByKind,
    meta: {
      sourceTypes: meta.sourceTypes ?? [],
      collectorVersion: meta.collectorVersion,
      nodeCount: nodeMap.size,
      edgeCount: dedupedEdges.length,
      warnings: meta.warnings ?? [],
      ingestedAt: meta.ingestedAt ?? new Date().toISOString(),
    },
  };
}

/** Fold any number of parsed BloodHound files into a single indexed graph. */
export function ingestBloodHoundFiles(files: unknown[]): AdGraph {
  const nodes: AdNode[] = [];
  const edges: AdEdge[] = [];
  const warnings: string[] = [];
  const sourceTypes: string[] = [];
  let collectorVersion: number | undefined;

  for (const [index, file] of files.entries()) {
    const chunk = parseBloodHoundFile(file);
    nodes.push(...chunk.nodes);
    edges.push(...chunk.edges);
    for (const warning of chunk.warnings) warnings.push(`file[${index}]: ${warning}`);
    if (chunk.sourceType && !sourceTypes.includes(chunk.sourceType)) sourceTypes.push(chunk.sourceType);
    if (chunk.collectorVersion !== undefined) {
      collectorVersion = Math.max(collectorVersion ?? 0, chunk.collectorVersion);
    }
  }

  return buildAdGraph(nodes, edges, { sourceTypes, collectorVersion, warnings });
}

/**
 * Same as {@link ingestBloodHoundFiles} but takes raw JSON text. A file that
 * fails to parse becomes a warning, not an exception — a single truncated file
 * must not cost us the rest of the collection.
 */
export function ingestBloodHoundJson(texts: string[]): AdGraph {
  const parsed: unknown[] = [];
  const parseErrors: string[] = [];
  for (const [index, text] of texts.entries()) {
    try {
      parsed.push(JSON.parse(text));
    } catch (error) {
      parseErrors.push(`file[${index}]: invalid JSON (${(error as Error).message})`);
    }
  }
  const graph = ingestBloodHoundFiles(parsed);
  graph.meta.warnings = [...parseErrors, ...graph.meta.warnings];
  return graph;
}
