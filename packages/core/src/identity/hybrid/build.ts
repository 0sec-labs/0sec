// Merge an on-premises AD graph and an Entra graph into one traversable graph.
//
// Offline: both inputs were built offline, and this only re-keys and re-indexes
// them. No network, no collection, no authentication.
//
// Two rules govern the boundary edges emitted here.
//
//   1. THE CORRESPONDENCE IS NOT SYMMETRIC. `SyncsTo` (on-premises -> cloud) is
//      a real capability: with password-hash sync or pass-through authentication
//      the on-premises credential authenticates as the cloud identity. The
//      reverse is not — compromising a cloud account does not hand you the
//      on-premises one. `SyncedFrom` is therefore emitted for reporting and for
//      the multi-crossing analyzer, but it is excluded from the default
//      traversal profile unless `meta.writeback` says a writeback direction is
//      actually configured. Traversing it unconditionally would generate
//      cloud-to-on-premises paths that do not work, in every hybrid estate.
//
//   2. CONFIDENCE TRAVELS WITH THE EDGE. Every boundary edge carries the join
//      confidence, the signals behind it, and the `heuristic` flag in its
//      properties, so an analyzer never has to re-derive how much a path can be
//      trusted and a renderer can caveat the exact hop that needs it.
//
// Node ids are prefixed on merge (`ad:` / `aad:`) — see the rationale in
// `./types.ts`.

import type { AdEdgeKind, AdGraph, AdNodeKind } from "../../adgraph/types.js";
import type { EntraGraph } from "../entra-graph/types.js";
import { joinDirectories, type HybridJoinOptions } from "./join.js";
import {
  detectWriteback,
  findCloudSyncAccounts,
  findOnPremSyncAccounts,
  writebackEnabled,
  type HybridSyncOptions,
} from "./sync.js";
import type {
  HybridEdge,
  HybridEdgeKind,
  HybridGraph,
  HybridGraphMeta,
  HybridNode,
  HybridSyncAccount,
  IdentityPlane,
} from "./types.js";

const AD_PREFIX = "ad:";
const CLOUD_PREFIX = "aad:";

export interface BuildHybridGraphOptions extends HybridJoinOptions, HybridSyncOptions {
  /** Injected clock for `meta.ingestedAt`. */
  now?: () => Date;
}

/** Prefixed id of an on-premises object. */
export function adNodeId(objectId: string): string {
  return `${AD_PREFIX}${objectId}`;
}

/** Prefixed id of a cloud object. */
export function entraNodeId(objectId: string): string {
  return `${CLOUD_PREFIX}${objectId}`;
}

/** Inverse of {@link adNodeId} / {@link entraNodeId}. */
export function splitHybridId(nodeId: string): { plane: IdentityPlane; objectId: string } | undefined {
  if (nodeId.startsWith(AD_PREFIX)) return { plane: "on-prem", objectId: nodeId.slice(AD_PREFIX.length) };
  if (nodeId.startsWith(CLOUD_PREFIX)) return { plane: "cloud", objectId: nodeId.slice(CLOUD_PREFIX.length) };
  return undefined;
}

/**
 * Join two directory graphs and index the result.
 *
 * Pure and total. Two graphs that share no correspondence produce a valid graph
 * with zero bridge edges and a populated `meta.join.gaps` — never a silent empty
 * result.
 */
export function buildHybridGraph(
  adGraph: AdGraph,
  entraGraph: EntraGraph,
  opts: BuildHybridGraphOptions = {},
): HybridGraph {
  const now = opts.now ?? (() => new Date());
  const nodes = new Map<string, HybridNode>();
  const edges: HybridEdge[] = [];
  const warnings: string[] = [];

  // ── re-key both graphs ──

  for (const node of adGraph.nodes.values()) {
    nodes.set(adNodeId(node.objectId), {
      ...node,
      objectId: adNodeId(node.objectId),
      sourceObjectId: node.objectId,
      plane: "on-prem",
    });
  }
  for (const node of entraGraph.nodes.values()) {
    nodes.set(entraNodeId(node.objectId), {
      ...node,
      objectId: entraNodeId(node.objectId),
      sourceObjectId: node.objectId,
      plane: "cloud",
    });
  }
  for (const edge of adGraph.edges) {
    edges.push({ ...edge, source: adNodeId(edge.source), target: adNodeId(edge.target) });
  }
  for (const edge of entraGraph.edges) {
    edges.push({ ...edge, source: entraNodeId(edge.source), target: entraNodeId(edge.target) });
  }

  // ── join ──

  const join = joinDirectories(adGraph, entraGraph, opts);
  const onPremSync = findOnPremSyncAccounts(adGraph, opts);
  const cloudSync = findCloudSyncAccounts(entraGraph, opts);
  const writeback = detectWriteback(adGraph, entraGraph, join.correspondences, onPremSync, opts);
  const writebackOn = writebackEnabled(writeback);

  let bridgeEdges = 0;
  const bridge = (
    source: string,
    target: string,
    kind: HybridEdgeKind,
    properties: Record<string, unknown>,
  ): void => {
    if (!nodes.has(source) || !nodes.has(target)) return;
    edges.push({ source, target, kind, properties });
    bridgeEdges += 1;
  };

  for (const c of join.correspondences) {
    const from = adNodeId(c.adObjectId);
    const to = entraNodeId(c.entraObjectId);
    const shared = {
      confidence: c.confidence,
      signals: c.signals,
      heuristic: c.heuristic,
      rationale: c.rationale,
      ...(c.syncEnabled !== undefined ? { syncEnabled: c.syncEnabled } : {}),
    };
    bridge(from, to, "SyncsTo", shared);
    bridge(to, from, "SyncedFrom", {
      ...shared,
      writeback: writebackOn,
      ...(writebackOn
        ? {
            writebackDirection: [
              writeback.password ? "password" : "",
              writeback.group ? "group" : "",
              writeback.device ? "device" : "",
            ]
              .filter(Boolean)
              .join("/"),
          }
        : {}),
    });
  }

  // ── sync plane ──

  const syncAccounts: HybridSyncAccount[] = [
    ...onPremSync.map((a) => ({ ...a, nodeId: adNodeId(a.nodeId) })),
    ...cloudSync.map((a) => ({ ...a, nodeId: entraNodeId(a.nodeId) })),
  ];

  // The sync plane is high-value by definition: it holds directory-write in the
  // cloud and replication rights on-premises. Flagging it on the node makes it a
  // target for the generic analyzers as well as this module's own.
  for (const account of syncAccounts) {
    const node = nodes.get(account.nodeId);
    if (!node) continue;
    node.properties = {
      ...node.properties,
      highvalue: true,
      hybridhighvalue: true,
      hybridsyncrole: account.role,
      hybridsyncnameonly: account.nameOnly,
    };
  }

  const tenantNodeId = firstOfKind(entraGraph, "AZTenant");
  const tenant = tenantNodeId ? entraNodeId(tenantNodeId) : undefined;

  const connectors = onPremSync.filter((a) => a.role === "ad-connector");
  const cloudIdentities = cloudSync.filter((a) => a.role === "cloud-sync-identity");

  for (const connector of connectors) {
    for (const cloudIdentity of cloudIdentities) {
      bridge(adNodeId(connector.nodeId), entraNodeId(cloudIdentity.nodeId), "SyncAccountFor", {
        evidence: [...connector.evidence, ...cloudIdentity.evidence],
        nameOnly: connector.nameOnly || cloudIdentity.nameOnly,
      });
    }
    // Fallback when the cloud identity was not collected or not identified. The
    // capability is real regardless of whether we can name the cloud account —
    // but only assert it when the connector was corroborated by something more
    // than its name, so a decoy `MSOL_x` cannot manufacture a tenant-takeover
    // path on its own.
    if (cloudIdentities.length === 0 && tenant && !connector.nameOnly) {
      bridge(adNodeId(connector.nodeId), tenant, "PasswordHashSync", {
        evidence: connector.evidence,
        note:
          "the cloud sync identity was not identified in the tenant collection; this edge asserts the " +
          "capability of the on-premises connector account, not a specific cloud principal",
      });
    }
  }

  if (cloudIdentities.length === 0 && connectors.length > 0) {
    warnings.push(
      "an on-premises Entra Connect connector account was identified but no matching cloud sync identity was " +
        "found in the tenant collection — the sync account's cloud privilege could not be enumerated, and its " +
        "absence here is not evidence that it is unprivileged",
    );
  }

  for (const sso of onPremSync.filter((a) => a.role === "seamless-sso")) {
    if (!tenant) continue;
    bridge(adNodeId(sso.nodeId), tenant, "SeamlessSsoForge", { evidence: sso.evidence });
  }
  if (!tenant) {
    warnings.push(
      "the Entra graph carried no tenant node, so sync-plane edges that terminate at tenant control could not " +
        "be created",
    );
  }

  return indexHybridGraph(nodes, edges, {
    onPrem: adGraph.meta,
    cloud: entraGraph.meta,
    ...(entraGraph.meta.tenantId ? { tenantId: entraGraph.meta.tenantId } : {}),
    join,
    syncAccounts,
    writeback,
    bridgeEdges,
    warnings: [...warnings, ...join.warnings],
    ingestedAt: now().toISOString(),
  });
}

// ---------------------------------------------------------------------------
// Indexing
// ---------------------------------------------------------------------------

/**
 * Build the adjacency indices the traversal layer reads. Same shape as
 * `buildAdGraph` and `indexGraph`; the difference is only that a node here knows
 * which plane it is on.
 */
export function indexHybridGraph(
  nodes: Map<string, HybridNode>,
  rawEdges: HybridEdge[],
  meta: {
    onPrem: HybridGraphMeta["onPrem"];
    cloud: HybridGraphMeta["cloud"];
    tenantId?: string;
    join: HybridGraphMeta["join"];
    syncAccounts: HybridSyncAccount[];
    writeback: HybridGraphMeta["writeback"];
    bridgeEdges: number;
    warnings: string[];
    ingestedAt: string;
  },
): HybridGraph {
  const outbound = new Map<string, number[]>();
  const inbound = new Map<string, number[]>();
  const edgesByKind = new Map<AdEdgeKind, number[]>();
  const nodesByKind = new Map<AdNodeKind, string[]>();

  const push = <K, V>(index: Map<K, V[]>, key: K, value: V): void => {
    const bucket = index.get(key);
    if (bucket) bucket.push(value);
    else index.set(key, [value]);
  };

  const edges: HybridEdge[] = [];
  const seen = new Set<string>();
  for (const edge of rawEdges) {
    if (!edge.source || !edge.target || !edge.kind) continue;
    const key = `${edge.source} ${edge.kind} ${edge.target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // Both source graphs already guarantee their own referential integrity, so
    // a dangling reference here means a re-keying bug, not bad collector data.
    if (!nodes.has(edge.source) || !nodes.has(edge.target)) continue;
    const index = edges.length;
    edges.push(edge);
    push(outbound, edge.source, index);
    push(inbound, edge.target, index);
    push(edgesByKind, edge.kind, index);
  }

  for (const node of nodes.values()) push(nodesByKind, node.kind, node.objectId);

  let onPremNodes = 0;
  let cloudNodes = 0;
  for (const node of nodes.values()) {
    if (node.plane === "on-prem") onPremNodes += 1;
    else cloudNodes += 1;
  }

  return {
    nodes,
    edges,
    outbound,
    inbound,
    nodesByKind,
    edgesByKind,
    meta: {
      sourceTypes: [...new Set([...meta.onPrem.sourceTypes, ...meta.cloud.sourceTypes])],
      nodeCount: nodes.size,
      edgeCount: edges.length,
      warnings: meta.warnings,
      ingestedAt: meta.ingestedAt,
      onPrem: meta.onPrem,
      cloud: meta.cloud,
      ...(meta.tenantId ? { tenantId: meta.tenantId } : {}),
      join: meta.join,
      syncAccounts: meta.syncAccounts,
      writeback: meta.writeback,
      counts: { onPremNodes, cloudNodes, bridgeEdges: meta.bridgeEdges },
    },
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function firstOfKind(graph: EntraGraph, kind: string): string | undefined {
  return (graph.nodesByKind.get(kind) ?? [])[0];
}

/** Boundary crossings in a path — the count that makes a finding interesting. */
export function boundaryCrossings(steps: ReadonlyArray<{ from: HybridNode; to: HybridNode }>): number {
  let crossings = 0;
  for (const step of steps) if (step.from.plane !== step.to.plane) crossings += 1;
  return crossings;
}
