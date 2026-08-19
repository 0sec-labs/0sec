// Entra ID attack-path analyzers.
//
// Structural mirror of `../../adgraph/analyzers.ts`: each analyzer is a pure
// `(graph, options?) => EntraPathFinding[]`, narrows its candidate set with one
// reverse BFS before it runs a single path search, and attaches the shortest
// supporting paths as the finding's evidence. The paths are the deliverable —
// "this guest account reaches Global Administrator in three hops" is actionable
// in a way that "27 things are misconfigured" is not.

import { reachableTo, shortestPaths } from "../../adgraph/paths.js";
// Imported, never redefined: `TIER0_GRAPH_PERMISSIONS` is the one definition of
// "equivalent to tenant compromise" in this module, shared with the 27 checks.
import { TIER0_GRAPH_PERMISSIONS as TIER0_PERMISSION_NAMES } from "../analyzers.js";
import type { TraversalOptions } from "../../adgraph/paths.js";
import { describeEntraEdge } from "./edges.js";
import type {
  EntraAttackPath,
  EntraEdge,
  EntraEdgeKind,
  EntraGraph,
  EntraNode,
  EntraPathAnalyzerId,
  EntraPathFinding,
} from "./types.js";
import type { AffectedPrincipal, IdentityPrincipalType, IdentitySeverity } from "../types.js";

/**
 * Edges by which one principal takes another object over. Used to answer "who
 * can seize this service principal?" without letting the answer wander through
 * unrelated capability edges.
 */
const TAKEOVER_EDGE_KINDS: EntraEdgeKind[] = [
  "AZMemberOf",
  "AZHasRole",
  "AZOwns",
  "AZRunsAs",
  "AZAddSecret",
  "AZAddOwner",
  "AZAddMember",
  "AZAppAdmin",
  "AZCloudAppAdmin",
  "AZResetPassword",
  "AZPrivilegedAuthAdmin",
];

export interface EntraPathAnalyzerOptions {
  /**
   * Principals already under operator control. When supplied these become the
   * path sources; otherwise every enabled, non-privileged user and service
   * principal is a candidate.
   */
  ownedPrincipalIds?: Iterable<string>;
  /** Extra objectIds to treat as tier-0 targets. */
  highValueIds?: Iterable<string>;
  /** Hop ceiling for every traversal. Default 6. */
  maxDepth?: number;
  /** Attack paths attached to a single finding. Default 5. */
  maxPathsPerFinding?: number;
  /** Findings a single analyzer may emit. Default 25. */
  maxFindingsPerAnalyzer?: number;
  /** Passed through to the traversal layer (edge filters, costs, budgets). */
  traversal?: TraversalOptions<EntraEdge>;
}

interface ResolvedOptions {
  maxDepth: number;
  maxPathsPerFinding: number;
  maxFindingsPerAnalyzer: number;
  traversal: TraversalOptions<EntraEdge>;
}

function resolveOptions(opts: EntraPathAnalyzerOptions): ResolvedOptions {
  const maxDepth = Math.max(1, opts.maxDepth ?? 6);
  return {
    maxDepth,
    maxPathsPerFinding: Math.max(1, opts.maxPathsPerFinding ?? 5),
    maxFindingsPerAnalyzer: Math.max(1, opts.maxFindingsPerAnalyzer ?? 25),
    // `describeEdge` is what makes every hop render its Entra abuse technique
    // instead of falling through to the on-prem AD table.
    traversal: { maxDepth, describeEdge: describeEntraEdge, ...opts.traversal },
  };
}

// ---------------------------------------------------------------------------
// Target and source selection
// ---------------------------------------------------------------------------

function nodesOfKind(graph: EntraGraph, kind: string): EntraNode[] {
  const out: EntraNode[] = [];
  for (const id of graph.nodesByKind.get(kind) ?? []) {
    const node = graph.nodes.get(id);
    if (node) out.push(node);
  }
  return out;
}

/** Tenant-wide role nodes flagged tier-0 at build time, plus the tenant itself. */
export function tier0TargetIds(graph: EntraGraph, extra?: Iterable<string>): Set<string> {
  const out = new Set<string>(extra ?? []);
  for (const node of nodesOfKind(graph, "AZRole")) {
    if (node.scopeId) continue;
    if (node.properties.tier0 === true) out.add(node.objectId);
  }
  for (const node of nodesOfKind(graph, "AZTenant")) out.add(node.objectId);
  return out;
}

/** Every role node we treat as privileged, scoped ones included. */
export function privilegedRoleIds(graph: EntraGraph): Set<string> {
  const out = new Set<string>();
  for (const node of nodesOfKind(graph, "AZRole")) {
    if (node.properties.privileged === true) out.add(node.objectId);
  }
  return out;
}

/** Principals holding (or PIM-eligible for) any privileged role. */
export function privilegedPrincipalIds(graph: EntraGraph): Set<string> {
  const privilegedRoles = privilegedRoleIds(graph);
  const out = new Set<string>();
  for (const edgeIndex of graph.edgesByKind.get("AZHasRole") ?? []) {
    const edge = graph.edges[edgeIndex]!;
    if (privilegedRoles.has(edge.target)) out.add(edge.source);
  }
  return out;
}

function isEnabled(node: EntraNode): boolean {
  return node.properties.accountenabled !== false;
}

/**
 * Candidate path origins: caller-supplied owned principals, else every enabled
 * user and service principal that does not already hold privilege.
 */
function candidateSources(graph: EntraGraph, opts: EntraPathAnalyzerOptions, privileged: Set<string>): string[] {
  if (opts.ownedPrincipalIds) {
    return [...opts.ownedPrincipalIds].map((id) => id.toLowerCase()).filter((id) => graph.nodes.has(id));
  }
  return [...nodesOfKind(graph, "AZUser"), ...nodesOfKind(graph, "AZServicePrincipal")]
    .filter((node) => isEnabled(node) && !privileged.has(node.objectId))
    .map((node) => node.objectId);
}

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

function slug(...parts: string[]): string {
  return parts
    .map((part) => part.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "x")
    .join(":");
}

const NODE_KIND_TO_PRINCIPAL_TYPE: Record<string, IdentityPrincipalType> = {
  AZUser: "user",
  AZGroup: "group",
  AZServicePrincipal: "servicePrincipal",
  AZApp: "application",
};

/** Render a graph node as the same `AffectedPrincipal` shape the 27 checks use. */
export function principalOf(graph: EntraGraph, objectId: string): AffectedPrincipal {
  const node = graph.nodes.get(objectId);
  if (!node) return { id: objectId, type: "unknown" };
  return {
    id: node.objectId,
    type: NODE_KIND_TO_PRINCIPAL_TYPE[node.kind] ?? "unknown",
    displayName: asString(node.properties.displayname) ?? node.label,
    ...(asString(node.properties.userprincipalname)
      ? { userPrincipalName: asString(node.properties.userprincipalname)! }
      : {}),
    ...(asString(node.properties.appid) ? { appId: asString(node.properties.appid)! } : {}),
  };
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function finding(
  analyzer: EntraPathAnalyzerId,
  id: string,
  severity: IdentitySeverity,
  title: string,
  description: string,
  remediation: string,
  paths: EntraAttackPath[],
  affectedPrincipals: AffectedPrincipal[],
  evidence?: Record<string, unknown>,
): EntraPathFinding {
  const seen = new Set<string>();
  return {
    id: `entra-graph:${analyzer}:${id}`,
    analyzer,
    title,
    severity,
    description,
    paths,
    affectedPrincipals: affectedPrincipals.filter((p) => (seen.has(p.id) ? false : (seen.add(p.id), true))),
    remediation,
    ...(evidence ? { evidence } : {}),
  };
}

/** Shortest path from each of `sources` to `targets`, cheapest first, capped. */
function pathsFrom(
  graph: EntraGraph,
  sources: string[],
  targets: Iterable<string>,
  resolved: ResolvedOptions,
): EntraAttackPath[] {
  const paths: EntraAttackPath[] = [];
  for (const sourceId of sources.slice(0, resolved.maxPathsPerFinding)) {
    const [path] = shortestPaths(graph, [sourceId], targets, { ...resolved.traversal, maxResults: 1 });
    if (path) paths.push(path);
  }
  return paths.sort((a, b) => a.cost - b.cost || a.length - b.length);
}

// ---------------------------------------------------------------------------
// Analyzer 1 — paths to Global Administrator and the other Tier-0 roles
// ---------------------------------------------------------------------------

/**
 * Shortest paths from unprivileged (or operator-owned) principals to each
 * Tier-0 directory role and to the tenant itself.
 *
 * One reverse BFS per target narrows the candidate set before any path search
 * runs, so cost is O(V + E) plus a bounded number of searches — not
 * O(sources x targets).
 */
export function findEntraPathsToGlobalAdmin(
  graph: EntraGraph,
  opts: EntraPathAnalyzerOptions = {},
): EntraPathFinding[] {
  const resolved = resolveOptions(opts);
  const targets = [...tier0TargetIds(graph, opts.highValueIds)];
  if (targets.length === 0) return [];

  const privileged = privilegedPrincipalIds(graph);
  const sources = candidateSources(graph, opts, privileged);
  if (sources.length === 0) return [];

  const findings: EntraPathFinding[] = [];
  for (const targetId of targets.sort()) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const target = graph.nodes.get(targetId);
    if (!target) continue;

    const distances = reachableTo(graph, [targetId], resolved.maxDepth, resolved.traversal);
    const reaching = sources
      .filter((id) => id !== targetId && distances.has(id))
      .sort((a, b) => distances.get(a)! - distances.get(b)! || a.localeCompare(b));
    if (reaching.length === 0) continue;

    const paths = pathsFrom(graph, reaching, [targetId], resolved);
    if (paths.length === 0) continue;

    findings.push(
      finding(
        "entra-paths-to-global-admin",
        slug(targetId),
        "critical",
        `Attack path from unprivileged principals to ${target.label}`,
        `${reaching.length} principal(s) with no privileged role of their own can reach ${target.label} ` +
          `within ${resolved.maxDepth} hops. The shortest path takes ${paths[0]!.length} hop(s): ` +
          `${paths[0]!.technique}.`,
        `Break the shortest hop first — in Entra it is almost always one of three things: membership of a group ` +
          `that carries a role assignment, ownership of an application whose service principal is privileged, or ` +
          `a consented Graph application permission. Move ${target.label} to PIM-eligible activation with ` +
          `approval, review the group and ownership assignments on the path, and re-collect to confirm it is gone.`,
        paths,
        reaching.slice(0, 100).map((id) => principalOf(graph, id)),
        {
          targetId,
          targetLabel: target.label,
          reachingPrincipalCount: reaching.length,
          shortestPathLength: paths[0]!.length,
        },
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 2 — service-principal escalation chains
// ---------------------------------------------------------------------------

/**
 * Application-identity takeover: who can add a credential to (or otherwise
 * seize) a service principal that holds tier-0 Graph permissions or a privileged
 * directory role.
 *
 * This is the escalation the flat checks cannot express. `analyzeServicePrincipals`
 * reports that an SP holds `Application.ReadWrite.All`; only the graph says that
 * a contractor's account owns the app registration behind it.
 */
export function findEntraServicePrincipalEscalation(
  graph: EntraGraph,
  opts: EntraPathAnalyzerOptions = {},
): EntraPathFinding[] {
  const resolved = resolveOptions(opts);
  const privileged = privilegedPrincipalIds(graph);
  const privilegedRoles = privilegedRoleIds(graph);
  const sources = new Set(candidateSources(graph, opts, privileged));
  if (sources.size === 0) return [];

  const takeover: TraversalOptions<EntraEdge> = {
    ...resolved.traversal,
    allowedEdgeKinds: TAKEOVER_EDGE_KINDS,
  };

  const findings: EntraPathFinding[] = [];
  for (const sp of nodesOfKind(graph, "AZServicePrincipal")) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;

    const permissions = asStringArray(sp.properties.grantedpermissions);
    const tier0Permissions = permissions.filter((name) => TIER0_PERMISSION_NAMES.has(name));
    const roleIds = rolesHeldBy(graph, sp.objectId).filter((id) => privilegedRoles.has(id));
    if (tier0Permissions.length === 0 && roleIds.length === 0) continue;

    // Who can seize this identity? One reverse BFS over takeover edges only.
    const distances = reachableTo(graph, [sp.objectId], resolved.maxDepth, takeover);
    const reaching = [...distances.keys()]
      .filter((id) => id !== sp.objectId && sources.has(id))
      .sort((a, b) => distances.get(a)! - distances.get(b)! || a.localeCompare(b));
    if (reaching.length === 0) continue;

    const paths: EntraAttackPath[] = [];
    for (const sourceId of reaching.slice(0, resolved.maxPathsPerFinding)) {
      const [path] = shortestPaths(graph, [sourceId], [sp.objectId], { ...takeover, maxResults: 1 });
      if (path) paths.push(path);
    }
    if (paths.length === 0) continue;

    const roleLabels = roleIds.map((id) => graph.nodes.get(id)?.label ?? id);
    findings.push(
      finding(
        "entra-service-principal-escalation",
        slug(sp.objectId),
        tier0Permissions.length > 0 || roleIds.length > 0 ? "critical" : "high",
        `${reaching.length} unprivileged principal(s) can take over privileged service principal ${sp.label}`,
        `Service principal ${sp.label} holds ` +
          [
            tier0Permissions.length > 0 ? `tenant-takeover Graph permissions (${tier0Permissions.join(", ")})` : "",
            roleLabels.length > 0 ? `privileged directory roles (${roleLabels.join(", ")})` : "",
          ]
            .filter(Boolean)
            .join(" and ") +
          `. ${reaching.length} principal(s) with no privileged role of their own can reach it within ` +
          `${resolved.maxDepth} hops — by owning its application registration, by holding an application-management ` +
          `role, or through a group that does. Adding a client secret to the registration is all that is then ` +
          `required to authenticate as this identity. Shortest path (${paths[0]!.length} hop(s)): ${paths[0]!.technique}.`,
        `Remove the ownership and application-management grants on the path, or strip the tier-0 permission from ` +
          `${sp.label} and re-consent the narrowest scope the workload needs. Application owners are not reviewed ` +
          `by the access reviews that cover directory roles, so they have to be audited explicitly.`,
        paths,
        [principalOf(graph, sp.objectId), ...reaching.slice(0, 100).map((id) => principalOf(graph, id))],
        {
          servicePrincipalId: sp.objectId,
          tier0Permissions,
          privilegedRoles: roleLabels,
          reachingPrincipalCount: reaching.length,
        },
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 3 — consent-grant escalation
// ---------------------------------------------------------------------------

/**
 * Service principals whose *consented* application permissions are equivalent to
 * tenant takeover, with the path from the permission to tenant control spelled
 * out.
 *
 * Requested permissions are deliberately not considered here — see the grants-
 * not-requests rule in `./build.ts`.
 */
export function findEntraConsentGrantEscalation(
  graph: EntraGraph,
  opts: EntraPathAnalyzerOptions = {},
): EntraPathFinding[] {
  const resolved = resolveOptions(opts);
  const targets = tier0TargetIds(graph, opts.highValueIds);
  if (targets.size === 0) return [];

  const findings: EntraPathFinding[] = [];
  for (const sp of nodesOfKind(graph, "AZServicePrincipal")) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const permissions = asStringArray(sp.properties.grantedpermissions);
    const tier0Permissions = permissions.filter((name) => TIER0_PERMISSION_NAMES.has(name));
    if (tier0Permissions.length === 0) continue;

    const paths = shortestPaths(graph, [sp.objectId], targets, {
      ...resolved.traversal,
      maxResults: resolved.maxPathsPerFinding,
    });
    if (paths.length === 0) continue;

    const external = sp.properties.external === true;
    findings.push(
      finding(
        "entra-consent-grant-escalation",
        slug(sp.objectId),
        "critical",
        `Consented Graph permissions let ${sp.label} escalate to tenant control`,
        `${sp.label} has been granted ${tier0Permissions.join(", ")} as application permission(s). These are ` +
          `live grants, not requests: the service principal can use them right now to assign itself a directory ` +
          `role, or to add a credential to an application that already holds one. It reaches ` +
          `${paths.length} tier-0 target(s) within ${resolved.maxDepth} hops; the shortest is ` +
          `${paths[0]!.length} hop(s): ${paths[0]!.technique}.` +
          (external ? " The application is owned by an external tenant, so its credentials are not under your control." : ""),
        `Revoke the app role assignment and re-consent with the least-privileged alternative — for directory reads ` +
          `that is usually \`Directory.Read.All\`, and for mailbox or site access it is resource-specific consent ` +
          `rather than a tenant-wide permission. Audit the service principal's sign-in and directory-audit history ` +
          `for prior use of the permission before revoking.`,
        paths,
        [principalOf(graph, sp.objectId)],
        {
          servicePrincipalId: sp.objectId,
          tier0Permissions,
          externalPublisher: external,
          reachableTier0TargetCount: paths.length,
        },
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 4 — owner-chain abuse
// ---------------------------------------------------------------------------

/**
 * Ownership of a directory object is full control of it, and ownership chains
 * (A owns the app whose service principal owns the group that carries the role)
 * are invisible to every per-object check.
 *
 * One finding per owning principal, so remediation has a single owner.
 */
export function findEntraOwnerChainAbuse(
  graph: EntraGraph,
  opts: EntraPathAnalyzerOptions = {},
): EntraPathFinding[] {
  const resolved = resolveOptions(opts);
  const targets = tier0TargetIds(graph, opts.highValueIds);
  if (targets.size === 0) return [];

  const privileged = privilegedPrincipalIds(graph);
  const ownerEdges = graph.edgesByKind.get("AZOwns") ?? [];
  if (ownerEdges.length === 0) return [];

  // owner -> objects it directly owns
  const ownedBy = new Map<string, string[]>();
  for (const edgeIndex of ownerEdges) {
    const edge = graph.edges[edgeIndex]!;
    if (privileged.has(edge.source)) continue; // a privileged owner is not an escalation
    const bucket = ownedBy.get(edge.source);
    if (bucket) bucket.push(edge.target);
    else ownedBy.set(edge.source, [edge.target]);
  }
  if (ownedBy.size === 0) return [];

  // One reverse BFS over every tier-0 target answers "can this owner get there?"
  const distances = reachableTo(graph, targets, resolved.maxDepth, resolved.traversal);

  const findings: EntraPathFinding[] = [];
  for (const [ownerId, owned] of [...ownedBy].sort(([a], [b]) => a.localeCompare(b))) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    if (!distances.has(ownerId)) continue;

    const paths = shortestPaths(graph, [ownerId], targets, {
      ...resolved.traversal,
      maxResults: resolved.maxPathsPerFinding,
    });
    if (paths.length === 0) continue;

    const owner = graph.nodes.get(ownerId)!;
    const ownedLabels = owned.slice(0, 20).map((id) => graph.nodes.get(id)?.label ?? id);
    findings.push(
      finding(
        "entra-owner-chain-abuse",
        slug(ownerId),
        "high",
        `${owner.label} owns ${owned.length} object(s) on a path to tier-0 control`,
        `${owner.label} holds no privileged directory role, but it owns ${owned.length} directory object(s) ` +
          `(${ownedLabels.join(", ")}${owned.length > ownedLabels.length ? ", …" : ""}). An owner can add ` +
          `credentials, owners, and members to what it owns without any further grant, and from here that ` +
          `reaches ${paths.length} tier-0 target(s) within ${resolved.maxDepth} hops. Shortest path ` +
          `(${paths[0]!.length} hop(s)): ${paths[0]!.technique}.`,
        `Remove ${owner.label} from the owners list of the objects on the path. Ownership in Entra is a standing, ` +
          `un-reviewed grant: it does not appear in PIM, it is not covered by access reviews of directory roles, ` +
          `and it survives the owner changing teams. Where an owner is genuinely needed, use a role-assignable ` +
          `group under access review rather than a personal account.`,
        paths,
        [principalOf(graph, ownerId), ...owned.slice(0, 50).map((id) => principalOf(graph, id))],
        {
          ownerId,
          ownedObjectIds: owned.slice(0, 50),
          ownedObjectCount: owned.length,
          shortestPathLength: paths[0]!.length,
        },
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 5 — guest / external identity reachability
// ---------------------------------------------------------------------------

/**
 * External identities — B2B guests and service principals homed in another
 * tenant — that reach privileged roles.
 *
 * The credential, its authentication methods, and its lifecycle all live in a
 * directory you do not control, so a compromise over there is a compromise here.
 * `guest-in-privileged-role` already reports a guest that *holds* a role; this
 * reports the guest that can *get* one.
 */
export function findEntraGuestEscalation(
  graph: EntraGraph,
  opts: EntraPathAnalyzerOptions = {},
): EntraPathFinding[] {
  const resolved = resolveOptions(opts);
  const targets = new Set([...tier0TargetIds(graph, opts.highValueIds), ...privilegedRoleIds(graph)]);
  if (targets.size === 0) return [];

  const external: EntraNode[] = [
    ...nodesOfKind(graph, "AZUser").filter((node) => node.properties.usertype === "guest"),
    ...nodesOfKind(graph, "AZServicePrincipal").filter((node) => node.properties.external === true),
  ];
  if (external.length === 0) return [];

  const distances = reachableTo(graph, targets, resolved.maxDepth, resolved.traversal);

  const findings: EntraPathFinding[] = [];
  for (const node of external.sort((a, b) => a.objectId.localeCompare(b.objectId))) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    if (!isEnabled(node)) continue;
    if (!distances.has(node.objectId)) continue;

    const paths = shortestPaths(graph, [node.objectId], targets, {
      ...resolved.traversal,
      maxResults: resolved.maxPathsPerFinding,
    });
    if (paths.length === 0) continue;

    const reachesTier0 = paths.some((path) => tier0TargetIds(graph, opts.highValueIds).has(path.targetId));
    const isGuest = node.kind === "AZUser";
    findings.push(
      finding(
        "entra-guest-escalation",
        slug(node.objectId),
        reachesTier0 ? "critical" : "high",
        `External identity ${node.label} reaches privileged roles in ${paths[0]!.length} hop(s)`,
        (isGuest
          ? `Guest account ${node.label} is an external B2B identity: its password, its MFA methods, and its ` +
            `deprovisioning are all governed by its home directory, not by yours. `
          : `Service principal ${node.label} belongs to an application published by another tenant, so its ` +
            `credentials are held and rotated outside your control. `) +
          `It reaches ${paths.length} privileged target(s) within ${resolved.maxDepth} hops` +
          (reachesTier0 ? ", including a Tier-0 target" : "") +
          `. Shortest path (${paths[0]!.length} hop(s)): ${paths[0]!.technique}.`,
        (isGuest
          ? `Remove the group memberships and ownerships that put this guest on the path, and gate external ` +
            `identities with a conditional-access policy that requires MFA and blocks them from administrative ` +
            `applications. Where the access is genuinely needed, issue a member account in this tenant instead.`
          : `Remove the grants that put this external service principal on the path and re-consent the narrowest ` +
            `scope its workload needs. A third-party application's credentials are outside your rotation and ` +
            `revocation controls, so treat every permission it holds as permanently exposed.`),
        paths,
        [principalOf(graph, node.objectId)],
        {
          principalId: node.objectId,
          kind: node.kind,
          reachablePrivilegedTargetCount: paths.length,
          shortestPathLength: paths[0]!.length,
        },
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

/** Every analyzer in this module, in reporting order. */
export const ENTRA_PATH_ANALYZERS: ReadonlyArray<
  (graph: EntraGraph, opts?: EntraPathAnalyzerOptions) => EntraPathFinding[]
> = [
  findEntraPathsToGlobalAdmin,
  findEntraConsentGrantEscalation,
  findEntraServicePrincipalEscalation,
  findEntraGuestEscalation,
  findEntraOwnerChainAbuse,
];

export const ENTRA_PATH_ANALYZERS_BY_ID: Record<
  EntraPathAnalyzerId,
  (graph: EntraGraph, opts?: EntraPathAnalyzerOptions) => EntraPathFinding[]
> = {
  "entra-paths-to-global-admin": findEntraPathsToGlobalAdmin,
  "entra-service-principal-escalation": findEntraServicePrincipalEscalation,
  "entra-consent-grant-escalation": findEntraConsentGrantEscalation,
  "entra-owner-chain-abuse": findEntraOwnerChainAbuse,
  "entra-guest-escalation": findEntraGuestEscalation,
};

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** Role node ids the principal holds directly (one `AZHasRole` hop). */
function rolesHeldBy(graph: EntraGraph, principalId: string): string[] {
  const out: string[] = [];
  for (const edgeIndex of graph.outbound.get(principalId) ?? []) {
    const edge = graph.edges[edgeIndex]!;
    if (edge.kind === "AZHasRole") out.push(edge.target);
  }
  return out;
}
