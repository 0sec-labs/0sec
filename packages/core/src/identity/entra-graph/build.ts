// Build a traversable Entra ID graph from a `TenantSnapshot`.
//
// Two rules govern every edge emitted here, and they are the difference between
// an attack path a customer can act on and one they will dispute:
//
//   1. GRANTS, NOT REQUESTS. An app registration that *asks* for
//      `RoleManagement.ReadWrite.Directory` in `requiredResourceAccess` has no
//      edge. Only a consented `appRoleAssignment` on the service principal
//      does. The request is already covered by the flat check
//      `app-requests-tier0-graph-permission`; turning it into a graph edge would
//      manufacture a path that does not exist yet.
//   2. NO PARALLEL EDGES FOR THE SAME CAPABILITY. Ownership is recorded once, as
//      `AZOwns`, whose written technique already says the owner can add
//      credentials and members. `AZAddSecret` / `AZAddOwner` / `AZAddMember` are
//      reserved for capabilities that come from a directory role or a consented
//      Graph permission. Emitting both would double the edge count and let the
//      shortest-path search pick an arbitrary one of two identical hops.
//
// Every role-template and permission catalog used below is imported from
// `../analyzers.js`. There is exactly one definition of "tier 0" in this module.

import {
  isLiveEligibility,
  roleDisplayName,
  templateIdFor,
  GRAPH_APP_ROLE_CATALOG,
  HIGH_IMPACT_GRAPH_PERMISSIONS,
  PRIVILEGED_ROLE_TEMPLATE_IDS,
  ROLE_TEMPLATE_IDS,
  TIER0_GRAPH_PERMISSIONS,
  TIER0_ROLE_TEMPLATE_IDS,
} from "../analyzers.js";
import type { AdEdgeKind, AdNodeKind } from "../../adgraph/types.js";
import type { ServicePrincipalRecord, TenantSnapshot } from "../types.js";
import type { EntraEdge, EntraEdgeKind, EntraGraph, EntraGraphMeta, EntraNode, EntraNodeKind } from "./types.js";

/** Prefixes keep synthetic node ids from colliding with Graph object ids. */
const ROLE_PREFIX = "role:";
const TENANT_PREFIX = "tenant:";

export interface BuildEntraGraphOptions {
  /**
   * Ceiling on the fan-out a single tenant-wide capability may emit (an
   * Application Administrator reaches *every* app registration). Truncation is
   * recorded as a graph warning rather than being silent. Default 2000.
   */
  maxDerivedEdgesPerSource?: number;
  /** Injected clock for `meta.ingestedAt`. */
  now?: () => Date;
  /**
   * Where the snapshot came from. Defaults to `tenant-snapshot` (a live
   * read-only Graph collection). `./ingest.ts` passes `azurehound` when the
   * snapshot was reconstructed from an offline export, so a reader can tell
   * whether a missing relationship means "not present in the directory" or
   * "the collector was never asked for it".
   */
  origin?: EntraGraphMeta["origin"];
  /**
   * Extra source-type labels for `meta.sourceTypes` — the offline path records
   * which AzureHound collections were actually present.
   */
  sourceTypes?: string[];
}

/** Graph object ids are case-insensitive; Graph lower-cases, AzureHound upper-cases. */
export function normalizeId(value: string | undefined | null): string | undefined {
  const trimmed = typeof value === "string" ? value.trim() : "";
  return trimmed.length > 0 ? trimmed.toLowerCase() : undefined;
}

export function roleNodeId(templateId: string, scopeId?: string): string {
  const base = `${ROLE_PREFIX}${templateId.toLowerCase()}`;
  return scopeId ? `${base}@${scopeId.toLowerCase()}` : base;
}

export function tenantNodeId(tenantId: string): string {
  return `${TENANT_PREFIX}${tenantId.toLowerCase()}`;
}

/** `/` and the empty string both mean tenant-wide; anything else is scoped. */
function scopeOf(directoryScopeId: string | undefined): string | undefined {
  const raw = (directoryScopeId ?? "/").trim();
  if (raw === "" || raw === "/") return undefined;
  const au = /^\/administrativeUnits\/(.+)$/i.exec(raw);
  return normalizeId(au ? au[1] : raw);
}

class GraphBuilder {
  readonly nodes = new Map<string, EntraNode>();
  readonly edges: EntraEdge[] = [];
  readonly warnings: string[] = [];
  private readonly seenEdges = new Set<string>();

  node(node: EntraNode): void {
    const existing = this.nodes.get(node.objectId);
    if (!existing) {
      this.nodes.set(node.objectId, node);
      return;
    }
    // A real record beats a reference stub; otherwise recover any detail the
    // duplicate carried.
    if (existing.stub && !node.stub) this.nodes.set(node.objectId, node);
    else if (existing.label === existing.objectId && node.label !== node.objectId) existing.label = node.label;
  }

  /** Register a referenced-but-not-collected object so traversal never dead-ends. */
  reference(objectId: string, kind: EntraNodeKind): void {
    if (this.nodes.has(objectId)) return;
    this.nodes.set(objectId, { objectId, label: objectId, kind, properties: {}, stub: true });
  }

  edge(source: string, target: string, kind: EntraEdgeKind, properties?: Record<string, unknown>): void {
    if (source === target) return;
    const key = `${source} ${kind} ${target}`;
    if (this.seenEdges.has(key)) return;
    this.seenEdges.add(key);
    this.edges.push(properties ? { source, target, kind, properties } : { source, target, kind });
  }

  warn(message: string): void {
    if (this.warnings.length < 200) this.warnings.push(message);
  }

  /** Emit `kind` from `source` to every target, capped, warning on truncation. */
  fanOut(source: string, targets: string[], kind: EntraEdgeKind, cap: number, label: string): void {
    if (targets.length > cap) {
      this.warn(`${label}: ${kind} fan-out truncated to ${cap} of ${targets.length} target(s)`);
    }
    for (const target of targets.slice(0, cap)) this.edge(source, target, kind);
  }
}

/**
 * Turn a posture snapshot into an attack-path graph.
 *
 * Pure and total: a snapshot with no `relationships` still produces a usable
 * graph (roles, applications, service principals and everything derived from
 * consented permissions), with `meta.relationshipsCollected = false` so callers
 * know membership and ownership edges are simply absent rather than nonexistent.
 */
export function buildEntraGraph(snapshot: TenantSnapshot, opts: BuildEntraGraphOptions = {}): EntraGraph {
  const cap = Math.max(1, opts.maxDerivedEdgesPerSource ?? 2000);
  const now = opts.now ?? (() => new Date());
  const b = new GraphBuilder();

  const tenantId = normalizeId(snapshot.tenantId) ?? "unknown";
  const tenant = tenantNodeId(tenantId);
  b.node({
    objectId: tenant,
    label: snapshot.tenantDisplayName ?? snapshot.tenantId,
    kind: "AZTenant",
    properties: { tenantid: tenantId },
  });

  // ── directory objects ──

  const userIds = new Set<string>();
  for (const user of snapshot.users) {
    const id = normalizeId(user.id);
    if (!id) continue;
    userIds.add(id);
    b.node({
      objectId: id,
      label: user.userPrincipalName ?? user.displayName ?? id,
      kind: "AZUser",
      properties: {
        displayname: user.displayName,
        userprincipalname: user.userPrincipalName,
        usertype: (user.userType ?? "").toLowerCase(),
        accountenabled: user.accountEnabled,
        onpremisessyncenabled: user.onPremisesSyncEnabled,
        ismfaregistered: user.isMfaRegistered,
      },
    });
  }

  const groupIds = new Set<string>();
  const roleAssignableGroupIds = new Set<string>();
  for (const group of snapshot.groups) {
    const id = normalizeId(group.id);
    if (!id) continue;
    groupIds.add(id);
    if (group.isAssignableToRole === true) roleAssignableGroupIds.add(id);
    b.node({
      objectId: id,
      label: group.displayName ?? id,
      kind: "AZGroup",
      properties: {
        displayname: group.displayName,
        isassignabletorole: group.isAssignableToRole,
        securityenabled: group.securityEnabled,
        membershiprule: group.membershipRule,
        onpremisessyncenabled: group.onPremisesSyncEnabled,
      },
    });
  }

  const spIds = new Set<string>();
  const spByAppId = new Map<string, string>();
  const grantsBySp = new Map<string, string[]>();
  for (const sp of snapshot.servicePrincipals) {
    const id = normalizeId(sp.id);
    if (!id) continue;
    spIds.add(id);
    const appId = normalizeId(sp.appId);
    if (appId) spByAppId.set(appId, id);
    const permissions = grantedPermissionNames(sp);
    grantsBySp.set(id, permissions);
    b.node({
      objectId: id,
      label: sp.displayName ?? sp.appId ?? id,
      kind: "AZServicePrincipal",
      properties: {
        displayname: sp.displayName,
        appid: appId,
        serviceprincipaltype: sp.servicePrincipalType,
        accountenabled: sp.accountEnabled,
        appownerorganizationid: normalizeId(sp.appOwnerOrganizationId),
        external: Boolean(sp.appOwnerOrganizationId && normalizeId(sp.appOwnerOrganizationId) !== tenantId),
        grantedpermissions: permissions,
        credentialcount: (sp.passwordCredentials?.length ?? 0) + (sp.keyCredentials?.length ?? 0),
      },
    });
  }

  const appIds: string[] = [];
  for (const app of snapshot.appRegistrations) {
    const id = normalizeId(app.id);
    if (!id) continue;
    appIds.push(id);
    const appId = normalizeId(app.appId);
    b.node({
      objectId: id,
      label: app.displayName ?? app.appId ?? id,
      kind: "AZApp",
      properties: {
        displayname: app.displayName,
        appid: appId,
        signinaudience: app.signInAudience,
        credentialcount: (app.passwordCredentials?.length ?? 0) + (app.keyCredentials?.length ?? 0),
      },
    });
    // The application registration and its service principal are two objects.
    // Control of the registration (an owner, an Application Administrator, or
    // `Application.ReadWrite.All`) becomes control of the service principal the
    // moment a credential is added, so the edge runs app -> service principal.
    const spId = appId ? spByAppId.get(appId) : undefined;
    if (spId) b.edge(id, spId, "AZRunsAs");
  }

  const relationships = snapshot.relationships;
  for (const device of relationships?.devices ?? []) {
    const id = normalizeId(device.id);
    if (!id) continue;
    b.node({
      objectId: id,
      label: device.displayName ?? id,
      kind: "AZDevice",
      properties: {
        displayname: device.displayName,
        deviceid: normalizeId(device.deviceId),
        operatingsystem: device.operatingSystem,
        trusttype: device.trustType,
        iscompliant: device.isCompliant,
        accountenabled: device.accountEnabled,
      },
    });
  }

  const auMembers = new Map<string, string[]>();
  for (const unit of relationships?.administrativeUnits ?? []) {
    const id = normalizeId(unit.id);
    if (!id) continue;
    const members = (unit.memberIds ?? []).map(normalizeId).filter((m): m is string => Boolean(m));
    auMembers.set(id, members);
    b.node({
      objectId: id,
      label: unit.displayName ?? id,
      kind: "AZAdministrativeUnit",
      properties: {
        displayname: unit.displayName,
        ismembermanagementrestricted: unit.isMemberManagementRestricted,
        membercount: members.length,
      },
    });
    for (const member of members) b.edge(id, member, "AZContains");
  }

  // ── membership and ownership ──

  for (const membership of relationships?.groupMembers ?? []) {
    const groupId = normalizeId(membership.groupId);
    const memberId = normalizeId(membership.memberId);
    if (!groupId || !memberId) continue;
    b.reference(groupId, "AZGroup");
    b.reference(memberId, principalKind(membership.memberType));
    b.edge(memberId, groupId, "AZMemberOf");
  }

  for (const [rows, ownedKind] of [
    [relationships?.applicationOwners ?? [], "AZApp"],
    [relationships?.servicePrincipalOwners ?? [], "AZServicePrincipal"],
    [relationships?.groupOwners ?? [], "AZGroup"],
    [relationships?.deviceOwners ?? [], "AZDevice"],
  ] as const) {
    for (const row of rows) {
      const objectId = normalizeId(row.objectId);
      const ownerId = normalizeId(row.ownerId);
      if (!objectId || !ownerId) continue;
      b.reference(objectId, ownedKind);
      b.reference(ownerId, principalKind(row.ownerType));
      b.edge(ownerId, objectId, "AZOwns");
    }
  }

  // ── role assignments ──
  //
  // Role nodes are created on demand for every role somebody actually holds,
  // plus Global Administrator unconditionally: it is the canonical target, and a
  // tenant where nobody currently holds it can still be escalated *into* it by a
  // Privileged Role Administrator.

  const roleNodes = new Map<string, { templateId: string; scopeId?: string }>();
  const ensureRole = (roleDefinitionId: string, scopeId?: string): string => {
    const templateId = normalizeId(templateIdFor(snapshot, roleDefinitionId)) ?? normalizeId(roleDefinitionId)!;
    const id = roleNodeId(templateId, scopeId);
    if (!roleNodes.has(id)) {
      roleNodes.set(id, { templateId, scopeId });
      b.node({
        objectId: id,
        label: scopeId
          ? `${roleDisplayName(snapshot, roleDefinitionId)} (scoped to ${scopeId})`
          : roleDisplayName(snapshot, roleDefinitionId),
        kind: "AZRole",
        ...(scopeId ? { scopeId } : {}),
        properties: {
          templateid: templateId,
          roledefinitionid: normalizeId(roleDefinitionId),
          tier0: TIER0_ROLE_TEMPLATE_IDS.has(templateId),
          privileged: PRIVILEGED_ROLE_TEMPLATE_IDS.has(templateId),
          scopeid: scopeId,
        },
      });
    }
    return id;
  };

  const globalAdminRole = ensureRole(ROLE_TEMPLATE_IDS.globalAdministrator);

  /** principal -> tenant-wide role template ids it holds (standing or eligible). */
  const rolesByPrincipal = new Map<string, Set<string>>();

  for (const assignment of snapshot.roleAssignments) {
    const principalId = normalizeId(assignment.principalId);
    if (!principalId) continue;
    const scopeId = scopeOf(assignment.directoryScopeId);
    const roleId = ensureRole(assignment.roleDefinitionId, scopeId);
    b.reference(principalId, "AZUser");
    b.edge(principalId, roleId, "AZHasRole", { standing: true, ...(scopeId ? { scopeId } : {}) });
    if (!scopeId) addTo(rolesByPrincipal, principalId, roleNodes.get(roleId)!.templateId);
  }

  for (const schedule of snapshot.roleEligibilitySchedules) {
    if (!isLiveEligibility(schedule.status)) continue;
    const principalId = normalizeId(schedule.principalId);
    if (!principalId) continue;
    const scopeId = scopeOf(schedule.directoryScopeId);
    const roleId = ensureRole(schedule.roleDefinitionId, scopeId);
    b.reference(principalId, "AZUser");
    b.edge(principalId, roleId, "AZHasRole", { standing: false, ...(scopeId ? { scopeId } : {}) });
    if (!scopeId) addTo(rolesByPrincipal, principalId, roleNodes.get(roleId)!.templateId);
  }

  // ── role-derived capability edges ──

  const privilegedPrincipals = [...rolesByPrincipal]
    .filter(([, templates]) => [...templates].some((t) => PRIVILEGED_ROLE_TEMPLATE_IDS.has(t)))
    .map(([principalId]) => principalId);
  const tier0RoleNodeIds = [...roleNodes]
    .filter(([, role]) => !role.scopeId && TIER0_ROLE_TEMPLATE_IDS.has(role.templateId))
    .map(([id]) => id);

  for (const [roleId, role] of roleNodes) {
    if (role.scopeId) continue; // scoped roles are handled separately, below
    switch (role.templateId) {
      case ROLE_TEMPLATE_IDS.globalAdministrator:
        b.edge(roleId, tenant, "AZGlobalAdmin");
        break;
      case ROLE_TEMPLATE_IDS.privilegedRoleAdministrator:
        // Can assign any directory role, so it reaches every tier-0 role node —
        // Global Administrator included, which is how it reaches the tenant.
        for (const target of [globalAdminRole, ...tier0RoleNodeIds]) {
          b.edge(roleId, target, "AZPrivilegedRoleAdmin");
        }
        break;
      case ROLE_TEMPLATE_IDS.privilegedAuthenticationAdministrator:
        b.fanOut(roleId, privilegedPrincipals, "AZPrivilegedAuthAdmin", cap, "Privileged Authentication Administrator");
        break;
      case ROLE_TEMPLATE_IDS.applicationAdministrator:
        b.fanOut(roleId, appIds, "AZAppAdmin", cap, "Application Administrator");
        break;
      case ROLE_TEMPLATE_IDS.cloudApplicationAdministrator:
        b.fanOut(roleId, appIds, "AZCloudAppAdmin", cap, "Cloud Application Administrator");
        break;
      case ROLE_TEMPLATE_IDS.hybridIdentityAdministrator:
      case ROLE_TEMPLATE_IDS.directorySynchronizationAccounts:
        // Control of the sync/federation plane is control of the token-issuing
        // path into the tenant: an attacker holding it can assert any user,
        // Global Administrators included.
        b.edge(roleId, globalAdminRole, "AZGrantRole");
        break;
      default:
        break;
    }
  }

  // AU-scoped roles reach only the members of their unit. Emitting the
  // tenant-wide edges above for a scoped assignment would be a false positive —
  // an AU-scoped User Administrator is not a tenant-wide one.
  for (const [roleId, role] of roleNodes) {
    if (!role.scopeId) continue;
    const members = auMembers.get(role.scopeId) ?? [];
    if (members.length === 0) continue;
    if (isPasswordResetRole(role.templateId)) {
      b.fanOut(roleId, members.filter((m) => userIds.has(m)), "AZResetPassword", cap, `scoped role ${roleId}`);
    }
    if (role.templateId === ROLE_TEMPLATE_IDS.userAdministrator) {
      b.fanOut(roleId, members.filter((m) => groupIds.has(m)), "AZAddMember", cap, `scoped role ${roleId}`);
    }
  }

  // ── consent-grant derived edges ──
  //
  // Only *granted* application permissions (`appRoleAssignments`), never
  // requested ones. Group targets exclude role-assignable groups: modifying one
  // requires Privileged Role Administrator or Global Administrator, not
  // `Group.ReadWrite.All`, so an edge there would be a path that does not work.

  const writableGroupIds = [...groupIds].filter((id) => !roleAssignableGroupIds.has(id));
  // Service principals with no matching in-tenant app registration — a managed
  // identity or a third-party app. There is no AZApp node to route through, so
  // credential-addition has to target the service principal directly.
  const registeredAppIds = new Set(appIds.map((id) => b.nodes.get(id)?.properties.appid).filter(Boolean));
  const orphanSpIds = [...spIds].filter((id) => !registeredAppIds.has(b.nodes.get(id)?.properties.appid));

  for (const [spId, permissions] of grantsBySp) {
    const held = new Set(permissions);
    const has = (name: string): boolean => held.has(name);

    if (has("RoleManagement.ReadWrite.Directory") || has("PrivilegedAccess.ReadWrite.AzureAD")) {
      for (const target of [globalAdminRole, ...tier0RoleNodeIds]) b.edge(spId, target, "AZGrantRole");
    }
    if (has("AppRoleAssignment.ReadWrite.All")) {
      // One step short of the above: it can grant itself
      // `RoleManagement.ReadWrite.Directory` first. The written technique on
      // AZGrantRole says so explicitly.
      b.edge(spId, globalAdminRole, "AZGrantRole");
    }
    if (has("Application.ReadWrite.All")) {
      b.fanOut(spId, appIds, "AZAddSecret", cap, `service principal ${spId}`);
      b.fanOut(spId, orphanSpIds, "AZAddSecret", cap, `service principal ${spId}`);
    }
    if (has("Directory.ReadWrite.All")) {
      b.fanOut(spId, appIds, "AZAddOwner", cap, `service principal ${spId}`);
      b.fanOut(spId, writableGroupIds, "AZAddMember", cap, `service principal ${spId}`);
    }
    if (has("Group.ReadWrite.All") || has("GroupMember.ReadWrite.All")) {
      b.fanOut(spId, writableGroupIds, "AZAddMember", cap, `service principal ${spId}`);
    }
  }

  // ── password-reset roles ──
  //
  // Emitted last, and only against accounts that already have somewhere to go.
  // User / Helpdesk / Authentication Administrator cannot reset a privileged
  // account's password at all (Entra blocks it), and resetting a leaf account
  // that holds no role, group, or ownership extends no path — so both are
  // excluded. That keeps this from being an O(users) fan-out on every tenant.

  const hasOutbound = new Set(b.edges.map((edge) => edge.source));
  const privilegedSet = new Set(privilegedPrincipals);
  const resettable = [...userIds].filter((id) => !privilegedSet.has(id) && hasOutbound.has(id));
  for (const [roleId, role] of roleNodes) {
    if (role.scopeId || !isPasswordResetRole(role.templateId)) continue;
    if (role.templateId === ROLE_TEMPLATE_IDS.privilegedAuthenticationAdministrator) continue; // covered above
    b.fanOut(roleId, resettable, "AZResetPassword", cap, `role ${roleId}`);
  }

  return indexGraph(b, {
    tenantId,
    tenantDisplayName: snapshot.tenantDisplayName,
    origin: opts.origin ?? "tenant-snapshot",
    relationshipsCollected: relationships !== undefined,
    sourceTypes: opts.sourceTypes ?? [opts.origin ?? "tenant-snapshot"],
    warnings: [...b.warnings],
    ingestedAt: now().toISOString(),
    roleCount: roleNodes.size,
  });
}

// ── indexing ──

/**
 * Build the adjacency indices the traversal layer reads. Mirrors `buildAdGraph`
 * but keeps Entra node kinds (an unknown reference becomes an `AZUser` stub, not
 * an AD `Base` one) and carries the richer Entra metadata.
 */
export function indexGraph(
  b: GraphBuilder,
  meta: {
    tenantId: string;
    tenantDisplayName?: string;
    origin: EntraGraphMeta["origin"];
    relationshipsCollected: boolean;
    sourceTypes: string[];
    warnings: string[];
    ingestedAt: string;
    roleCount: number;
  },
): EntraGraph {
  const outbound = new Map<string, number[]>();
  const inbound = new Map<string, number[]>();
  const edgesByKind = new Map<AdEdgeKind, number[]>();
  const nodesByKind = new Map<AdNodeKind, string[]>();

  const push = <K, V>(index: Map<K, V[]>, key: K, value: V): void => {
    const bucket = index.get(key);
    if (bucket) bucket.push(value);
    else index.set(key, [value]);
  };

  const edges: EntraEdge[] = [];
  for (const edge of b.edges) {
    if (!edge.source || !edge.target || !edge.kind) continue;
    // An edge naming an uncollected object still has to be traversable.
    b.reference(edge.source, "AZUser");
    b.reference(edge.target, "AZUser");
    const index = edges.length;
    edges.push(edge);
    push(outbound, edge.source, index);
    push(inbound, edge.target, index);
    push(edgesByKind, edge.kind, index);
  }

  for (const node of b.nodes.values()) push(nodesByKind, node.kind, node.objectId);

  const countOf = (kind: EntraNodeKind): number => nodesByKind.get(kind)?.length ?? 0;

  return {
    nodes: b.nodes,
    edges,
    outbound,
    inbound,
    nodesByKind,
    edgesByKind,
    meta: {
      tenantId: meta.tenantId,
      tenantDisplayName: meta.tenantDisplayName,
      origin: meta.origin,
      relationshipsCollected: meta.relationshipsCollected,
      sourceTypes: meta.sourceTypes,
      nodeCount: b.nodes.size,
      edgeCount: edges.length,
      warnings: meta.warnings,
      ingestedAt: meta.ingestedAt,
      counts: {
        users: countOf("AZUser"),
        groups: countOf("AZGroup"),
        servicePrincipals: countOf("AZServicePrincipal"),
        applications: countOf("AZApp"),
        devices: countOf("AZDevice"),
        administrativeUnits: countOf("AZAdministrativeUnit"),
        roles: meta.roleCount,
      },
    },
  };
}

export { GraphBuilder };

// ── helpers ──

/**
 * Resolved names of the application permissions a service principal has been
 * *granted*. Prefers the collector's tenant-side resolution and falls back to
 * the static catalog, exactly as `analyzeServicePrincipals` does.
 */
export function grantedPermissionNames(sp: ServicePrincipalRecord): string[] {
  const out: string[] = [];
  for (const grant of sp.appRoleAssignments ?? []) {
    const name = grant.value ?? GRAPH_APP_ROLE_CATALOG[grant.appRoleId];
    if (name && !out.includes(name)) out.push(name);
  }
  return out;
}

/** True when the permission set contains anything equivalent to tenant takeover. */
export function holdsTier0Permission(permissions: Iterable<string>): string[] {
  return [...permissions].filter((name) => TIER0_GRAPH_PERMISSIONS.has(name));
}

export function holdsHighImpactPermission(permissions: Iterable<string>): string[] {
  return [...permissions].filter((name) => HIGH_IMPACT_GRAPH_PERMISSIONS.has(name));
}

/**
 * Roles that can reset another account's password. Privileged Authentication
 * Administrator is the only one that may do so against an admin, which is why
 * it is modelled separately from the rest.
 */
function isPasswordResetRole(templateId: string): boolean {
  return (
    templateId === ROLE_TEMPLATE_IDS.userAdministrator ||
    templateId === ROLE_TEMPLATE_IDS.helpdeskAdministrator ||
    templateId === ROLE_TEMPLATE_IDS.authenticationAdministrator ||
    templateId === ROLE_TEMPLATE_IDS.privilegedAuthenticationAdministrator
  );
}

function principalKind(type: string | undefined): EntraNodeKind {
  switch ((type ?? "").toLowerCase()) {
    case "group":
      return "AZGroup";
    case "serviceprincipal":
      return "AZServicePrincipal";
    case "application":
      return "AZApp";
    case "device":
      return "AZDevice";
    default:
      return "AZUser";
  }
}

function addTo(map: Map<string, Set<string>>, key: string, value: string): void {
  const existing = map.get(key);
  if (existing) existing.add(value);
  else map.set(key, new Set([value]));
}
