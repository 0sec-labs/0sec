// AzureHound offline ingest — reconstruct a `TenantSnapshot` from an export.
//
// Why this exists: `buildEntraGraph` takes a `TenantSnapshot`, which normally
// comes from a live read-only Graph collection. That requires a token with
// directory read scope, which an engagement may not grant us. AzureHound is the
// collector the rest of the industry already runs, so accepting its output lets
// the client (or the prime contractor) collect while we do the analysis — the
// same split `../../adgraph/ingest.ts` gives on-premises AD via SharpHound.
//
// This module never touches a network and never authenticates. It parses JSON
// that already exists on disk.
//
// Tolerance is deliberate. An AzureHound run may be partial: a missing scope, a
// throttled collection, an operator who only gathered users and groups. Every
// unparseable document produces a warning and an empty contribution rather than
// an exception, and `collections` records what was actually present — because
// "no ownership edges were collected" and "this tenant has no ownership edges"
// are different sentences, and only one of them is a finding.

import type {
  AdministrativeUnitRecord,
  AppRegistration,
  DirectoryMembership,
  DirectoryOwnership,
  GraphAppRoleAssignment,
  GraphKeyCredential,
  GraphPasswordCredential,
  RoleAssignment,
  RoleDefinition,
  ServicePrincipalRecord,
  TenantDevice,
  TenantGroup,
  TenantRelationships,
  TenantSnapshot,
  TenantUser,
} from "../types.js";
import { buildEntraGraph, type BuildEntraGraphOptions } from "./build.js";
import type { EntraGraph } from "./types.js";

// ---------------------------------------------------------------------------
// Accepted file shapes
// ---------------------------------------------------------------------------

/**
 * AzureHound writes `{ "data": [ … ], "meta": { "type": "azusers", … } }`.
 * Items are either flat objects or `{ "kind": "AZUser", "data": { … } }`
 * depending on collector version, so both are accepted. A bare array is also
 * accepted for hand-assembled fixtures.
 */
interface AzureHoundDocument {
  data?: unknown;
  meta?: { type?: unknown; count?: unknown; version?: unknown };
}

export interface AzureHoundIngestResult {
  snapshot: TenantSnapshot;
  /** Parse problems and partial-collection notes. Never throws; warns instead. */
  warnings: string[];
  /**
   * Which AzureHound collections were present, normalised (`azusers`,
   * `azgroupmembers`, …). An absent collection is the difference between "not
   * collected" and "empty", and downstream findings must not conflate them.
   */
  collections: string[];
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const str = (v: unknown): string | undefined => {
  const s = typeof v === "string" ? v.trim() : "";
  return s.length > 0 ? s : undefined;
};

const bool = (v: unknown): boolean | undefined => (typeof v === "boolean" ? v : undefined);

const strArray = (v: unknown): string[] | undefined => {
  if (!Array.isArray(v)) return undefined;
  const out = v.map(str).filter((s): s is string => s !== undefined);
  return out.length > 0 ? out : undefined;
};

/**
 * AzureHound is inconsistent about casing across versions and object types
 * (`Id` vs `id`, `DisplayName` vs `displayName`). Rather than encode every
 * variant at every call site, look up case-insensitively once.
 */
function pick(obj: Record<string, unknown>, ...names: string[]): unknown {
  for (const name of names) {
    if (name in obj) return obj[name];
    const lower = name.toLowerCase();
    for (const key of Object.keys(obj)) {
      if (key.toLowerCase() === lower) return obj[key];
    }
  }
  return undefined;
}

/** `#microsoft.graph.user` → `user`. Used to type membership and ownership rows. */
function odataType(obj: Record<string, unknown>): string | undefined {
  const raw = str(pick(obj, "@odata.type", "odataType", "type"));
  if (!raw) return undefined;
  const tail = raw.split(".").pop();
  return tail ? tail.toLowerCase() : undefined;
}

const PRINCIPAL_TYPES = new Set(["user", "group", "serviceprincipal", "device"]);

function principalType(obj: Record<string, unknown>): DirectoryMembership["memberType"] {
  const t = odataType(obj);
  if (!t || !PRINCIPAL_TYPES.has(t)) return undefined;
  if (t === "user") return "user";
  if (t === "group") return "group";
  if (t === "device") return "device";
  return "servicePrincipal";
}

// ---------------------------------------------------------------------------
// Collection routing
// ---------------------------------------------------------------------------

/**
 * `kind` on an item is more reliable than `meta.type` on the file, because a
 * hand-merged export loses the file boundary but keeps per-item kinds. Both are
 * consulted, item kind first.
 */
const KIND_TO_COLLECTION: Record<string, string> = {
  azuser: "azusers",
  azgroup: "azgroups",
  azserviceprincipal: "azserviceprincipals",
  azapp: "azapps",
  azapplication: "azapps",
  azdevice: "azdevices",
  azrole: "azroles",
  azroleassignment: "azroleassignments",
  azgroupmember: "azgroupmembers",
  azgroupowner: "azgroupowners",
  azappowner: "azappowners",
  azapplicationowner: "azappowners",
  azserviceprincipalowner: "azserviceprincipalowners",
  azadministrativeunit: "azadministrativeunits",
  aztenant: "aztenants",
};

const KNOWN_COLLECTIONS = new Set(Object.values(KIND_TO_COLLECTION));

function normalizeCollection(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const key = raw.trim().toLowerCase().replace(/[\s_-]/g, "");
  if (KNOWN_COLLECTIONS.has(key)) return key;
  return KIND_TO_COLLECTION[key];
}

interface FlatItem {
  collection?: string;
  body: Record<string, unknown>;
}

/** Unwrap one document into flat items tagged with their collection. */
function flatten(doc: unknown, index: number, warnings: string[]): FlatItem[] {
  let payload: unknown = doc;
  let fileCollection: string | undefined;

  if (isRecord(doc)) {
    const d = doc as AzureHoundDocument;
    if (d.meta && isRecord(d.meta)) fileCollection = normalizeCollection(str(d.meta.type));
    if ("data" in d) payload = d.data;
  }

  if (!Array.isArray(payload)) {
    warnings.push(
      `document ${index}: expected an array at \`data\` (AzureHound writes { data: [...], meta: {...} }); skipped`,
    );
    return [];
  }

  const out: FlatItem[] = [];
  for (const raw of payload) {
    if (!isRecord(raw)) continue;
    const kind = normalizeCollection(str(pick(raw, "kind")));
    const inner = pick(raw, "data");
    if (kind && isRecord(inner)) out.push({ collection: kind, body: inner });
    else out.push({ collection: kind ?? fileCollection, body: raw });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Per-collection mappers
// ---------------------------------------------------------------------------

function toUser(o: Record<string, unknown>): TenantUser | undefined {
  const id = str(pick(o, "id", "objectId"));
  if (!id) return undefined;
  return {
    id,
    displayName: str(pick(o, "displayName")),
    userPrincipalName: str(pick(o, "userPrincipalName", "upn")),
    mail: str(pick(o, "mail")),
    accountEnabled: bool(pick(o, "accountEnabled")),
    userType: str(pick(o, "userType")),
    createdDateTime: str(pick(o, "createdDateTime")),
    onPremisesSyncEnabled: bool(pick(o, "onPremisesSyncEnabled")),
    // Hybrid-correspondence anchors. Carried through even though no posture
    // check reads them: `../hybrid/` joins the on-premises graph on these, and
    // dropping them here would silently make every hybrid path unfindable.
    onPremisesImmutableId: str(pick(o, "onPremisesImmutableId", "immutableId")),
    onPremisesSecurityIdentifier: str(pick(o, "onPremisesSecurityIdentifier")),
    onPremisesDistinguishedName: str(pick(o, "onPremisesDistinguishedName")),
    onPremisesSamAccountName: str(pick(o, "onPremisesSamAccountName")),
    onPremisesDomainName: str(pick(o, "onPremisesDomainName")),
  };
}

function toGroup(o: Record<string, unknown>): TenantGroup | undefined {
  const id = str(pick(o, "id", "objectId"));
  if (!id) return undefined;
  return {
    id,
    displayName: str(pick(o, "displayName")),
    description: str(pick(o, "description")),
    mailEnabled: bool(pick(o, "mailEnabled")),
    securityEnabled: bool(pick(o, "securityEnabled")),
    groupTypes: strArray(pick(o, "groupTypes")),
    membershipRule: str(pick(o, "membershipRule")),
    onPremisesSecurityIdentifier: str(pick(o, "onPremisesSecurityIdentifier")),
    onPremisesDistinguishedName: str(pick(o, "onPremisesDistinguishedName")),
    onPremisesSamAccountName: str(pick(o, "onPremisesSamAccountName")),
  };
}

/**
 * Credential and grant arrays are mapped field-by-field rather than passed
 * through. A structural cast would compile but would let a malformed export put
 * an object with no `appRoleId` into the consent-grant analyzer's input, where
 * it would silently fail to match a Tier-0 permission — a false negative in the
 * exact check that matters most.
 */
function toPasswordCredentials(v: unknown): GraphPasswordCredential[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return v.filter(isRecord).map((c) => ({
    keyId: str(pick(c, "keyId")),
    displayName: str(pick(c, "displayName")),
    hint: str(pick(c, "hint")),
    startDateTime: str(pick(c, "startDateTime")),
    endDateTime: str(pick(c, "endDateTime")),
  }));
}

function toKeyCredentials(v: unknown): GraphKeyCredential[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return v.filter(isRecord).map((c) => ({
    keyId: str(pick(c, "keyId")),
    displayName: str(pick(c, "displayName")),
    type: str(pick(c, "type")),
    usage: str(pick(c, "usage")),
    startDateTime: str(pick(c, "startDateTime")),
    endDateTime: str(pick(c, "endDateTime")),
  }));
}

/** Grants missing `id` or `appRoleId` are dropped — they cannot be matched. */
function toAppRoleAssignments(v: unknown): GraphAppRoleAssignment[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: GraphAppRoleAssignment[] = [];
  for (const raw of v) {
    if (!isRecord(raw)) continue;
    const id = str(pick(raw, "id"));
    const appRoleId = str(pick(raw, "appRoleId"));
    if (!id || !appRoleId) continue;
    out.push({
      id,
      appRoleId,
      principalId: str(pick(raw, "principalId")),
      principalDisplayName: str(pick(raw, "principalDisplayName")),
      resourceId: str(pick(raw, "resourceId")),
      resourceDisplayName: str(pick(raw, "resourceDisplayName")),
      createdDateTime: str(pick(raw, "createdDateTime")),
    });
  }
  return out;
}

function toServicePrincipal(o: Record<string, unknown>): ServicePrincipalRecord | undefined {
  const id = str(pick(o, "id", "objectId"));
  if (!id) return undefined;
  return {
    id,
    // `appId` is required on the record but an export may omit it. Empty string
    // rather than a synthetic value: the graph builder keys on the object id,
    // and inventing an appId would make two distinct principals look related.
    appId: str(pick(o, "appId")) ?? "",
    displayName: str(pick(o, "displayName")),
    servicePrincipalType: str(pick(o, "servicePrincipalType")),
    accountEnabled: bool(pick(o, "accountEnabled")),
    appOwnerOrganizationId: str(pick(o, "appOwnerOrganizationId")),
    signInAudience: str(pick(o, "signInAudience")),
    tags: strArray(pick(o, "tags")),
    passwordCredentials: toPasswordCredentials(pick(o, "passwordCredentials")),
    keyCredentials: toKeyCredentials(pick(o, "keyCredentials")),
    appRoleAssignments: toAppRoleAssignments(pick(o, "appRoleAssignments", "appRoleAssignedTo")),
  };
}

function toApp(o: Record<string, unknown>): AppRegistration | undefined {
  const id = str(pick(o, "id", "objectId"));
  if (!id) return undefined;
  return {
    id,
    appId: str(pick(o, "appId")) ?? "",
    displayName: str(pick(o, "displayName")),
    signInAudience: str(pick(o, "signInAudience")),
    createdDateTime: str(pick(o, "createdDateTime")),
    publisherDomain: str(pick(o, "publisherDomain")),
    passwordCredentials: toPasswordCredentials(pick(o, "passwordCredentials")),
    keyCredentials: toKeyCredentials(pick(o, "keyCredentials")),
  };
}

function toDevice(o: Record<string, unknown>): TenantDevice | undefined {
  const id = str(pick(o, "id", "objectId"));
  if (!id) return undefined;
  return {
    id,
    displayName: str(pick(o, "displayName")),
    deviceId: str(pick(o, "deviceId")),
    operatingSystem: str(pick(o, "operatingSystem")),
    trustType: str(pick(o, "trustType")),
    isCompliant: bool(pick(o, "isCompliant")),
    isManaged: bool(pick(o, "isManaged")),
    accountEnabled: bool(pick(o, "accountEnabled")),
  };
}

function toRoleDefinition(o: Record<string, unknown>): RoleDefinition | undefined {
  const id = str(pick(o, "id", "roleDefinitionId", "templateId"));
  if (!id) return undefined;
  return {
    id,
    displayName: str(pick(o, "displayName")),
    templateId: str(pick(o, "templateId", "roleTemplateId")),
    isBuiltIn: bool(pick(o, "isBuiltIn")),
    isEnabled: bool(pick(o, "isEnabled")),
    description: str(pick(o, "description")),
  };
}

function toRoleAssignment(o: Record<string, unknown>): RoleAssignment | undefined {
  const roleDefinitionId = str(pick(o, "roleDefinitionId", "roleTemplateId", "templateId"));
  const principalId = str(pick(o, "principalId", "principalObjectId", "memberId"));
  if (!roleDefinitionId || !principalId) return undefined;
  return {
    id: str(pick(o, "id")) ?? `${roleDefinitionId}:${principalId}`,
    roleDefinitionId,
    principalId,
    directoryScopeId: str(pick(o, "directoryScopeId", "scopeId")),
  };
}

/** Membership rows carry the member either inline or as a nested object. */
function toMembership(o: Record<string, unknown>): DirectoryMembership | undefined {
  const groupId = str(pick(o, "groupId", "groupObjectId", "id"));
  const memberRaw = pick(o, "member");
  const member = isRecord(memberRaw) ? memberRaw : o;
  const memberId = str(pick(member, "memberId", "id", "objectId"));
  if (!groupId || !memberId || groupId === memberId) return undefined;
  return {
    groupId,
    memberId,
    memberType: principalType(member),
    memberDisplayName: str(pick(member, "displayName")),
  };
}

function toOwnership(o: Record<string, unknown>): DirectoryOwnership | undefined {
  const objectId = str(pick(o, "objectId", "appId", "groupId", "servicePrincipalId", "id"));
  const ownerRaw = pick(o, "owner");
  const owner = isRecord(ownerRaw) ? ownerRaw : o;
  const ownerId = str(pick(owner, "ownerId", "id", "objectId"));
  if (!objectId || !ownerId || objectId === ownerId) return undefined;
  return {
    objectId,
    ownerId,
    ownerType: principalType(owner),
    ownerDisplayName: str(pick(owner, "displayName")),
  };
}

function toAdministrativeUnit(o: Record<string, unknown>): AdministrativeUnitRecord | undefined {
  const id = str(pick(o, "id", "objectId"));
  if (!id) return undefined;
  return {
    id,
    displayName: str(pick(o, "displayName")),
    description: str(pick(o, "description")),
    isMemberManagementRestricted: bool(pick(o, "isMemberManagementRestricted")),
    memberIds: strArray(pick(o, "memberIds", "members")),
  };
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/**
 * Reconstruct a `TenantSnapshot` from one or more parsed AzureHound documents.
 *
 * The result is deliberately partial where the export was partial: the posture
 * collections the 27 checks read (conditional access, federation, eligibility
 * schedules) are not part of an AzureHound run, so they come back empty with a
 * warning saying so. Run `0sec identity` against a live tenant for those.
 */
export function ingestAzureHound(documents: readonly unknown[]): AzureHoundIngestResult {
  const warnings: string[] = [];
  const seen = new Set<string>();

  const users: TenantUser[] = [];
  const groups: TenantGroup[] = [];
  const servicePrincipals: ServicePrincipalRecord[] = [];
  const appRegistrations: AppRegistration[] = [];
  const devices: TenantDevice[] = [];
  const roleDefinitions: RoleDefinition[] = [];
  const roleAssignments: RoleAssignment[] = [];
  const groupMembers: DirectoryMembership[] = [];
  const groupOwners: DirectoryOwnership[] = [];
  const applicationOwners: DirectoryOwnership[] = [];
  const servicePrincipalOwners: DirectoryOwnership[] = [];
  const deviceOwners: DirectoryOwnership[] = [];
  const administrativeUnits: AdministrativeUnitRecord[] = [];

  let tenantId: string | undefined;
  let tenantDisplayName: string | undefined;
  let unrouted = 0;

  const push = <T>(sink: T[], value: T | undefined): void => {
    if (value !== undefined) sink.push(value);
  };

  documents.forEach((doc, i) => {
    for (const { collection, body } of flatten(doc, i, warnings)) {
      if (collection) seen.add(collection);
      switch (collection) {
        case "azusers": push(users, toUser(body)); break;
        case "azgroups": push(groups, toGroup(body)); break;
        case "azserviceprincipals": push(servicePrincipals, toServicePrincipal(body)); break;
        case "azapps": push(appRegistrations, toApp(body)); break;
        case "azdevices": push(devices, toDevice(body)); break;
        case "azroles": push(roleDefinitions, toRoleDefinition(body)); break;
        case "azroleassignments": push(roleAssignments, toRoleAssignment(body)); break;
        case "azgroupmembers": push(groupMembers, toMembership(body)); break;
        case "azgroupowners": push(groupOwners, toOwnership(body)); break;
        case "azappowners": push(applicationOwners, toOwnership(body)); break;
        case "azserviceprincipalowners": push(servicePrincipalOwners, toOwnership(body)); break;
        case "azdeviceowners": push(deviceOwners, toOwnership(body)); break;
        case "azadministrativeunits": push(administrativeUnits, toAdministrativeUnit(body)); break;
        case "aztenants":
          tenantId ??= str(pick(body, "tenantId", "id", "objectId"));
          tenantDisplayName ??= str(pick(body, "displayName", "name"));
          break;
        default:
          unrouted += 1;
      }
      tenantId ??= str(pick(body, "tenantId"));
    }
  });

  if (unrouted > 0) {
    warnings.push(
      `${unrouted} item(s) had no recognised AzureHound kind or meta.type and were skipped`,
    );
  }
  if (!tenantId) {
    warnings.push("no tenant id found in the export; graph metadata will report `unknown`");
  }

  // The distinction that matters downstream: relationship collections absent
  // from the export mean the collector was not asked for them. Reporting an
  // empty relationship set as if it were a clean directory would be a false
  // negative in a client report.
  const relationshipCollections = [
    "azgroupmembers",
    "azgroupowners",
    "azappowners",
    "azserviceprincipalowners",
    "azdeviceowners",
  ];
  const haveRelationships = relationshipCollections.some((c) => seen.has(c));
  if (!haveRelationships) {
    warnings.push(
      "export carried no membership or ownership collections — attack paths that depend on them cannot be computed, and their absence is not evidence that none exist",
    );
  }

  for (const missing of ["azusers", "azgroups", "azroleassignments"].filter((c) => !seen.has(c))) {
    warnings.push(`export carried no \`${missing}\` collection; coverage is partial`);
  }

  warnings.push(
    "AzureHound exports do not include conditional-access policies, federation configuration, or PIM eligibility schedules — run `0sec identity` against a live tenant for the posture checks that read them",
  );

  const relationships: TenantRelationships | undefined = haveRelationships
    ? {
        groupMembers,
        groupOwners,
        applicationOwners,
        servicePrincipalOwners,
        devices,
        deviceOwners,
        administrativeUnits,
      }
    : undefined;

  const snapshot: TenantSnapshot = {
    tenantId: tenantId ?? "unknown",
    tenantDisplayName,
    collectedAt: new Date(0).toISOString(),
    users,
    groups,
    servicePrincipals,
    appRegistrations,
    roleDefinitions,
    roleAssignments,
    roleEligibilitySchedules: [],
    conditionalAccessPolicies: [],
    federationConfig: { domains: [] },
    relationships,
    warnings: [...warnings],
  };

  return { snapshot, warnings, collections: [...seen].sort() };
}

/**
 * Convenience: ingest an AzureHound export and build the graph in one call,
 * tagging the result `origin: "azurehound"` so a consumer can distinguish an
 * offline reconstruction from a live collection.
 */
export function buildEntraGraphFromAzureHound(
  documents: readonly unknown[],
  opts: BuildEntraGraphOptions = {},
): { graph: EntraGraph; ingest: AzureHoundIngestResult } {
  const ingest = ingestAzureHound(documents);
  const graph = buildEntraGraph(ingest.snapshot, {
    ...opts,
    origin: "azurehound",
    sourceTypes: ingest.collections.length > 0 ? ingest.collections : ["azurehound"],
  });
  return { graph, ingest };
}
