// How each Entra edge kind is abused, one line per hop.
//
// Same contract as `AD_EDGE_TECHNIQUES` in `../../adgraph/paths.ts`: the string
// is spliced after the source node's label to render an `AttackPathStep`, so it
// reads as a sentence — "SVC-BUILD@contoso.com adds a client secret to the
// application registration and then authenticates as it". Unknown kinds fall
// back to the raw kind name rather than being dropped.

import type { EntraEdge, EntraEdgeKind } from "./types.js";

export const AZ_EDGE_TECHNIQUES: Record<string, string> = {
  // ── structure ──
  AZMemberOf: "inherits every right the group holds through its membership",
  AZHasRole:
    "holds the directory role and everything that role authorises across its scope",
  AZContains:
    "administers the objects inside the administrative unit through its scoped role assignments",
  AZOwns:
    "owns the object and can therefore add credentials, owners, or members to it without any further grant",
  AZRunsAs:
    "authenticates as the application's service principal, inheriting every app role and directory role granted to it",

  // ── object takeover ──
  AZAddSecret:
    "adds a client secret or certificate to the application and then authenticates as it",
  AZAddOwner:
    "adds itself as an owner of the object, which is full control of it from the next request onwards",
  AZAddMember:
    "adds itself to the group and inherits every role and permission assigned to that group",
  AZResetPassword:
    "resets the account's password and signs in as it, without knowing the previous one",

  // ── role-derived control ──
  AZGlobalAdmin:
    "holds Global Administrator, which is unrestricted control of every object and setting in the tenant",
  AZPrivilegedRoleAdmin:
    "can assign any directory role to any principal, including granting itself Global Administrator",
  AZPrivilegedAuthAdmin:
    "can reset the authentication methods of any principal, including Global Administrators, and then sign in as them",
  AZAppAdmin:
    "can add a credential to any application registration in the tenant and authenticate as its service principal",
  AZCloudAppAdmin:
    "can add a credential to any cloud application registration and authenticate as its service principal",

  // ── consent / app-role grant abuse ──
  AZGrantRole:
    "can grant itself a directory role or a Microsoft Graph application permission, escalating to tenant control",
};

export function describeEntraEdgeTechnique(kind: EntraEdgeKind): string {
  return AZ_EDGE_TECHNIQUES[kind] ?? `holds the ${kind} relationship over the target`;
}

/**
 * Edge-level `describeEdge` hook for the traversal layer. Takes the edge rather
 * than the kind so an edge that carries qualifying properties can refine its own
 * wording — a PIM-eligible role assignment is a real path, but it needs an
 * activation first and the write-up must say so rather than implying standing
 * privilege.
 */
export function describeEntraEdge(edge: EntraEdge): string {
  if (edge.kind === "AZHasRole" && edge.properties?.standing === false) {
    return "is PIM-eligible for the directory role and inherits it on activation";
  }
  if (edge.kind === "AZHasRole" && typeof edge.properties?.scopeId === "string") {
    return `holds the directory role, scoped to administrative unit ${edge.properties.scopeId}`;
  }
  return describeEntraEdgeTechnique(edge.kind);
}
