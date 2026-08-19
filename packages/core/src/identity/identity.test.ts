import { describe, it, expect } from "vitest";
import { ScopePolicy } from "../scope/scope.js";
import {
  analyzeAppRegistrations,
  analyzeConditionalAccess,
  analyzeFederation,
  analyzePrivilegedRoles,
  analyzeServicePrincipals,
  ROLE_TEMPLATE_IDS,
} from "./analyzers.js";
import {
  collectTenantSnapshot,
  GraphAuthError,
  GraphClient,
  GraphError,
  GraphForbiddenError,
  GraphNetworkError,
  GraphRateLimitError,
  GraphScopeError,
  MICROSOFT_GRAPH_APP_ID,
} from "./graph-client.js";
import { runIdentityAssessment } from "./index.js";
import type {
  AppRegistration,
  ConditionalAccessPolicy,
  FederatedDomain,
  IdentityCheck,
  IdentityFinding,
  ServicePrincipalRecord,
  TenantSnapshot,
  TenantUser,
} from "./types.js";

// ── fixtures ──

const GA = ROLE_TEMPLATE_IDS.globalAdministrator;
const USER_ADMIN = ROLE_TEMPLATE_IDS.userAdministrator;
const NOW = new Date("2026-03-01T00:00:00Z");

/** Well-known Microsoft Graph app-role GUIDs used across the fixtures. */
const PERM = {
  directoryReadWriteAll: "19dbc75e-c2e2-444c-a770-ec69d8559fc7",
  applicationReadWriteAll: "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",
  roleManagementReadWriteDirectory: "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
  mailRead: "810c84a8-4a9e-49e6-bf7d-12d183f40d01",
  directoryReadAll: "7ab1d382-f21e-4acd-a863-ba3e13f7da61",
};

function snapshot(overrides: Partial<TenantSnapshot> = {}): TenantSnapshot {
  return {
    tenantId: "11111111-2222-3333-4444-555555555555",
    tenantDisplayName: "Contoso",
    collectedAt: NOW.toISOString(),
    users: [],
    groups: [],
    servicePrincipals: [],
    appRegistrations: [],
    roleDefinitions: [
      { id: GA, templateId: GA, displayName: "Global Administrator", isBuiltIn: true },
      { id: USER_ADMIN, templateId: USER_ADMIN, displayName: "User Administrator", isBuiltIn: true },
    ],
    roleAssignments: [],
    roleEligibilitySchedules: [],
    conditionalAccessPolicies: [],
    federationConfig: { domains: [] },
    warnings: [],
    ...overrides,
  };
}

function user(id: string, overrides: Partial<TenantUser> = {}): TenantUser {
  return {
    id,
    displayName: `User ${id}`,
    userPrincipalName: `${id}@contoso.com`,
    accountEnabled: true,
    userType: "Member",
    onPremisesSyncEnabled: false,
    isMfaRegistered: true,
    isMfaCapable: true,
    ...overrides,
  };
}

function checks(findings: IdentityFinding[]): IdentityCheck[] {
  return findings.map((f) => f.check);
}

function withCheck(findings: IdentityFinding[], check: IdentityCheck): IdentityFinding[] {
  return findings.filter((f) => f.check === check);
}

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

// ── analyzePrivilegedRoles ──

describe("analyzePrivilegedRoles", () => {
  it("flags more standing Global Administrators than the configured ceiling", () => {
    const admins = ["u1", "u2", "u3", "u4", "u5"];
    const result = analyzePrivilegedRoles(
      snapshot({
        users: admins.map((id) => user(id)),
        roleAssignments: admins.map((id) => ({ id: `ra-${id}`, principalId: id, roleDefinitionId: GA })),
      }),
    );
    const finding = withCheck(result, "excessive-standing-global-admins");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("high");
    expect(finding[0].title).toContain("5");
    expect(finding[0].affectedPrincipals.map((p) => p.id).sort()).toEqual(admins);
  });

  it("raises nothing for a tenant with PIM-backed, MFA-registered admins", () => {
    const admins = ["u1", "u2", "u3"];
    const result = analyzePrivilegedRoles(
      snapshot({
        users: admins.map((id) => user(id)),
        roleAssignments: admins.map((id) => ({ id: `ra-${id}`, principalId: id, roleDefinitionId: GA })),
        roleEligibilitySchedules: admins.map((id) => ({
          id: `res-${id}`,
          principalId: id,
          roleDefinitionId: GA,
          status: "Provisioned",
        })),
      }),
    );
    expect(result).toEqual([]);
  });

  it("does not count an activated PIM assignment as standing", () => {
    const base = {
      users: [user("u1"), user("u2"), user("u3"), user("u4"), user("u5")],
      roleAssignments: ["u1", "u2", "u3", "u4", "u5"].map((id) => ({
        id: `ra-${id}`,
        principalId: id,
        roleDefinitionId: GA,
      })),
    };
    const withoutPim = analyzePrivilegedRoles(snapshot(base));
    const withPim = analyzePrivilegedRoles(
      snapshot({
        ...base,
        roleEligibilitySchedules: ["u4", "u5"].map((id) => ({
          id: `res-${id}`,
          principalId: id,
          roleDefinitionId: GA,
          status: "Provisioned",
        })),
      }),
    );
    expect(withCheck(withoutPim, "excessive-standing-global-admins")).toHaveLength(1);
    // 3 standing admins is under the default ceiling of 4.
    expect(withCheck(withPim, "excessive-standing-global-admins")).toHaveLength(0);
    expect(withCheck(withPim, "standing-privileged-access")).toHaveLength(3);
  });

  it("ignores a revoked eligibility schedule when deciding whether access is standing", () => {
    const result = analyzePrivilegedRoles(
      snapshot({
        users: [user("u1"), user("u2")],
        roleAssignments: [
          { id: "ra-1", principalId: "u1", roleDefinitionId: GA },
          { id: "ra-2", principalId: "u2", roleDefinitionId: GA },
        ],
        roleEligibilitySchedules: [
          { id: "res-1", principalId: "u1", roleDefinitionId: GA, status: "Revoked" },
        ],
      }),
    );
    expect(withCheck(result, "standing-privileged-access").map((f) => f.affectedPrincipals[0].id).sort())
      .toEqual(["u1", "u2"]);
  });

  it("resolves a custom role definition id through its templateId", () => {
    const result = analyzePrivilegedRoles(
      snapshot({
        users: [user("u1", { isMfaRegistered: false }), user("u2")],
        roleDefinitions: [
          { id: "custom-def-1", templateId: GA, displayName: "Global Administrator", isBuiltIn: true },
        ],
        roleAssignments: [
          { id: "ra-1", principalId: "u1", roleDefinitionId: "custom-def-1" },
          { id: "ra-2", principalId: "u2", roleDefinitionId: "custom-def-1" },
        ],
      }),
    );
    expect(withCheck(result, "privileged-account-without-mfa")).toHaveLength(1);
    expect(withCheck(result, "insufficient-global-admins")).toHaveLength(0);
  });

  it("flags a privileged account with no MFA registered", () => {
    const result = analyzePrivilegedRoles(
      snapshot({
        users: [user("u1", { isMfaRegistered: false }), user("u2")],
        roleAssignments: [
          { id: "ra-1", principalId: "u1", roleDefinitionId: GA },
          { id: "ra-2", principalId: "u2", roleDefinitionId: GA },
        ],
      }),
    );
    const finding = withCheck(result, "privileged-account-without-mfa");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("critical");
    expect(finding[0].affectedPrincipals[0].userPrincipalName).toBe("u1@contoso.com");
  });

  it("treats unknown MFA state as unknown, not as missing MFA", () => {
    const result = analyzePrivilegedRoles(
      snapshot({
        users: [
          user("u1", { isMfaRegistered: undefined }),
          user("u2", { isMfaRegistered: undefined }),
        ],
        roleAssignments: [
          { id: "ra-1", principalId: "u1", roleDefinitionId: GA },
          { id: "ra-2", principalId: "u2", roleDefinitionId: GA },
        ],
      }),
    );
    expect(withCheck(result, "privileged-account-without-mfa")).toHaveLength(0);
  });

  it("flags a guest, a disabled account, and an on-prem synced account in privileged roles", () => {
    const result = analyzePrivilegedRoles(
      snapshot({
        users: [
          user("guest", { userType: "Guest" }),
          user("disabled", { accountEnabled: false }),
          user("synced", { onPremisesSyncEnabled: true }),
        ],
        roleAssignments: [
          { id: "ra-1", principalId: "guest", roleDefinitionId: GA },
          { id: "ra-2", principalId: "disabled", roleDefinitionId: GA },
          { id: "ra-3", principalId: "synced", roleDefinitionId: GA },
        ],
      }),
    );
    expect(withCheck(result, "guest-in-privileged-role")[0].severity).toBe("critical");
    expect(withCheck(result, "disabled-account-in-privileged-role")[0].severity).toBe("medium");
    expect(withCheck(result, "synced-account-in-privileged-role")[0].severity).toBe("high");
  });

  it("rates a non-tier-0 role lower than a tier-0 role for the same posture problem", () => {
    const result = analyzePrivilegedRoles(
      snapshot({
        users: [user("u1", { userType: "Guest" }), user("u2"), user("u3")],
        roleAssignments: [
          { id: "ra-1", principalId: "u1", roleDefinitionId: USER_ADMIN },
          { id: "ra-2", principalId: "u2", roleDefinitionId: GA },
          { id: "ra-3", principalId: "u3", roleDefinitionId: GA },
        ],
      }),
    );
    expect(withCheck(result, "guest-in-privileged-role")[0].severity).toBe("high");
    expect(withCheck(result, "standing-privileged-access").find((f) => f.id.endsWith("u1"))?.severity)
      .toBe("medium");
  });

  it("flags a single-administrator tenant as a lockout risk", () => {
    const result = analyzePrivilegedRoles(
      snapshot({
        users: [user("u1")],
        roleAssignments: [{ id: "ra-1", principalId: "u1", roleDefinitionId: GA }],
      }),
    );
    expect(withCheck(result, "insufficient-global-admins")).toHaveLength(1);
  });

  it("stays silent when role management could not be read at all", () => {
    const result = analyzePrivilegedRoles(
      snapshot({ users: [user("u1")], warnings: ["roleAssignments: HTTP 403"] }),
    );
    expect(result).toEqual([]);
  });
});

// ── analyzeConditionalAccess ──

function mfaAdminPolicy(overrides: Partial<ConditionalAccessPolicy> = {}): ConditionalAccessPolicy {
  return {
    id: "cap-mfa-admins",
    displayName: "Require MFA for admins",
    state: "enabled",
    modifiedDateTime: "2026-02-01T00:00:00Z",
    conditions: {
      users: { includeRoles: [GA, USER_ADMIN] },
      applications: { includeApplications: ["All"] },
      clientAppTypes: ["all"],
    },
    grantControls: { operator: "OR", builtInControls: ["mfa"] },
    ...overrides,
  };
}

function legacyBlockPolicy(overrides: Partial<ConditionalAccessPolicy> = {}): ConditionalAccessPolicy {
  return {
    id: "cap-legacy",
    displayName: "Block legacy authentication",
    state: "enabled",
    modifiedDateTime: "2026-02-01T00:00:00Z",
    conditions: {
      users: { includeUsers: ["All"] },
      applications: { includeApplications: ["All"] },
      clientAppTypes: ["exchangeActiveSync", "other"],
    },
    grantControls: { operator: "OR", builtInControls: ["block"] },
    ...overrides,
  };
}

describe("analyzeConditionalAccess", () => {
  it("flags a tenant with no enforced policies at all", () => {
    const result = analyzeConditionalAccess(snapshot(), { now: NOW });
    expect(checks(result)).toEqual(
      expect.arrayContaining([
        "no-enabled-conditional-access-policies",
        "no-mfa-policy-for-admins",
        "legacy-authentication-not-blocked",
      ]),
    );
    expect(withCheck(result, "no-enabled-conditional-access-policies")[0].severity).toBe("critical");
  });

  it("raises nothing for a baseline of enforced MFA-for-admins plus legacy block", () => {
    const result = analyzeConditionalAccess(
      snapshot({ conditionalAccessPolicies: [mfaAdminPolicy(), legacyBlockPolicy()] }),
      { now: NOW },
    );
    expect(result).toEqual([]);
  });

  it("stays silent when the policy collection could not be read", () => {
    const result = analyzeConditionalAccess(
      snapshot({ warnings: ["identity/conditionalAccess/policies: HTTP 403"] }),
      { now: NOW },
    );
    expect(result).toEqual([]);
  });

  it("does not credit a disabled policy as coverage", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        conditionalAccessPolicies: [
          mfaAdminPolicy({ state: "disabled" }),
          legacyBlockPolicy({ state: "disabled" }),
        ],
      }),
      { now: NOW },
    );
    expect(checks(result)).toContain("no-mfa-policy-for-admins");
    expect(checks(result)).toContain("legacy-authentication-not-blocked");
  });

  it("accepts an authentication strength in place of the coarse mfa control", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        conditionalAccessPolicies: [
          mfaAdminPolicy({
            grantControls: {
              operator: "OR",
              builtInControls: [],
              authenticationStrength: { id: "str-1", displayName: "Phishing-resistant MFA" },
            },
          }),
          legacyBlockPolicy(),
        ],
      }),
      { now: NOW },
    );
    expect(checks(result)).not.toContain("no-mfa-policy-for-admins");
  });

  it("does not treat an all-client-apps block policy as a legacy-auth block", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        conditionalAccessPolicies: [
          mfaAdminPolicy(),
          legacyBlockPolicy({ conditions: { ...legacyBlockPolicy().conditions, clientAppTypes: ["all"] } }),
        ],
      }),
      { now: NOW },
    );
    expect(checks(result)).toContain("legacy-authentication-not-blocked");
  });

  it("does not accept a block that covers only exchangeActiveSync as a full legacy block", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        conditionalAccessPolicies: [
          mfaAdminPolicy(),
          legacyBlockPolicy({
            conditions: { ...legacyBlockPolicy().conditions, clientAppTypes: ["exchangeActiveSync"] },
          }),
        ],
      }),
      { now: NOW },
    );
    expect(checks(result)).toContain("legacy-authentication-not-blocked");
  });

  it("flags a policy parked in report-only past the evaluation window", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        conditionalAccessPolicies: [
          mfaAdminPolicy(),
          legacyBlockPolicy(),
          {
            id: "cap-ro",
            displayName: "Require compliant device",
            state: "enabledForReportingButNotEnforced",
            modifiedDateTime: "2026-01-01T00:00:00Z",
            grantControls: { builtInControls: ["compliantDevice"] },
          },
        ],
      }),
      { now: NOW },
    );
    const finding = withCheck(result, "policy-stuck-in-report-only");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("medium");
    expect(finding[0].title).toContain("59 days");
  });

  it("escalates a report-only policy that is the only thing closing an open gap", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        conditionalAccessPolicies: [
          legacyBlockPolicy(),
          mfaAdminPolicy({ state: "enabledForReportingButNotEnforced", modifiedDateTime: "2026-01-01T00:00:00Z" }),
        ],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "policy-stuck-in-report-only")[0].severity).toBe("high");
  });

  it("leaves a recently changed report-only policy alone", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        conditionalAccessPolicies: [
          mfaAdminPolicy(),
          legacyBlockPolicy(),
          {
            id: "cap-ro",
            displayName: "New policy under evaluation",
            state: "enabledForReportingButNotEnforced",
            modifiedDateTime: "2026-02-20T00:00:00Z",
            grantControls: { builtInControls: ["mfa"] },
          },
        ],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "policy-stuck-in-report-only")).toHaveLength(0);
  });

  it("flags user exclusions on an enforcing policy", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        users: [user("carveout")],
        conditionalAccessPolicies: [
          mfaAdminPolicy({
            conditions: {
              users: { includeRoles: [GA], excludeUsers: ["carveout"] },
              clientAppTypes: ["all"],
            },
          }),
          legacyBlockPolicy(),
        ],
      }),
      { now: NOW },
    );
    const finding = withCheck(result, "critical-policy-exclusions");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("high");
    expect(finding[0].evidence.some((e) => e.detail.includes("carveout@contoso.com"))).toBe(true);
  });

  it("accepts declared break-glass accounts as a legitimate exclusion", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        users: [user("breakglass")],
        conditionalAccessPolicies: [
          mfaAdminPolicy({
            conditions: {
              users: { includeRoles: [GA], excludeUsers: ["breakglass"] },
              clientAppTypes: ["all"],
            },
          }),
          legacyBlockPolicy(),
        ],
      }),
      { now: NOW, breakGlassPrincipalIds: ["breakglass"] },
    );
    expect(withCheck(result, "critical-policy-exclusions")).toHaveLength(0);
  });

  it("escalates when the carve-out is an entire privileged directory role", () => {
    const result = analyzeConditionalAccess(
      snapshot({
        conditionalAccessPolicies: [
          mfaAdminPolicy({
            conditions: {
              users: { includeUsers: ["All"], excludeRoles: [GA] },
              clientAppTypes: ["all"],
            },
          }),
          legacyBlockPolicy(),
        ],
      }),
      { now: NOW },
    );
    const finding = withCheck(result, "critical-policy-exclusions");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("critical");
    expect(finding[0].evidence.some((e) => e.detail.includes("Global Administrator"))).toBe(true);
  });
});

// ── analyzeAppRegistrations ──

function app(overrides: Partial<AppRegistration> = {}): AppRegistration {
  return {
    id: "app-obj-1",
    appId: "app-1",
    displayName: "Reporting Job",
    signInAudience: "AzureADMyOrg",
    passwordCredentials: [
      { keyId: "k1", displayName: "ci", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2026-06-01T00:00:00Z" },
    ],
    requiredResourceAccess: [
      {
        resourceAppId: MICROSOFT_GRAPH_APP_ID,
        resourceAccess: [{ id: PERM.directoryReadAll, type: "Role" }],
      },
    ],
    ...overrides,
  };
}

describe("analyzeAppRegistrations", () => {
  it("raises nothing for a least-privilege app with a bounded credential", () => {
    const result = analyzeAppRegistrations(snapshot({ appRegistrations: [app()] }), { now: NOW });
    expect(result).toEqual([]);
  });

  it("flags a tier-0 application permission as critical", () => {
    const result = analyzeAppRegistrations(
      snapshot({
        appRegistrations: [
          app({
            requiredResourceAccess: [
              {
                resourceAppId: MICROSOFT_GRAPH_APP_ID,
                resourceAccess: [{ id: PERM.roleManagementReadWriteDirectory, type: "Role" }],
              },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    const finding = withCheck(result, "app-requests-tier0-graph-permission");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("critical");
    expect(finding[0].evidence[0].detail).toContain("RoleManagement.ReadWrite.Directory");
  });

  it("rates the delegated form of a tier-0 permission below the application form", () => {
    const result = analyzeAppRegistrations(
      snapshot({
        appRegistrations: [
          app({
            requiredResourceAccess: [
              {
                resourceAppId: MICROSOFT_GRAPH_APP_ID,
                resourceAccess: [{ id: PERM.directoryReadWriteAll, type: "Scope" }],
              },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "app-requests-tier0-graph-permission")[0].severity).toBe("high");
  });

  it("prefers the collector-resolved permission name over the static catalog", () => {
    const result = analyzeAppRegistrations(
      snapshot({
        appRegistrations: [
          app({
            requiredResourceAccess: [
              {
                resourceAppId: MICROSOFT_GRAPH_APP_ID,
                resourceAccess: [
                  { id: "guid-not-in-any-catalog", type: "Role", value: "Application.ReadWrite.All" },
                ],
              },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "app-requests-tier0-graph-permission")).toHaveLength(1);
  });

  it("ignores an unresolvable permission GUID rather than guessing", () => {
    const result = analyzeAppRegistrations(
      snapshot({
        appRegistrations: [
          app({
            requiredResourceAccess: [
              { resourceAppId: MICROSOFT_GRAPH_APP_ID, resourceAccess: [{ id: "unknown-guid", type: "Role" }] },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    expect(result).toEqual([]);
  });

  it("flags broad data-access permissions separately from tier-0", () => {
    const result = analyzeAppRegistrations(
      snapshot({
        appRegistrations: [
          app({
            requiredResourceAccess: [
              { resourceAppId: MICROSOFT_GRAPH_APP_ID, resourceAccess: [{ id: PERM.mailRead, type: "Role" }] },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "app-requests-tier0-graph-permission")).toHaveLength(0);
    expect(withCheck(result, "app-requests-high-impact-graph-permission")[0].severity).toBe("high");
  });

  it("escalates a multi-tenant app that requests high privilege", () => {
    const result = analyzeAppRegistrations(
      snapshot({
        appRegistrations: [
          app({
            signInAudience: "AzureADMultipleOrgs",
            requiredResourceAccess: [
              {
                resourceAppId: MICROSOFT_GRAPH_APP_ID,
                resourceAccess: [{ id: PERM.applicationReadWriteAll, type: "Role" }],
              },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    const finding = withCheck(result, "multi-tenant-app-with-high-privilege");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("critical");
  });

  it("does not flag a multi-tenant app that only requests low-privilege permissions", () => {
    const result = analyzeAppRegistrations(
      snapshot({ appRegistrations: [app({ signInAudience: "AzureADMultipleOrgs" })] }),
      { now: NOW },
    );
    expect(withCheck(result, "multi-tenant-app-with-high-privilege")).toHaveLength(0);
  });

  it("flags expired credentials left attached to the registration", () => {
    const result = analyzeAppRegistrations(
      snapshot({
        appRegistrations: [
          app({
            passwordCredentials: [
              { keyId: "old", displayName: "rotated", startDateTime: "2025-01-01T00:00:00Z", endDateTime: "2026-01-15T00:00:00Z" },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    const finding = withCheck(result, "app-credential-expired");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("low");
  });

  it("scales long-lived credential severity with the lifetime", () => {
    const medium = analyzeAppRegistrations(
      snapshot({
        appRegistrations: [
          app({
            passwordCredentials: [
              { keyId: "k", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2027-07-01T00:00:00Z" },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    const high = analyzeAppRegistrations(
      snapshot({
        appRegistrations: [
          app({
            keyCredentials: [
              { keyId: "c", type: "AsymmetricX509Cert", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2029-01-01T00:00:00Z" },
            ],
            passwordCredentials: [],
          }),
        ],
      }),
      { now: NOW },
    );
    expect(withCheck(medium, "app-credential-long-lived")[0].severity).toBe("medium");
    expect(withCheck(high, "app-credential-long-lived")[0].severity).toBe("high");
  });
});

// ── analyzeServicePrincipals ──

function servicePrincipal(overrides: Partial<ServicePrincipalRecord> = {}): ServicePrincipalRecord {
  return {
    id: "sp-1",
    appId: "app-1",
    displayName: "Reporting Job",
    servicePrincipalType: "Application",
    accountEnabled: true,
    passwordCredentials: [
      { keyId: "k1", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2026-09-01T00:00:00Z" },
    ],
    appRoleAssignments: [],
    ...overrides,
  };
}

describe("analyzeServicePrincipals", () => {
  it("raises nothing for an unprivileged SP with a bounded credential", () => {
    const result = analyzeServicePrincipals(snapshot({ servicePrincipals: [servicePrincipal()] }), { now: NOW });
    expect(result).toEqual([]);
  });

  it("flags a service principal holding a tier-0 directory role", () => {
    const result = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [servicePrincipal()],
        roleAssignments: [{ id: "ra-1", principalId: "sp-1", roleDefinitionId: GA }],
      }),
      { now: NOW },
    );
    const finding = withCheck(result, "service-principal-in-privileged-role");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("critical");
    expect(finding[0].evidence[0].detail).toContain("Global Administrator");
  });

  it("rates a non-tier-0 directory role on a service principal as high", () => {
    const result = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [servicePrincipal()],
        roleAssignments: [{ id: "ra-1", principalId: "sp-1", roleDefinitionId: USER_ADMIN }],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "service-principal-in-privileged-role")[0].severity).toBe("high");
  });

  it("flags a consented tier-0 Graph app role as critical", () => {
    const result = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [
          servicePrincipal({
            appRoleAssignments: [
              {
                id: "ara-1",
                appRoleId: PERM.directoryReadWriteAll,
                principalId: "sp-1",
                resourceDisplayName: "Microsoft Graph",
              },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    const finding = withCheck(result, "service-principal-granted-tier0-permission");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("critical");
    expect(finding[0].evidence[0].detail).toContain("Directory.ReadWrite.All");
  });

  it("rates a broad but non-escalating grant below a tier-0 grant", () => {
    const result = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [
          servicePrincipal({
            appRoleAssignments: [{ id: "ara-1", appRoleId: PERM.mailRead, principalId: "sp-1" }],
          }),
        ],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "service-principal-granted-tier0-permission")[0].severity).toBe("high");
  });

  it("ignores a benign grant", () => {
    const result = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [
          servicePrincipal({
            appRoleAssignments: [{ id: "ara-1", appRoleId: PERM.directoryReadAll, principalId: "sp-1" }],
          }),
        ],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "service-principal-granted-tier0-permission")).toHaveLength(0);
  });

  it("flags a credential with no expiry and one with an absurd expiry", () => {
    const noExpiry = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [servicePrincipal({ passwordCredentials: [{ keyId: "k1", startDateTime: "2026-01-01T00:00:00Z" }] })],
      }),
      { now: NOW },
    );
    const absurdExpiry = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [
          servicePrincipal({
            passwordCredentials: [
              { keyId: "k1", startDateTime: "2026-01-01T00:00:00Z", endDateTime: "2099-12-31T00:00:00Z" },
            ],
          }),
        ],
      }),
      { now: NOW },
    );
    expect(withCheck(noExpiry, "service-principal-credential-never-expires")).toHaveLength(1);
    expect(withCheck(absurdExpiry, "service-principal-credential-never-expires")).toHaveLength(1);
  });

  it("escalates a never-expiring credential when the SP is also privileged", () => {
    const result = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [servicePrincipal({ passwordCredentials: [{ keyId: "k1" }] })],
        roleAssignments: [{ id: "ra-1", principalId: "sp-1", roleDefinitionId: GA }],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "service-principal-credential-never-expires")[0].severity).toBe("critical");
  });

  it("flags a privileged service principal that has been idle past the window", () => {
    const result = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [
          servicePrincipal({ signInActivity: { lastSignInDateTime: "2025-06-01T00:00:00Z" } }),
        ],
        roleAssignments: [{ id: "ra-1", principalId: "sp-1", roleDefinitionId: GA }],
      }),
      { now: NOW },
    );
    const finding = withCheck(result, "unused-privileged-service-principal");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("high");
  });

  it("leaves a recently active privileged service principal alone", () => {
    const result = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [
          servicePrincipal({ signInActivity: { lastSignInDateTime: "2026-02-20T00:00:00Z" } }),
        ],
        roleAssignments: [{ id: "ra-1", principalId: "sp-1", roleDefinitionId: GA }],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "unused-privileged-service-principal")).toHaveLength(0);
  });

  it("does not treat missing sign-in telemetry as evidence of disuse", () => {
    const result = analyzeServicePrincipals(
      snapshot({
        servicePrincipals: [servicePrincipal({ signInActivity: undefined })],
        roleAssignments: [{ id: "ra-1", principalId: "sp-1", roleDefinitionId: GA }],
      }),
      { now: NOW },
    );
    expect(withCheck(result, "unused-privileged-service-principal")).toHaveLength(0);
  });
});

// ── analyzeFederation ──

function federatedDomain(overrides: Partial<FederatedDomain> = {}): FederatedDomain {
  return {
    id: "contoso.com",
    authenticationType: "Federated",
    isVerified: true,
    isDefault: true,
    federationConfiguration: {
      issuerUri: "https://sts.contoso.com/adfs/services/trust",
      passiveSignInUri: "https://sts.contoso.com/adfs/ls/",
      metadataExchangeUri: "https://sts.contoso.com/adfs/services/trust/mex",
      signingCertificate: "MIIC-active",
      nextSigningCertificate: "MIIC-next",
      federatedIdpMfaBehavior: "enforceMfaByFederatedIdp",
      isSignedAuthenticationRequestRequired: true,
      signingCertificateUpdateStatus: { certificateUpdateResult: "success", lastRunDateTime: "2026-02-01T00:00:00Z" },
    },
    ...overrides,
  };
}

describe("analyzeFederation", () => {
  it("raises nothing for a hardened federated domain", () => {
    const result = analyzeFederation(snapshot({ federationConfig: { domains: [federatedDomain()] } }));
    expect(result).toEqual([]);
  });

  it("ignores managed (cloud-authenticated) domains entirely", () => {
    const result = analyzeFederation(
      snapshot({
        federationConfig: {
          domains: [{ id: "contoso.onmicrosoft.com", authenticationType: "Managed", isVerified: true }],
        },
      }),
    );
    expect(result).toEqual([]);
  });

  it("flags an IdP allowed to assert MFA on the tenant's behalf", () => {
    const base = federatedDomain();
    const result = analyzeFederation(
      snapshot({
        federationConfig: {
          domains: [
            {
              ...base,
              federationConfiguration: {
                ...base.federationConfiguration,
                federatedIdpMfaBehavior: "acceptIfMfaDoneByFederatedIdp",
              },
            },
          ],
        },
      }),
    );
    const finding = withCheck(result, "federated-idp-mfa-bypass");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("critical");
    expect(finding[0].evidence[0].detail).toBe("acceptIfMfaDoneByFederatedIdp");
  });

  it("still flags an unset MFA behaviour, one notch lower", () => {
    const base = federatedDomain();
    const result = analyzeFederation(
      snapshot({
        federationConfig: {
          domains: [
            {
              ...base,
              federationConfiguration: {
                ...base.federationConfiguration,
                federatedIdpMfaBehavior: undefined,
              },
            },
          ],
        },
      }),
    );
    expect(withCheck(result, "federated-idp-mfa-bypass")[0].severity).toBe("high");
  });

  it("flags an unverified federated domain", () => {
    const result = analyzeFederation(
      snapshot({ federationConfig: { domains: [federatedDomain({ isVerified: false })] } }),
    );
    expect(withCheck(result, "unverified-federated-domain")[0].severity).toBe("high");
  });

  it("flags a missing successor signing certificate and a failed certificate update", () => {
    const base = federatedDomain();
    const result = analyzeFederation(
      snapshot({
        federationConfig: {
          domains: [
            {
              ...base,
              federationConfiguration: {
                ...base.federationConfiguration,
                nextSigningCertificate: undefined,
                signingCertificateUpdateStatus: { certificateUpdateResult: "failed", lastRunDateTime: "2026-02-01T00:00:00Z" },
              },
            },
          ],
        },
      }),
    );
    expect(withCheck(result, "federation-no-signing-certificate-rollover")).toHaveLength(1);
    expect(withCheck(result, "federation-signing-certificate-update-failed")).toHaveLength(1);
  });

  it("flags unsigned authentication requests", () => {
    const base = federatedDomain();
    const result = analyzeFederation(
      snapshot({
        federationConfig: {
          domains: [
            {
              ...base,
              federationConfiguration: {
                ...base.federationConfiguration,
                isSignedAuthenticationRequestRequired: false,
              },
            },
          ],
        },
      }),
    );
    expect(withCheck(result, "federation-request-signing-not-required")[0].severity).toBe("medium");
  });

  it("flags cleartext federation endpoints and names each one", () => {
    const base = federatedDomain();
    const result = analyzeFederation(
      snapshot({
        federationConfig: {
          domains: [
            {
              ...base,
              federationConfiguration: {
                ...base.federationConfiguration,
                issuerUri: "http://sts.contoso.com/adfs/services/trust",
                metadataExchangeUri: "http://sts.contoso.com/adfs/services/trust/mex",
              },
            },
          ],
        },
      }),
    );
    const finding = withCheck(result, "federation-insecure-endpoint");
    expect(finding).toHaveLength(1);
    expect(finding[0].severity).toBe("high");
    expect(finding[0].evidence.map((e) => e.label).sort()).toEqual(["issuerUri", "metadataExchangeUri"]);
  });
});

// ── GraphClient ──

const TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.NEVER_LEAK_THIS";

describe("GraphClient — requests", () => {
  it("sends a bearer token and only ever issues GET", async () => {
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      seen.push({ url: String(url), init: init ?? {} });
      return jsonResponse({ value: [] });
    }) as typeof fetch;

    const client = new GraphClient({ accessToken: TOKEN, fetchImpl });
    await client.collect("/users", { $top: 999 });

    expect(seen).toHaveLength(1);
    expect(seen[0].init.method).toBe("GET");
    const headers = seen[0].init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(seen[0].url).toBe("https://graph.microsoft.com/v1.0/users?%24top=999");
  });

  it("maps 401 and 403 to typed errors", async () => {
    const unauthorized = new GraphClient({
      accessToken: TOKEN,
      fetchImpl: (async () => new Response("no", { status: 401 })) as typeof fetch,
    });
    const forbidden = new GraphClient({
      accessToken: TOKEN,
      fetchImpl: (async () => new Response("no", { status: 403 })) as typeof fetch,
    });
    await expect(unauthorized.get("/users")).rejects.toBeInstanceOf(GraphAuthError);
    await expect(forbidden.get("/users")).rejects.toBeInstanceOf(GraphForbiddenError);
  });

  it("scrubs the access token out of network-layer error messages", async () => {
    const client = new GraphClient({
      accessToken: TOKEN,
      fetchImpl: (async () => {
        throw new Error(`connect failed while sending Bearer ${TOKEN}`);
      }) as typeof fetch,
    });
    const err = await client.get("/users").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GraphNetworkError);
    expect((err as Error).message).not.toContain(TOKEN);
    expect((err as Error).message).toContain("[REDACTED]");
  });
});

describe("GraphClient — pagination", () => {
  it("follows @odata.nextLink until it is absent and concatenates every page", async () => {
    const requested: string[] = [];
    const fetchImpl = (async (url: string | URL | Request) => {
      const href = String(url);
      requested.push(href);
      if (href.includes("$skiptoken=page2")) {
        return jsonResponse({
          value: [{ id: "u3" }, { id: "u4" }],
          "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=page3",
        });
      }
      if (href.includes("$skiptoken=page3")) {
        return jsonResponse({ value: [{ id: "u5" }] });
      }
      return jsonResponse({
        value: [{ id: "u1" }, { id: "u2" }],
        "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=page2",
      });
    }) as typeof fetch;

    const client = new GraphClient({ accessToken: TOKEN, fetchImpl });
    const users = await client.collect<{ id: string }>("/users");

    expect(users.map((u) => u.id)).toEqual(["u1", "u2", "u3", "u4", "u5"]);
    expect(requested).toHaveLength(3);
    expect(requested[1]).toContain("$skiptoken=page2");
    expect(requested[2]).toContain("$skiptoken=page3");
  });

  it("stops after a single request when there is no nextLink", async () => {
    let calls = 0;
    const client = new GraphClient({
      accessToken: TOKEN,
      fetchImpl: (async () => {
        calls += 1;
        return jsonResponse({ value: [{ id: "u1" }] });
      }) as typeof fetch,
    });
    const users = await client.collect<{ id: string }>("/users");
    expect(users).toHaveLength(1);
    expect(calls).toBe(1);
  });

  it("refuses to follow a nextLink that points off the Graph origin", async () => {
    const requested: string[] = [];
    const client = new GraphClient({
      accessToken: TOKEN,
      fetchImpl: (async (url: string | URL | Request) => {
        requested.push(String(url));
        return jsonResponse({
          value: [{ id: "u1" }],
          "@odata.nextLink": "https://evil.example.com/v1.0/users?$skiptoken=page2",
        });
      }) as typeof fetch,
    });

    await expect(client.collect("/users")).rejects.toBeInstanceOf(GraphScopeError);
    // The off-origin URL must never reach fetch at all.
    expect(requested).toEqual(["https://graph.microsoft.com/v1.0/users"]);
  });

  it("stops runaway pagination at the configured page ceiling", async () => {
    const client = new GraphClient({
      accessToken: TOKEN,
      maxPages: 3,
      fetchImpl: (async () =>
        jsonResponse({
          value: [{ id: "u" }],
          "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=loop",
        })) as typeof fetch,
    });
    await expect(client.collect("/users")).rejects.toThrow(/exceeded 3 pages/);
  });
});

describe("GraphClient — 429 handling", () => {
  it("honours Retry-After and retries the same URL", async () => {
    const slept: number[] = [];
    let calls = 0;
    const client = new GraphClient({
      accessToken: TOKEN,
      sleep: async (ms) => {
        slept.push(ms);
      },
      fetchImpl: (async () => {
        calls += 1;
        if (calls === 1) return new Response("throttled", { status: 429, headers: { "Retry-After": "17" } });
        return jsonResponse({ value: [{ id: "u1" }] });
      }) as typeof fetch,
    });

    const users = await client.collect<{ id: string }>("/users");
    expect(users).toHaveLength(1);
    expect(calls).toBe(2);
    expect(slept).toEqual([17_000]);
  });

  it("caps an outrageous Retry-After at the configured ceiling", async () => {
    const slept: number[] = [];
    let calls = 0;
    const client = new GraphClient({
      accessToken: TOKEN,
      maxRetryDelayMs: 5_000,
      sleep: async (ms) => {
        slept.push(ms);
      },
      fetchImpl: (async () => {
        calls += 1;
        if (calls === 1) return new Response("throttled", { status: 429, headers: { "Retry-After": "3600" } });
        return jsonResponse({ value: [] });
      }) as typeof fetch,
    });

    await client.collect("/users");
    expect(slept).toEqual([5_000]);
  });

  it("falls back to exponential back-off when Retry-After is absent", async () => {
    const slept: number[] = [];
    let calls = 0;
    const client = new GraphClient({
      accessToken: TOKEN,
      maxRetries: 3,
      sleep: async (ms) => {
        slept.push(ms);
      },
      fetchImpl: (async () => {
        calls += 1;
        if (calls <= 3) return new Response("throttled", { status: 429 });
        return jsonResponse({ value: [] });
      }) as typeof fetch,
    });

    await client.collect("/users");
    expect(slept).toEqual([1_000, 2_000, 4_000]);
  });

  it("throws GraphRateLimitError once retries are exhausted", async () => {
    let calls = 0;
    const client = new GraphClient({
      accessToken: TOKEN,
      maxRetries: 2,
      sleep: async () => {},
      fetchImpl: (async () => {
        calls += 1;
        return new Response("throttled", { status: 429, headers: { "Retry-After": "1" } });
      }) as typeof fetch,
    });

    const err = await client.get("/users").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(GraphRateLimitError);
    expect((err as GraphRateLimitError).retryAfterSec).toBe(1);
    expect(calls).toBe(3); // initial attempt + 2 retries
  });

  it("retries a 503 but not a 400", async () => {
    let serviceUnavailableCalls = 0;
    const retried = new GraphClient({
      accessToken: TOKEN,
      sleep: async () => {},
      fetchImpl: (async () => {
        serviceUnavailableCalls += 1;
        if (serviceUnavailableCalls === 1) return new Response("later", { status: 503 });
        return jsonResponse({ value: [] });
      }) as typeof fetch,
    });
    await retried.collect("/users");
    expect(serviceUnavailableCalls).toBe(2);

    let badRequestCalls = 0;
    const notRetried = new GraphClient({
      accessToken: TOKEN,
      sleep: async () => {},
      fetchImpl: (async () => {
        badRequestCalls += 1;
        return new Response("bad", { status: 400 });
      }) as typeof fetch,
    });
    await expect(notRetried.get("/users")).rejects.toBeInstanceOf(GraphError);
    expect(badRequestCalls).toBe(1);
  });
});

describe("GraphClient — scope enforcement", () => {
  it("refuses every request when graph.microsoft.com is out of scope", async () => {
    let calls = 0;
    const client = new GraphClient({
      accessToken: TOKEN,
      scope: ScopePolicy.fromJson({ in_scope: ["app.contoso.com"] }),
      fetchImpl: (async () => {
        calls += 1;
        return jsonResponse({ value: [] });
      }) as typeof fetch,
    });

    await expect(client.get("/users")).rejects.toBeInstanceOf(GraphScopeError);
    expect(calls).toBe(0);
  });

  it("proceeds when the operator has authorized the Graph host", async () => {
    const client = new GraphClient({
      accessToken: TOKEN,
      scope: ScopePolicy.fromJson({ in_scope: ["graph.microsoft.com"] }),
      fetchImpl: (async () => jsonResponse({ value: [{ id: "u1" }] })) as typeof fetch,
    });
    await expect(client.collect("/users")).resolves.toHaveLength(1);
  });
});

// ── collectTenantSnapshot ──

/** Route a fixture body per Graph pathname; anything unrouted 404s. */
function routedFetch(routes: Record<string, unknown>, failures: Record<string, number> = {}): typeof fetch {
  return (async (url: string | URL | Request) => {
    const path = new URL(String(url)).pathname.replace("/v1.0", "").replace("/beta", "");
    if (failures[path]) return new Response("denied", { status: failures[path] });
    if (path in routes) return jsonResponse(routes[path]);
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
}

describe("collectTenantSnapshot", () => {
  const routes: Record<string, unknown> = {
    "/organization": { value: [{ id: "tenant-1", displayName: "Contoso", onPremisesSyncEnabled: true }] },
    "/users": { value: [{ id: "u1", userPrincipalName: "u1@contoso.com" }, { id: "u2" }] },
    "/reports/authenticationMethods/userRegistrationDetails": {
      value: [{ id: "u1", isMfaRegistered: false, isMfaCapable: false }],
    },
    "/groups": { value: [{ id: "g1", displayName: "Admins" }] },
    "/servicePrincipals": {
      value: [
        { id: "sp-graph", appId: MICROSOFT_GRAPH_APP_ID, displayName: "Microsoft Graph" },
        { id: "sp-1", appId: "app-1", displayName: "Reporting Job" },
      ],
    },
    "/servicePrincipals/sp-graph": {
      appRoles: [{ id: PERM.directoryReadWriteAll, value: "Directory.ReadWrite.All" }],
      oauth2PermissionScopes: [],
    },
    "/servicePrincipals/sp-graph/appRoleAssignments": { value: [] },
    "/servicePrincipals/sp-1/appRoleAssignments": {
      value: [{ id: "ara-1", appRoleId: PERM.directoryReadWriteAll, principalId: "sp-1" }],
    },
    "/applications": {
      value: [
        {
          id: "app-obj-1",
          appId: "app-1",
          requiredResourceAccess: [
            {
              resourceAppId: MICROSOFT_GRAPH_APP_ID,
              resourceAccess: [{ id: PERM.directoryReadWriteAll, type: "Role" }],
            },
          ],
        },
      ],
    },
    "/roleManagement/directory/roleDefinitions": {
      value: [{ id: GA, templateId: GA, displayName: "Global Administrator" }],
    },
    "/roleManagement/directory/roleAssignments": {
      value: [{ id: "ra-1", principalId: "u1", roleDefinitionId: GA }],
    },
    "/roleManagement/directory/roleEligibilitySchedules": { value: [] },
    "/identity/conditionalAccess/policies": { value: [] },
    "/domains": { value: [{ id: "contoso.com", authenticationType: "Federated", isVerified: true }] },
    "/domains/contoso.com/federationConfiguration": {
      value: [{ issuerUri: "https://sts.contoso.com", federatedIdpMfaBehavior: "acceptIfMfaDoneByFederatedIdp" }],
    },
  };

  it("assembles a complete snapshot and joins the MFA registration report onto users", async () => {
    const client = new GraphClient({ accessToken: TOKEN, fetchImpl: routedFetch(routes) });
    const result = await collectTenantSnapshot(client, { now: () => NOW });

    expect(result.warnings).toEqual([]);
    expect(result.tenantId).toBe("tenant-1");
    expect(result.users.find((u) => u.id === "u1")?.isMfaRegistered).toBe(false);
    // u2 has no registration row; it must stay unknown rather than default to false.
    expect(result.users.find((u) => u.id === "u2")?.isMfaRegistered).toBeUndefined();
    expect(result.federationConfig.directorySyncEnabled).toBe(true);
    expect(result.federationConfig.domains[0].federationConfiguration?.federatedIdpMfaBehavior)
      .toBe("acceptIfMfaDoneByFederatedIdp");
  });

  it("resolves permission GUIDs to names off the tenant's Microsoft Graph service principal", async () => {
    const client = new GraphClient({ accessToken: TOKEN, fetchImpl: routedFetch(routes) });
    const result = await collectTenantSnapshot(client, { now: () => NOW });

    expect(result.appRegistrations[0].requiredResourceAccess?.[0].resourceAccess[0].value)
      .toBe("Directory.ReadWrite.All");
    expect(result.servicePrincipals.find((sp) => sp.id === "sp-1")?.appRoleAssignments?.[0].value)
      .toBe("Directory.ReadWrite.All");
  });

  it("degrades to a partial snapshot with a warning when one collection is forbidden", async () => {
    const client = new GraphClient({
      accessToken: TOKEN,
      fetchImpl: routedFetch(routes, { "/identity/conditionalAccess/policies": 403 }),
    });
    const result = await collectTenantSnapshot(client, { now: () => NOW });

    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toContain("identity/conditionalAccess/policies");
    // Everything else still collected.
    expect(result.users).toHaveLength(2);
    expect(result.roleAssignments).toHaveLength(1);
  });

  it("records truncation when the service-principal fan-out is capped", async () => {
    const client = new GraphClient({ accessToken: TOKEN, fetchImpl: routedFetch(routes) });
    const result = await collectTenantSnapshot(client, { now: () => NOW, appRoleAssignmentLimit: 1 });

    expect(result.warnings.some((w) => w.includes("appRoleAssignments truncated"))).toBe(true);
    expect(result.servicePrincipals.find((sp) => sp.id === "sp-1")?.appRoleAssignments).toBeUndefined();
  });
});

// ── runIdentityAssessment ──

describe("runIdentityAssessment", () => {
  it("analyzes a supplied snapshot and returns findings sorted by severity", async () => {
    const result = await runIdentityAssessment({
      snapshot: snapshot({
        users: [user("u1", { isMfaRegistered: false }), user("u2")],
        roleAssignments: [
          { id: "ra-1", principalId: "u1", roleDefinitionId: GA },
          { id: "ra-2", principalId: "u2", roleDefinitionId: GA },
        ],
        federationConfig: { domains: [federatedDomain({ isVerified: false })] },
      }),
      now: () => NOW,
      analyzers: { now: NOW },
    });

    expect(result.tenantId).toBe("11111111-2222-3333-4444-555555555555");
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].severity).toBe("critical");
    expect(result.summary.total).toBe(result.findings.length);
    expect(result.summary.bySeverity.critical).toBeGreaterThan(0);
    expect(checks(result.findings)).toContain("privileged-account-without-mfa");
    expect(checks(result.findings)).toContain("unverified-federated-domain");

    const severities = result.findings.map((f) => f.severity);
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
    for (let i = 1; i < severities.length; i += 1) {
      expect(rank[severities[i]]).toBeGreaterThanOrEqual(rank[severities[i - 1]]);
    }
  });

  it("marks a snapshot with collection warnings as partial", async () => {
    const clean = await runIdentityAssessment({ snapshot: snapshot(), now: () => NOW });
    const partial = await runIdentityAssessment({
      snapshot: snapshot({ warnings: ["users: HTTP 403"] }),
      now: () => NOW,
    });
    expect(clean.snapshot.partial).toBe(false);
    expect(partial.snapshot.partial).toBe(true);
    expect(partial.snapshot.warnings).toEqual(["users: HTTP 403"]);
  });

  it("collects through an injected client when no snapshot is supplied", async () => {
    const client = new GraphClient({
      accessToken: TOKEN,
      fetchImpl: routedFetch({
        "/organization": { value: [{ id: "tenant-9", displayName: "Fabrikam" }] },
        "/users": { value: [{ id: "u1" }] },
        "/reports/authenticationMethods/userRegistrationDetails": { value: [] },
        "/groups": { value: [] },
        "/servicePrincipals": { value: [] },
        "/applications": { value: [] },
        "/roleManagement/directory/roleDefinitions": { value: [] },
        "/roleManagement/directory/roleAssignments": { value: [] },
        "/roleManagement/directory/roleEligibilitySchedules": { value: [] },
        "/identity/conditionalAccess/policies": { value: [] },
        "/domains": { value: [] },
      }),
    });

    const result = await runIdentityAssessment({ client, now: () => NOW, analyzers: { now: NOW } });
    expect(result.tenantId).toBe("tenant-9");
    expect(result.snapshot.counts.users).toBe(1);
    // No conditional-access policies and no warning for them: a real gap.
    expect(checks(result.findings)).toContain("no-enabled-conditional-access-policies");
  });

  it("refuses to run without a snapshot, client, or access token", async () => {
    await expect(runIdentityAssessment({})).rejects.toThrow(/snapshot.*client.*accessToken/s);
  });
});
