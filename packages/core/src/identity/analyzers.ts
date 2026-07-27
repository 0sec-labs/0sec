// Pure analysis over a `TenantSnapshot`.
//
// Every exported analyzer is `(snapshot, options?) => IdentityFinding[]` with
// no I/O and no ambient clock — the only time source is `options.now`, which
// defaults to the real clock but is always overridable. That is deliberate:
// a check that cannot be run against a fixture cannot be regression-tested,
// and an identity finding that a customer disputes has to be reproducible from
// the captured snapshot alone.
//
// Two invariants every check obeys:
//
//   1. ABSENT IS NOT SAFE. `undefined` means "the collector could not read
//      this", which is never grounds for a finding *or* for a clean bill of
//      health. Checks skip unknowns; the caller sees `snapshot.warnings`.
//   2. EVIDENCE IS GROUNDED. Every finding cites the concrete object ids and
//      values it was derived from, with the Graph path they came from, so a
//      reviewer can re-run the same GET and see the same thing.

import type {
  AffectedPrincipal,
  AppRegistration,
  ConditionalAccessPolicy,
  GraphAppRoleAssignment,
  GraphKeyCredential,
  GraphPasswordCredential,
  IdentityCheck,
  IdentityEvidence,
  IdentityFinding,
  IdentityFindingCategory,
  IdentitySeverity,
  ServicePrincipalRecord,
  TenantSnapshot,
} from "./types.js";

// ── catalogs ──
//
// Role template ids are stable across every Entra tenant on the planet, which
// is exactly why conditional-access `includeRoles` refers to them rather than
// to per-tenant role definition ids.

export const ROLE_TEMPLATE_IDS = {
  globalAdministrator: "62e90394-69f5-4237-9190-012177145e10",
  privilegedRoleAdministrator: "e8611ab8-c189-46e8-94e1-60213ab1f814",
  privilegedAuthenticationAdministrator: "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
  applicationAdministrator: "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
  cloudApplicationAdministrator: "158c047a-c907-4556-b7ef-446551a6b5f7",
  hybridIdentityAdministrator: "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",
  directorySynchronizationAccounts: "d29b2b05-8046-44ba-8758-1e26182fcf32",
  userAdministrator: "fe930be7-5e62-47db-91af-98c3a49a38b1",
  authenticationAdministrator: "c4e39bd9-1100-46d3-8c65-fb160da0071f",
  conditionalAccessAdministrator: "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
  securityAdministrator: "194ae4cb-b126-40b2-bd5b-6091b380977d",
  exchangeAdministrator: "29232cdf-9323-42fd-ade2-1d097af3e4de",
  sharePointAdministrator: "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
  intuneAdministrator: "3a2c62db-5318-420d-8d74-23affee5d9d5",
  helpdeskAdministrator: "729827e3-9c14-49f7-bb1b-9608f156bbb8",
  globalReader: "f2ef992c-3afb-46b9-b7cf-a126ee74c451",
} as const;

/**
 * Roles whose holder can reach full tenant control, directly or in one hop —
 * by minting app credentials, resetting another admin's authentication, or
 * granting themselves a directory role.
 */
export const TIER0_ROLE_TEMPLATE_IDS: ReadonlySet<string> = new Set([
  ROLE_TEMPLATE_IDS.globalAdministrator,
  ROLE_TEMPLATE_IDS.privilegedRoleAdministrator,
  ROLE_TEMPLATE_IDS.privilegedAuthenticationAdministrator,
  ROLE_TEMPLATE_IDS.applicationAdministrator,
  ROLE_TEMPLATE_IDS.cloudApplicationAdministrator,
  ROLE_TEMPLATE_IDS.hybridIdentityAdministrator,
  ROLE_TEMPLATE_IDS.directorySynchronizationAccounts,
]);

/** Every role we treat as privileged for MFA / PIM / exclusion purposes. */
export const PRIVILEGED_ROLE_TEMPLATE_IDS: ReadonlySet<string> = new Set([
  ...TIER0_ROLE_TEMPLATE_IDS,
  ROLE_TEMPLATE_IDS.userAdministrator,
  ROLE_TEMPLATE_IDS.authenticationAdministrator,
  ROLE_TEMPLATE_IDS.conditionalAccessAdministrator,
  ROLE_TEMPLATE_IDS.securityAdministrator,
  ROLE_TEMPLATE_IDS.exchangeAdministrator,
  ROLE_TEMPLATE_IDS.sharePointAdministrator,
  ROLE_TEMPLATE_IDS.intuneAdministrator,
  ROLE_TEMPLATE_IDS.helpdeskAdministrator,
  ROLE_TEMPLATE_IDS.globalReader,
]);

/**
 * Fallback GUID → permission-name map for Microsoft Graph app roles. The
 * collector prefers the tenant's own copy of the Graph service principal; this
 * table only kicks in when that lookup was unavailable (offline fixture, token
 * without `Application.Read.All`).
 */
export const GRAPH_APP_ROLE_CATALOG: Readonly<Record<string, string>> = {
  "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
  "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
  "19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
  "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
  "7ab1d382-f21e-4acd-a863-ba3e13f7da61": "Directory.Read.All",
  "741f803b-c850-494e-b5df-cde7c675a1ca": "User.ReadWrite.All",
  "df021288-bdef-4463-88db-98f22de89214": "User.Read.All",
  "62a82d76-70ea-41e2-9197-370581804d09": "Group.ReadWrite.All",
  "dbaae8cf-10b5-4b86-a4a1-f871c94c6695": "GroupMember.ReadWrite.All",
  "e2a3a72e-5f79-4c64-b1b1-878b674786c9": "Mail.ReadWrite",
  "810c84a8-4a9e-49e6-bf7d-12d183f40d01": "Mail.Read",
  "b633e1c5-b582-4048-a93e-9f11b44c7e96": "Mail.Send",
  "75359482-378d-4052-8f01-80520e7db3cd": "Files.ReadWrite.All",
  "a82116e5-55eb-4c41-a434-62fe8a61c773": "Sites.FullControl.All",
};

/**
 * Permissions that are equivalent to tenant compromise. Holding any of these
 * as an *application* permission lets the app grant itself everything else:
 * `RoleManagement.ReadWrite.Directory` assigns Global Administrator,
 * `Application.ReadWrite.All` adds credentials to any other app (including
 * one that is already Global Administrator), and `Directory.ReadWrite.All`
 * plus `AppRoleAssignment.ReadWrite.All` get there in two steps.
 */
export const TIER0_GRAPH_PERMISSIONS: ReadonlySet<string> = new Set([
  "RoleManagement.ReadWrite.Directory",
  "Application.ReadWrite.All",
  "Directory.ReadWrite.All",
  "AppRoleAssignment.ReadWrite.All",
  "PrivilegedAccess.ReadWrite.AzureAD",
  "PrivilegedAccess.ReadWrite.AzureADGroup",
]);

/** Broad data access or policy control. Serious, but not a one-hop takeover. */
export const HIGH_IMPACT_GRAPH_PERMISSIONS: ReadonlySet<string> = new Set([
  "Application.ReadWrite.OwnedBy",
  "User.ReadWrite.All",
  "Group.ReadWrite.All",
  "GroupMember.ReadWrite.All",
  "Mail.Read",
  "Mail.ReadWrite",
  "Mail.Send",
  "Files.ReadWrite.All",
  "Sites.FullControl.All",
  "Policy.ReadWrite.ConditionalAccess",
  "Policy.ReadWrite.AuthenticationMethod",
  "Domain.ReadWrite.All",
  "DeviceManagementConfiguration.ReadWrite.All",
]);

const MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";
const DAY_MS = 86_400_000;

// ── option shapes ──

export interface PrivilegedRoleOptions {
  /** Standing Global Administrators above this count is a finding. Default 4. */
  maxStandingGlobalAdmins?: number;
  /** Fewer Global Administrators than this is a lockout risk. Default 2. */
  minGlobalAdmins?: number;
}

export interface ConditionalAccessOptions {
  /**
   * Object ids of sanctioned break-glass accounts. Excluding these from a
   * critical policy is correct practice, so they never raise an exclusion
   * finding; anything else excluded does.
   */
  breakGlassPrincipalIds?: string[];
  /** Report-only policies older than this are treated as stalled. Default 30. */
  reportOnlyMaxAgeDays?: number;
  now?: Date;
}

export interface AppRegistrationOptions {
  /** Credential lifetimes above this are flagged. Default 365 days. */
  maxCredentialLifetimeDays?: number;
  now?: Date;
}

export interface ServicePrincipalOptions {
  /** A privileged SP idle this long is flagged. Default 90 days. */
  unusedAfterDays?: number;
  /**
   * A credential valid for longer than this counts as "never expires".
   * Default 3650 days (10 years).
   */
  neverExpiresAfterDays?: number;
  now?: Date;
}

export interface IdentityAnalyzerOptions
  extends PrivilegedRoleOptions,
    ConditionalAccessOptions,
    AppRegistrationOptions,
    ServicePrincipalOptions {}

// ── privileged roles ──

/**
 * Standing Global Administrators, privileged roles held permanently instead of
 * through PIM, and privileged principals whose account posture (no MFA, guest,
 * disabled, on-prem synced) undermines the role.
 */
export function analyzePrivilegedRoles(
  snapshot: TenantSnapshot,
  options: PrivilegedRoleOptions = {},
): IdentityFinding[] {
  const findings: IdentityFinding[] = [];
  const maxStandingGa = options.maxStandingGlobalAdmins ?? 4;
  const minGa = options.minGlobalAdmins ?? 2;

  // A missing collection is not a clean tenant. Bail rather than assert
  // "0 admins" on a token that could not read role management.
  if (snapshot.roleAssignments.length === 0) return findings;

  const privileged = snapshot.roleAssignments.filter((a) =>
    PRIVILEGED_ROLE_TEMPLATE_IDS.has(templateIdFor(snapshot, a.roleDefinitionId)),
  );

  const globalAdmins = snapshot.roleAssignments.filter(
    (a) => templateIdFor(snapshot, a.roleDefinitionId) === ROLE_TEMPLATE_IDS.globalAdministrator,
  );
  const standingGlobalAdmins = globalAdmins.filter((a) => !hasEligibility(snapshot, a.principalId, a.roleDefinitionId));
  const eligibleGlobalAdmins = snapshot.roleEligibilitySchedules.filter(
    (s) =>
      templateIdFor(snapshot, s.roleDefinitionId) === ROLE_TEMPLATE_IDS.globalAdministrator &&
      isLiveEligibility(s.status),
  );

  if (standingGlobalAdmins.length > maxStandingGa) {
    findings.push({
      id: "excessive-standing-global-admins",
      check: "excessive-standing-global-admins",
      title: `${standingGlobalAdmins.length} accounts hold standing Global Administrator`,
      severity: "high",
      category: "privileged-roles",
      description:
        `The tenant has ${standingGlobalAdmins.length} permanent Global Administrator assignments, above the ` +
        `configured ceiling of ${maxStandingGa}. Every standing Global Administrator is a full-tenant-takeover ` +
        `target that is exploitable at any moment, not only during an approved activation window.`,
      evidence: [
        {
          label: "Standing Global Administrators",
          detail: String(standingGlobalAdmins.length),
          graphPath: "/roleManagement/directory/roleAssignments",
        },
        {
          label: "PIM-eligible Global Administrators",
          detail: String(eligibleGlobalAdmins.length),
          graphPath: "/roleManagement/directory/roleEligibilitySchedules",
        },
        {
          label: "Assigned principals",
          detail: standingGlobalAdmins.map((a) => principalLabel(snapshot, a.principalId)).join(", "),
        },
      ],
      affectedPrincipals: standingGlobalAdmins.map((a) => resolvePrincipal(snapshot, a.principalId)),
      remediation:
        `Reduce permanent Global Administrator assignments to ${maxStandingGa} or fewer (Microsoft's guidance is ` +
        "two to four emergency-access accounts) and move day-to-day administration to PIM-eligible, " +
        "time-bound, approval-gated activation.",
      references: [
        "https://learn.microsoft.com/entra/identity/role-based-access-control/best-practices",
      ],
    });
  }

  const distinctGlobalAdmins = new Set([
    ...globalAdmins.map((a) => a.principalId),
    ...eligibleGlobalAdmins.map((s) => s.principalId),
  ]);
  if (distinctGlobalAdmins.size < minGa) {
    findings.push({
      id: "insufficient-global-admins",
      check: "insufficient-global-admins",
      title: `Only ${distinctGlobalAdmins.size} principal(s) can hold Global Administrator`,
      severity: "low",
      category: "privileged-roles",
      description:
        "Fewer than the recommended number of Global Administrators exist. If the sole administrator loses " +
        "access, or their authentication method is compromised and revoked, the tenant cannot be recovered " +
        "without Microsoft support intervention.",
      evidence: [
        {
          label: "Distinct Global Administrators (standing + eligible)",
          detail: String(distinctGlobalAdmins.size),
          graphPath: "/roleManagement/directory/roleAssignments",
        },
      ],
      affectedPrincipals: [...distinctGlobalAdmins].map((id) => resolvePrincipal(snapshot, id)),
      remediation:
        "Provision at least two cloud-only emergency-access accounts with Global Administrator, excluded from " +
        "conditional-access policies that could lock them out, with credentials stored offline.",
    });
  }

  // Standing (non-PIM) privileged access, grouped per principal so a tenant
  // with no PIM at all produces one finding per admin rather than per role.
  const standingByPrincipal = new Map<string, string[]>();
  for (const assignment of privileged) {
    if (hasEligibility(snapshot, assignment.principalId, assignment.roleDefinitionId)) continue;
    const roles = standingByPrincipal.get(assignment.principalId) ?? [];
    roles.push(assignment.roleDefinitionId);
    standingByPrincipal.set(assignment.principalId, roles);
  }
  for (const [principalId, roleDefinitionIds] of standingByPrincipal) {
    const tier0 = roleDefinitionIds.some((id) => TIER0_ROLE_TEMPLATE_IDS.has(templateIdFor(snapshot, id)));
    findings.push({
      id: `standing-privileged-access:${principalId}`,
      check: "standing-privileged-access",
      title: `${principalLabel(snapshot, principalId)} holds privileged roles permanently (no PIM)`,
      severity: tier0 ? "high" : "medium",
      category: "privileged-roles",
      description:
        "The principal holds one or more privileged directory roles as a permanent assignment with no matching " +
        "PIM eligibility schedule. Standing privilege removes the activation gate, the approval trail, and the " +
        "time bound that make privileged access auditable.",
      evidence: [
        {
          label: "Permanently assigned roles",
          detail: roleDefinitionIds.map((id) => roleDisplayName(snapshot, id)).join(", "),
          graphPath: "/roleManagement/directory/roleAssignments",
        },
        {
          label: "Matching PIM eligibility",
          detail: "none",
          graphPath: "/roleManagement/directory/roleEligibilitySchedules",
        },
      ],
      affectedPrincipals: [resolvePrincipal(snapshot, principalId)],
      remediation:
        "Convert the permanent assignment to a PIM-eligible assignment with a maximum activation duration, " +
        "justification, and approval where the role warrants it.",
    });
  }

  // Per-principal posture checks. A principal counts as privileged whether the
  // role is standing or merely eligible — eligibility is still a path in.
  const privilegedPrincipals = new Map<string, Set<string>>();
  for (const assignment of privileged) {
    addTo(privilegedPrincipals, assignment.principalId, assignment.roleDefinitionId);
  }
  for (const schedule of snapshot.roleEligibilitySchedules) {
    if (!isLiveEligibility(schedule.status)) continue;
    if (!PRIVILEGED_ROLE_TEMPLATE_IDS.has(templateIdFor(snapshot, schedule.roleDefinitionId))) continue;
    addTo(privilegedPrincipals, schedule.principalId, schedule.roleDefinitionId);
  }

  const usersById = new Map(snapshot.users.map((u) => [u.id, u]));
  for (const [principalId, roleDefinitionIds] of privilegedPrincipals) {
    const user = usersById.get(principalId);
    if (!user) continue;
    const roleNames = [...roleDefinitionIds].map((id) => roleDisplayName(snapshot, id)).join(", ");
    const tier0 = [...roleDefinitionIds].some((id) => TIER0_ROLE_TEMPLATE_IDS.has(templateIdFor(snapshot, id)));
    const roleEvidence: IdentityEvidence = {
      label: "Privileged roles",
      detail: roleNames,
      graphPath: "/roleManagement/directory/roleAssignments",
    };

    // `isMfaRegistered === undefined` means the registration report was not
    // readable — not that the admin lacks MFA.
    if (user.isMfaRegistered === false) {
      findings.push({
        id: `privileged-account-without-mfa:${principalId}`,
        check: "privileged-account-without-mfa",
        title: `Privileged account ${principalLabel(snapshot, principalId)} has no MFA registered`,
        severity: "critical",
        category: "privileged-roles",
        description:
          "A principal holding privileged directory roles has no multi-factor authentication method registered. " +
          "A single stolen or sprayed password yields the role immediately, with no second factor in the way.",
        evidence: [
          roleEvidence,
          {
            label: "isMfaRegistered",
            detail: "false",
            graphPath: "/reports/authenticationMethods/userRegistrationDetails",
          },
        ],
        affectedPrincipals: [resolvePrincipal(snapshot, principalId)],
        remediation:
          "Register a phishing-resistant authentication method (FIDO2 or certificate-based) for the account and " +
          "enforce it with a conditional-access authentication strength targeting privileged roles.",
      });
    }

    if ((user.userType ?? "").toLowerCase() === "guest") {
      findings.push({
        id: `guest-in-privileged-role:${principalId}`,
        check: "guest-in-privileged-role",
        title: `Guest account ${principalLabel(snapshot, principalId)} holds privileged roles`,
        severity: tier0 ? "critical" : "high",
        category: "privileged-roles",
        description:
          "An external guest identity holds privileged directory roles. The credential, its MFA methods, and its " +
          "lifecycle are all governed by a directory you do not control, so a compromise in the home tenant " +
          "becomes a compromise here.",
        evidence: [
          roleEvidence,
          { label: "userType", detail: "Guest", graphPath: "/users" },
        ],
        affectedPrincipals: [resolvePrincipal(snapshot, principalId)],
        remediation:
          "Replace the guest assignment with a member account in this tenant, or remove the role and grant scoped, " +
          "time-bound access through PIM with approval.",
      });
    }

    if (user.accountEnabled === false) {
      findings.push({
        id: `disabled-account-in-privileged-role:${principalId}`,
        check: "disabled-account-in-privileged-role",
        title: `Disabled account ${principalLabel(snapshot, principalId)} still holds privileged roles`,
        severity: "medium",
        category: "privileged-roles",
        description:
          "A disabled account retains privileged role assignments. Re-enabling the account — which is a far " +
          "lower bar than a fresh role grant, and is often done by a helpdesk role — instantly restores full " +
          "privilege with no additional approval.",
        evidence: [
          roleEvidence,
          { label: "accountEnabled", detail: "false", graphPath: "/users" },
        ],
        affectedPrincipals: [resolvePrincipal(snapshot, principalId)],
        remediation: "Remove the role assignments as part of the account-disable workflow, then delete the account.",
      });
    }

    const syncOnly = [...roleDefinitionIds].every(
      (id) => templateIdFor(snapshot, id) === ROLE_TEMPLATE_IDS.directorySynchronizationAccounts,
    );
    if (user.onPremisesSyncEnabled === true && !syncOnly) {
      findings.push({
        id: `synced-account-in-privileged-role:${principalId}`,
        check: "synced-account-in-privileged-role",
        title: `On-premises synced account ${principalLabel(snapshot, principalId)} holds privileged roles`,
        severity: tier0 ? "high" : "medium",
        category: "privileged-roles",
        description:
          "A privileged principal is mastered on-premises and synchronised into the tenant. This collapses the " +
          "tier boundary: anyone who compromises Active Directory (or the sync account) inherits the cloud role " +
          "without ever touching the cloud control plane.",
        evidence: [
          roleEvidence,
          { label: "onPremisesSyncEnabled", detail: "true", graphPath: "/users" },
        ],
        affectedPrincipals: [resolvePrincipal(snapshot, principalId)],
        remediation:
          "Move privileged roles onto cloud-only accounts that have no on-premises counterpart, and exclude " +
          "privileged cloud accounts from directory synchronisation.",
      });
    }
  }

  return findings;
}

// ── conditional access ──

/**
 * Gaps in the conditional-access ruleset: no enforced policies at all, admins
 * not covered by an MFA requirement, legacy authentication left reachable,
 * policies parked in report-only, and carve-outs on the policies that matter.
 */
export function analyzeConditionalAccess(
  snapshot: TenantSnapshot,
  options: ConditionalAccessOptions = {},
): IdentityFinding[] {
  const findings: IdentityFinding[] = [];
  const now = options.now ?? new Date();
  const maxReportOnlyAgeDays = options.reportOnlyMaxAgeDays ?? 30;
  const breakGlass = new Set(options.breakGlassPrincipalIds ?? []);
  const policies = snapshot.conditionalAccessPolicies;

  // Zero policies plus a collection warning means "could not read", not
  // "none configured". Only the former is silent here.
  if (policies.length === 0 && collectionFailed(snapshot, "conditionalAccess")) return findings;

  const enabled = policies.filter((p) => p.state === "enabled");

  if (enabled.length === 0) {
    findings.push({
      id: "no-enabled-conditional-access-policies",
      check: "no-enabled-conditional-access-policies",
      title: "No conditional-access policy is enforced",
      severity: "critical",
      category: "conditional-access",
      description:
        "The tenant has no conditional-access policy in the `enabled` state. Every sign-in — any user, any " +
        "application, any location, any client — is permitted on a password alone.",
      evidence: [
        {
          label: "Policies by state",
          detail: summarizeStates(policies),
          graphPath: "/identity/conditionalAccess/policies",
        },
      ],
      affectedPrincipals: [{ id: snapshot.tenantId, type: "policy", displayName: snapshot.tenantDisplayName }],
      remediation:
        "Deploy a baseline set of enforced policies: MFA for administrators, MFA for all users, block legacy " +
        "authentication, and require compliant or hybrid-joined devices for privileged operations.",
    });
  }

  const adminMfaPolicies = enabled.filter((p) => requiresStrongAuth(p) && targetsAdmins(p));
  if (adminMfaPolicies.length === 0) {
    findings.push({
      id: "no-mfa-policy-for-admins",
      check: "no-mfa-policy-for-admins",
      title: "No enforced policy requires MFA for administrators",
      severity: "critical",
      category: "conditional-access",
      description:
        "No conditional-access policy in the `enabled` state both targets privileged directory roles (or all " +
        "users) and requires multi-factor authentication or an authentication strength. Administrative sign-in " +
        "is therefore reachable with a password alone.",
      evidence: [
        {
          label: "Enabled policies requiring MFA",
          detail: String(enabled.filter(requiresStrongAuth).length),
          graphPath: "/identity/conditionalAccess/policies",
        },
        {
          label: "Enabled policies targeting admin roles",
          detail: String(enabled.filter(targetsAdmins).length),
        },
      ],
      affectedPrincipals: [{ id: snapshot.tenantId, type: "policy", displayName: snapshot.tenantDisplayName }],
      remediation:
        "Create an enabled policy targeting the privileged role templates with a phishing-resistant " +
        "authentication strength as the grant control, excluding only documented break-glass accounts.",
    });
  }

  const legacyBlocks = enabled.filter(blocksLegacyAuth);
  if (legacyBlocks.length === 0) {
    findings.push({
      id: "legacy-authentication-not-blocked",
      check: "legacy-authentication-not-blocked",
      title: "Legacy authentication is not blocked",
      severity: "high",
      category: "conditional-access",
      description:
        "No enforced policy blocks the `exchangeActiveSync` and `other` client-app types. Legacy authentication " +
        "protocols cannot present an MFA challenge, so any password-spray against them bypasses every MFA " +
        "requirement the tenant has configured.",
      evidence: [
        {
          label: "Enabled policies blocking legacy client apps",
          detail: "0",
          graphPath: "/identity/conditionalAccess/policies",
        },
      ],
      affectedPrincipals: [{ id: snapshot.tenantId, type: "policy", displayName: snapshot.tenantDisplayName }],
      remediation:
        "Add an enabled policy scoped to `clientAppTypes: [exchangeActiveSync, other]` for all users with the " +
        "`block` grant control.",
    });
  }

  // Report-only policies that have sat unenforced past the evaluation window.
  for (const policy of policies) {
    if (policy.state !== "enabledForReportingButNotEnforced") continue;
    const changedAt = policy.modifiedDateTime ?? policy.createdDateTime;
    const ageDays = changedAt ? daysBetween(changedAt, now) : undefined;
    if (ageDays === undefined || ageDays < maxReportOnlyAgeDays) continue;

    // A stalled report-only policy that would have closed one of the gaps
    // above is worse than one that duplicates an already-enforced control.
    const closesGap =
      (requiresStrongAuth(policy) && targetsAdmins(policy) && adminMfaPolicies.length === 0) ||
      (blocksLegacyAuth(policy) && legacyBlocks.length === 0);

    findings.push({
      id: `policy-stuck-in-report-only:${policy.id}`,
      check: "policy-stuck-in-report-only",
      title: `Policy "${policy.displayName ?? policy.id}" has been report-only for ${Math.floor(ageDays)} days`,
      severity: closesGap ? "high" : "medium",
      category: "conditional-access",
      description:
        "The policy is in `enabledForReportingButNotEnforced`. It writes sign-in log entries but blocks nothing. " +
        (closesGap
          ? "It is also the only policy that would close an otherwise-open control gap, so the tenant is " +
            "operating as if the control exists when it does not."
          : "Report-only is an evaluation state, not a steady state."),
      evidence: [
        { label: "state", detail: policy.state, graphPath: "/identity/conditionalAccess/policies" },
        { label: "Last modified", detail: changedAt ?? "unknown" },
        { label: "Grant controls", detail: describeGrantControls(policy) },
      ],
      affectedPrincipals: [{ id: policy.id, type: "policy", displayName: policy.displayName }],
      remediation:
        "Review the report-only impact data and either move the policy to `enabled` or delete it. Leaving it in " +
        "report-only indefinitely creates a false sense of coverage.",
    });
  }

  // Exclusions on the policies that actually enforce something.
  for (const policy of enabled) {
    if (!requiresStrongAuth(policy) && !blocksAccess(policy)) continue;
    const users = policy.conditions?.users;
    const excludedUsers = (users?.excludeUsers ?? []).filter((id) => !breakGlass.has(id));
    const excludedGroups = users?.excludeGroups ?? [];
    const excludedRoles = users?.excludeRoles ?? [];
    if (excludedUsers.length === 0 && excludedGroups.length === 0 && excludedRoles.length === 0) continue;

    const excludesPrivilegedRole = excludedRoles.some((id) => PRIVILEGED_ROLE_TEMPLATE_IDS.has(id));
    const evidence: IdentityEvidence[] = [
      { label: "Grant controls", detail: describeGrantControls(policy), graphPath: "/identity/conditionalAccess/policies" },
    ];
    if (excludedUsers.length > 0) {
      evidence.push({
        label: "Excluded users (excluding declared break-glass)",
        detail: excludedUsers.map((id) => principalLabel(snapshot, id)).join(", "),
      });
    }
    if (excludedGroups.length > 0) {
      evidence.push({
        label: "Excluded groups",
        detail: excludedGroups.map((id) => principalLabel(snapshot, id)).join(", "),
      });
    }
    if (excludedRoles.length > 0) {
      evidence.push({
        label: "Excluded directory roles",
        detail: excludedRoles.map((id) => roleTemplateName(id)).join(", "),
      });
    }

    findings.push({
      id: `critical-policy-exclusions:${policy.id}`,
      check: "critical-policy-exclusions",
      title: `Enforcing policy "${policy.displayName ?? policy.id}" carves out principals`,
      severity: excludesPrivilegedRole ? "critical" : "high",
      category: "conditional-access",
      description:
        "An enforced policy with an MFA or block grant control excludes principals beyond the declared " +
        "break-glass set. Each exclusion is a permanent, unmonitored bypass of the control the policy exists " +
        "to apply" +
        (excludesPrivilegedRole
          ? ", and here the carve-out is a privileged directory role — precisely the population the policy " +
            "most needs to cover."
          : "."),
      evidence,
      affectedPrincipals: [
        { id: policy.id, type: "policy", displayName: policy.displayName },
        ...excludedUsers.map((id) => resolvePrincipal(snapshot, id)),
        ...excludedGroups.map((id) => resolvePrincipal(snapshot, id)),
      ],
      remediation:
        "Remove the exclusions, or document each one as a break-glass account, register it in the assessment " +
        "configuration, and alert on every sign-in it performs.",
    });
  }

  return findings;
}

// ── app registrations ──

/**
 * Permissions an application *requests*, plus credential hygiene on the app
 * registration itself. What the app actually *holds* is on its service
 * principal and is covered by `analyzeServicePrincipals`.
 */
export function analyzeAppRegistrations(
  snapshot: TenantSnapshot,
  options: AppRegistrationOptions = {},
): IdentityFinding[] {
  const findings: IdentityFinding[] = [];
  const now = options.now ?? new Date();
  const maxLifetimeDays = options.maxCredentialLifetimeDays ?? 365;

  for (const app of snapshot.appRegistrations) {
    const requested = requestedPermissions(app);
    const tier0 = requested.filter((p) => TIER0_GRAPH_PERMISSIONS.has(p.name));
    const highImpact = requested.filter((p) => HIGH_IMPACT_GRAPH_PERMISSIONS.has(p.name));
    const principal = appPrincipal(app);

    if (tier0.length > 0) {
      // Application permissions run with no signed-in user, so consent alone
      // is the whole control. Delegated equivalents still need an admin in the
      // loop, hence the lower rating.
      const hasApplicationPermission = tier0.some((p) => p.type === "Role");
      findings.push({
        id: `app-requests-tier0-graph-permission:${app.id}`,
        check: "app-requests-tier0-graph-permission",
        title: `App "${app.displayName ?? app.appId}" requests tenant-takeover Graph permissions`,
        severity: hasApplicationPermission ? "critical" : "high",
        category: "app-registrations",
        description:
          "The app registration requests Microsoft Graph permissions that are equivalent to full tenant control. " +
          "Any principal that can add a credential to this application — or the app's own compromised secret — " +
          "inherits the ability to grant itself every remaining permission in the directory.",
        evidence: [
          {
            label: "Requested permissions",
            detail: tier0.map((p) => `${p.name} (${p.type})`).join(", "),
            graphPath: "/applications",
          },
          { label: "signInAudience", detail: app.signInAudience ?? "unknown" },
        ],
        affectedPrincipals: [principal],
        remediation:
          "Replace the tier-0 permission with the narrowest scope that satisfies the workload (for example " +
          "`Directory.Read.All` or a resource-specific role), and re-consent the application.",
        references: [
          "https://learn.microsoft.com/entra/identity/role-based-access-control/protected-actions-overview",
        ],
      });
    }

    if (highImpact.length > 0) {
      findings.push({
        id: `app-requests-high-impact-graph-permission:${app.id}`,
        check: "app-requests-high-impact-graph-permission",
        title: `App "${app.displayName ?? app.appId}" requests broad Graph data access`,
        severity: highImpact.some((p) => p.type === "Role") ? "high" : "medium",
        category: "app-registrations",
        description:
          "The app registration requests Microsoft Graph permissions granting tenant-wide read or write access " +
          "to user data, mail, files, or policy. These do not escalate to directory control on their own, but " +
          "they do put the tenant's data in reach of whoever holds the app's credentials.",
        evidence: [
          {
            label: "Requested permissions",
            detail: highImpact.map((p) => `${p.name} (${p.type})`).join(", "),
            graphPath: "/applications",
          },
        ],
        affectedPrincipals: [principal],
        remediation:
          "Scope the app down with resource-specific consent or an application access policy so it can only " +
          "reach the mailboxes, sites, or users it actually needs.",
      });
    }

    if ((tier0.length > 0 || highImpact.length > 0) && isMultiTenant(app.signInAudience)) {
      findings.push({
        id: `multi-tenant-app-with-high-privilege:${app.id}`,
        check: "multi-tenant-app-with-high-privilege",
        title: `Multi-tenant app "${app.displayName ?? app.appId}" requests high-privilege permissions`,
        severity: "critical",
        category: "app-registrations",
        description:
          "The application is published to external tenants (`signInAudience` is not `AzureADMyOrg`) while " +
          "requesting high-privilege Graph permissions. A multi-tenant registration widens the blast radius of " +
          "a stolen credential from this tenant to every tenant that has consented to the app.",
        evidence: [
          { label: "signInAudience", detail: app.signInAudience ?? "unknown", graphPath: "/applications" },
          {
            label: "High-privilege permissions requested",
            detail: [...tier0, ...highImpact].map((p) => p.name).join(", "),
          },
          {
            label: "Verified publisher",
            detail: app.verifiedPublisher?.displayName ?? "none",
          },
        ],
        affectedPrincipals: [principal],
        remediation:
          "Set `signInAudience` to `AzureADMyOrg` unless multi-tenant distribution is a product requirement. If " +
          "it is, split the high-privilege workload into a separate single-tenant registration.",
      });
    }

    const credentials = allCredentials(app.passwordCredentials, app.keyCredentials);
    const expired = credentials.filter((c) => c.endDateTime && Date.parse(c.endDateTime) < now.getTime());
    if (expired.length > 0) {
      findings.push({
        id: `app-credential-expired:${app.id}`,
        check: "app-credential-expired",
        title: `App "${app.displayName ?? app.appId}" retains ${expired.length} expired credential(s)`,
        severity: "low",
        category: "app-registrations",
        description:
          "Expired secrets or certificates are still attached to the app registration. They no longer " +
          "authenticate, but they inflate the credential surface a reviewer has to reason about and usually " +
          "indicate that credential rotation is not being cleaned up.",
        evidence: expired.map((c) => ({
          label: `Expired ${c.kind}`,
          detail: `${c.displayName ?? c.keyId ?? "unnamed"} expired ${c.endDateTime}`,
          graphPath: "/applications",
        })),
        affectedPrincipals: [principal],
        remediation: "Delete expired `passwordCredentials` and `keyCredentials` entries from the registration.",
      });
    }

    const longLived = credentials.filter((c) => {
      const lifetime = credentialLifetimeDays(c, now);
      return lifetime !== undefined && lifetime > maxLifetimeDays;
    });
    if (longLived.length > 0) {
      const worst = Math.max(...longLived.map((c) => credentialLifetimeDays(c, now) ?? 0));
      findings.push({
        id: `app-credential-long-lived:${app.id}`,
        check: "app-credential-long-lived",
        title: `App "${app.displayName ?? app.appId}" has credentials valid for up to ${Math.floor(worst)} days`,
        severity: worst > maxLifetimeDays * 2 ? "high" : "medium",
        category: "app-registrations",
        description:
          "One or more credentials on the app registration are valid for longer than the configured maximum " +
          `lifetime of ${maxLifetimeDays} days. A long-lived secret extends the window in which a leaked ` +
          "credential stays usable, and it is the window — not the leak — that determines impact.",
        evidence: longLived.map((c) => ({
          label: `Long-lived ${c.kind}`,
          detail:
            `${c.displayName ?? c.keyId ?? "unnamed"} valid ` +
            `${Math.floor(credentialLifetimeDays(c, now) ?? 0)} days (until ${c.endDateTime ?? "unspecified"})`,
          graphPath: "/applications",
        })),
        affectedPrincipals: [principal],
        remediation:
          "Move the workload to workload-identity federation (no stored secret at all) or, failing that, to " +
          "certificate credentials with a lifetime under the configured maximum and automated rotation.",
      });
    }
  }

  return findings;
}

// ── service principals ──

/**
 * The grant side of the app model: directory roles held by service principals,
 * Graph app roles actually consented to, credentials that effectively never
 * expire, and privileged identities nobody has used in months.
 */
export function analyzeServicePrincipals(
  snapshot: TenantSnapshot,
  options: ServicePrincipalOptions = {},
): IdentityFinding[] {
  const findings: IdentityFinding[] = [];
  const now = options.now ?? new Date();
  const unusedAfterDays = options.unusedAfterDays ?? 90;
  const neverExpiresAfterDays = options.neverExpiresAfterDays ?? 3650;

  const rolesByPrincipal = new Map<string, string[]>();
  for (const assignment of snapshot.roleAssignments) {
    if (!PRIVILEGED_ROLE_TEMPLATE_IDS.has(templateIdFor(snapshot, assignment.roleDefinitionId))) continue;
    const roles = rolesByPrincipal.get(assignment.principalId) ?? [];
    roles.push(assignment.roleDefinitionId);
    rolesByPrincipal.set(assignment.principalId, roles);
  }

  for (const sp of snapshot.servicePrincipals) {
    const principal = servicePrincipalPrincipal(sp);
    const roleDefinitionIds = rolesByPrincipal.get(sp.id) ?? [];
    const tier0Role = roleDefinitionIds.some((id) => TIER0_ROLE_TEMPLATE_IDS.has(templateIdFor(snapshot, id)));

    if (roleDefinitionIds.length > 0) {
      findings.push({
        id: `service-principal-in-privileged-role:${sp.id}`,
        check: "service-principal-in-privileged-role",
        title: `Service principal "${sp.displayName ?? sp.appId}" holds privileged directory roles`,
        severity: tier0Role ? "critical" : "high",
        category: "service-principals",
        description:
          "A non-human identity holds privileged directory roles. Service principals authenticate with secrets " +
          "or certificates, are exempt from conditional access in most configurations, and rarely appear in the " +
          "access reviews that cover human admins — so this privilege tends to persist unexamined.",
        evidence: [
          {
            label: "Privileged roles",
            detail: roleDefinitionIds.map((id) => roleDisplayName(snapshot, id)).join(", "),
            graphPath: "/roleManagement/directory/roleAssignments",
          },
          { label: "servicePrincipalType", detail: sp.servicePrincipalType ?? "unknown", graphPath: "/servicePrincipals" },
          { label: "Credentials on principal", detail: String(allCredentials(sp.passwordCredentials, sp.keyCredentials).length) },
        ],
        affectedPrincipals: [principal],
        remediation:
          "Remove the directory role and grant the narrowest Graph application permission the workload needs. " +
          "Where a role is genuinely required, use a managed identity with federated credentials rather than a " +
          "secret, and put the assignment under access review.",
      });
    }

    const grantedNames: Array<{ grant: GraphAppRoleAssignment; name: string }> = [];
    for (const grant of sp.appRoleAssignments ?? []) {
      const name = grant.value ?? GRAPH_APP_ROLE_CATALOG[grant.appRoleId];
      if (name) grantedNames.push({ grant, name });
    }
    const tier0Grants = grantedNames.filter((g) => TIER0_GRAPH_PERMISSIONS.has(g.name));
    const highImpactGrants = grantedNames.filter((g) => HIGH_IMPACT_GRAPH_PERMISSIONS.has(g.name));

    if (tier0Grants.length > 0 || highImpactGrants.length > 0) {
      findings.push({
        id: `service-principal-granted-tier0-permission:${sp.id}`,
        check: "service-principal-granted-tier0-permission",
        title: `Service principal "${sp.displayName ?? sp.appId}" has been granted high-privilege Graph permissions`,
        severity: tier0Grants.length > 0 ? "critical" : "high",
        category: "service-principals",
        description:
          "These are consented grants, not requests — the permissions are live right now. " +
          (tier0Grants.length > 0
            ? "The granted set is equivalent to tenant takeover: the service principal can assign directory " +
              "roles or add credentials to other applications and escalate from there."
            : "The granted set gives tenant-wide access to user data, mail, files, or policy."),
        evidence: [
          {
            label: "Granted application permissions",
            detail: [...tier0Grants, ...highImpactGrants].map((g) => g.name).join(", "),
            graphPath: `/servicePrincipals/${sp.id}/appRoleAssignments`,
          },
          {
            label: "Home tenant",
            detail:
              sp.appOwnerOrganizationId && sp.appOwnerOrganizationId !== snapshot.tenantId
                ? `external (${sp.appOwnerOrganizationId})`
                : "this tenant",
          },
        ],
        affectedPrincipals: [principal],
        remediation:
          "Revoke the app role assignment and re-consent with the least-privileged alternative. Audit the " +
          "service principal's sign-in and directory-audit history for use of the permission before revoking.",
      });
    }

    const credentials = allCredentials(sp.passwordCredentials, sp.keyCredentials);
    const nonExpiring = credentials.filter((c) => {
      if (!c.endDateTime) return true;
      const lifetime = credentialLifetimeDays(c, now);
      return lifetime !== undefined && lifetime > neverExpiresAfterDays;
    });
    if (nonExpiring.length > 0) {
      findings.push({
        id: `service-principal-credential-never-expires:${sp.id}`,
        check: "service-principal-credential-never-expires",
        title: `Service principal "${sp.displayName ?? sp.appId}" has credentials that never expire`,
        severity: tier0Role || tier0Grants.length > 0 ? "critical" : "high",
        category: "service-principals",
        description:
          "One or more credentials on the service principal have no expiry, or an expiry so distant it is not a " +
          "control. A credential that never expires converts a single leak — a log line, a CI variable, a " +
          "committed config — into indefinite access.",
        evidence: nonExpiring.map((c) => ({
          label: `Non-expiring ${c.kind}`,
          detail: `${c.displayName ?? c.keyId ?? "unnamed"} endDateTime=${c.endDateTime ?? "none"}`,
          graphPath: "/servicePrincipals",
        })),
        affectedPrincipals: [principal],
        remediation:
          "Replace the credential with a federated (workload-identity) credential, or set a bounded expiry and " +
          "automate rotation.",
      });
    }

    // Sign-in activity comes from a beta report and is often absent. Only a
    // *present* timestamp older than the window is evidence of disuse.
    const lastSignIn = sp.signInActivity?.lastSignInDateTime;
    const isPrivileged = roleDefinitionIds.length > 0 || tier0Grants.length > 0 || highImpactGrants.length > 0;
    if (isPrivileged && lastSignIn) {
      const idleDays = daysBetween(lastSignIn, now);
      if (idleDays !== undefined && idleDays > unusedAfterDays) {
        findings.push({
          id: `unused-privileged-service-principal:${sp.id}`,
          check: "unused-privileged-service-principal",
          title: `Privileged service principal "${sp.displayName ?? sp.appId}" has been idle ${Math.floor(idleDays)} days`,
          severity: "high",
          category: "service-principals",
          description:
            "The service principal holds privileged access but has not signed in for longer than the configured " +
            "window. Dormant privileged identities are the ideal target: the access still works, and nobody is " +
            "watching a workload that stopped producing signal months ago.",
          evidence: [
            {
              label: "Last sign-in",
              detail: lastSignIn,
              graphPath: "/reports/servicePrincipalSignInActivities",
            },
            {
              label: "Privileged access held",
              detail: [
                ...roleDefinitionIds.map((id) => roleDisplayName(snapshot, id)),
                ...tier0Grants.map((g) => g.name),
                ...highImpactGrants.map((g) => g.name),
              ].join(", "),
            },
          ],
          affectedPrincipals: [principal],
          remediation:
            "Confirm the workload is retired and delete the service principal, or remove its privileged access " +
            "until the workload is active again.",
        });
      }
    }
  }

  return findings;
}

// ── federation ──

/**
 * Federated-domain trust configuration. A federated domain hands the tenant's
 * authentication decision to an external IdP, so the settings governing that
 * trust are effectively part of the tenant's authentication boundary.
 */
export function analyzeFederation(snapshot: TenantSnapshot): IdentityFinding[] {
  const findings: IdentityFinding[] = [];

  for (const domain of snapshot.federationConfig.domains) {
    if ((domain.authenticationType ?? "").toLowerCase() !== "federated") continue;
    const principal: AffectedPrincipal = { id: domain.id, type: "domain", displayName: domain.id };
    const config = domain.federationConfiguration;

    if (domain.isVerified === false) {
      findings.push({
        id: `unverified-federated-domain:${domain.id}`,
        check: "unverified-federated-domain",
        title: `Federated domain ${domain.id} is not verified`,
        severity: "high",
        category: "federation",
        description:
          "A domain is configured for federation but its ownership has not been verified. An unverified " +
          "federated domain is a trust relationship the tenant cannot prove it should have.",
        evidence: [
          { label: "authenticationType", detail: domain.authenticationType ?? "unknown", graphPath: "/domains" },
          { label: "isVerified", detail: "false", graphPath: "/domains" },
        ],
        affectedPrincipals: [principal],
        remediation:
          "Complete DNS verification for the domain, or remove the federation configuration and the domain if it " +
          "is not in use.",
      });
    }

    if (!config) continue;
    const path = `/domains/${domain.id}/federationConfiguration`;

    // The historical default, `acceptIfMfaDoneByFederatedIdp`, lets the
    // federated IdP simply assert that MFA happened. Anyone holding the
    // token-signing key can therefore forge an MFA-satisfied assertion and
    // walk straight past every MFA policy in the tenant.
    const mfaBehavior = config.federatedIdpMfaBehavior;
    if (mfaBehavior !== "enforceMfaByFederatedIdp") {
      findings.push({
        id: `federated-idp-mfa-bypass:${domain.id}`,
        check: "federated-idp-mfa-bypass",
        title: `Federated domain ${domain.id} accepts MFA claims from the external IdP`,
        severity: mfaBehavior === "acceptIfMfaDoneByFederatedIdp" ? "critical" : "high",
        category: "federation",
        description:
          "`federatedIdpMfaBehavior` is " +
          (mfaBehavior ? `\`${mfaBehavior}\`` : "unset, which falls back to the legacy `SupportsMfa` behaviour") +
          ". Entra ID trusts the federated identity provider's assertion that multi-factor authentication was " +
          "performed rather than requiring it itself. An attacker who compromises the IdP or its token-signing " +
          "key can assert MFA without performing it, defeating every MFA conditional-access policy for users in " +
          "this domain.",
        evidence: [
          { label: "federatedIdpMfaBehavior", detail: mfaBehavior ?? "unset", graphPath: path },
          { label: "issuerUri", detail: config.issuerUri ?? "unknown", graphPath: path },
        ],
        affectedPrincipals: [principal],
        remediation:
          "Set `federatedIdpMfaBehavior` to `enforceMfaByFederatedIdp` so Entra ID requires MFA regardless of " +
          "the federated claim, or migrate the domain to managed authentication with cloud MFA.",
        references: [
          "https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-server-migration-utility",
        ],
      });
    }

    if (!config.nextSigningCertificate) {
      findings.push({
        id: `federation-no-signing-certificate-rollover:${domain.id}`,
        check: "federation-no-signing-certificate-rollover",
        title: `Federated domain ${domain.id} has no successor signing certificate staged`,
        severity: "medium",
        category: "federation",
        description:
          "No `nextSigningCertificate` is configured, so there is no staged rollover. When the active " +
          "token-signing certificate expires, federated authentication for the domain fails outright — and the " +
          "emergency fix under outage pressure is usually a rushed, unreviewed trust change.",
        evidence: [
          { label: "nextSigningCertificate", detail: "not set", graphPath: path },
          { label: "signingCertificate", detail: config.signingCertificate ? "present" : "not set", graphPath: path },
        ],
        affectedPrincipals: [principal],
        remediation: "Stage the successor token-signing certificate and automate the rollover ahead of expiry.",
      });
    }

    const updateResult = config.signingCertificateUpdateStatus?.certificateUpdateResult;
    if (updateResult && updateResult.toLowerCase() !== "success") {
      findings.push({
        id: `federation-signing-certificate-update-failed:${domain.id}`,
        check: "federation-signing-certificate-update-failed",
        title: `Signing-certificate update failed for federated domain ${domain.id}`,
        severity: "medium",
        category: "federation",
        description:
          "The last automated token-signing certificate update did not succeed, so the tenant's view of the " +
          "IdP's signing material may be stale relative to what the IdP is actually signing with.",
        evidence: [
          { label: "certificateUpdateResult", detail: updateResult, graphPath: path },
          {
            label: "lastRunDateTime",
            detail: config.signingCertificateUpdateStatus?.lastRunDateTime ?? "unknown",
            graphPath: path,
          },
        ],
        affectedPrincipals: [principal],
        remediation:
          "Re-run the federation metadata update and confirm `certificateUpdateResult` reports success.",
      });
    }

    if (config.isSignedAuthenticationRequestRequired !== true) {
      findings.push({
        id: `federation-request-signing-not-required:${domain.id}`,
        check: "federation-request-signing-not-required",
        title: `Federated domain ${domain.id} does not require signed authentication requests`,
        severity: "medium",
        category: "federation",
        description:
          "`isSignedAuthenticationRequestRequired` is not enabled, so the identity provider accepts unsigned " +
          "authentication requests. Request signing is what lets the IdP prove a request genuinely originated " +
          "from Entra ID rather than from an attacker-controlled relay.",
        evidence: [
          {
            label: "isSignedAuthenticationRequestRequired",
            detail: String(config.isSignedAuthenticationRequestRequired ?? "unset"),
            graphPath: path,
          },
        ],
        affectedPrincipals: [principal],
        remediation:
          "Enable signed authentication requests on the federation configuration once the IdP is confirmed to " +
          "validate them.",
      });
    }

    const insecure = ([
      ["issuerUri", config.issuerUri],
      ["passiveSignInUri", config.passiveSignInUri],
      ["activeSignInUri", config.activeSignInUri],
      ["metadataExchangeUri", config.metadataExchangeUri],
      ["signOutUri", config.signOutUri],
    ] as const).filter(([, value]) => typeof value === "string" && value.toLowerCase().startsWith("http://"));

    if (insecure.length > 0) {
      findings.push({
        id: `federation-insecure-endpoint:${domain.id}`,
        check: "federation-insecure-endpoint",
        title: `Federated domain ${domain.id} uses cleartext federation endpoints`,
        severity: "high",
        category: "federation",
        description:
          "One or more federation endpoints are plain `http://`. Federation traffic carries authentication " +
          "assertions and metadata, including the signing certificates the trust is built on; over cleartext " +
          "both are readable and modifiable by anyone on the path.",
        evidence: insecure.map(([label, value]) => ({ label, detail: String(value), graphPath: path })),
        affectedPrincipals: [principal],
        remediation: "Reconfigure every federation endpoint to HTTPS and re-import the federation metadata.",
      });
    }
  }

  return findings;
}

// ── composition ──

/** Every analyzer, in a stable order. Used by `runIdentityAssessment`. */
export function runAllAnalyzers(
  snapshot: TenantSnapshot,
  options: IdentityAnalyzerOptions = {},
): IdentityFinding[] {
  return [
    ...analyzePrivilegedRoles(snapshot, options),
    ...analyzeConditionalAccess(snapshot, options),
    ...analyzeAppRegistrations(snapshot, options),
    ...analyzeServicePrincipals(snapshot, options),
    ...analyzeFederation(snapshot),
  ];
}

const SEVERITY_ORDER: Record<IdentitySeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

/** Sort findings most-severe-first, then by check and id for run-to-run stability. */
export function sortFindings(findings: IdentityFinding[]): IdentityFinding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (bySeverity !== 0) return bySeverity;
    if (a.check !== b.check) return a.check < b.check ? -1 : 1;
    return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  });
}

export function summarizeFindings(findings: IdentityFinding[]): {
  total: number;
  bySeverity: Record<IdentitySeverity, number>;
  byCategory: Record<IdentityFindingCategory, number>;
} {
  const bySeverity: Record<IdentitySeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byCategory: Record<IdentityFindingCategory, number> = {
    "privileged-roles": 0,
    "conditional-access": 0,
    "app-registrations": 0,
    "service-principals": 0,
    federation: 0,
  };
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    byCategory[finding.category] += 1;
  }
  return { total: findings.length, bySeverity, byCategory };
}

// ── internals ──

/**
 * Resolve a role definition id to its cross-tenant template id. Built-in roles
 * usually use the template id as the definition id, but custom roles do not,
 * and we should not rely on the coincidence.
 */
function templateIdFor(snapshot: TenantSnapshot, roleDefinitionId: string): string {
  const definition = snapshot.roleDefinitions.find((d) => d.id === roleDefinitionId);
  return definition?.templateId ?? roleDefinitionId;
}

function roleDisplayName(snapshot: TenantSnapshot, roleDefinitionId: string): string {
  const definition = snapshot.roleDefinitions.find((d) => d.id === roleDefinitionId);
  if (definition?.displayName) return definition.displayName;
  return roleTemplateName(templateIdFor(snapshot, roleDefinitionId));
}

function roleTemplateName(templateId: string): string {
  for (const [name, id] of Object.entries(ROLE_TEMPLATE_IDS)) {
    if (id === templateId) return splitCamel(name);
  }
  return templateId;
}

function splitCamel(name: string): string {
  const spaced = name.replace(/([A-Z])/g, " $1");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/**
 * True when the principal has a live PIM eligibility for the role, which means
 * an active assignment for it is a just-in-time activation rather than
 * standing privilege.
 */
function hasEligibility(snapshot: TenantSnapshot, principalId: string, roleDefinitionId: string): boolean {
  return snapshot.roleEligibilitySchedules.some(
    (s) => s.principalId === principalId && s.roleDefinitionId === roleDefinitionId && isLiveEligibility(s.status),
  );
}

function isLiveEligibility(status: string | undefined): boolean {
  if (status === undefined) return true;
  const normalized = status.toLowerCase();
  return normalized === "provisioned" || normalized === "granted";
}

function resolvePrincipal(snapshot: TenantSnapshot, principalId: string): AffectedPrincipal {
  const user = snapshot.users.find((u) => u.id === principalId);
  if (user) {
    return {
      id: user.id,
      type: "user",
      displayName: user.displayName,
      userPrincipalName: user.userPrincipalName,
    };
  }
  const sp = snapshot.servicePrincipals.find((s) => s.id === principalId);
  if (sp) return servicePrincipalPrincipal(sp);
  const group = snapshot.groups.find((g) => g.id === principalId);
  if (group) return { id: group.id, type: "group", displayName: group.displayName };
  return { id: principalId, type: "unknown" };
}

function principalLabel(snapshot: TenantSnapshot, principalId: string): string {
  const principal = resolvePrincipal(snapshot, principalId);
  return principal.userPrincipalName ?? principal.displayName ?? principal.id;
}

function servicePrincipalPrincipal(sp: ServicePrincipalRecord): AffectedPrincipal {
  return { id: sp.id, type: "servicePrincipal", displayName: sp.displayName, appId: sp.appId };
}

function appPrincipal(app: AppRegistration): AffectedPrincipal {
  return { id: app.id, type: "application", displayName: app.displayName, appId: app.appId };
}

function addTo(map: Map<string, Set<string>>, key: string, value: string): void {
  const existing = map.get(key);
  if (existing) existing.add(value);
  else map.set(key, new Set([value]));
}

function collectionFailed(snapshot: TenantSnapshot, needle: string): boolean {
  return snapshot.warnings.some((w) => w.toLowerCase().includes(needle.toLowerCase()));
}

// conditional-access predicates

function requiresStrongAuth(policy: ConditionalAccessPolicy): boolean {
  const controls = policy.grantControls;
  if (!controls) return false;
  if (controls.authenticationStrength?.id) return true;
  return (controls.builtInControls ?? []).includes("mfa");
}

function blocksAccess(policy: ConditionalAccessPolicy): boolean {
  return (policy.grantControls?.builtInControls ?? []).includes("block");
}

/**
 * A policy covers admins when it targets privileged role templates directly or
 * targets every user (the reserved `All` literal), which necessarily includes
 * the admins.
 */
function targetsAdmins(policy: ConditionalAccessPolicy): boolean {
  const users = policy.conditions?.users;
  if (!users) return false;
  if ((users.includeUsers ?? []).some((id) => id.toLowerCase() === "all")) return true;
  return (users.includeRoles ?? []).some((id) => PRIVILEGED_ROLE_TEMPLATE_IDS.has(id));
}

/**
 * The canonical legacy-auth block: a `block` grant control covering *both*
 * legacy client-app buckets. Both are required — `exchangeActiveSync` alone
 * leaves `other` (IMAP, POP, SMTP AUTH, older Office clients) reachable, which
 * is the bucket most password-spray traffic actually lands in. A policy scoped
 * to `all` client apps is a different control and does not count.
 */
function blocksLegacyAuth(policy: ConditionalAccessPolicy): boolean {
  if (!blocksAccess(policy)) return false;
  const clientApps = policy.conditions?.clientAppTypes ?? [];
  return clientApps.includes("exchangeActiveSync") && clientApps.includes("other");
}

function describeGrantControls(policy: ConditionalAccessPolicy): string {
  const controls = policy.grantControls;
  if (!controls) return "none";
  const parts = [...(controls.builtInControls ?? [])];
  if (controls.authenticationStrength?.displayName) {
    parts.push(`authenticationStrength=${controls.authenticationStrength.displayName}`);
  }
  return parts.length > 0 ? parts.join(` ${controls.operator ?? "OR"} `) : "none";
}

function summarizeStates(policies: ConditionalAccessPolicy[]): string {
  const counts = new Map<string, number>();
  for (const policy of policies) counts.set(policy.state, (counts.get(policy.state) ?? 0) + 1);
  if (counts.size === 0) return "no policies configured";
  return [...counts].map(([state, count]) => `${state}=${count}`).join(", ");
}

// permission + credential helpers

interface ResolvedPermission {
  name: string;
  type: "Role" | "Scope";
}

/**
 * Flatten `requiredResourceAccess` into resolved permission names. Names come
 * from the collector's tenant-side resolution when available, and fall back to
 * the static catalog for Microsoft Graph.
 */
function requestedPermissions(app: AppRegistration): ResolvedPermission[] {
  const out: ResolvedPermission[] = [];
  for (const required of app.requiredResourceAccess ?? []) {
    for (const access of required.resourceAccess ?? []) {
      const name =
        access.value ??
        (required.resourceAppId === MICROSOFT_GRAPH_APP_ID ? GRAPH_APP_ROLE_CATALOG[access.id] : undefined);
      if (name) out.push({ name, type: access.type });
    }
  }
  return out;
}

interface CredentialView {
  kind: "secret" | "certificate";
  keyId?: string;
  displayName?: string;
  startDateTime?: string;
  endDateTime?: string;
}

function allCredentials(
  passwords: GraphPasswordCredential[] | undefined,
  keys: GraphKeyCredential[] | undefined,
): CredentialView[] {
  return [
    ...(passwords ?? []).map((c): CredentialView => ({
      kind: "secret",
      keyId: c.keyId,
      displayName: c.displayName,
      startDateTime: c.startDateTime,
      endDateTime: c.endDateTime,
    })),
    ...(keys ?? []).map((c): CredentialView => ({
      kind: "certificate",
      keyId: c.keyId,
      displayName: c.displayName,
      startDateTime: c.startDateTime,
      endDateTime: c.endDateTime,
    })),
  ];
}

/**
 * Total validity window in days. Uses `startDateTime` when present, otherwise
 * measures from now — which understates the lifetime of an old credential, so
 * the check errs toward not firing.
 */
function credentialLifetimeDays(credential: CredentialView, now: Date): number | undefined {
  if (!credential.endDateTime) return undefined;
  const end = Date.parse(credential.endDateTime);
  if (!Number.isFinite(end)) return undefined;
  const startRaw = credential.startDateTime ? Date.parse(credential.startDateTime) : Number.NaN;
  const start = Number.isFinite(startRaw) ? startRaw : now.getTime();
  return (end - start) / DAY_MS;
}

function daysBetween(iso: string, now: Date): number | undefined {
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return undefined;
  return (now.getTime() - then) / DAY_MS;
}

/** Exported so `IdentityCheck` stays the single list of implemented rules. */
export const IDENTITY_CHECKS: readonly IdentityCheck[] = [
  "excessive-standing-global-admins",
  "insufficient-global-admins",
  "standing-privileged-access",
  "privileged-account-without-mfa",
  "guest-in-privileged-role",
  "disabled-account-in-privileged-role",
  "synced-account-in-privileged-role",
  "no-enabled-conditional-access-policies",
  "no-mfa-policy-for-admins",
  "legacy-authentication-not-blocked",
  "policy-stuck-in-report-only",
  "critical-policy-exclusions",
  "app-requests-tier0-graph-permission",
  "app-requests-high-impact-graph-permission",
  "app-credential-expired",
  "app-credential-long-lived",
  "multi-tenant-app-with-high-privilege",
  "service-principal-in-privileged-role",
  "service-principal-granted-tier0-permission",
  "service-principal-credential-never-expires",
  "unused-privileged-service-principal",
  "federated-idp-mfa-bypass",
  "unverified-federated-domain",
  "federation-no-signing-certificate-rollover",
  "federation-signing-certificate-update-failed",
  "federation-request-signing-not-required",
  "federation-insecure-endpoint",
];

function isMultiTenant(signInAudience: string | undefined): boolean {
  if (!signInAudience) return false;
  return signInAudience !== "AzureADMyOrg";
}
