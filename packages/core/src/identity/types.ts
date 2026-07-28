// Cloud identity assessment — Microsoft Entra ID (Azure AD) types.
//
// Every shape in this file mirrors a real Microsoft Graph v1.0 resource so a
// snapshot can be built by de-serialising Graph responses with no lossy
// translation step in between. Field names match Graph exactly (camelCase,
// `...DateTime` suffixes, `@odata` envelope handled in `graph-client.ts`).
// Where a field only exists on the beta endpoint, or is joined in from a
// second endpoint, the doc comment says so — that provenance is what keeps a
// finding defensible when a customer asks "where did you read that?".
//
// Optionality rule: anything Graph can legitimately omit (because the caller
// didn't `$select` it, or the token lacks the scope) is optional here, and
// every analyzer must treat "absent" as "unknown", never as "safe". A finding
// raised off a field the collector never populated is a false positive we
// would have to defend, so analyzers skip unknowns instead of guessing.

// ── findings ──

export type IdentitySeverity = "critical" | "high" | "medium" | "low" | "info";

export type IdentityFindingCategory =
  | "privileged-roles"
  | "conditional-access"
  | "app-registrations"
  | "service-principals"
  | "federation"
  | "tokens";

/**
 * Stable rule identifier. One per check implemented in `analyzers.ts` or
 * `tokens.ts`. `IdentityFinding.id` is per-instance (rule + affected object) so
 * callers can dedupe across runs; `check` is the rule itself so callers can
 * group.
 */
export type IdentityCheck =
  // privileged-roles
  | "excessive-standing-global-admins"
  | "insufficient-global-admins"
  | "standing-privileged-access"
  | "privileged-account-without-mfa"
  | "guest-in-privileged-role"
  | "disabled-account-in-privileged-role"
  | "synced-account-in-privileged-role"
  // conditional-access
  | "no-enabled-conditional-access-policies"
  | "no-mfa-policy-for-admins"
  | "legacy-authentication-not-blocked"
  | "policy-stuck-in-report-only"
  | "critical-policy-exclusions"
  // app-registrations
  | "app-requests-tier0-graph-permission"
  | "app-requests-high-impact-graph-permission"
  | "app-credential-expired"
  | "app-credential-long-lived"
  | "multi-tenant-app-with-high-privilege"
  // service-principals
  | "service-principal-in-privileged-role"
  | "service-principal-granted-tier0-permission"
  | "service-principal-credential-never-expires"
  | "unused-privileged-service-principal"
  // federation
  | "federated-idp-mfa-bypass"
  | "unverified-federated-domain"
  | "federation-no-signing-certificate-rollover"
  | "federation-signing-certificate-update-failed"
  | "federation-request-signing-not-required"
  | "federation-insecure-endpoint"
  // tokens — JWT (see `tokens.ts`; offline analysis of supplied material)
  | "token-unrecognized-format"
  | "jwt-malformed"
  | "jwt-alg-none"
  | "jwt-algorithm-confusion-exposure"
  | "jwt-unsafe-key-identifier"
  | "jwt-missing-expiry"
  | "jwt-excessive-lifetime"
  | "jwt-expired"
  | "jwt-untrusted-issuer"
  | "jwt-weak-audience"
  | "jwt-missing-replay-controls"
  | "jwt-sensitive-claim-data"
  | "jwt-overly-broad-scope"
  // tokens — Entra-specific
  | "entra-token-type-mismatch"
  | "entra-token-weak-client-binding"
  | "entra-token-privileged-wids"
  | "entra-token-multi-tenant-issuer"
  | "entra-token-long-lived-session"
  // tokens — SAML
  | "saml-malformed"
  | "saml-unsigned-assertion"
  | "saml-signature-wrapping-exposure"
  | "saml-weak-conditions"
  | "saml-missing-audience-restriction"
  | "saml-weak-subject-confirmation"
  | "saml-nameid-comment-truncation"
  | "saml-golden-saml-preconditions";

export type IdentityPrincipalType =
  | "user"
  | "group"
  | "servicePrincipal"
  | "application"
  | "domain"
  | "policy"
  | "unknown";

/**
 * An object a finding is about. `id` is the Graph object id (or the domain
 * name for `domain` principals, which is what Graph uses as the key on
 * `/domains`).
 */
export interface AffectedPrincipal {
  id: string;
  type: IdentityPrincipalType;
  displayName?: string;
  userPrincipalName?: string;
  appId?: string;
}

/**
 * A single grounded observation backing a finding. `graphPath` is the v1.0
 * path the value was read from, so a reviewer can re-run the same GET.
 */
export interface IdentityEvidence {
  label: string;
  detail: string;
  graphPath?: string;
}

export interface IdentityFinding {
  /** Per-instance id: `<check>` for tenant-wide, `<check>:<objectId>` otherwise. */
  id: string;
  check: IdentityCheck;
  title: string;
  severity: IdentitySeverity;
  category: IdentityFindingCategory;
  description: string;
  evidence: IdentityEvidence[];
  affectedPrincipals: AffectedPrincipal[];
  remediation: string;
  references?: string[];
}

// ── shared Graph credential shapes ──

/** `passwordCredential` resource. `secretText` is write-only and never read. */
export interface GraphPasswordCredential {
  keyId?: string;
  displayName?: string;
  hint?: string;
  startDateTime?: string;
  /** Absent (or absurdly far future) means "effectively never expires". */
  endDateTime?: string;
}

/** `keyCredential` resource (certificates). */
export interface GraphKeyCredential {
  keyId?: string;
  displayName?: string;
  /** e.g. `AsymmetricX509Cert`. */
  type?: string;
  /** e.g. `Verify` / `Sign`. */
  usage?: string;
  startDateTime?: string;
  endDateTime?: string;
}

// ── directory objects ──

/**
 * `/users`. `signInActivity` requires `AuditLog.Read.All` and is dropped by
 * Graph when the caller lacks it. The `isMfa*` fields are NOT on the user
 * resource — they are joined in from
 * `/reports/authenticationMethods/userRegistrationDetails` by the collector.
 */
export interface TenantUser {
  id: string;
  displayName?: string;
  userPrincipalName?: string;
  mail?: string;
  accountEnabled?: boolean;
  /** `Member` | `Guest`. */
  userType?: string;
  createdDateTime?: string;
  /** True when the account is mastered on-premises and synced by Entra Connect. */
  onPremisesSyncEnabled?: boolean;
  /**
   * Base64 of the source object's `objectGUID` (or `mS-DS-ConsistencyGuid` when
   * the Connect anchor was moved). This is the anchor Entra Connect itself joins
   * on, so it is the highest-confidence link back to an on-premises object.
   * Consumed by `./hybrid/` — nothing else in this module reads it.
   */
  onPremisesImmutableId?: string;
  /** The source object's `objectSid`, verbatim. Equally authoritative. */
  onPremisesSecurityIdentifier?: string;
  onPremisesDistinguishedName?: string;
  onPremisesSamAccountName?: string;
  onPremisesDomainName?: string;
  signInActivity?: {
    lastSignInDateTime?: string;
    lastNonInteractiveSignInDateTime?: string;
  };
  /** Joined from `/reports/authenticationMethods/userRegistrationDetails`. */
  isMfaRegistered?: boolean;
  /** Joined from the same report. Registered-but-not-capable is a real state. */
  isMfaCapable?: boolean;
}

/** `/groups`. `isAssignableToRole` marks a role-assignable (protected) group. */
export interface TenantGroup {
  id: string;
  displayName?: string;
  description?: string;
  mailEnabled?: boolean;
  securityEnabled?: boolean;
  /** e.g. `["Unified"]`, `["DynamicMembership"]`. */
  groupTypes?: string[];
  membershipRule?: string;
  isAssignableToRole?: boolean;
  visibility?: string;
  onPremisesSyncEnabled?: boolean;
  /** Same hybrid-correspondence anchors as `TenantUser`. Read by `./hybrid/`. */
  onPremisesSecurityIdentifier?: string;
  onPremisesDistinguishedName?: string;
  onPremisesSamAccountName?: string;
  createdDateTime?: string;
}

/** One entry of `application.requiredResourceAccess[].resourceAccess[]`. */
export interface GraphResourceAccess {
  /** GUID of the app role (`Role`) or delegated scope (`Scope`). */
  id: string;
  /** `Role` = application permission, `Scope` = delegated permission. */
  type: "Role" | "Scope";
  /**
   * Human-readable permission name (`Directory.ReadWrite.All`). Not part of
   * the Graph payload — resolved by the collector from the resource service
   * principal's `appRoles` / `oauth2PermissionScopes`. Analyzers fall back to
   * a static GUID catalog when this is absent.
   */
  value?: string;
}

/** `application.requiredResourceAccess[]` — permissions the app *requests*. */
export interface GraphRequiredResourceAccess {
  /** e.g. `00000003-0000-0000-c000-000000000000` for Microsoft Graph. */
  resourceAppId: string;
  resourceAccess: GraphResourceAccess[];
}

/**
 * `/applications` — an app registration. Note the request/grant split: this
 * resource carries what the app *asks for* (`requiredResourceAccess`); what it
 * actually *holds* lives on the tenant's service principal for the app
 * (`ServicePrincipalRecord.appRoleAssignments`).
 */
export interface AppRegistration {
  id: string;
  appId: string;
  displayName?: string;
  /**
   * `AzureADMyOrg` (single-tenant) | `AzureADMultipleOrgs` |
   * `AzureADandPersonalMicrosoftAccount` | `PersonalMicrosoftAccount`.
   */
  signInAudience?: string;
  createdDateTime?: string;
  publisherDomain?: string;
  verifiedPublisher?: { displayName?: string; verifiedPublisherId?: string };
  passwordCredentials?: GraphPasswordCredential[];
  keyCredentials?: GraphKeyCredential[];
  requiredResourceAccess?: GraphRequiredResourceAccess[];
  web?: {
    redirectUris?: string[];
    implicitGrantSettings?: {
      enableAccessTokenIssuance?: boolean;
      enableIdTokenIssuance?: boolean;
    };
  };
}

/** `/servicePrincipals/{id}/appRoleAssignments` — permissions actually granted. */
export interface GraphAppRoleAssignment {
  id: string;
  /** The app role GUID on the *resource* (e.g. a Microsoft Graph app role). */
  appRoleId: string;
  /** Object id of the service principal holding the grant. */
  principalId?: string;
  principalDisplayName?: string;
  /** Object id of the resource service principal (e.g. Microsoft Graph). */
  resourceId?: string;
  resourceDisplayName?: string;
  createdDateTime?: string;
  /** Resolved permission name; see `GraphResourceAccess.value`. */
  value?: string;
}

/**
 * `/servicePrincipals`. `signInActivity` is joined in from
 * `/reports/servicePrincipalSignInActivity` (beta) — absent means "unknown",
 * which analyzers must not read as "unused".
 */
export interface ServicePrincipalRecord {
  id: string;
  appId: string;
  displayName?: string;
  /** `Application` | `ManagedIdentity` | `Legacy` | `SocialIdp`. */
  servicePrincipalType?: string;
  accountEnabled?: boolean;
  /** Home tenant of the app. Differs from `tenantId` for third-party apps. */
  appOwnerOrganizationId?: string;
  signInAudience?: string;
  tags?: string[];
  passwordCredentials?: GraphPasswordCredential[];
  keyCredentials?: GraphKeyCredential[];
  appRoleAssignments?: GraphAppRoleAssignment[];
  signInActivity?: {
    lastSignInDateTime?: string;
  };
}

/** `/roleManagement/directory/roleDefinitions`. */
export interface RoleDefinition {
  id: string;
  displayName?: string;
  /**
   * Stable across tenants for built-in roles (Global Administrator is always
   * `62e90394-69f5-4237-9190-012177145e10`). This — not `id` — is what
   * conditional-access `includeRoles` refers to.
   */
  templateId?: string;
  isBuiltIn?: boolean;
  isEnabled?: boolean;
  description?: string;
}

/**
 * `/roleManagement/directory/roleAssignments` — an *active* assignment. A
 * permanent assignment and a currently-activated PIM assignment look identical
 * here; the eligibility schedules below are what tell them apart.
 */
export interface RoleAssignment {
  id: string;
  principalId: string;
  roleDefinitionId: string;
  /** `/` = tenant-wide, `/administrativeUnits/{id}` = scoped. */
  directoryScopeId?: string;
}

/**
 * `/roleManagement/directory/roleEligibilitySchedules` — PIM eligibility. The
 * presence of an eligibility for (principal, role) is how we decide an active
 * assignment is just-in-time rather than standing.
 */
export interface RoleEligibilitySchedule {
  id: string;
  principalId: string;
  roleDefinitionId: string;
  directoryScopeId?: string;
  /** `Direct` | `Group` | `Inherited`. */
  memberType?: string;
  /** `Provisioned` | `Revoked` | … — only provisioned schedules are live. */
  status?: string;
  scheduleInfo?: {
    startDateTime?: string;
    expiration?: { type?: string; endDateTime?: string; duration?: string };
  };
}

// ── conditional access ──

/**
 * `enabled` | `disabled` | `enabledForReportingButNotEnforced` (report-only).
 * Report-only policies produce sign-in log entries but never block anything.
 */
export type ConditionalAccessState =
  | "enabled"
  | "disabled"
  | "enabledForReportingButNotEnforced";

/**
 * `conditions.users`. Ids are object ids except for the reserved literals
 * `All`, `None`, `GuestsOrExternalUsers`. `includeRoles`/`excludeRoles` carry
 * role *template* ids.
 */
export interface ConditionalAccessUsers {
  includeUsers?: string[];
  excludeUsers?: string[];
  includeGroups?: string[];
  excludeGroups?: string[];
  includeRoles?: string[];
  excludeRoles?: string[];
}

/** `conditions.applications`. Reserved literals: `All`, `None`, `Office365`. */
export interface ConditionalAccessApplications {
  includeApplications?: string[];
  excludeApplications?: string[];
  includeUserActions?: string[];
}

/**
 * `all` | `browser` | `mobileAppsAndDesktopClients` | `exchangeActiveSync` |
 * `other`. The last two are the legacy-authentication surface.
 */
export type ConditionalAccessClientAppType =
  | "all"
  | "browser"
  | "mobileAppsAndDesktopClients"
  | "exchangeActiveSync"
  | "other";

export interface ConditionalAccessConditions {
  users?: ConditionalAccessUsers;
  applications?: ConditionalAccessApplications;
  clientAppTypes?: ConditionalAccessClientAppType[];
  platforms?: { includePlatforms?: string[]; excludePlatforms?: string[] };
  locations?: { includeLocations?: string[]; excludeLocations?: string[] };
  signInRiskLevels?: string[];
  userRiskLevels?: string[];
}

/**
 * `grantControls`. `builtInControls` values seen in v1.0: `block`, `mfa`,
 * `compliantDevice`, `domainJoinedDevice`, `approvedApplication`,
 * `compliantApplication`, `passwordChange`. A policy can instead point at an
 * `authenticationStrength`, which supersedes the coarse `mfa` control.
 */
export interface ConditionalAccessGrantControls {
  operator?: "AND" | "OR";
  builtInControls?: string[];
  customAuthenticationFactors?: string[];
  termsOfUse?: string[];
  authenticationStrength?: { id?: string; displayName?: string };
}

export interface ConditionalAccessSessionControls {
  signInFrequency?: { isEnabled?: boolean; type?: string; value?: number };
  persistentBrowser?: { isEnabled?: boolean; mode?: string };
  applicationEnforcedRestrictions?: { isEnabled?: boolean };
  cloudAppSecurity?: { isEnabled?: boolean; cloudAppSecurityType?: string };
}

/** `/identity/conditionalAccess/policies`. */
export interface ConditionalAccessPolicy {
  id: string;
  displayName?: string;
  state: ConditionalAccessState;
  createdDateTime?: string;
  modifiedDateTime?: string;
  conditions?: ConditionalAccessConditions;
  grantControls?: ConditionalAccessGrantControls;
  sessionControls?: ConditionalAccessSessionControls;
}

// ── federation ──

/** `/domains`. `id` is the domain name itself, which is also its Graph key. */
export interface FederatedDomain {
  id: string;
  /** `Managed` (cloud auth) | `Federated` (external IdP). */
  authenticationType?: string;
  isDefault?: boolean;
  isInitial?: boolean;
  isVerified?: boolean;
  supportedServices?: string[];
  passwordValidityPeriodInDays?: number;
  /** Joined from `/domains/{id}/federationConfiguration` when federated. */
  federationConfiguration?: DomainFederationSettings;
}

/**
 * `/domains/{id}/federationConfiguration` (`internalDomainFederation`).
 *
 * `federatedIdpMfaBehavior` is the one that matters most: the historical
 * default `acceptIfMfaDoneByFederatedIdp` lets an attacker who controls the
 * federated IdP (or a stolen token-signing key) assert MFA to Entra without
 * ever performing it. Microsoft's guidance is `enforceMfaByFederatedIdp`.
 */
export interface DomainFederationSettings {
  id?: string;
  displayName?: string;
  issuerUri?: string;
  metadataExchangeUri?: string;
  passiveSignInUri?: string;
  activeSignInUri?: string;
  signOutUri?: string;
  preferredAuthenticationProtocol?: string;
  signingCertificate?: string;
  nextSigningCertificate?: string;
  /**
   * `acceptIfMfaDoneByFederatedIdp` | `enforceMfaByFederatedIdp` |
   * `rejectMfaByFederatedIdp`.
   */
  federatedIdpMfaBehavior?: string;
  isSignedAuthenticationRequestRequired?: boolean;
  promptLoginBehavior?: string;
  signingCertificateUpdateStatus?: {
    /** `success` | `failed` | … */
    certificateUpdateResult?: string;
    lastRunDateTime?: string;
  };
}

/** Tenant-level federation posture, assembled from `/domains` + `/organization`. */
export interface FederationConfig {
  domains: FederatedDomain[];
  /** `organization.onPremisesSyncEnabled` — Entra Connect is provisioning here. */
  directorySyncEnabled?: boolean;
}

// ── directory relationships ──
//
// The collections below are what turn a flat posture snapshot into a graph.
// They are optional and collected only when the caller asks for them
// (`CollectSnapshotOptions.includeDirectoryRelationships`), because every one of
// them is a per-object fan-out against Graph: reading them on a large tenant
// costs hundreds of extra GETs that the 27 posture checks do not need.

/**
 * What a membership or ownership row points at. Wider than
 * {@link IdentityPrincipalType} by exactly one arm: a device can be a group
 * member and a device can have a registered owner, but a device is never the
 * subject of a posture finding, so it has no place in the finding vocabulary.
 */
export type DirectoryPrincipalType = IdentityPrincipalType | "device";

/** `/groups/{id}/members` — one row per (group, member) pair. */
export interface DirectoryMembership {
  groupId: string;
  memberId: string;
  /** Resolved from the member's `@odata.type` when Graph reported one. */
  memberType?: DirectoryPrincipalType;
  memberDisplayName?: string;
}

/**
 * `/{collection}/{id}/owners` — one row per (object, owner) pair. Ownership is
 * a control edge in Entra: an application owner can add credentials to the app,
 * a group owner can add members to the group.
 */
export interface DirectoryOwnership {
  /** Object id of the owned application, service principal, group, or device. */
  objectId: string;
  ownerId: string;
  ownerType?: DirectoryPrincipalType;
  ownerDisplayName?: string;
}

/** `/devices`. Collected for completeness of the directory graph. */
export interface TenantDevice {
  id: string;
  displayName?: string;
  /** The device's own GUID, distinct from the directory object id. */
  deviceId?: string;
  operatingSystem?: string;
  /** `AzureAd` | `ServerAd` | `Workplace`. */
  trustType?: string;
  isCompliant?: boolean;
  isManaged?: boolean;
  accountEnabled?: boolean;
}

/**
 * `/directory/administrativeUnits`. An AU scopes a role assignment to a subset
 * of the directory, so an AU-scoped admin is emphatically *not* a tenant-wide
 * one — the graph builder keeps the two apart.
 */
export interface AdministrativeUnitRecord {
  id: string;
  displayName?: string;
  description?: string;
  isMemberManagementRestricted?: boolean;
  /** Joined from `/directory/administrativeUnits/{id}/members`. */
  memberIds?: string[];
}

/** Everything the graph builder needs beyond the posture snapshot itself. */
export interface TenantRelationships {
  groupMembers: DirectoryMembership[];
  groupOwners: DirectoryOwnership[];
  applicationOwners: DirectoryOwnership[];
  servicePrincipalOwners: DirectoryOwnership[];
  devices: TenantDevice[];
  deviceOwners: DirectoryOwnership[];
  administrativeUnits: AdministrativeUnitRecord[];
}

// ── snapshot ──

/**
 * Everything an assessment reads, captured once. Analyzers are pure functions
 * of this object — no network, no clock beyond an injected `now` — which is
 * what makes each check independently testable against a fixture.
 *
 * `roleDefinitions` and `roleEligibilitySchedules` are carried alongside the
 * assignments because a role assignment on its own says neither *which* role
 * it is (only a definition id) nor whether it is standing or just-in-time.
 */
export interface TenantSnapshot {
  tenantId: string;
  tenantDisplayName?: string;
  collectedAt: string;
  users: TenantUser[];
  groups: TenantGroup[];
  servicePrincipals: ServicePrincipalRecord[];
  appRegistrations: AppRegistration[];
  roleDefinitions: RoleDefinition[];
  roleAssignments: RoleAssignment[];
  roleEligibilitySchedules: RoleEligibilitySchedule[];
  conditionalAccessPolicies: ConditionalAccessPolicy[];
  federationConfig: FederationConfig;
  /**
   * Membership, ownership, device and administrative-unit edges. Absent unless
   * the caller asked for them; the 27 posture checks never read this field, so
   * a snapshot without it is still a complete input for `runAllAnalyzers`.
   * `buildEntraGraph` treats absent as "no relationships collected" and says so
   * in the graph metadata rather than reporting an empty directory.
   */
  relationships?: TenantRelationships;
  /**
   * Collections the token could not read (missing scope, throttled, endpoint
   * unavailable). Non-empty means the snapshot is partial and absent findings
   * are not evidence of a clean tenant.
   */
  warnings: string[];
}

// ── result ──

export interface IdentitySnapshotMetadata {
  collectedAt: string;
  /** True when any collection step failed; see `warnings`. */
  partial: boolean;
  counts: {
    users: number;
    groups: number;
    servicePrincipals: number;
    appRegistrations: number;
    roleAssignments: number;
    roleEligibilitySchedules: number;
    conditionalAccessPolicies: number;
    domains: number;
  };
  warnings: string[];
}

export interface IdentityAssessmentSummary {
  total: number;
  bySeverity: Record<IdentitySeverity, number>;
  byCategory: Record<IdentityFindingCategory, number>;
}

export interface IdentityAssessmentResult {
  tenantId: string;
  tenantDisplayName?: string;
  generatedAt: string;
  /** Wall-clock ms for collection + analysis. */
  durationMs: number;
  /** Wall-clock ms spent in Graph collection alone. */
  collectionMs: number;
  findings: IdentityFinding[];
  summary: IdentityAssessmentSummary;
  snapshot: IdentitySnapshotMetadata;
}
