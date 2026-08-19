// Cloud identity assessment — Microsoft Entra ID (Azure AD).
//
// Read-only posture assessment of a tenant's identity plane: privileged role
// assignments, conditional-access coverage, app registrations, service
// principals, and federated-domain trust.
//
// The pipeline is deliberately split so the expensive, non-deterministic half
// and the interesting, deterministic half can be exercised independently:
//
//   GraphClient  →  collectTenantSnapshot  →  analyzers  →  IdentityAssessmentResult
//   (injectable      (fault-tolerant,          (pure)        (findings + metadata)
//    fetch)           per-collection warnings)
//
// Authorization reuses the engagement-wide `ScopePolicy` from `../scope/` —
// there is one scope model in this codebase and this module does not add a
// second one. Pass a policy and `graph.microsoft.com` must be explicitly in
// scope before a single request goes out.

import type { ScopePolicy } from "../scope/scope.js";
import {
  collectTenantSnapshot,
  GraphClient,
  type CollectSnapshotOptions,
  type GraphFetch,
} from "./graph-client.js";
import { runAllAnalyzers, sortFindings, summarizeFindings, type IdentityAnalyzerOptions } from "./analyzers.js";
import type { IdentityAssessmentResult, TenantSnapshot } from "./types.js";

export type {
  AffectedPrincipal,
  AppRegistration,
  ConditionalAccessApplications,
  ConditionalAccessClientAppType,
  ConditionalAccessConditions,
  ConditionalAccessGrantControls,
  ConditionalAccessPolicy,
  ConditionalAccessSessionControls,
  ConditionalAccessState,
  ConditionalAccessUsers,
  DomainFederationSettings,
  FederatedDomain,
  FederationConfig,
  GraphAppRoleAssignment,
  GraphKeyCredential,
  GraphPasswordCredential,
  GraphRequiredResourceAccess,
  GraphResourceAccess,
  IdentityAssessmentResult,
  IdentityAssessmentSummary,
  IdentityCheck,
  IdentityEvidence,
  IdentityFinding,
  IdentityFindingCategory,
  IdentityPrincipalType,
  IdentitySeverity,
  IdentitySnapshotMetadata,
  RoleAssignment,
  RoleDefinition,
  RoleEligibilitySchedule,
  ServicePrincipalRecord,
  TenantGroup,
  TenantSnapshot,
  TenantUser,
} from "./types.js";

export {
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
// `parseRetryAfter` is intentionally NOT re-exported here: `@pwnkit/core`
// already exports the HackerOne client's function of that name, and a star
// re-export would be silently shadowed by it. Import it from
// `./identity/graph-client.js` directly when you need the Graph variant.
export type {
  CollectSnapshotOptions,
  GraphClientOptions,
  GraphCollection,
  GraphFetch,
  GraphQuery,
} from "./graph-client.js";

export {
  analyzeAppRegistrations,
  analyzeConditionalAccess,
  analyzeFederation,
  analyzePrivilegedRoles,
  analyzeServicePrincipals,
  GRAPH_APP_ROLE_CATALOG,
  HIGH_IMPACT_GRAPH_PERMISSIONS,
  IDENTITY_CHECKS,
  PRIVILEGED_ROLE_TEMPLATE_IDS,
  ROLE_TEMPLATE_IDS,
  runAllAnalyzers,
  sortFindings,
  summarizeFindings,
  TIER0_GRAPH_PERMISSIONS,
  TIER0_ROLE_TEMPLATE_IDS,
} from "./analyzers.js";
export type {
  AppRegistrationOptions,
  ConditionalAccessOptions,
  IdentityAnalyzerOptions,
  PrivilegedRoleOptions,
  ServicePrincipalOptions,
} from "./analyzers.js";

// Token / assertion analysis. Offline by construction — see `tokens.ts`. These
// are deliberately NOT part of `runIdentityAssessment`: they analyse material
// the operator supplies rather than anything the Graph collector reads.
export {
  analyzeJwt,
  analyzeSamlAssertion,
  analyzeToken,
  classifyEntraToken,
  decodeJwtUnverified,
  MSA_TENANT_ID,
  PUBLIC_CLIENT_APP_IDS,
  redactTokenValue,
  TOKEN_CHECKS,
  tokenFingerprint,
} from "./tokens.js";
export type {
  DecodedJwt,
  JwtDecodeResult,
  TokenAnalysisOptions,
} from "./tokens.js";
// `./xml.ts` is deliberately NOT re-exported. It is the narrow structural
// reader the SAML checks are built on, not a general-purpose XML parser, and
// putting names like `parseXml` on the `@pwnkit/core` surface would invite it
// to be used as one. Import it directly from `./identity/xml.js` if you are
// working inside this module.

// Attack-path analysis. The posture checks above answer "what is
// misconfigured"; this answers "what can be reached, and how". Same split as
// `../adgraph/` for on-premises AD. Both input routes are offline analysis —
// neither builds nor traverses a graph over the network.
export * from "./entra-graph/index.js";

// The seam between the two. `../adgraph/` and `./entra-graph/` each stop at the
// synchronisation boundary; this joins their graphs and computes the paths that
// cross it — the ones neither single-directory assessment can structurally find.
// Offline like both of its inputs: it re-keys two in-memory graphs and compares
// attributes already present on them.
export * from "./hybrid/index.js";

export interface IdentityAssessmentOptions {
  /**
   * OAuth2 bearer token with directory read scopes. Ignored when `client` or
   * `snapshot` is supplied.
   */
  accessToken?: string;
  /** Pre-built client. Takes precedence over `accessToken`. */
  client?: GraphClient;
  /**
   * Skip collection entirely and analyze an already-captured snapshot. Lets a
   * stored snapshot be re-scored against updated checks without re-reading the
   * tenant.
   */
  snapshot?: TenantSnapshot;
  /** Engagement scope. `graph.microsoft.com` must be in scope when supplied. */
  scope?: ScopePolicy;
  /** Injectable fetch, used when this function builds the client itself. */
  fetchImpl?: GraphFetch;
  /** Graph base URL override. Default `https://graph.microsoft.com/v1.0`. */
  baseUrl?: string;
  /** Collection tuning (fan-out caps, beta sign-in activity). */
  collect?: CollectSnapshotOptions;
  /** Per-check thresholds (admin ceilings, credential lifetimes, break-glass). */
  analyzers?: IdentityAnalyzerOptions;
  /** Injected clock. Drives timestamps, durations, and every relative check. */
  now?: () => Date;
}

/**
 * Collect a tenant snapshot and run every analyzer over it.
 *
 * Collection is fault-tolerant by design: a token missing one scope produces a
 * partial snapshot plus warnings rather than a failed assessment. That partial
 * state is surfaced on `result.snapshot.partial` — an empty finding list from a
 * partial snapshot is not evidence of a healthy tenant, and any consumer that
 * renders these results has to say so.
 */
export async function runIdentityAssessment(
  opts: IdentityAssessmentOptions,
): Promise<IdentityAssessmentResult> {
  const now = opts.now ?? (() => new Date());
  const startedAt = now().getTime();

  const snapshot = opts.snapshot ?? (await collectTenantSnapshot(resolveClient(opts), {
    now,
    ...opts.collect,
  }));
  const collectedAt = now().getTime();

  // `now` reaches the analyzers as a Date because every relative check (idle
  // service principals, stalled report-only policies, credential lifetimes)
  // must be reproducible against a fixture.
  const findings = sortFindings(
    runAllAnalyzers(snapshot, { now: now(), ...opts.analyzers }),
  );
  const finishedAt = now().getTime();

  return {
    tenantId: snapshot.tenantId,
    tenantDisplayName: snapshot.tenantDisplayName,
    generatedAt: new Date(finishedAt).toISOString(),
    durationMs: finishedAt - startedAt,
    collectionMs: opts.snapshot ? 0 : collectedAt - startedAt,
    findings,
    summary: summarizeFindings(findings),
    snapshot: {
      collectedAt: snapshot.collectedAt,
      partial: snapshot.warnings.length > 0,
      counts: {
        users: snapshot.users.length,
        groups: snapshot.groups.length,
        servicePrincipals: snapshot.servicePrincipals.length,
        appRegistrations: snapshot.appRegistrations.length,
        roleAssignments: snapshot.roleAssignments.length,
        roleEligibilitySchedules: snapshot.roleEligibilitySchedules.length,
        conditionalAccessPolicies: snapshot.conditionalAccessPolicies.length,
        domains: snapshot.federationConfig.domains.length,
      },
      warnings: snapshot.warnings,
    },
  };
}

function resolveClient(opts: IdentityAssessmentOptions): GraphClient {
  if (opts.client) return opts.client;
  if (!opts.accessToken) {
    throw new Error(
      "runIdentityAssessment requires one of: `snapshot`, `client`, or `accessToken`.",
    );
  }
  return new GraphClient({
    accessToken: opts.accessToken,
    baseUrl: opts.baseUrl,
    fetchImpl: opts.fetchImpl,
    scope: opts.scope,
  });
}
