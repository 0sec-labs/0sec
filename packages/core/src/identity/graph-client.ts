// Microsoft Graph read-only client + tenant snapshot collector.
//
// Deliberately narrow, in the same spirit as `h1/client.ts`: this is the Graph
// client, not a generic "cloud API" client. It does exactly four things —
// authenticated GET, `@odata.nextLink` pagination, 429/5xx retry that honours
// `Retry-After`, and typed errors.
//
// READ-ONLY IS STRUCTURAL, NOT A CONVENTION. There is no method parameter
// anywhere in this file; every request literally hard-codes `method: "GET"`.
// Adding a write path would mean adding a new public method, which is the sort
// of thing a reviewer notices. An identity assessment must never be able to
// mutate the tenant it is assessing.
//
// SECURITY:
//   - Every URL is pinned to the configured Graph origin before it is fetched.
//     `@odata.nextLink` is server-controlled data; following it blindly would
//     let a compromised or spoofed response walk our bearer token off to
//     another host. Same check applies to the initial URL.
//   - When a `ScopePolicy` is supplied (`--scope`), every URL also passes the
//     normal engagement scope gate. Same policy object the rest of the agent
//     uses — there is exactly one scope model in this codebase.
//   - The access token is never echoed into an error message. Network-layer
//     messages are scrubbed of the literal token as defence-in-depth.

import type { ScopePolicy } from "../scope/scope.js";
import type {
  AppRegistration,
  ConditionalAccessPolicy,
  DomainFederationSettings,
  FederatedDomain,
  GraphAppRoleAssignment,
  RoleAssignment,
  RoleDefinition,
  RoleEligibilitySchedule,
  ServicePrincipalRecord,
  TenantGroup,
  TenantSnapshot,
  TenantUser,
} from "./types.js";

const DEFAULT_BASE_URL = "https://graph.microsoft.com/v1.0";
const DEFAULT_BETA_BASE_URL = "https://graph.microsoft.com/beta";
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_MAX_RETRY_DELAY_MS = 60_000;
const DEFAULT_PAGE_DELAY_MS = 0;
const DEFAULT_MAX_PAGES = 200;
/** Per-SP `appRoleAssignments` is an N+1 fan-out; cap it and warn on truncation. */
const DEFAULT_APP_ROLE_ASSIGNMENT_LIMIT = 250;

/** Microsoft Graph's own `appId` — the resource most permissions hang off. */
export const MICROSOFT_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000";

export class GraphError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly path?: string,
  ) {
    super(message);
    this.name = "GraphError";
  }
}

export class GraphAuthError extends GraphError {
  constructor(path: string) {
    super(`Graph auth failed (HTTP 401) on ${path}. Access token missing, expired, or wrong audience.`, 401, path);
    this.name = "GraphAuthError";
  }
}

export class GraphForbiddenError extends GraphError {
  constructor(path: string) {
    super(`Graph forbidden (HTTP 403) on ${path}. Token lacks the required directory read scope.`, 403, path);
    this.name = "GraphForbiddenError";
  }
}

export class GraphRateLimitError extends GraphError {
  constructor(path: string, readonly retryAfterSec: number) {
    super(`Graph rate limited (HTTP 429) on ${path} after exhausting retries. Retry-After=${retryAfterSec}s.`, 429, path);
    this.name = "GraphRateLimitError";
  }
}

export class GraphNetworkError extends GraphError {
  constructor(message: string, path: string) {
    super(`Graph network error on ${path}: ${message}`, undefined, path);
    this.name = "GraphNetworkError";
  }
}

/** Refusal to fetch a URL that failed the origin pin or the engagement scope. */
export class GraphScopeError extends GraphError {
  constructor(url: string, reason: string) {
    super(`Graph request refused for ${url}: ${reason}`, undefined, url);
    this.name = "GraphScopeError";
  }
}

export type GraphFetch = typeof fetch;

export interface GraphClientOptions {
  /** OAuth2 bearer token with directory *read* scopes. Never mutated. */
  accessToken: string;
  /** Default `https://graph.microsoft.com/v1.0`. */
  baseUrl?: string;
  /** Default `https://graph.microsoft.com/beta`. Must share the v1.0 origin. */
  betaBaseUrl?: string;
  /** Injectable fetch. Tests supply fixtures; nothing here touches the wire. */
  fetchImpl?: GraphFetch;
  /**
   * Engagement scope. When present, every Graph URL must be in scope — the
   * operator has to have authorised `graph.microsoft.com` explicitly.
   */
  scope?: ScopePolicy;
  /** Retries per request on 429/503/504. Default 3. */
  maxRetries?: number;
  /** Ceiling on a single honoured `Retry-After`. Default 60s. */
  maxRetryDelayMs?: number;
  /** Pacing delay between pages. Default 0. */
  pageDelayMs?: number;
  /** Hard stop on runaway pagination. Default 200 pages. */
  maxPages?: number;
  /** Injectable timer so tests never actually sleep. */
  sleep?: (ms: number) => Promise<void>;
  userAgent?: string;
}

/** The OData envelope every Graph collection endpoint returns. */
export interface GraphCollection<T> {
  value?: T[];
  "@odata.nextLink"?: string;
  "@odata.count"?: number;
}

export class GraphClient {
  private readonly accessToken: string;
  private readonly baseUrl: string;
  private readonly betaBaseUrl: string;
  private readonly origin: string;
  private readonly fetchImpl: GraphFetch;
  private readonly scope?: ScopePolicy;
  private readonly maxRetries: number;
  private readonly maxRetryDelayMs: number;
  private readonly pageDelayMs: number;
  private readonly maxPages: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly userAgent: string;

  constructor(opts: GraphClientOptions) {
    this.accessToken = opts.accessToken;
    this.baseUrl = stripTrailingSlash(opts.baseUrl ?? DEFAULT_BASE_URL);
    this.betaBaseUrl = stripTrailingSlash(opts.betaBaseUrl ?? deriveBetaUrl(this.baseUrl));
    this.origin = new URL(this.baseUrl).origin;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.scope = opts.scope;
    this.maxRetries = opts.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.maxRetryDelayMs = opts.maxRetryDelayMs ?? DEFAULT_MAX_RETRY_DELAY_MS;
    this.pageDelayMs = opts.pageDelayMs ?? DEFAULT_PAGE_DELAY_MS;
    this.maxPages = opts.maxPages ?? DEFAULT_MAX_PAGES;
    this.sleep = opts.sleep ?? defaultSleep;
    this.userAgent = opts.userAgent ?? "pwnkit-identity";
  }

  /** GET a v1.0-relative path (`/users`) and return the parsed body. */
  async get<T = unknown>(path: string, query?: GraphQuery): Promise<T> {
    return await this.getUrl<T>(buildUrl(this.baseUrl, path, query), path);
  }

  /** GET a beta-relative path. Only used for data v1.0 does not expose yet. */
  async getBeta<T = unknown>(path: string, query?: GraphQuery): Promise<T> {
    return await this.getUrl<T>(buildUrl(this.betaBaseUrl, path, query), path);
  }

  /**
   * GET a fully-qualified Graph URL. Used by `paginate` to follow Graph's own
   * `@odata.nextLink` rather than synthesising page URLs ourselves — skip
   * tokens are opaque and must not be reconstructed.
   */
  async getUrl<T = unknown>(url: string, displayPath?: string): Promise<T> {
    this.authorize(url);
    const path = displayPath ?? safePath(url);
    let attempt = 0;

    while (true) {
      let res: Response;
      try {
        res = await this.fetchImpl(url, {
          method: "GET",
          headers: this.headers(),
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        throw new GraphNetworkError(this.scrub(msg), path);
      }

      if (isRetryable(res.status) && attempt < this.maxRetries) {
        // Graph is explicit about back-off: it returns `Retry-After` on 429 and
        // on service-side 503/504. Honour it rather than guessing, and fall
        // back to exponential back-off only when the header is absent.
        const hinted = parseRetryAfter(res.headers.get("Retry-After"));
        const delayMs = hinted !== null
          ? Math.min(hinted * 1000, this.maxRetryDelayMs)
          : Math.min(2 ** attempt * 1000, this.maxRetryDelayMs);
        await this.sleep(delayMs);
        attempt += 1;
        continue;
      }

      this.assertOk(res, path);
      return (await res.json()) as T;
    }
  }

  /**
   * Async-generator over a collection endpoint. Yields one page of `value[]`
   * at a time; stops when Graph stops handing back an `@odata.nextLink`.
   */
  async *paginate<T>(path: string, query?: GraphQuery): AsyncGenerator<T[]> {
    let url: string | null = buildUrl(this.baseUrl, path, query);
    let page = 0;

    while (url) {
      if (page > 0 && this.pageDelayMs > 0) await this.sleep(this.pageDelayMs);
      const body: GraphCollection<T> = await this.getUrl<GraphCollection<T>>(url, path);
      yield body.value ?? [];
      page += 1;
      if (page >= this.maxPages) {
        // Loud stop rather than a silent partial result — a nextLink that never
        // terminates is either a Graph bug or a filter that needs narrowing.
        throw new GraphError(
          `Graph pagination exceeded ${this.maxPages} pages on ${path}; refusing to continue.`,
          undefined,
          path,
        );
      }
      url = body["@odata.nextLink"] ?? null;
    }
  }

  /** Drain `paginate` into a single array. The common case for collectors. */
  async collect<T>(path: string, query?: GraphQuery): Promise<T[]> {
    const out: T[] = [];
    for await (const page of this.paginate<T>(path, query)) out.push(...page);
    return out;
  }

  /** Same as `collect` but against the beta endpoint. */
  async collectBeta<T>(path: string, query?: GraphQuery): Promise<T[]> {
    const out: T[] = [];
    let url: string | null = buildUrl(this.betaBaseUrl, path, query);
    let page = 0;
    while (url) {
      if (page > 0 && this.pageDelayMs > 0) await this.sleep(this.pageDelayMs);
      const body: GraphCollection<T> = await this.getUrl<GraphCollection<T>>(url, path);
      out.push(...(body.value ?? []));
      page += 1;
      if (page >= this.maxPages) break;
      url = body["@odata.nextLink"] ?? null;
    }
    return out;
  }

  /** Map a non-2xx response to a typed error. Public so callers can reuse it. */
  assertOk(res: Response, path: string): void {
    if (res.ok) return;
    if (res.status === 401) throw new GraphAuthError(path);
    if (res.status === 403) throw new GraphForbiddenError(path);
    if (res.status === 429) {
      throw new GraphRateLimitError(path, parseRetryAfter(res.headers.get("Retry-After")) ?? 0);
    }
    throw new GraphError(`Graph request failed (HTTP ${res.status}) on ${path}.`, res.status, path);
  }

  // ── internals ──

  /**
   * Origin pin + engagement scope. Runs before *every* fetch, including
   * server-supplied nextLinks.
   */
  private authorize(url: string): void {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new GraphScopeError(url, "not a valid absolute URL");
    }
    if (parsed.origin !== this.origin) {
      throw new GraphScopeError(url, `origin '${parsed.origin}' is not the configured Graph origin '${this.origin}'`);
    }
    if (this.scope) {
      const match = this.scope.match(url);
      if (!match.allowed) throw new GraphScopeError(url, match.reason);
    }
  }

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.accessToken}`,
      Accept: "application/json",
      "User-Agent": this.userAgent,
      // Graph only returns `signInActivity` and a few other advanced properties
      // when the request is flagged as eventual-consistency capable.
      ConsistencyLevel: "eventual",
    };
  }

  private scrub(s: string): string {
    if (!this.accessToken) return s;
    return s.split(this.accessToken).join("[REDACTED]");
  }
}

// ── snapshot collection ──

export interface CollectSnapshotOptions {
  /** Cap on per-SP `appRoleAssignments` fan-out. Default 250. */
  appRoleAssignmentLimit?: number;
  /**
   * Fetch service-principal sign-in activity from the beta endpoint. Needed by
   * the unused-privileged-SP check; off by default because beta endpoints are
   * not contractually stable.
   */
  includeServicePrincipalSignInActivity?: boolean;
  /** Injected clock for `collectedAt`. */
  now?: () => Date;
}

/**
 * Read an entire tenant into a `TenantSnapshot`.
 *
 * Each collection step is independently fault-tolerant: a token that can read
 * users but not conditional-access policies yields a snapshot with users and a
 * warning, not a hard failure. Analyzers see the warning list through
 * `snapshot.warnings` so a partial run can never be reported as a clean tenant.
 */
export async function collectTenantSnapshot(
  client: GraphClient,
  opts: CollectSnapshotOptions = {},
): Promise<TenantSnapshot> {
  const now = opts.now ?? (() => new Date());
  const warnings: string[] = [];
  const limit = opts.appRoleAssignmentLimit ?? DEFAULT_APP_ROLE_ASSIGNMENT_LIMIT;

  const org = await step(warnings, "organization", async () =>
    await client.collect<{ id?: string; displayName?: string; onPremisesSyncEnabled?: boolean }>("/organization"),
  ) ?? [];

  const users = await step(warnings, "users", async () =>
    await client.collect<TenantUser>("/users", {
      $select:
        "id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,onPremisesSyncEnabled," +
        "onPremisesImmutableId,onPremisesSecurityIdentifier,onPremisesDistinguishedName,onPremisesSamAccountName," +
        "onPremisesDomainName,signInActivity",
      $top: 999,
    }),
  ) ?? [];

  // MFA registration state is a separate report resource keyed on the user's
  // object id — it is not a property of the user itself.
  const registration = await step(warnings, "authenticationMethods/userRegistrationDetails", async () =>
    await client.collect<{ id?: string; isMfaRegistered?: boolean; isMfaCapable?: boolean }>(
      "/reports/authenticationMethods/userRegistrationDetails",
    ),
  ) ?? [];
  const registrationById = new Map(registration.filter((r) => r.id).map((r) => [r.id as string, r]));
  for (const user of users) {
    const detail = registrationById.get(user.id);
    if (!detail) continue;
    user.isMfaRegistered = detail.isMfaRegistered;
    user.isMfaCapable = detail.isMfaCapable;
  }

  const groups = await step(warnings, "groups", async () =>
    await client.collect<TenantGroup>("/groups", {
      $select:
        "id,displayName,description,mailEnabled,securityEnabled,groupTypes,membershipRule,isAssignableToRole," +
        "visibility,onPremisesSyncEnabled,onPremisesSecurityIdentifier,onPremisesDistinguishedName," +
        "onPremisesSamAccountName,createdDateTime",
      $top: 999,
    }),
  ) ?? [];

  const servicePrincipals = await step(warnings, "servicePrincipals", async () =>
    await client.collect<ServicePrincipalRecord>("/servicePrincipals", {
      $select:
        "id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,signInAudience,tags,passwordCredentials,keyCredentials",
      $top: 999,
    }),
  ) ?? [];

  const appRegistrations = await step(warnings, "applications", async () =>
    await client.collect<AppRegistration>("/applications", {
      $select:
        "id,appId,displayName,signInAudience,createdDateTime,publisherDomain,verifiedPublisher,passwordCredentials,keyCredentials,requiredResourceAccess,web",
      $top: 999,
    }),
  ) ?? [];

  const roleDefinitions = await step(warnings, "roleManagement/directory/roleDefinitions", async () =>
    await client.collect<RoleDefinition>("/roleManagement/directory/roleDefinitions"),
  ) ?? [];

  const roleAssignments = await step(warnings, "roleManagement/directory/roleAssignments", async () =>
    await client.collect<RoleAssignment>("/roleManagement/directory/roleAssignments"),
  ) ?? [];

  const roleEligibilitySchedules = await step(
    warnings,
    "roleManagement/directory/roleEligibilitySchedules",
    async () =>
      await client.collect<RoleEligibilitySchedule>("/roleManagement/directory/roleEligibilitySchedules"),
  ) ?? [];

  const conditionalAccessPolicies = await step(warnings, "identity/conditionalAccess/policies", async () =>
    await client.collect<ConditionalAccessPolicy>("/identity/conditionalAccess/policies"),
  ) ?? [];

  const domains = await step(warnings, "domains", async () =>
    await client.collect<FederatedDomain>("/domains"),
  ) ?? [];

  // Federation settings are a per-domain sub-resource and only exist for
  // federated domains, so managed domains are skipped rather than 404'd.
  for (const domain of domains) {
    if ((domain.authenticationType ?? "").toLowerCase() !== "federated") continue;
    const settings = await step(warnings, `domains/${domain.id}/federationConfiguration`, async () =>
      await client.collect<DomainFederationSettings>(
        `/domains/${encodeURIComponent(domain.id)}/federationConfiguration`,
      ),
    );
    if (settings && settings.length > 0) domain.federationConfiguration = settings[0];
  }

  // Resolve permission GUIDs to names off the Microsoft Graph service principal
  // in *this* tenant. Static GUID tables rot; the tenant's own copy of the
  // resource app is authoritative. Analyzers fall back to their catalog when
  // this lookup is unavailable.
  const permissionNames = await resolveGraphPermissionNames(client, servicePrincipals, warnings);
  for (const app of appRegistrations) {
    for (const required of app.requiredResourceAccess ?? []) {
      for (const access of required.resourceAccess ?? []) {
        access.value ??= permissionNames.get(access.id);
      }
    }
  }

  // App role *grants* are a per-SP sub-resource. This is the N+1 in the
  // collector; cap the fan-out and record truncation as a warning so a large
  // tenant degrades visibly rather than silently.
  const spTargets = servicePrincipals.slice(0, limit);
  if (servicePrincipals.length > limit) {
    warnings.push(
      `appRoleAssignments truncated: read ${limit} of ${servicePrincipals.length} service principals`,
    );
  }
  for (const sp of spTargets) {
    const grants = await step(warnings, `servicePrincipals/${sp.id}/appRoleAssignments`, async () =>
      await client.collect<GraphAppRoleAssignment>(`/servicePrincipals/${encodeURIComponent(sp.id)}/appRoleAssignments`),
    );
    if (!grants) continue;
    for (const grant of grants) grant.value ??= permissionNames.get(grant.appRoleId);
    sp.appRoleAssignments = grants;
  }

  if (opts.includeServicePrincipalSignInActivity) {
    const activity = await step(warnings, "reports/servicePrincipalSignInActivities", async () =>
      await client.collectBeta<{ appId?: string; lastSignInActivity?: { lastSignInDateTime?: string } }>(
        "/reports/servicePrincipalSignInActivities",
      ),
    );
    if (activity) {
      const byAppId = new Map(activity.filter((a) => a.appId).map((a) => [a.appId as string, a]));
      for (const sp of servicePrincipals) {
        const hit = byAppId.get(sp.appId);
        if (hit?.lastSignInActivity) {
          sp.signInActivity = { lastSignInDateTime: hit.lastSignInActivity.lastSignInDateTime };
        }
      }
    }
  }

  return {
    tenantId: org[0]?.id ?? "unknown",
    tenantDisplayName: org[0]?.displayName,
    collectedAt: now().toISOString(),
    users,
    groups,
    servicePrincipals,
    appRegistrations,
    roleDefinitions,
    roleAssignments,
    roleEligibilitySchedules,
    conditionalAccessPolicies,
    federationConfig: {
      domains,
      directorySyncEnabled: org[0]?.onPremisesSyncEnabled,
    },
    warnings,
  };
}

/**
 * Build a GUID → permission-name map from the Microsoft Graph service
 * principal's own `appRoles` and `oauth2PermissionScopes`.
 */
async function resolveGraphPermissionNames(
  client: GraphClient,
  servicePrincipals: ServicePrincipalRecord[],
  warnings: string[],
): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  const graphSp = servicePrincipals.find((sp) => sp.appId === MICROSOFT_GRAPH_APP_ID);
  const objectId = graphSp?.id;
  const body = await step(warnings, "servicePrincipals (Microsoft Graph appRoles)", async () => {
    if (objectId) {
      return await client.get<{
        appRoles?: Array<{ id?: string; value?: string }>;
        oauth2PermissionScopes?: Array<{ id?: string; value?: string }>;
      }>(`/servicePrincipals/${encodeURIComponent(objectId)}`, {
        $select: "appRoles,oauth2PermissionScopes",
      });
    }
    const found = await client.collect<{
      appRoles?: Array<{ id?: string; value?: string }>;
      oauth2PermissionScopes?: Array<{ id?: string; value?: string }>;
    }>("/servicePrincipals", { $filter: `appId eq '${MICROSOFT_GRAPH_APP_ID}'` });
    return found[0];
  });
  if (!body) return map;
  for (const entry of [...(body.appRoles ?? []), ...(body.oauth2PermissionScopes ?? [])]) {
    if (entry.id && entry.value) map.set(entry.id, entry.value);
  }
  return map;
}

/**
 * Run one collection step, converting a failure into a warning and `undefined`.
 * Keeps a missing scope from aborting the entire assessment.
 */
async function step<T>(
  warnings: string[],
  label: string,
  fn: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await fn();
  } catch (err) {
    warnings.push(`${label}: ${err instanceof Error ? err.message : String(err)}`);
    return undefined;
  }
}

// ── url helpers ──

export type GraphQuery = Record<string, string | number | undefined>;

function buildUrl(baseUrl: string, path: string, query?: GraphQuery): string {
  const url = new URL(baseUrl + (path.startsWith("/") ? path : `/${path}`));
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value === undefined) continue;
    url.searchParams.set(key, String(value));
  }
  return url.toString();
}

function stripTrailingSlash(url: string): string {
  return url.endsWith("/") ? url.slice(0, -1) : url;
}

function deriveBetaUrl(baseUrl: string): string {
  return baseUrl.endsWith("/v1.0") ? `${baseUrl.slice(0, -"/v1.0".length)}/beta` : DEFAULT_BETA_BASE_URL;
}

/** Path for error messages — never the query string, which can carry filters. */
function safePath(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

function isRetryable(status: number): boolean {
  return status === 429 || status === 503 || status === 504;
}

/**
 * `Retry-After` is delta-seconds in every Graph throttling response we have
 * seen. Returns `null` when the header is absent or unparseable so the caller
 * can distinguish "server told us to wait N" from "we picked a back-off".
 */
export function parseRetryAfter(header: string | null): number | null {
  if (!header) return null;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const asDate = Date.parse(header);
  if (Number.isFinite(asDate)) return Math.max(0, Math.round((asDate - Date.now()) / 1000));
  return null;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
