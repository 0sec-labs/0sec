// Bearer-authenticated 0sec client for health, hosted model catalog,
// inference balance, and request usage. Provider keys stay on the service.
//
// SECURITY:
//   - The Authorization header value is built from the token but never
//     emitted back to the caller. Errors include status + path + host,
//     never headers or the token itself.
//   - `User-Agent` includes `0sec-cli/<version>` so server-side ops can
//     identify CLI traffic if it looks anomalous.

import { VERSION } from "@0sec/shared";

export class CloudError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly path?: string,
  ) {
    super(message);
    this.name = "CloudError";
  }
}

/** 401 — token rejected. Distinct from CloudAuthMissingError, which means no token was configured. */
export class CloudUnauthorizedError extends CloudError {
  constructor(path: string) {
    super(`0sec-cloud auth rejected (HTTP 401) on ${path}. Run \`0sec auth login\` to refresh.`, 401, path);
    this.name = "CloudUnauthorizedError";
  }
}
export class CloudForbiddenError extends CloudError {
  constructor(path: string) {
    super(
      `0sec-cloud forbidden (HTTP 403) on ${path}. Token lacks scope for this resource.`,
      403,
      path,
    );
    this.name = "CloudForbiddenError";
  }
}
export class CloudNetworkError extends CloudError {
  constructor(message: string, path: string) {
    super(`0sec-cloud network error on ${path}: ${message}`, undefined, path);
    this.name = "CloudNetworkError";
  }
}

export type FetchImpl = typeof fetch;

export interface CloudClientOptions {
  host: string;
  token: string;
  fetchImpl?: FetchImpl;
}

/** Shape of a `/health` response. Kept loose on purpose: the server may
 *  add fields, and we only commit to `status` for this PR. zod schemas
 *  arrive when real endpoints land. */
export interface CloudHealthResponse {
  status: string;
}

// ── HostedAllowanceOverview — supplier-cost-based allowance ────────────────
//
// Public DTO from the inference-billing producer. Copied as a projection type;
// never import from the billing package. Validation is structural only — the
// server is authoritative; malformed responses fail closed as null.

/** One window in the allowance overview (monthly / weekly / five_hour). */
export interface HostedAllowanceWindow {
  id: string;
  kind: "monthly" | "weekly" | "five_hour";
  limitUsd: number;
  settledUsd: number;
  reservedUsd: number;
  unknownReservedUsd: number;
  availableUsd: number;
  remainingPercent: number;
  startsAt: string;
  endsAt: string;
  resetSemantics: "billing_period" | "utc_monday" | "first_admission";
}

/** Qualification record for a hosted model's route. */
export interface HostedAllowanceModelQualification {
  status: "unknown" | "passed" | "failed";
  evidenceRef: string | null;
  verifiedAt: string | null;
  sourceRevision: string | null;
  routeIdentity: string | null;
}

/** Readiness mirror for a hosted model. */
export interface HostedAllowanceModelReadiness {
  configured: boolean;
  entitled: boolean;
  reason: string | null;
  qualification: HostedAllowanceModelQualification;
}

/** Per-model allowance entry with pricing and estimated supplier cost. */
export interface HostedAllowanceModel {
  id: string;
  provider: string;
  upstreamModel: string;
  wireApi: string;
  endpointIdentity: string | null;
  routeIdentity: string;
  priceVersion: string;
  state: "available" | "disabled" | "unsupported";
  reason: string | null;
  qualification: HostedAllowanceModelQualification;
  readiness: HostedAllowanceModelReadiness;
  contextWindow: number;
  maxOutputTokens: number;
  cacheWriteSupported: false;
  contextTiersSupported: false;
  supplierRatesUsdPerMillion: {
    freshInput: number;
    cacheRead: number;
    output: number;
  };
  scenario: {
    freshInput: 10000;
    cacheRead: 0;
    output: 2000;
    includesBilledReasoning: true;
  };
  estimatedSupplierCostUsd: number | null;
  requestsPerFreshFiveHours: number | null;
  sharedMonthlyBasisUsd: 10;
  /** Default offered by this cloud account for this allowance pool; never overrides an explicit model. */
  recommended?: boolean;
}

/**
 * Supplier-cost-based allowance overview returned from GET /api/inference/account.
 * The server is authoritative; the client validates structure and fails closed
 * (null) on malformed data. Never computes debit, remaining, or estimates.
 */
export interface HostedAllowanceOverview {
  snapshotAt: string;
  policyVersion: string;
  basis: "supplier_cost_usd";
  unresolvedReservedUsd: number | null;
  subscription: {
    priceUsd: 15;
    cadence: "monthly";
    state: "active" | "inactive" | "unavailable";
    sourceId: string | null;
    periodStart: string | null;
    periodEnd: string | null;
  };
  windows: HostedAllowanceWindow[];
  admission: {
    allowed: boolean;
    reason: string | null;
  };
  purchases: {
    enabled: false;
    offer: null;
  };
  models: HostedAllowanceModel[];
}

// ── Hosted inference API types ──

/** A single model entry from the hosted inference catalog. */
export interface InferenceModel {
  id: string;
  object: "model";
  owned_by: string;
  provider: string;
  /** Default offered by this cloud account; never overrides an explicit model. */
  recommended?: boolean;
  upstream_model: string;
  wire_api: "chat_completions" | "responses";
  context_length: number;
  max_output_tokens: number;
  pricing: {
    input_per_million_usd: number;
    output_per_million_usd: number;
    cached_input_per_million_usd: number;
    /** Supplier cost basis; absent or `customer_tariff_usd` means legacy pricing. */
    cost_basis?: "supplier_cost_usd" | "customer_tariff_usd";
  };
  /** Availability state from the catalog — `"available"` means route is qualified and entitled. */
  state?: string;
  /** Route identity from allowance qualification — present for available qualified routes. */
  routeIdentity?: string;
  /** Readiness mirror from the allowance overview (maps qualification for available routes). */
  readiness?: HostedAllowanceModelReadiness;
}

/** Response shape from GET /api/inference/v1/models */
export interface InferenceModelsResponse {
  object: "list";
  data: InferenceModel[];
}

/** Availability reported by the service for one Autumn credit pool. */
export interface InferenceCreditBalance {
  featureId: string;
  granted: number | null;
  remaining: number;
  remainingPercent: number | null;
  /** Unix milliseconds; only the earliest balance source may reset then. */
  nextResetAt: number | null;
}

/** Account balance from GET /api/inference/account */
export interface InferenceAccountResponse {
  remainingUsd: number | null;
  currency: "USD";
  credits: InferenceCreditBalance | null;
  /** Supplier-cost-based allowance overview; null when unavailable/unreachable. */
  allowance?: HostedAllowanceOverview | null;
}

/** Usage metadata from GET /api/inference/usage */
export interface InferenceUsageResponse {
  requests: Record<string, unknown>[];
}
function healthPath(host: string): string {
  try {
    const hostname = new URL(host).hostname.toLowerCase();
    if (hostname === "cloud.0sec.ai" || hostname === "cloud.0.security") {
      return "/api/health";
    }
  } catch {
    // Preserve the generic path and let getJson surface the malformed host.
  }
  return "/health";
}


export class CloudClient {
  private readonly host: string;
  private readonly token: string;
  private readonly fetchImpl: FetchImpl;

  constructor(opts: CloudClientOptions) {
    this.host = opts.host;
    this.token = opts.token;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  /**
   * Verify cloud reachability through its health route. The hosted dashboard
   * uses `/api/health`; a self-hosted receiver uses `/health`.
   */
  async pingHealth(): Promise<CloudHealthResponse> {
    return this.getJson<CloudHealthResponse>(healthPath(this.host));
  }

  /**
   * Fetch the hosted inference model catalog — available models, pricing,
   * wire API protocol, and context limits. Used at runtime for model
   * selection and by the hosted provider to determine per-model capabilities.
   * Rejects malformed recommendation metadata; the caller caches/filters as needed.
   */
  async getInferenceModels(): Promise<InferenceModelsResponse> {
    const path = "/api/inference/v1/models";
    const catalog = await this.getJson<InferenceModelsResponse>(path);
    if (!catalog || !Array.isArray(catalog.data) ||
        catalog.data.some(model => !model || typeof model !== "object" ||
          (model.recommended !== undefined && typeof model.recommended !== "boolean"))) {
      throw new CloudError("0sec Cloud returned an invalid hosted model catalog.", 502, path);
    }
    return catalog;
  }

  /**
   * Fetch server-produced subscription windows and legacy credit metadata.
   * An absent allowance identifies the older wallet API; null means unavailable
   * or malformed subscription data and must not fall back to a legacy wallet.
   * Never reconstruct debit, remaining allowance, or request estimates.
   */
  async getInferenceAccount(): Promise<InferenceAccountResponse> {
    const raw = (await this.getJson<Record<string, unknown>>("/api/inference/account")) as Record<string, unknown>;
    // Subscription accounts do not expose a legacy wallet amount.
    const remainingUsd = typeof raw.remainingUsd === "number" && Number.isFinite(raw.remainingUsd) ? raw.remainingUsd : null;
    // Legacy credits: validated separately from allowance.
    const credits = this.parseLegacyCredits(raw.credits);
    // Allowance: safe parse, fail closed on malformed.
    const allowance = this.parseAllowance(raw.allowance);
    return { remainingUsd, currency: "USD", credits, ...(allowance !== undefined ? { allowance } : {}) };
  }

  /**
   * Fetch request-level usage metadata for the operator's hosted
   * inference sessions. Returns lightweight metadata records (model,
   * tokens, provider, timestamp) — no prompt/response payload.
   */
  async getInferenceUsage(): Promise<InferenceUsageResponse> {
    return this.getJson<InferenceUsageResponse>("/api/inference/usage");
  }

  /**
   * Generic JSON GET helper. Public so future modules (scans, findings)
   * can reuse the same error mapping without duplicating it. Not exported
   * past the package boundary — see ./index.ts.
   */
  async getJson<T = unknown>(path: string): Promise<T> {
    const url = `${this.host}${path}`;
    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method: "GET",
        headers: this.headers(),
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new CloudNetworkError(this.scrub(msg), path);
    }

    this.assertOk(res, path);
    return (await res.json()) as T;
  }

  /**
   * Throw a typed error for non-2xx responses. Public so direct callers
   * (e.g. an integration test driving raw fetch) can reuse the mapping.
   */
  assertOk(res: Response, path: string): void {
    if (res.ok) return;
    if (res.status === 401) throw new CloudUnauthorizedError(path);
    if (res.status === 403) throw new CloudForbiddenError(path);
    throw new CloudError(
      `0sec-cloud request failed (HTTP ${res.status}) on ${path}.`,
      res.status,
      path,
    );
  }

  // ── internals ──

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
      Accept: "application/json",
      "User-Agent": `0sec-cli/${VERSION}`,
    };
  }

  /**
   * Strip anything that looks like our own token from a string. The
   * cloud token may be interpolated into a TLS-layer error message in
   * exotic failure modes — we redact it to keep the no-leak invariant
   * local to this module.
   */
  private scrub(s: string): string {
    if (!this.token) return s;
    return s.split(this.token).join("[REDACTED]");
  }

  /**
   * Parse and validate legacy Autumn credit balance from the raw response.
   * Returns null when credits are absent or structurally invalid.
   */
  private parseLegacyCredits(raw: unknown): InferenceCreditBalance | null {
    if (!raw || typeof raw !== "object") return null;
    const rc = raw as Record<string, unknown>;
    if (typeof rc.featureId !== "string" || !rc.featureId.trim()) return null;
    if (typeof rc.remaining !== "number" || !Number.isFinite(rc.remaining) || rc.remaining < 0) return null;
    if (rc.granted !== null && (typeof rc.granted !== "number" || !Number.isFinite(rc.granted) || rc.granted < 0)) return null;
    // Validate percentage but never reconstruct it.
    const remainingPercent = typeof rc.remainingPercent === "number" &&
      Number.isFinite(rc.remainingPercent) && rc.remainingPercent >= 0 && rc.remainingPercent <= 100 &&
      rc.granted !== null && rc.granted > 0 && rc.remaining <= rc.granted
      ? rc.remainingPercent : null;
    const nextResetAt = typeof rc.nextResetAt === "number" &&
      Number.isSafeInteger(rc.nextResetAt) && rc.nextResetAt > 0 && rc.nextResetAt <= 8.64e15
      ? rc.nextResetAt : null;
    return {
      featureId: rc.featureId,
      granted: rc.granted ?? null,
      remaining: rc.remaining,
      remainingPercent,
      nextResetAt,
    };
  }

  /**
   * Parse and validate the supplier-cost-based allowance overview. Returns
   * null when allowance is unreachable or structurally invalid (fail closed).
   * Returns undefined when the field is absent from the response (pre-rollout).
   * Never computes debit, remaining, or estimates.
   *
   * Validates ALL fields the parent/consumer actually reads — subscription,
   * admission, purchases, windows, models with nested
   * qualification/readiness/pricing/scenario. NaN/infinity, null-where-finite,
   * and malformed type/range/choice fields reject the entire allowance so no
   * downstream code trusts invalid eligibility or cost data.
   */
  private parseAllowance(raw: unknown): HostedAllowanceOverview | null | undefined {
    if (raw === undefined) return undefined;
    if (raw === null) return null;
    if (typeof raw !== "object") return null;
    const a = raw as Record<string, unknown>;

    // ── Top-level scalars ──────────────────────────────────────────────
    if (typeof a.snapshotAt !== "string" || a.snapshotAt.length === 0) return null;
    if (typeof a.policyVersion !== "string") return null;
    if (a.basis !== "supplier_cost_usd") return null;
    if (a.unresolvedReservedUsd !== null &&
        (typeof a.unresolvedReservedUsd !== "number" || !Number.isFinite(a.unresolvedReservedUsd) || a.unresolvedReservedUsd < 0))
      return null;

    // ── subscription ───────────────────────────────────────────────────
    if (typeof a.subscription !== "object" || a.subscription === null) return null;
    const sub = a.subscription as Record<string, unknown>;
    if (sub.priceUsd !== 15 || sub.cadence !== "monthly") return null;
    if (!["active", "inactive", "unavailable"].includes(sub.state as string)) return null;
    if (sub.sourceId !== null && typeof sub.sourceId !== "string") return null;
    if (sub.periodStart !== null && typeof sub.periodStart !== "string") return null;
    if (sub.periodEnd !== null && typeof sub.periodEnd !== "string") return null;

    // ── admission ──────────────────────────────────────────────────────
    if (typeof a.admission !== "object" || a.admission === null) return null;
    const adm = a.admission as Record<string, unknown>;
    if (typeof adm.allowed !== "boolean") return null;
    if (adm.reason !== null && typeof adm.reason !== "string") return null;

    // ── purchases (fixed shape — disabled) ──────────────────────────────
    if (typeof a.purchases !== "object" || a.purchases === null) return null;
    const pur = a.purchases as Record<string, unknown>;
    if (pur.enabled !== false || pur.offer !== null) return null;

    // ── windows ────────────────────────────────────────────────────────
    if (!Array.isArray(a.windows)) return null;
    for (const w of a.windows) {
      if (typeof w !== "object" || w === null) return null;
      const win = w as Record<string, unknown>;
      if (typeof win.id !== "string") return null;
      if (!["monthly", "weekly", "five_hour"].includes(win.kind as string)) return null;
      if (typeof win.limitUsd !== "number" || !Number.isFinite(win.limitUsd) || win.limitUsd < 0) return null;
      if (typeof win.settledUsd !== "number" || !Number.isFinite(win.settledUsd) || win.settledUsd < 0) return null;
      if (typeof win.reservedUsd !== "number" || !Number.isFinite(win.reservedUsd) || win.reservedUsd < 0) return null;
      if (typeof win.unknownReservedUsd !== "number" || !Number.isFinite(win.unknownReservedUsd) || win.unknownReservedUsd < 0) return null;
      if (typeof win.availableUsd !== "number" || !Number.isFinite(win.availableUsd) || win.availableUsd < 0) return null;
      if (typeof win.remainingPercent !== "number" || !Number.isFinite(win.remainingPercent) || win.remainingPercent < 0 || win.remainingPercent > 100) return null;
      if (typeof win.startsAt !== "string") return null;
      if (typeof win.endsAt !== "string") return null;
      if (!["billing_period", "utc_monday", "first_admission"].includes(win.resetSemantics as string)) return null;
    }

    // ── models ─────────────────────────────────────────────────────────
    if (!Array.isArray(a.models)) return null;
    for (const m of a.models) {
      if (typeof m !== "object" || m === null) return null;
      const model = m as Record<string, unknown>;
      if (typeof model.id !== "string") return null;
      if (model.recommended !== undefined && typeof model.recommended !== "boolean") return null;
      if (typeof model.provider !== "string") return null;
      if (typeof model.upstreamModel !== "string") return null;
      if (typeof model.wireApi !== "string") return null;
      if (model.endpointIdentity !== null && typeof model.endpointIdentity !== "string") return null;
      if (typeof model.routeIdentity !== "string" || model.routeIdentity.length === 0) return null;
      if (typeof model.priceVersion !== "string") return null;
      if (!["available", "disabled", "unsupported"].includes(model.state as string)) return null;
      if (model.reason !== null && typeof model.reason !== "string") return null;
      // Context/max tokens: safe positive integers.
      if (typeof model.contextWindow !== "number" || !Number.isSafeInteger(model.contextWindow) || model.contextWindow <= 0) return null;
      if (typeof model.maxOutputTokens !== "number" || !Number.isSafeInteger(model.maxOutputTokens) || model.maxOutputTokens <= 0) return null;
      // Fixed boolean flags.
      if (model.cacheWriteSupported !== false) return null;
      if (model.contextTiersSupported !== false) return null;
      // sharedMonthlyBasisUsd: fixed at 10.
      if (model.sharedMonthlyBasisUsd !== 10) return null;
      // estimatedSupplierCostUsd: non-negative finite or null (unknown).
      if (model.estimatedSupplierCostUsd !== null &&
          (typeof model.estimatedSupplierCostUsd !== "number" || !Number.isFinite(model.estimatedSupplierCostUsd) || model.estimatedSupplierCostUsd < 0))
        return null;
      // requestsPerFreshFiveHours: non-negative integer or null.
      if (model.requestsPerFreshFiveHours !== null &&
          (typeof model.requestsPerFreshFiveHours !== "number" || !Number.isSafeInteger(model.requestsPerFreshFiveHours) || model.requestsPerFreshFiveHours < 0))
        return null;

      // ── supplierRatesUsdPerMillion ───────────────────────────────────
      if (typeof model.supplierRatesUsdPerMillion !== "object" || model.supplierRatesUsdPerMillion === null) return null;
      const rates = model.supplierRatesUsdPerMillion as Record<string, unknown>;
      if (typeof rates.freshInput !== "number" || !Number.isFinite(rates.freshInput) || rates.freshInput < 0) return null;
      if (typeof rates.cacheRead !== "number" || !Number.isFinite(rates.cacheRead) || rates.cacheRead < 0) return null;
      if (typeof rates.output !== "number" || !Number.isFinite(rates.output) || rates.output < 0) return null;

      // ── scenario ─────────────────────────────────────────────────────
      if (typeof model.scenario !== "object" || model.scenario === null) return null;
      const scen = model.scenario as Record<string, unknown>;
      if (scen.freshInput !== 10000 || scen.cacheRead !== 0 || scen.output !== 2000) return null;
      if (scen.includesBilledReasoning !== true) return null;

      // ── qualification ────────────────────────────────────────────────
      if (typeof model.qualification !== "object" || model.qualification === null) return null;
      const qual = model.qualification as Record<string, unknown>;
      if (!["unknown", "passed", "failed"].includes(qual.status as string)) return null;
      if (qual.evidenceRef !== null && typeof qual.evidenceRef !== "string") return null;
      if (qual.verifiedAt !== null && typeof qual.verifiedAt !== "string") return null;
      if (qual.sourceRevision !== null && typeof qual.sourceRevision !== "string") return null;
      if (qual.routeIdentity !== null && typeof qual.routeIdentity !== "string") return null;

      // ── readiness ────────────────────────────────────────────────────
      if (typeof model.readiness !== "object" || model.readiness === null) return null;
      const read = model.readiness as Record<string, unknown>;
      if (typeof read.configured !== "boolean") return null;
      if (typeof read.entitled !== "boolean") return null;
      if (read.reason !== null && typeof read.reason !== "string") return null;
      if (typeof read.qualification !== "object" || read.qualification === null) return null;
      const rqual = read.qualification as Record<string, unknown>;
      if (!["unknown", "passed", "failed"].includes(rqual.status as string)) return null;
      if (rqual.evidenceRef !== null && typeof rqual.evidenceRef !== "string") return null;
      if (rqual.verifiedAt !== null && typeof rqual.verifiedAt !== "string") return null;
      if (rqual.sourceRevision !== null && typeof rqual.sourceRevision !== "string") return null;
      if (rqual.routeIdentity !== null && typeof rqual.routeIdentity !== "string") return null;
    }

    return a as unknown as HostedAllowanceOverview;
  }
}
