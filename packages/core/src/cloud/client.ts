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

// ── Hosted inference API types ──

/** A single model entry from the hosted inference catalog. */
export interface InferenceModel {
  id: string;
  object: "model";
  owned_by: string;
  provider: string;
  upstream_model: string;
  wire_api: "chat_completions" | "responses";
  context_length: number;
  max_output_tokens: number;
  pricing: {
    input_per_million_usd: number;
    output_per_million_usd: number;
    cached_input_per_million_usd: number;
  };
}

/** Response shape from GET /api/inference/v1/models */
export interface InferenceModelsResponse {
  object: "list";
  data: InferenceModel[];
}

/** Account balance from GET /api/inference/account */
export interface InferenceAccountResponse {
  remainingUsd: number;
  currency: "USD";
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
   * uses `/api/health`; a self-hosted receiver uses `/host`.
   */
  async pingHealth(): Promise<CloudHealthResponse> {
    return this.getJson<CloudHealthResponse>(healthPath(this.host));
  }

  /**
   * Fetch the hosted inference model catalog — available models, pricing,
   * wire API protocol, and context limits. Used at runtime for model
   * selection and by the hosted provider to determine per-model capabilities.
   * Returns the raw list response; the caller caches/filters as needed.
   */
  async getInferenceModels(): Promise<InferenceModelsResponse> {
    return this.getJson<InferenceModelsResponse>("/api/inference/v1/models");
  }

  /**
   * Fetch the operator's hosted inference account balance. Reflects
   * remaining prepaid credits (Autumn billing) in USD. A depleted balance
   * will cause the inference endpoint to return 402 InsufficientFunds.
   */
  async getInferenceAccount(): Promise<InferenceAccountResponse> {
    return this.getJson<InferenceAccountResponse>("/api/inference/account");
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
}
