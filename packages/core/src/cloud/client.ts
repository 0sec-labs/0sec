// 0sec-cloud HTTP client. Bearer-auth, JSON, scaffolding.
//
// Scope:
//   - One method: `pingHealth()` — hits the configured health endpoint to
//     verify cloud reachability.
//
// The hosted 0cloud dashboard serves health under `/api/health`; generic
// self-hosted receivers retain the original `/health` convention.
//
// Out of scope:
//   - `dispatchScan()`, `listScans()`, etc. — those will use real
//     response schemas with zod once the cloud API surface is pinned.
//   - No pagination, no rate-limit retry, no cursor-aware paginator.
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
