// pwnkit-cloud HTTP client. Bearer-auth, JSON, scaffolding.
//
// Scope (this PR):
//   - One method: `pingHealth()` — hits `GET /health` to verify that the
//     configured token is accepted by the server.
//
// Out of scope (follow-up PR, after the server-side mint endpoint lands):
//   - `dispatchScan()`, `listScans()`, etc. — those will use real
//     response schemas with zod once the cloud API surface is pinned.
//
// DIVERGENCE FROM h1/client.ts:
//   - Bearer-token auth (single secret) instead of HTTP Basic. There is
//     no identifier to embed in the header.
//   - No pagination, no rate-limit retry, no cursor-aware paginator —
//     none of those exist for `/health`. Follow-up will reintroduce them
//     when listing scans / findings.
//
// SECURITY:
//   - The Authorization header value is built from the token but never
//     emitted back to the caller. Errors include status + path + host,
//     never headers or the token itself.
//   - `User-Agent` includes `pwnkit-cli/<version>` so server-side ops can
//     identify CLI traffic if it looks anomalous.

import { VERSION } from "@pwnkit/shared";

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
    super(`pwnkit-cloud auth rejected (HTTP 401) on ${path}. Run \`pwnkit auth login\` to refresh.`, 401, path);
    this.name = "CloudUnauthorizedError";
  }
}
export class CloudForbiddenError extends CloudError {
  constructor(path: string) {
    super(
      `pwnkit-cloud forbidden (HTTP 403) on ${path}. Token lacks scope for this resource.`,
      403,
      path,
    );
    this.name = "CloudForbiddenError";
  }
}
export class CloudNetworkError extends CloudError {
  constructor(message: string, path: string) {
    super(`pwnkit-cloud network error on ${path}: ${message}`, undefined, path);
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
   * Verify the configured token by hitting `GET /health`. Returns the
   * parsed body on success. Throws a typed error on non-2xx.
   *
   * The server contract for `/health` (per #303): respond 200 with a
   * JSON body containing at least `{ status: "ok" }` when the bearer is
   * accepted. 401 means the token is invalid; 403 means it's valid but
   * lacks the scope required to talk to the API at all (rare).
   */
  async pingHealth(): Promise<CloudHealthResponse> {
    return this.getJson<CloudHealthResponse>("/health");
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
      `pwnkit-cloud request failed (HTTP ${res.status}) on ${path}.`,
      res.status,
      path,
    );
  }

  // ── internals ──

  private headers(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.token}`,
      Accept: "application/json",
      "User-Agent": `pwnkit-cli/${VERSION}`,
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
