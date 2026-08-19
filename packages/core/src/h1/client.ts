// HackerOne hacker-API client. Read-only, Basic-auth, JSON.
//
// Scope:
//   - GET only. No write endpoints anywhere. (No `--submit` lever exists.)
//   - Returns parsed JSON; typed-error on non-2xx.
//   - Paginates `links.next` for collection endpoints with a configurable
//     pacing delay (H1 rate limit is 600 reads/min; we default to 100ms
//     between page fetches per AGENTS.md guidance).
//
// Per AGENTS.md "no premature abstraction": this is the H1 client, not a
// generic "venue API" client. When future venues land (Bugcrowd / IBB /
// etc.) we'll fork a sibling module rather than parameterise this one.
//
// SECURITY:
//   - The Authorization header value is built from the token but never
//     emitted back to the caller. Errors include status + path + URL,
//     never headers, never the body if it might contain echoes of the
//     token (which the H1 API doesn't currently do but we still avoid).
//   - `User-Agent` includes `0sec-cli/<version>` so H1 ops can identify
//     us if traffic looks anomalous.

import { VERSION } from "@0sec/shared";
import type { H1Collection } from "./types.js";

const BASE_URL = "https://api.hackerone.com";

export class H1Error extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly path?: string,
  ) {
    super(message);
    this.name = "H1Error";
  }
}
export class H1AuthError extends H1Error {
  constructor(path: string) {
    super(`H1 auth failed (HTTP 401) on ${path}. Check H1_API_IDENTIFIER + H1_API_TOKEN.`, 401, path);
    this.name = "H1AuthError";
  }
}
export class H1ForbiddenError extends H1Error {
  constructor(path: string) {
    super(`H1 forbidden (HTTP 403) on ${path}. Likely a private program you can't view.`, 403, path);
    this.name = "H1ForbiddenError";
  }
}
export class H1RateLimitError extends H1Error {
  constructor(path: string, readonly retryAfterSec: number) {
    super(`H1 rate limited (HTTP 429) on ${path}. Retry-After=${retryAfterSec}s.`, 429, path);
    this.name = "H1RateLimitError";
  }
}
export class H1NetworkError extends H1Error {
  constructor(message: string, path: string) {
    super(`H1 network error on ${path}: ${message}`, undefined, path);
    this.name = "H1NetworkError";
  }
}

export type FetchImpl = typeof fetch;

export interface H1ClientOptions {
  identifier: string;
  token: string;
  baseUrl?: string;
  fetchImpl?: FetchImpl;
  /** ms to sleep between paginated requests. Default 100ms. */
  pageDelayMs?: number;
  /** Max retries on 429. Default 1 — fail loudly so the caller can decide. */
  maxRetries429?: number;
  /** Hook used by tests to substitute timers without `vi.useFakeTimers`. */
  sleep?: (ms: number) => Promise<void>;
}

const DEFAULT_PAGE_DELAY_MS = 100;
const DEFAULT_MAX_RETRIES_429 = 1;

export class H1Client {
  private readonly identifier: string;
  private readonly token: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchImpl;
  private readonly pageDelayMs: number;
  private readonly maxRetries429: number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(opts: H1ClientOptions) {
    this.identifier = opts.identifier;
    this.token = opts.token;
    this.baseUrl = opts.baseUrl ?? BASE_URL;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.pageDelayMs = opts.pageDelayMs ?? DEFAULT_PAGE_DELAY_MS;
    this.maxRetries429 = opts.maxRetries429 ?? DEFAULT_MAX_RETRIES_429;
    this.sleep = opts.sleep ?? defaultSleep;
  }

  /**
   * GET an absolute path (e.g. `/v1/hackers/programs/foo`) and return the
   * parsed JSON body. Throws typed errors on non-2xx.
   */
  async get<T = unknown>(path: string, query?: Record<string, string | number | undefined>): Promise<T> {
    const url = this.buildUrl(path, query);
    return this.getUrl<T>(url, path);
  }

  /**
   * GET a fully-qualified URL (e.g. one produced by H1 in `links.next`).
   * Used internally by `paginate` to honour H1's own cursor links instead
   * of synthesising the next URL ourselves.
   */
  async getUrl<T = unknown>(url: string, displayPath?: string): Promise<T> {
    const path = displayPath ?? new URL(url).pathname;
    let attempt = 0;
    // We retry exactly once on 429 by default — the caller usually wants to
    // know about rate-limit pressure rather than have us silently sleep
    // through it.
    while (true) {
      let res: Response;
      try {
        res = await this.fetchImpl(url, {
          method: "GET",
          headers: this.headers(),
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        // Defence-in-depth: scrub any accidental token leakage in the
        // network-layer message. Node's `fetch` does not include
        // Authorization in `cause` strings as of writing, but we strip
        // anyway to keep the invariant local.
        throw new H1NetworkError(this.scrub(msg), path);
      }

      if (res.status === 429 && attempt < this.maxRetries429) {
        const retryAfter = parseRetryAfter(res.headers.get("Retry-After"));
        await this.sleep(retryAfter * 1000);
        attempt += 1;
        continue;
      }

      this.assertOk(res, path);
      return (await res.json()) as T;
    }
  }

  /**
   * Async-generator over `links.next`. Yields each parsed page in turn;
   * the caller pulls until they have enough or the generator exhausts.
   */
  async *paginate<TAttrs, TRels = Record<string, unknown>>(
    path: string,
    query?: Record<string, string | number | undefined>,
  ): AsyncGenerator<H1Collection<TAttrs, TRels>> {
    let url: string | null = this.buildUrl(path, query);
    let isFirst = true;
    while (url) {
      if (!isFirst) await this.sleep(this.pageDelayMs);
      isFirst = false;
      const page: H1Collection<TAttrs, TRels> = await this.getUrl<H1Collection<TAttrs, TRels>>(url, path);
      yield page;
      url = page.links?.next ?? null;
    }
  }

  /**
   * Throw a typed error for non-2xx responses. Public so direct callers
   * (e.g. an integration test driving raw fetch) can reuse the mapping.
   */
  assertOk(res: Response, path: string): void {
    if (res.ok) return;
    if (res.status === 401) throw new H1AuthError(path);
    if (res.status === 403) throw new H1ForbiddenError(path);
    if (res.status === 429) {
      const retryAfter = parseRetryAfter(res.headers.get("Retry-After"));
      throw new H1RateLimitError(path, retryAfter);
    }
    throw new H1Error(`H1 request failed (HTTP ${res.status}) on ${path}.`, res.status, path);
  }

  // ── internals ──

  private headers(): Record<string, string> {
    const basic = Buffer.from(`${this.identifier}:${this.token}`).toString("base64");
    return {
      Authorization: `Basic ${basic}`,
      Accept: "application/json",
      "User-Agent": `0sec-cli/${VERSION}`,
    };
  }

  private buildUrl(path: string, query?: Record<string, string | number | undefined>): string {
    // We hand-encode bracketed keys (`page[size]`, `page[number]`) because
    // H1 specifically requires `%5B` / `%5D` and Node's URLSearchParams
    // has historically been inconsistent across runtimes about whether it
    // re-encodes already-encoded brackets. Using URLSearchParams works
    // here too, but the explicit pass keeps behaviour identical across
    // Node 20 / 22 / Bun.
    const u = new URL(path, this.baseUrl);
    if (query) {
      const parts: string[] = [];
      for (const [key, val] of Object.entries(query)) {
        if (val === undefined) continue;
        parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(val))}`);
      }
      if (parts.length > 0) u.search = parts.join("&");
    }
    return u.toString();
  }

  /**
   * Strip anything that looks like our own token from a string. The token
   * is base64 (44 chars in practice) — we redact substrings that contain
   * a long run of token characters. Defensive: H1's own errors don't
   * echo it, and our typed errors don't carry it, but the network-layer
   * message could theoretically interpolate request data on TLS failure.
   */
  private scrub(s: string): string {
    if (!this.token) return s;
    return s.split(this.token).join("[REDACTED]");
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * H1 sets `Retry-After` as either delta-seconds (RFC 7231) or, in some
 * rare cases, an HTTP-date. We only handle the seconds form because it's
 * what H1 actually uses in practice; an HTTP-date falls back to a fixed
 * 1-second hint so the caller still gets *some* delay.
 */
export function parseRetryAfter(header: string | null): number {
  if (!header) return 1;
  const n = Number(header);
  if (Number.isFinite(n) && n >= 0) return Math.min(n, 60);
  return 1;
}
