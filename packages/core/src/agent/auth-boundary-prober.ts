/**
 * Auth-boundary differential prober (pwnkit#770, part of #761).
 *
 * Question this module answers, per endpoint: **is it reachable WITHOUT
 * credentials?** This is the "22 of 200 endpoints were unauthenticated"
 * finding — an authorization-boundary leak distinct from the BOLA/IDOR diff
 * `access_control_probe` performs (which replays ONE request across MULTIPLE
 * authenticated identities). Here we diff a single endpoint *authenticated vs
 * unauthenticated* and decide whether the unauth principal can reach it.
 *
 * Given an endpoint list + optional credentials, the prober:
 *   1. Requests each endpoint unauthenticated (no creds).
 *   2. If creds are supplied, requests the same endpoint authenticated.
 *   3. Emits a per-endpoint verdict (`unauthReachable: true/false`) plus
 *      evidence (both statuses, body similarity, a short body preview).
 *
 * Verdict logic (`classifyAuthBoundary`) is a pure function over the two
 * responses so it can be unit-tested with mocked responses — no network. The
 * runner takes an injectable `FetchLike` (defaulting to `globalThis.fetch`),
 * mirroring the `wp-fingerprint.ts` convention used elsewhere in this package.
 *
 * AuthConfig → headers reuses `buildAuthHeaders` so credential handling stays
 * consistent with the rest of the agent.
 */

import type { AuthConfig } from "@pwnkit/shared";
import { buildAuthHeaders } from "./prompts.js";

// ── Types ──

export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  headers?: { get(name: string): string | null } | Record<string, string>;
  text: () => Promise<string>;
}>;

/** One endpoint to probe. A bare string is shorthand for `{ url }`. */
export interface ProbeEndpoint {
  url: string;
  /** HTTP method, default GET. */
  method?: string;
  /** Optional request body sent verbatim to both authed + unauthed requests. */
  body?: string;
}

/** A single request/response snapshot used as verdict evidence. */
export interface BoundaryResponse {
  status: number;
  contentType: string;
  /** Truncated body preview (non-secret evidence). */
  bodyPreview: string;
  /** Full normalized length, for diff context without dumping the body. */
  bodyLength: number;
  /** Set when the request itself failed (network error / timeout). */
  error?: string;
}

export type AuthBoundaryVerdict =
  /** Reachable with no credentials — the boundary leak we hunt for. */
  | "unauth-reachable"
  /** Unauth got 401/403 (or auth-gated redirect) — boundary holds. */
  | "auth-required"
  /** Endpoint not found / gone for everyone — nothing to gate. */
  | "not-found"
  /** Could not decide (request error, ambiguous status, no authed baseline). */
  | "inconclusive";

export interface EndpointVerdict {
  url: string;
  method: string;
  /** The headline boolean the issue asks for. */
  unauthReachable: boolean;
  verdict: AuthBoundaryVerdict;
  /** "high" when an authed-only resource leaked unauthenticated; else lower. */
  severity: "high" | "medium" | "low" | "info";
  /** Human-readable rationale for the verdict. */
  note: string;
  /** Token-Jaccard similarity of unauth vs auth body in [0,1], when both ran. */
  bodySimilarity?: number;
  unauth: BoundaryResponse;
  /** Present only when credentials were supplied. */
  auth?: BoundaryResponse;
}

export interface AuthBoundaryReport {
  endpointCount: number;
  /** Count of endpoints with `unauthReachable === true`. */
  unauthReachableCount: number;
  results: EndpointVerdict[];
}

export interface AuthBoundaryProbeOptions {
  endpoints: Array<ProbeEndpoint | string>;
  /** Credentials for the authenticated leg. Omit to run unauth-only. */
  auth?: AuthConfig;
  /** Injectable fetch for tests. Defaults to globalThis.fetch. */
  fetchImpl?: FetchLike;
  /** Per-request timeout, milliseconds. Default 10_000. */
  timeoutMs?: number;
  /** Max bytes of body kept as evidence. Default 1_000. */
  maxBodyPreview?: number;
}

// ── Verdict logic (pure, unit-tested) ──

const is2xx = (s: number): boolean => s >= 200 && s < 300;
const isAuthDenied = (s: number): boolean => s === 401 || s === 403;
const isNotFound = (s: number): boolean => s === 404 || s === 410;

/**
 * Decide whether an endpoint is reachable unauthenticated, given the unauth
 * response and an optional authenticated baseline.
 *
 * Rules (evaluated in order):
 *  - unauth request errored → `inconclusive`.
 *  - unauth 401/403 → `auth-required` (boundary holds).
 *  - unauth 404/410, and no authed 2xx to contradict it → `not-found`.
 *  - unauth 2xx:
 *      • no authed baseline → `unauth-reachable` (reachable without creds).
 *      • authed baseline also 2xx with near-identical body → `unauth-reachable`
 *        at HIGH severity: the unauth principal got the SAME protected resource.
 *      • authed baseline 2xx but a distinct body → `unauth-reachable` at medium:
 *        the path is open to anonymous callers (maybe a public projection).
 *      • authed baseline non-2xx → `unauth-reachable` (anon works where the
 *        configured creds did not; still an open endpoint).
 *  - unauth 3xx/5xx/other → `inconclusive` (neither a clear allow nor deny).
 */
export function classifyAuthBoundary(
  unauth: Pick<BoundaryResponse, "status" | "bodyPreview" | "error">,
  authed?: Pick<BoundaryResponse, "status" | "bodyPreview" | "error">,
): Pick<EndpointVerdict, "unauthReachable" | "verdict" | "severity" | "note" | "bodySimilarity"> {
  if (unauth.error) {
    return {
      unauthReachable: false,
      verdict: "inconclusive",
      severity: "info",
      note: `unauthenticated request failed: ${unauth.error}`,
    };
  }

  if (isAuthDenied(unauth.status)) {
    return {
      unauthReachable: false,
      verdict: "auth-required",
      severity: "info",
      note: `unauthenticated request was denied (HTTP ${unauth.status}); auth boundary holds`,
    };
  }

  // Body similarity is only meaningful when we have an authed baseline.
  const sim =
    authed && !authed.error
      ? bodySimilarity(unauth.bodyPreview, authed.bodyPreview)
      : undefined;

  if (isNotFound(unauth.status)) {
    // If the authed identity DID reach it, the 404 was an auth-gated "hide",
    // not a true absence — treat as boundary holding, not "not-found".
    if (authed && !authed.error && is2xx(authed.status)) {
      return {
        unauthReachable: false,
        verdict: "auth-required",
        severity: "info",
        bodySimilarity: sim,
        note: `unauthenticated got HTTP ${unauth.status} but authenticated got ${authed.status}; endpoint exists and is auth-gated`,
      };
    }
    return {
      unauthReachable: false,
      verdict: "not-found",
      severity: "info",
      bodySimilarity: sim,
      note: `endpoint returned HTTP ${unauth.status} unauthenticated; nothing to gate`,
    };
  }

  if (is2xx(unauth.status)) {
    if (!authed || authed.error) {
      return {
        unauthReachable: true,
        verdict: "unauth-reachable",
        severity: "medium",
        note: `reachable without credentials (HTTP ${unauth.status}); no authenticated baseline to compare`,
      };
    }
    if (is2xx(authed.status) && (sim ?? 0) >= 0.9) {
      return {
        unauthReachable: true,
        verdict: "unauth-reachable",
        severity: "high",
        bodySimilarity: sim,
        note: `unauthenticated request retrieved the SAME resource as the authenticated baseline (body similarity ${(sim ?? 0).toFixed(2)}) — protected endpoint exposed to anonymous callers`,
      };
    }
    if (is2xx(authed.status)) {
      return {
        unauthReachable: true,
        verdict: "unauth-reachable",
        severity: "medium",
        bodySimilarity: sim,
        note: `reachable without credentials (HTTP ${unauth.status}); body differs from authenticated baseline (similarity ${(sim ?? 0).toFixed(2)}) — verify whether the anonymous projection leaks data`,
      };
    }
    // Authed leg was non-2xx but anon got through.
    return {
      unauthReachable: true,
      verdict: "unauth-reachable",
      severity: "medium",
      bodySimilarity: sim,
      note: `reachable without credentials (HTTP ${unauth.status}) while the authenticated request returned HTTP ${authed.status}`,
    };
  }

  return {
    unauthReachable: false,
    verdict: "inconclusive",
    severity: "info",
    bodySimilarity: sim,
    note: `unauthenticated HTTP ${unauth.status} is neither a clear allow (2xx) nor deny (401/403/404)`,
  };
}

/** Normalize a response body for similarity comparison. */
function normalizeBody(s: string): string {
  return (s ?? "").toLowerCase().replace(/\s+/g, " ").trim();
}

/**
 * Token-Jaccard similarity of two response bodies in [0, 1]. 1 = identical
 * (after whitespace/case normalization), 0 = no shared tokens. Deterministic.
 */
export function bodySimilarity(a: string, b: string): number {
  const na = normalizeBody(a);
  const nb = normalizeBody(b);
  if (na === "" && nb === "") return 1;
  if (na === nb) return 1;
  const ta = new Set(na.split(" ").filter(Boolean));
  const tb = new Set(nb.split(" ").filter(Boolean));
  if (ta.size === 0 && tb.size === 0) return 1;
  let inter = 0;
  for (const t of ta) if (tb.has(t)) inter++;
  const union = new Set([...ta, ...tb]).size;
  return union === 0 ? 0 : inter / union;
}

// ── Runner ──

/** Coerce a string-or-object endpoint into the normalized shape. */
export function normalizeEndpoint(ep: ProbeEndpoint | string): ProbeEndpoint {
  if (typeof ep === "string") return { url: ep, method: "GET" };
  return { url: ep.url, method: (ep.method ?? "GET").toUpperCase(), body: ep.body };
}

/**
 * Probe every endpoint authenticated vs unauthenticated and emit per-endpoint
 * auth verdicts. Pure I/O orchestration — the decision lives in
 * `classifyAuthBoundary`.
 */
export async function runAuthBoundaryProbe(
  opts: AuthBoundaryProbeOptions,
): Promise<AuthBoundaryReport> {
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxBodyPreview = opts.maxBodyPreview ?? 1_000;
  const authHeaders = opts.auth ? buildAuthHeaders(opts.auth) : undefined;

  const endpoints = opts.endpoints.map(normalizeEndpoint);

  const results: EndpointVerdict[] = await Promise.all(
    endpoints.map(async (ep) => {
      const method = ep.method ?? "GET";

      // Unauthenticated leg — explicitly strip any auth.
      const unauth = await fetchOnce(fetchImpl, ep, {}, timeoutMs, maxBodyPreview);

      // Authenticated leg — only when creds were supplied.
      const authed = authHeaders
        ? await fetchOnce(fetchImpl, ep, authHeaders, timeoutMs, maxBodyPreview)
        : undefined;

      const decision = classifyAuthBoundary(unauth, authed);

      return {
        url: ep.url,
        method,
        unauthReachable: decision.unauthReachable,
        verdict: decision.verdict,
        severity: decision.severity,
        note: decision.note,
        bodySimilarity: decision.bodySimilarity,
        unauth,
        auth: authed,
      };
    }),
  );

  const unauthReachableCount = results.filter((r) => r.unauthReachable).length;
  return { endpointCount: results.length, unauthReachableCount, results };
}

async function fetchOnce(
  fetchImpl: FetchLike,
  ep: ProbeEndpoint,
  headers: Record<string, string>,
  timeoutMs: number,
  maxBodyPreview: number,
): Promise<BoundaryResponse> {
  try {
    const res = await withTimeout(
      fetchImpl(ep.url, {
        method: ep.method ?? "GET",
        headers,
        body: ep.body,
      }),
      timeoutMs,
    );
    if (!res) {
      return { status: 0, contentType: "", bodyPreview: "", bodyLength: 0, error: "timeout" };
    }
    const body = await res.text().catch(() => "");
    return {
      status: res.status,
      contentType: headerGet(res.headers, "content-type") ?? "",
      bodyPreview: body.slice(0, maxBodyPreview),
      bodyLength: body.length,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { status: 0, contentType: "", bodyPreview: "", bodyLength: 0, error: message };
  }
}

function headerGet(
  headers: { get(name: string): string | null } | Record<string, string> | undefined,
  name: string,
): string | null {
  if (!headers) return null;
  if (typeof (headers as { get?: unknown }).get === "function") {
    return (headers as { get(n: string): string | null }).get(name);
  }
  const rec = headers as Record<string, string>;
  return rec[name] ?? rec[name.toLowerCase()] ?? null;
}

async function withTimeout<T>(p: Promise<T>, timeoutMs: number): Promise<T | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      p,
      new Promise<undefined>((resolve) => {
        timer = setTimeout(() => resolve(undefined), timeoutMs);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ── Summary helper (for the eventual tool wrapper / agent-facing output) ──

export function summarizeAuthBoundaryReport(report: AuthBoundaryReport): string {
  const lines: string[] = [];
  lines.push(
    `Auth-boundary probe: ${report.unauthReachableCount} of ${report.endpointCount} endpoint(s) reachable WITHOUT credentials.`,
  );
  const reachable = report.results.filter((r) => r.unauthReachable);
  if (reachable.length > 0) {
    lines.push("");
    lines.push("Unauthenticated-reachable endpoints:");
    for (const r of reachable) {
      lines.push(
        `  - [${r.severity}] ${r.method} ${r.url} — unauth ${r.unauth.status}${r.auth ? ` / auth ${r.auth.status}` : ""}${r.bodySimilarity !== undefined ? ` (body sim ${r.bodySimilarity.toFixed(2)})` : ""}`,
      );
    }
  }
  return lines.join("\n");
}
