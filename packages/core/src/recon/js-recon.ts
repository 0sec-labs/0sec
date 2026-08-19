// JS-driven endpoint + secret discovery (pwnkit#927).
//
// The CodeWall "hardcoded credentials in a public JavaScript file" move: fetch
// the JS a live site serves, then mine each bundle for (a) endpoint/route
// strings + API base URLs the app talks to, and (b) embedded secrets (API
// keys, tokens, cloud creds, private keys). The discovered endpoints come back
// as `ReconAsset`s in the SAME `(kind:"endpoint", value:"METHOD /path")` shape
// `discover_api_surface` emits, so they feed straight into `surface_sweep` /
// `auth_boundary_probe` with no adapter. Secrets come back redacted.
//
// SAFETY IS THE DESIGN — same deny-by-default contract as
// `enumerateSubdomainsActive` (active-subdomains.ts):
//
//   * SCOPE   — every JS URL is run through a `ScopePolicy` before it is
//               fetched. With NO policy supplied, nothing is fetched
//               (deny-by-default), so an unauthorized run is a no-op. This is
//               the only path to a network touch.
//   * BOUNDED — a hard cap on the number of JS files fetched per pass, and the
//               endpoint extractor is itself bounded per-body.
//
// `fetchText` is injected (exactly like the recon spec/MCP probes and
// js-artifacts.ts) so the whole module is unit-testable with no live network.
// No LLM. Raw secret values are NEVER returned or logged — only the redacted
// excerpt from `redactSecret`.

import type { ScopePolicy } from "../scope/scope.js";
import type { ReconAsset } from "./recon.js";
import { scanBody, type SecretHit, type FetchTextResult } from "./js-artifacts.js";
import { extractEndpointsFromJs } from "./js-endpoints.js";

/** Hard cap on JS files fetched in a single pass — a safety rail, not a knob. */
export const MAX_JS_FILES = 100;

export interface JsReconOptions {
  /**
   * JS URLs to mine — typically the `scripts` array a `crawl` already
   * extracted from the target's pages. Out-of-scope / malformed URLs are
   * dropped before any fetch.
   */
  scriptUrls: readonly string[];
  /**
   * Authorized-scope gate. Every JS URL is checked against this policy and
   * only fetched when `match(url).allowed`. REQUIRED in practice: with no
   * policy, nothing is fetched (deny-by-default), so an unauthorized run is a
   * no-op rather than a live JS sweep.
   */
  scope?: ScopePolicy;
  /**
   * Injected fetch — returns `{ status, body }`. Keeps the pass testable and
   * offline; the agent tool wires a scope-validated fetch here.
   */
  fetchText: (url: string) => Promise<FetchTextResult>;
  /** Max JS files to fetch. Clamped to `[0, MAX_JS_FILES]`. Default 100. */
  maxFiles?: number;
}

export interface JsReconResult {
  /**
   * Discovered endpoints as `ReconAsset`s (kind `"endpoint"`, value
   * `METHOD /path`), ready to feed into `surface_sweep` / `auth_boundary_probe`.
   */
  endpoints: ReconAsset[];
  /** Distinct absolute API base URLs the bundles reference. */
  apiBaseUrls: string[];
  /** Redacted secret hits — the raw value is never carried here. */
  secrets: SecretHit[];
  /** JS URLs actually fetched (passed scope + within budget). */
  scanned: string[];
  /** JS URLs skipped because they were out of scope or unparseable. */
  skipped: string[];
}

function clampFiles(n: number | undefined): number {
  const v = Number.isFinite(n) ? Math.floor(n as number) : MAX_JS_FILES;
  return Math.max(0, Math.min(v, MAX_JS_FILES));
}

/**
 * Mine a set of (in-scope) JS URLs for endpoints + secrets.
 *
 * Gating contract (must pass before any fetch):
 *   1. `scope.match(url).allowed`  — per-URL authorized-scope check. No policy
 *                                    → deny-by-default → nothing fetched.
 *   2. within `maxFiles`           — bounded fetch budget.
 *
 * Endpoints are emitted in the recon `ReconAsset` shape so a caller can hand
 * them straight to the auth-boundary probe. Secrets are pre-redacted.
 */
export async function runJsRecon(opts: JsReconOptions): Promise<JsReconResult> {
  const result: JsReconResult = {
    endpoints: [],
    apiBaseUrls: [],
    secrets: [],
    scanned: [],
    skipped: [],
  };

  const budget = clampFiles(opts.maxFiles);
  if (budget === 0) return result;

  // Rail 1: an authorized-scope policy is mandatory for a live JS sweep. With
  // none, deny-by-default → fetch nothing.
  const scope = opts.scope;
  if (!scope) {
    result.skipped.push(...opts.scriptUrls);
    return result;
  }

  // Dedupe + scope-filter the candidate URLs BEFORE any fetch.
  const seenUrl = new Set<string>();
  const inScope: string[] = [];
  for (const raw of opts.scriptUrls) {
    const url = typeof raw === "string" ? raw.trim() : "";
    if (!url || seenUrl.has(url)) continue;
    seenUrl.add(url);
    if (!/^https?:\/\//i.test(url) || !scope.match(url).allowed) {
      result.skipped.push(url);
      continue;
    }
    inScope.push(url);
  }

  const endpointsByValue = new Map<string, ReconAsset>();
  const apiBases = new Set<string>();
  const secretSeen = new Set<string>();

  for (const url of inScope) {
    if (result.scanned.length >= budget) {
      result.skipped.push(url);
      continue;
    }

    let res: FetchTextResult;
    try {
      res = await opts.fetchText(url);
    } catch {
      result.skipped.push(url);
      continue;
    }
    if (res.status !== 200 || !res.body) {
      result.skipped.push(url);
      continue;
    }
    result.scanned.push(url);

    // Endpoints + API bases.
    const extraction = extractEndpointsFromJs(res.body);
    for (const ep of extraction.endpoints) {
      const method = ep.method ?? "GET";
      const value = `${method} ${ep.path}`;
      const existing = endpointsByValue.get(value.toLowerCase());
      if (existing) continue;
      endpointsByValue.set(value.toLowerCase(), {
        kind: "endpoint",
        value,
        source: url,
        metadata: { method, path: ep.path, origin: "js-recon" },
      });
    }
    for (const base of extraction.apiBaseUrls) apiBases.add(base);

    // Secrets (reuse the canonical js-artifacts scanner; already redacted).
    for (const hit of scanBody(url, res.body)) {
      const key = `${hit.kind}::${hit.match}::${hit.chunk}`;
      if (secretSeen.has(key)) continue;
      secretSeen.add(key);
      result.secrets.push(hit);
    }
  }

  result.endpoints = [...endpointsByValue.values()];
  result.apiBaseUrls = [...apiBases];
  return result;
}
