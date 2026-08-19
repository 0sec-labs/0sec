// Recon mode — surface enumeration for a domain/org (pwnkit#769, #924).
//
// Given a domain, probe a set of well-known OpenAPI/Swagger paths and MCP
// endpoints, extract API endpoints from any spec found, enumerate subdomains
// (passive CT+DNS always; active wordlist brute-force when explicitly turned
// on), and emit a deduped, structured asset inventory as JSON. The shape is
// designed to be consumable as `discovered_assets`.
//
// Active subdomain brute-force (#924) is OFF by default and gated behind an
// authorized `ScopePolicy` + a wall-clock kill-switch — see
// `./active-subdomains.ts`. When enabled, its resolving hosts merge into the
// same subdomain-asset stream and dedupe against the passive results.

import { parseApiSpec, type ApiSpecSummary } from "../api-spec.js";
import type { ScopePolicy } from "../scope/scope.js";
import {
  enumerateSubdomains as enumerateDiscoveredHosts,
  type DiscoveredHost,
  type EnumerateSubdomainsOptions,
} from "./subdomains.js";
import {
  enumerateSubdomainsActive,
  type ActiveEnumerateOptions,
} from "./active-subdomains.js";

/** Kinds of asset the recon surface can surface. */
export type ReconAssetKind =
  | "subdomain"
  | "endpoint"
  | "openapi_spec"
  | "swagger_ui"
  | "mcp_server";

/**
 * A single discovered asset. Flat, JSON-serializable, and stable enough to
 * be consumed directly as a `discovered_assets` row. The `(kind, value)`
 * pair is the dedup key.
 */
export interface ReconAsset {
  kind: ReconAssetKind;
  /** Canonical identifier — a URL, host, or `METHOD /path` for endpoints. */
  value: string;
  /** Where this asset was found (probe URL, parent host, etc.). */
  source: string;
  /** Free-form, kind-specific extras (HTTP method, spec title, …). */
  metadata?: Record<string, string>;
}

export interface ReconResult {
  domain: string;
  generatedAt: string;
  assets: ReconAsset[];
  summary: {
    total: number;
    byKind: Record<string, number>;
  };
  /** Non-fatal problems encountered while probing (timeouts, parse errors). */
  warnings: string[];
}

export interface ReconOptions {
  /** Per-request timeout in ms. Default 10s. */
  timeout?: number;
  /** Override the candidate OpenAPI/Swagger paths to probe. */
  specPaths?: string[];
  /** Override the candidate MCP endpoint paths to probe. */
  mcpPaths?: string[];
  /**
   * Injectable fetch — defaults to global `fetch`. Lets tests drive the
   * network surface deterministically without hitting the wire.
   */
  fetchImpl?: typeof fetch;
  /**
   * Active subdomain brute-force config (pwnkit#924). OFF by default: omit it
   * (or leave `enabled` unset/false) and recon stays purely passive. When
   * enabled, the resolving hosts merge into the subdomain asset stream and
   * dedupe against the passive (CT+DNS) results. Every candidate is gated by
   * `scope` + a wall-clock kill-switch — see `enumerateSubdomainsActive`.
   */
  activeSubdomains?: Pick<
    ActiveEnumerateOptions,
    "enabled" | "scope" | "wordlist" | "resolve" | "concurrency" | "maxDurationMs" | "now"
  >;
}

/** Well-known locations where OpenAPI / Swagger specs commonly live. */
export const DEFAULT_SPEC_PATHS: readonly string[] = [
  "/openapi.json",
  "/openapi.yaml",
  "/swagger.json",
  "/swagger/v1/swagger.json",
  "/v2/api-docs",
  "/v3/api-docs",
  "/api-docs",
  "/api/openapi.json",
  "/api/v3/openapi.json",
  "/.well-known/openapi.json",
];

/** Well-known MCP HTTP transport mount points. */
export const DEFAULT_MCP_PATHS: readonly string[] = ["/mcp", "/sse", "/mcp/sse"];

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Normalize a user-supplied domain into an `https://host` origin (no path,
 * no trailing slash). Accepts bare hosts (`example.com`), `host:port`, and
 * full URLs (scheme is preserved when given).
 */
export function normalizeDomain(domain: string): string {
  const trimmed = domain.trim();
  if (!trimmed) throw new Error("recon: empty domain");
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error(`recon: invalid domain '${domain}'`);
  }
  return `${url.protocol}//${url.host}`;
}

/**
 * Build a stable dedup key for an asset. Endpoints and subdomains are
 * case-insensitive on the value; the URL/path is otherwise compared verbatim.
 */
function assetKey(asset: ReconAsset): string {
  return `${asset.kind}::${asset.value.toLowerCase()}`;
}

/**
 * Deduplicate assets by `(kind, value)`. On collision the first occurrence
 * wins, but its `metadata` is shallow-merged with later duplicates so a
 * second sighting can enrich (never overwrite) the first. Order is preserved.
 *
 * This is the heart of the recon pipeline and the primary unit-tested unit.
 */
export function dedupeAssets(assets: ReconAsset[]): ReconAsset[] {
  const byKey = new Map<string, ReconAsset>();
  for (const asset of assets) {
    const key = assetKey(asset);
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...asset, metadata: asset.metadata ? { ...asset.metadata } : undefined });
      continue;
    }
    if (asset.metadata) {
      existing.metadata = { ...asset.metadata, ...(existing.metadata ?? {}) };
    }
  }
  return [...byKey.values()];
}

/**
 * Turn a parsed OpenAPI/Swagger summary into endpoint + spec assets. The
 * spec itself becomes one `openapi_spec` asset; every operation becomes an
 * `endpoint` asset keyed by `METHOD /path`.
 */
export function apiSpecToAssets(spec: ApiSpecSummary, sourceUrl: string): ReconAsset[] {
  const assets: ReconAsset[] = [
    {
      kind: "openapi_spec",
      value: sourceUrl,
      source: sourceUrl,
      metadata: {
        title: spec.title,
        version: spec.version,
        ...(spec.baseUrl ? { baseUrl: spec.baseUrl } : {}),
        endpointCount: String(spec.endpoints.length),
      },
    },
  ];
  for (const ep of spec.endpoints) {
    assets.push({
      kind: "endpoint",
      value: `${ep.method} ${ep.path}`,
      source: sourceUrl,
      metadata: {
        method: ep.method,
        path: ep.path,
        ...(ep.summary ? { summary: ep.summary } : {}),
        ...(ep.auth?.length ? { auth: ep.auth.join(",") } : {}),
      },
    });
  }
  return assets;
}

/**
 * Parse a raw spec body (JSON or YAML) into an `ApiSpecSummary`. We reuse the
 * battle-tested `parseApiSpec`, which only reads from disk, by routing the
 * in-memory body through a temp file. Returns `undefined` if the body is not
 * a recognizable OpenAPI/Swagger document.
 */
async function parseSpecBody(body: string): Promise<ApiSpecSummary | undefined> {
  const { writeFileSync, rmSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "pwnkit-recon-"));
  // .json vs .yaml only affects nothing in parseApiSpec (it sniffs content),
  // but a stable extension keeps the temp path predictable.
  const file = join(dir, "spec.json");
  try {
    writeFileSync(file, body, "utf-8");
    return await parseApiSpec(file);
  } catch {
    return undefined;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function fetchText(
  fetchImpl: typeof fetch,
  url: string,
  timeout: number,
  init?: RequestInit,
): Promise<{ status: number; body: string } | { error: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetchImpl(url, { ...init, signal: controller.signal });
    const body = await res.text();
    return { status: res.status, body };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Probe candidate OpenAPI/Swagger paths under `origin`. Any 2xx body that
 * parses as a spec yields an `openapi_spec` asset plus one `endpoint` asset
 * per operation.
 */
async function discoverApiSpecs(
  origin: string,
  paths: readonly string[],
  timeout: number,
  fetchImpl: typeof fetch,
  warnings: string[],
): Promise<ReconAsset[]> {
  const assets: ReconAsset[] = [];
  for (const path of paths) {
    const url = `${origin}${path}`;
    const res = await fetchText(fetchImpl, url, timeout, {
      headers: { Accept: "application/json, application/yaml, text/yaml, */*" },
    });
    if ("error" in res) {
      warnings.push(`spec probe ${url}: ${res.error}`);
      continue;
    }
    if (res.status < 200 || res.status >= 300 || !res.body.trim()) continue;
    const spec = await parseSpecBody(res.body);
    if (!spec) continue;
    assets.push(...apiSpecToAssets(spec, url));
  }
  return assets;
}

/**
 * Probe candidate MCP endpoints under `origin`. A reachable endpoint (any
 * non-network-error response) is recorded as an `mcp_server` asset; we do not
 * attempt the full MCP handshake here (that is `discoverMcpTarget`'s job in
 * scan mode).
 */
async function discoverMcpServers(
  origin: string,
  paths: readonly string[],
  timeout: number,
  fetchImpl: typeof fetch,
  warnings: string[],
): Promise<ReconAsset[]> {
  const assets: ReconAsset[] = [];
  for (const path of paths) {
    const url = `${origin}${path}`;
    const res = await fetchText(fetchImpl, url, timeout, {
      headers: { Accept: "application/json, text/event-stream" },
    });
    if ("error" in res) {
      warnings.push(`mcp probe ${url}: ${res.error}`);
      continue;
    }
    // 404 means "not an MCP mount"; anything else (200/400/405/406) signals a
    // live handler worth flagging for the scanner to follow up with mcp://.
    if (res.status === 404) continue;
    assets.push({
      kind: "mcp_server",
      value: url,
      source: origin,
      metadata: { status: String(res.status) },
    });
  }
  return assets;
}

/** Map a `DiscoveredHost` (passive or active) onto a `subdomain` ReconAsset. */
function hostToAsset(host: DiscoveredHost): ReconAsset {
  return {
    kind: "subdomain",
    value: host.host,
    source: host.source,
    metadata: {
      ...(host.addresses?.length ? { addresses: host.addresses.join(",") } : {}),
      ...(host.cname ? { cname: host.cname } : {}),
    },
  };
}

/**
 * Passive subdomain enumeration (pwnkit#769, wired to `./subdomains.ts`).
 *
 * Delegates to the CT-log + DNS enumerator and maps each discovered host onto
 * a `subdomain` ReconAsset. The CT/DNS layer is passive (no brute-force) and
 * degrades gracefully to an empty list on failure, so this keeps the existing
 * `(domain) => Promise<ReconAsset[]>` contract and never throws.
 */
export async function enumerateSubdomains(
  domain: string,
  hooks?: Pick<EnumerateSubdomainsOptions, "fetchJson" | "resolve">,
): Promise<ReconAsset[]> {
  let apex: string;
  try {
    apex = new URL(normalizeDomain(domain)).hostname;
  } catch {
    return [];
  }
  let hosts: DiscoveredHost[];
  try {
    hosts = await enumerateDiscoveredHosts({ domain: apex, ...hooks });
  } catch {
    return [];
  }
  return hosts.map(hostToAsset);
}

/**
 * Run recon against a single domain. Enumerates subdomains (passive CT+DNS
 * always, active brute-force when `activeSubdomains.enabled` is set + scoped),
 * probes OpenAPI/Swagger specs and MCP endpoints, then returns a deduped,
 * structured asset inventory consumable as `discovered_assets`.
 */
export async function runRecon(domain: string, options: ReconOptions = {}): Promise<ReconResult> {
  const origin = normalizeDomain(domain);
  const apex = new URL(origin).hostname;
  const timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = options.fetchImpl ?? fetch;
  const specPaths = options.specPaths ?? DEFAULT_SPEC_PATHS;
  const mcpPaths = options.mcpPaths ?? DEFAULT_MCP_PATHS;
  const warnings: string[] = [];

  const collected: ReconAsset[] = [];
  // Route subdomain enumeration's CT-log fetch through the same injectable
  // `fetchImpl` so callers (and tests) stay deterministic/offline. A custom
  // fetch that 404s or throws on the crt.sh URL yields zero candidates, so the
  // passive resolver is never invoked.
  const subdomainHooks =
    options.fetchImpl
      ? {
          fetchJson: async (url: string) => {
            const res = await fetchImpl(url);
            return res.json();
          },
        }
      : undefined;
  const passiveHosts = await enumerateSubdomains(domain, subdomainHooks);
  collected.push(...passiveHosts);

  // Active subdomain brute-force (pwnkit#924). OFF unless the caller opted in
  // AND supplied an authorized scope policy — `enumerateSubdomainsActive`
  // enforces both rails internally and returns [] otherwise, so an
  // unauthorized/unconfigured run never issues a DNS query. Seed permutations
  // off whatever the passive pass already found.
  const active = options.activeSubdomains;
  if (active?.enabled) {
    try {
      const knownHosts = passiveHosts.map((a) => a.value);
      const activeHosts = await enumerateSubdomainsActive({
        domain: apex,
        knownHosts,
        ...active,
      });
      collected.push(...activeHosts.map(hostToAsset));
    } catch (err) {
      warnings.push(
        `active subdomain enum: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  collected.push(...(await discoverApiSpecs(origin, specPaths, timeout, fetchImpl, warnings)));
  collected.push(...(await discoverMcpServers(origin, mcpPaths, timeout, fetchImpl, warnings)));

  const assets = dedupeAssets(collected);

  const byKind: Record<string, number> = {};
  for (const asset of assets) byKind[asset.kind] = (byKind[asset.kind] ?? 0) + 1;

  return {
    domain: origin,
    generatedAt: new Date().toISOString(),
    assets,
    summary: { total: assets.length, byKind },
    warnings,
  };
}
