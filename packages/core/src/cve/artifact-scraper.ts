/**
 * CVE artifact scraper — finds public PoC artifacts, write-ups, and
 * affected-version metadata for a given CVE identifier by hitting a
 * curated set of public catalogues in order:
 *
 *   1. NVD                       — description + reference URLs (tagged)
 *   2. GitHub Security Advisories — references + advisory identifiers
 *   3. OSV.dev                    — fallback if GHSA returns empty
 *   4. Distro trackers            — Ubuntu USN + Red Hat CSAF (URL-pattern)
 *   5. GitHub PoC search          — repositories + code search
 *
 * Each source has its own timeout + retry policy and is allowed to fail
 * independently — the function never throws; instead it returns a
 * `CveArtifacts` shape with whatever it managed to collect plus a
 * `sources[]` log so the caller can see which sources hit / missed /
 * rate-limited.
 *
 * Responses are cached on disk at `~/.0sec/cve-cache/<source>/<hash>.json`
 * with a 24h TTL (override via `opts.cacheTtlMs`, or skip the cache with
 * `opts.cache: false`). The cache is keyed on `(source, query)` so an
 * NVD lookup for CVE-2024-1086 and a GitHub search for the same CVE
 * each get their own entry.
 *
 * Network adapter is injectable (`opts.fetchImpl`) for tests. The default
 * is the global `fetch` shim that ships with Node 20+ — same pattern as
 * `wp-fingerprint.ts` and `audit.ts`.
 *
 * Out of scope for this slice:
 *   - Downloading / building / running PoC source — that depends on the
 *     Tier-1 plumbing on issue #271 and lives in the next slice
 *   - SemVer-style affected-range *evaluation*; we surface the raw ranges
 *     so the caller can match them against the local kernel/userland
 */

import { createHash } from "node:crypto";
import { homeStateDir } from "@0sec/shared";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

// ────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────

export type PocSource = "github" | "gist" | "inline-writeup" | "distro-tracker";
export type PocLanguage = "c" | "python" | "syz" | "shell" | "unknown";

export interface PocCandidate {
  /** Direct URL to the artifact (repo, gist, raw file, advisory page). */
  url: string;
  /** Which source flagged this candidate. */
  source: PocSource;
  /** 0.0–1.0 heuristic confidence that this is a real, runnable PoC. */
  confidence: number;
  /** Best-effort language guess from filename / repo metadata. */
  language?: PocLanguage;
  /** Optional human-readable label (repo full name, gist owner, etc.). */
  label?: string;
  /** Star count when the source provides it — used by the ranker. */
  stars?: number;
  /** ISO timestamp of the last activity, when available. */
  updatedAt?: string;
}

export interface AffectedVersionRange {
  /** Package / product name, e.g. "linux_kernel", "nginx". */
  product?: string;
  /** Vendor when distinct from product. */
  vendor?: string;
  /** Free-form version constraint string, e.g. "<6.6.46". */
  range: string;
  /** Origin source for this range row. */
  source: "nvd" | "ghsa" | "osv" | "ubuntu" | "redhat";
}

export interface SourceFetched {
  /** Canonical source name. */
  source: "nvd" | "ghsa" | "osv" | "ubuntu" | "redhat" | "github-search";
  /** URL we hit (or the cache key for it). */
  url: string;
  /** "ok" | "miss" | "rate-limited" | "error" | "cached". */
  status: "ok" | "miss" | "rate-limited" | "error" | "cached" | "skipped";
  /** HTTP status when applicable. */
  httpStatus?: number;
  /** Error message when status="error". */
  error?: string;
  /** Wall-time in ms (0 for cache hits). */
  durationMs: number;
}

export interface CveArtifacts {
  cve_id: string;
  description?: string;
  /** ISO date when the CVE was first published, when known. */
  published?: string;
  /** Write-up / advisory URLs gathered across sources. */
  writeup_urls: string[];
  /** Candidate proof-of-concept artifacts, ranked by confidence desc. */
  poc_urls: PocCandidate[];
  /** Affected ranges (deduped). */
  affected: AffectedVersionRange[];
  /** Per-source fetch log — never empty (always reports each attempt). */
  sources: SourceFetched[];
}

// ────────────────────────────────────────────────────────────────────
// Internals — types
// ────────────────────────────────────────────────────────────────────

export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
  json: () => Promise<unknown>;
  headers?: { get: (name: string) => string | null };
}>;

export interface FindCveArtifactsOptions {
  /** Override the cache directory (default `~/.0sec/cve-cache`). */
  cacheDir?: string;
  /** Disable cache entirely (default true = cache on). */
  cache?: boolean;
  /** Cache TTL in milliseconds (default 24h). */
  cacheTtlMs?: number;
  /** Per-request timeout (default 10_000 ms). */
  timeoutMs?: number;
  /** Maximum number of retries per source on transient failure (default 2). */
  retries?: number;
  /** Initial retry backoff in ms (default 250; exponential * 2^n). */
  backoffMs?: number;
  /** GitHub token; falls back to `process.env.GITHUB_TOKEN`. */
  githubToken?: string;
  /** Injectable fetch — defaults to globalThis.fetch. */
  fetchImpl?: FetchLike;
  /** Injectable clock (ms since epoch) — for cache-TTL tests. */
  now?: () => number;
  /** Skip the GitHub PoC search step — useful in tests / low-quota runs. */
  skipGithubPocSearch?: boolean;
}

interface FetchJsonResult<T> {
  data?: T;
  status: number;
  ok: boolean;
  error?: string;
  rateLimited?: boolean;
  cached?: boolean;
  durationMs: number;
}

// ────────────────────────────────────────────────────────────────────
// CVE id validation
// ────────────────────────────────────────────────────────────────────

/** Canonicalise a CVE id to upper-case. Throws on obviously malformed input. */
export function normaliseCveId(input: string): string {
  const trimmed = input.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(trimmed)) {
    throw new Error(`invalid CVE id: ${JSON.stringify(input)}`);
  }
  return trimmed;
}

// ────────────────────────────────────────────────────────────────────
// Cache layer
// ────────────────────────────────────────────────────────────────────

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;

function defaultCacheDir(): string {
  return join(homeStateDir(), "cve-cache");
}

function cacheKey(source: string, query: string): string {
  const h = createHash("sha256").update(query).digest("hex").slice(0, 24);
  return `${source}/${h}.json`;
}

function readCache<T>(
  cacheDir: string,
  source: string,
  query: string,
  now: number,
  ttlMs: number,
): T | undefined {
  const file = join(cacheDir, cacheKey(source, query));
  if (!existsSync(file)) return undefined;
  try {
    const raw = readFileSync(file, "utf8");
    const parsed = JSON.parse(raw) as { savedAt: number; payload: T };
    if (typeof parsed.savedAt !== "number") return undefined;
    if (now - parsed.savedAt > ttlMs) return undefined;
    return parsed.payload;
  } catch {
    return undefined;
  }
}

function writeCache<T>(
  cacheDir: string,
  source: string,
  query: string,
  now: number,
  payload: T,
): void {
  const file = join(cacheDir, cacheKey(source, query));
  try {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    writeFileSync(file, JSON.stringify({ savedAt: now, payload }), {
      mode: 0o600,
    });
  } catch {
    // Cache is best-effort. A read-only homedir is fine; just skip.
  }
}

// ────────────────────────────────────────────────────────────────────
// HTTP with timeout + retry + cache
// ────────────────────────────────────────────────────────────────────

interface FetchPlumbingOptions {
  fetchImpl: FetchLike;
  timeoutMs: number;
  retries: number;
  backoffMs: number;
  now: () => number;
  cacheDir?: string;
  ttlMs: number;
  source: string;
  /** Cache identity key — typically `${method} ${url}|${body?}`. */
  cacheQuery: string;
  /** Bypass cache entirely. */
  noCache?: boolean;
  init?: { method?: string; headers?: Record<string, string>; body?: string };
  /** Treat 404 as "miss" (not error). Default true. */
  treat404AsMiss?: boolean;
}

async function fetchJsonWithRetry<T = unknown>(
  url: string,
  opts: FetchPlumbingOptions,
): Promise<FetchJsonResult<T>> {
  const treat404AsMiss = opts.treat404AsMiss ?? true;

  // Cache read (synchronous, fast)
  if (opts.cacheDir && !opts.noCache) {
    const hit = readCache<T>(
      opts.cacheDir,
      opts.source,
      opts.cacheQuery,
      opts.now(),
      opts.ttlMs,
    );
    if (hit !== undefined) {
      return { data: hit, ok: true, status: 200, cached: true, durationMs: 0 };
    }
  }

  let lastErr: string | undefined;
  let lastStatus = 0;
  let attempt = 0;
  const start = opts.now();

  // total attempts = 1 initial + retries
  while (attempt <= opts.retries) {
    attempt += 1;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeoutMs);
    try {
      const res = await opts.fetchImpl(url, {
        ...(opts.init ?? {}),
        // AbortSignal isn't part of the FetchLike contract above, but
        // the real fetch honours it; for mock fetches it's a no-op.
        ...({ signal: controller.signal } as Record<string, unknown>),
      });
      clearTimeout(timer);
      lastStatus = res.status;

      // 404 means "this CVE/repo isn't here" — that's a miss, not a retry.
      if (treat404AsMiss && res.status === 404) {
        return {
          ok: false,
          status: 404,
          durationMs: opts.now() - start,
        };
      }

      // 429 / 403 with rate-limit headers → don't retry hard, surface as
      // a soft rate-limited result so the caller can degrade gracefully.
      if (res.status === 429) {
        return {
          ok: false,
          status: 429,
          rateLimited: true,
          error: "rate limited",
          durationMs: opts.now() - start,
        };
      }
      // GitHub uses 403 + X-RateLimit-Remaining: 0 for unauthenticated rate limits.
      if (res.status === 403) {
        const remaining = res.headers?.get?.("x-ratelimit-remaining");
        if (remaining === "0") {
          return {
            ok: false,
            status: 403,
            rateLimited: true,
            error: "GitHub API rate limit (set GITHUB_TOKEN to lift)",
            durationMs: opts.now() - start,
          };
        }
      }

      // 5xx → retry with backoff
      if (res.status >= 500 && res.status < 600) {
        lastErr = `HTTP ${res.status}`;
        if (attempt <= opts.retries) {
          await delay(opts.backoffMs * Math.pow(2, attempt - 1));
          continue;
        }
        return {
          ok: false,
          status: res.status,
          error: lastErr,
          durationMs: opts.now() - start,
        };
      }

      if (!res.ok) {
        return {
          ok: false,
          status: res.status,
          error: `HTTP ${res.status}`,
          durationMs: opts.now() - start,
        };
      }

      // Happy path
      const data = (await res.json()) as T;
      if (opts.cacheDir && !opts.noCache) {
        writeCache(opts.cacheDir, opts.source, opts.cacheQuery, opts.now(), data);
      }
      return {
        data,
        ok: true,
        status: res.status,
        durationMs: opts.now() - start,
      };
    } catch (err) {
      clearTimeout(timer);
      lastErr = err instanceof Error ? err.message : String(err);
      if (attempt <= opts.retries) {
        await delay(opts.backoffMs * Math.pow(2, attempt - 1));
        continue;
      }
      return {
        ok: false,
        status: lastStatus,
        error: lastErr,
        durationMs: opts.now() - start,
      };
    }
  }

  return {
    ok: false,
    status: lastStatus,
    error: lastErr ?? "exhausted retries",
    durationMs: opts.now() - start,
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    if (ms <= 0) resolve();
    else setTimeout(resolve, ms);
  });
}

// ────────────────────────────────────────────────────────────────────
// Source: NVD
// ────────────────────────────────────────────────────────────────────

interface NvdReference {
  url: string;
  source?: string;
  tags?: string[];
}

interface NvdCveItem {
  cve?: {
    id?: string;
    published?: string;
    descriptions?: Array<{ lang: string; value: string }>;
    references?: NvdReference[];
    configurations?: Array<{
      nodes?: Array<{
        cpeMatch?: Array<{
          vulnerable?: boolean;
          criteria?: string;
          versionStartIncluding?: string;
          versionStartExcluding?: string;
          versionEndIncluding?: string;
          versionEndExcluding?: string;
        }>;
      }>;
    }>;
  };
}

interface NvdResponse {
  vulnerabilities?: NvdCveItem[];
}

export function parseNvdResponse(json: NvdResponse, cveId: string): {
  description?: string;
  published?: string;
  references: NvdReference[];
  affected: AffectedVersionRange[];
} {
  const item = (json.vulnerabilities ?? []).find(
    (v) => v.cve?.id?.toUpperCase() === cveId,
  );
  if (!item?.cve) {
    return { references: [], affected: [] };
  }
  const description = (item.cve.descriptions ?? []).find(
    (d) => d.lang === "en",
  )?.value;
  const references = item.cve.references ?? [];
  const affected: AffectedVersionRange[] = [];
  for (const cfg of item.cve.configurations ?? []) {
    for (const node of cfg.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (m.vulnerable === false) continue;
        const range = renderCpeRange(m);
        if (!range) continue;
        const parsed = parseCpeUri(m.criteria);
        affected.push({
          vendor: parsed?.vendor,
          product: parsed?.product,
          range,
          source: "nvd",
        });
      }
    }
  }
  return {
    description,
    published: item.cve.published,
    references,
    affected,
  };
}

function renderCpeRange(m: {
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
  criteria?: string;
}): string | undefined {
  const parts: string[] = [];
  if (m.versionStartIncluding) parts.push(`>=${m.versionStartIncluding}`);
  if (m.versionStartExcluding) parts.push(`>${m.versionStartExcluding}`);
  if (m.versionEndIncluding) parts.push(`<=${m.versionEndIncluding}`);
  if (m.versionEndExcluding) parts.push(`<${m.versionEndExcluding}`);
  if (parts.length === 0 && m.criteria) {
    // No bounds — emit the CPE itself
    return m.criteria;
  }
  return parts.join(",");
}

function parseCpeUri(uri?: string): { vendor: string; product: string } | undefined {
  if (!uri) return undefined;
  // cpe:2.3:o:linux:linux_kernel:6.6.0:*:*:*:*:*:*:*
  const parts = uri.split(":");
  if (parts.length < 6) return undefined;
  return { vendor: parts[3] ?? "", product: parts[4] ?? "" };
}

async function fetchNvd(
  cveId: string,
  plumbing: Omit<FetchPlumbingOptions, "source" | "cacheQuery">,
  log: SourceFetched[],
): Promise<{
  description?: string;
  published?: string;
  references: NvdReference[];
  affected: AffectedVersionRange[];
}> {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
  const result = await fetchJsonWithRetry<NvdResponse>(url, {
    ...plumbing,
    source: "nvd",
    cacheQuery: `GET ${url}`,
  });
  log.push({
    source: "nvd",
    url,
    status: result.cached
      ? "cached"
      : result.ok
        ? "ok"
        : result.status === 404
          ? "miss"
          : result.rateLimited
            ? "rate-limited"
            : "error",
    httpStatus: result.status || undefined,
    error: result.error,
    durationMs: result.durationMs,
  });
  if (!result.ok || !result.data) {
    return { references: [], affected: [] };
  }
  return parseNvdResponse(result.data, cveId);
}

// ────────────────────────────────────────────────────────────────────
// Source: GitHub Security Advisories
// ────────────────────────────────────────────────────────────────────

interface GhsaAdvisory {
  ghsa_id?: string;
  cve_id?: string;
  summary?: string;
  description?: string;
  published_at?: string;
  html_url?: string;
  references?: string[] | Array<{ url: string }>;
  identifiers?: Array<{ type?: string; value?: string }>;
  vulnerabilities?: Array<{
    package?: { name?: string; ecosystem?: string };
    vulnerable_version_range?: string;
  }>;
}

export function parseGhsaResponse(json: unknown, cveId: string): {
  description?: string;
  published?: string;
  references: string[];
  affected: AffectedVersionRange[];
} {
  // `/advisories?cve_id=` returns an array.
  const items: GhsaAdvisory[] = Array.isArray(json)
    ? (json as GhsaAdvisory[])
    : json && typeof json === "object" && "advisories" in (json as Record<string, unknown>)
      ? ((json as { advisories: GhsaAdvisory[] }).advisories ?? [])
      : [];
  if (items.length === 0) return { references: [], affected: [] };

  // Pick the one matching the CVE if multiple
  const adv =
    items.find((it) => (it.cve_id ?? "").toUpperCase() === cveId) ?? items[0];

  const references = normaliseGhsaRefs(adv.references);
  const affected: AffectedVersionRange[] = [];
  for (const v of adv.vulnerabilities ?? []) {
    if (!v.vulnerable_version_range) continue;
    affected.push({
      product: v.package?.name,
      range: v.vulnerable_version_range,
      source: "ghsa",
    });
  }
  return {
    description: adv.summary ?? adv.description,
    published: adv.published_at,
    references,
    affected,
  };
}

function normaliseGhsaRefs(
  refs: GhsaAdvisory["references"],
): string[] {
  if (!refs) return [];
  if (Array.isArray(refs)) {
    return refs
      .map((r) => (typeof r === "string" ? r : r?.url ?? ""))
      .filter((s) => s.length > 0);
  }
  return [];
}

async function fetchGhsa(
  cveId: string,
  plumbing: Omit<FetchPlumbingOptions, "source" | "cacheQuery">,
  githubToken: string | undefined,
  log: SourceFetched[],
): Promise<{
  description?: string;
  published?: string;
  references: string[];
  affected: AffectedVersionRange[];
}> {
  const url = `https://api.github.com/advisories?cve_id=${encodeURIComponent(cveId)}`;
  const headers: Record<string, string> = {
    accept: "application/vnd.github+json",
    "user-agent": "0sec-cve-scraper",
  };
  if (githubToken) headers.authorization = `Bearer ${githubToken}`;
  const result = await fetchJsonWithRetry<unknown>(url, {
    ...plumbing,
    source: "ghsa",
    cacheQuery: `GET ${url}`,
    init: { method: "GET", headers },
  });
  log.push({
    source: "ghsa",
    url,
    status: result.cached
      ? "cached"
      : result.ok
        ? "ok"
        : result.status === 404
          ? "miss"
          : result.rateLimited
            ? "rate-limited"
            : "error",
    httpStatus: result.status || undefined,
    error: result.error,
    durationMs: result.durationMs,
  });
  if (!result.ok || !result.data) {
    return { references: [], affected: [] };
  }
  return parseGhsaResponse(result.data, cveId);
}

// ────────────────────────────────────────────────────────────────────
// Source: OSV.dev (fallback)
// ────────────────────────────────────────────────────────────────────

interface OsvVuln {
  id?: string;
  summary?: string;
  details?: string;
  published?: string;
  references?: Array<{ type?: string; url: string }>;
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
  aliases?: string[];
}

export function parseOsvResponse(json: OsvVuln): {
  description?: string;
  published?: string;
  references: string[];
  affected: AffectedVersionRange[];
} {
  const references: string[] = (json.references ?? [])
    .map((r) => r.url)
    .filter((u): u is string => typeof u === "string" && u.length > 0);
  const affected: AffectedVersionRange[] = [];
  for (const aff of json.affected ?? []) {
    for (const rng of aff.ranges ?? []) {
      const parts: string[] = [];
      for (const ev of rng.events ?? []) {
        if (ev.introduced && ev.introduced !== "0") parts.push(`>=${ev.introduced}`);
        if (ev.fixed) parts.push(`<${ev.fixed}`);
        if (ev.last_affected) parts.push(`<=${ev.last_affected}`);
      }
      if (parts.length === 0) continue;
      affected.push({
        product: aff.package?.name,
        range: parts.join(","),
        source: "osv",
      });
    }
  }
  return {
    description: json.summary ?? json.details,
    published: json.published,
    references,
    affected,
  };
}

async function fetchOsv(
  cveId: string,
  plumbing: Omit<FetchPlumbingOptions, "source" | "cacheQuery">,
  log: SourceFetched[],
): Promise<{
  description?: string;
  published?: string;
  references: string[];
  affected: AffectedVersionRange[];
}> {
  const url = `https://api.osv.dev/v1/vulns/${encodeURIComponent(cveId)}`;
  const result = await fetchJsonWithRetry<OsvVuln>(url, {
    ...plumbing,
    source: "osv",
    cacheQuery: `GET ${url}`,
  });
  log.push({
    source: "osv",
    url,
    status: result.cached
      ? "cached"
      : result.ok
        ? "ok"
        : result.status === 404
          ? "miss"
          : result.rateLimited
            ? "rate-limited"
            : "error",
    httpStatus: result.status || undefined,
    error: result.error,
    durationMs: result.durationMs,
  });
  if (!result.ok || !result.data) {
    return { references: [], affected: [] };
  }
  return parseOsvResponse(result.data);
}

// ────────────────────────────────────────────────────────────────────
// Source: Distro trackers (Ubuntu USN + Red Hat CSAF)
//
// Both of these track a vendor-specific advisory ID that we derive from
// the references collected in earlier sources. We don't go fishing —
// we only follow URLs whose pattern unambiguously says "this is the
// distro's CSAF/USN JSON endpoint for this CVE".
// ────────────────────────────────────────────────────────────────────

/** Extract Ubuntu USN advisory URLs from a list of reference URLs. */
export function findUbuntuTrackerUrls(refs: string[]): string[] {
  const out = new Set<string>();
  for (const ref of refs) {
    // ubuntu.com/security/notices/USN-XXXX-Y (HTML) → JSON sibling
    const m = ref.match(/ubuntu\.com\/security\/notices\/(USN-[A-Z0-9-]+)/i);
    if (m) out.add(`https://ubuntu.com/security/notices/${m[1]}.json`);
  }
  return [...out];
}

/** Extract Red Hat CSAF JSON URLs from a list of reference URLs. */
export function findRedHatTrackerUrls(refs: string[], cveId: string): string[] {
  const out = new Set<string>();
  for (const ref of refs) {
    // access.redhat.com/security/cve/CVE-... (HTML) → CSAF sibling
    const m = ref.match(/access\.redhat\.com\/security\/cve\/(CVE-[\d-]+)/i);
    if (m) {
      out.add(`https://access.redhat.com/hydra/rest/securitydata/cve/${m[1]}.json`);
    }
  }
  // If we have the CVE id but no reference, still emit the canonical URL
  // — Red Hat keeps a JSON entry for every CVE they've triaged, and
  // 404s degrade gracefully.
  if (out.size === 0) {
    out.add(`https://access.redhat.com/hydra/rest/securitydata/cve/${cveId}.json`);
  }
  return [...out];
}

interface UbuntuUsn {
  id?: string;
  title?: string;
  description?: string;
  published?: string;
  releases?: Record<
    string,
    {
      sources?: Record<string, { version?: string; description?: string }>;
    }
  >;
  references?: string[];
}

export function parseUbuntuTracker(json: UbuntuUsn): {
  references: string[];
  affected: AffectedVersionRange[];
} {
  const refs: string[] = (json.references ?? []).filter(
    (s): s is string => typeof s === "string" && s.length > 0,
  );
  const affected: AffectedVersionRange[] = [];
  for (const [release, payload] of Object.entries(json.releases ?? {})) {
    for (const [pkg, info] of Object.entries(payload?.sources ?? {})) {
      if (!info?.version) continue;
      affected.push({
        product: pkg,
        vendor: `ubuntu/${release}`,
        range: `<${info.version}`,
        source: "ubuntu",
      });
    }
  }
  return { references: refs, affected };
}

interface RedHatCsaf {
  bugzilla?: { description?: string; id?: string; url?: string };
  details?: string[];
  references?: string[];
  affected_release?: Array<{
    product_name?: string;
    package?: string;
    release_date?: string;
    advisory?: string;
  }>;
  package_state?: Array<{
    product_name?: string;
    fix_state?: string;
    package_name?: string;
  }>;
}

export function parseRedHatTracker(json: RedHatCsaf): {
  references: string[];
  affected: AffectedVersionRange[];
} {
  const refs = new Set<string>();
  if (json.bugzilla?.url) refs.add(json.bugzilla.url);
  for (const u of json.references ?? []) {
    if (typeof u === "string" && u.length > 0) refs.add(u);
  }
  const affected: AffectedVersionRange[] = [];
  for (const rel of json.affected_release ?? []) {
    if (!rel.package) continue;
    affected.push({
      product: rel.package,
      vendor: rel.product_name ?? "redhat",
      range: `fixed in ${rel.package}`,
      source: "redhat",
    });
  }
  return { references: [...refs], affected };
}

async function fetchUbuntu(
  url: string,
  plumbing: Omit<FetchPlumbingOptions, "source" | "cacheQuery">,
  log: SourceFetched[],
): Promise<{ references: string[]; affected: AffectedVersionRange[] }> {
  const result = await fetchJsonWithRetry<UbuntuUsn>(url, {
    ...plumbing,
    source: "ubuntu",
    cacheQuery: `GET ${url}`,
  });
  log.push({
    source: "ubuntu",
    url,
    status: result.cached
      ? "cached"
      : result.ok
        ? "ok"
        : result.status === 404
          ? "miss"
          : result.rateLimited
            ? "rate-limited"
            : "error",
    httpStatus: result.status || undefined,
    error: result.error,
    durationMs: result.durationMs,
  });
  if (!result.ok || !result.data) return { references: [], affected: [] };
  return parseUbuntuTracker(result.data);
}

async function fetchRedHat(
  url: string,
  plumbing: Omit<FetchPlumbingOptions, "source" | "cacheQuery">,
  log: SourceFetched[],
): Promise<{ references: string[]; affected: AffectedVersionRange[] }> {
  const result = await fetchJsonWithRetry<RedHatCsaf>(url, {
    ...plumbing,
    source: "redhat",
    cacheQuery: `GET ${url}`,
  });
  log.push({
    source: "redhat",
    url,
    status: result.cached
      ? "cached"
      : result.ok
        ? "ok"
        : result.status === 404
          ? "miss"
          : result.rateLimited
            ? "rate-limited"
            : "error",
    httpStatus: result.status || undefined,
    error: result.error,
    durationMs: result.durationMs,
  });
  if (!result.ok || !result.data) return { references: [], affected: [] };
  return parseRedHatTracker(result.data);
}

// ────────────────────────────────────────────────────────────────────
// Source: GitHub PoC search (repositories + code)
// ────────────────────────────────────────────────────────────────────

interface GithubRepo {
  full_name?: string;
  html_url?: string;
  description?: string;
  stargazers_count?: number;
  language?: string;
  pushed_at?: string;
  updated_at?: string;
  fork?: boolean;
}

interface GithubReposSearch {
  total_count?: number;
  items?: GithubRepo[];
}

interface GithubCodeItem {
  name?: string;
  path?: string;
  html_url?: string;
  repository?: GithubRepo;
}

interface GithubCodeSearch {
  total_count?: number;
  items?: GithubCodeItem[];
}

/**
 * Score a candidate PoC repository: stars (log), recency, filename match,
 * fork penalty. Returns a 0–1 confidence.
 */
export function scoreRepoCandidate(repo: GithubRepo, cveId: string): {
  confidence: number;
  language?: PocLanguage;
} {
  const stars = repo.stargazers_count ?? 0;
  let score = 0;

  // Base from stars: log so a 1000-star repo doesn't trivially outrank a
  // freshly published 5-star single-author PoC.
  score += Math.min(0.5, Math.log10(stars + 1) / 4);

  // Filename / name match
  const name = (repo.full_name ?? "").toLowerCase();
  const desc = (repo.description ?? "").toLowerCase();
  const cveLower = cveId.toLowerCase();
  if (name.includes(cveLower)) score += 0.35;
  else if (desc.includes(cveLower)) score += 0.15;
  if (/poc|exploit|reproducer/.test(name)) score += 0.12;
  else if (/poc|exploit|reproducer/.test(desc)) score += 0.06;

  // Fork penalty
  if (repo.fork) score -= 0.2;

  // Recency: half-life ~ 2 years.
  if (repo.pushed_at) {
    const updated = Date.parse(repo.pushed_at);
    if (Number.isFinite(updated)) {
      const ageDays = (Date.now() - updated) / 86_400_000;
      if (ageDays < 30) score += 0.08;
      else if (ageDays < 365) score += 0.04;
      else if (ageDays > 365 * 3) score -= 0.05;
    }
  }

  const language = languageFromHint(repo.language);
  return { confidence: clamp01(score), language };
}

export function scoreCodeCandidate(item: GithubCodeItem, cveId: string): {
  confidence: number;
  language?: PocLanguage;
} {
  const name = (item.name ?? "").toLowerCase();
  const path = (item.path ?? "").toLowerCase();
  const cveLower = cveId.toLowerCase();
  let score = 0;

  // Filename heuristics: poc.c / exploit.c / <cve>.c are strong signals
  if (name === "poc.c" || name === "exploit.c") score += 0.4;
  if (name === `${cveLower}.c`) score += 0.5;
  if (name.includes(cveLower)) score += 0.2;
  if (/poc|exploit/.test(path)) score += 0.1;

  // Stars on the parent repo (log scale)
  const stars = item.repository?.stargazers_count ?? 0;
  score += Math.min(0.3, Math.log10(stars + 1) / 5);

  // Fork penalty
  if (item.repository?.fork) score -= 0.2;

  return {
    confidence: clamp01(score),
    language: languageFromFilename(name) ?? "c",
  };
}

function languageFromHint(lang?: string): PocLanguage | undefined {
  if (!lang) return undefined;
  const l = lang.toLowerCase();
  if (l === "c" || l === "c++") return "c";
  if (l === "python") return "python";
  if (l === "shell" || l === "sh" || l === "bash") return "shell";
  return "unknown";
}

function languageFromFilename(name: string): PocLanguage | undefined {
  if (name.endsWith(".c") || name.endsWith(".cpp") || name.endsWith(".cc"))
    return "c";
  if (name.endsWith(".py")) return "python";
  if (name.endsWith(".syz") || name.endsWith(".syzprog")) return "syz";
  if (name.endsWith(".sh") || name.endsWith(".bash")) return "shell";
  return undefined;
}

function clamp01(n: number): number {
  if (!Number.isFinite(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

async function fetchGithubPocSearch(
  cveId: string,
  plumbing: Omit<FetchPlumbingOptions, "source" | "cacheQuery">,
  githubToken: string | undefined,
  log: SourceFetched[],
): Promise<PocCandidate[]> {
  const headers: Record<string, string> = {
    accept: "application/vnd.github+json",
    "user-agent": "0sec-cve-scraper",
  };
  if (githubToken) headers.authorization = `Bearer ${githubToken}`;

  const candidates: PocCandidate[] = [];

  // Repos
  const reposUrl = `https://api.github.com/search/repositories?q=${encodeURIComponent(cveId)}`;
  const repos = await fetchJsonWithRetry<GithubReposSearch>(reposUrl, {
    ...plumbing,
    source: "github-search",
    cacheQuery: `GET ${reposUrl}`,
    init: { method: "GET", headers },
  });
  log.push({
    source: "github-search",
    url: reposUrl,
    status: repos.cached
      ? "cached"
      : repos.ok
        ? "ok"
        : repos.rateLimited
          ? "rate-limited"
          : repos.status === 404
            ? "miss"
            : "error",
    httpStatus: repos.status || undefined,
    error: repos.error,
    durationMs: repos.durationMs,
  });
  if (repos.ok && repos.data) {
    for (const r of repos.data.items ?? []) {
      const { confidence, language } = scoreRepoCandidate(r, cveId);
      if (confidence <= 0 || !r.html_url) continue;
      candidates.push({
        url: r.html_url,
        source: "github",
        confidence,
        language,
        label: r.full_name,
        stars: r.stargazers_count,
        updatedAt: r.pushed_at ?? r.updated_at,
      });
    }
  }

  // Code (.c filenames). We don't ask for every extension — `.c` is the
  // most common PoC file extension for the kernel/userland CVEs this
  // scraper is targeted at. If the cve is non-C, the repo result above
  // covers it.
  const codeUrl = `https://api.github.com/search/code?q=${encodeURIComponent(`${cveId} in:file filename:*.c`)}`;
  // Code search REQUIRES auth.
  if (githubToken) {
    const code = await fetchJsonWithRetry<GithubCodeSearch>(codeUrl, {
      ...plumbing,
      source: "github-search",
      cacheQuery: `GET ${codeUrl}`,
      init: { method: "GET", headers },
    });
    log.push({
      source: "github-search",
      url: codeUrl,
      status: code.cached
        ? "cached"
        : code.ok
          ? "ok"
          : code.rateLimited
            ? "rate-limited"
            : code.status === 404
              ? "miss"
              : "error",
      httpStatus: code.status || undefined,
      error: code.error,
      durationMs: code.durationMs,
    });
    if (code.ok && code.data) {
      for (const item of code.data.items ?? []) {
        const { confidence, language } = scoreCodeCandidate(item, cveId);
        if (confidence <= 0 || !item.html_url) continue;
        candidates.push({
          url: item.html_url,
          source: "github",
          confidence,
          language,
          label: `${item.repository?.full_name ?? ""}:${item.path ?? item.name ?? ""}`,
          stars: item.repository?.stargazers_count,
          updatedAt: item.repository?.pushed_at,
        });
      }
    }
  } else {
    log.push({
      source: "github-search",
      url: codeUrl,
      status: "skipped",
      durationMs: 0,
      error: "code search requires GITHUB_TOKEN",
    });
  }

  return candidates;
}

// ────────────────────────────────────────────────────────────────────
// Reference splitting: inline-writeup PoCs vs write-ups vs distro URLs
// ────────────────────────────────────────────────────────────────────

/**
 * From a flat list of reference URLs (potentially tagged), pull out:
 *   - PoC candidates that point at github.com / gist.github.com directly
 *   - Write-up URLs (everything else that looks textual)
 */
export function classifyReferences(
  refs: Array<NvdReference | string>,
  source: PocSource = "inline-writeup",
): { pocs: PocCandidate[]; writeups: string[] } {
  const pocs: PocCandidate[] = [];
  const writeups: string[] = [];

  for (const refRaw of refs) {
    const url = typeof refRaw === "string" ? refRaw : refRaw.url;
    if (!url) continue;
    const tags = typeof refRaw === "string" ? [] : refRaw.tags ?? [];
    const lowered = url.toLowerCase();

    // GitHub repository / gist references inside NVD/GHSA referenced URLs
    // are very high-signal PoC candidates.
    if (/^https?:\/\/(www\.)?github\.com\/[^/]+\/[^/]+/.test(url)) {
      // The /commit/, /blob/, /pull/ and /security/ subpaths are patches
      // or advisories, not PoCs.
      const isPatch = /\/(commit|pull|blob|security|advisories)\//i.test(url);
      if (!isPatch || tags.includes("Exploit")) {
        pocs.push({
          url,
          source: "github",
          confidence: tags.includes("Exploit") ? 0.85 : 0.5,
          language: languageFromFilename(url.toLowerCase()) ?? undefined,
        });
      }
      writeups.push(url);
      continue;
    }

    if (/^https?:\/\/gist\.github\.com\//.test(url)) {
      pocs.push({
        url,
        source: "gist",
        confidence: tags.includes("Exploit") ? 0.8 : 0.55,
      });
      writeups.push(url);
      continue;
    }

    // Anything tagged "Exploit" but not on github → still a PoC candidate
    if (tags.includes("Exploit")) {
      pocs.push({ url, source, confidence: 0.7 });
    }

    writeups.push(url);
    void lowered;
  }

  return { pocs, writeups };
}

// ────────────────────────────────────────────────────────────────────
// Public entry: findCveArtifacts
// ────────────────────────────────────────────────────────────────────

export async function findCveArtifacts(
  cveIdInput: string,
  opts: FindCveArtifactsOptions = {},
): Promise<CveArtifacts> {
  const cveId = normaliseCveId(cveIdInput);
  const cache = opts.cache !== false;
  const cacheDir = cache ? opts.cacheDir ?? defaultCacheDir() : undefined;
  const ttlMs = opts.cacheTtlMs ?? DEFAULT_TTL_MS;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const retries = opts.retries ?? 2;
  const backoffMs = opts.backoffMs ?? 250;
  const now = opts.now ?? (() => Date.now());
  const fetchImpl =
    opts.fetchImpl ??
    (globalThis.fetch as unknown as FetchLike | undefined);

  if (!fetchImpl) {
    return {
      cve_id: cveId,
      writeup_urls: [],
      poc_urls: [],
      affected: [],
      sources: [
        {
          source: "nvd",
          url: "",
          status: "error",
          error: "no fetch impl available",
          durationMs: 0,
        },
      ],
    };
  }

  const githubToken = opts.githubToken ?? process.env.GITHUB_TOKEN;
  const log: SourceFetched[] = [];
  const plumbing: Omit<FetchPlumbingOptions, "source" | "cacheQuery"> = {
    fetchImpl,
    timeoutMs,
    retries,
    backoffMs,
    now,
    cacheDir,
    ttlMs,
    noCache: !cache,
  };

  // 1. NVD
  const nvd = await fetchNvd(cveId, plumbing, log);

  // 2. GHSA
  const ghsa = await fetchGhsa(cveId, plumbing, githubToken, log);

  // 3. OSV (only if GHSA empty)
  let osvOut: {
    description?: string;
    published?: string;
    references: string[];
    affected: AffectedVersionRange[];
  } = { references: [], affected: [] };
  if (ghsa.references.length === 0 && ghsa.affected.length === 0) {
    osvOut = await fetchOsv(cveId, plumbing, log);
  } else {
    log.push({
      source: "osv",
      url: `https://api.osv.dev/v1/vulns/${cveId}`,
      status: "skipped",
      durationMs: 0,
      error: "GHSA had hits — OSV fallback skipped",
    });
  }

  // Reference splitting on the merged set
  const allRefsNvd: NvdReference[] = nvd.references;
  const allRefsString: string[] = [...ghsa.references, ...osvOut.references];

  const nvdSplit = classifyReferences(allRefsNvd, "inline-writeup");
  const otherSplit = classifyReferences(allRefsString, "inline-writeup");

  // 4. Distro trackers (best-effort)
  const flatRefs: string[] = [
    ...allRefsString,
    ...allRefsNvd.map((r) => r.url),
  ];
  const ubuntuUrls = findUbuntuTrackerUrls(flatRefs);
  const redHatUrls = findRedHatTrackerUrls(flatRefs, cveId);

  const distroResults = await Promise.all([
    ...ubuntuUrls.map((u) => fetchUbuntu(u, plumbing, log)),
    ...redHatUrls.map((u) => fetchRedHat(u, plumbing, log)),
  ]);

  // 5. GitHub PoC search
  const ghSearchCandidates = opts.skipGithubPocSearch
    ? []
    : await fetchGithubPocSearch(cveId, plumbing, githubToken, log);

  // Merge everything
  const description = nvd.description ?? ghsa.description ?? osvOut.description;
  const published = nvd.published ?? ghsa.published ?? osvOut.published;

  const writeup_urls = uniqueStrings([
    ...nvdSplit.writeups,
    ...otherSplit.writeups,
    ...distroResults.flatMap((d) => d.references),
  ]);

  // PoCs from reference classification (high-trust because curated) +
  // PoCs from GitHub search (heuristic).
  const allPocs: PocCandidate[] = [
    ...nvdSplit.pocs.map((p) => ({ ...p, source: p.source })),
    ...otherSplit.pocs,
    ...ghSearchCandidates,
  ];
  const poc_urls = dedupePocs(allPocs).sort(
    (a, b) => b.confidence - a.confidence,
  );

  const affected = dedupeAffected([
    ...nvd.affected,
    ...ghsa.affected,
    ...osvOut.affected,
    ...distroResults.flatMap((d) => d.affected),
  ]);

  return {
    cve_id: cveId,
    description,
    published,
    writeup_urls,
    poc_urls,
    affected,
    sources: log,
  };
}

function uniqueStrings(arr: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const s of arr) {
    if (!s || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

function dedupePocs(pocs: PocCandidate[]): PocCandidate[] {
  const byUrl = new Map<string, PocCandidate>();
  for (const p of pocs) {
    const existing = byUrl.get(p.url);
    if (!existing) {
      byUrl.set(p.url, p);
      continue;
    }
    // Keep the higher-confidence record; merge metadata.
    const merged: PocCandidate = {
      ...existing,
      confidence: Math.max(existing.confidence, p.confidence),
      language: existing.language ?? p.language,
      label: existing.label ?? p.label,
      stars: existing.stars ?? p.stars,
      updatedAt: existing.updatedAt ?? p.updatedAt,
    };
    byUrl.set(p.url, merged);
  }
  return [...byUrl.values()];
}

function dedupeAffected(rows: AffectedVersionRange[]): AffectedVersionRange[] {
  const seen = new Set<string>();
  const out: AffectedVersionRange[] = [];
  for (const r of rows) {
    const key = `${r.source}|${r.vendor ?? ""}|${r.product ?? ""}|${r.range}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}
