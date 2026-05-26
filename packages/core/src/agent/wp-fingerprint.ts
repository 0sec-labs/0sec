/**
 * WordPress fingerprinter — tool-side implementation.
 *
 * Pure-HTTP reconnaissance module that:
 *   1. Confirms the target is WordPress and extracts the core version
 *   2. Enumerates installed plugins (HTML source, REST API, directory listing)
 *   3. Enumerates installed themes
 *   4. Detects plugin / theme versions via their shipped readme.txt files
 *   5. Looks up known CVEs for each (slug, version) pair via the OSV API
 *
 * The module is intentionally framework-agnostic: it takes a `fetchImpl`
 * parameter (defaulting to globalThis.fetch) so the unit tests can substitute
 * a deterministic mock without ever touching the network.
 *
 * Exposed to the agent as the `wp_fingerprint` tool, gated behind the
 * `wpFingerprint` feature flag so it does not run on every challenge.
 */

import { getCveExploit, formatExploitRecipe } from "./cve-exploit-codex.js";
import {
  WP_VULNERABLE_PLUGIN_SLUGS,
  compareVersions,
  findWpVulnerabilities,
  type WpVulnerabilityMatch,
} from "./wp-vuln-db.js";

// ── Types ──

export interface WpPlugin {
  /** Plugin slug (matches the /wp-content/plugins/<slug>/ directory name). */
  slug: string;
  /** Version extracted from readme.txt if available, else undefined. */
  version?: string;
  /** Where the plugin was discovered. */
  source: "html" | "rest_api" | "directory_listing" | "readme" | "vulnerable_catalog";
}

export interface WpTheme {
  slug: string;
  version?: string;
  source: "html" | "rest_api" | "directory_listing" | "style_css";
}

export interface WpCveHit {
  id: string;
  aliases: string[];
  severity?: string;
  summary?: string;
  url?: string;
  source?: "osv" | "local_catalog" | "wpvulnerability" | "wpscan";
}

export interface WpFinding {
  kind: "plugin" | "theme";
  slug: string;
  version?: string;
  source: string;
  cves: WpCveHit[];
  exploitHints: string[];
}

export interface WpFingerprintResult {
  isWordPress: boolean;
  /** Which endpoints confirmed WordPress. */
  evidence: string[];
  /** Core WordPress version if detected. */
  coreVersion?: string;
  plugins: WpPlugin[];
  themes: WpTheme[];
  /** Aggregated per-(plugin|theme, version) CVE findings. */
  findings: WpFinding[];
}

export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  text: () => Promise<string>;
  json: () => Promise<unknown>;
}>;

export interface WpFingerprintOptions {
  /** Base target URL (scheme + host). Trailing slash optional. */
  target: string;
  /** Injectable fetch for tests. Defaults to globalThis.fetch. */
  fetchImpl?: FetchLike;
  /** Per-request timeout, milliseconds. Default 10_000. */
  timeoutMs?: number;
  /** Maximum number of plugins to probe for a readme.txt. Default 40. */
  maxPluginProbes?: number;
  /** Maximum high-value vulnerable plugin slugs to probe proactively. Default 40. */
  maxVulnerablePluginProbes?: number;
  /** Skip OSV lookups (useful in tests to avoid network). Default false. */
  skipOsv?: boolean;
  /** Optional WPScan API token for fresh WordPress vulnerability lookups. */
  wpScanApiToken?: string;
  /** Optional auth headers to include with every probe. */
  headers?: Record<string, string>;
}

// ── Public entry point ──

export async function runWpFingerprint(
  opts: WpFingerprintOptions,
): Promise<WpFingerprintResult> {
  const base = normalizeBase(opts.target);
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxProbes = opts.maxPluginProbes ?? 40;
  const maxVulnerableProbes = opts.maxVulnerablePluginProbes ?? 40;
  const wpScanApiToken = opts.wpScanApiToken?.trim();

  const result: WpFingerprintResult = {
    isWordPress: false,
    evidence: [],
    plugins: [],
    themes: [],
    findings: [],
  };

  // ── Step 1: Detect WordPress + core version ──
  const detection = await detectWordPress(base, fetchImpl, timeoutMs, opts.headers);
  result.isWordPress = detection.isWordPress;
  result.evidence = detection.evidence;
  result.coreVersion = detection.coreVersion;

  if (!result.isWordPress) {
    return result;
  }

  // ── Step 2: Enumerate plugins (parallel sources) ──
  const pluginSlugs = new Map<string, WpPlugin>();
  const themeSlugs = new Map<string, WpTheme>();

  const [htmlSources, restPlugins, pluginDirListing, themeDirListing] = await Promise.all([
    collectFromHomepage(base, fetchImpl, timeoutMs, opts.headers),
    collectFromRestApi(base, fetchImpl, timeoutMs, opts.headers),
    collectFromDirListing(base, "plugins", fetchImpl, timeoutMs, opts.headers),
    collectFromDirListing(base, "themes", fetchImpl, timeoutMs, opts.headers),
  ]);

  for (const slug of htmlSources.plugins) {
    pluginSlugs.set(slug, { slug, source: "html" });
  }
  for (const slug of htmlSources.themes) {
    themeSlugs.set(slug, { slug, source: "html" });
  }
  for (const slug of restPlugins) {
    if (!pluginSlugs.has(slug)) pluginSlugs.set(slug, { slug, source: "rest_api" });
  }
  for (const slug of pluginDirListing) {
    if (!pluginSlugs.has(slug)) pluginSlugs.set(slug, { slug, source: "directory_listing" });
  }
  for (const slug of themeDirListing) {
    if (!themeSlugs.has(slug)) themeSlugs.set(slug, { slug, source: "directory_listing" });
  }

  // ── Step 3: WPScan-style high-value vulnerable plugin probes ──
  const catalogPlugins = await probeVulnerablePluginCatalog(
    base,
    pluginSlugs,
    maxVulnerableProbes,
    fetchImpl,
    timeoutMs,
    opts.headers,
  );
  for (const plugin of catalogPlugins) {
    pluginSlugs.set(plugin.slug, plugin);
  }

  // ── Step 4: Version probes (readme.txt for plugins, style.css for themes) ──
  const allPlugins = [...pluginSlugs.values()];
  const pluginList = [
    ...allPlugins.filter((p) => p.source === "vulnerable_catalog"),
    ...allPlugins.filter((p) => p.source !== "vulnerable_catalog"),
  ].slice(0, maxProbes);
  await Promise.all(
    pluginList.map(async (p) => {
      if (p.version) return;
      const version = await probePluginVersion(base, p.slug, fetchImpl, timeoutMs, opts.headers);
      if (version) {
        p.version = version;
        if (p.source === "html" || p.source === "rest_api") {
          p.source = "readme"; // upgrade — readme.txt is a stronger signal
        }
      }
    }),
  );

  const themeList = [...themeSlugs.values()].slice(0, maxProbes);
  await Promise.all(
    themeList.map(async (t) => {
      const version = await probeThemeVersion(base, t.slug, fetchImpl, timeoutMs, opts.headers);
      if (version) {
        t.version = version;
        if (t.source === "html" || t.source === "rest_api") {
          t.source = "style_css";
        }
      }
    }),
  );

  result.plugins = pluginList;
  result.themes = themeList;

  // ── Step 5: local WordPress vuln catalog + live CVE lookups ──
  const all: Array<{ kind: "plugin" | "theme"; slug: string; version?: string; source: string }> =
    [
      ...pluginList.map((p) => ({ kind: "plugin" as const, slug: p.slug, version: p.version, source: p.source })),
      ...themeList.map((t) => ({ kind: "theme" as const, slug: t.slug, version: t.version, source: t.source })),
    ];

  if (!opts.skipOsv) {
    result.findings = await Promise.all(
      all.map(async (entry) => {
        const localMatches = entry.kind === "plugin"
          ? findWpVulnerabilities(entry.slug, entry.version)
          : [];
        const wpVulnerabilityCves = await queryWpVulnerabilityForWordPress(
          entry.kind,
          entry.slug,
          entry.version,
          fetchImpl,
          timeoutMs,
        );
        const wpScanCves = wpScanApiToken
          ? await queryWpScanForWordPress(entry.kind, entry.slug, entry.version, wpScanApiToken, fetchImpl, timeoutMs)
          : [];
        const osvCves = await queryOsvForWordPress(entry.slug, entry.version, fetchImpl, timeoutMs);
        const cves = mergeCveHits(localMatchesToCves(localMatches), wpVulnerabilityCves, wpScanCves, osvCves);
        return {
          kind: entry.kind,
          slug: entry.slug,
          version: entry.version,
          source: entry.source,
          cves,
          exploitHints: buildExploitHints(entry.slug, cves, localMatches),
        };
      }),
    );
  } else {
    result.findings = await Promise.all(all.map(async (entry) => {
      const localMatches = entry.kind === "plugin"
        ? findWpVulnerabilities(entry.slug, entry.version)
        : [];
      const wpVulnerabilityCves = await queryWpVulnerabilityForWordPress(
        entry.kind,
        entry.slug,
        entry.version,
        fetchImpl,
        timeoutMs,
      );
      const wpScanCves = wpScanApiToken
        ? await queryWpScanForWordPress(entry.kind, entry.slug, entry.version, wpScanApiToken, fetchImpl, timeoutMs)
        : [];
      const cves = mergeCveHits(localMatchesToCves(localMatches), wpVulnerabilityCves, wpScanCves);
      return {
        kind: entry.kind,
        slug: entry.slug,
        version: entry.version,
        source: entry.source,
        cves,
        exploitHints: buildExploitHints(entry.slug, cves, localMatches),
      };
    }));
  }

  return result;
}

// ── Step 1: WordPress detection ──

interface DetectionResult {
  isWordPress: boolean;
  evidence: string[];
  coreVersion?: string;
}

async function detectWordPress(
  base: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
  headers?: Record<string, string>,
): Promise<DetectionResult> {
  const probes = [
    "wp-login.php",
    "wp-admin/",
    "readme.html",
    "wp-includes/version.php",
    "feed/",
    "wp-json/",
  ];

  const evidence: string[] = [];
  let coreVersion: string | undefined;

  const results = await Promise.all(
    probes.map((path) => safeGet(`${base}/${path}`, fetchImpl, timeoutMs, headers)),
  );

  for (let i = 0; i < probes.length; i++) {
    const res = results[i];
    if (!res) continue;
    const path = probes[i];

    if (path === "wp-login.php" && res.ok && /wp-submit|user_login|wp-login/i.test(res.body)) {
      evidence.push("wp-login.php");
    }
    if (path === "wp-admin/" && (res.status === 200 || res.status === 302 || res.status === 301)) {
      // Redirects to wp-login.php are a strong WP signal
      evidence.push("wp-admin/");
    }
    if (path === "readme.html" && res.ok) {
      const m = res.body.match(/Version\s+(\d+\.\d+(?:\.\d+)?)/i);
      if (m || /wordpress/i.test(res.body)) {
        evidence.push("readme.html");
        if (m) coreVersion = m[1];
      }
    }
    if (path === "wp-includes/version.php" && res.ok) {
      const m = res.body.match(/\$wp_version\s*=\s*['"]([\d.]+)['"]/);
      if (m) {
        evidence.push("wp-includes/version.php");
        coreVersion = m[1];
      }
    }
    if (path === "feed/" && res.ok) {
      const m = res.body.match(/<generator>\s*https?:\/\/wordpress\.org\/\?v=([\d.]+)/i);
      if (m) {
        evidence.push("feed/");
        if (!coreVersion) coreVersion = m[1];
      } else if (/wordpress/i.test(res.body)) {
        evidence.push("feed/");
      }
    }
    if (path === "wp-json/" && res.ok && /"namespace"|wp\/v2/.test(res.body)) {
      evidence.push("wp-json/");
    }
  }

  return {
    isWordPress: evidence.length >= 1,
    evidence,
    coreVersion,
  };
}

// ── Step 2: Plugin / theme enumeration ──

interface HomepageCollect {
  plugins: Set<string>;
  themes: Set<string>;
}

async function collectFromHomepage(
  base: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
  headers?: Record<string, string>,
): Promise<HomepageCollect> {
  const plugins = new Set<string>();
  const themes = new Set<string>();

  const pages = ["", "?p=1", "?page_id=1", "?p=2"];
  const results = await Promise.all(
    pages.map((p) => safeGet(`${base}/${p}`, fetchImpl, timeoutMs, headers)),
  );
  for (const res of results) {
    if (!res || !res.ok) continue;
    parsePluginsFromHtml(res.body, plugins);
    parseThemesFromHtml(res.body, themes);
  }

  return { plugins, themes };
}

/** Extract plugin slugs from HTML source. Exposed for testing. */
export function parsePluginsFromHtml(html: string, out: Set<string>): void {
  const re = /\/wp-content\/plugins\/([a-zA-Z0-9_\-]+)\//g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    out.add(m[1]);
  }
}

/** Extract theme slugs from HTML source. Exposed for testing. */
export function parseThemesFromHtml(html: string, out: Set<string>): void {
  const re = /\/wp-content\/themes\/([a-zA-Z0-9_\-]+)\//g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    out.add(m[1]);
  }
}

async function collectFromRestApi(
  base: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
  headers?: Record<string, string>,
): Promise<Set<string>> {
  const plugins = new Set<string>();

  // /wp-json/wp/v2/ index — plugin-provided namespaces leak slugs
  const root = await safeGet(`${base}/wp-json/`, fetchImpl, timeoutMs, headers);
  if (root?.ok) {
    try {
      const data = JSON.parse(root.body) as { namespaces?: string[] };
      if (Array.isArray(data.namespaces)) {
        for (const ns of data.namespaces) {
          // "contact-form-7/v1" -> "contact-form-7". Skip the core "wp/v2"
          const slug = ns.split("/")[0];
          if (slug && slug !== "wp" && slug !== "oembed") {
            plugins.add(slug);
          }
        }
      }
    } catch {
      // Non-JSON — skip
    }
  }

  // Posts endpoint — rendered content often leaks plugin asset URLs
  const posts = await safeGet(`${base}/wp-json/wp/v2/posts?per_page=5`, fetchImpl, timeoutMs, headers);
  if (posts?.ok) {
    parsePluginsFromHtml(posts.body, plugins);
  }

  return plugins;
}

async function collectFromDirListing(
  base: string,
  kind: "plugins" | "themes",
  fetchImpl: FetchLike,
  timeoutMs: number,
  headers?: Record<string, string>,
): Promise<Set<string>> {
  const out = new Set<string>();
  const res = await safeGet(`${base}/wp-content/${kind}/`, fetchImpl, timeoutMs, headers);
  if (!res?.ok) return out;
  // Apache/nginx autoindex — look for <a href="slug/">slug/</a>
  const re = /<a\s+href="([a-zA-Z0-9_\-]+)\/?">/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(res.body)) !== null) {
    const slug = m[1];
    if (slug === ".." || slug === ".") continue;
    out.add(slug);
  }
  return out;
}

// ── Step 3: vulnerable plugin catalog probing ──

async function probeVulnerablePluginCatalog(
  base: string,
  knownPlugins: Map<string, WpPlugin>,
  maxProbes: number,
  fetchImpl: FetchLike,
  timeoutMs: number,
  headers?: Record<string, string>,
): Promise<WpPlugin[]> {
  const candidates = WP_VULNERABLE_PLUGIN_SLUGS
    .filter((slug) => !knownPlugins.has(slug))
    .slice(0, Math.max(0, maxProbes));

  const probed: Array<WpPlugin | null> = await Promise.all(
    candidates.map(async (slug) => {
      const version = await probePluginVersion(base, slug, fetchImpl, timeoutMs, headers);
      return version
        ? { slug, version, source: "vulnerable_catalog" as const }
        : null;
    }),
  );

  return probed.filter((plugin): plugin is WpPlugin => plugin !== null);
}

// ── Step 4: Version probing ──

async function probePluginVersion(
  base: string,
  slug: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
  headers?: Record<string, string>,
): Promise<string | undefined> {
  const res = await safeGet(
    `${base}/wp-content/plugins/${slug}/readme.txt`,
    fetchImpl,
    timeoutMs,
    headers,
  );
  if (!res?.ok) return undefined;
  return parseReadmeVersion(res.body);
}

/** Parse the "Stable tag:" line from a WordPress plugin readme.txt. Exposed for tests. */
export function parseReadmeVersion(body: string): string | undefined {
  // Prefer "Stable tag: X.Y.Z" — WordPress convention for the released version.
  const stable = body.match(/^\s*Stable\s+tag:\s*([0-9][0-9A-Za-z._\-]*)/im);
  if (stable) return stable[1].trim();
  // Fallback: "Version: X.Y.Z"
  const ver = body.match(/^\s*Version:\s*([0-9][0-9A-Za-z._\-]*)/im);
  if (ver) return ver[1].trim();
  return undefined;
}

async function probeThemeVersion(
  base: string,
  slug: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
  headers?: Record<string, string>,
): Promise<string | undefined> {
  const res = await safeGet(
    `${base}/wp-content/themes/${slug}/style.css`,
    fetchImpl,
    timeoutMs,
    headers,
  );
  if (!res?.ok) return undefined;
  return parseStyleCssVersion(res.body);
}

/** Parse the "Version:" header from a WordPress theme style.css. Exposed for tests. */
export function parseStyleCssVersion(body: string): string | undefined {
  const m = body.match(/^\s*Version:\s*([0-9][0-9A-Za-z._\-]*)/im);
  return m ? m[1].trim() : undefined;
}

// ── Step 4: OSV lookup ──

/**
 * Query the OSV API for advisories matching a WordPress plugin/theme slug.
 *
 * OSV does not (yet) have a dedicated "WordPress" ecosystem, so we issue an
 * ecosystem-less query keyed on the slug. That returns every advisory whose
 * package name matches, which in practice surfaces the wpvulndb / Patchstack
 * entries imported into OSV.
 */
export async function queryOsvForWordPress(
  slug: string,
  version: string | undefined,
  fetchImpl: FetchLike,
  timeoutMs: number,
): Promise<WpCveHit[]> {
  try {
    const body: Record<string, unknown> = {
      package: { name: slug },
    };
    if (version) body.version = version;

    const res = await withTimeout(
      fetchImpl("https://api.osv.dev/v1/query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }),
      timeoutMs,
    );
    if (!res || !res.ok) return [];

    const json = (await res.json()) as { vulns?: Array<Record<string, unknown>> };
    const vulns = json.vulns ?? [];
    return vulns.map((v) => {
      const aliases = (v.aliases as string[] | undefined) ?? [];
      const id = (v.id as string) ?? aliases[0] ?? "UNKNOWN";
      const severity = extractSeverity(v);
      return {
        id,
        aliases,
        severity,
        summary: v.summary as string | undefined,
        url: `https://osv.dev/vulnerability/${id}`,
        source: "osv" as const,
      };
    });
  } catch {
    return [];
  }
}

function extractSeverity(vuln: Record<string, unknown>): string | undefined {
  const sev = vuln.severity as Array<{ type?: string; score?: string }> | undefined;
  if (Array.isArray(sev) && sev.length > 0) {
    const cvss = sev.find((s) => typeof s.type === "string" && /cvss/i.test(s.type));
    if (cvss?.score) return cvss.score;
    if (sev[0]?.score) return sev[0].score;
  }
  const dbSpecific = vuln.database_specific as { severity?: string } | undefined;
  if (dbSpecific?.severity) return dbSpecific.severity;
  return undefined;
}

export async function queryWpScanForWordPress(
  kind: "plugin" | "theme",
  slug: string,
  version: string | undefined,
  token: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
): Promise<WpCveHit[]> {
  if (!token.trim()) return [];
  const path = kind === "theme" ? "themes" : "plugins";
  try {
    const res = await withTimeout(
      fetchImpl(`https://wpscan.com/api/v3/${path}/${encodeURIComponent(slug)}`, {
        method: "GET",
        headers: {
          "Authorization": `Token token=${token}`,
          "Accept": "application/json",
        },
      }),
      timeoutMs,
    );
    if (!res || !res.ok) return [];

    const json = await res.json();
    const vulnerabilities = extractWpScanVulnerabilities(json, slug);
    return vulnerabilities
      .filter((vuln) => isWpScanVulnerabilityRelevant(vuln, version))
      .map((vuln) => wpScanVulnerabilityToCveHit(vuln));
  } catch {
    return [];
  }
}

export async function queryWpVulnerabilityForWordPress(
  kind: "plugin" | "theme",
  slug: string,
  version: string | undefined,
  fetchImpl: FetchLike,
  timeoutMs: number,
): Promise<WpCveHit[]> {
  const path = kind === "theme" ? "theme" : "plugin";
  try {
    const res = await withTimeout(
      fetchImpl(`https://www.wpvulnerability.net/${path}/${encodeURIComponent(slug)}/`, {
        method: "GET",
        headers: { "Accept": "application/json" },
      }),
      timeoutMs,
    );
    if (!res || !res.ok) return [];

    const json = await res.json();
    const vulnerabilities = extractWpVulnerabilityEntries(json);
    return vulnerabilities
      .filter((vuln) => isWpVulnerabilityEntryRelevant(vuln, version))
      .flatMap((vuln) => wpVulnerabilityEntryToCveHits(vuln));
  } catch {
    return [];
  }
}

function extractWpVulnerabilityEntries(json: unknown): Array<Record<string, unknown>> {
  if (!isRecord(json)) return [];
  const data = isRecord(json.data) ? json.data : json;
  const vulnerabilities = data.vulnerability ?? data.vulnerabilities;
  if (!Array.isArray(vulnerabilities)) return [];
  return vulnerabilities.filter(isRecord);
}

function isWpVulnerabilityEntryRelevant(vuln: Record<string, unknown>, version: string | undefined): boolean {
  if (!version) return true;
  const operator = isRecord(vuln.operator) ? vuln.operator : undefined;
  if (!operator) return true;
  return versionMatchesWpVulnerabilityOperator(version, operator);
}

function versionMatchesWpVulnerabilityOperator(version: string, operator: Record<string, unknown>): boolean {
  const minVersion = typeof operator.min_version === "string" ? operator.min_version : undefined;
  const minOperator = typeof operator.min_operator === "string" ? operator.min_operator : undefined;
  const maxVersion = typeof operator.max_version === "string" ? operator.max_version : undefined;
  const maxOperator = typeof operator.max_operator === "string" ? operator.max_operator : undefined;

  if (minVersion && minOperator && !compareWithOperator(version, minVersion, minOperator)) return false;
  if (maxVersion && maxOperator && !compareWithOperator(version, maxVersion, maxOperator)) return false;
  return true;
}

function compareWithOperator(version: string, boundary: string, operator: string): boolean {
  const cmp = compareVersions(version, boundary);
  switch (operator.toLowerCase()) {
    case "lt":
    case "<":
      return cmp < 0;
    case "le":
    case "lte":
    case "<=":
      return cmp <= 0;
    case "gt":
    case ">":
      return cmp > 0;
    case "ge":
    case "gte":
    case ">=":
      return cmp >= 0;
    case "eq":
    case "=":
    case "==":
      return cmp === 0;
    default:
      return true;
  }
}

function wpVulnerabilityEntryToCveHits(vuln: Record<string, unknown>): WpCveHit[] {
  const sources = Array.isArray(vuln.source) ? vuln.source.filter(isRecord) : [];
  const cveSources = sources.filter((source) => {
    const id = typeof source.id === "string" ? source.id : "";
    const name = typeof source.name === "string" ? source.name : "";
    return /^CVE-/i.test(id) || /^CVE-/i.test(name);
  });
  const selectedSources = cveSources.length > 0 ? cveSources : sources.slice(0, 1);
  if (selectedSources.length === 0) {
    const fallbackId = formatWpVulnerabilityFallbackId(vuln.uuid);
    return [{
      id: fallbackId,
      aliases: [],
      severity: extractWpVulnerabilitySeverity(vuln),
      summary: typeof vuln.name === "string" ? vuln.name : undefined,
      source: "wpvulnerability" as const,
    }];
  }

  return selectedSources.map((source) => {
    const rawId = findCveLikeString(source.id, source.name)
      ?? (typeof source.id === "string" ? source.id : undefined)
      ?? (typeof source.name === "string" ? source.name : undefined);
    const id = normalizeCveId(rawId)
      ?? formatWpVulnerabilityFallbackId(vuln.uuid);
    return {
      id,
      aliases: [],
      severity: extractWpVulnerabilitySeverity(vuln),
      summary: typeof vuln.name === "string" ? vuln.name : undefined,
      url: typeof source.link === "string" ? source.link : undefined,
      source: "wpvulnerability" as const,
    };
  });
}

function formatWpVulnerabilityFallbackId(value: unknown): string {
  if (typeof value !== "string" || value.trim().length === 0) return "WPVULNERABILITY";
  return `WPVULN-${value.trim().slice(0, 12)}`;
}

function extractWpVulnerabilitySeverity(vuln: Record<string, unknown>): string | undefined {
  const impact = isRecord(vuln.impact) ? vuln.impact : undefined;
  const cvss = impact?.cvss;
  if (typeof cvss === "string") return cvss;
  if (typeof cvss === "number") return String(cvss);
  if (typeof vuln.severity === "string") return vuln.severity;
  return undefined;
}

function extractWpScanVulnerabilities(json: unknown, slug: string): Array<Record<string, unknown>> {
  if (!json || typeof json !== "object") return [];
  const obj = json as Record<string, unknown>;
  const direct = obj.vulnerabilities;
  if (Array.isArray(direct)) return direct.filter(isRecord);

  const nested = obj[slug];
  if (isRecord(nested) && Array.isArray(nested.vulnerabilities)) {
    return nested.vulnerabilities.filter(isRecord);
  }

  const firstRecordWithVulns = Object.values(obj).find((value) => (
    isRecord(value) && Array.isArray(value.vulnerabilities)
  ));
  if (isRecord(firstRecordWithVulns)) {
    return (firstRecordWithVulns.vulnerabilities as unknown[]).filter(isRecord);
  }

  return [];
}

function isWpScanVulnerabilityRelevant(vuln: Record<string, unknown>, version: string | undefined): boolean {
  if (!version) return true;
  const fixedIn = parseWpScanFixedIn(vuln.fixed_in);
  if (fixedIn.length === 0) return true;
  return fixedIn.some((fixedVersion) => compareVersions(version, fixedVersion) < 0);
}

function parseWpScanFixedIn(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string");
  return [];
}

function wpScanVulnerabilityToCveHit(vuln: Record<string, unknown>): WpCveHit {
  const references = isRecord(vuln.references) ? vuln.references : {};
  const cveRefs = parseWpScanReferenceList(references.cve);
  const urlRefs = parseWpScanReferenceList(references.url);
  const id = normalizeCveId(cveRefs[0])
    ?? (typeof vuln.id === "string" ? vuln.id : undefined)
    ?? (typeof vuln.uuid === "string" ? vuln.uuid : undefined)
    ?? "WPSCAN";
  return {
    id,
    aliases: cveRefs.map((cve) => normalizeCveId(cve) ?? cve).filter((cve) => cve !== id),
    severity: extractWpScanSeverity(vuln),
    summary: typeof vuln.title === "string" ? vuln.title : undefined,
    url: typeof vuln.url === "string" ? vuln.url : urlRefs[0],
    source: "wpscan" as const,
  };
}

function parseWpScanReferenceList(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === "string");
  return [];
}

function normalizeCveId(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (/^CVE-\d{4}-\d{4,}$/i.test(trimmed)) return trimmed.toUpperCase();
  if (/^\d{4}-\d{4,}$/.test(trimmed)) return `CVE-${trimmed}`;
  return undefined;
}

function findCveLikeString(...values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value !== "string") continue;
    const match = value.match(/CVE-\d{4}-\d{4,}|\b\d{4}-\d{4,}\b/i);
    if (match) return match[0];
  }
  return undefined;
}

function extractWpScanSeverity(vuln: Record<string, unknown>): string | undefined {
  if (typeof vuln.cvss === "string") return vuln.cvss;
  if (typeof vuln.cvss === "number") return String(vuln.cvss);
  if (typeof vuln.severity === "string") return vuln.severity;
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function localMatchesToCves(matches: WpVulnerabilityMatch[]): WpCveHit[] {
  return matches.map((match) => ({
    id: match.cveId,
    aliases: match.aliases ?? [],
    severity: match.severity,
    summary: `${match.pluginName} ${match.affectedRange}: ${match.summary}`,
    url: match.references[0],
    source: "local_catalog" as const,
  }));
}

function mergeCveHits(...sources: WpCveHit[][]): WpCveHit[] {
  const seen = new Set<string>();
  const merged: WpCveHit[] = [];
  for (const cve of sources.flat()) {
    const key = [cve.id, ...cve.aliases].find((id) => /^CVE-\d{4}-\d+/i.test(id)) ?? cve.id;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(cve);
  }
  return merged;
}

function buildExploitHints(
  slug: string,
  cves: WpCveHit[],
  localMatches: WpVulnerabilityMatch[] = [],
): string[] {
  const hints: string[] = [];
  if (cves.length === 0) return hints;

  for (const match of localMatches) {
    for (const hint of match.exploitHints) {
      hints.push(`[local ${match.cveId}] ${hint}`);
    }
  }

  // ── Curated CVE codex pass ──
  // For each CVE we have a hand-curated exploit recipe for, prepend the full
  // formatted recipe so the agent can act on it immediately. We also check
  // GHSA aliases so an OSV record keyed on a GHSA still resolves.
  for (const cve of cves) {
    const candidates = [cve.id, ...cve.aliases];
    for (const id of candidates) {
      const recipe = getCveExploit(id);
      if (recipe) {
        hints.push(formatExploitRecipe(recipe));
        break; // one recipe per CVE
      }
    }
  }

  const summaries = cves.map((c) => (c.summary ?? "").toLowerCase()).join(" | ");
  if (/file upload|arbitrary file|upload/i.test(summaries)) {
    hints.push(
      `Try unauthenticated file upload against /wp-content/plugins/${slug}/ endpoints — check the CVE advisory for the exact path.`,
    );
  }
  if (/sql ?injection|sqli/i.test(summaries)) {
    hints.push(`Look for vulnerable parameters in /wp-admin/admin-ajax.php?action=${slug}_*.`);
  }
  if (/(unauth|unauthenticated).*rce|remote code execution/i.test(summaries)) {
    hints.push(`Unauthenticated RCE reported for ${slug} — try the PoC against the advisory-specified endpoint.`);
  }
  if (/xss|cross.site scripting/i.test(summaries)) {
    hints.push(`Stored/reflected XSS reported for ${slug} — look for the affected input on plugin-rendered pages.`);
  }
  if (/deserial/i.test(summaries)) {
    hints.push(`Deserialization gadget reported for ${slug} — inspect cookies and POST bodies for serialized payloads.`);
  }
  if (hints.length === 0) {
    hints.push(`Review OSV entries for ${slug} — ${cves.length} advisory/advisories found.`);
  }
  return hints;
}

// ── HTTP helpers ──

interface SafeGetResult {
  ok: boolean;
  status: number;
  body: string;
}

async function safeGet(
  url: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
  headers?: Record<string, string>,
): Promise<SafeGetResult | undefined> {
  try {
    const res = await withTimeout(
      fetchImpl(url, { method: "GET", headers: headers ?? {} }),
      timeoutMs,
    );
    if (!res) return undefined;
    const body = await res.text().catch(() => "");
    return { ok: res.ok, status: res.status, body };
  } catch {
    return undefined;
  }
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

function normalizeBase(target: string): string {
  return target.replace(/\/+$/, "");
}

// ── Summary helper (used by the tool wrapper to format output for the agent) ──

export function summarizeWpFingerprint(result: WpFingerprintResult): string {
  if (!result.isWordPress) {
    return "Target does not appear to be WordPress (no WP-specific endpoints detected).";
  }
  const lines: string[] = [];
  lines.push(
    `WordPress detected${result.coreVersion ? ` — core v${result.coreVersion}` : ""}. Evidence: ${result.evidence.join(", ")}`,
  );
  lines.push(`Plugins: ${result.plugins.length}, Themes: ${result.themes.length}`);
  const withCves = result.findings.filter((f) => f.cves.length > 0);
  if (withCves.length > 0) {
    lines.push("");
    lines.push(`CVE hits (${withCves.length}):`);
    for (const f of withCves) {
      const ids = f.cves.map((c) => c.id).slice(0, 5).join(", ");
      lines.push(
        `  - [${f.kind}] ${f.slug}${f.version ? `@${f.version}` : ""}: ${ids}${f.cves.length > 5 ? ` (+${f.cves.length - 5} more)` : ""}`,
      );
      for (const hint of f.exploitHints) {
        lines.push(`      hint: ${hint}`);
      }
    }
  } else {
    lines.push("No CVE matches via OSV.");
  }
  return lines.join("\n");
}
