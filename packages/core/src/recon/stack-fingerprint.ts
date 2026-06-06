// Generic web stack fingerprinting (pwnkit gap B).
//
// Pure-HTTP reconnaissance that, given a web target, identifies:
//   1. The server-side / meta framework (Next.js, Nuxt, Remix, SvelteKit, …)
//      and its version, from response headers, HTML markers, and JS bundles.
//   2. The client UI runtime (React, Vue, Angular, Svelte, …) and version.
//   3. A list of client libraries with versions, scraped from bundle banners
//      and `version:"x.y.z"` markers in fetched JS chunks.
//
// This is the generic counterpart to the WordPress-specific fingerprinter in
// `../agent/wp-fingerprint.ts`; it follows the same conventions — an
// injectable fetch so tests stay off the wire, pure exported parsers, and a
// flat JSON-serializable result shape consumable as dossier fields.
//
// No LLM calls. No live vuln-DB lookups (that is a downstream concern, fed by
// the {name, version} pairs this module produces).

// ── Types ──

/** Where a particular signal was observed. */
export type StackSignalSource =
  | "header"
  | "html"
  | "meta_generator"
  | "js_bundle"
  | "window_global";

export interface FrameworkFingerprint {
  /** Canonical framework name, e.g. "Next.js", "React", "Nuxt". */
  name: string;
  /** Detected version if one could be extracted. */
  version?: string;
  /** Strongest signal that established the framework. */
  source: StackSignalSource;
}

export interface LibraryFingerprint {
  /** Library/package name, e.g. "react", "lucide-react". */
  name: string;
  /** Detected version if one could be extracted. */
  version?: string;
  /** Where the library version was observed. */
  source: StackSignalSource;
}

export interface WebStackFingerprint {
  /** The meta/server framework, if one was identified. */
  framework?: FrameworkFingerprint;
  /** Client libraries discovered in bundles / markers, deduped by name. */
  libraries: LibraryFingerprint[];
  /** Raw human-readable signals collected, for auditing / explainability. */
  rawSignals: string[];
}

/** Minimal response shape the fingerprinter needs from a fetch. */
export interface FetchTextResult {
  status: number;
  /** Lowercased header names recommended; lookups are case-insensitive. */
  headers: Record<string, string>;
  body: string;
}

export interface FingerprintWebStackOptions {
  /** Base target URL (scheme + host, optionally a path). Trailing slash optional. */
  baseUrl: string;
  /**
   * Injectable fetch. Returns status, headers, and the body text for a URL.
   * Taken as a dependency so the unit tests never touch the network.
   */
  fetchText: (url: string) => Promise<FetchTextResult>;
  /** Maximum number of JS chunks to fetch and grep. Default 12. */
  maxChunks?: number;
}

const DEFAULT_MAX_CHUNKS = 12;

// ── Public entry point ──

/**
 * Fingerprint the web stack behind `baseUrl`.
 *
 * Flow: fetch the root HTML, inspect response headers + HTML markers for a
 * framework, enumerate a bounded number of JS chunk URLs referenced by the
 * HTML, fetch them, and grep each for framework versions, `window.*` globals,
 * and library version markers. All signals are merged and deduped.
 */
export async function fingerprintWebStack(
  opts: FingerprintWebStackOptions,
): Promise<WebStackFingerprint> {
  const base = normalizeBase(opts.baseUrl);
  const maxChunks = opts.maxChunks ?? DEFAULT_MAX_CHUNKS;

  const rawSignals: string[] = [];
  const libraries = new Map<string, LibraryFingerprint>();
  let framework: FrameworkFingerprint | undefined;

  // ── Step 1: fetch root HTML + headers ──
  const root = await safeFetch(opts.fetchText, base);
  const html = root?.body ?? "";
  const headers = normalizeHeaders(root?.headers ?? {});

  // ── Step 2: framework from headers (strongest cheap signal) ──
  const headerFw = detectFrameworkFromHeaders(headers);
  if (headerFw) {
    framework = headerFw;
    rawSignals.push(`header: ${headerFw.name}${headerFw.version ? ` v${headerFw.version}` : ""}`);
  }

  // ── Step 3: framework + libs from HTML ──
  if (html) {
    const htmlFw = detectFrameworkFromHtml(html);
    if (htmlFw) {
      rawSignals.push(`html: ${htmlFw.name}${htmlFw.version ? ` v${htmlFw.version}` : ""}`);
      framework = mergeFramework(framework, htmlFw);
    }
    for (const lib of parseLibraryBanners(html)) {
      addLibrary(libraries, lib);
      rawSignals.push(`html banner: ${lib.name}${lib.version ? ` v${lib.version}` : ""}`);
    }
  }

  // ── Step 4: enumerate + fetch JS chunks, grep for versions ──
  const chunkUrls = enumerateJsChunkUrls(html, base).slice(0, maxChunks);
  const chunkBodies = await Promise.all(
    chunkUrls.map(async (url) => ({ url, body: (await safeFetch(opts.fetchText, url))?.body ?? "" })),
  );

  for (const { url, body } of chunkBodies) {
    if (!body) continue;

    const chunkFw = detectFrameworkFromBundle(body);
    if (chunkFw) {
      rawSignals.push(`bundle ${shortUrl(url)}: ${chunkFw.name}${chunkFw.version ? ` v${chunkFw.version}` : ""}`);
      framework = mergeFramework(framework, chunkFw);
    }

    for (const lib of parseLibraryBanners(body)) {
      addLibrary(libraries, lib);
      rawSignals.push(`bundle ${shortUrl(url)} banner: ${lib.name}${lib.version ? ` v${lib.version}` : ""}`);
    }
  }

  return {
    framework,
    libraries: [...libraries.values()],
    rawSignals,
  };
}

// ── Framework detection: headers ──

/** Map of `x-powered-by` / `server` header substrings to canonical names. */
const HEADER_FRAMEWORK_HINTS: ReadonlyArray<{ pattern: RegExp; name: string }> = [
  { pattern: /Next\.js/i, name: "Next.js" },
  { pattern: /Nuxt/i, name: "Nuxt" },
  { pattern: /Express/i, name: "Express" },
  { pattern: /SvelteKit/i, name: "SvelteKit" },
  { pattern: /Remix/i, name: "Remix" },
  { pattern: /Gatsby/i, name: "Gatsby" },
  { pattern: /Astro/i, name: "Astro" },
  { pattern: /Django/i, name: "Django" },
  { pattern: /Laravel/i, name: "Laravel" },
  { pattern: /Rails|Phusion Passenger/i, name: "Ruby on Rails" },
];

/** Detect a framework from response headers. Exposed for tests. */
export function detectFrameworkFromHeaders(
  headers: Record<string, string>,
): FrameworkFingerprint | undefined {
  const lower = normalizeHeaders(headers);
  const haystack = [lower["x-powered-by"], lower["server"], lower["x-framework"]]
    .filter((v): v is string => typeof v === "string")
    .join(" | ");
  if (!haystack) return undefined;

  for (const hint of HEADER_FRAMEWORK_HINTS) {
    if (hint.pattern.test(haystack)) {
      // Some headers embed a version, e.g. "Express/4.18.2".
      const ver = haystack.match(new RegExp(`${escapeRegExp(hint.name)}[\\s/]v?(\\d+\\.\\d+(?:\\.\\d+)?)`, "i"));
      return { name: hint.name, version: ver?.[1], source: "header" };
    }
  }
  return undefined;
}

// ── Framework detection: HTML ──

/** Detect a framework from rendered HTML markers. Exposed for tests. */
export function detectFrameworkFromHtml(html: string): FrameworkFingerprint | undefined {
  // <meta name="generator" content="Next.js 15.0.7" /> and friends.
  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (gen) {
    const fw = parseGeneratorContent(gen[1]);
    if (fw) return fw;
  }

  // Next.js: presence of /_next/ asset paths or __NEXT_DATA__ blob.
  if (/\/_next\/static\//.test(html) || /id=["']__NEXT_DATA__["']/.test(html)) {
    const buildVer = html.match(/"buildId":"[^"]*"[\s\S]{0,200}?"nextExport"/);
    void buildVer; // buildId is not a semver; left for future enrichment.
    return { name: "Next.js", source: "html" };
  }

  // Nuxt: __NUXT__ hydration global or /_nuxt/ assets.
  if (/window\.__NUXT__/.test(html) || /\/_nuxt\//.test(html)) {
    return { name: "Nuxt", source: "html" };
  }

  // Gatsby: ___gatsby root node.
  if (/id=["']___gatsby["']/.test(html)) {
    return { name: "Gatsby", source: "html" };
  }

  // Generic React root with no meta-framework — weak signal, still useful.
  if (/<div[^>]+id=["']root["'][^>]*>/.test(html) && /\.chunk\.js|static\/js\//.test(html)) {
    return { name: "React", source: "html" };
  }

  return undefined;
}

/** Parse a `<meta generator>` content string into a framework. Exposed for tests. */
export function parseGeneratorContent(content: string): FrameworkFingerprint | undefined {
  for (const hint of HEADER_FRAMEWORK_HINTS) {
    if (hint.pattern.test(content)) {
      const ver = content.match(/v?(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?)/);
      return { name: hint.name, version: ver?.[1], source: "meta_generator" };
    }
  }
  return undefined;
}

// ── Framework detection: JS bundle ──

/** Detect framework name + version from a JS bundle body. Exposed for tests. */
export function detectFrameworkFromBundle(body: string): FrameworkFingerprint | undefined {
  // Next.js client global: window.next={version:"15.0.7",appDir:!0}
  const nextGlobal = body.match(/window\.next\s*=\s*\{[^}]*?version:\s*["']([^"']+)["']/);
  if (nextGlobal) {
    return { name: "Next.js", version: nextGlobal[1], source: "window_global" };
  }

  // React DevTools / framework chunk marker: reactVersion:"19.0.0-rc-..."
  // React versions are semver, often with -rc / -canary / date suffixes.
  const reactVer = body.match(/reactVersion["':\s]+["']?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)/);
  if (reactVer) {
    return { name: "React", version: reactVer[1], source: "js_bundle" };
  }
  // Framework chunk: a `version:"x.y.z..."` / `version="x.y.z..."` marker near
  // React internals. Accept either `:` or `=` assignment, and either a plain
  // semver or a pre-release (rc/canary/…) build string.
  if (/react|reactdom|__SECRET_INTERNALS/i.test(body)) {
    const ver = body.match(
      /version\s*[:=]\s*["'](\d+\.\d+\.\d+(?:-(?:rc|canary|experimental|beta|alpha|next)-[0-9A-Za-z.-]+)?)["']/i,
    );
    if (ver) return { name: "React", version: ver[1], source: "js_bundle" };
  }

  // Vue global build marker.
  const vueVer = body.match(/Vue\.version\s*=\s*["'](\d+\.\d+\.\d+)["']/);
  if (vueVer) return { name: "Vue", version: vueVer[1], source: "js_bundle" };

  return undefined;
}

// ── Library banner parsing ──

/**
 * Parse `{library, version}` pairs from bundle banners and version markers.
 * Handles three common shapes seen in minified bundles:
 *   1. Banner comments:  `lucide-react v0.417.0`  /  `@scope/pkg v1.2.3`
 *   2. JSDoc-ish:        `* react-dom v18.2.0`
 *   3. `name@version`:   `axios@1.7.2`
 *
 * Exposed for tests.
 */
export function parseLibraryBanners(text: string): LibraryFingerprint[] {
  const out = new Map<string, LibraryFingerprint>();

  // "lucide-react v0.417.0", "@radix-ui/react-dialog v1.0.5"
  const bannerRe = /(?:^|[\s/*])((?:@[a-z0-9][\w.-]*\/)?[a-z][a-z0-9][\w.-]*)\s+v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\b/gim;
  for (const m of text.matchAll(bannerRe)) {
    const name = m[1].toLowerCase();
    if (isLikelyLibraryName(name)) {
      addLibrary(out, { name, version: m[2], source: "js_bundle" });
    }
  }

  // "axios@1.7.2", "@scope/pkg@1.2.3". We require a full three-part semver here
  // (not the looser `\d+\.\d+`) to avoid matching email/CSS `foo@2.0` noise.
  const atRe = /(?:^|[\s"'(/])((?:@[a-z0-9][\w.-]*\/)?[a-z][a-z0-9-]*[a-z0-9])@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\b/gim;
  for (const m of text.matchAll(atRe)) {
    const name = m[1].toLowerCase();
    if (isLikelyLibraryName(name)) {
      addLibrary(out, { name, version: m[2], source: "js_bundle" });
    }
  }

  return [...out.values()];
}

/** Names that show up in version-ish strings but are not real libraries. */
const LIBRARY_NAME_DENYLIST = new Set([
  "version",
  "node",
  "npm",
  "http",
  "https",
  "true",
  "false",
  "null",
  "function",
]);

function isLikelyLibraryName(name: string): boolean {
  if (name.length < 2 || name.length > 64) return false;
  if (LIBRARY_NAME_DENYLIST.has(name)) return false;
  // Reject pure numbers / version-looking tokens.
  if (/^\d/.test(name)) return false;
  return true;
}

// ── JS chunk enumeration ──

/**
 * Extract JS chunk URLs referenced from the HTML. Resolves relative URLs
 * against `base`, dedupes, and only returns `.js`/`.mjs` assets. Exposed for
 * tests.
 */
export function enumerateJsChunkUrls(html: string, base: string): string[] {
  const urls = new Set<string>();

  // <script src="...">
  const scriptRe = /<script[^>]+src=["']([^"']+)["']/gi;
  for (const m of html.matchAll(scriptRe)) {
    pushIfJs(urls, m[1], base);
  }

  // <link rel="modulepreload" href="..."> / preload as=script
  const linkRe = /<link[^>]+(?:href|src)=["']([^"']+\.(?:m?js)(?:\?[^"']*)?)["']/gi;
  for (const m of html.matchAll(linkRe)) {
    pushIfJs(urls, m[1], base);
  }

  return [...urls];
}

function pushIfJs(out: Set<string>, raw: string, base: string): void {
  const url = resolveUrl(raw, base);
  if (!url) return;
  // Strip query for the .js test, keep the full URL for fetching.
  const path = url.split("?")[0];
  if (/\.(m?js)$/i.test(path)) {
    out.add(url);
  }
}

// ── helpers ──

function addLibrary(map: Map<string, LibraryFingerprint>, lib: LibraryFingerprint): void {
  const existing = map.get(lib.name);
  if (!existing) {
    map.set(lib.name, lib);
    return;
  }
  // Prefer an entry that carries a version over one that does not.
  if (!existing.version && lib.version) {
    map.set(lib.name, lib);
  }
}

/**
 * Merge two framework signals, keeping the stronger one but enriching with a
 * version where the current pick lacks it. Source precedence (strongest →
 * weakest): window_global > js_bundle > header > meta_generator > html.
 */
function mergeFramework(
  current: FrameworkFingerprint | undefined,
  next: FrameworkFingerprint,
): FrameworkFingerprint {
  if (!current) return next;

  // If the names disagree, the more specific signal (a precise version) wins;
  // otherwise keep the current framework but fill in a missing version.
  if (current.name === next.name) {
    return {
      name: current.name,
      version: current.version ?? next.version,
      source: sourceRank(next.source) > sourceRank(current.source) ? next.source : current.source,
    };
  }

  // Different names: a versioned bundle/global signal overrides a vague
  // header/html guess (e.g. header says "React" but bundle proves "Next.js").
  if (sourceRank(next.source) > sourceRank(current.source)) {
    return next;
  }
  return current;
}

function sourceRank(source: StackSignalSource): number {
  switch (source) {
    case "window_global":
      return 5;
    case "js_bundle":
      return 4;
    case "header":
      return 3;
    case "meta_generator":
      return 2;
    case "html":
      return 1;
    default:
      return 0;
  }
}

function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k.toLowerCase()] = v;
  }
  return out;
}

function normalizeBase(target: string): string {
  return target.replace(/\/+$/, "");
}

function resolveUrl(raw: string, base: string): string | undefined {
  try {
    return new URL(raw, `${base}/`).toString();
  } catch {
    return undefined;
  }
}

function shortUrl(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname.split("/").slice(-1)[0] || u.pathname;
  } catch {
    return url;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

async function safeFetch(
  fetchText: (url: string) => Promise<FetchTextResult>,
  url: string,
): Promise<FetchTextResult | undefined> {
  try {
    return await fetchText(url);
  } catch {
    return undefined;
  }
}

// ── Summary helper (mirrors summarizeWpFingerprint) ──

/** Format a fingerprint into a one-screen human summary for the agent. */
export function summarizeWebStackFingerprint(result: WebStackFingerprint): string {
  const lines: string[] = [];
  if (result.framework) {
    const { name, version, source } = result.framework;
    lines.push(`Framework: ${name}${version ? ` v${version}` : ""} (via ${source})`);
  } else {
    lines.push("Framework: not identified");
  }
  if (result.libraries.length > 0) {
    lines.push(`Libraries (${result.libraries.length}):`);
    for (const lib of result.libraries) {
      lines.push(`  - ${lib.name}${lib.version ? `@${lib.version}` : ""} (${lib.source})`);
    }
  } else {
    lines.push("Libraries: none detected");
  }
  return lines.join("\n");
}
