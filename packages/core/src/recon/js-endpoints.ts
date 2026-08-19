// Endpoint / API-base extraction from JavaScript bodies (pwnkit#927).
//
// `discover_api_surface` only finds routes declared in an OpenAPI/Swagger spec.
// Most real SPAs ship their entire route table inside the JS bundle and never
// publish a spec, so the bundle is the richest endpoint source on a live web
// target. This module is the parsing half of the CodeWall "read the public JS"
// move: given a fetched JS body, pull out (a) the API base URLs the app talks
// to and (b) the route/path strings it calls — both as plain strings, with no
// network access of its own (the caller fetches; this only parses).
//
// Pure + dependency-free so it is fully unit-testable on fixture strings. The
// orchestration + scope gating lives in `js-recon.ts`.

/** A path/route string extracted from a JS body. */
export interface ExtractedEndpoint {
  /** The raw path or absolute URL as it appeared, e.g. `/api/v2/users`. */
  path: string;
  /** Best-effort HTTP method when the call site reveals one (fetch/axios). */
  method?: string;
}

/** Result of parsing one JS body for endpoints + API bases. */
export interface JsEndpointExtraction {
  /** Distinct path/route strings (relative or absolute). */
  endpoints: ExtractedEndpoint[];
  /** Distinct absolute API base URLs (origin or origin+prefix). */
  apiBaseUrls: string[];
}

// String literals that look like an API route: start with `/`, contain at
// least one more path segment, and don't look like a static asset / CSS / data
// URI. We match single, double, and backtick-quoted literals.
const PATH_LITERAL_RE = /["'`](\/(?:api|v\d+|graphql|rest|internal|auth|oauth|admin|users?|account|session|token|login|logout|signup|register|search|upload|download|webhook|callback|payments?|orders?|products?|cart|checkout|notifications?|messages?|files?|media|assets?|config|settings?|health|status|metrics|graph|rpc|ws|sse)[A-Za-z0-9_\-./{}:]*)["'`]/gi;

// A broader fallback: any quoted literal that is a multi-segment absolute path.
// Filtered hard against static-asset extensions to keep the signal up.
const GENERIC_PATH_LITERAL_RE = /["'`](\/[A-Za-z0-9_\-]+\/[A-Za-z0-9_\-./{}:]+)["'`]/g;

// Absolute http(s) URLs that look like an API base (have a host; optionally a
// short path prefix). Captured so the agent knows which origin the SPA calls.
const ABSOLUTE_URL_RE = /["'`](https?:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[A-Za-z0-9_\-./]*)?)["'`]/gi;

// fetch("...")/axios.get("...")/$.ajax({url:"..."}) style call sites, used to
// associate an HTTP method with a path literal when one is visible.
const METHODED_CALL_RE =
  /\b(?:axios\s*\.\s*(get|post|put|delete|patch)|fetch)\s*\(\s*["'`](\/[A-Za-z0-9_\-./{}:]+|https?:\/\/[A-Za-z0-9_\-./{}:%?=&]+)["'`]/gi;

// Static-asset / non-API extensions we never treat as endpoints.
const STATIC_ASSET_RE =
  /\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|mp4|webm|wasm|html?|json5|txt|md)(?:[?#]|$)/i;

/** True when a path looks like a static asset rather than an API route. */
function isStaticAsset(path: string): boolean {
  return STATIC_ASSET_RE.test(path);
}

/** Normalize a captured path: strip a trailing `)`/quote junk, drop query/hash. */
function normalizePath(raw: string): string {
  let p = raw.trim();
  // Drop a query string / fragment so `/api/x?id=1` and `/api/x` dedupe.
  p = p.split(/[?#]/)[0];
  // Strip a trailing slash except for the bare root.
  if (p.length > 1) p = p.replace(/\/+$/, "");
  return p;
}

/**
 * Extract endpoint paths + API base URLs from a single JS body.
 *
 * Deterministic and bounded: every regex is global and we cap the number of
 * distinct results so a hostile / huge bundle can't blow up memory.
 */
export function extractEndpointsFromJs(body: string): JsEndpointExtraction {
  const MAX = 500;
  const byPath = new Map<string, ExtractedEndpoint>();
  const apiBases = new Set<string>();

  const addPath = (rawPath: string, method?: string) => {
    if (byPath.size >= MAX) return;
    const path = normalizePath(rawPath);
    if (!path || path === "/") return;
    if (isStaticAsset(path)) return;
    const existing = byPath.get(path);
    if (existing) {
      // Enrich with a method if we now have one and didn't before.
      if (method && !existing.method) existing.method = method.toUpperCase();
      return;
    }
    byPath.set(path, method ? { path, method: method.toUpperCase() } : { path });
  };

  let m: RegExpExecArray | null;

  // 1. Methoded call sites first so paths get their HTTP method attached.
  // A bare `fetch("…")` with no options object defaults to GET per the fetch
  // spec, so we attribute GET when the call site reveals no explicit verb.
  METHODED_CALL_RE.lastIndex = 0;
  while ((m = METHODED_CALL_RE.exec(body)) !== null) {
    const method = m[1] ?? "GET"; // group 1 is the axios verb; undefined for bare fetch()
    const target = m[2];
    if (/^https?:\/\//i.test(target)) {
      try {
        const u = new URL(target);
        apiBases.add(`${u.protocol}//${u.host}`);
        addPath(u.pathname, method);
      } catch {
        /* skip malformed */
      }
    } else {
      addPath(target, method);
    }
  }

  // 2. High-signal API-shaped path literals.
  PATH_LITERAL_RE.lastIndex = 0;
  while ((m = PATH_LITERAL_RE.exec(body)) !== null) addPath(m[1]);

  // 3. Generic multi-segment path literals (filtered against static assets).
  GENERIC_PATH_LITERAL_RE.lastIndex = 0;
  while ((m = GENERIC_PATH_LITERAL_RE.exec(body)) !== null) addPath(m[1]);

  // 4. Absolute URLs → API base origins (skip obvious asset/CDN URLs).
  ABSOLUTE_URL_RE.lastIndex = 0;
  while ((m = ABSOLUTE_URL_RE.exec(body)) !== null) {
    const raw = m[1];
    if (isStaticAsset(raw)) continue;
    try {
      const u = new URL(raw);
      // Treat origin (optionally + a short path prefix) as the base.
      const base = `${u.protocol}//${u.host}`;
      if (apiBases.size < MAX) apiBases.add(base);
      // A meaningful path on an absolute URL is also an endpoint worth probing.
      if (u.pathname && u.pathname !== "/") addPath(u.pathname);
    } catch {
      /* skip malformed */
    }
  }

  return {
    endpoints: [...byPath.values()],
    apiBaseUrls: [...apiBases],
  };
}
