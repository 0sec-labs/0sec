// JavaScript artifact scanning — gap E (pwnkit web recon).
//
// For a web target, this module does two things against already-enumerated
// JS bundles (the chunk URLs you get from stack fingerprinting):
//
//   1. Source-map exposure: a bundle that ships a `//# sourceMappingURL=`
//      comment AND serves that map with a 200 leaks original source. We probe
//      both the explicit `sourceMappingURL` target and the conventional
//      `<bundle>.map` sibling.
//   2. Leaked secrets: scan bundle bodies for API keys / tokens. The signal
//      problem is real — a typical SPA legitimately ships a public PostHog or
//      Vercel-analytics key. So every pattern carries a confidence, and the
//      known-public ones are tagged `low` (noise) while genuine credentials
//      (pk_live, AKIA…, Google AIza…, Supabase service_role JWT, bearer/JWT)
//      are `high`.
//
// No network access is baked in: callers inject `fetchText`, exactly like the
// recon spec/MCP probes. No LLM. Matches are redacted in the output so we
// never persist a full live credential.

/** A secret-pattern definition. `confidence` drives the finding severity. */
export interface SecretPattern {
  /** Stable identifier for the kind of secret (used in findings). */
  kind: string;
  /** The regex that locates the secret in a bundle body. Global, no `g` reuse hazard — we recompile per scan. */
  source: RegExp;
  /**
   * `high`  — a genuine credential; surfacing it is a real finding.
   * `low`   — a known-public/expected key (analytics). Reported but flagged
   *           as noise so the caller can drop or downrank it.
   */
  confidence: "high" | "low";
}

/**
 * Curated secret-regex set. Ordering matters: known-public patterns are
 * matched first so an analytics key is classified `low` even if a broader
 * high-signal pattern would also touch it.
 *
 * Each `source` is written without the `g` flag here; `scanBody` clones it
 * with `g` so a shared definition is never mutated by `lastIndex`.
 */
export const SECRET_PATTERNS: readonly SecretPattern[] = [
  // ---- Known-public / expected keys (noise, never a real finding) ----
  // PostHog project key — shipped client-side by design.
  { kind: "posthog_public_key", source: /\bphc_[A-Za-z0-9]{32,}\b/, confidence: "low" },
  // Vercel Web Analytics / Speed Insights public token.
  { kind: "vercel_analytics_key", source: /\b(?:va_pub_|vercel_analytics_)[A-Za-z0-9]{16,}\b/, confidence: "low" },

  // ---- High-signal credentials ----
  // Stripe live secret / restricted key.
  { kind: "stripe_live_key", source: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/, confidence: "high" },
  // AWS access key id.
  { kind: "aws_access_key_id", source: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/, confidence: "high" },
  // Google API key.
  { kind: "google_api_key", source: /\bAIza[A-Za-z0-9_-]{35}\b/, confidence: "high" },
  // GitHub personal-access / app tokens.
  { kind: "github_token", source: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, confidence: "high" },
  // Slack token.
  { kind: "slack_token", source: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, confidence: "high" },
  // JWT (three base64url segments). Catches Supabase service_role keys, which
  // are JWTs — a service_role key in a client bundle is a serious leak.
  {
    kind: "jwt",
    source: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
    confidence: "high",
  },
] as const;

/** Result of a source-map exposure probe for a single bundle. */
export interface SourceMapResult {
  /** The map URL we probed (resolved from `sourceMappingURL` or `<bundle>.map`). */
  url: string;
  /** True when the map served a 200 with a non-empty body. */
  exposed: boolean;
}

/** A single secret hit, with the match redacted so the raw value never leaks. */
export interface SecretHit {
  kind: string;
  /** Redacted excerpt of the matched secret (prefix + length, never the full value). */
  match: string;
  /** The bundle URL the secret was found in. */
  chunk: string;
  confidence: "high" | "low";
}

export interface JsArtifactScanResult {
  sourceMaps: SourceMapResult[];
  secrets: SecretHit[];
}

export interface FetchTextResult {
  status: number;
  body: string;
}

export interface ScanJsArtifactsOptions {
  /** Origin/base URL of the target, used to resolve relative map references. */
  baseUrl: string;
  /** Already-enumerated JS bundle URLs (from stack fingerprinting). */
  chunkUrls: string[];
  /** Injected fetch — returns status + body. Keeps the scan testable/offline. */
  fetchText: (url: string) => Promise<FetchTextResult>;
}

/** Matches a trailing `//# sourceMappingURL=...` (or the legacy `//@`) comment. */
const SOURCE_MAPPING_URL_RE = /\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/;

/**
 * Redact a matched secret so the output never carries a usable credential.
 * Keeps a short, recognizable prefix and the total length for triage.
 */
export function redactSecret(value: string): string {
  const prefixLen = Math.min(6, value.length);
  const prefix = value.slice(0, prefixLen);
  return `${prefix}…(${value.length} chars)`;
}

/**
 * Resolve a `sourceMappingURL` value against the bundle URL it came from.
 * Handles absolute URLs, root-relative, and bare-filename references.
 * Inline data: URLs are not external maps — returns `undefined` for those.
 */
export function resolveSourceMapUrl(bundleUrl: string, mappingValue: string): string | undefined {
  const trimmed = mappingValue.trim();
  if (!trimmed || trimmed.startsWith("data:")) return undefined;
  try {
    return new URL(trimmed, bundleUrl).toString();
  } catch {
    return undefined;
  }
}

/**
 * Scan a single bundle body for secrets. Each pattern is cloned with the `g`
 * flag so the shared `SECRET_PATTERNS` definitions are never mutated. A given
 * literal match is reported once per (kind) to avoid flooding on repeated keys.
 */
export function scanBody(chunkUrl: string, body: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  for (const pattern of SECRET_PATTERNS) {
    const re = new RegExp(pattern.source.source, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
      const raw = m[0];
      const dedupeKey = `${pattern.kind}::${raw}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);
      hits.push({
        kind: pattern.kind,
        match: redactSecret(raw),
        chunk: chunkUrl,
        confidence: pattern.confidence,
      });
      // Guard against zero-width matches looping forever.
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  return hits;
}

/**
 * Probe whether a bundle's source map is exposed. We collect candidate map
 * URLs from (a) the `sourceMappingURL` comment in the body and (b) the
 * conventional `<bundle>.map` sibling, dedupe them, and fetch each. A map is
 * "exposed" when it serves 200 with a non-empty body.
 */
async function probeSourceMaps(
  chunkUrl: string,
  body: string,
  fetchText: ScanJsArtifactsOptions["fetchText"],
): Promise<SourceMapResult[]> {
  const candidates = new Set<string>();

  const comment = body.match(SOURCE_MAPPING_URL_RE);
  if (comment) {
    const resolved = resolveSourceMapUrl(chunkUrl, comment[1]);
    if (resolved) candidates.add(resolved);
  }
  // Conventional sibling: strip query/hash, append `.map`.
  try {
    const sibling = new URL(chunkUrl);
    sibling.search = "";
    sibling.hash = "";
    candidates.add(`${sibling.toString()}.map`);
  } catch {
    // non-URL chunk reference; skip the sibling guess.
  }

  const results: SourceMapResult[] = [];
  for (const url of candidates) {
    let res: FetchTextResult;
    try {
      res = await fetchText(url);
    } catch {
      results.push({ url, exposed: false });
      continue;
    }
    results.push({ url, exposed: res.status === 200 && res.body.trim().length > 0 });
  }
  return results;
}

/**
 * Scan a web target's JS artifacts for exposed source maps and leaked secrets.
 *
 * Intended to run after stack fingerprinting, which supplies `chunkUrls`. The
 * caller maps results onto findings: an exposed source map is a MEDIUM
 * finding; a `high`-confidence secret is a HIGH finding; `low`-confidence
 * secrets are expected-public keys and should be dropped or downranked.
 */
export async function scanJsArtifacts(
  opts: ScanJsArtifactsOptions,
): Promise<JsArtifactScanResult> {
  const { chunkUrls, fetchText } = opts;
  const sourceMaps: SourceMapResult[] = [];
  const secrets: SecretHit[] = [];
  const seenMapUrls = new Set<string>();

  for (const chunkUrl of chunkUrls) {
    let res: FetchTextResult;
    try {
      res = await fetchText(chunkUrl);
    } catch {
      continue;
    }
    if (res.status !== 200 || !res.body) continue;

    for (const sm of await probeSourceMaps(chunkUrl, res.body, fetchText)) {
      if (seenMapUrls.has(sm.url)) continue;
      seenMapUrls.add(sm.url);
      sourceMaps.push(sm);
    }
    secrets.push(...scanBody(chunkUrl, res.body));
  }

  return { sourceMaps, secrets };
}
