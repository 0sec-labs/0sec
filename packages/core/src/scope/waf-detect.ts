/**
 * pwnkit#568 — WAF detection + adaptive evasion for authorized engagements.
 *
 * Real authorized engagements run against WAF'd production. Without WAF
 * awareness pwnkit silently produces FALSE NEGATIVES: a probe comes back
 * 403/406 from a CDN edge rule and the agent treats it as "not vulnerable"
 * instead of "blocked, try a different shape". This module gives the fetch
 * chokepoints two new capabilities:
 *
 *   1. Fingerprint pass — inspect a response's signature headers, challenge
 *      cookies, status code, and block-page body for known WAF vendors
 *      (Cloudflare, Akamai, AWS WAF, Imperva/Incapsula, Sucuri, F5 BIG-IP,
 *      ModSecurity, Wordfence, Barracuda, …). Pure, network-free, testable.
 *
 *   2. Adaptive evasion — when a request is classified as WAF-blocked, derive
 *      a sequence of semantically-equivalent request variants (parameter
 *      re-encoding, keyword case folding, inline comments, header casing,
 *      whitespace alternation) paced with jitter, re-issue them through a
 *      caller-supplied `send` function, and record every attempt as evidence.
 *
 * AUTHORIZED-ENGAGEMENT FRAMING. Evasion is only ever exercised when the scan
 * carries an engagement scope (see `WafDetector` wiring in the agent loop) and
 * every attempt — strategy, transformed shape, resulting status — is recorded
 * so the operator's report shows exactly what was sent and why. The transforms
 * are server-decodable equivalences (e.g. percent-encoding a query value is
 * URL-decoded back to the original by the origin), so they change the bytes a
 * naive signature matcher sees on the wire without changing the request's
 * meaning at the application layer. Nothing here is a 0-day or an exploit; it
 * is the same payload, reshaped, for a target the operator is authorized to
 * test.
 *
 * Design notes mirror `rate-limit.ts`:
 *   - Time / randomness are injectable (`nowFn`, `sleepFn`, `rng`) so the
 *     adaptive loop is deterministic under test — no real `setTimeout`.
 *   - The detector is a small mutable per-scan aggregator (like
 *     `EnforcementTracker`), created once and shared across tool calls so the
 *     report can summarize "host X is behind Cloudflare, 3 evasion attempts,
 *     1 bypass".
 */

// ── Response abstraction ──────────────────────────────────────────────────

/** Header bag accepted from either a `fetch` `Headers` or a plain record. */
export type HeaderLike =
  | Headers
  | { get(name: string): string | null }
  | Record<string, string | string[] | undefined>;

/** Minimal response shape the fingerprinter inspects. */
export interface WafResponseLike {
  status: number;
  headers: HeaderLike;
  /** Response body (already read to a string; may be truncated by caller). */
  body?: string;
  /** Optional explicit Set-Cookie values when the caller has them. */
  cookies?: string[];
}

/** Read a single header case-insensitively from any supported bag. */
export function readHeader(headers: HeaderLike, name: string): string | null {
  const lower = name.toLowerCase();
  if (headers == null) return null;
  const maybeGet = (headers as { get?: unknown }).get;
  if (typeof maybeGet === "function") {
    const v = (headers as { get(n: string): string | null }).get(name);
    return v ?? null;
  }
  // Plain record: find the key case-insensitively.
  for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
    if (k.toLowerCase() === lower) {
      if (Array.isArray(v)) return v.join(", ");
      return v == null ? null : String(v);
    }
  }
  return null;
}

/** Collect all Set-Cookie values we can see from a response. */
function readCookies(resp: WafResponseLike): string[] {
  if (resp.cookies && resp.cookies.length > 0) return resp.cookies;
  const h = resp.headers;
  // undici Headers exposes getSetCookie(); fall back to a single get().
  const getSet = (h as { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSet === "function") {
    try {
      const arr = getSet.call(h);
      if (Array.isArray(arr) && arr.length) return arr;
    } catch {
      /* ignore */
    }
  }
  const single = readHeader(h, "set-cookie");
  return single ? [single] : [];
}

// ── WAF signature database ────────────────────────────────────────────────

export type WafVendor =
  | "cloudflare"
  | "akamai"
  | "aws-waf"
  | "imperva-incapsula"
  | "sucuri"
  | "f5-big-ip"
  | "modsecurity"
  | "wordfence"
  | "barracuda"
  | "fortinet-fortiweb"
  | "generic";

interface WafSignature {
  vendor: WafVendor;
  label: string;
  /** Header name → substring (lowercased) that must appear in its value. "" = header present is enough. */
  headers?: Array<{ name: string; contains?: string }>;
  /** Set-Cookie name prefixes that indicate this WAF (lowercased). */
  cookies?: string[];
  /** Case-insensitive substrings in the response body that indicate this WAF. */
  body?: string[];
}

/**
 * Vendor fingerprints. Ordered most-specific first; the first vendor that
 * accrues any signal wins the `vendor` label, but ALL matched signals are
 * reported so the operator sees the full evidence.
 */
const WAF_SIGNATURES: WafSignature[] = [
  {
    vendor: "cloudflare",
    label: "Cloudflare",
    headers: [
      { name: "server", contains: "cloudflare" },
      { name: "cf-ray" },
      { name: "cf-mitigated" },
    ],
    cookies: ["__cfduid", "cf_clearance", "__cf_bm"],
    body: ["attention required! | cloudflare", "cf-error-details", "ray id:", "cloudflare to restrict access"],
  },
  {
    vendor: "akamai",
    label: "Akamai (Kona/Ghost)",
    headers: [
      { name: "server", contains: "akamaighost" },
      { name: "x-akamai-transformed" },
    ],
    cookies: ["ak_bmsc", "ak_bmsc", "bm_sz", "bm_sv"],
    body: ["access denied", "reference&#32;&#35;", "you don't have permission to access"],
  },
  {
    vendor: "aws-waf",
    label: "AWS WAF",
    headers: [
      { name: "x-amzn-requestid" },
      { name: "x-amz-cf-id" },
      { name: "x-amzn-waf-action" },
    ],
    cookies: ["aws-waf-token"],
    body: ["request blocked", "aws waf"],
  },
  {
    vendor: "imperva-incapsula",
    label: "Imperva / Incapsula",
    headers: [
      { name: "x-iinfo" },
      { name: "x-cdn", contains: "incapsula" },
    ],
    cookies: ["incap_ses", "visid_incap", "nlbi_"],
    body: ["incapsula incident id", "powered by incapsula", "_incapsula_resource"],
  },
  {
    vendor: "sucuri",
    label: "Sucuri CloudProxy",
    headers: [
      { name: "server", contains: "sucuri" },
      { name: "x-sucuri-id" },
      { name: "x-sucuri-cache" },
    ],
    body: ["access denied - sucuri website firewall", "sucuri/cloudproxy", "questions about why you are blocked"],
  },
  {
    vendor: "f5-big-ip",
    label: "F5 BIG-IP ASM",
    headers: [{ name: "server", contains: "big-ip" }],
    cookies: ["ts", "bigipserver", "f5_cspm"],
    body: ["the requested url was rejected", "support id", "please consult with your administrator"],
  },
  {
    vendor: "fortinet-fortiweb",
    label: "Fortinet FortiWeb",
    headers: [{ name: "server", contains: "fortiweb" }],
    cookies: ["cookiesession1", "fortiwafsid"],
    body: ["web page blocked", ".fgd_icon", "blocked by fortiweb"],
  },
  {
    vendor: "barracuda",
    label: "Barracuda WAF",
    headers: [{ name: "server", contains: "barracuda" }],
    cookies: ["barra_counter_session", "bni_"],
    body: ["you are being redirected", "barracuda"],
  },
  {
    vendor: "wordfence",
    label: "Wordfence",
    body: ["generated by wordfence", "your access to this site has been limited", "wordfence"],
  },
  {
    vendor: "modsecurity",
    label: "ModSecurity / OWASP CRS",
    headers: [{ name: "server", contains: "mod_security" }],
    body: ["mod_security", "modsecurity", "this error was generated by mod_security", "not acceptable!"],
  },
];

// ── Fingerprint result ──────────────────────────────────────────────────

export interface WafSignal {
  kind: "header" | "cookie" | "body" | "status";
  detail: string;
}

export interface WafFingerprint {
  vendor: WafVendor;
  label: string;
  /** 0..1 — share of evidence; header+cookie hits weigh more than a body match. */
  confidence: number;
  signals: WafSignal[];
}

/** Status codes a WAF commonly returns when it blocks a request. */
const WAF_BLOCK_STATUSES = new Set([403, 406, 418, 429, 501, 503]);

/**
 * Generic block-page body markers that are not vendor-specific but still
 * strongly indicate an edge-rule rejection rather than an application 403.
 */
const GENERIC_BLOCK_MARKERS = [
  "request blocked",
  "access denied",
  "forbidden",
  "the requested url was rejected",
  "your request has been blocked",
  "this request was blocked",
  "security policy",
  "web application firewall",
  "blocked for security reasons",
];

/**
 * Fingerprint a response against the vendor signature DB. Returns the
 * best-matching vendor with all accrued signals, or `null` when no vendor
 * signature matched at all (the response may still be a generic block — see
 * `classifyResponse`).
 */
export function fingerprintWaf(resp: WafResponseLike): WafFingerprint | null {
  const headers = resp.headers;
  const cookies = readCookies(resp).map((c) => c.toLowerCase());
  const body = (resp.body ?? "").toLowerCase();

  let best: { sig: WafSignature; signals: WafSignal[]; weight: number } | null = null;

  for (const sig of WAF_SIGNATURES) {
    const signals: WafSignal[] = [];
    let weight = 0;

    for (const h of sig.headers ?? []) {
      const val = readHeader(headers, h.name);
      if (val == null) continue;
      if (h.contains == null || val.toLowerCase().includes(h.contains)) {
        signals.push({ kind: "header", detail: `${h.name}: ${val}` });
        weight += 3; // header/cookie evidence is hard to spoof accidentally
      }
    }
    for (const cookiePrefix of sig.cookies ?? []) {
      const hit = cookies.find((c) => c.startsWith(cookiePrefix) || c.includes(`${cookiePrefix}=`) || c.includes(` ${cookiePrefix}`));
      if (hit) {
        signals.push({ kind: "cookie", detail: cookiePrefix });
        weight += 3;
      }
    }
    for (const marker of sig.body ?? []) {
      if (body.includes(marker)) {
        signals.push({ kind: "body", detail: marker });
        weight += 1;
      }
    }

    if (signals.length > 0 && (best == null || weight > best.weight)) {
      best = { sig, signals, weight };
    }
  }

  if (!best) return null;
  // Confidence: saturate at a handful of strong signals.
  const confidence = Math.min(1, best.weight / 6);
  return {
    vendor: best.sig.vendor,
    label: best.sig.label,
    confidence: Math.round(confidence * 100) / 100,
    signals: best.signals,
  };
}

// ── Block classification ──────────────────────────────────────────────────

export interface BlockVerdict {
  /** True when the response looks like a WAF/edge rejection rather than a real app response. */
  blocked: boolean;
  status: number;
  /** Vendor fingerprint when one matched (may be present even on a 200 challenge page). */
  fingerprint: WafFingerprint | null;
  /** Why we decided this is (or isn't) a block. */
  reason: string;
  signals: WafSignal[];
}

/**
 * Decide whether a response is a WAF block. A block is asserted when EITHER:
 *   - a vendor fingerprint matched AND the status is a known block status, OR
 *   - a vendor fingerprint matched on the body with a block status, OR
 *   - the status is a block status AND the body carries a generic block marker
 *     (covers un-fingerprinted WAFs / custom edge rules), OR
 *   - status 429 (rate-limit rejection is itself an actionable block signal).
 *
 * A 200/302 with a challenge fingerprint (e.g. Cloudflare JS challenge) is also
 * flagged as blocked because the agent is being served an interstitial, not the
 * real resource.
 */
export function classifyResponse(resp: WafResponseLike): BlockVerdict {
  const status = resp.status;
  const fingerprint = fingerprintWaf(resp);
  const body = (resp.body ?? "").toLowerCase();
  const signals: WafSignal[] = fingerprint ? [...fingerprint.signals] : [];

  const statusIsBlock = WAF_BLOCK_STATUSES.has(status);
  if (statusIsBlock) signals.push({ kind: "status", detail: String(status) });

  const genericMarker = GENERIC_BLOCK_MARKERS.find((m) => body.includes(m));
  const challengeMarker =
    body.includes("checking your browser") ||
    body.includes("just a moment") ||
    body.includes("enable javascript and cookies to continue") ||
    body.includes("verify you are a human") ||
    body.includes("ddos protection by");

  let blocked = false;
  let reason: string;

  if (fingerprint && statusIsBlock) {
    blocked = true;
    reason = `${fingerprint.label} block (HTTP ${status})`;
  } else if (fingerprint && (genericMarker || challengeMarker)) {
    blocked = true;
    reason = `${fingerprint.label} interstitial/challenge page`;
  } else if (statusIsBlock && genericMarker) {
    blocked = true;
    if (genericMarker) signals.push({ kind: "body", detail: genericMarker });
    reason = `generic WAF block marker "${genericMarker}" (HTTP ${status})`;
  } else if (status === 429) {
    blocked = true;
    reason = "HTTP 429 rate-limit rejection (edge throttle)";
  } else if (challengeMarker) {
    blocked = true;
    reason = "browser-challenge interstitial";
  } else {
    reason = fingerprint
      ? `${fingerprint.label} fingerprinted but response looks legitimate (HTTP ${status})`
      : `no WAF block detected (HTTP ${status})`;
  }

  return { blocked, status, fingerprint, reason, signals };
}

// ── Adaptive evasion ────────────────────────────────────────────────────

export interface HttpRequestParts {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

export type EvasionStrategyName =
  | "percent-encode-params"
  | "double-encode-params"
  | "case-fold-keywords"
  | "inline-comment-keywords"
  | "alt-whitespace"
  | "header-casing";

export interface EvasionStrategy {
  name: EvasionStrategyName;
  /** Human description recorded in evidence. */
  description: string;
  apply(parts: HttpRequestParts): { parts: HttpRequestParts; changed: boolean; note: string };
}

/** SQLi / XSS / traversal keywords worth reshaping for signature evasion. */
const EVASION_KEYWORDS = [
  "select",
  "union",
  "insert",
  "update",
  "delete",
  "drop",
  "from",
  "where",
  "or",
  "and",
  "script",
  "alert",
  "onerror",
  "onload",
  "javascript",
  "eval",
  "etc/passwd",
  "concat",
  "sleep",
  "benchmark",
];

/** Escape a literal string for safe interpolation into a RegExp. */
function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Percent-encode every byte of a value (over-encoding; origin decodes it back). */
function percentEncodeAll(value: string): string {
  let out = "";
  for (const ch of Buffer.from(value, "utf8")) {
    out += "%" + ch.toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

/** Transform each query-param value (and a urlencoded/JSON-ish body) via `fn`. */
function transformParamValues(
  parts: HttpRequestParts,
  fn: (v: string) => string,
): { parts: HttpRequestParts; changed: boolean } {
  let changed = false;
  let url = parts.url;
  try {
    const u = new URL(parts.url);
    const next = new URLSearchParams();
    for (const [k, v] of u.searchParams.entries()) {
      const nv = fn(v);
      if (nv !== v) changed = true;
      next.append(k, nv);
    }
    // Avoid re-encoding the already-transformed values: build the query manually.
    const qs = Array.from(next.entries())
      .map(([k, v]) => `${encodeURIComponent(k)}=${v}`)
      .join("&");
    u.search = qs ? `?${qs}` : "";
    url = u.toString();
  } catch {
    // Not a parseable URL; leave it.
  }

  let body = parts.body;
  if (typeof body === "string" && body.length > 0) {
    const nb = fn(body);
    if (nb !== body) {
      changed = true;
      body = nb;
    }
  }

  return { parts: { ...parts, url, body }, changed };
}

/** Alternate the casing of known keywords inside a value, deterministically. */
function caseFoldKeywords(value: string): string {
  let out = value;
  for (const kw of EVASION_KEYWORDS) {
    const re = new RegExp(escapeRegExp(kw), "gi");
    out = out.replace(re, (match) =>
      match
        .split("")
        .map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()))
        .join(""),
    );
  }
  return out;
}

/** Insert SQL inline comments inside keywords, e.g. UNION becomes UN(comment)ION. */
function inlineCommentKeywords(value: string): string {
  let out = value;
  for (const kw of EVASION_KEYWORDS) {
    if (kw.length < 3 || kw.includes("/")) continue;
    const re = new RegExp(escapeRegExp(kw), "gi");
    out = out.replace(re, (match) => {
      const mid = Math.floor(match.length / 2);
      return match.slice(0, mid) + "/**/" + match.slice(mid);
    });
  }
  return out;
}

/** Replace literal spaces with WAF-evasive inline-comment whitespace tokens. */
function altWhitespace(value: string): string {
  return value.includes(" ") ? value.replace(/ /g, "/**/") : value;
}

/**
 * Vary header-name casing and append benign request-origin headers that some
 * IP/geo edge rules key on. The transformed header names are still valid
 * (HTTP header names are case-insensitive), so the request is unchanged at the
 * application layer.
 */
function varyHeaderCasing(parts: HttpRequestParts): { headers: Record<string, string>; changed: boolean } {
  const next: Record<string, string> = {};
  let changed = false;
  for (const [k, v] of Object.entries(parts.headers)) {
    const recased = k
      .split("-")
      .map((seg, i) => (i % 2 === 0 ? seg.toLowerCase() : seg.toUpperCase()))
      .join("-");
    if (recased !== k) changed = true;
    next[recased] = v;
  }
  if (!("x-forwarded-for" in parts.headers) && !("X-Forwarded-For" in parts.headers)) {
    next["X-Forwarded-For"] = "127.0.0.1";
    changed = true;
  }
  return { headers: next, changed };
}

/** Ordered evasion ladder; the campaign walks these in sequence on a block. */
export const EVASION_STRATEGIES: EvasionStrategy[] = [
  {
    name: "percent-encode-params",
    description: "percent-encode query/body values (origin URL-decodes; defeats literal signature match)",
    apply(parts) {
      const r = transformParamValues(parts, percentEncodeAll);
      return { parts: r.parts, changed: r.changed, note: "percent-encoded parameter values" };
    },
  },
  {
    name: "double-encode-params",
    description: "double percent-encode values (defeats single-pass URL-decode normalizers)",
    apply(parts) {
      const r = transformParamValues(parts, (v) => percentEncodeAll(percentEncodeAll(v)));
      return { parts: r.parts, changed: r.changed, note: "double percent-encoded parameter values" };
    },
  },
  {
    name: "case-fold-keywords",
    description: "alternate keyword casing (SeLeCt) to slip case-sensitive rules",
    apply(parts) {
      const r = transformParamValues(parts, caseFoldKeywords);
      return { parts: r.parts, changed: r.changed, note: "case-folded SQL/XSS keywords" };
    },
  },
  {
    name: "inline-comment-keywords",
    description: "insert SQL inline comments inside keywords (UN/**/ION)",
    apply(parts) {
      const r = transformParamValues(parts, inlineCommentKeywords);
      return { parts: r.parts, changed: r.changed, note: "inline-commented keywords" };
    },
  },
  {
    name: "alt-whitespace",
    description: "replace spaces with /**/ to evade whitespace-anchored rules",
    apply(parts) {
      const r = transformParamValues(parts, altWhitespace);
      return { parts: r.parts, changed: r.changed, note: "alternate whitespace tokens" };
    },
  },
  {
    name: "header-casing",
    description: "vary header-name casing + add benign X-Forwarded-For (IP/geo rule probe)",
    apply(parts) {
      const r = varyHeaderCasing(parts);
      return { parts: { ...parts, headers: r.headers }, changed: r.changed, note: "varied header casing / origin headers" };
    },
  },
];

/**
 * Jitter (ms) to pace the next evasion attempt. Increases with attempt number
 * so we back off rather than hammer. Randomness is injectable for tests; the
 * default is deterministic (`base * (attempt + 1)`).
 */
export function jitterFor(attempt: number, baseMs = 250, rng?: () => number): number {
  const factor = attempt + 1;
  if (rng) {
    // Full-jitter: random in [0, base*factor].
    return Math.floor(rng() * baseMs * factor);
  }
  return baseMs * factor;
}

export interface EvasionAttempt {
  strategy: EvasionStrategyName;
  description: string;
  note: string;
  jitterMs: number;
  status: number;
  blocked: boolean;
  /** The URL actually sent (transformed). Truncated by the caller if needed. */
  url: string;
}

export interface EvasionCampaignResult {
  /** The last response received (the bypass response when `bypassed`, else the final blocked one). */
  final: WafResponseLike;
  attempts: EvasionAttempt[];
  /** True if any variant produced a non-blocked response. */
  bypassed: boolean;
  /** Strategy that produced the bypass, if any. */
  bypassStrategy: EvasionStrategyName | null;
}

export interface EvasionCampaignOpts {
  /** Max distinct strategies to try. Defaults to the full ladder length. */
  maxAttempts?: number;
  /** Pace between attempts. */
  sleepFn?: (ms: number) => Promise<void>;
  jitterBaseMs?: number;
  /** Injectable randomness for jitter (tests pass a deterministic stub). */
  rng?: () => number;
  /** Strategy ladder override (tests / tuning). */
  strategies?: EvasionStrategy[];
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/**
 * Run the adaptive evasion campaign against an already-blocked request.
 *
 * The caller supplies `send`, which performs ONE real request for a given set
 * of parts and returns the response (status + headers + body). We walk the
 * evasion ladder, applying each transform that actually changes the request,
 * pacing with jitter, until a variant comes back un-blocked or the ladder is
 * exhausted. Every attempt is recorded.
 *
 * This function issues NO request itself beyond `send`, holds no global state,
 * and uses only the injected clock — so it is fully deterministic under test.
 */
export async function runEvasionCampaign(
  blockedParts: HttpRequestParts,
  send: (parts: HttpRequestParts) => Promise<WafResponseLike>,
  opts: EvasionCampaignOpts = {},
): Promise<EvasionCampaignResult> {
  const ladder = opts.strategies ?? EVASION_STRATEGIES;
  const max = Math.min(opts.maxAttempts ?? ladder.length, ladder.length);
  const sleepFn = opts.sleepFn ?? defaultSleep;
  const attempts: EvasionAttempt[] = [];
  let lastResponse: WafResponseLike | null = null;
  let attemptNo = 0;

  for (let i = 0; i < max; i++) {
    const strategy = ladder[i];
    const transformed = strategy.apply(blockedParts);
    if (!transformed.changed) {
      // Strategy is a no-op for this request shape — skip without burning a
      // network round-trip, but note it so the operator sees it was considered.
      attempts.push({
        strategy: strategy.name,
        description: strategy.description,
        note: `skipped (no-op for this request)`,
        jitterMs: 0,
        status: lastResponse?.status ?? 0,
        blocked: true,
        url: blockedParts.url,
      });
      continue;
    }

    const jitterMs = jitterFor(attemptNo, opts.jitterBaseMs, opts.rng);
    attemptNo += 1;
    if (jitterMs > 0) {
      // eslint-disable-next-line no-await-in-loop
      await sleepFn(jitterMs);
    }

    // eslint-disable-next-line no-await-in-loop
    const res = await send(transformed.parts);
    lastResponse = res;
    const verdict = classifyResponse(res);
    attempts.push({
      strategy: strategy.name,
      description: strategy.description,
      note: transformed.note,
      jitterMs,
      status: res.status,
      blocked: verdict.blocked,
      url: transformed.parts.url,
    });

    if (!verdict.blocked) {
      return {
        final: res,
        attempts,
        bypassed: true,
        bypassStrategy: strategy.name,
      };
    }
  }

  return {
    final: lastResponse ?? { status: 0, headers: {}, body: "" },
    attempts,
    bypassed: false,
    bypassStrategy: null,
  };
}

// ── Per-scan aggregator ────────────────────────────────────────────────────

export interface WafHostState {
  host: string;
  vendor: WafVendor;
  label: string;
  confidence: number;
  /** First time we saw a block for this host (ms since epoch). */
  firstSeenMs: number;
  blockCount: number;
  evasionAttempts: number;
  bypasses: number;
}

export interface WafEvidenceEntry {
  ts: number;
  host: string;
  url: string;
  vendor: WafVendor;
  label: string;
  reason: string;
  /** Recorded evasion attempts for this block, when a campaign ran. */
  attempts?: EvasionAttempt[];
  bypassed?: boolean;
  /** Always set — authorized-engagement provenance for the report. */
  authorizedEngagement: true;
}

/**
 * Per-scan WAF detector / evidence aggregator. One instance is created when an
 * engagement scope is configured (mirrors `EnforcementTracker`) and shared
 * across every tool call so the report can summarize WAF posture per host and
 * surface the full evasion audit trail.
 */
export class WafDetector {
  private readonly nowFn: () => number;
  private readonly hosts = new Map<string, WafHostState>();
  private readonly evidenceLog: WafEvidenceEntry[] = [];
  /** Cap so a pathological scan can't grow the evidence log unbounded. */
  private readonly maxEvidence: number;

  constructor(opts: { nowFn?: () => number; maxEvidence?: number } = {}) {
    this.nowFn = opts.nowFn ?? (() => Date.now());
    this.maxEvidence = opts.maxEvidence ?? 500;
  }

  /** Host key for a URL (lowercased hostname; falls back to the raw string). */
  private hostOf(url: string): string {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return url.toLowerCase();
    }
  }

  /**
   * Record a detected block for `url`. Returns the verdict so the caller can
   * decide whether to launch an evasion campaign. Updates per-host state.
   */
  recordBlock(url: string, verdict: BlockVerdict): void {
    const host = this.hostOf(url);
    const vendor = verdict.fingerprint?.vendor ?? "generic";
    const label = verdict.fingerprint?.label ?? "unfingerprinted WAF";
    const confidence = verdict.fingerprint?.confidence ?? 0.3;
    const now = this.nowFn();
    let state = this.hosts.get(host);
    if (!state) {
      state = {
        host,
        vendor,
        label,
        confidence,
        firstSeenMs: now,
        blockCount: 0,
        evasionAttempts: 0,
        bypasses: 0,
      };
      this.hosts.set(host, state);
    } else if (confidence > state.confidence) {
      // Upgrade to the higher-confidence fingerprint if a later block is clearer.
      state.vendor = vendor;
      state.label = label;
      state.confidence = confidence;
    }
    state.blockCount += 1;
  }

  /** Record the outcome of an evasion campaign as evidence. */
  recordEvasion(url: string, verdict: BlockVerdict, campaign: EvasionCampaignResult): void {
    const host = this.hostOf(url);
    const state = this.hosts.get(host);
    if (state) {
      state.evasionAttempts += campaign.attempts.filter((a) => a.jitterMs > 0 || a.note !== "skipped (no-op for this request)").length;
      if (campaign.bypassed) state.bypasses += 1;
    }
    if (this.evidenceLog.length < this.maxEvidence) {
      this.evidenceLog.push({
        ts: this.nowFn(),
        host,
        url,
        vendor: verdict.fingerprint?.vendor ?? "generic",
        label: verdict.fingerprint?.label ?? "unfingerprinted WAF",
        reason: verdict.reason,
        attempts: campaign.attempts,
        bypassed: campaign.bypassed,
        authorizedEngagement: true,
      });
    }
  }

  /** True if we've ever seen a block for this URL's host. */
  isKnownWafHost(url: string): boolean {
    return this.hosts.has(this.hostOf(url));
  }

  /** All per-host WAF states. */
  hostStates(): WafHostState[] {
    return Array.from(this.hosts.values());
  }

  /** Full evidence trail (capped). */
  evidence(): WafEvidenceEntry[] {
    return [...this.evidenceLog];
  }

  /** Compact summary for the report. */
  summary(): {
    waf_detected: boolean;
    hosts: WafHostState[];
    total_blocks: number;
    total_evasion_attempts: number;
    total_bypasses: number;
  } {
    const hosts = this.hostStates();
    return {
      waf_detected: hosts.length > 0,
      hosts,
      total_blocks: hosts.reduce((n, h) => n + h.blockCount, 0),
      total_evasion_attempts: hosts.reduce((n, h) => n + h.evasionAttempts, 0),
      total_bypasses: hosts.reduce((n, h) => n + h.bypasses, 0),
    };
  }
}
