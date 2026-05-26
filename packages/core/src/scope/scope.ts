// ── Programmatic scope ingestion (pwnkit#215) ──
//
// Loads a JSON scope file ({ in_scope, out_of_scope }) and exposes a single
// matcher used by every URL-touching code path in the agent (validateTargetUrl,
// shellExec URL extraction, the 5 fetch sites). Three rule shapes are
// recognised, all venue-agnostic so cloud products can transform venue-
// specific scope formats into this primitive:
//
//   1. Exact host        — "api.example.com" matches `api.example.com`
//                          (and ONLY that hostname; not subdomains, not apex).
//   2. Wildcard subdomain — "*.example.com" matches `sub.example.com` and
//                          `a.b.example.com`. Bare apex (`example.com`) is
//                          NOT matched on purpose — that is a separate rule
//                          shape and merging the two trivially defeats the
//                          point of a wildcard rule (see #215 spec).
//   3. CIDR (IPv4 only)  — "10.0.0.0/8" matches any IPv4 address in the
//                          block. IPv6 is intentionally out of scope for v1.
//
// Out-of-scope wins. This is the conservative default — coordinated
// disclosure programs treat "asset listed in both lists" as a
// configuration error from the operator, and erring on the side of NOT
// touching the asset is the only sane policy. Same principle as a deny
// rule beating an allow rule in a firewall.

import { readFileSync } from "node:fs";
import { isIP } from "node:net";

export type ScopeRule = string;

export interface ScopeJson {
  in_scope?: ScopeRule[];
  out_of_scope?: ScopeRule[];
  /**
   * Optional attribution block (pwnkit#216). Format and semantics live in
   * `attribution.ts`; declared here so the JSON schema is co-located with
   * the rest of the scope file shape. Callers that don't care about
   * attribution (most of the codebase) can ignore this field.
   */
  attribution?: {
    headers?: Record<string, string>;
    user_agent_token?: string;
  };
}

export interface ScopeMatch {
  allowed: boolean;
  reason: string;
}

interface ParsedRule {
  raw: string;
  kind: "exact" | "wildcard" | "cidr";
  host?: string;
  suffix?: string;
  cidr?: { network: number; prefix: number };
}

export class ScopePolicy {
  private readonly inScope: ParsedRule[];
  private readonly outOfScope: ParsedRule[];
  /**
   * Original JSON the policy was constructed from. Exposed read-only so
   * downstream features (pwnkit#216 attribution headers) can pull their
   * own optional blocks out of the same file without re-reading it.
   */
  readonly raw: ScopeJson;

  constructor(json: ScopeJson) {
    this.inScope = (json.in_scope ?? []).map(parseRule);
    this.outOfScope = (json.out_of_scope ?? []).map(parseRule);
    this.raw = json;
  }

  /**
   * Load a policy from a JSON file on disk.
   *
   * Bubbles up the underlying ENOENT/JSON-parse error to the caller; the
   * scan CLI is responsible for translating these into a user-facing
   * "scope file not found / malformed" message and exiting non-zero before
   * the agent ever boots.
   */
  static fromJsonFile(path: string): ScopePolicy {
    const raw = readFileSync(path, "utf-8");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Scope file ${path} is not valid JSON: ${msg}`);
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error(`Scope file ${path} must be a JSON object with in_scope/out_of_scope arrays`);
    }
    return ScopePolicy.fromJson(parsed as ScopeJson);
  }

  static fromJson(obj: ScopeJson): ScopePolicy {
    return new ScopePolicy(obj);
  }

  /**
   * Decide whether a URL is allowed by this policy.
   *
   * The contract used by every call site:
   *   - allowed=true  → URL is in scope, callers may proceed.
   *   - allowed=false → URL is out of scope; callers MUST surface this as
   *                     a hard error (`ToolResult.error`), not a warning.
   *
   * `reason` is human-readable and meant to be embedded in the error
   * message returned to the agent so it can self-correct.
   */
  match(url: string): ScopeMatch {
    let host: string;
    try {
      host = new URL(url).hostname.toLowerCase();
    } catch {
      return { allowed: false, reason: `out-of-scope: not a valid URL (${url})` };
    }

    // Out-of-scope wins. We evaluate it first and short-circuit on a
    // match because a rule appearing in both lists must NOT slip through
    // — see the "operator misconfiguration" rationale in the file header.
    const denyHit = this.outOfScope.find((rule) => matches(rule, host));
    if (denyHit) {
      return { allowed: false, reason: `out-of-scope: host '${host}' matches deny rule '${denyHit.raw}'` };
    }

    // Empty in_scope is a "deny everything" policy. This is what an operator
    // who ships an empty scope file presumably intends, and it makes the
    // failure mode loud rather than silent.
    if (this.inScope.length === 0) {
      return { allowed: false, reason: `out-of-scope: host '${host}' (no in_scope rules defined)` };
    }

    const allowHit = this.inScope.find((rule) => matches(rule, host));
    if (allowHit) {
      return { allowed: true, reason: `in-scope: host '${host}' matches '${allowHit.raw}'` };
    }

    return { allowed: false, reason: `out-of-scope: host '${host}' did not match any in_scope rule` };
  }
}

/**
 * Convenience: extract every `https?://...` URL from a freeform string
 * (e.g. a shell command) and run each through the policy. Used by the
 * shellExec chokepoint to refuse a `curl https://evil.com` before exec.
 */
export function extractUrls(text: string): string[] {
  const re = /https?:\/\/[^\s'"`<>|]+/gi;
  const out: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    // Trim trailing punctuation that isn't part of the URL (commas,
    // closing parens from inline prose, etc).
    let url = m[0];
    while (url.length > 0 && /[.,;:)\]}]$/.test(url)) {
      url = url.slice(0, -1);
    }
    if (url.length > 0) out.push(url);
  }
  return out;
}

/**
 * Top-level loader; thin wrapper around fromJsonFile that the CLI calls.
 * Exposed as a separate symbol because the issue's DoD names it explicitly.
 */
export function loadScope(path: string): ScopePolicy {
  return ScopePolicy.fromJsonFile(path);
}

/**
 * Top-level matcher. Equivalent to `policy.match(url)` but spelled the
 * way the issue's DoD names it. Kept as a free function so a caller that
 * has been handed an already-parsed policy can do `matchUrl(url, policy)`
 * without juggling the class-vs-bag-of-methods distinction.
 */
export function matchUrl(url: string, policy: ScopePolicy): ScopeMatch {
  return policy.match(url);
}

// ── internals ──

function parseRule(raw: unknown): ParsedRule {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    throw new Error(`Invalid scope rule: ${JSON.stringify(raw)} (must be a non-empty string)`);
  }
  const rule = raw.trim().toLowerCase();

  // CIDR: anything with a slash. IPv4 only — we explicitly reject IPv6
  // because the spec deferred it and silently accepting "::/0" would be
  // a disaster.
  //
  // Parsing is intentionally strict (pwnkit#218 review): destructuring a
  // bare `rule.split("/")` plus `Number()` accepts "10.0.0.0/" as /0 and
  // silently drops extra segments in "10.0.0.0/8/anything". Both are
  // operator typos that would fail open to "match every IPv4". We reject
  // them up-front so the misconfiguration is visible at scope-load time.
  if (rule.includes("/")) {
    const parts = rule.split("/");
    if (parts.length !== 2) {
      throw new Error(`Invalid CIDR '${raw}': expected exactly one '/'`);
    }
    const [ip, prefixStr] = parts;
    if (!/^\d+$/.test(prefixStr)) {
      throw new Error(
        `Invalid CIDR prefix in '${raw}': must be a non-negative integer 0-32`,
      );
    }
    const prefix = Number(prefixStr);
    if (prefix < 0 || prefix > 32) {
      throw new Error(`Invalid CIDR prefix in '${raw}': must be 0-32`);
    }
    if (isIP(ip) !== 4) {
      throw new Error(`Invalid CIDR '${raw}': only IPv4 CIDR is supported`);
    }
    return { raw, kind: "cidr", cidr: { network: ipv4ToInt(ip), prefix } };
  }

  // Wildcard: must be exactly "*.<rest>". Multiple stars or interior
  // stars (e.g. "sub.*.example.com") are not supported — they introduce
  // matching ambiguity that is not worth the implementation cost for a
  // primitive whose whole job is to be conservative.
  if (rule.startsWith("*.")) {
    const suffix = rule.slice(2);
    if (suffix.length === 0 || suffix.includes("*")) {
      throw new Error(`Invalid wildcard rule '${raw}': must be of the form '*.domain.tld'`);
    }
    return { raw, kind: "wildcard", suffix };
  }

  if (rule.includes("*")) {
    throw new Error(`Invalid scope rule '${raw}': only leading '*.' wildcards are supported`);
  }

  return { raw, kind: "exact", host: rule };
}

function matches(rule: ParsedRule, host: string): boolean {
  switch (rule.kind) {
    case "exact":
      return rule.host === host;
    case "wildcard": {
      // Sub-domains only. `*.example.com` must match `sub.example.com`
      // but NOT `example.com` itself, and crucially NOT
      // `evil.example.com.attacker.com` — the dot is part of the match.
      const suffix = "." + rule.suffix!;
      return host !== rule.suffix && host.endsWith(suffix);
    }
    case "cidr": {
      if (isIP(host) !== 4) return false;
      const { network, prefix } = rule.cidr!;
      if (prefix === 0) return true;
      const mask = prefix === 32 ? 0xffffffff : (~((1 << (32 - prefix)) - 1)) >>> 0;
      return ((ipv4ToInt(host) & mask) >>> 0) === ((network & mask) >>> 0);
    }
  }
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split(".").map((p) => Number(p));
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}
