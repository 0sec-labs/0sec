// ── Attribution-header injection (pwnkit#216) ──
//
// Coordinated-disclosure venues and pentest engagements commonly require an
// identifying header on test traffic so the receiving party can deconflict
// (i.e. distinguish authorized testing from real attack traffic). Without
// attribution, scan traffic looks indistinguishable from a malicious scan,
// reports get closed as "could not deconflict", and anti-abuse systems
// trigger on legitimate engagement traffic.
//
// This module provides the primitive: a configurable set of headers (plus
// an optional User-Agent override) that gets attached to every outbound
// request to in-scope hosts, and to in-scope hosts ONLY. Out-of-scope
// hosts must not have attribution attached — leaking an engagement
// identifier to an unrelated third party is a real harm, so we err on
// the side of NOT tagging.
//
// ── Configuration sources & precedence ──
//
// Per the issue's DoD, attribution is sourced from three places, with the
// scope file winning over env, and env winning over CLI:
//
//   1. Scope file: an optional `attribution` block alongside `in_scope` /
//      `out_of_scope` in the JSON file. This is the natural unit because
//      the scope file already binds to a specific engagement, and per-
//      program override is exactly what venues need (HackerOne uses
//      `X-HackerOne-Research`, Bugcrowd uses different fields, internal
//      programs invent their own).
//   2. Env vars: `PWNKIT_ATTRIBUTION_HEADERS` (JSON object of name→value)
//      and `PWNKIT_ATTRIBUTION_UA_TOKEN` (string).
//   3. CLI flags: repeatable `--attribution-header NAME=VALUE` and
//      `--attribution-ua TOKEN`.
//
// "Precedence" here means "a key set by an earlier source wins on conflict".
// Sources still merge for distinct keys — if the scope file sets
// `X-Pentest: foo` and the CLI adds `X-Engagement-ID: 42`, both end up on
// the wire. This matches operator intent: the scope file pins the per-
// program override, env/CLI add ad-hoc fields without replacing the file.
//
// ── No-scope behaviour ──
//
// When NO scope file is loaded, attribution is opt-in: only injected when
// the operator explicitly set it via env or CLI. This avoids leaking
// engagement headers when pwnkit is used outside an engagement (e.g.
// against a personal target). The DoD calls this out:
// "never injected on out-of-scope traffic".

import type { ScopePolicy, ScopeJson } from "./scope.js";
import { VERSION } from "@pwnkit/shared";

export interface AttributionConfig {
  /** Headers to attach to every in-scope outbound request. */
  headers: Record<string, string>;
  /** Optional engagement token to embed in the User-Agent override. */
  userAgentToken?: string;
}

/**
 * Shape of the optional `attribution` block inside a scope JSON file.
 * Both fields are optional; either may be absent.
 */
export interface AttributionScopeBlock {
  headers?: Record<string, string>;
  user_agent_token?: string;
}

export interface AttributionScopeJson extends ScopeJson {
  attribution?: AttributionScopeBlock;
}

export interface AttributionInputs {
  /** Already-parsed `attribution` block from the scope file, if any. */
  scopeFileBlock?: AttributionScopeBlock;
  /** Env-var inputs, normally read from `process.env`. */
  env?: NodeJS.ProcessEnv;
  /** CLI inputs (repeatable `--attribution-header NAME=VALUE` etc.). */
  cliHeaders?: string[];
  cliUaToken?: string;
}

const ENV_HEADERS_KEY = "PWNKIT_ATTRIBUTION_HEADERS";
const ENV_UA_TOKEN_KEY = "PWNKIT_ATTRIBUTION_UA_TOKEN";

/**
 * Build an `AttributionConfig` from the three configured sources, applying
 * the documented precedence (scope file > env > CLI on conflicts) and
 * merging across sources for distinct keys. Returns `undefined` when no
 * source contributed anything — callers can short-circuit injection in
 * that case.
 */
export function resolveAttribution(inputs: AttributionInputs = {}): AttributionConfig | undefined {
  const headers: Record<string, string> = {};

  // Apply LOWEST priority FIRST so higher-priority sources overwrite.
  // CLI is lowest, env is middle, scope file is highest. This is
  // backwards from how a naive reader might write it — be careful when
  // editing.

  // CLI (lowest)
  for (const raw of inputs.cliHeaders ?? []) {
    const parsed = parseCliHeader(raw);
    if (parsed) headers[parsed.name] = parsed.value;
  }

  // Env (middle)
  const envHeadersRaw = inputs.env?.[ENV_HEADERS_KEY];
  if (envHeadersRaw && envHeadersRaw.trim().length > 0) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(envHeadersRaw);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`${ENV_HEADERS_KEY} must be a JSON object of header→value: ${msg}`);
    }
    assertHeaderObject(parsed, ENV_HEADERS_KEY);
    for (const [k, v] of Object.entries(parsed as Record<string, string>)) {
      headers[normalizeHeaderName(k)] = v;
    }
  }

  // Scope file (highest)
  if (inputs.scopeFileBlock?.headers) {
    assertHeaderObject(inputs.scopeFileBlock.headers, "scope file `attribution.headers`");
    for (const [k, v] of Object.entries(inputs.scopeFileBlock.headers)) {
      headers[normalizeHeaderName(k)] = v;
    }
  }

  // UA token: same precedence (file > env > CLI). First non-empty value
  // along that chain wins.
  let userAgentToken: string | undefined;
  const fileToken = inputs.scopeFileBlock?.user_agent_token;
  const envToken = inputs.env?.[ENV_UA_TOKEN_KEY];
  if (typeof fileToken === "string" && fileToken.trim().length > 0) {
    userAgentToken = fileToken.trim();
  } else if (typeof envToken === "string" && envToken.trim().length > 0) {
    userAgentToken = envToken.trim();
  } else if (typeof inputs.cliUaToken === "string" && inputs.cliUaToken.trim().length > 0) {
    userAgentToken = inputs.cliUaToken.trim();
  }

  if (Object.keys(headers).length === 0 && !userAgentToken) {
    return undefined;
  }

  return { headers, userAgentToken };
}

/**
 * Apply attribution to a `(url, init)` request pair. Returns a NEW init
 * object with the configured headers merged in and the User-Agent
 * overridden when a token is configured. The caller-supplied headers
 * win on conflict — operators that pass a specific `Authorization` or
 * `Content-Type` should not have it silently overwritten by attribution
 * config (those are not attribution-shaped headers).
 *
 * Three guards:
 *   1. If `attribution` is undefined → return init untouched.
 *   2. If `scope` is defined AND the URL is out-of-scope → return init
 *      untouched. Defence in depth: scope already refuses out-of-scope
 *      URLs at the chokepoint, but if a future code path slips through,
 *      we still don't leak attribution headers.
 *   3. If `scope` is undefined → injection is opt-in and the caller
 *      decides (we trust `attribution !== undefined` as that signal).
 */
export function applyAttribution(
  url: string,
  init: RequestInit | undefined,
  attribution: AttributionConfig | undefined,
  scope: ScopePolicy | undefined,
): RequestInit | undefined {
  if (!attribution) return init;

  if (scope) {
    const verdict = scope.match(url);
    if (!verdict.allowed) return init;
  }

  const merged: Record<string, string> = {};
  // Attribution headers FIRST so caller-supplied init.headers can override
  // (operator-supplied Authorization etc. wins).
  for (const [k, v] of Object.entries(attribution.headers)) {
    merged[k] = v;
  }
  // Carry over caller-supplied headers. We accept the three RequestInit
  // header shapes (Headers object, array of pairs, plain object) the same
  // way `fetch` does.
  const callerHeaders = init?.headers;
  if (callerHeaders) {
    if (typeof Headers !== "undefined" && callerHeaders instanceof Headers) {
      callerHeaders.forEach((value, key) => {
        merged[normalizeHeaderName(key)] = value;
      });
    } else if (Array.isArray(callerHeaders)) {
      for (const pair of callerHeaders) {
        if (Array.isArray(pair) && pair.length === 2) {
          merged[normalizeHeaderName(String(pair[0]))] = String(pair[1]);
        }
      }
    } else if (typeof callerHeaders === "object") {
      for (const [k, v] of Object.entries(callerHeaders as Record<string, string>)) {
        merged[normalizeHeaderName(k)] = String(v);
      }
    }
  }

  // User-Agent override — only when a token is configured AND the caller
  // didn't already set one. Caller-supplied UA wins because some tools
  // (e.g. wp_fingerprint plugin probes) deliberately spoof a browser UA
  // for fingerprinting accuracy, and overriding that would defeat the
  // tool's purpose. When neither caller nor attribution sets it, the
  // platform default applies.
  if (attribution.userAgentToken) {
    const callerHasUa = Object.keys(merged).some((k) => k.toLowerCase() === "user-agent");
    if (!callerHasUa) {
      merged["User-Agent"] = formatUserAgent(attribution.userAgentToken);
    }
  }

  return { ...(init ?? {}), headers: merged };
}

/**
 * Format the User-Agent override. Kept in one place so the format is
 * stable and we don't accidentally drift between fetch sites.
 */
export function formatUserAgent(token: string): string {
  return `pwnkit/${VERSION} (engagement: ${token})`;
}

/**
 * Pull the `attribution` block out of a scope JSON object, if present.
 * Returns `undefined` when no block exists. Validates shape — anything
 * that isn't `{ headers?: object, user_agent_token?: string }` is a hard
 * error so operators see misconfiguration loudly at scan start.
 */
export function extractAttributionFromScopeJson(json: unknown): AttributionScopeBlock | undefined {
  if (!json || typeof json !== "object" || Array.isArray(json)) return undefined;
  const block = (json as { attribution?: unknown }).attribution;
  if (block === undefined) return undefined;
  if (!block || typeof block !== "object" || Array.isArray(block)) {
    throw new Error("Scope file `attribution` must be an object with optional `headers` / `user_agent_token` fields");
  }
  const out: AttributionScopeBlock = {};
  const b = block as Record<string, unknown>;
  if (b.headers !== undefined) {
    assertHeaderObject(b.headers, "scope file `attribution.headers`");
    out.headers = b.headers as Record<string, string>;
  }
  if (b.user_agent_token !== undefined) {
    if (typeof b.user_agent_token !== "string") {
      throw new Error("Scope file `attribution.user_agent_token` must be a string");
    }
    out.user_agent_token = b.user_agent_token;
  }
  return out;
}

// ── internals ──

function parseCliHeader(raw: string): { name: string; value: string } | null {
  if (typeof raw !== "string") return null;
  const eq = raw.indexOf("=");
  if (eq <= 0) return null;
  const name = raw.slice(0, eq).trim();
  const value = raw.slice(eq + 1);
  if (!name || !isValidHeaderName(name)) return null;
  return { name: normalizeHeaderName(name), value };
}

function assertHeaderObject(value: unknown, label: string): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object of header→value strings`);
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (!isValidHeaderName(k)) {
      throw new Error(`${label}: invalid header name '${k}'`);
    }
    if (typeof v !== "string") {
      throw new Error(`${label}: header '${k}' value must be a string`);
    }
  }
}

// RFC 7230 token characters for header names. Names are canonicalized to
// HTTP title-case (X-Hackerone-Research) before they enter our internal
// merge dict so two sources disagreeing on casing can't both ride the wire
// (pwnkit#239). On-the-wire casing then matches whatever this canonical
// form produces; HTTP is case-insensitive so this is operator-invisible.
const HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function isValidHeaderName(name: string): boolean {
  return typeof name === "string" && HEADER_NAME_RE.test(name);
}

function normalizeHeaderName(name: string): string {
  // Canonicalize to HTTP title-case (X-Hackerone-Research) so two configs
  // that disagree only on casing collapse to one key. Without this, scope
  // file `X-Pentest: foo` and env `x-pentest: foo` would both ride the wire
  // as separate headers (pwnkit#239). Header names are case-insensitive per
  // RFC 7230 §3.2; the canonical form is purely an internal dedup key.
  return name
    .split("-")
    .map((part) =>
      part.length === 0 ? part : part.charAt(0).toUpperCase() + part.slice(1).toLowerCase(),
    )
    .join("-");
}
