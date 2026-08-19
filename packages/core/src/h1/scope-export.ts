// Convert a HackerOne `structured_scopes` payload into the venue-neutral
// `ScopeJson` shape that `pwnkit scan --scope <path>` consumes.
//
// The consumer schema (see `packages/core/src/scope/scope.ts`) is:
//
//   {
//     in_scope?:     string[];   // exact host | *.host | IPv4 CIDR
//     out_of_scope?: string[];   // same shape; deny wins
//     attribution?:  { headers?, user_agent_token? };
//   }
//
// Each H1 structured scope has an `asset_type` and an `asset_identifier`.
// The H1 asset types we map are the web/network primitives:
//
//   URL         → host extracted from the URL string
//   DOMAIN      → exact host, modulo a leading "*." which is the wildcard
//   WILDCARD    → wildcard form
//   IP_ADDRESS  → IPv4 host or CIDR if "/" present
//   CIDR        → IPv4 CIDR
//
// Anything else (SOURCE_CODE, EXECUTABLE, HARDWARE, OTHER, …) is dropped
// from the export with a `dropped[]` rationale entry, so the caller can
// surface it to the operator. The matcher is web-traffic-only and
// would silently never match those identifiers anyway.
//
// Out-of-scope wins by H1's policy too, so `eligible_for_submission ===
// false` lands in `out_of_scope[]` regardless of asset_type. We mirror
// the same "deny everything we don't understand" stance: an out-of-scope
// asset that we can't render is still recorded under `dropped[]` so
// downstream review notices it.

import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { isIP } from "node:net";
import type { ScopeJson } from "../scope/scope.js";
import type { H1Program, H1Scope } from "./types.js";

export interface ToScopeFileOptions {
  /** Override the default `~/.pwnkit/scopes/<handle>.json` path. */
  outPath?: string;
  /**
   * Override the home directory base. Tests use this to write scope files
   * into a tmpdir without touching the operator's real `~/.pwnkit`.
   */
  homeDir?: string;
}

export interface ScopeExportResult {
  /** Final on-disk path of the scope JSON. */
  path: string;
  /** The JSON we wrote (returned for callers that want to re-validate). */
  json: ScopeJson;
  /**
   * Scopes we couldn't render (asset_type unknown, malformed identifier,
   * etc.). Surfaced so the CLI can WARN — silently dropping rules in a
   * scope policy file is exactly the failure mode that triggers
   * out-of-scope traffic in real engagements.
   */
  dropped: Array<{ scope: H1Scope; reason: string }>;
}

/**
 * Render the JSON without writing it. Useful for tests that want to
 * round-trip through `loadScope`/`ScopePolicy.fromJson` without touching
 * disk.
 */
export function toScopeJson(program: H1Program, scopes: H1Scope[]): {
  json: ScopeJson;
  dropped: Array<{ scope: H1Scope; reason: string }>;
} {
  const inScope = new Set<string>();
  const outOfScope = new Set<string>();
  const dropped: Array<{ scope: H1Scope; reason: string }> = [];

  for (const s of scopes) {
    const rendered = renderRule(s);
    if (rendered.kind === "error") {
      dropped.push({ scope: s, reason: rendered.reason });
      continue;
    }
    const target = s.attributes.eligible_for_submission === false ? outOfScope : inScope;
    target.add(rendered.rule);
  }

  // Resolve overlap: a rule that appears in both lists is an H1
  // configuration anomaly. Per the consumer-side semantics in scope.ts
  // ("out_of_scope wins"), drop the duplicate from in_scope so the
  // matcher sees an unambiguous rule set.
  for (const r of outOfScope) inScope.delete(r);

  const json: ScopeJson = {
    in_scope: [...inScope].sort(),
    out_of_scope: [...outOfScope].sort(),
    // Per pwnkit#216: the consumer-side scope file may carry an
    // `attribution` block. We don't synthesise one here — the operator
    // sets that explicitly on the engagement, not the venue. But we
    // leave the field absent so the matcher loads cleanly and the
    // operator can append an `attribution` block by hand if they want.
  };

  // Sanity: scope.ts treats EMPTY in_scope as "deny everything", which
  // is the correct fail-loud default. We don't fall back to anything
  // tighter — if H1 returned zero usable scopes for a program, the
  // operator should see that as zero in_scope rules and notice.

  // Stash the program handle in an attribution-adjacent comment shape
  // would be nice, but ScopeJson is strict: only in_scope / out_of_scope
  // / attribution are typed, and adding extra top-level keys would just
  // be ignored by the consumer. We keep the JSON spec-conformant and let
  // the file path (`<handle>.json`) carry the program identity.
  void program;

  return { json, dropped };
}

/**
 * Render + write to `~/.pwnkit/scopes/<handle>.json` with mode 0o600.
 * Returns the final path so the CLI can echo it.
 */
export function toScopeFile(
  program: H1Program,
  scopes: H1Scope[],
  opts: ToScopeFileOptions = {},
): ScopeExportResult {
  const { json, dropped } = toScopeJson(program, scopes);
  const handle = program.attributes.handle;
  const home = opts.homeDir ?? homedir();
  const path = opts.outPath ?? join(home, ".pwnkit", "scopes", `${handle}.json`);

  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify(json, null, 2) + "\n", { mode: 0o600 });
  return { path, json, dropped };
}

// ── internals ──

type Rendered = { kind: "ok"; rule: string } | { kind: "error"; reason: string };

function renderRule(scope: H1Scope): Rendered {
  const type = (scope.attributes.asset_type ?? "").toUpperCase();
  const identRaw = (scope.attributes.asset_identifier ?? "").trim();
  if (identRaw.length === 0) {
    return { kind: "error", reason: `empty asset_identifier (asset_type=${type})` };
  }

  switch (type) {
    case "URL": {
      // H1 stores URL scopes as either bare hostnames ("api.example.com"),
      // path-prefixed entries ("api.example.com/v1/*"), or full URLs
      // ("https://api.example.com/v1"). The matcher is host-only, so we
      // strip path/scheme and emit an exact-host rule.
      const host = extractHost(identRaw);
      if (!host) return { kind: "error", reason: `URL scope has no parseable host: ${identRaw}` };
      // A URL scope with a leading wildcard (e.g. "*.example.com/path")
      // collapses to a wildcard host rule.
      if (host.startsWith("*.")) return wildcardRule(host);
      return exactRule(host);
    }
    case "DOMAIN": {
      const lower = identRaw.toLowerCase();
      if (lower.startsWith("*.")) return wildcardRule(lower);
      return exactRule(lower);
    }
    case "WILDCARD": {
      const lower = identRaw.toLowerCase();
      // H1 sometimes records wildcards bare ("example.com") and sometimes
      // with the leading "*.". Normalise both forms to "*.<rest>".
      if (lower.startsWith("*.")) return wildcardRule(lower);
      // Bare apex used as a wildcard scope = subdomain wildcard. We treat
      // it as `*.example.com`, which matches scope.ts semantics
      // (sub-domains only — apex stays a separate rule the operator can
      // add by hand if they really mean to include it).
      return wildcardRule(`*.${lower}`);
    }
    case "IP_ADDRESS":
    case "CIDR": {
      // Identifier may already be a CIDR or a bare IP; pass through if
      // valid, else flag.
      if (identRaw.includes("/")) {
        return cidrRule(identRaw);
      }
      if (isIP(identRaw) === 4) return exactRule(identRaw);
      return { kind: "error", reason: `unsupported IP_ADDRESS: ${identRaw} (only IPv4 supported)` };
    }
    default:
      return { kind: "error", reason: `unsupported asset_type: ${type}` };
  }
}

function extractHost(input: string): string | null {
  let s = input.trim();
  if (s.length === 0) return null;
  // If it parses as a URL, take the hostname.
  try {
    if (/^https?:\/\//i.test(s)) {
      return new URL(s).hostname.toLowerCase();
    }
  } catch {
    // fall through
  }
  // Strip leading "//" and trailing path/qs.
  s = s.replace(/^\/+/, "");
  const slash = s.indexOf("/");
  if (slash > 0) s = s.slice(0, slash);
  // A "*.example.com" entry survives this path with the leading "*."
  // intact, which is what the wildcard rule needs.
  return s.toLowerCase();
}

function exactRule(host: string): Rendered {
  // Host validation: the consumer rejects empty, mixed-wildcard, and
  // multi-segment-CIDR rules at parse time. We pre-filter the obvious
  // garbage so the dropped[] log is informative.
  if (host.length === 0) return { kind: "error", reason: "empty host" };
  if (host.includes("*")) return { kind: "error", reason: `unexpected '*' in exact host: ${host}` };
  if (host.includes(" ")) return { kind: "error", reason: `whitespace in host: ${host}` };
  return { kind: "ok", rule: host };
}

function wildcardRule(rule: string): Rendered {
  if (!rule.startsWith("*.")) return { kind: "error", reason: `wildcard rule must start with "*.": ${rule}` };
  const suffix = rule.slice(2);
  if (suffix.length === 0 || suffix.includes("*")) {
    return { kind: "error", reason: `invalid wildcard rule: ${rule}` };
  }
  return { kind: "ok", rule };
}

function cidrRule(rule: string): Rendered {
  const parts = rule.split("/");
  if (parts.length !== 2) return { kind: "error", reason: `malformed CIDR: ${rule}` };
  const [ip, prefixStr] = parts;
  if (!/^\d+$/.test(prefixStr)) return { kind: "error", reason: `malformed CIDR prefix: ${rule}` };
  const prefix = Number(prefixStr);
  if (prefix < 0 || prefix > 32) return { kind: "error", reason: `CIDR prefix out of range: ${rule}` };
  if (isIP(ip) !== 4) return { kind: "error", reason: `CIDR must be IPv4: ${rule}` };
  return { kind: "ok", rule };
}
