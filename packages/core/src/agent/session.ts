/**
 * Stateful per-identity HTTP session engine (pwnkit#564).
 *
 * The HTTP tools (`http_request`, `crawl`, `submit_form`) were previously
 * stateless: each request carried only the one static credential and any
 * `Set-Cookie` the server returned was dropped on the floor. That makes
 * session-based auth (the common case) and broken-access-control testing
 * (BOLA/IDOR/BFLA — you need ≥2 principals and persistent sessions) impossible.
 *
 * This module adds:
 *  - `CookieJar`: a minimal per-identity cookie store that captures
 *    `Set-Cookie` and re-injects it on subsequent requests to the same host.
 *  - `SessionEngine`: holds one jar per named identity, tracks the active
 *    identity, merges static auth + jar cookies into outbound headers, and
 *    handles 401/403 by dropping stale captured cookies so the configured
 *    static credential re-establishes the session.
 *
 * When no `SessionEngine` is wired into the `ToolContext`, the tools fall back
 * to the legacy `buildAuthHeaders(authConfig)` path — behaviour is byte-for-byte
 * unchanged for single-credential scans.
 */

import type { AuthConfig, NamedIdentity } from "@pwnkit/shared";
import { buildAuthHeaders } from "./prompts.js";

/** One stored cookie. We track domain + path coarsely for host-scoped matching. */
interface StoredCookie {
  name: string;
  value: string;
  domain?: string;
  path: string;
}

/**
 * Minimal cookie jar — host-scoped, last-write-wins per (host, path, name).
 *
 * This is deliberately not a full RFC 6265 implementation: pwnkit only ever
 * talks to a single in-scope target origin (enforced by `validateTargetUrl`),
 * so a flat per-host store keyed by cookie name is sufficient and predictable.
 * Attributes we don't model (Secure, SameSite, Max-Age expiry timers) are
 * parsed-and-ignored rather than mishandled.
 */
export class CookieJar {
  // host → (name → StoredCookie)
  private byHost = new Map<string, Map<string, StoredCookie>>();

  /**
   * Capture cookies from a response's `Set-Cookie` header(s).
   *
   * `Headers.get("set-cookie")` folds multiple cookies into one
   * comma-joined string in the WHATWG fetch API. We accept either a `Headers`
   * object or a pre-split array (what `parseCookies` already produces) and
   * split conservatively on the boundary between cookies, which is a comma
   * that is NOT inside an `Expires=...,` date.
   */
  ingest(setCookies: string[] | Headers, requestUrl: string): void {
    const host = safeHost(requestUrl);
    if (!host) return;
    const raw = Array.isArray(setCookies) ? setCookies : collectSetCookie(setCookies);
    if (raw.length === 0) return;

    let jar = this.byHost.get(host);
    if (!jar) {
      jar = new Map();
      this.byHost.set(host, jar);
    }

    for (const line of raw) {
      for (const cookie of splitCookieLine(line)) {
        const parsed = parseSetCookie(cookie);
        if (!parsed) continue;
        // An empty / expired value deletes the cookie.
        if (parsed.value === "" || isExpired(cookie)) {
          jar.delete(parsed.name);
          continue;
        }
        jar.set(parsed.name, parsed);
      }
    }
  }

  /** Build the `Cookie` request header for the given URL, or "" when empty. */
  header(requestUrl: string): string {
    const host = safeHost(requestUrl);
    if (!host) return "";
    const jar = this.byHost.get(host);
    if (!jar || jar.size === 0) return "";
    return [...jar.values()].map((c) => `${c.name}=${c.value}`).join("; ");
  }

  /** Cookie names currently held for a host (for diagnostics / tests). */
  names(requestUrl: string): string[] {
    const host = safeHost(requestUrl);
    if (!host) return [];
    return [...(this.byHost.get(host)?.keys() ?? [])];
  }

  /** Drop all captured cookies for a host (used on 401/403 re-auth). */
  clearHost(requestUrl: string): void {
    const host = safeHost(requestUrl);
    if (host) this.byHost.delete(host);
  }

  /** Drop everything. */
  clear(): void {
    this.byHost.clear();
  }
}

/** A resolved identity plus its live cookie jar. */
export interface IdentitySession {
  label: string;
  role?: string;
  auth?: AuthConfig;
  jar: CookieJar;
}

/**
 * Holds one cookie jar per named identity and the notion of an "active"
 * identity. The normal HTTP tools operate as the active identity; the
 * `access_control_probe` tool drives specific identities explicitly without
 * mutating the active one.
 */
export class SessionEngine {
  private sessions = new Map<string, IdentitySession>();
  private order: string[] = [];
  private _activeLabel: string;

  constructor(identities: NamedIdentity[]) {
    if (identities.length === 0) {
      throw new Error("SessionEngine requires at least one identity");
    }
    for (const idn of identities) {
      this.sessions.set(idn.label, {
        label: idn.label,
        role: idn.role,
        auth: idn.auth,
        jar: new CookieJar(),
      });
      this.order.push(idn.label);
    }
    this._activeLabel = this.order[0];
  }

  /** Labels in declaration order. */
  get labels(): string[] {
    return [...this.order];
  }

  /** All sessions in declaration order. */
  get all(): IdentitySession[] {
    return this.order.map((l) => this.sessions.get(l)!);
  }

  get activeLabel(): string {
    return this._activeLabel;
  }

  set activeLabel(label: string) {
    if (!this.sessions.has(label)) {
      throw new Error(`Unknown identity: ${label}`);
    }
    this._activeLabel = label;
  }

  has(label: string): boolean {
    return this.sessions.has(label);
  }

  get(label: string): IdentitySession | undefined {
    return this.sessions.get(label);
  }

  /**
   * Outbound headers for a given identity: its static auth headers merged with
   * any cookies its jar has captured for `requestUrl`. Static `Cookie` auth and
   * jar cookies are concatenated (static first) so an operator-provided session
   * cookie and a freshly captured one coexist.
   */
  headersFor(label: string, requestUrl: string): Record<string, string> {
    const session = this.sessions.get(label);
    if (!session) return {};
    const headers = buildAuthHeaders(session.auth);
    const jarCookie = session.jar.header(requestUrl);
    if (jarCookie) {
      headers.Cookie = headers.Cookie ? `${headers.Cookie}; ${jarCookie}` : jarCookie;
    }
    return headers;
  }

  /** Capture `Set-Cookie` from a response into the identity's jar. */
  capture(label: string, setCookies: string[] | Headers, requestUrl: string): void {
    this.sessions.get(label)?.jar.ingest(setCookies, requestUrl);
  }

  /**
   * 401/403 handling: a session that was authenticated via captured cookies
   * has gone stale, so drop those cookies for the host. The next request then
   * falls back to the identity's configured static credential (bearer/basic/
   * header/cookie) — i.e. it "re-auths" from the durable credential rather than
   * the expired session. Returns true when cookies were actually dropped.
   */
  handleAuthStatus(label: string, status: number, requestUrl: string): boolean {
    if (status !== 401 && status !== 403) return false;
    const session = this.sessions.get(label);
    if (!session) return false;
    if (session.jar.names(requestUrl).length === 0) return false;
    session.jar.clearHost(requestUrl);
    return true;
  }
}

// ── helpers ──

function safeHost(url: string): string | null {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return null;
  }
}

/** Pull every Set-Cookie value out of a Headers object. */
function collectSetCookie(headers: Headers): string[] {
  // Node 18+ / undici expose getSetCookie(); fall back to the folded value.
  const anyHeaders = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof anyHeaders.getSetCookie === "function") {
    return anyHeaders.getSetCookie();
  }
  const folded = headers.get("set-cookie");
  return folded ? [folded] : [];
}

/**
 * Split a (possibly comma-folded) Set-Cookie string into individual cookies.
 * The only legitimate comma inside a single cookie is in an `Expires=Wed, 09
 * Jun 2021 ...` date, so we split on commas that are followed by a `token=`
 * pair (the start of the next cookie) but not on the date comma.
 */
function splitCookieLine(line: string): string[] {
  const parts: string[] = [];
  let current = "";
  const segments = line.split(",");
  for (const seg of segments) {
    // A new cookie starts when the segment (after the comma) looks like
    // `name=value...`. The Expires date continuation looks like ` 09 Jun ...`
    // (no `=` before the first `;`).
    const head = seg.split(";")[0];
    if (current !== "" && /^\s*[^=;\s]+=/.test(head)) {
      parts.push(current.trim());
      current = seg;
    } else {
      current = current === "" ? seg : `${current},${seg}`;
    }
  }
  if (current.trim() !== "") parts.push(current.trim());
  return parts;
}

function parseSetCookie(cookie: string): StoredCookie | null {
  const firstSemi = cookie.indexOf(";");
  const pair = (firstSemi === -1 ? cookie : cookie.slice(0, firstSemi)).trim();
  const eq = pair.indexOf("=");
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  if (!name) return null;

  const attrs = firstSemi === -1 ? "" : cookie.slice(firstSemi + 1);
  const domainMatch = /;?\s*domain\s*=\s*([^;]+)/i.exec(attrs);
  const pathMatch = /;?\s*path\s*=\s*([^;]+)/i.exec(attrs);
  return {
    name,
    value,
    domain: domainMatch?.[1]?.trim().replace(/^\./, "").toLowerCase(),
    path: pathMatch?.[1]?.trim() ?? "/",
  };
}

/** A Set-Cookie line that explicitly expires the cookie (past date or Max-Age<=0). */
function isExpired(cookie: string): boolean {
  const maxAge = /;\s*max-age\s*=\s*(-?\d+)/i.exec(cookie);
  if (maxAge && Number.parseInt(maxAge[1], 10) <= 0) return true;
  const expires = /;\s*expires\s*=\s*([^;]+)/i.exec(cookie);
  if (expires) {
    const t = Date.parse(expires[1]);
    if (Number.isFinite(t) && t <= Date.now()) return true;
  }
  return false;
}
