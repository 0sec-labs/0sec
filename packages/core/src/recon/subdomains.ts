// Passive subdomain enumeration (pwnkit gap D).
//
// Given an apex domain, discover subdomains from Certificate Transparency
// logs (crt.sh) and confirm which ones actually resolve in DNS. The pattern
// is deliberately *passive*: no brute-force, no wordlists, no auth probing —
// just public CT data + plain DNS resolution. In a real pilot this surfaced
// `dev.doky.ch` and `app.doky.ch` from a single apex domain.
//
// Self-contained on purpose: `fetchJson` and `resolve` are injectable so the
// module is fully unit-testable without touching the network or DNS. Defaults
// fall back to native `fetch` + `node:dns/promises`.

/** A subdomain we discovered, plus how we found it and where it resolves. */
export interface DiscoveredHost {
  /** Lowercased hostname, e.g. `dev.example.com`. */
  host: string;
  /** How this host first surfaced. */
  source: "crt.sh" | "dns";
  /** A/AAAA addresses, present when DNS resolution succeeded. */
  addresses?: string[];
  /** CNAME target, when the host is a DNS alias. */
  cname?: string;
}

export interface EnumerateSubdomainsOptions {
  /** Apex domain to enumerate, e.g. `example.com`. */
  domain: string;
  /**
   * Injectable JSON fetcher — defaults to a `fetch`-backed implementation with
   * a bounded timeout. Tests pass a stub to drive crt.sh deterministically.
   */
  fetchJson?: (url: string) => Promise<unknown>;
  /**
   * Injectable resolver — given a hostname, returns its A/AAAA addresses (and
   * optionally follows a CNAME). Defaults to a `node:dns/promises` resolver.
   * Hosts that fail to resolve are dropped from the result.
   */
  resolve?: (host: string) => Promise<ResolvedHost>;
  /** crt.sh request timeout in ms. Default 15s. */
  timeoutMs?: number;
}

/** Resolver output: addresses plus an optional CNAME target. */
export interface ResolvedHost {
  addresses: string[];
  cname?: string;
}

/** Raw crt.sh JSON row (only the fields we read). */
interface CrtShRow {
  common_name?: string;
  name_value?: string;
}

const DEFAULT_TIMEOUT_MS = 15_000;
const CRT_SH_BASE = "https://crt.sh";

/** Apex hosts that are never useful to report on their own. */
function isApexOrEmpty(host: string, apex: string): boolean {
  return host === apex || host.length === 0;
}

/**
 * Normalize a raw certificate name into a clean candidate hostname, or
 * `undefined` if it should be dropped. Strips wildcards (`*.`), surrounding
 * whitespace, a trailing dot, and lowercases. Rejects anything that does not
 * sit under the apex domain.
 */
export function normalizeCertName(raw: string, apex: string): string | undefined {
  let host = raw.trim().toLowerCase();
  if (!host) return undefined;
  // Strip a leading wildcard label: `*.example.com` -> `example.com`.
  if (host.startsWith("*.")) host = host.slice(2);
  // Defensive: drop any remaining wildcard / glob noise.
  if (host.includes("*")) return undefined;
  // Trailing dot from FQDN form.
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!host) return undefined;
  // Must be the apex itself or a subdomain of it.
  if (host !== apex && !host.endsWith(`.${apex}`)) return undefined;
  return host;
}

/**
 * Parse a crt.sh JSON payload into a deduped, sorted set of candidate hosts
 * under `apex`. Each crt.sh row can carry multiple newline-separated SANs in
 * `name_value`, plus a `common_name` — we harvest all of them.
 */
export function parseCrtShRows(rows: unknown, apex: string): string[] {
  if (!Array.isArray(rows)) return [];
  const hosts = new Set<string>();
  for (const row of rows as CrtShRow[]) {
    const fields: string[] = [];
    if (typeof row?.common_name === "string") fields.push(row.common_name);
    if (typeof row?.name_value === "string") fields.push(...row.name_value.split(/\n+/));
    for (const field of fields) {
      const host = normalizeCertName(field, apex);
      if (host && !isApexOrEmpty(host, apex)) hosts.add(host);
    }
  }
  return [...hosts].sort();
}

/**
 * Default JSON fetcher: a `fetch` call guarded by an `AbortController` timeout.
 * Returns parsed JSON, or throws on network / non-2xx / parse errors (callers
 * treat a throw as "no CT data" rather than a fatal failure).
 */
async function defaultFetchJson(url: string, timeoutMs: number): Promise<unknown> {
  // Pin the host: this fetcher only ever talks to the crt.sh CT-log API (a
  // fixed, trusted intel source — the dynamic part is the domain query string,
  // not the host). Refuse anything else so the enumerator can never be steered
  // into an SSRF.
  if (new URL(url).hostname.toLowerCase() !== "crt.sh") {
    throw new Error(`subdomains: refusing non-crt.sh fetch (${url})`);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // host is pinned to crt.sh above; only the domain query string is dynamic,
    // never the outbound host.
    // foxguard: ignore[js/no-ssrf]
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json", "User-Agent": "pwnkit-recon" },
    });
    if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Default resolver backed by `node:dns/promises`. Resolves A + AAAA records
 * (concurrently) and a best-effort CNAME. Throws if the host has no A/AAAA
 * records — the caller drops non-resolving hosts.
 */
async function defaultResolve(host: string): Promise<ResolvedHost> {
  const dns = await import("node:dns/promises");
  const [a, aaaa, cname] = await Promise.allSettled([
    dns.resolve4(host),
    dns.resolve6(host),
    dns.resolveCname(host),
  ]);
  const addresses = [
    ...(a.status === "fulfilled" ? a.value : []),
    ...(aaaa.status === "fulfilled" ? aaaa.value : []),
  ];
  if (addresses.length === 0) throw new Error(`no A/AAAA records for ${host}`);
  const cnameTarget = cname.status === "fulfilled" ? cname.value[0] : undefined;
  return { addresses, ...(cnameTarget ? { cname: cnameTarget } : {}) };
}

/**
 * Passively enumerate live subdomains of `domain`.
 *
 * 1. Query crt.sh CT logs for certificates issued under the apex.
 * 2. Normalize / dedup / strip wildcards from the certificate names.
 * 3. Resolve each candidate in DNS; keep only the ones that resolve.
 *
 * Returns one `DiscoveredHost` per resolving subdomain, sorted by host. CT
 * failures degrade gracefully to an empty result rather than throwing.
 */
export async function enumerateSubdomains(
  opts: EnumerateSubdomainsOptions,
): Promise<DiscoveredHost[]> {
  const apex = opts.domain.trim().toLowerCase().replace(/\.$/, "");
  if (!apex) throw new Error("subdomains: empty domain");

  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchJson = opts.fetchJson ?? ((url: string) => defaultFetchJson(url, timeoutMs));
  const resolve = opts.resolve ?? defaultResolve;

  // crt.sh: `%25` is a URL-encoded `%` SQL wildcard → `%.apex` matches every
  // subdomain. `output=json` returns one row per leaf certificate.
  const url = `${CRT_SH_BASE}/?q=${encodeURIComponent(`%.${apex}`)}&output=json`;

  let candidates: string[];
  try {
    candidates = parseCrtShRows(await fetchJson(url), apex);
  } catch {
    // No CT data available (timeout, rate-limit, parse error). Passive enum
    // is best-effort; surface nothing rather than aborting the recon phase.
    return [];
  }

  const resolved = await Promise.allSettled(
    candidates.map(async (host): Promise<DiscoveredHost> => {
      const { addresses, cname } = await resolve(host);
      return {
        host,
        source: "crt.sh",
        addresses,
        ...(cname ? { cname } : {}),
      };
    }),
  );

  const out: DiscoveredHost[] = [];
  for (const result of resolved) {
    if (result.status === "fulfilled") out.push(result.value);
  }
  out.sort((a, b) => a.host.localeCompare(b.host));
  return out;
}
