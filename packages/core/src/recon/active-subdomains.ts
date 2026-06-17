// Active subdomain enumeration (pwnkit#924).
//
// The passive enumerator (`./subdomains.ts`) only sees what Certificate
// Transparency logs already published. This module adds the *active* leg:
// generate candidate hostnames from a built-in wordlist plus a few cheap
// permutations, then resolve each in DNS and keep the ones that answer. The
// resolving hosts merge into the same `DiscoveredHost` shape the passive path
// emits, so the asset-map assembly in `./recon.ts` can dedupe across both.
//
// SAFETY IS THE DESIGN. Active enumeration touches the target's DNS, so it is
// gated like a scanner — OFF unless the caller explicitly turns it on — and
// every candidate is run through three independent rails before a single DNS
// query is issued:
//
//   * SCOPE      — each candidate host is checked against a `ScopePolicy`
//                  (the same matcher every URL-touching code path uses). A
//                  host that is not in scope is never resolved. With no policy
//                  supplied, the brute-force resolves nothing (deny-by-default).
//   * BOUNDED    — a hard cap on the number of candidates ever generated
//                  (MAX_CANDIDATES), plus bounded resolver concurrency so we
//                  never fan out an unbounded burst of DNS lookups.
//   * TIME-BOXED — a wall-clock deadline acts as a kill-switch: once it passes,
//                  no further candidates are resolved and whatever resolved so
//                  far is returned. There is no retry / amplification path.
//
// Like the passive path, `resolve` is injectable so the whole module is
// unit-testable without a live network or real DNS.

import type { ScopePolicy } from "../scope/scope.js";
import type { DiscoveredHost, ResolvedHost } from "./subdomains.js";

/**
 * Default brute-force wordlist: the highest-signal labels in practice (the
 * ones a real recon pass almost always finds). Deliberately small — this is a
 * fast confirmation sweep, not an exhaustive dictionary. Callers wanting a
 * bigger list pass `wordlist`.
 */
export const DEFAULT_SUBDOMAIN_WORDLIST: readonly string[] = [
  "www",
  "api",
  "app",
  "dev",
  "staging",
  "stage",
  "test",
  "qa",
  "admin",
  "portal",
  "dashboard",
  "auth",
  "login",
  "sso",
  "vpn",
  "mail",
  "smtp",
  "imap",
  "webmail",
  "ns1",
  "ns2",
  "mx",
  "blog",
  "shop",
  "store",
  "cdn",
  "static",
  "assets",
  "img",
  "media",
  "files",
  "docs",
  "support",
  "help",
  "status",
  "git",
  "gitlab",
  "jenkins",
  "ci",
  "registry",
  "grafana",
  "kibana",
  "prometheus",
  "internal",
  "intranet",
  "beta",
  "demo",
  "sandbox",
  "preprod",
  "uat",
];

/**
 * Hard upper bound on candidates this brute-force will ever generate, no
 * matter how large the wordlist / permutation set is. A safety rail, not a
 * tuning knob — raising it is an operator decision.
 */
export const MAX_CANDIDATES = 2_000;

/** Default resolver concurrency — modest enough to stay polite. */
export const DEFAULT_CONCURRENCY = 10;

/** Default wall-clock kill-switch for the whole brute-force, in ms. */
export const DEFAULT_MAX_DURATION_MS = 60_000;

export interface ActiveEnumerateOptions {
  /** Apex domain to brute-force under, e.g. `example.com`. */
  domain: string;
  /**
   * Master switch. Active enumeration is OFF by default — exactly like a
   * scanner. The caller MUST pass `enabled: true` to issue any DNS query.
   * When false (or omitted) this returns `[]` without touching the resolver.
   */
  enabled?: boolean;
  /**
   * Authorized-scope gate. Every candidate host is checked against this policy
   * and only resolved when `match(host).allowed` is true. REQUIRED in practice:
   * with no policy, nothing resolves (deny-by-default), so an unauthorized run
   * is a no-op rather than a live brute-force.
   */
  scope?: ScopePolicy;
  /** Brute-force labels. Defaults to `DEFAULT_SUBDOMAIN_WORDLIST`. */
  wordlist?: readonly string[];
  /**
   * Existing known hosts (e.g. from the passive CT pass) used to seed cheap
   * permutations like `dev-<known-label>` and `<known-label>-staging`. Kept
   * minimal on purpose. Each must sit under the apex; others are ignored.
   */
  knownHosts?: readonly string[];
  /**
   * Injectable resolver — same contract as the passive path. Throws / rejects
   * for a host that does not resolve; that host is dropped. Defaults to a
   * `node:dns/promises` resolver.
   */
  resolve?: (host: string) => Promise<ResolvedHost>;
  /** Max in-flight DNS lookups. Clamped to `[1, 50]`. Default 10. */
  concurrency?: number;
  /**
   * Wall-clock kill-switch in ms. Once elapsed, no further candidates are
   * resolved. Default 60s. Injectable `now` lets tests drive it.
   */
  maxDurationMs?: number;
  /** Injectable clock for the time-box. Defaults to `Date.now`. */
  now?: () => number;
}

/** A small set of permutation templates applied to each base label. */
const PERMUTATION_PREFIXES: readonly string[] = ["dev", "staging", "test", "api"];
const PERMUTATION_SUFFIXES: readonly string[] = ["dev", "staging", "test", "internal"];

/** Lowercase, trim, drop a trailing dot. Empty / invalid → undefined. */
function normalizeApex(domain: string): string | undefined {
  const apex = domain.trim().toLowerCase().replace(/\.$/, "");
  return apex.length > 0 ? apex : undefined;
}

/**
 * Extract the leftmost label of a known host relative to the apex, e.g.
 * `dev.example.com` under `example.com` → `dev`. Returns undefined when the
 * host is not a direct single-label child of the apex (we only permute simple
 * labels, not deep nestings, to keep the candidate set small and meaningful).
 */
function leafLabelUnderApex(host: string, apex: string): string | undefined {
  const h = host.trim().toLowerCase().replace(/\.$/, "");
  if (!h.endsWith(`.${apex}`)) return undefined;
  const label = h.slice(0, h.length - apex.length - 1);
  if (!label || label.includes(".")) return undefined;
  return label;
}

/**
 * Build the deduped candidate-host set under `apex`: the wordlist plus cheap
 * permutations seeded from `knownHosts`. Pure + exported so the generation
 * logic is unit-testable on its own. Capped at `MAX_CANDIDATES`.
 */
export function buildCandidateHosts(
  apex: string,
  wordlist: readonly string[],
  knownHosts: readonly string[] = [],
): string[] {
  const labels = new Set<string>();

  for (const raw of wordlist) {
    const label = raw.trim().toLowerCase();
    if (label && !label.includes(".") && !label.includes("*")) labels.add(label);
  }

  // Permute around the known leaf labels (e.g. `app` → `dev-app`, `app-staging`).
  for (const known of knownHosts) {
    const base = leafLabelUnderApex(known, apex);
    if (!base) continue;
    for (const p of PERMUTATION_PREFIXES) labels.add(`${p}-${base}`);
    for (const s of PERMUTATION_SUFFIXES) labels.add(`${base}-${s}`);
  }

  const hosts: string[] = [];
  for (const label of labels) {
    hosts.push(`${label}.${apex}`);
    if (hosts.length >= MAX_CANDIDATES) break;
  }
  return hosts;
}

function clampConcurrency(n: number | undefined): number {
  const v = Number.isFinite(n) ? Math.floor(n as number) : DEFAULT_CONCURRENCY;
  return Math.max(1, Math.min(v, 50));
}

/**
 * Default resolver, mirroring the passive path: A + AAAA + best-effort CNAME.
 * Throws when the host has no A/AAAA records so the caller drops it.
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
 * Run a bounded async map over `items` with at most `concurrency` in flight,
 * checking `shouldStop()` before each new task so the time-box can short the
 * remaining work. Rejections are swallowed (the host just didn't resolve).
 */
async function boundedResolveAll(
  hosts: string[],
  concurrency: number,
  shouldStop: () => boolean,
  resolveOne: (host: string) => Promise<DiscoveredHost | undefined>,
): Promise<DiscoveredHost[]> {
  const out: DiscoveredHost[] = [];
  let cursor = 0;

  async function worker(): Promise<void> {
    while (true) {
      if (shouldStop()) return;
      const i = cursor++;
      if (i >= hosts.length) return;
      const host = hosts[i];
      try {
        const found = await resolveOne(host);
        if (found) out.push(found);
      } catch {
        // Non-resolving host; drop it.
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, hosts.length) }, () => worker());
  await Promise.all(workers);
  return out;
}

/**
 * Actively enumerate live subdomains of `domain` by DNS-resolving a wordlist +
 * permutations. Returns one `DiscoveredHost` (source `"dns-bruteforce"`) per
 * candidate that both passes the scope gate AND resolves, sorted by host.
 *
 * Gating contract (all three must pass before any DNS query):
 *   1. `enabled === true`            — default OFF, like a scanner.
 *   2. `scope.match(host).allowed`   — per-candidate authorized-scope check.
 *   3. within `maxDurationMs`        — wall-clock kill-switch.
 *
 * Any other state (disabled, no scope, invalid domain) yields `[]` without a
 * single network touch.
 */
export async function enumerateSubdomainsActive(
  opts: ActiveEnumerateOptions,
): Promise<DiscoveredHost[]> {
  // Rail 1: master switch, default OFF.
  if (opts.enabled !== true) return [];

  const apex = normalizeApex(opts.domain);
  if (!apex) return [];

  // Rail 2: an authorized-scope policy is mandatory for a live brute-force.
  // With none, deny-by-default → resolve nothing.
  const scope = opts.scope;
  if (!scope) return [];

  const wordlist = opts.wordlist ?? DEFAULT_SUBDOMAIN_WORDLIST;
  const concurrency = clampConcurrency(opts.concurrency);
  const resolve = opts.resolve ?? defaultResolve;
  const now = opts.now ?? Date.now;
  const maxDurationMs = opts.maxDurationMs ?? DEFAULT_MAX_DURATION_MS;
  const deadline = now() + Math.max(0, maxDurationMs);

  // Generate, then keep only in-scope candidates. Scope is checked here (before
  // any resolution) AND it is the only path to a DNS query.
  const candidates = buildCandidateHosts(apex, wordlist, opts.knownHosts ?? []).filter(
    (host) => scope.match(`https://${host}`).allowed,
  );
  if (candidates.length === 0) return [];

  // Rail 3: the wall-clock kill-switch.
  const shouldStop = () => now() >= deadline;

  const found = await boundedResolveAll(candidates, concurrency, shouldStop, async (host) => {
    const { addresses, cname } = await resolve(host);
    return {
      host,
      source: "dns-bruteforce",
      addresses,
      ...(cname ? { cname } : {}),
    };
  });

  found.sort((a, b) => a.host.localeCompare(b.host));
  return found;
}
