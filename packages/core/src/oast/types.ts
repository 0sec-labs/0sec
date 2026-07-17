/**
 * Out-of-band application security testing (OAST) — shared types (pwnkit#659).
 *
 * These types describe a hosted *interaction collaborator* (an interactsh-style
 * DNS + HTTP callback server we control) and the handles/interactions it hands
 * out. The point is to confirm the class of bug whose proof lives OUT of the
 * request/response we can see: blind SSRF, blind XSS, OOB RCE, OOB-SQLi,
 * XXE-OOB, JNDI/log4shell. The agent injects a unique collaborator URL/host
 * into a candidate payload; when the collaborator later records a DNS lookup or
 * HTTP request carrying that unique token, the interaction is provably tied to
 * that candidate and the finding flips from inconclusive to verified.
 *
 * This file is I/O-free on purpose: the correlation logic in `oracle.ts` is a
 * pure function of (handle, interactions), and the concrete server transport is
 * behind the `OastCollaborator` interface in `collaborator.ts`. That keeps the
 * testable core independent of whether the collaborator is in-memory (tests),
 * a self-hosted server (prod), or a third-party interactsh instance (adapter).
 */

/** Callback channel an interaction arrived on. */
export type OastProtocol = "dns" | "http" | "smtp" | "ldap";

/**
 * A single recorded callback the collaborator saw. Fields are best-effort: a
 * bare DNS lookup carries only `queryName`; an HTTP request also carries a
 * path, method, and headers. The oracle correlates on whichever addressable
 * field carries the token — for DNS that's the queried name, for HTTP the Host
 * header + request line.
 */
export interface OastInteraction {
  /** Channel this callback arrived on. */
  protocol: OastProtocol;
  /** ISO-8601 timestamp the collaborator recorded the interaction. */
  timestamp: string;
  /**
   * The fully-qualified name the peer addressed — the DNS QNAME for a DNS
   * lookup, or the HTTP `Host` header for an HTTP request. Carries the handle
   * token (and any per-candidate nonce) as subdomain labels.
   */
  queryName: string;
  /** HTTP request path (with query), when protocol === "http". */
  path?: string;
  /** HTTP method, when known. */
  method?: string;
  /** Source address of the peer that reached the collaborator, when known. */
  remoteAddress?: string;
  /** Raw request line / headers / DNS record, kept verbatim as evidence. */
  raw?: string;
}

/**
 * A unique interaction handle minted per candidate. `token` is the correlation
 * secret embedded as the leading subdomain label of `host`; a hit is tied to
 * THIS handle iff the recorded interaction's addressable fields contain
 * `token`. `httpUrl` / `dnsHost` are the two payload shapes the agent injects.
 */
export interface OastHandle {
  /** Stable short id surfaced to the agent (e.g. `oast-1`). */
  id: string;
  /** Correlation secret; the leading label of `host`. Lowercase [a-z0-9]. */
  token: string;
  /** Full callback host: `<token>.<baseDomain>`. */
  host: string;
  /** HTTP payload URL: `http://<host>/`. */
  httpUrl: string;
  /** DNS/host payload: bare `<host>` (for nslookup/LOAD_FILE/UTL_HTTP/JNDI). */
  dnsHost: string;
  /** ISO-8601 mint time. */
  createdAt: string;
}

/**
 * Derive a per-candidate probe from a handle without minting a new one. When
 * the agent wants to reuse one handle across several candidates (param A vs B,
 * HTTP vs DNS channel), it embeds `nonce` as an extra subdomain label / path
 * segment so the resulting hit is provably tied to that specific candidate —
 * the oracle matches BOTH the handle token and the nonce. Nonce is normalized
 * to a DNS-safe label by the collaborator; callers should pass short
 * `[a-z0-9]` strings.
 */
export interface OastProbe {
  /** Per-candidate nonce, normalized to a DNS label. */
  nonce: string;
  /** `<nonce>.<host>`. */
  host: string;
  /** `http://<host>/<nonce>`. */
  httpUrl: string;
  /** `<nonce>.<host>` for DNS/host payloads. */
  dnsHost: string;
}

/**
 * A hosted interaction collaborator. Implementations: `InMemoryCollaborator`
 * (reference + test double), `HttpCollaborator` (self-hosted server adapter),
 * and any interactsh-compatible adapter. Registration is cheap and pollable;
 * the collaborator holds no per-scan state beyond the interactions it records.
 */
export interface OastCollaborator {
  /** Base domain interactions are addressed under (e.g. `oast.0sec.ai`). */
  readonly baseDomain: string;
  /** Mint a fresh unique handle (unique subdomain + correlation token). */
  register(): Promise<OastHandle>;
  /** Return every interaction recorded for `handle` so far, oldest first. */
  poll(handle: OastHandle): Promise<OastInteraction[]>;
}
