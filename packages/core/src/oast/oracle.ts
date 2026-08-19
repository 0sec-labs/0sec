/**
 * OAST oracle — correlation-token matching for out-of-band verdicts (0sec#659).
 *
 * This is the core testable logic of the feature and carries NO I/O. Given a
 * handle's correlation token (and optionally a per-candidate nonce) plus the
 * interactions a collaborator recorded, it decides whether a blind/out-of-band
 * bug is *confirmed* — and by which channel. The "no exploit, no report"
 * principle in `triage/oracles.ts` applies here too: a verdict is only
 * `verified` when a recorded interaction provably carries our unique token on a
 * channel that makes sense for the vulnerability class.
 *
 * Why per-class channel rules matter: a DNS lookup proves the target resolved a
 * name we control (server-side) — enough for blind SSRF, OOB-RCE, OOB-SQLi,
 * XXE. But a DNS-only hit does NOT prove a script executed in a victim's
 * browser, so blind XSS requires an actual HTTP callback. Encoding that per
 * class is what stops us over-claiming.
 */

import type { OastInteraction, OastProtocol } from "./types.js";

/** Out-of-band vulnerability classes an interaction can confirm. */
export type OastClass =
  | "blind-ssrf"
  | "blind-xss"
  | "oob-rce"
  | "oob-sqli"
  | "xxe-oob"
  | "jndi";

export interface OastVerdict {
  /** True iff a token-matching interaction arrived on an acceptable channel. */
  verified: boolean;
  /** 0-1. HTTP/LDAP callbacks score 1.0; DNS-only scores 0.9. */
  confidence: number;
  /** Channel the confirming interaction arrived on, or null when unconfirmed. */
  protocol: OastProtocol | null;
  /** Concrete artifact proving the callback (the matched interaction, rendered). */
  evidence: string;
  /** Why it did not verify, when `verified` is false. */
  reason: string;
  /** The matched interaction, when one confirmed the verdict. */
  interaction: OastInteraction | null;
}

/**
 * Per-class acceptable callback channels. A hit on a channel outside this list
 * is recorded but does not verify (e.g. a DNS-only hit for blind XSS).
 */
const CLASS_ACCEPT: Record<OastClass, OastProtocol[]> = {
  // Server-side fetch: either the DNS resolution or the HTTP request proves it.
  "blind-ssrf": ["http", "dns"],
  // Script execution in a victim browser: the beacon is an HTTP request. A DNS
  // lookup alone doesn't prove the payload rendered/executed.
  "blind-xss": ["http"],
  // Command execution: curl (http) or nslookup/host (dns) callback.
  "oob-rce": ["http", "dns"],
  // Out-of-band SQLi: DNS via xp_dirtree/UTL_HTTP/LOAD_FILE is the canonical
  // channel; UTL_HTTP can also make an HTTP request.
  "oob-sqli": ["dns", "http"],
  // XXE external entity: SYSTEM fetch over HTTP, or the DNS resolution for it.
  "xxe-oob": ["http", "dns"],
  // JNDI/log4shell: the lookup drives an LDAP/RMI connect, preceded by a DNS
  // resolution; interactsh-style servers also see a plain HTTP fetch of the
  // second-stage payload.
  jndi: ["ldap", "dns", "http"],
};

/** Confidence per channel — HTTP/LDAP/SMTP are unambiguous; DNS is near-certain. */
function protocolConfidence(protocol: OastProtocol): number {
  return protocol === "dns" ? 0.9 : 1.0;
}

/**
 * Normalize an arbitrary string into a single DNS label ([a-z0-9], ≤48 chars).
 * Shared by the collaborator (when building probe hosts) and the oracle (when
 * matching a recorded interaction against a candidate nonce) so both sides
 * agree on the exact bytes that land in the subdomain.
 */
export function normalizeLabel(input: string): string {
  const cleaned = input.toLowerCase().replace(/[^a-z0-9]/g, "");
  return cleaned.slice(0, 48);
}

/** Lowercased, concatenated addressable text of an interaction (for matching). */
function addressableText(hit: OastInteraction): string {
  return [hit.queryName, hit.path ?? "", hit.raw ?? ""].join(" ").toLowerCase();
}

/**
 * Return every interaction whose addressable fields carry `token` — and, when a
 * `nonce` is supplied, its normalized form too. This is the correlation step
 * that ties a hit to a specific candidate: the token proves the callback
 * reached OUR collaborator, the nonce proves WHICH candidate triggered it.
 */
export function matchInteractions(opts: {
  token: string;
  nonce?: string;
  interactions: OastInteraction[];
}): OastInteraction[] {
  const token = opts.token.toLowerCase();
  if (!token) return [];
  const nonce = opts.nonce ? normalizeLabel(opts.nonce) : "";
  return opts.interactions.filter((hit) => {
    const text = addressableText(hit);
    if (!text.includes(token)) return false;
    if (nonce && !text.includes(nonce)) return false;
    return true;
  });
}

function renderInteraction(hit: OastInteraction): string {
  const where = hit.protocol === "http" ? `${hit.method ?? "GET"} ${hit.path ?? "/"} ` : "";
  const from = hit.remoteAddress ? ` from=${hit.remoteAddress}` : "";
  return `${hit.protocol.toUpperCase()} callback: ${where}host=${hit.queryName}${from} at ${hit.timestamp}`;
}

/**
 * Turn recorded interactions into a confirmed/inconclusive verdict for one
 * candidate. Pure: no polling, no clock, no network — the caller polls the
 * collaborator and passes the interactions in.
 *
 * A verdict verifies when at least one interaction (a) carries the correlation
 * token (and nonce, if given) and (b) arrived on a channel acceptable for the
 * class. When token-matching interactions exist but all arrived on the wrong
 * channel (e.g. DNS-only for blind XSS), the verdict stays unverified but
 * surfaces the off-channel hit as `interaction` so the caller can reason about
 * it rather than discarding a near-miss.
 */
export function confirmOast(opts: {
  oastClass: OastClass;
  token: string;
  nonce?: string;
  interactions: OastInteraction[];
}): OastVerdict {
  const { oastClass, token, nonce, interactions } = opts;
  const matched = matchInteractions({ token, nonce, interactions });

  if (matched.length === 0) {
    const scope = nonce ? `token=${token} nonce=${normalizeLabel(nonce)}` : `token=${token}`;
    return {
      verified: false,
      confidence: 0,
      protocol: null,
      evidence: "",
      reason: `no interaction carried the correlation ${scope} (${interactions.length} recorded)`,
      interaction: null,
    };
  }

  const accept = CLASS_ACCEPT[oastClass];
  const onChannel = matched.filter((hit) => accept.includes(hit.protocol));

  if (onChannel.length === 0) {
    // Token matched but on a channel that doesn't prove this class. Surface the
    // strongest near-miss so the caller isn't blind to it.
    const nearMiss = matched[0];
    return {
      verified: false,
      confidence: 0,
      protocol: null,
      evidence: renderInteraction(nearMiss),
      reason: `interaction matched but arrived on ${nearMiss.protocol}; ${oastClass} requires one of [${accept.join(", ")}]`,
      interaction: nearMiss,
    };
  }

  // Prefer the highest-confidence channel (http/ldap over dns), then earliest.
  const best = [...onChannel].sort(
    (a, b) => protocolConfidence(b.protocol) - protocolConfidence(a.protocol),
  )[0];

  return {
    verified: true,
    confidence: protocolConfidence(best.protocol),
    protocol: best.protocol,
    evidence: renderInteraction(best),
    reason: "",
    interaction: best,
  };
}

/**
 * Map a scanner `AttackCategory` (kept loose as a string to avoid a hard
 * dependency on the shared enum here) to the OAST class whose channel rules
 * apply. Returns null for categories with no out-of-band shape, so the caller
 * can skip OAST entirely for, say, path traversal.
 */
export function categoryToOastClass(category: string): OastClass | null {
  switch (category) {
    case "ssrf":
      return "blind-ssrf";
    case "xss":
      return "blind-xss";
    case "command-injection":
    case "code-injection":
      return "oob-rce";
    case "sql-injection":
      return "oob-sqli";
    default:
      return null;
  }
}
