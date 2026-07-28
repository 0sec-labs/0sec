// Token and assertion analysis — JWT / OAuth2 / OpenID Connect / SAML 2.0.
//
// OFFLINE IS STRUCTURAL, NOT A CONVENTION. This module imports nothing that can
// reach a network — no `fetch`, no `http`, no client, no injectable transport —
// and every exported function is a pure `(material, options?) => IdentityFinding[]`
// over a string the operator (or an earlier stage) already has in hand. It never
// resolves a JWKS endpoint, never follows a `jku`/`x5u`, never contacts an IdP,
// and never authenticates. In the same spirit as `graph-client.ts` making
// read-only structural: adding a network path here would mean adding an import
// that a reviewer notices.
//
// Consequently this module CANNOT and DOES NOT verify a signature. Every check
// is about what the token *claims* and what a verifier would have to get right —
// exposure, not proof of forgery. A finding here says "this token's shape lets a
// verifier be fooled", never "this signature is invalid".
//
// SECURITY — no raw token material leaves this module. Following the
// `agent/credential-store.ts` pattern, a token is only ever referred to by its
// SHA-256 fingerprint (truncated) and a redacted length-annotated preview.
// Claim *metadata* that a reviewer needs to reproduce the finding (`alg`, `exp`,
// `aud`, `iss`, `tid`, role template ids, scope names) is grounded verbatim
// because it is not secret material; anything that looks like a secret, an
// email, or PII is redacted before it reaches an evidence string. Nothing here
// logs, writes, or persists.
//
// Two invariants shared with `analyzers.ts`:
//
//   1. NEVER THROW. A malformed token is a finding, not an exception. Every
//      parser in this file is total: it returns a result, and the caller turns
//      a parse failure into a `jwt-malformed` / `saml-malformed` finding.
//   2. EVIDENCE IS GROUNDED. Each finding cites the exact segment, claim name,
//      or XML path it was derived from, so a reviewer can decode the same token
//      and see the same thing.
//
// The SAML checks read structure through the deliberately narrow XML reader in
// `./xml.ts` — no XML dependency, no entity expansion, no DTD.

import { createHash } from "node:crypto";
import {
  HIGH_IMPACT_GRAPH_PERMISSIONS,
  PRIVILEGED_ROLE_TEMPLATE_IDS,
  TIER0_GRAPH_PERMISSIONS,
  TIER0_ROLE_TEMPLATE_IDS,
  ROLE_TEMPLATE_IDS,
} from "./analyzers.js";
import {
  ancestors,
  descendants,
  isDescendantOf,
  parseXml,
  type XmlElement,
} from "./xml.js";
import type {
  AffectedPrincipal,
  IdentityCheck,
  IdentityEvidence,
  IdentityFinding,
  IdentitySeverity,
} from "./types.js";

// ── catalogs ──

/** The rules implemented in this file. Subset of `IDENTITY_CHECKS`. */
export const TOKEN_CHECKS: readonly IdentityCheck[] = [
  "token-unrecognized-format",
  "jwt-malformed",
  "jwt-alg-none",
  "jwt-algorithm-confusion-exposure",
  "jwt-unsafe-key-identifier",
  "jwt-missing-expiry",
  "jwt-excessive-lifetime",
  "jwt-expired",
  "jwt-untrusted-issuer",
  "jwt-weak-audience",
  "jwt-missing-replay-controls",
  "jwt-sensitive-claim-data",
  "jwt-overly-broad-scope",
  "entra-token-type-mismatch",
  "entra-token-weak-client-binding",
  "entra-token-privileged-wids",
  "entra-token-multi-tenant-issuer",
  "entra-token-long-lived-session",
  "saml-malformed",
  "saml-unsigned-assertion",
  "saml-signature-wrapping-exposure",
  "saml-weak-conditions",
  "saml-missing-audience-restriction",
  "saml-weak-subject-confirmation",
  "saml-nameid-comment-truncation",
  "saml-golden-saml-preconditions",
];

/** JWS algorithms that use a shared secret rather than a key pair. */
const SYMMETRIC_ALGORITHMS: ReadonlySet<string> = new Set(["HS256", "HS384", "HS512"]);

/** JWS algorithms that use a public/private key pair. */
const ASYMMETRIC_ALGORITHMS: ReadonlySet<string> = new Set([
  "RS256", "RS384", "RS512",
  "PS256", "PS384", "PS512",
  "ES256", "ES384", "ES512", "ES256K",
  "EdDSA",
]);

/**
 * Well-known Microsoft first-party public clients. A token minted for one of
 * these was obtained without any client secret, and most of them belong to the
 * "family of client ids" (FOCI) — a refresh token issued to one is redeemable
 * for an access token for the others. Seeing one in `azp`/`appid` means the
 * client half of the credential pair is worth nothing as a control.
 */
export const PUBLIC_CLIENT_APP_IDS: Readonly<Record<string, string>> = {
  "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Azure CLI",
  "1950a258-227b-4e31-a9cf-717495945fc2": "Azure PowerShell",
  "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
  "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
  "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
  "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive SyncEngine",
  "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223": "Intune Company Portal",
  "872cd9fa-d31f-45e0-9eab-6e460a02d1f1": "Visual Studio",
  "29d9ed98-a469-4536-ade2-f981bc1d605e": "Microsoft Authentication Broker",
  "4813382a-8fa7-425e-ab75-3b753aab3abb": "Microsoft Authenticator App",
  "b26aadf8-566f-4478-926f-589f601d9c74": "OneDrive",
  "9bc3ab49-b65d-410a-85ad-de819febfddc": "SharePoint Online Management Shell",
};

/** The fixed tenant id every personal Microsoft account authenticates against. */
export const MSA_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad";

/** Issuer path segments that mean "any tenant, including ones you don't own". */
const MULTI_TENANT_ISSUER_SEGMENTS = ["/common/", "/organizations/", "/consumers/"];

/**
 * Claims that are *expected* to carry an email address or UPN. An email-shaped
 * value here is the claim doing its job, so the sensitive-data check ignores
 * them — otherwise every Entra ID token on earth raises a finding and the check
 * is worthless.
 */
const IDENTIFIER_CLAIMS: ReadonlySet<string> = new Set([
  "upn", "unique_name", "preferred_username", "email", "emails", "mail",
  "sub", "oid", "name", "given_name", "family_name", "nickname",
  "iss", "aud", "azp", "appid", "tid", "idp", "iat", "nbf", "exp",
  "verified_primary_email", "verified_secondary_email",
]);

/** Claim names whose presence means the token is carrying regulated PII. */
const PII_CLAIM_NAMES: ReadonlySet<string> = new Set([
  "phone_number", "phone", "mobile", "birthdate", "dateofbirth", "dob",
  "address", "street_address", "postal_code", "ssn", "social_security_number",
  "national_id", "passport", "passport_number", "tax_id", "iban", "salary",
]);

const EMAIL_SHAPE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const INTERNAL_HOSTNAME_SHAPE = /\b[a-z0-9][a-z0-9-]*\.(?:local|internal|intranet|corp|lan|home|test)\b/i;
const PRIVATE_IP_SHAPE =
  /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/;

/** `kid` shapes that only appear when someone is steering key resolution. */
const UNSAFE_KID_SHAPES: readonly { pattern: RegExp; label: string }[] = [
  { pattern: /\.\.[/\\]/, label: "path traversal" },
  { pattern: /^[/\\]/, label: "absolute path" },
  { pattern: /^[a-z][a-z0-9+.-]*:\/\//i, label: "URL" },
  { pattern: /\0/, label: "null byte" },
  { pattern: /['"`;]|--|\/\*/, label: "SQL/quote injection" },
  { pattern: /\|/, label: "shell metacharacter" },
];

/** SAML `AuthnContextClassRef` values that assert multi-factor authentication. */
const MFA_AUTHN_CONTEXT_SHAPE = /multifactor|multipleauthn|\bmfa\b/i;

const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;

// ── options ──

export interface TokenAnalysisOptions {
  /** Injected clock. Every relative check reads this so fixtures are stable. */
  now?: Date;
  /**
   * Stable reference used in finding ids instead of the token fingerprint.
   * Useful when a report analyses several tokens and needs readable ids.
   */
  label?: string;
  /** Audience(s) the token is supposed to be for. Mismatch is a finding. */
  expectedAudience?: string | string[];
  /** Exact issuer the token is supposed to come from. Mismatch is a finding. */
  expectedIssuer?: string;
  /** Entra tenant id the token is supposed to be scoped to (`tid`). */
  expectedTenantId?: string;
  /** Which kind of token the consumer believes it is holding. */
  expectedTokenType?: "access" | "id";
  /**
   * A single-tenant app that accepts `/common/` issuers accepts every tenant on
   * the planet. Set false only for a deliberately multi-tenant consumer.
   * Default true.
   */
  expectSingleTenant?: boolean;
  /** Lifetimes above this are flagged. Default 60 (Entra's access-token default). */
  maxLifetimeMinutes?: number;
  /** SAML assertion validity windows above this are flagged. Default 10. */
  maxAssertionValidityMinutes?: number;
  /** `groups` claims larger than this are flagged. Default 50. */
  maxGroupClaims?: number;
}

// ── redaction ──

/** How many leading chars of a value survive into the (redacted) preview. */
const PREVIEW_PREFIX_LEN = 6;

/**
 * SHA-256 of token material, used only to give a finding a stable, non-secret
 * handle. Unlike `hashCredentialValue` in `agent/credential-store.ts` this does
 * NOT lowercase: base64url is case-significant, and two tokens differing only
 * in case are two different tokens.
 */
export function tokenFingerprint(material: string): string {
  return createHash("sha256").update(material.trim(), "utf8").digest("hex");
}

/**
 * Redacted, non-secret preview of a value: short prefix plus length, e.g.
 * `eyJhbG…(842)`. Same shape as `previewCredentialValue` so an operator reading
 * a report recognises the convention.
 */
export function redactTokenValue(value: string): string {
  const v = value.trim();
  if (v.length === 0) return "…(0)";
  if (v.length <= PREVIEW_PREFIX_LEN) {
    return `${v.slice(0, Math.min(2, v.length))}…(${v.length})`;
  }
  return `${v.slice(0, PREVIEW_PREFIX_LEN)}…(${v.length})`;
}

/** The handle a finding id is built from: caller label, else short fingerprint. */
function tokenRef(material: string, options: TokenAnalysisOptions): string {
  return options.label ?? tokenFingerprint(material).slice(0, 12);
}

// ── JWT decoding ──

export interface DecodedJwt {
  header: Record<string, unknown>;
  /** Empty for a JWE, whose payload is ciphertext this module will not touch. */
  payload: Record<string, unknown>;
  /** Number of dot-separated segments: 3 for a JWS, 5 for a JWE. */
  segments: number;
  /** Decoded byte length of the signature segment. 0 means unsigned. */
  signatureBytes: number;
  /** True for a 5-segment compact JWE; claim-level checks are skipped. */
  encrypted: boolean;
}

export type JwtDecodeResult =
  | { ok: true; jwt: DecodedJwt }
  | { ok: false; reason: string };

/**
 * Decode a compact JWS/JWE without verifying anything. Total function: it
 * returns a reason rather than throwing, because the malformed case is a
 * finding this module has to be able to emit.
 */
export function decodeJwtUnverified(token: string): JwtDecodeResult {
  const raw = token.trim();
  if (raw.length === 0) return { ok: false, reason: "empty input" };

  const parts = raw.split(".");
  if (parts.length !== 3 && parts.length !== 5) {
    return {
      ok: false,
      reason: `expected 3 (JWS) or 5 (JWE) dot-separated segments, got ${parts.length}`,
    };
  }

  const header = decodeJsonSegment(parts[0]);
  if (!header.ok) return { ok: false, reason: `header segment: ${header.reason}` };

  const encrypted = parts.length === 5;
  let payload: Record<string, unknown> = {};
  if (!encrypted) {
    const decoded = decodeJsonSegment(parts[1]);
    if (!decoded.ok) return { ok: false, reason: `payload segment: ${decoded.reason}` };
    payload = decoded.value;
  }

  // For a JWE the last segment is the authentication tag, which plays the same
  // "is this thing integrity-protected at all" role as a JWS signature.
  const signatureSegment = parts[parts.length - 1];
  return {
    ok: true,
    jwt: {
      header: header.value,
      payload,
      segments: parts.length,
      signatureBytes: base64UrlByteLength(signatureSegment),
      encrypted,
    },
  };
}

type SegmentResult =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; reason: string };

function decodeJsonSegment(segment: string): SegmentResult {
  if (segment.length === 0) return { ok: false, reason: "segment is empty" };
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) {
    return { ok: false, reason: "segment is not valid base64url" };
  }
  let text: string;
  try {
    text = base64UrlDecode(segment);
  } catch {
    return { ok: false, reason: "segment could not be base64url-decoded" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, reason: "segment did not contain JSON" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { ok: false, reason: "segment JSON is not an object" };
  }
  return { ok: true, value: parsed as Record<string, unknown> };
}

function base64UrlDecode(segment: string): string {
  return Buffer.from(segment.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

function base64UrlByteLength(segment: string): number {
  if (segment.length === 0) return 0;
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) return 0;
  return Buffer.from(segment.replace(/-/g, "+").replace(/_/g, "/"), "base64").length;
}

// ── JWT analysis ──

/**
 * Analyse a JWT (or a compact JWE) that was supplied to us. Never verifies a
 * signature and never fetches a key — see the module header.
 */
export function analyzeJwt(token: string, options: TokenAnalysisOptions = {}): IdentityFinding[] {
  const ref = tokenRef(token, options);
  const decoded = decodeJwtUnverified(token);
  if (!decoded.ok) {
    return [
      {
        id: `jwt-malformed:${ref}`,
        check: "jwt-malformed",
        title: "Supplied material does not decode as a JWT",
        severity: "medium",
        category: "tokens",
        description:
          `The value could not be decoded as a compact JWS or JWE (${decoded.reason}). A consumer that ` +
          "hands this to a permissive decoder rather than rejecting it outright is doing attacker-controlled " +
          "parsing before any signature check happens, which is where JWT libraries have historically broken.",
        evidence: [
          { label: "decode failure", detail: decoded.reason },
          { label: "input (redacted)", detail: redactTokenValue(token) },
        ],
        affectedPrincipals: [],
        remediation:
          "Reject structurally invalid tokens before parsing. Confirm the value was captured intact and is " +
          "actually a JWT rather than an opaque or encrypted reference token.",
      },
    ];
  }

  const { header, payload, encrypted } = decoded.jwt;
  const findings: IdentityFinding[] = [];
  const principals = jwtPrincipals(payload);

  findings.push(...checkJwtAlgorithm(decoded.jwt, ref, principals));
  findings.push(...checkJwtKeyIdentifier(header, ref, principals));
  if (encrypted) return findings;

  findings.push(...checkJwtLifetime(payload, ref, principals, options));
  findings.push(...checkJwtIssuer(payload, ref, principals, options));
  findings.push(...checkJwtAudience(payload, ref, principals, options));
  findings.push(...checkJwtReplayControls(payload, ref, principals));
  findings.push(...checkJwtSensitiveClaims(payload, ref, principals));
  findings.push(...checkJwtScope(payload, ref, principals, options));
  findings.push(...checkEntraTokenType(payload, ref, principals, options));
  findings.push(...checkEntraClientBinding(payload, ref, principals));
  findings.push(...checkEntraPrivilegedWids(payload, ref, principals));
  findings.push(...checkEntraIssuerTenancy(payload, ref, principals, options));
  findings.push(...checkEntraLongLivedSession(payload, ref, principals));

  return findings;
}

function checkJwtAlgorithm(
  jwt: DecodedJwt,
  ref: string,
  principals: AffectedPrincipal[],
): IdentityFinding[] {
  const findings: IdentityFinding[] = [];
  const algValue = jwt.header.alg;
  const alg = typeof algValue === "string" ? algValue : undefined;
  const normalized = alg?.trim().toLowerCase();

  if (!alg || normalized === "none") {
    findings.push({
      id: `jwt-alg-none:${ref}`,
      check: "jwt-alg-none",
      title: alg ? "Token declares the unsecured `none` algorithm" : "Token header declares no algorithm",
      severity: "critical",
      category: "tokens",
      description:
        (alg
          ? "The JOSE header sets `alg` to `none`, the unsecured JWS variant. "
          : "The JOSE header carries no `alg` at all, so the verifier picks the algorithm. ") +
        "Any verifier that honours the header's own algorithm choice will accept a token an attacker minted " +
        "themselves: the claims are freely editable and there is nothing to forge.",
      evidence: [
        { label: "header.alg", detail: alg ?? "absent" },
        { label: "signature bytes", detail: String(jwt.signatureBytes) },
      ],
      affectedPrincipals: principals,
      remediation:
        "Pin the accepted algorithm(s) in the verifier configuration and reject the header's `alg` as an input. " +
        "`none` must never be in the accept list.",
      references: ["https://datatracker.ietf.org/doc/html/rfc8725#section-3.1"],
    });
    return findings;
  }

  // A signed-looking algorithm with no signature bytes is the same attack with
  // a different disguise — the header says RS256 but there is nothing to check.
  if (!jwt.encrypted && jwt.signatureBytes === 0) {
    findings.push({
      id: `jwt-alg-none:${ref}`,
      check: "jwt-alg-none",
      title: `Token declares \`${alg}\` but carries an empty signature`,
      severity: "critical",
      category: "tokens",
      description:
        "The header claims a signing algorithm while the signature segment is empty. A verifier that treats an " +
        "empty signature as \"nothing to compare\" rather than as a failure accepts arbitrary claims.",
      evidence: [
        { label: "header.alg", detail: alg },
        { label: "signature bytes", detail: "0" },
      ],
      affectedPrincipals: principals,
      remediation: "Reject tokens with an empty signature segment before any claim is read.",
    });
  }

  if (SYMMETRIC_ALGORITHMS.has(alg.toUpperCase())) {
    findings.push({
      id: `jwt-algorithm-confusion-exposure:${ref}`,
      check: "jwt-algorithm-confusion-exposure",
      title: `Token is signed with the symmetric algorithm \`${alg}\``,
      severity: "high",
      category: "tokens",
      description:
        "The token uses an HMAC algorithm, so the verification key is the same shared secret used to sign. " +
        "Where the issuer is expected to sign asymmetrically (RS256/ES256/PS256), a verifier that trusts the " +
        "header's algorithm can be handed an HS256 token signed with the issuer's *public* key — which is " +
        "published — and will accept it. This is the classic algorithm-confusion forgery.",
      evidence: [
        { label: "header.alg", detail: alg },
        { label: "algorithm family", detail: "symmetric (HMAC)" },
        { label: "header.kid", detail: typeof jwt.header.kid === "string" ? jwt.header.kid : "absent" },
      ],
      affectedPrincipals: principals,
      remediation:
        "Configure the verifier with a single expected algorithm and resolve the key by algorithm family, not by " +
        "the header. Never let an HMAC key and an asymmetric public key resolve through the same code path.",
      references: ["https://datatracker.ietf.org/doc/html/rfc8725#section-2.1"],
    });
  } else if (!ASYMMETRIC_ALGORITHMS.has(alg.toUpperCase()) && !jwt.encrypted) {
    findings.push({
      id: `jwt-algorithm-confusion-exposure:${ref}`,
      check: "jwt-algorithm-confusion-exposure",
      title: `Token declares the unrecognised algorithm \`${alg}\``,
      severity: "medium",
      category: "tokens",
      description:
        "`alg` is not a registered JWS algorithm this analyser recognises. An unrecognised algorithm means the " +
        "verifier is either rejecting the token or resolving something non-standard — and the second case is " +
        "worth reading, because algorithm handling is where JWT libraries go wrong.",
      evidence: [{ label: "header.alg", detail: alg }],
      affectedPrincipals: principals,
      remediation: "Confirm which algorithm the verifier accepts and pin it explicitly.",
    });
  }

  return findings;
}

function checkJwtKeyIdentifier(
  header: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
): IdentityFinding[] {
  const evidence: IdentityEvidence[] = [];
  const reasons: string[] = [];

  const kid = typeof header.kid === "string" ? header.kid : undefined;
  if (kid !== undefined) {
    for (const shape of UNSAFE_KID_SHAPES) {
      if (shape.pattern.test(kid)) reasons.push(`\`kid\` contains a ${shape.label}`);
    }
    if (reasons.length > 0) {
      evidence.push({ label: "header.kid", detail: kid });
    }
  }

  // `jku` and `x5u` tell the verifier where to fetch the key from. Honouring
  // either means the token names its own trust anchor.
  for (const remote of ["jku", "x5u"] as const) {
    const value = header[remote];
    if (typeof value === "string" && value.length > 0) {
      reasons.push(`\`${remote}\` points the verifier at a key location carried inside the token`);
      evidence.push({ label: `header.${remote}`, detail: value });
    }
  }

  // An embedded key is the same problem stated even more directly.
  for (const embedded of ["jwk", "x5c"] as const) {
    if (header[embedded] !== undefined) {
      reasons.push(`\`${embedded}\` embeds key material in the token itself`);
      evidence.push({ label: `header.${embedded}`, detail: "present" });
    }
  }

  if (reasons.length === 0) return [];

  return [
    {
      id: `jwt-unsafe-key-identifier:${ref}`,
      check: "jwt-unsafe-key-identifier",
      title: "Token header steers verification-key resolution",
      severity: "high",
      category: "tokens",
      description:
        `${reasons.join("; ")}. The JOSE header is attacker-controlled data. A verifier that uses it to look up ` +
        "a key — by interpolating `kid` into a path or query, by fetching `jku`/`x5u`, or by trusting an " +
        "embedded `jwk`/`x5c` — lets the token choose the key it will be checked against, which is a complete " +
        "authentication bypass. This module deliberately does not fetch any of these locations.",
      evidence,
      affectedPrincipals: principals,
      remediation:
        "Resolve verification keys only from a pre-configured, issuer-pinned key set. Treat `kid` as an opaque " +
        "lookup key against that set (never a path or query fragment) and ignore `jku`, `x5u`, `jwk`, and `x5c`.",
      references: ["https://datatracker.ietf.org/doc/html/rfc8725#section-3.9"],
    },
  ];
}

function checkJwtLifetime(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
  options: TokenAnalysisOptions,
): IdentityFinding[] {
  const findings: IdentityFinding[] = [];
  const now = options.now ?? new Date();
  const maxLifetimeMs = (options.maxLifetimeMinutes ?? 60) * MINUTE_MS;

  const exp = numericClaim(payload, "exp");
  const iat = numericClaim(payload, "iat");
  const nbf = numericClaim(payload, "nbf");

  if (exp === undefined) {
    findings.push({
      id: `jwt-missing-expiry:${ref}`,
      check: "jwt-missing-expiry",
      title: "Token carries no expiry",
      severity: "critical",
      category: "tokens",
      description:
        "There is no `exp` claim, so the token is valid forever from the verifier's point of view. A stolen " +
        "token with no expiry is permanent access: rotation, sign-out, and password reset all fail to revoke " +
        "it, and the only remaining control is revoking the signing key for every token at once.",
      evidence: [
        { label: "payload.exp", detail: "absent" },
        { label: "payload.iat", detail: iat === undefined ? "absent" : isoFromEpoch(iat) },
      ],
      affectedPrincipals: principals,
      remediation:
        "Issue tokens with a short `exp` and reject tokens without one. A verifier must treat a missing `exp` as " +
        "invalid, not as unbounded validity.",
    });
    return findings;
  }

  const expMs = exp * 1000;
  if (expMs < now.getTime()) {
    findings.push({
      id: `jwt-expired:${ref}`,
      check: "jwt-expired",
      title: "Token is already expired",
      severity: "info",
      category: "tokens",
      description:
        "The token's `exp` is in the past relative to the analysis clock. Recorded so a reviewer knows the " +
        "remaining findings describe a token that a correct verifier would already reject — they still describe " +
        "how the issuer mints tokens, which is the durable part.",
      evidence: [
        { label: "payload.exp", detail: isoFromEpoch(exp) },
        { label: "analysis clock", detail: now.toISOString() },
      ],
      affectedPrincipals: principals,
      remediation: "None. Informational context for the other findings on this token.",
    });
  }

  // Prefer iat, fall back to nbf, and only then to the analysis clock — which
  // understates an old token's lifetime, so the check errs toward not firing.
  const startMs = iat !== undefined ? iat * 1000 : nbf !== undefined ? nbf * 1000 : now.getTime();
  const lifetimeMs = expMs - startMs;
  if (lifetimeMs > maxLifetimeMs) {
    const severity: IdentitySeverity =
      lifetimeMs >= 24 * HOUR_MS ? "critical" : lifetimeMs >= 4 * HOUR_MS ? "high" : "medium";
    findings.push({
      id: `jwt-excessive-lifetime:${ref}`,
      check: "jwt-excessive-lifetime",
      title: `Token is valid for ${formatDuration(lifetimeMs)}`,
      severity,
      category: "tokens",
      description:
        `The validity window is ${formatDuration(lifetimeMs)}, above the ${formatDuration(maxLifetimeMs)} ` +
        "threshold. Bearer tokens cannot be recalled: the lifetime is exactly how long a stolen token keeps " +
        "working after the account is disabled, the password is reset, or conditional access is tightened.",
      evidence: [
        { label: iat !== undefined ? "payload.iat" : nbf !== undefined ? "payload.nbf" : "analysis clock", detail: isoFromEpoch(startMs / 1000) },
        { label: "payload.exp", detail: isoFromEpoch(exp) },
        { label: "lifetime", detail: formatDuration(lifetimeMs) },
      ],
      affectedPrincipals: principals,
      remediation:
        "Shorten the token lifetime policy toward the platform default and rely on refresh plus continuous " +
        "access evaluation for continuity rather than on a long-lived access token.",
    });
  }

  return findings;
}

function checkJwtIssuer(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
  options: TokenAnalysisOptions,
): IdentityFinding[] {
  const iss = stringClaim(payload, "iss");

  if (iss === undefined) {
    return [
      {
        id: `jwt-untrusted-issuer:${ref}`,
        check: "jwt-untrusted-issuer",
        title: "Token carries no issuer",
        severity: "medium",
        category: "tokens",
        description:
          "There is no `iss` claim, so a verifier cannot tell which authority minted the token. Without an " +
          "issuer check, any party the verifier trusts a key from can mint a token for any other — one " +
          "compromised or merely sloppy issuer becomes an authentication bypass across every relying party " +
          "that shares the key set.",
        evidence: [{ label: "payload.iss", detail: "absent" }],
        affectedPrincipals: principals,
        remediation: "Require and pin `iss` in the verifier, and reject tokens without it.",
      },
    ];
  }

  if (options.expectedIssuer !== undefined && iss !== options.expectedIssuer) {
    return [
      {
        id: `jwt-untrusted-issuer:${ref}`,
        check: "jwt-untrusted-issuer",
        title: "Token issuer does not match the expected issuer",
        severity: "high",
        category: "tokens",
        description:
          "The `iss` claim differs from the issuer the consumer was configured to trust. Either the token came " +
          "from somewhere it should not have, or the verifier's issuer pin is wrong — both are authentication " +
          "boundary problems.",
        evidence: [
          { label: "payload.iss", detail: iss },
          { label: "expected issuer", detail: options.expectedIssuer },
        ],
        affectedPrincipals: principals,
        remediation:
          "Reconcile the configured issuer with the authority actually minting these tokens, and reject any " +
          "token whose `iss` is not an exact match.",
      },
    ];
  }

  return [];
}

function checkJwtAudience(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
  options: TokenAnalysisOptions,
): IdentityFinding[] {
  const audValue = payload.aud;
  const aud = claimList(audValue);
  const expected = options.expectedAudience === undefined
    ? undefined
    : Array.isArray(options.expectedAudience)
      ? options.expectedAudience
      : [options.expectedAudience];

  if (audValue === undefined || aud.length === 0) {
    return [
      {
        id: `jwt-weak-audience:${ref}`,
        check: "jwt-weak-audience",
        title: "Token carries no audience",
        severity: "high",
        category: "tokens",
        description:
          "There is no usable `aud` claim, so nothing binds the token to a particular resource. A token minted " +
          "for a low-value API can then be replayed against a high-value one that shares the issuer — the " +
          "confused-deputy pattern that makes token theft in one service a compromise of every service.",
        evidence: [{ label: "payload.aud", detail: audValue === undefined ? "absent" : "empty" }],
        affectedPrincipals: principals,
        remediation: "Mint tokens with a resource-specific `aud` and require an exact match at every verifier.",
      },
    ];
  }

  const wildcard = aud.find((a) => a === "*" || a === "" || a.endsWith("/*"));
  if (wildcard !== undefined) {
    return [
      {
        id: `jwt-weak-audience:${ref}`,
        check: "jwt-weak-audience",
        title: "Token audience is a wildcard",
        severity: "high",
        category: "tokens",
        description:
          "The `aud` claim is a wildcard, which is the same as having no audience at all: every resource that " +
          "trusts this issuer will match. The token is replayable across the entire trust domain.",
        evidence: [{ label: "payload.aud", detail: aud.join(", ") }],
        affectedPrincipals: principals,
        remediation: "Replace the wildcard with the specific resource identifier the token is intended for.",
      },
    ];
  }

  if (expected !== undefined && !aud.some((a) => expected.includes(a))) {
    return [
      {
        id: `jwt-weak-audience:${ref}`,
        check: "jwt-weak-audience",
        title: "Token audience does not match the expected audience",
        severity: "high",
        category: "tokens",
        description:
          "None of the values in `aud` match what this consumer was configured to accept. A verifier that " +
          "accepts it anyway is accepting a token minted for somebody else — which is how a token leaked to a " +
          "third-party API turns into access to this one.",
        evidence: [
          { label: "payload.aud", detail: aud.join(", ") },
          { label: "expected audience", detail: expected.join(", ") },
        ],
        affectedPrincipals: principals,
        remediation: "Require an exact `aud` match against the resource identifier of this consumer.",
      },
    ];
  }

  if (aud.length > 1) {
    return [
      {
        id: `jwt-weak-audience:${ref}`,
        check: "jwt-weak-audience",
        title: `Token audience covers ${aud.length} resources`,
        severity: "medium",
        category: "tokens",
        description:
          "The token is addressed to more than one resource, so each of them is a place the token can be stolen " +
          "from and every other one is where it can then be replayed. The blast radius of a leak is the whole " +
          "audience list, not just the resource that leaked it.",
        evidence: [{ label: "payload.aud", detail: aud.join(", ") }],
        affectedPrincipals: principals,
        remediation: "Mint one token per resource so a leak from one does not reach the others.",
      },
    ];
  }

  return [];
}

function checkJwtReplayControls(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
): IdentityFinding[] {
  const missing: string[] = [];
  if (numericClaim(payload, "nbf") === undefined) missing.push("nbf");
  if (stringClaim(payload, "jti") === undefined && numericClaim(payload, "jti") === undefined) {
    missing.push("jti");
  }
  if (missing.length === 0) return [];

  return [
    {
      id: `jwt-missing-replay-controls:${ref}`,
      check: "jwt-missing-replay-controls",
      title: `Token omits ${missing.join(" and ")}`,
      severity: "low",
      category: "tokens",
      description:
        (missing.includes("jti")
          ? "Without `jti` there is no unique identifier a verifier can record, so replay detection and " +
            "targeted revocation of a single token are both impossible. "
          : "") +
        (missing.includes("nbf")
          ? "Without `nbf` the token is valid the moment it is minted, which removes the window that limits " +
            "pre-issued or clock-skew-abusing tokens. "
          : "") +
        "Neither is fatal on its own; together with a long lifetime they mean a captured token cannot be " +
        "individually killed.",
      evidence: missing.map((claim) => ({ label: `payload.${claim}`, detail: "absent" })),
      affectedPrincipals: principals,
      remediation:
        "Emit `jti` on every token and record it at the verifier for the token's lifetime, and set `nbf` to the " +
        "issue time.",
    },
  ];
}

function checkJwtSensitiveClaims(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
): IdentityFinding[] {
  const evidence: IdentityEvidence[] = [];
  const kinds = new Set<string>();

  for (const { path, leaf, value } of walkClaims(payload)) {
    const lowerLeaf = leaf.toLowerCase();
    const uriLeaf = lowerLeaf.split("/").pop() ?? lowerLeaf;

    if (PII_CLAIM_NAMES.has(lowerLeaf) || PII_CLAIM_NAMES.has(uriLeaf)) {
      kinds.add("regulated PII");
      evidence.push({ label: `payload.${path}`, detail: `PII claim, value ${redactTokenValue(value)}` });
      continue;
    }
    if (INTERNAL_HOSTNAME_SHAPE.test(value) || PRIVATE_IP_SHAPE.test(value)) {
      kinds.add("internal network detail");
      evidence.push({ label: `payload.${path}`, detail: `internal host/address, value ${redactTokenValue(value)}` });
      continue;
    }
    if (EMAIL_SHAPE.test(value) && !IDENTIFIER_CLAIMS.has(lowerLeaf) && !IDENTIFIER_CLAIMS.has(uriLeaf)) {
      kinds.add("email address in a non-identifier claim");
      evidence.push({ label: `payload.${path}`, detail: `email-shaped, value ${redactTokenValue(value)}` });
    }
  }

  if (evidence.length === 0) return [];

  const severity: IdentitySeverity = kinds.has("regulated PII") || kinds.has("internal network detail")
    ? "medium"
    : "low";

  return [
    {
      id: `jwt-sensitive-claim-data:${ref}`,
      check: "jwt-sensitive-claim-data",
      title: `Token claims carry ${[...kinds].join(", ")}`,
      severity,
      category: "tokens",
      description:
        "A JWT payload is base64url, not encryption — anything in it is readable by every party the token " +
        "passes through, including browser storage, proxy logs, and any downstream API it is forwarded to. " +
        "Claim values are shown redacted below; the analyser never records the plaintext.",
      evidence: evidence.slice(0, 12),
      affectedPrincipals: principals,
      remediation:
        "Remove the data from the token and have the resource fetch it over an authenticated channel when it " +
        "is actually needed, or move to an encrypted (JWE) or opaque reference token.",
    },
  ];
}

function checkJwtScope(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
  options: TokenAnalysisOptions,
): IdentityFinding[] {
  const findings: IdentityFinding[] = [];
  const scopes = [
    ...claimList(payload.scp ?? payload.scope).flatMap((s) => s.split(/\s+/)).filter(Boolean),
    ...claimList(payload.roles),
  ];

  const tier0 = scopes.filter((s) => TIER0_GRAPH_PERMISSIONS.has(s));
  const highImpact = scopes.filter((s) => HIGH_IMPACT_GRAPH_PERMISSIONS.has(s));
  const broad = scopes.filter((s) => s === "*" || s === ".default" || s.endsWith("/.default"));

  if (tier0.length > 0 || highImpact.length > 0 || broad.length > 0) {
    const severity: IdentitySeverity = tier0.length > 0 ? "critical" : highImpact.length > 0 ? "high" : "medium";
    findings.push({
      id: `jwt-overly-broad-scope:${ref}`,
      check: "jwt-overly-broad-scope",
      title: tier0.length > 0
        ? "Token carries a tenant-takeover scope"
        : highImpact.length > 0
          ? "Token carries a high-impact scope"
          : "Token carries an unbounded scope",
      severity,
      category: "tokens",
      description:
        (tier0.length > 0
          ? "The token grants a permission that is equivalent to tenant compromise: its holder can assign " +
            "directory roles or mint credentials for other applications, and reach everything else from there. "
          : highImpact.length > 0
            ? "The token grants broad data access or policy control across the tenant. "
            : "") +
        (broad.length > 0
          ? "The scope list includes a wildcard or `.default`, meaning the token carries every permission the " +
            "application has ever been consented for rather than the ones this call needs. "
          : "") +
        "Whatever the token holds is what an attacker who captures it holds — scope is the blast radius.",
      evidence: [
        ...(tier0.length > 0 ? [{ label: "tier-0 permissions", detail: tier0.join(", ") }] : []),
        ...(highImpact.length > 0 ? [{ label: "high-impact permissions", detail: highImpact.join(", ") }] : []),
        ...(broad.length > 0 ? [{ label: "unbounded scopes", detail: broad.join(", ") }] : []),
        { label: "scope claim", detail: payload.scp !== undefined ? "scp" : payload.scope !== undefined ? "scope" : "roles" },
      ],
      affectedPrincipals: principals,
      remediation:
        "Request the narrowest scope the caller actually needs, split high-privilege work into a separate " +
        "identity, and stop using `.default` where an explicit scope list would do.",
    });
  }

  const groups = claimList(payload.groups);
  const maxGroups = options.maxGroupClaims ?? 50;
  if (groups.length > maxGroups) {
    findings.push({
      id: `jwt-overly-broad-scope:groups:${ref}`,
      check: "jwt-overly-broad-scope",
      title: `Token carries ${groups.length} group memberships`,
      severity: "low",
      category: "tokens",
      description:
        `The \`groups\` claim lists ${groups.length} memberships, above the configured ceiling of ${maxGroups}. ` +
        "A token that enumerates the subject's entire group graph is both an authorization surface (every " +
        "group a downstream service keys off is present) and a disclosure of the directory's structure to " +
        "anyone the token passes through.",
      evidence: [
        { label: "payload.groups", detail: `${groups.length} entries` },
        { label: "ceiling", detail: String(maxGroups) },
      ],
      affectedPrincipals: principals,
      remediation:
        "Emit only the groups the application is configured to consume, or switch to app-role assignments and " +
        "resolve group membership at the resource.",
    });
  }

  return findings;
}

// ── Entra-specific ──

type EntraTokenShape = "access" | "id" | "ambiguous" | "unknown";

/**
 * Classify an Entra token by the markers only one kind carries. An access token
 * is for a resource and is opaque to the client; an ID token is for the client
 * and must never be used as a credential. Getting this wrong in either
 * direction is a real, common bug, so the classification is deliberately based
 * on claims that do not overlap. `roles` is NOT used: Entra emits app-role
 * assignments into both kinds.
 */
export function classifyEntraToken(payload: Record<string, unknown>): EntraTokenShape {
  const idMarkers = ["nonce", "at_hash", "c_hash"].filter((k) => payload[k] !== undefined);
  const accessMarkers = ["scp", "scope", "wids", "idtyp", "xms_cc", "acrs"].filter(
    (k) => payload[k] !== undefined,
  );
  if (accessMarkers.length > 0 && idMarkers.length > 0) return "ambiguous";
  if (accessMarkers.length > 0) return "access";
  if (idMarkers.length > 0) return "id";
  return "unknown";
}

function checkEntraTokenType(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
  options: TokenAnalysisOptions,
): IdentityFinding[] {
  const shape = classifyEntraToken(payload);
  const client = stringClaim(payload, "azp") ?? stringClaim(payload, "appid");
  const aud = claimList(payload.aud);

  if (options.expectedTokenType !== undefined && (shape === "access" || shape === "id") && shape !== options.expectedTokenType) {
    return [
      {
        id: `entra-token-type-mismatch:${ref}`,
        check: "entra-token-type-mismatch",
        title: `Token looks like an ${shape} token but is being handled as an ${options.expectedTokenType} token`,
        severity: "high",
        category: "tokens",
        description:
          "The two token types answer different questions. An ID token proves who signed in to *this* client " +
          "and is not a credential; an access token authorises a call to a *resource* and its claims are the " +
          "resource's to interpret. Treating an ID token as a bearer credential lets any client that receives " +
          "one call the resource; validating an access token as an ID token means checking `aud` against the " +
          "wrong value and accepting a token minted for someone else.",
        evidence: [
          { label: "classified as", detail: shape },
          { label: "expected", detail: options.expectedTokenType },
          { label: "payload.aud", detail: aud.length > 0 ? aud.join(", ") : "absent" },
          { label: "client (azp/appid)", detail: client ?? "absent" },
        ],
        affectedPrincipals: principals,
        remediation:
          "Use the access token for resource calls and the ID token only to establish the local session. Never " +
          "forward an ID token as an Authorization bearer value.",
        references: ["https://learn.microsoft.com/entra/identity-platform/access-tokens"],
      },
    ];
  }

  if (shape === "ambiguous") {
    return [
      {
        id: `entra-token-type-mismatch:${ref}`,
        check: "entra-token-type-mismatch",
        title: "Token carries markers of both an access token and an ID token",
        severity: "medium",
        category: "tokens",
        description:
          "The payload holds both authorization markers (`scp`/`wids`/`idtyp`) and authentication markers " +
          "(`nonce`/`at_hash`). A consumer cannot tell from the token which validation rules apply, and the " +
          "two rule sets differ in exactly the checks that matter — audience binding and whether the token is " +
          "a credential at all.",
        evidence: [
          { label: "payload.aud", detail: aud.length > 0 ? aud.join(", ") : "absent" },
          { label: "client (azp/appid)", detail: client ?? "absent" },
        ],
        affectedPrincipals: principals,
        remediation: "Confirm which token type the issuer intends and validate it against that type's rules only.",
      },
    ];
  }

  if (shape === "access" && client !== undefined && aud.length === 1 && aud[0] === client) {
    return [
      {
        id: `entra-token-type-mismatch:${ref}`,
        check: "entra-token-type-mismatch",
        title: "Access token is audienced at the client that requested it",
        severity: "medium",
        category: "tokens",
        description:
          "`aud` equals `azp`/`appid`, so the resource and the client are the same application. This is the " +
          "shape apps most often mistake for an ID token and validate with ID-token rules, and it is also the " +
          "shape that makes an access token look safe to store in the browser. Neither is true.",
        evidence: [
          { label: "payload.aud", detail: aud.join(", ") },
          { label: "client (azp/appid)", detail: client },
        ],
        affectedPrincipals: principals,
        remediation:
          "Expose the API as its own resource with a distinct application ID URI so client and resource " +
          "identity stay separable, and validate the token as an access token.",
      },
    ];
  }

  return [];
}

function checkEntraClientBinding(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
): IdentityFinding[] {
  const azp = stringClaim(payload, "azp");
  const appid = stringClaim(payload, "appid");
  const client = azp ?? appid;
  const acr = stringClaim(payload, "azpacr") ?? stringClaim(payload, "appidacr");

  if (client === undefined) {
    return [
      {
        id: `entra-token-weak-client-binding:${ref}`,
        check: "entra-token-weak-client-binding",
        title: "Token names no client application",
        severity: "medium",
        category: "tokens",
        description:
          "Neither `azp` nor `appid` is present, so the resource cannot tell which application obtained the " +
          "token on the user's behalf. Without that, per-client authorization, client allow-listing, and any " +
          "forensic answer to \"which app did this\" are all unavailable.",
        evidence: [
          { label: "payload.azp", detail: "absent" },
          { label: "payload.appid", detail: "absent" },
        ],
        affectedPrincipals: principals,
        remediation: "Require `azp`/`appid` at the resource and allow-list the clients permitted to call it.",
      },
    ];
  }

  const findings: IdentityFinding[] = [];

  // `azpacr`/`appidacr` of "0" means the client authenticated with nothing at
  // all — a public client. 1 is a shared secret, 2 is a certificate.
  if (acr === "0") {
    findings.push({
      id: `entra-token-weak-client-binding:${ref}`,
      check: "entra-token-weak-client-binding",
      title: "Token was issued to a client that presented no credential",
      severity: "high",
      category: "tokens",
      description:
        "`azpacr`/`appidacr` is `0`, meaning the client is public: it proved nothing about itself when it " +
        "requested this token. Any attacker who can drive the authorization flow — a phished consent, a " +
        "device-code prompt, a stolen refresh token — obtains the same token, because there is no client " +
        "secret they would also need to steal.",
      evidence: [
        { label: "payload.azpacr/appidacr", detail: acr },
        { label: "client (azp/appid)", detail: client },
      ],
      affectedPrincipals: principals,
      remediation:
        "Move the flow to a confidential client with a certificate credential (`azpacr` 2) where the " +
        "architecture allows, and constrain public clients with conditional access and token-protection " +
        "policies where it does not.",
    });
  }

  const publicClient = PUBLIC_CLIENT_APP_IDS[client.toLowerCase()];
  if (publicClient !== undefined) {
    findings.push({
      id: `entra-token-weak-client-binding:foci:${ref}`,
      check: "entra-token-weak-client-binding",
      title: `Token was issued to the first-party public client "${publicClient}"`,
      severity: "high",
      category: "tokens",
      description:
        `The client is ${publicClient}, a Microsoft first-party public client. These have no client secret and ` +
        "most belong to the family-of-client-IDs set, where a refresh token issued to one is redeemable for " +
        "access tokens across the others. A token in this family is therefore not scoped to one application in " +
        "any meaningful sense, and it is the standard pivot after any token theft on an Entra tenant.",
      evidence: [
        { label: "client (azp/appid)", detail: client },
        { label: "known client", detail: publicClient },
        { label: "payload.azpacr/appidacr", detail: acr ?? "absent" },
      ],
      affectedPrincipals: principals,
      remediation:
        "Establish whether this client should be reaching this resource at all. Restrict first-party client " +
        "usage with conditional access application-filter policies and monitor for token redemption across the " +
        "FOCI family.",
    });
  }

  return findings;
}

function checkEntraPrivilegedWids(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
): IdentityFinding[] {
  const wids = claimList(payload.wids).map((w) => w.toLowerCase());
  if (wids.length === 0) return [];

  const tier0 = wids.filter((w) => TIER0_ROLE_TEMPLATE_IDS.has(w));
  const privileged = wids.filter((w) => PRIVILEGED_ROLE_TEMPLATE_IDS.has(w) && !TIER0_ROLE_TEMPLATE_IDS.has(w));
  if (tier0.length === 0 && privileged.length === 0) return [];

  return [
    {
      id: `entra-token-privileged-wids:${ref}`,
      check: "entra-token-privileged-wids",
      title: tier0.length > 0
        ? "Token carries a tier-0 directory role"
        : "Token carries a privileged directory role",
      severity: tier0.length > 0 ? "critical" : "high",
      category: "tokens",
      description:
        "The `wids` claim lists directory roles the subject holds, and they are carried inside the bearer token " +
        "itself. " +
        (tier0.length > 0
          ? "At least one is a tier-0 role whose holder can reach full tenant control in one hop — by minting " +
            "application credentials, resetting another administrator's authentication, or granting themselves " +
            "a directory role. Whoever holds this token holds that path for as long as the token is valid."
          : "Anyone who captures this token inherits the administrative capability it represents until it " +
            "expires, and no directory-side control revokes an already-issued access token."),
      evidence: [
        ...(tier0.length > 0
          ? [{ label: "tier-0 roles (wids)", detail: tier0.map(roleTemplateName).join(", ") }]
          : []),
        ...(privileged.length > 0
          ? [{ label: "privileged roles (wids)", detail: privileged.map(roleTemplateName).join(", ") }]
          : []),
        { label: "payload.wids", detail: `${wids.length} role template ids` },
      ],
      affectedPrincipals: principals,
      remediation:
        "Confirm the standing assignment is intended; move it behind PIM so the role is not present in " +
        "day-to-day tokens, and shorten the token lifetime for privileged sessions. This finding pairs with " +
        "`standing-privileged-access` and `privileged-account-without-mfa` from the tenant assessment.",
    },
  ];
}

function checkEntraIssuerTenancy(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
  options: TokenAnalysisOptions,
): IdentityFinding[] {
  const iss = stringClaim(payload, "iss");
  const tid = stringClaim(payload, "tid");
  const findings: IdentityFinding[] = [];
  const expectSingleTenant = options.expectSingleTenant ?? true;

  const multiTenantSegment = iss === undefined
    ? undefined
    : MULTI_TENANT_ISSUER_SEGMENTS.find((segment) => iss.toLowerCase().includes(segment));

  if (expectSingleTenant && multiTenantSegment !== undefined) {
    findings.push({
      id: `entra-token-multi-tenant-issuer:${ref}`,
      check: "entra-token-multi-tenant-issuer",
      title: `Token issuer uses the multi-tenant endpoint \`${multiTenantSegment.replaceAll("/", "")}\``,
      severity: "high",
      category: "tokens",
      description:
        "The issuer is the shared multi-tenant endpoint rather than a tenant-specific one. A verifier that " +
        "pins this issuer string accepts tokens minted for *any* Entra tenant, and an attacker only needs a " +
        "free tenant of their own to mint a valid one. The tenant check has to come from `tid`, and if it is " +
        "not there the token has no tenant boundary at all.",
      evidence: [
        { label: "payload.iss", detail: iss ?? "absent" },
        { label: "payload.tid", detail: tid ?? "absent" },
      ],
      affectedPrincipals: principals,
      remediation:
        "Validate `tid` against an allow-list of tenant ids in addition to `iss`, and pin the tenant-specific " +
        "issuer URL where the application is genuinely single-tenant.",
      references: ["https://learn.microsoft.com/entra/identity-platform/howto-convert-app-to-be-multi-tenant"],
    });
  }

  if (tid !== undefined && tid.toLowerCase() === MSA_TENANT_ID) {
    findings.push({
      id: `entra-token-multi-tenant-issuer:msa:${ref}`,
      check: "entra-token-multi-tenant-issuer",
      title: "Token was issued to a personal Microsoft account",
      severity: "high",
      category: "tokens",
      description:
        "`tid` is the fixed tenant every personal Microsoft account authenticates against. The subject is " +
        "outside the organisation's directory entirely: no conditional access, no lifecycle, no offboarding, " +
        "and the account can be created by anyone in seconds.",
      evidence: [
        { label: "payload.tid", detail: tid },
        { label: "payload.iss", detail: iss ?? "absent" },
      ],
      affectedPrincipals: principals,
      remediation:
        "Restrict the application's supported account types to organisational directories, or explicitly " +
        "allow-list the consumer tenant if personal accounts are intended.",
    });
  }

  if (
    options.expectedTenantId !== undefined &&
    tid !== undefined &&
    tid.toLowerCase() !== options.expectedTenantId.toLowerCase()
  ) {
    findings.push({
      id: `entra-token-multi-tenant-issuer:tid:${ref}`,
      check: "entra-token-multi-tenant-issuer",
      title: "Token tenant does not match the expected tenant",
      severity: "high",
      category: "tokens",
      description:
        "The `tid` claim names a different tenant than the one this consumer was configured for. Either the " +
        "token crossed a tenant boundary it should not have, or the consumer's tenant pin is wrong.",
      evidence: [
        { label: "payload.tid", detail: tid },
        { label: "expected tenant", detail: options.expectedTenantId },
      ],
      affectedPrincipals: principals,
      remediation: "Reject tokens whose `tid` is not on the configured tenant allow-list.",
    });
  }

  return findings;
}

function checkEntraLongLivedSession(
  payload: Record<string, unknown>,
  ref: string,
  principals: AffectedPrincipal[],
): IdentityFinding[] {
  const findings: IdentityFinding[] = [];
  const deviceId = stringClaim(payload, "deviceid");
  const clientCapabilities = claimList(payload.xms_cc).map((c) => c.toLowerCase());
  const amr = claimList(payload.amr);

  if (deviceId !== undefined) {
    findings.push({
      id: `entra-token-long-lived-session:prt:${ref}`,
      check: "entra-token-long-lived-session",
      title: "Token was issued from a device-bound primary refresh token",
      severity: "high",
      category: "tokens",
      description:
        "The `deviceid` claim means this token was minted from a Primary Refresh Token — the long-lived, " +
        "device-resident artifact that backs Windows single sign-on. A PRT is valid for 14 days with a rolling " +
        "renewal, covers every application the user can reach, and carries the MFA claim forward without " +
        "re-prompting. Extracting one from a compromised endpoint yields durable, MFA-satisfied access to the " +
        "whole tenant, and revoking it requires an explicit refresh-token revocation rather than a password " +
        "reset.",
      evidence: [
        { label: "payload.deviceid", detail: deviceId },
        { label: "payload.amr", detail: amr.length > 0 ? amr.join(", ") : "absent" },
      ],
      affectedPrincipals: principals,
      remediation:
        "Enforce token protection (sign-in session binding) in conditional access for privileged applications, " +
        "require compliant/hybrid-joined devices, and make PRT revocation part of the incident playbook rather " +
        "than relying on a password reset.",
      references: ["https://learn.microsoft.com/entra/identity/devices/concept-primary-refresh-token"],
    });
  }

  if (clientCapabilities.includes("cp1")) {
    findings.push({
      id: `entra-token-long-lived-session:cae:${ref}`,
      check: "entra-token-long-lived-session",
      title: "Token is a long-lived continuous-access-evaluation token",
      severity: "medium",
      category: "tokens",
      description:
        "`xms_cc` advertises the `CP1` client capability, so Entra issues this client long-lived tokens — up " +
        "to 28 hours instead of the usual hour — on the understanding that the resource enforces continuous " +
        "access evaluation and will honour a revocation event mid-lifetime. That trade is only safe if the " +
        "resource actually implements CAE; if it does not, the result is simply a 28-hour bearer token.",
      evidence: [
        { label: "payload.xms_cc", detail: clientCapabilities.join(", ") },
        { label: "payload.deviceid", detail: deviceId ?? "absent" },
      ],
      affectedPrincipals: principals,
      remediation:
        "Confirm the resource validates CAE claims challenges and honours revocation events. Where it does " +
        "not, do not advertise `CP1`.",
    });
  }

  return findings;
}

// ── SAML ──

/**
 * Analyse a SAML assertion or response. Accepts raw XML or the base64 form the
 * value takes in a `SAMLResponse` form field; the encoding is sniffed. Parses
 * and reasons about signature *structure* only — no cryptographic verification
 * happens here, and no key or metadata is fetched.
 */
export function analyzeSamlAssertion(
  material: string,
  options: TokenAnalysisOptions = {},
): IdentityFinding[] {
  const ref = tokenRef(material, options);
  const xml = unwrapSamlEncoding(material);
  if (xml === undefined) {
    return [samlMalformed(ref, material, "input is neither XML nor base64-encoded XML")];
  }

  const parsed = parseXml(xml);
  if (!parsed.ok) return [samlMalformed(ref, material, parsed.reason)];

  const { all } = parsed;
  const assertions = all.filter((e) => e.name === "Assertion");
  const encryptedAssertions = all.filter((e) => e.name === "EncryptedAssertion");
  const responses = all.filter((e) => e.name === "Response");

  if (assertions.length === 0 && encryptedAssertions.length === 0 && responses.length === 0) {
    return [samlMalformed(ref, material, "document contains no SAML Response, Assertion, or EncryptedAssertion")];
  }

  const coverage = signatureCoverage(all);
  const findings: IdentityFinding[] = [];

  findings.push(...checkSamlSignatureCoverage(ref, assertions, responses, encryptedAssertions, coverage));
  findings.push(...checkSamlWrapping(ref, all, assertions, coverage));

  for (const assertion of assertions) {
    const principals = samlPrincipals(assertion);
    const suffix = assertion.attrs.ID ? `${ref}:${assertion.attrs.ID}` : ref;
    findings.push(...checkSamlConditions(assertion, suffix, principals, options));
    findings.push(...checkSamlAudience(assertion, suffix, principals, options));
    findings.push(...checkSamlSubjectConfirmation(assertion, suffix, principals, options));
    findings.push(...checkSamlNameIdComment(assertion, suffix, principals));
    findings.push(...checkGoldenSamlPreconditions(assertion, suffix, principals, encryptedAssertions.length > 0, coverage));
  }

  return findings;
}

function samlMalformed(ref: string, material: string, reason: string): IdentityFinding {
  return {
    id: `saml-malformed:${ref}`,
    check: "saml-malformed",
    title: "Supplied material does not parse as a SAML document",
    severity: "medium",
    category: "tokens",
    description:
      `The value could not be parsed as SAML XML (${reason}). Note what this means for the relying party: ` +
      "SAML processing is XML processing, and a document that a strict parser rejects but a lenient one " +
      "accepts is exactly the gap signature-wrapping and canonicalisation attacks live in. A relying party " +
      "must reject malformed input outright rather than recover from it.",
    evidence: [
      { label: "parse failure", detail: reason },
      { label: "input (redacted)", detail: redactTokenValue(material) },
    ],
    affectedPrincipals: [],
    remediation:
      "Confirm the assertion was captured intact. Ensure the relying party uses a strict, non-recovering XML " +
      "parser with entity expansion and external entity resolution disabled.",
  };
}

interface SignatureCoverage {
  signatures: XmlElement[];
  /** Signature → the element its Reference resolves to, when it resolves. */
  targets: Map<XmlElement, XmlElement | undefined>;
  /** Reference URIs that resolve to nothing in this document. */
  danglingReferences: string[];
  /** ID values used by more than one element. */
  duplicateIds: string[];
  /** Signatures whose target is not an ancestor — i.e. not enveloped. */
  detachedSignatures: XmlElement[];
}

function signatureCoverage(all: XmlElement[]): SignatureCoverage {
  const byId = new Map<string, XmlElement[]>();
  for (const el of all) {
    const id = el.attrs.ID ?? el.attrs.Id ?? el.attrs.id;
    if (id === undefined || id.length === 0) continue;
    const bucket = byId.get(id);
    if (bucket) bucket.push(el);
    else byId.set(id, [el]);
  }

  const signatures = all.filter((e) => e.name === "Signature");
  const targets = new Map<XmlElement, XmlElement | undefined>();
  const danglingReferences: string[] = [];
  const detachedSignatures: XmlElement[] = [];

  for (const signature of signatures) {
    const references = descendants(signature).filter((e) => e.name === "Reference");
    // An empty URI means "the whole document"; treat it as covering the root.
    const uri = references.map((r) => r.attrs.URI).find((u) => u !== undefined);
    if (uri === undefined) {
      targets.set(signature, undefined);
      continue;
    }
    if (uri === "") {
      targets.set(signature, signature.parent ?? undefined);
      continue;
    }
    const resolved = byId.get(uri.replace(/^#/, ""));
    if (resolved === undefined || resolved.length === 0) {
      danglingReferences.push(uri);
      targets.set(signature, undefined);
      continue;
    }
    const target = resolved[0];
    targets.set(signature, target);
    if (!isDescendantOf(signature, target)) detachedSignatures.push(signature);
  }

  const duplicateIds = [...byId.entries()].filter(([, els]) => els.length > 1).map(([id]) => id);
  return { signatures, targets, danglingReferences, duplicateIds, detachedSignatures };
}

function isSignedBy(element: XmlElement, coverage: SignatureCoverage): boolean {
  for (const target of coverage.targets.values()) {
    if (target === element) return true;
  }
  return false;
}

function checkSamlSignatureCoverage(
  ref: string,
  assertions: XmlElement[],
  responses: XmlElement[],
  encryptedAssertions: XmlElement[],
  coverage: SignatureCoverage,
): IdentityFinding[] {
  if (assertions.length === 0) return [];

  // Partial coverage — some assertions signed, some not — is a wrapping shape,
  // not a coverage gap, and `saml-signature-wrapping-exposure` owns it. Emitting
  // both would put two contradictory descriptions on the same document.
  const signedAssertions = assertions.filter((a) => isSignedBy(a, coverage));
  if (signedAssertions.length > 0) return [];

  const responseSigned = responses.some((r) => isSignedBy(r, coverage));
  const nothingSigned = coverage.signatures.length === 0;

  return [
    {
      id: `saml-unsigned-assertion:${ref}`,
      check: "saml-unsigned-assertion",
      title: nothingSigned
        ? "SAML document carries no signature at all"
        : responseSigned
          ? "Only the SAML response is signed, not the assertion"
          : "SAML assertion is not covered by any signature",
      severity: nothingSigned ? "critical" : responseSigned ? "medium" : "critical",
      category: "tokens",
      description:
        (nothingSigned
          ? "There is no `Signature` element anywhere in the document. Nothing binds these claims to the " +
            "identity provider: a relying party that accepts this is accepting whatever the browser posted, " +
            "and the entire authentication decision is attacker-supplied."
          : responseSigned
            ? "The signature covers the `Response` element but not the `Assertion` inside it. The assertion is " +
              "covered transitively only for as long as the relying party validates the response as a whole " +
              "and reads the assertion from inside the verified subtree. Many implementations verify the " +
              "response and then re-extract the assertion by searching the document — at which point an " +
              "injected second assertion is read instead. This is the precondition for signature wrapping."
            : "No signature reference resolves to the assertion element, so the assertion's claims are " +
              "unauthenticated even though the document contains signatures.") +
        (encryptedAssertions.length > 0
          ? " The document also contains encrypted assertions, which this offline analyser does not decrypt."
          : ""),
      evidence: [
        { label: "Assertion elements", detail: String(assertions.length) },
        { label: "signed assertions", detail: String(signedAssertions.length) },
        { label: "Signature elements", detail: String(coverage.signatures.length) },
        { label: "Response signed", detail: responseSigned ? "yes" : "no" },
      ],
      affectedPrincipals: assertions.flatMap(samlPrincipals),
      remediation:
        "Sign the assertion itself (in addition to the response, if the response is signed) and configure the " +
        "relying party to reject any assertion it did not read out of a verified, reference-resolved subtree.",
      references: ["https://www.oasis-open.org/committees/download.php/27819/sstc-saml-tech-overview-2.0-cd-02.pdf"],
    },
  ];
}

function checkSamlWrapping(
  ref: string,
  all: XmlElement[],
  assertions: XmlElement[],
  coverage: SignatureCoverage,
): IdentityFinding[] {
  const reasons: string[] = [];
  const evidence: IdentityEvidence[] = [];
  let critical = false;

  if (assertions.length > 1) {
    critical = true;
    reasons.push(`the document contains ${assertions.length} Assertion elements`);
    evidence.push({
      label: "Assertion IDs",
      detail: assertions.map((a) => a.attrs.ID ?? "(no ID)").join(", "),
    });
  }

  if (coverage.duplicateIds.length > 0) {
    critical = true;
    reasons.push(`the ID value(s) ${coverage.duplicateIds.join(", ")} are used by more than one element`);
    evidence.push({ label: "duplicate ID values", detail: coverage.duplicateIds.join(", ") });
  }

  const buriedAssertions = assertions.filter((a) =>
    ancestors(a).some((p) => p.name === "Signature" || p.name === "Object" || p.name === "Extensions"),
  );
  if (buriedAssertions.length > 0) {
    critical = true;
    reasons.push(
      `${buriedAssertions.length} Assertion element(s) are nested inside a Signature, Object, or Extensions element`,
    );
    evidence.push({
      label: "buried Assertion IDs",
      detail: buriedAssertions.map((a) => a.attrs.ID ?? "(no ID)").join(", "),
    });
  }

  const signedAssertions = assertions.filter((a) => isSignedBy(a, coverage));
  if (signedAssertions.length > 0 && signedAssertions.length < assertions.length) {
    critical = true;
    reasons.push("some assertions are signed and others are not");
    evidence.push({
      label: "signed / total assertions",
      detail: `${signedAssertions.length} / ${assertions.length}`,
    });
  }

  if (coverage.danglingReferences.length > 0) {
    reasons.push(
      `signature reference(s) ${coverage.danglingReferences.join(", ")} do not resolve to any element in the document`,
    );
    evidence.push({ label: "dangling Reference URIs", detail: coverage.danglingReferences.join(", ") });
  }

  if (coverage.detachedSignatures.length > 0) {
    reasons.push(
      `${coverage.detachedSignatures.length} signature(s) reference an element they are not contained in`,
    );
    evidence.push({
      label: "non-enveloped signatures",
      detail: String(coverage.detachedSignatures.length),
    });
  }

  if (reasons.length === 0) return [];

  return [
    {
      id: `saml-signature-wrapping-exposure:${ref}`,
      check: "saml-signature-wrapping-exposure",
      title: "SAML document has the structure of an XML signature wrapping attack",
      severity: critical ? "critical" : "high",
      category: "tokens",
      description:
        `Structural anomalies found: ${reasons.join("; ")}. XML Signature Wrapping works by exploiting the gap ` +
        "between the element a signature cryptographically covers and the element the application actually " +
        "reads. The signature verifies — it is a genuine, unmodified IdP signature over a genuine assertion — " +
        "while the application processes a second, attacker-authored assertion somewhere else in the document. " +
        "The result is a fully valid signature check and a completely forged identity, which is why this is the " +
        "single highest-value structural check on a SAML response. This analyser reports structure only; it " +
        "does not verify the signature, so a clean result here is not proof the signature is valid.",
      evidence,
      affectedPrincipals: assertions.flatMap(samlPrincipals),
      remediation:
        "Process only the assertion the verified `Reference` resolves to — resolve by ID against the verified " +
        "subtree, never by re-searching the document. Reject documents containing more than one assertion, " +
        "duplicate ID values, or dangling references, and use a SAML library that returns the verified node " +
        "rather than a boolean.",
      references: ["https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky"],
    },
  ];
}

function checkSamlConditions(
  assertion: XmlElement,
  ref: string,
  principals: AffectedPrincipal[],
  options: TokenAnalysisOptions,
): IdentityFinding[] {
  const conditions = descendants(assertion).find((e) => e.name === "Conditions");
  const maxValidityMs = (options.maxAssertionValidityMinutes ?? 10) * MINUTE_MS;

  if (conditions === undefined) {
    return [
      {
        id: `saml-weak-conditions:${ref}`,
        check: "saml-weak-conditions",
        title: "SAML assertion carries no Conditions element",
        severity: "high",
        category: "tokens",
        description:
          "There is no `Conditions` element, so the assertion states no validity window and no audience " +
          "restriction. A captured assertion stays replayable indefinitely and against any relying party that " +
          "trusts the issuer.",
        evidence: [{ label: "Assertion/Conditions", detail: "absent" }],
        affectedPrincipals: principals,
        remediation:
          "Configure the IdP to emit `Conditions` with a short `NotBefore`/`NotOnOrAfter` window and an " +
          "`AudienceRestriction`, and reject assertions without them at the relying party.",
      },
    ];
  }

  const notBefore = conditions.attrs.NotBefore;
  const notOnOrAfter = conditions.attrs.NotOnOrAfter;
  const findings: IdentityFinding[] = [];

  if (notOnOrAfter === undefined) {
    findings.push({
      id: `saml-weak-conditions:${ref}`,
      check: "saml-weak-conditions",
      title: "SAML assertion has no expiry",
      severity: "high",
      category: "tokens",
      description:
        "`Conditions` carries no `NotOnOrAfter`, so the assertion never expires. Anything that captures it — " +
        "a proxy log, browser history, a referer header — holds a permanently replayable authentication.",
      evidence: [
        { label: "Conditions/@NotOnOrAfter", detail: "absent" },
        { label: "Conditions/@NotBefore", detail: notBefore ?? "absent" },
      ],
      affectedPrincipals: principals,
      remediation: "Emit a short `NotOnOrAfter` and reject assertions without one.",
    });
    return findings;
  }

  const endMs = Date.parse(notOnOrAfter);
  const startMs = notBefore === undefined ? Number.NaN : Date.parse(notBefore);

  if (notBefore === undefined) {
    findings.push({
      id: `saml-weak-conditions:notbefore:${ref}`,
      check: "saml-weak-conditions",
      title: "SAML assertion has no NotBefore bound",
      severity: "medium",
      category: "tokens",
      description:
        "`Conditions` sets `NotOnOrAfter` but no `NotBefore`, so the assertion is valid from the beginning of " +
        "time up to its expiry. That removes the lower bound that would otherwise limit pre-minted assertions " +
        "and clock-skew abuse.",
      evidence: [
        { label: "Conditions/@NotBefore", detail: "absent" },
        { label: "Conditions/@NotOnOrAfter", detail: notOnOrAfter },
      ],
      affectedPrincipals: principals,
      remediation: "Emit `NotBefore` alongside `NotOnOrAfter` and enforce both at the relying party.",
    });
  }

  if (Number.isFinite(endMs) && Number.isFinite(startMs) && endMs - startMs > maxValidityMs) {
    findings.push({
      id: `saml-weak-conditions:window:${ref}`,
      check: "saml-weak-conditions",
      title: `SAML assertion is valid for ${formatDuration(endMs - startMs)}`,
      severity: endMs - startMs >= HOUR_MS ? "high" : "medium",
      category: "tokens",
      description:
        `The validity window is ${formatDuration(endMs - startMs)}, above the ` +
        `${formatDuration(maxValidityMs)} threshold. A SAML assertion is a single-use, in-flight artifact; ` +
        "the window only needs to absorb clock skew. Anything longer is replay time an attacker gets for free.",
      evidence: [
        { label: "Conditions/@NotBefore", detail: notBefore ?? "absent" },
        { label: "Conditions/@NotOnOrAfter", detail: notOnOrAfter },
        { label: "validity window", detail: formatDuration(endMs - startMs) },
      ],
      affectedPrincipals: principals,
      remediation:
        "Reduce the assertion lifetime to a few minutes and enforce single use by recording the assertion ID " +
        "at the relying party for the length of the window.",
    });
  }

  return findings;
}

function checkSamlAudience(
  assertion: XmlElement,
  ref: string,
  principals: AffectedPrincipal[],
  options: TokenAnalysisOptions,
): IdentityFinding[] {
  const audiences = descendants(assertion)
    .filter((e) => e.name === "Audience")
    .map((e) => e.text.trim())
    .filter((t) => t.length > 0);

  if (audiences.length === 0) {
    return [
      {
        id: `saml-missing-audience-restriction:${ref}`,
        check: "saml-missing-audience-restriction",
        title: "SAML assertion carries no AudienceRestriction",
        severity: "high",
        category: "tokens",
        description:
          "The assertion names no audience, so nothing binds it to one service provider. An assertion issued " +
          "for a low-value application can be replayed at a high-value one that trusts the same IdP — the SAML " +
          "form of the confused-deputy problem, and the reason a single weak SP compromises the whole " +
          "federation.",
        evidence: [{ label: "Assertion//Audience", detail: "absent" }],
        affectedPrincipals: principals,
        remediation:
          "Emit `AudienceRestriction` with the service provider's entity ID and reject assertions whose " +
          "audience is not an exact match for this SP.",
      },
    ];
  }

  const expected = options.expectedAudience === undefined
    ? undefined
    : Array.isArray(options.expectedAudience)
      ? options.expectedAudience
      : [options.expectedAudience];

  if (expected !== undefined && !audiences.some((a) => expected.includes(a))) {
    return [
      {
        id: `saml-missing-audience-restriction:mismatch:${ref}`,
        check: "saml-missing-audience-restriction",
        title: "SAML audience does not match the expected service provider",
        severity: "high",
        category: "tokens",
        description:
          "The assertion's audience is not the entity ID this consumer expects. It was minted for a different " +
          "service provider, and accepting it means accepting a replayed assertion.",
        evidence: [
          { label: "Assertion//Audience", detail: audiences.join(", ") },
          { label: "expected audience", detail: expected.join(", ") },
        ],
        affectedPrincipals: principals,
        remediation: "Enforce an exact audience match against this service provider's entity ID.",
      },
    ];
  }

  return [];
}

function checkSamlSubjectConfirmation(
  assertion: XmlElement,
  ref: string,
  principals: AffectedPrincipal[],
  options: TokenAnalysisOptions,
): IdentityFinding[] {
  const data = descendants(assertion).filter((e) => e.name === "SubjectConfirmationData");
  const missing: string[] = [];
  const evidence: IdentityEvidence[] = [];

  if (data.length === 0) {
    missing.push("SubjectConfirmationData");
    evidence.push({ label: "Assertion//SubjectConfirmationData", detail: "absent" });
  } else {
    const first = data[0];
    for (const attr of ["Recipient", "NotOnOrAfter", "InResponseTo"] as const) {
      if (first.attrs[attr] === undefined) {
        missing.push(attr);
        evidence.push({ label: `SubjectConfirmationData/@${attr}`, detail: "absent" });
      } else {
        evidence.push({ label: `SubjectConfirmationData/@${attr}`, detail: first.attrs[attr] });
      }
    }
    const maxValidityMs = (options.maxAssertionValidityMinutes ?? 10) * MINUTE_MS;
    const expiry = first.attrs.NotOnOrAfter === undefined ? Number.NaN : Date.parse(first.attrs.NotOnOrAfter);
    const issued = assertion.attrs.IssueInstant === undefined ? Number.NaN : Date.parse(assertion.attrs.IssueInstant);
    if (Number.isFinite(expiry) && Number.isFinite(issued) && expiry - issued > maxValidityMs) {
      missing.push("a short NotOnOrAfter");
      evidence.push({
        label: "confirmation window",
        detail: formatDuration(expiry - issued),
      });
    }
  }

  if (missing.length === 0) return [];

  return [
    {
      id: `saml-weak-subject-confirmation:${ref}`,
      check: "saml-weak-subject-confirmation",
      title: `SAML subject confirmation omits ${missing.join(", ")}`,
      severity: missing.includes("SubjectConfirmationData") || missing.includes("Recipient") ? "high" : "medium",
      category: "tokens",
      description:
        "`SubjectConfirmationData` is what binds the assertion to *this* delivery: `Recipient` pins the " +
        "assertion consumer URL it may be posted to, `NotOnOrAfter` bounds how long that delivery stays valid, " +
        "and `InResponseTo` ties it to a request this SP actually made. Each one missing is a replay path — " +
        "without `Recipient` the assertion can be posted to a different SP, and without `InResponseTo` an " +
        "unsolicited assertion is indistinguishable from a legitimate response.",
      evidence,
      affectedPrincipals: principals,
      remediation:
        "Require `Recipient`, `NotOnOrAfter`, and `InResponseTo` on `SubjectConfirmationData`, and verify all " +
        "three at the relying party — `Recipient` against this SP's ACS URL and `InResponseTo` against a " +
        "request ID this SP issued and has not yet consumed.",
    },
  ];
}

function checkSamlNameIdComment(
  assertion: XmlElement,
  ref: string,
  principals: AffectedPrincipal[],
): IdentityFinding[] {
  const nameIds = descendants(assertion).filter((e) => e.name === "NameID" || e.name === "NameIdentifier");
  const affected = nameIds.filter((n) => n.hasComment || n.textChunks > 1);
  if (affected.length === 0) return [];

  return [
    {
      id: `saml-nameid-comment-truncation:${ref}`,
      check: "saml-nameid-comment-truncation",
      title: "SAML NameID contains an XML comment",
      severity: "high",
      category: "tokens",
      description:
        "The `NameID` element's text content is interrupted by a comment node. This is the comment-truncation " +
        "attack: XML canonicalisation for the signature sees the full concatenated text, while many XML APIs " +
        "return only the first text node to the application. An attacker who can register " +
        "`victim@example.com<!---->.attacker.com` gets a signature that legitimately covers their own " +
        "identifier while the relying party reads `victim@example.com` and logs them in as the victim. The " +
        "signature is valid throughout — nothing was forged.",
      evidence: affected.map((n) => ({
        label: `Assertion//${n.name}`,
        detail: `${n.textChunks} text node(s), comment present: ${n.hasComment ? "yes" : "no"}, ` +
          `value ${redactTokenValue(n.text)}`,
      })),
      affectedPrincipals: principals,
      remediation:
        "Read the identifier with an API that concatenates all text nodes, or reject any assertion whose " +
        "`NameID` contains a comment. Update the SAML library — every major implementation shipped a fix for " +
        "this class in 2018.",
      references: ["https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations"],
    },
  ];
}

function checkGoldenSamlPreconditions(
  assertion: XmlElement,
  ref: string,
  principals: AffectedPrincipal[],
  hasEncryptedAssertion: boolean,
  coverage: SignatureCoverage,
): IdentityFinding[] {
  const authnContexts = descendants(assertion)
    .filter((e) => e.name === "AuthnContextClassRef" || e.name === "AuthenticationMethod")
    .map((e) => e.text.trim())
    .filter((t) => t.length > 0);
  const mfaContexts = authnContexts.filter((c) => MFA_AUTHN_CONTEXT_SHAPE.test(c));
  if (mfaContexts.length === 0) return [];

  const authnStatement = descendants(assertion).find((e) => e.name === "AuthnStatement");
  const sessionNotOnOrAfter = authnStatement?.attrs.SessionNotOnOrAfter;
  const issuer = descendants(assertion).find((e) => e.name === "Issuer")?.text.trim();

  return [
    {
      id: `saml-golden-saml-preconditions:${ref}`,
      check: "saml-golden-saml-preconditions",
      title: "Assertion asserts multi-factor authentication on the IdP's word alone",
      severity: "high",
      category: "tokens",
      description:
        "The assertion carries an authentication-context class that claims multi-factor authentication was " +
        "performed. The service provider has no way to confirm that; it trusts the statement because the " +
        "assertion is signed. Anyone holding the IdP's token-signing key can therefore mint an assertion for " +
        "any user, with the MFA claim set, without touching the IdP's authentication path, without a password, " +
        "and without generating a sign-in the IdP can log or revoke. That is Golden SAML, and it is why the " +
        "token-signing key is the highest-value secret in a federated estate. " +
        "This finding is the assertion-side half of `federated-idp-mfa-bypass` from the tenant assessment: " +
        "that check finds tenants configured to accept the claim, this one confirms the IdP is actually " +
        "sending it. Together they establish both ends of the bypass.",
      evidence: [
        { label: "AuthnContextClassRef", detail: mfaContexts.join(", ") },
        { label: "Assertion/Issuer", detail: issuer ?? "absent" },
        { label: "AuthnStatement/@SessionNotOnOrAfter", detail: sessionNotOnOrAfter ?? "absent" },
        { label: "assertion encrypted", detail: hasEncryptedAssertion ? "yes" : "no" },
        { label: "signature count", detail: String(coverage.signatures.length) },
      ],
      affectedPrincipals: principals,
      remediation:
        "Treat the IdP token-signing key as tier-0: HSM-backed, access-logged, and rotated on a schedule. On " +
        "the Entra side, set `federatedIdpMfaBehavior` to `enforceMfaByFederatedIdp` so the tenant requires " +
        "MFA itself rather than accepting the federated claim, and alert on assertions issued outside the " +
        "IdP's own sign-in logs.",
      references: [
        "https://learn.microsoft.com/entra/identity/authentication/how-to-mfa-server-migration-utility",
      ],
    },
  ];
}

// ── dispatcher ──

/**
 * Sniff the supplied material and route it to the right analyser. Total: an
 * unrecognisable input produces a finding, never an exception.
 */
export function analyzeToken(material: string, options: TokenAnalysisOptions = {}): IdentityFinding[] {
  const trimmed = material.trim();
  // `unwrapSamlEncoding` only returns a value when the (possibly base64-wrapped)
  // input is XML, and a compact JWT contains dots, which its base64 test
  // rejects — so this cannot swallow a JWT.
  if (unwrapSamlEncoding(trimmed) !== undefined) return analyzeSamlAssertion(material, options);

  const segments = trimmed.split(".").length;
  if (segments === 3 || segments === 5) return analyzeJwt(material, options);

  return [
    {
      id: `token-unrecognized-format:${tokenRef(material, options)}`,
      check: "token-unrecognized-format",
      title: "Supplied material is not a recognised token format",
      severity: "info",
      category: "tokens",
      description:
        "The value is neither a compact JWS/JWE nor a SAML document. It may be an opaque reference token, a " +
        "refresh token, or a truncated capture. Opaque tokens carry no readable claims by design, which is a " +
        "legitimate and often better choice — there is nothing to analyse offline, and validation has to " +
        "happen at the issuer's introspection endpoint.",
      evidence: [
        { label: "input (redacted)", detail: redactTokenValue(material) },
        { label: "dot-separated segments", detail: String(segments) },
      ],
      affectedPrincipals: [],
      remediation:
        "Confirm the capture is intact. If the token is intentionally opaque, validate it through the issuer's " +
        "introspection endpoint rather than by inspection.",
    },
  ];
}

// ── SAML transport encoding ──

/**
 * Accept raw XML or the base64 form the value takes in a `SAMLResponse` form
 * field. Returns undefined for anything that is not XML either way, which is
 * also what makes it safe to use as the sniff in `analyzeToken`.
 */
function unwrapSamlEncoding(material: string): string | undefined {
  const trimmed = material.trim();
  if (trimmed.startsWith("<")) return trimmed;
  if (trimmed.length === 0 || !/^[A-Za-z0-9+/=\s%]+$/.test(trimmed)) return undefined;
  try {
    const decoded = Buffer.from(decodeURIComponent(trimmed), "base64").toString("utf8").trim();
    return decoded.startsWith("<") ? decoded : undefined;
  } catch {
    return undefined;
  }
}

// ── shared internals ──

function stringClaim(payload: Record<string, unknown>, key: string): string | undefined {
  const value = payload[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numericClaim(payload: Record<string, unknown>, key: string): number | undefined {
  const value = payload[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  // Some issuers emit numeric date claims as strings. Reading them is more
  // useful than treating a present-but-stringly-typed `exp` as absent.
  if (typeof value === "string" && /^\d+$/.test(value)) return Number.parseInt(value, 10);
  return undefined;
}

/** Normalise a claim that may be a string, an array, or absent into a string[]. */
function claimList(value: unknown): string[] {
  if (typeof value === "string") return value.length > 0 ? [value] : [];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return [];
}

const MAX_CLAIM_WALK_NODES = 500;
const MAX_CLAIM_WALK_DEPTH = 4;

interface WalkedClaim {
  /** Dotted path from the payload root. */
  path: string;
  /** Final path segment — the claim's own name. */
  leaf: string;
  value: string;
}

/** Depth- and node-bounded walk over every string leaf in a claim set. */
function walkClaims(payload: Record<string, unknown>): WalkedClaim[] {
  const out: WalkedClaim[] = [];
  const visit = (node: unknown, path: string, leaf: string, depth: number): void => {
    if (out.length >= MAX_CLAIM_WALK_NODES || depth > MAX_CLAIM_WALK_DEPTH) return;
    if (typeof node === "string") {
      out.push({ path, leaf, value: node });
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, index) => visit(item, `${path}[${index}]`, leaf, depth + 1));
      return;
    }
    if (node !== null && typeof node === "object") {
      for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
        visit(value, path.length > 0 ? `${path}.${key}` : key, key, depth + 1);
      }
    }
  };
  visit(payload, "", "", 0);
  return out;
}

const ROLE_TEMPLATE_NAMES: Readonly<Record<string, string>> = Object.fromEntries(
  Object.entries(ROLE_TEMPLATE_IDS).map(([name, id]) => [
    id,
    // camelCase → "Camel Case", so evidence reads like the Entra portal.
    name.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase()).trim(),
  ]),
);

function roleTemplateName(templateId: string): string {
  const name = ROLE_TEMPLATE_NAMES[templateId];
  return name === undefined ? templateId : `${name} (${templateId})`;
}

function jwtPrincipals(payload: Record<string, unknown>): AffectedPrincipal[] {
  const oid = stringClaim(payload, "oid");
  const sub = stringClaim(payload, "sub");
  const id = oid ?? sub;
  if (id === undefined) return [];

  const upn = stringClaim(payload, "upn") ?? stringClaim(payload, "preferred_username")
    ?? stringClaim(payload, "unique_name");
  const appid = stringClaim(payload, "appid") ?? stringClaim(payload, "azp");
  // `idtyp: app` marks an app-only token — there is no user behind it.
  const appOnly = stringClaim(payload, "idtyp") === "app" || (upn === undefined && oid !== undefined && appid !== undefined && oid === appid);

  return [
    {
      id,
      type: appOnly ? "servicePrincipal" : upn !== undefined ? "user" : "unknown",
      displayName: stringClaim(payload, "name"),
      userPrincipalName: upn,
      appId: appid,
    },
  ];
}

function samlPrincipals(assertion: XmlElement): AffectedPrincipal[] {
  const nameId = descendants(assertion).find((e) => e.name === "NameID" || e.name === "NameIdentifier");
  const value = nameId?.text.trim();
  if (value === undefined || value.length === 0) return [];
  return [{ id: value, type: "user", userPrincipalName: value }];
}

function isoFromEpoch(seconds: number): string {
  const ms = seconds * 1000;
  if (!Number.isFinite(ms)) return "invalid";
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? "invalid" : date.toISOString();
}

function formatDuration(ms: number): string {
  if (ms < MINUTE_MS) return `${Math.round(ms / 1000)}s`;
  if (ms < HOUR_MS) return `${Math.round(ms / MINUTE_MS)}m`;
  if (ms < 48 * HOUR_MS) return `${(ms / HOUR_MS).toFixed(1).replace(/\.0$/, "")}h`;
  return `${(ms / (24 * HOUR_MS)).toFixed(1).replace(/\.0$/, "")}d`;
}
