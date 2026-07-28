import { describe, it, expect } from "vitest";
import { IDENTITY_CHECKS, ROLE_TEMPLATE_IDS } from "./analyzers.js";
import {
  analyzeJwt,
  analyzeSamlAssertion,
  analyzeToken,
  classifyEntraToken,
  decodeJwtUnverified,
  MSA_TENANT_ID,
  redactTokenValue,
  TOKEN_CHECKS,
  tokenFingerprint,
} from "./tokens.js";
import type { IdentityCheck, IdentityFinding } from "./types.js";

// ── fixtures ──

const NOW = new Date("2026-03-01T00:00:00Z");
const NOW_S = Math.floor(NOW.getTime() / 1000);
const TENANT = "11111111-2222-3333-4444-555555555555";
const CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const AZURE_CLI = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

function b64url(value: string): string {
  return Buffer.from(value, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Build a compact JWS. `signature` is never verified — only its presence is read. */
function jwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature = "c2lnbmF0dXJl",
): string {
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.${signature}`;
}

/** A JOSE header a correctly-configured Entra tenant emits. */
function header(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { typ: "JWT", alg: "RS256", kid: "X5eXk4xyojNFum1kl2Ytv8dlNP4", ...overrides };
}

/** An Entra v2 access token with nothing wrong with it. */
function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: `https://login.microsoftonline.com/${TENANT}/v2.0`,
    aud: "api://contoso-reports",
    tid: TENANT,
    oid: "99999999-8888-7777-6666-555555555555",
    sub: "77777777-6666-5555-4444-333333333333",
    upn: "alice@contoso.com",
    name: "Alice Example",
    azp: CLIENT,
    azpacr: "2",
    scp: "Reports.Read",
    iat: NOW_S - 60,
    nbf: NOW_S - 60,
    exp: NOW_S + 3000,
    jti: "c1a2b3c4-d5e6-7f80-9012-3456789abcde",
    ...overrides,
  };
}

function checks(findings: IdentityFinding[]): IdentityCheck[] {
  return findings.map((f) => f.check);
}

function withCheck(findings: IdentityFinding[], check: IdentityCheck): IdentityFinding[] {
  return findings.filter((f) => f.check === check);
}

const OPTS = { now: NOW, label: "t1" } as const;

// ── SAML fixtures ──

function reference(uri: string): string {
  return (
    `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
    `<ds:SignedInfo><ds:Reference URI="${uri}"></ds:Reference></ds:SignedInfo>` +
    `<ds:SignatureValue>QUFBQQ==</ds:SignatureValue></ds:Signature>`
  );
}

interface AssertionParts {
  id?: string;
  /** `null` drops the signature entirely. */
  signature?: string | null;
  /** `null` drops the Conditions element entirely. */
  conditions?: string | null;
  /** `null` drops SubjectConfirmation entirely. */
  subjectConfirmation?: string | null;
  nameId?: string;
  authnContextClassRef?: string;
}

function assertion(parts: AssertionParts = {}): string {
  const id = parts.id ?? "_a1";
  const signature = parts.signature === null ? "" : parts.signature ?? reference(`#${id}`);
  const conditions =
    parts.conditions === null
      ? ""
      : parts.conditions ??
        `<saml:Conditions NotBefore="2026-03-01T00:00:00Z" NotOnOrAfter="2026-03-01T00:05:00Z">` +
          `<saml:AudienceRestriction><saml:Audience>https://sp.contoso.com</saml:Audience>` +
          `</saml:AudienceRestriction></saml:Conditions>`;
  const confirmation =
    parts.subjectConfirmation === null
      ? ""
      : parts.subjectConfirmation ??
        `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
          `<saml:SubjectConfirmationData Recipient="https://sp.contoso.com/acs" ` +
          `NotOnOrAfter="2026-03-01T00:05:00Z" InResponseTo="_req1"></saml:SubjectConfirmationData>` +
          `</saml:SubjectConfirmation>`;
  const nameId = parts.nameId ?? "alice@contoso.com";
  const acr =
    parts.authnContextClassRef ?? "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

  return (
    `<saml:Assertion ID="${id}" IssueInstant="2026-03-01T00:00:00Z" Version="2.0">` +
    `<saml:Issuer>https://idp.contoso.com/</saml:Issuer>` +
    signature +
    `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` +
    `${nameId}</saml:NameID>${confirmation}</saml:Subject>` +
    conditions +
    `<saml:AuthnStatement AuthnInstant="2026-03-01T00:00:00Z" SessionNotOnOrAfter="2026-03-01T08:00:00Z">` +
    `<saml:AuthnContext><saml:AuthnContextClassRef>${acr}</saml:AuthnContextClassRef></saml:AuthnContext>` +
    `</saml:AuthnStatement></saml:Assertion>`
  );
}

function samlResponse(body?: string, responseSignature = ""): string {
  return (
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
    `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" ` +
    `IssueInstant="2026-03-01T00:00:00Z" Destination="https://sp.contoso.com/acs">` +
    `<saml:Issuer>https://idp.contoso.com/</saml:Issuer>` +
    responseSignature +
    (body ?? assertion()) +
    `</samlp:Response>`
  );
}

// ── decoding ──

describe("decodeJwtUnverified", () => {
  it("decodes a well-formed compact JWS", () => {
    const result = decodeJwtUnverified(jwt(header(), claims()));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.jwt.header.alg).toBe("RS256");
    expect(result.jwt.payload.tid).toBe(TENANT);
    expect(result.jwt.segments).toBe(3);
    expect(result.jwt.encrypted).toBe(false);
    expect(result.jwt.signatureBytes).toBeGreaterThan(0);
  });

  it("decodes a 5-segment JWE header without touching the ciphertext", () => {
    const token = `${b64url(JSON.stringify({ alg: "RSA-OAEP", enc: "A256GCM" }))}.a.b.c.d`;
    const result = decodeJwtUnverified(token);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.jwt.encrypted).toBe(true);
    expect(result.jwt.payload).toEqual({});
  });

  it.each([
    ["empty input", ""],
    ["wrong segment count", "a.b"],
    ["non-base64url header", "!!!.eyJhIjoxfQ.sig"],
    ["header is not JSON", `${b64url("not json")}.${b64url("{}")}.sig`],
    ["payload is not an object", `${b64url("{}")}.${b64url("[1,2,3]")}.sig`],
    ["empty payload segment", `${b64url("{}")}..sig`],
  ])("returns a reason rather than throwing for %s", (_label, token) => {
    expect(() => decodeJwtUnverified(token)).not.toThrow();
    expect(decodeJwtUnverified(token).ok).toBe(false);
  });
});

describe("redaction", () => {
  it("never echoes the full value in a preview", () => {
    const token = jwt(header(), claims());
    const preview = redactTokenValue(token);
    expect(preview).not.toContain(token);
    expect(preview.length).toBeLessThan(20);
    expect(preview).toMatch(/^.{1,6}…\(\d+\)$/);
  });

  it("marks short values by length instead of echoing them", () => {
    expect(redactTokenValue("abc")).toBe("ab…(3)");
    expect(redactTokenValue("")).toBe("…(0)");
  });

  it("fingerprints case-sensitively so two tokens differing only in case differ", () => {
    expect(tokenFingerprint("AbC")).not.toBe(tokenFingerprint("abc"));
    expect(tokenFingerprint(" abc ")).toBe(tokenFingerprint("abc"));
  });

  it("keeps raw token material out of every finding on a badly-broken token", () => {
    const token = jwt(header({ alg: "none" }), claims({ ssn: "123-45-6789" }), "");
    const findings = analyzeJwt(token, OPTS);
    const serialized = JSON.stringify(findings);
    expect(serialized).not.toContain(token);
    expect(serialized).not.toContain("123-45-6789");
    expect(findings.length).toBeGreaterThan(0);
  });
});

// ── JWT: structural checks ──

describe("analyzeJwt — header", () => {
  it("raises nothing for a well-formed, tightly-scoped Entra access token", () => {
    expect(analyzeJwt(jwt(header(), claims()), OPTS)).toEqual([]);
  });

  it("returns a finding rather than throwing on malformed input", () => {
    expect(() => analyzeJwt("this is not a token", OPTS)).not.toThrow();
    const findings = analyzeJwt("this is not a token", OPTS);
    expect(checks(findings)).toEqual(["jwt-malformed"]);
    expect(findings[0].evidence[1].detail).toMatch(/…\(\d+\)$/);
  });

  it("flags `alg: none`", () => {
    const findings = analyzeJwt(jwt(header({ alg: "none" }), claims(), ""), OPTS);
    expect(withCheck(findings, "jwt-alg-none")[0].severity).toBe("critical");
  });

  it("flags a missing `alg`", () => {
    const { alg: _alg, ...rest } = header();
    const findings = analyzeJwt(jwt(rest, claims()), OPTS);
    expect(withCheck(findings, "jwt-alg-none")).toHaveLength(1);
  });

  it("flags a signed-looking algorithm with an empty signature", () => {
    const findings = analyzeJwt(jwt(header(), claims(), ""), OPTS);
    const finding = withCheck(findings, "jwt-alg-none");
    expect(finding).toHaveLength(1);
    expect(finding[0].evidence).toContainEqual({ label: "signature bytes", detail: "0" });
  });

  it("flags HS256 as algorithm-confusion exposure but not RS256", () => {
    expect(withCheck(analyzeJwt(jwt(header({ alg: "HS256" }), claims()), OPTS), "jwt-algorithm-confusion-exposure"))
      .toHaveLength(1);
    expect(withCheck(analyzeJwt(jwt(header({ alg: "ES256" }), claims()), OPTS), "jwt-algorithm-confusion-exposure"))
      .toHaveLength(0);
  });

  it("flags an unrecognised algorithm one notch lower", () => {
    const findings = withCheck(
      analyzeJwt(jwt(header({ alg: "RS256HMAC" }), claims()), OPTS),
      "jwt-algorithm-confusion-exposure",
    );
    expect(findings[0].severity).toBe("medium");
  });

  it.each([
    ["path traversal", "../../../../dev/null"],
    ["absolute path", "/etc/passwd"],
    ["url", "https://attacker.example/keys.json"],
    ["quote injection", "key' OR '1'='1"],
  ])("flags a %s shaped kid", (_label, kid) => {
    const findings = analyzeJwt(jwt(header({ kid }), claims()), OPTS);
    expect(withCheck(findings, "jwt-unsafe-key-identifier")[0].severity).toBe("high");
  });

  it("does not flag an ordinary opaque kid", () => {
    expect(withCheck(analyzeJwt(jwt(header(), claims()), OPTS), "jwt-unsafe-key-identifier")).toHaveLength(0);
  });

  it("flags jku, x5u, and embedded keys without fetching them", () => {
    const findings = analyzeJwt(
      jwt(header({ jku: "https://attacker.example/jwks.json", x5c: ["MIIB"] }), claims()),
      OPTS,
    );
    const finding = withCheck(findings, "jwt-unsafe-key-identifier")[0];
    expect(finding.evidence.map((e) => e.label)).toContain("header.jku");
    expect(finding.evidence.map((e) => e.label)).toContain("header.x5c");
  });

  it("skips claim-level checks for an encrypted (JWE) token", () => {
    const token = `${b64url(JSON.stringify({ alg: "RSA-OAEP", enc: "A256GCM" }))}.a.b.c.d`;
    expect(checks(analyzeJwt(token, OPTS))).toEqual([]);
  });
});

// ── JWT: claim checks ──

describe("analyzeJwt — claims", () => {
  it("flags a token with no expiry as critical", () => {
    const { exp: _exp, ...rest } = claims();
    const findings = analyzeJwt(jwt(header(), rest), OPTS);
    expect(withCheck(findings, "jwt-missing-expiry")[0].severity).toBe("critical");
    // No exp means the lifetime check cannot run at all.
    expect(withCheck(findings, "jwt-excessive-lifetime")).toHaveLength(0);
  });

  it("scales the excessive-lifetime severity with the window", () => {
    const at = (seconds: number) =>
      withCheck(analyzeJwt(jwt(header(), claims({ exp: NOW_S - 60 + seconds })), OPTS), "jwt-excessive-lifetime");
    expect(at(3000)).toHaveLength(0);
    expect(at(2 * 3600)[0].severity).toBe("medium");
    expect(at(8 * 3600)[0].severity).toBe("high");
    expect(at(48 * 3600)[0].severity).toBe("critical");
  });

  it("honours a caller-supplied lifetime ceiling", () => {
    const token = jwt(header(), claims());
    expect(withCheck(analyzeJwt(token, { ...OPTS, maxLifetimeMinutes: 15 }), "jwt-excessive-lifetime"))
      .toHaveLength(1);
  });

  it("records an already-expired token as informational", () => {
    const findings = analyzeJwt(jwt(header(), claims({ exp: NOW_S - 10 })), OPTS);
    expect(withCheck(findings, "jwt-expired")[0].severity).toBe("info");
  });

  it("flags a missing issuer and an unexpected issuer", () => {
    const { iss: _iss, ...rest } = claims();
    expect(withCheck(analyzeJwt(jwt(header(), rest), OPTS), "jwt-untrusted-issuer")[0].severity).toBe("medium");

    const mismatch = analyzeJwt(jwt(header(), claims()), { ...OPTS, expectedIssuer: "https://idp.example/" });
    expect(withCheck(mismatch, "jwt-untrusted-issuer")[0].severity).toBe("high");
  });

  it("accepts a matching expected issuer", () => {
    const findings = analyzeJwt(jwt(header(), claims()), {
      ...OPTS,
      expectedIssuer: `https://login.microsoftonline.com/${TENANT}/v2.0`,
    });
    expect(withCheck(findings, "jwt-untrusted-issuer")).toHaveLength(0);
  });

  it.each([
    ["absent", undefined],
    ["wildcard", "*"],
    ["empty", ""],
  ])("flags a %s audience", (_label, aud) => {
    const payload = claims();
    if (aud === undefined) delete payload.aud;
    else payload.aud = aud;
    expect(withCheck(analyzeJwt(jwt(header(), payload), OPTS), "jwt-weak-audience")[0].severity).toBe("high");
  });

  it("flags an audience that does not match the expected one, and accepts one that does", () => {
    const token = jwt(header(), claims());
    expect(withCheck(analyzeJwt(token, { ...OPTS, expectedAudience: "api://other" }), "jwt-weak-audience"))
      .toHaveLength(1);
    expect(
      withCheck(analyzeJwt(token, { ...OPTS, expectedAudience: ["api://contoso-reports"] }), "jwt-weak-audience"),
    ).toHaveLength(0);
  });

  it("flags a multi-resource audience one notch lower", () => {
    const findings = analyzeJwt(jwt(header(), claims({ aud: ["api://a", "api://b"] })), OPTS);
    expect(withCheck(findings, "jwt-weak-audience")[0].severity).toBe("medium");
  });

  it("flags missing nbf and jti together in one low finding", () => {
    const { nbf: _nbf, jti: _jti, ...rest } = claims();
    const findings = withCheck(analyzeJwt(jwt(header(), rest), OPTS), "jwt-missing-replay-controls");
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("low");
    expect(findings[0].title).toContain("nbf and jti");
  });

  it("does not flag replay controls when both are present", () => {
    expect(withCheck(analyzeJwt(jwt(header(), claims()), OPTS), "jwt-missing-replay-controls")).toHaveLength(0);
  });
});

describe("analyzeJwt — sensitive claim data", () => {
  it("ignores email addresses in the claims that are supposed to carry them", () => {
    const token = jwt(header(), claims({ preferred_username: "alice@contoso.com", email: "alice@contoso.com" }));
    expect(withCheck(analyzeJwt(token, OPTS), "jwt-sensitive-claim-data")).toHaveLength(0);
  });

  it("flags an email address in a non-identifier claim", () => {
    const findings = analyzeJwt(jwt(header(), claims({ manager_contact: "bob@contoso.com" })), OPTS);
    const finding = withCheck(findings, "jwt-sensitive-claim-data")[0];
    expect(finding.severity).toBe("low");
    expect(finding.evidence[0].label).toBe("payload.manager_contact");
    expect(finding.evidence[0].detail).not.toContain("bob@contoso.com");
  });

  it("flags a regulated PII claim, including behind a claim-URI name", () => {
    const findings = analyzeJwt(
      jwt(header(), claims({ "http://schemas.contoso.com/identity/claims/ssn": "123-45-6789" })),
      OPTS,
    );
    expect(withCheck(findings, "jwt-sensitive-claim-data")[0].severity).toBe("medium");
  });

  it("flags internal hostnames and private addresses in nested claims", () => {
    const findings = analyzeJwt(
      jwt(header(), claims({ ctx: { origin: "dc01.corp", peer: "10.4.1.9" } })),
      OPTS,
    );
    const finding = withCheck(findings, "jwt-sensitive-claim-data")[0];
    expect(finding.severity).toBe("medium");
    expect(finding.evidence.map((e) => e.label)).toContain("payload.ctx.origin");
  });
});

describe("analyzeJwt — scope breadth", () => {
  it("raises nothing for a narrow scope", () => {
    expect(withCheck(analyzeJwt(jwt(header(), claims()), OPTS), "jwt-overly-broad-scope")).toHaveLength(0);
  });

  it("flags a tier-0 Graph permission as critical", () => {
    const findings = analyzeJwt(
      jwt(header(), claims({ scp: "Reports.Read RoleManagement.ReadWrite.Directory" })),
      OPTS,
    );
    const finding = withCheck(findings, "jwt-overly-broad-scope")[0];
    expect(finding.severity).toBe("critical");
    expect(finding.evidence[0].detail).toBe("RoleManagement.ReadWrite.Directory");
  });

  it("flags a high-impact app role from the `roles` claim", () => {
    const findings = analyzeJwt(jwt(header(), claims({ roles: ["Mail.Send"] })), OPTS);
    expect(withCheck(findings, "jwt-overly-broad-scope")[0].severity).toBe("high");
  });

  it("flags `.default` as unbounded", () => {
    const findings = analyzeJwt(jwt(header(), claims({ scp: "https://graph.microsoft.com/.default" })), OPTS);
    expect(withCheck(findings, "jwt-overly-broad-scope")[0].severity).toBe("medium");
  });

  it("flags an oversized groups claim against the configured ceiling", () => {
    const groups = Array.from({ length: 12 }, (_, i) => `g${i}`);
    expect(
      withCheck(analyzeJwt(jwt(header(), claims({ groups })), OPTS), "jwt-overly-broad-scope"),
    ).toHaveLength(0);
    const findings = withCheck(
      analyzeJwt(jwt(header(), claims({ groups })), { ...OPTS, maxGroupClaims: 5 }),
      "jwt-overly-broad-scope",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("low");
  });
});

// ── Entra-specific ──

describe("classifyEntraToken", () => {
  it("separates access, id, ambiguous, and unknown shapes", () => {
    expect(classifyEntraToken({ scp: "User.Read" })).toBe("access");
    expect(classifyEntraToken({ nonce: "abc" })).toBe("id");
    expect(classifyEntraToken({ scp: "User.Read", nonce: "abc" })).toBe("ambiguous");
    expect(classifyEntraToken({ sub: "u1" })).toBe("unknown");
  });

  it("does not treat `roles` as an access-token marker — ID tokens carry it too", () => {
    expect(classifyEntraToken({ roles: ["Reader"], nonce: "abc" })).toBe("id");
  });
});

describe("analyzeJwt — Entra token type", () => {
  it("raises nothing when the token matches what the consumer expects", () => {
    const findings = analyzeJwt(jwt(header(), claims()), { ...OPTS, expectedTokenType: "access" });
    expect(withCheck(findings, "entra-token-type-mismatch")).toHaveLength(0);
  });

  it("flags an ID token being handled as an access token", () => {
    const { scp: _scp, ...rest } = claims();
    const findings = analyzeJwt(jwt(header(), { ...rest, nonce: "n1" }), {
      ...OPTS,
      expectedTokenType: "access",
    });
    expect(withCheck(findings, "entra-token-type-mismatch")[0].severity).toBe("high");
  });

  it("flags a token carrying markers of both types", () => {
    const findings = analyzeJwt(jwt(header(), claims({ nonce: "n1" })), OPTS);
    expect(withCheck(findings, "entra-token-type-mismatch")[0].severity).toBe("medium");
  });

  it("flags an access token audienced at its own client", () => {
    const findings = analyzeJwt(jwt(header(), claims({ aud: CLIENT })), OPTS);
    expect(withCheck(findings, "entra-token-type-mismatch")[0].severity).toBe("medium");
  });
});

describe("analyzeJwt — Entra client binding", () => {
  it("raises nothing for a confidential client with a certificate credential", () => {
    expect(withCheck(analyzeJwt(jwt(header(), claims()), OPTS), "entra-token-weak-client-binding"))
      .toHaveLength(0);
  });

  it("flags a token that names no client", () => {
    const { azp: _azp, azpacr: _acr, ...rest } = claims();
    const findings = analyzeJwt(jwt(header(), rest), OPTS);
    expect(withCheck(findings, "entra-token-weak-client-binding")[0].severity).toBe("medium");
  });

  it("flags a public client that presented no credential", () => {
    const findings = analyzeJwt(jwt(header(), claims({ azpacr: "0" })), OPTS);
    expect(withCheck(findings, "entra-token-weak-client-binding")[0].severity).toBe("high");
  });

  it("names a known first-party FOCI client", () => {
    const findings = analyzeJwt(jwt(header(), claims({ azp: AZURE_CLI, azpacr: "0" })), OPTS);
    const foci = withCheck(findings, "entra-token-weak-client-binding").find((f) => f.id.includes("foci"));
    expect(foci?.severity).toBe("high");
    expect(foci?.title).toContain("Azure CLI");
  });
});

describe("analyzeJwt — Entra privileged roles", () => {
  it("raises nothing when wids carries no privileged role", () => {
    const findings = analyzeJwt(jwt(header(), claims({ wids: ["b79fbf4d-3ef9-4689-8143-76b194e85509"] })), OPTS);
    expect(withCheck(findings, "entra-token-privileged-wids")).toHaveLength(0);
  });

  it("flags a tier-0 role template id as critical and names the role", () => {
    const findings = analyzeJwt(
      jwt(header(), claims({ wids: [ROLE_TEMPLATE_IDS.globalAdministrator] })),
      OPTS,
    );
    const finding = withCheck(findings, "entra-token-privileged-wids")[0];
    expect(finding.severity).toBe("critical");
    expect(finding.evidence[0].detail).toContain("Global Administrator");
  });

  it("flags a non-tier-0 privileged role one notch lower", () => {
    const findings = analyzeJwt(jwt(header(), claims({ wids: [ROLE_TEMPLATE_IDS.helpdeskAdministrator] })), OPTS);
    expect(withCheck(findings, "entra-token-privileged-wids")[0].severity).toBe("high");
  });

  it("matches role template ids case-insensitively", () => {
    const findings = analyzeJwt(
      jwt(header(), claims({ wids: [ROLE_TEMPLATE_IDS.globalAdministrator.toUpperCase()] })),
      OPTS,
    );
    expect(withCheck(findings, "entra-token-privileged-wids")).toHaveLength(1);
  });
});

describe("analyzeJwt — Entra issuer tenancy", () => {
  it("raises nothing for a tenant-specific issuer", () => {
    expect(withCheck(analyzeJwt(jwt(header(), claims()), OPTS), "entra-token-multi-tenant-issuer"))
      .toHaveLength(0);
  });

  it("flags the /common/ endpoint", () => {
    const findings = analyzeJwt(
      jwt(header(), claims({ iss: "https://login.microsoftonline.com/common/v2.0" })),
      OPTS,
    );
    expect(withCheck(findings, "entra-token-multi-tenant-issuer")[0].severity).toBe("high");
  });

  it("does not flag /common/ for a deliberately multi-tenant consumer", () => {
    const findings = analyzeJwt(
      jwt(header(), claims({ iss: "https://login.microsoftonline.com/common/v2.0" })),
      { ...OPTS, expectSingleTenant: false },
    );
    expect(withCheck(findings, "entra-token-multi-tenant-issuer")).toHaveLength(0);
  });

  it("flags a personal Microsoft account tenant", () => {
    const findings = analyzeJwt(jwt(header(), claims({ tid: MSA_TENANT_ID })), OPTS);
    expect(withCheck(findings, "entra-token-multi-tenant-issuer")[0].title).toContain("personal Microsoft account");
  });

  it("flags a tid that is not the expected tenant, and accepts one that is", () => {
    const token = jwt(header(), claims());
    expect(withCheck(analyzeJwt(token, { ...OPTS, expectedTenantId: "0000" }), "entra-token-multi-tenant-issuer"))
      .toHaveLength(1);
    expect(withCheck(analyzeJwt(token, { ...OPTS, expectedTenantId: TENANT }), "entra-token-multi-tenant-issuer"))
      .toHaveLength(0);
  });
});

describe("analyzeJwt — long-lived session artifacts", () => {
  it("raises nothing for an ordinary browser-issued token", () => {
    expect(withCheck(analyzeJwt(jwt(header(), claims()), OPTS), "entra-token-long-lived-session"))
      .toHaveLength(0);
  });

  it("flags a PRT-derived, device-bound token", () => {
    const findings = analyzeJwt(
      jwt(header(), claims({ deviceid: "dddddddd-1111-2222-3333-444444444444", amr: ["pwd", "mfa"] })),
      OPTS,
    );
    const finding = withCheck(findings, "entra-token-long-lived-session").find((f) => f.id.includes("prt"));
    expect(finding?.severity).toBe("high");
  });

  it("flags a CAE-capable client advertising CP1", () => {
    const findings = analyzeJwt(jwt(header(), claims({ xms_cc: ["CP1"] })), OPTS);
    const finding = withCheck(findings, "entra-token-long-lived-session").find((f) => f.id.includes("cae"));
    expect(finding?.severity).toBe("medium");
  });
});

// ── SAML ──

describe("analyzeSamlAssertion", () => {
  it("raises nothing for a signed, tightly-bound assertion", () => {
    expect(analyzeSamlAssertion(samlResponse(), OPTS)).toEqual([]);
  });

  it("accepts a bare assertion as well as a full response", () => {
    expect(analyzeSamlAssertion(assertion(), OPTS)).toEqual([]);
  });

  it("accepts the base64 form a SAMLResponse form field carries", () => {
    const encoded = Buffer.from(samlResponse(), "utf8").toString("base64");
    expect(analyzeSamlAssertion(encoded, OPTS)).toEqual([]);
  });

  it.each([
    ["mismatched closing tag", "<saml:Assertion><saml:Subject></saml:Assertion>"],
    ["unclosed element", "<saml:Assertion><saml:Subject>"],
    ["unterminated comment", "<saml:Assertion><!-- oops </saml:Assertion>"],
    ["a DOCTYPE declaration", `<!DOCTYPE x [<!ENTITY e "v">]><saml:Assertion></saml:Assertion>`],
    ["non-XML input", "not a saml document at all"],
    ["empty input", ""],
  ])("returns a finding rather than throwing for %s", (_label, xml) => {
    expect(() => analyzeSamlAssertion(xml, OPTS)).not.toThrow();
    expect(checks(analyzeSamlAssertion(xml, OPTS))).toEqual(["saml-malformed"]);
  });

  it("flags a document with no signature at all as critical", () => {
    const findings = analyzeSamlAssertion(samlResponse(assertion({ signature: null })), OPTS);
    const finding = withCheck(findings, "saml-unsigned-assertion")[0];
    expect(finding.severity).toBe("critical");
    expect(finding.title).toContain("no signature at all");
  });

  it("flags a response-only signature as the precondition for wrapping", () => {
    const findings = analyzeSamlAssertion(
      samlResponse(assertion({ signature: null }), reference("#_resp1")),
      OPTS,
    );
    const finding = withCheck(findings, "saml-unsigned-assertion")[0];
    expect(finding.severity).toBe("medium");
    expect(finding.description).toContain("signature wrapping");
  });

  it("flags a dangling signature reference", () => {
    const findings = analyzeSamlAssertion(
      samlResponse(assertion({ signature: reference("#_doesnotexist") })),
      OPTS,
    );
    const finding = withCheck(findings, "saml-signature-wrapping-exposure")[0];
    expect(finding.severity).toBe("high");
    expect(finding.evidence.map((e) => e.label)).toContain("dangling Reference URIs");
  });
});

describe("analyzeSamlAssertion — XML signature wrapping", () => {
  it("raises nothing for a single signed assertion", () => {
    expect(withCheck(analyzeSamlAssertion(samlResponse(), OPTS), "saml-signature-wrapping-exposure"))
      .toHaveLength(0);
  });

  it("flags a second, unsigned assertion smuggled alongside the signed one", () => {
    const forged = assertion({ id: "_a2", signature: null, nameId: "admin@contoso.com" });
    const findings = analyzeSamlAssertion(samlResponse(assertion() + forged), OPTS);
    const finding = withCheck(findings, "saml-signature-wrapping-exposure")[0];
    expect(finding.severity).toBe("critical");
    expect(finding.description).toContain("2 Assertion elements");
    expect(finding.description).toContain("some assertions are signed and others are not");
  });

  it("flags two elements sharing one ID value", () => {
    const twin = assertion({ id: "_a1", signature: null });
    const findings = analyzeSamlAssertion(samlResponse(assertion() + twin), OPTS);
    expect(withCheck(findings, "saml-signature-wrapping-exposure")[0].evidence.map((e) => e.label))
      .toContain("duplicate ID values");
  });

  it("flags an assertion buried inside a ds:Object", () => {
    const buried =
      `<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
      assertion({ id: "_a2", signature: null }) +
      `</ds:Object>`;
    const findings = analyzeSamlAssertion(samlResponse(assertion() + buried), OPTS);
    const finding = withCheck(findings, "saml-signature-wrapping-exposure")[0];
    expect(finding.severity).toBe("critical");
    expect(finding.evidence.map((e) => e.label)).toContain("buried Assertion IDs");
  });

  it("flags a signature that references an element it does not contain", () => {
    // Signature sits on the Response but references the assertion — the classic
    // detached shape a verifier can be walked past.
    const findings = analyzeSamlAssertion(
      samlResponse(assertion({ signature: null }), reference("#_a1")),
      OPTS,
    );
    expect(withCheck(findings, "saml-signature-wrapping-exposure")[0].evidence.map((e) => e.label))
      .toContain("non-enveloped signatures");
  });
});

describe("analyzeSamlAssertion — conditions and binding", () => {
  it("flags a missing Conditions element", () => {
    const findings = analyzeSamlAssertion(samlResponse(assertion({ conditions: null })), OPTS);
    expect(withCheck(findings, "saml-weak-conditions")[0].severity).toBe("high");
    expect(withCheck(findings, "saml-missing-audience-restriction")).toHaveLength(1);
  });

  it("flags a Conditions element with no expiry", () => {
    const conditions =
      `<saml:Conditions NotBefore="2026-03-01T00:00:00Z">` +
      `<saml:AudienceRestriction><saml:Audience>https://sp.contoso.com</saml:Audience>` +
      `</saml:AudienceRestriction></saml:Conditions>`;
    const findings = analyzeSamlAssertion(samlResponse(assertion({ conditions })), OPTS);
    const finding = withCheck(findings, "saml-weak-conditions")[0];
    expect(finding.severity).toBe("high");
    expect(finding.title).toContain("no expiry");
  });

  it("flags a missing NotBefore and an over-long validity window separately", () => {
    const conditions =
      `<saml:Conditions NotOnOrAfter="2026-03-01T02:00:00Z">` +
      `<saml:AudienceRestriction><saml:Audience>https://sp.contoso.com</saml:Audience>` +
      `</saml:AudienceRestriction></saml:Conditions>`;
    const findings = withCheck(
      analyzeSamlAssertion(samlResponse(assertion({ conditions })), OPTS),
      "saml-weak-conditions",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain("NotBefore");
  });

  it("flags an over-long validity window", () => {
    const conditions =
      `<saml:Conditions NotBefore="2026-03-01T00:00:00Z" NotOnOrAfter="2026-03-01T04:00:00Z">` +
      `<saml:AudienceRestriction><saml:Audience>https://sp.contoso.com</saml:Audience>` +
      `</saml:AudienceRestriction></saml:Conditions>`;
    const findings = withCheck(
      analyzeSamlAssertion(samlResponse(assertion({ conditions })), OPTS),
      "saml-weak-conditions",
    );
    expect(findings[0].severity).toBe("high");
    expect(findings[0].title).toContain("4h");
  });

  it("flags an audience that does not match the expected service provider", () => {
    const clean = samlResponse();
    expect(
      withCheck(analyzeSamlAssertion(clean, { ...OPTS, expectedAudience: "https://sp.contoso.com" }),
        "saml-missing-audience-restriction"),
    ).toHaveLength(0);
    expect(
      withCheck(analyzeSamlAssertion(clean, { ...OPTS, expectedAudience: "https://other.example" }),
        "saml-missing-audience-restriction"),
    ).toHaveLength(1);
  });

  it("flags missing subject-confirmation binding", () => {
    const findings = analyzeSamlAssertion(samlResponse(assertion({ subjectConfirmation: null })), OPTS);
    const finding = withCheck(findings, "saml-weak-subject-confirmation")[0];
    expect(finding.severity).toBe("high");
    expect(finding.title).toContain("SubjectConfirmationData");
  });

  it("flags a SubjectConfirmationData missing Recipient and InResponseTo", () => {
    const subjectConfirmation =
      `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">` +
      `<saml:SubjectConfirmationData NotOnOrAfter="2026-03-01T00:05:00Z"></saml:SubjectConfirmationData>` +
      `</saml:SubjectConfirmation>`;
    const findings = analyzeSamlAssertion(samlResponse(assertion({ subjectConfirmation })), OPTS);
    const finding = withCheck(findings, "saml-weak-subject-confirmation")[0];
    expect(finding.title).toContain("Recipient");
    expect(finding.title).toContain("InResponseTo");
  });
});

describe("analyzeSamlAssertion — NameID comment truncation", () => {
  it("raises nothing for an ordinary NameID", () => {
    expect(withCheck(analyzeSamlAssertion(samlResponse(), OPTS), "saml-nameid-comment-truncation"))
      .toHaveLength(0);
  });

  it("flags a comment splicing the NameID text", () => {
    const findings = analyzeSamlAssertion(
      samlResponse(assertion({ nameId: "alice@contoso.com<!---->.attacker.example" })),
      OPTS,
    );
    const finding = withCheck(findings, "saml-nameid-comment-truncation")[0];
    expect(finding.severity).toBe("high");
    expect(finding.evidence[0].detail).toContain("2 text node(s)");
    expect(JSON.stringify(finding)).not.toContain("alice@contoso.com<!---->");
  });
});

describe("analyzeSamlAssertion — Golden SAML preconditions", () => {
  it("raises nothing when the assertion does not claim MFA", () => {
    expect(withCheck(analyzeSamlAssertion(samlResponse(), OPTS), "saml-golden-saml-preconditions"))
      .toHaveLength(0);
  });

  it.each([
    "http://schemas.microsoft.com/claims/multipleauthn",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactorAuthentication",
  ])("flags an IdP asserting MFA via %s", (acr) => {
    const findings = analyzeSamlAssertion(
      samlResponse(assertion({ authnContextClassRef: acr })),
      OPTS,
    );
    const finding = withCheck(findings, "saml-golden-saml-preconditions")[0];
    expect(finding.severity).toBe("high");
    // Must point back at the tenant-side half of the same bypass.
    expect(finding.description).toContain("federated-idp-mfa-bypass");
    expect(finding.evidence[0].detail).toBe(acr);
  });
});

// ── dispatcher + catalog ──

describe("analyzeToken", () => {
  it("routes a JWT to the JWT analyser", () => {
    expect(analyzeToken(jwt(header({ alg: "none" }), claims(), ""), OPTS).map((f) => f.check))
      .toContain("jwt-alg-none");
  });

  it("routes raw and base64 SAML to the SAML analyser", () => {
    const xml = samlResponse(assertion({ signature: null }));
    expect(checks(analyzeToken(xml, OPTS))).toContain("saml-unsigned-assertion");
    expect(checks(analyzeToken(Buffer.from(xml, "utf8").toString("base64"), OPTS)))
      .toContain("saml-unsigned-assertion");
  });

  it("reports an opaque token instead of guessing", () => {
    const findings = analyzeToken("2YotnFZFEjr1zCsicMWpAA", OPTS);
    expect(checks(findings)).toEqual(["token-unrecognized-format"]);
    expect(findings[0].severity).toBe("info");
  });

  it("never throws on arbitrary input", () => {
    for (const input of ["", "   ", "....", "<", "%%%", "a.b.c.d.e.f"]) {
      expect(() => analyzeToken(input, OPTS)).not.toThrow();
    }
  });
});

describe("token check catalog", () => {
  it("registers every token check in IDENTITY_CHECKS", () => {
    for (const check of TOKEN_CHECKS) {
      expect(IDENTITY_CHECKS).toContain(check);
    }
  });

  it("has no duplicate ids and no orphans in either direction", () => {
    expect(new Set(TOKEN_CHECKS).size).toBe(TOKEN_CHECKS.length);
    expect(new Set(IDENTITY_CHECKS).size).toBe(IDENTITY_CHECKS.length);
  });

  it("only emits checks that are in the catalog, and always in the tokens category", () => {
    const findings = [
      ...analyzeJwt(jwt(header({ alg: "none", kid: "../../x" }), { aud: "*", groups: [] }, ""), OPTS),
      ...analyzeSamlAssertion(samlResponse(assertion({ signature: null, conditions: null })), OPTS),
      ...analyzeToken("opaque", OPTS),
    ];
    expect(findings.length).toBeGreaterThan(5);
    for (const finding of findings) {
      expect(TOKEN_CHECKS).toContain(finding.check);
      expect(finding.category).toBe("tokens");
      expect(finding.id).toContain(finding.check);
      expect(finding.title.length).toBeGreaterThan(0);
      expect(finding.remediation.length).toBeGreaterThan(0);
    }
  });
});
