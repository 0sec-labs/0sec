/**
 * Sensitive-data redaction in published advisories.
 *
 * Validates `redactSensitiveHeaders` masks values for the documented set of
 * auth headers (case-insensitive), AWS access keys, and JWT-looking strings,
 * without disturbing benign content (URLs, ordinary text, short tokens).
 */

import { describe, it, expect } from "vitest";
import { redactSensitiveHeaders, renderAdvisoryMarkdown } from "./index.js";
import type { Finding } from "@pwnkit/shared";

describe("redactSensitiveHeaders — auth headers", () => {
  it("masks Authorization header values", () => {
    const out = redactSensitiveHeaders("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9");
    expect(out).toBe("Authorization: <REDACTED-Authorization>");
  });

  it("masks Cookie / Set-Cookie", () => {
    const out = redactSensitiveHeaders("Cookie: session=abc123\nSet-Cookie: refresh=xyz");
    expect(out).toContain("Cookie: <REDACTED-Cookie>");
    expect(out).toContain("Set-Cookie: <REDACTED-Set-Cookie>");
    expect(out).not.toContain("abc123");
    expect(out).not.toContain("xyz");
  });

  it("masks X-Auth-Token, X-Api-Key, X-Csrf-Token (case-insensitive)", () => {
    const out = redactSensitiveHeaders([
      "x-auth-token: tok-1",
      "X-API-KEY: key-2",
      "X-CSRF-Token: csrf-3",
    ].join("\n"));
    expect(out).toContain("<REDACTED-x-auth-token>");
    expect(out).toContain("<REDACTED-X-API-KEY>");
    expect(out).toContain("<REDACTED-X-CSRF-Token>");
    expect(out).not.toContain("tok-1");
    expect(out).not.toContain("key-2");
    expect(out).not.toContain("csrf-3");
  });

  it("preserves leading whitespace (so indented header blocks survive)", () => {
    const out = redactSensitiveHeaders("  Authorization: Bearer xyz");
    expect(out).toBe("  Authorization: <REDACTED-Authorization>");
  });

  it("does not redact non-sensitive headers", () => {
    const out = redactSensitiveHeaders("Content-Type: application/json\nX-Whatever: value");
    expect(out).toContain("Content-Type: application/json");
    expect(out).toContain("X-Whatever: value");
  });

  it("does not touch non-header lines that happen to contain a colon", () => {
    const out = redactSensitiveHeaders('{"key":"val"}');
    expect(out).toBe('{"key":"val"}');
  });
});

describe("redactSensitiveHeaders — AWS access keys", () => {
  it("masks AWS access key id (AKIA + 16 uppercase alphanumerics)", () => {
    const out = redactSensitiveHeaders("export AWS_KEY=AKIAIOSFODNN7EXAMPLE rest");
    expect(out).toBe("export AWS_KEY=<REDACTED-AWS-KEY> rest");
  });

  it("does not match strings that merely contain AKIA prefix without 16 capitals after", () => {
    // 15 chars after AKIA — should not match.
    const out = redactSensitiveHeaders("AKIASHORTKEYAAAAAA");
    // 16 caps total → AKIA + 12 → no match
    expect(out).toBe("AKIASHORTKEYAAAAAA");
  });
});

describe("redactSensitiveHeaders — JWTs", () => {
  it("masks JWT-looking strings (3 base64 segments, length >= 80)", () => {
    const head = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0";
    const sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const jwt = `${head}.${payload}.${sig}`;
    expect(jwt.length).toBeGreaterThanOrEqual(80);
    const out = redactSensitiveHeaders(`token=${jwt}`);
    expect(out).toContain("<REDACTED-JWT>");
    expect(out).not.toContain(payload);
  });

  it("does not mask short dotted strings that aren't JWTs (e.g. version numbers)", () => {
    // 1.2.3 has 3 segments but length < 80 — leave alone
    const out = redactSensitiveHeaders("version=1.2.3");
    expect(out).toBe("version=1.2.3");
  });
});

describe("redactSensitiveHeaders — empty / no-op", () => {
  it("round-trips empty string", () => {
    expect(redactSensitiveHeaders("")).toBe("");
  });

  it("returns the input unchanged when no patterns match", () => {
    const text = "GET /api/users\nHost: example.com";
    expect(redactSensitiveHeaders(text)).toBe(text);
  });
});

// ── End-to-end: redaction lands in the rendered advisory ───────────────────

function findingWithEvidence(req: string, res: string): Finding {
  return {
    id: "finding-redact",
    templateId: "test",
    title: "Test",
    description: "Test",
    severity: "high",
    category: "ssrf",
    status: "verified",
    evidence: { request: req, response: res },
    timestamp: 1,
  };
}

describe("renderAdvisoryMarkdown — applies redaction to evidence", () => {
  it("replaces Authorization values in the rendered Request block", () => {
    const finding = findingWithEvidence(
      "GET /api/foo HTTP/1.1\nAuthorization: Bearer secret-bearer-token-1234",
      "200 OK",
    );
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("<REDACTED-Authorization>");
    expect(markdown).not.toContain("secret-bearer-token-1234");
  });

  it("replaces Cookie values in the rendered Response block", () => {
    const finding = findingWithEvidence(
      "GET /api HTTP/1.1",
      "HTTP/1.1 200\nSet-Cookie: session=should-not-leak",
    );
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("<REDACTED-Set-Cookie>");
    expect(markdown).not.toContain("should-not-leak");
  });
});

// ── pocSteps redaction (Fix B: shell/http step graph leaks → CoC violation) ─

describe("redactSensitiveHeaders — inline shell patterns", () => {
  it("masks `-H 'Cookie: ...'` curl arg", () => {
    const cmd = "curl -H 'Cookie: session=should-not-leak' https://acme.com/x";
    const out = redactSensitiveHeaders(cmd);
    expect(out).toContain("<REDACTED-Cookie>");
    expect(out).not.toContain("should-not-leak");
  });

  it("masks `--header \"Authorization: Bearer ...\"` curl arg", () => {
    const cmd = 'curl --header "Authorization: Bearer secret-bearer-9876" https://acme.com/x';
    const out = redactSensitiveHeaders(cmd);
    expect(out).toContain("<REDACTED-Authorization>");
    expect(out).not.toContain("secret-bearer-9876");
  });

  it("masks bare `Bearer <token>` not wrapped in a header", () => {
    const out = redactSensitiveHeaders("export TOKEN='Bearer abcdef-zzz'");
    expect(out).toContain("<REDACTED-Bearer>");
    expect(out).not.toContain("abcdef-zzz");
  });
});

function findingWithPocSteps(steps: import("@pwnkit/shared").PocStep[]): Finding {
  return {
    id: "finding-poc-redact",
    templateId: "test",
    title: "Test",
    description: "Test",
    severity: "high",
    category: "ssrf",
    status: "verified",
    evidence: { request: "", response: "" },
    timestamp: 1,
    pocSteps: steps,
  };
}

describe("renderAdvisoryMarkdown — applies redaction to pocSteps", () => {
  it("redacts `Cookie:` header inside a shell-step curl command", () => {
    const finding = findingWithPocSteps([
      {
        id: "exploit",
        kind: "exploit",
        summary: "drive-by",
        action: {
          type: "shell",
          cmd: "curl -H 'Cookie: session=should-not-leak' https://acme.com/api",
        },
      },
    ]);
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("<REDACTED-Cookie>");
    expect(markdown).not.toContain("should-not-leak");
  });

  it("redacts inline `Authorization: Bearer ...` in a shell-step", () => {
    const finding = findingWithPocSteps([
      {
        id: "auth-step",
        kind: "exploit",
        summary: "auth then call",
        action: {
          type: "shell",
          cmd: "curl -H \"Authorization: Bearer real-bearer-token-xyz\" https://acme.com/x",
        },
      },
    ]);
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("<REDACTED-Authorization>");
    expect(markdown).not.toContain("real-bearer-token-xyz");
  });

  it("redacts `Set-Cookie` header lines in an http-step body", () => {
    const finding = findingWithPocSteps([
      {
        id: "http-step",
        kind: "exploit",
        summary: "POST",
        action: {
          type: "http",
          method: "POST",
          url: "/login",
          body: "username=alice\nSet-Cookie: session=must-not-leak",
        },
      },
    ]);
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("<REDACTED-Set-Cookie>");
    expect(markdown).not.toContain("must-not-leak");
  });

  it("redacts a JWT-shaped string inside an http-step body", () => {
    const head = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0";
    const sig = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const jwt = `${head}.${payload}.${sig}`;
    const finding = findingWithPocSteps([
      {
        id: "jwt-step",
        kind: "exploit",
        summary: "JWT exfil",
        action: {
          type: "http",
          method: "POST",
          url: "/login",
          body: `token=${jwt}`,
        },
      },
    ]);
    const { markdown } = renderAdvisoryMarkdown(finding);
    expect(markdown).toContain("<REDACTED-JWT>");
    expect(markdown).not.toContain(payload);
  });
});
