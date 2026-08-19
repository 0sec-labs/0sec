import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import type { AttackCategory, Finding } from "@pwnkit/shared";
import {
  verifySqli,
  verifyReflectedXss,
  verifyPathTraversal,
  verifyIdor,
  verifyOracleByCategory,
  parseRequest,
} from "./oracles.js";

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "oracle-test",
    templateId: "audit-sink",
    title: "Test finding",
    description: "",
    severity: "high",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "GET /search?q=foo HTTP/1.1\nHost: example.com\n\n",
      response: "",
    },
    confidence: 0.7,
    timestamp: Date.now(),
    ...overrides,
  };
}

interface FakeResponseSpec {
  status?: number;
  body?: string;
  delayMs?: number;
}

function makeFakeFetch(
  handler: (
    url: string,
    init: RequestInit | undefined,
    calls: number
  ) => FakeResponseSpec
) {
  let calls = 0;
  return vi.fn(async (url: any, init?: any) => {
    calls += 1;
    const spec = handler(String(url), init, calls);
    if (spec.delayMs && spec.delayMs > 0) {
      await new Promise((r) => setTimeout(r, spec.delayMs));
    }
    const body = spec.body ?? "";
    return {
      status: spec.status ?? 200,
      text: async () => body,
      headers: new Map(),
    } as any;
  });
}

// ────────────────────────────────────────────────────────────────────
// parseRequest
// ────────────────────────────────────────────────────────────────────

describe("parseRequest", () => {
  it("parses raw HTTP request with query params", () => {
    const parsed = parseRequest(
      "GET /search?q=foo&id=1 HTTP/1.1\nHost: example.com\n\n",
      "http://example.com"
    );
    expect(parsed.method).toBe("GET");
    expect(parsed.url).toBe("http://example.com/search?q=foo&id=1");
    expect(parsed.params).toEqual({ q: "foo", id: "1" });
  });

  it("parses POST form body", () => {
    const parsed = parseRequest(
      "POST /login HTTP/1.1\nHost: example.com\n\nuser=alice&pass=hunter2",
      "http://example.com"
    );
    expect(parsed.method).toBe("POST");
    expect(parsed.params).toEqual({ user: "alice", pass: "hunter2" });
  });

  it("falls back to target URL when request is empty", () => {
    const parsed = parseRequest("", "http://example.com/?x=1");
    expect(parsed.url).toBe("http://example.com/?x=1");
    expect(parsed.params).toEqual({ x: "1" });
  });
});

// ────────────────────────────────────────────────────────────────────
// SQLi oracle
// ────────────────────────────────────────────────────────────────────

describe("verifySqli", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("verifies with boolean_diff + sql_error (2/3 signals)", async () => {
    // Responses:
    //   1. baseline (orig value)                          → small page
    //   2. boolean true  (' OR 1=1--)                     → big page
    //   3. boolean false (' OR 1=2--)                     → small page
    //   4+. time-based probes (no delay; skipped)
    //   N. error probe (single quote)                     → error body
    vi.stubGlobal(
      "fetch",
      makeFakeFetch((url) => {
        if (url.includes("OR+1%3D1") || url.includes("OR%201%3D1"))
          return { body: "x".repeat(1000) };
        if (url.includes("OR+1%3D2") || url.includes("OR%201%3D2"))
          return { body: "x".repeat(200) };
        if (url.includes("SLEEP") || url.includes("pg_sleep"))
          return { body: "no delay" };
        if (url.match(/q=foo%27($|&)/))
          return {
            body: "You have an error in your SQL syntax near 'foo''",
          };
        return { body: "x".repeat(200) };
      })
    );

    const result = await verifySqli(makeFinding(), "http://example.com");
    expect(result.verified).toBe(true);
    expect(result.evidence).toContain("boolean_diff");
    expect(result.evidence).toContain("sql_error");
  });

  it("does not verify when there is no diff and no error", async () => {
    vi.stubGlobal(
      "fetch",
      makeFakeFetch(() => ({ body: "static page content" }))
    );

    const result = await verifySqli(makeFinding(), "http://example.com");
    expect(result.verified).toBe(false);
    expect(result.confidence).toBeLessThan(1);
  });

  it("returns not verifiable when no injectable param", async () => {
    const finding = makeFinding({
      evidence: { request: "GET / HTTP/1.1\nHost: example.com\n\n", response: "" },
    });
    const result = await verifySqli(finding, "http://example.com");
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch(/no injectable parameter/);
  });
});

// ────────────────────────────────────────────────────────────────────
// Reflected XSS oracle
// ────────────────────────────────────────────────────────────────────

describe("verifyReflectedXss", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("reports html_reflection signal when payload echoes unencoded", async () => {
    vi.stubGlobal(
      "fetch",
      makeFakeFetch((url) => {
        // Decode the payload back so we can echo it raw
        const u = new URL(url);
        const q = u.searchParams.get("q") ?? "";
        return { body: `<html>results for ${q}</html>` };
      })
    );

    const finding = makeFinding({ category: "xss" as AttackCategory });
    const result = await verifyReflectedXss(finding, "http://example.com");
    // Playwright is optional in this environment — we at least expect the
    // html-reflection fallback signal to surface.
    expect(result.evidence).toMatch(/html_reflection|dialog/);
  });

  it("returns not verifiable when payload is encoded in response", async () => {
    vi.stubGlobal(
      "fetch",
      makeFakeFetch(() => ({
        body: "<html>results for &lt;script&gt;&lt;/script&gt;</html>",
      }))
    );

    const finding = makeFinding({ category: "xss" as AttackCategory });
    const result = await verifyReflectedXss(finding, "http://example.com");
    expect(result.verified).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────
// Path traversal oracle
// ────────────────────────────────────────────────────────────────────

describe("verifyPathTraversal", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("verifies when response contains /etc/passwd signature", async () => {
    vi.stubGlobal(
      "fetch",
      makeFakeFetch(() => ({
        body: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
      }))
    );

    const finding = makeFinding({
      category: "path-traversal" as AttackCategory,
      evidence: {
        request:
          "GET /file?name=welcome.txt HTTP/1.1\nHost: example.com\n\n",
        response: "",
      },
    });
    const result = await verifyPathTraversal(finding, "http://example.com");
    expect(result.verified).toBe(true);
    expect(result.evidence).toMatch(/root:x:0:0|\/bin\/bash/);
  });

  it("does not verify when response has no passwd signature", async () => {
    vi.stubGlobal(
      "fetch",
      makeFakeFetch(() => ({ body: "<html>404 not found</html>" }))
    );
    const finding = makeFinding({
      category: "path-traversal" as AttackCategory,
      evidence: {
        request:
          "GET /file?name=welcome.txt HTTP/1.1\nHost: example.com\n\n",
        response: "",
      },
    });
    const result = await verifyPathTraversal(finding, "http://example.com");
    expect(result.verified).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────
// IDOR oracle
// ────────────────────────────────────────────────────────────────────

describe("verifyIdor", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("flags distinct 200 responses on id mutation", async () => {
    vi.stubGlobal(
      "fetch",
      makeFakeFetch((url) => {
        const u = new URL(url);
        const id = u.searchParams.get("id") ?? "";
        return { status: 200, body: `user record for id=${id}` };
      })
    );
    const finding = makeFinding({
      category: "information-disclosure" as AttackCategory,
      evidence: {
        request: "GET /account?id=42 HTTP/1.1\nHost: example.com\n\n",
        response: "",
      },
    });
    const result = await verifyIdor(finding, "http://example.com");
    expect(result.verified).toBe(true);
    expect(result.confidence).toBeLessThan(1);
  });

  it("does not verify when every id returns the same body", async () => {
    vi.stubGlobal(
      "fetch",
      makeFakeFetch(() => ({ status: 200, body: "same body always" }))
    );
    const finding = makeFinding({
      category: "information-disclosure" as AttackCategory,
      evidence: {
        request: "GET /account?id=42 HTTP/1.1\nHost: example.com\n\n",
        response: "",
      },
    });
    const result = await verifyIdor(finding, "http://example.com");
    expect(result.verified).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────
// Dispatch
// ────────────────────────────────────────────────────────────────────

describe("verifyOracleByCategory", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns no-oracle result for categories without a verifier", async () => {
    const finding = makeFinding({
      category: "prompt-injection" as AttackCategory,
    });
    const result = await verifyOracleByCategory(finding, "http://example.com");
    expect(result.verified).toBe(false);
    expect(result.reason).toMatch(/no oracle for category/);
  });

  it("routes path-traversal findings to the path oracle", async () => {
    vi.stubGlobal(
      "fetch",
      makeFakeFetch(() => ({
        body: "root:x:0:0:root:/root:/bin/bash",
      }))
    );
    const finding = makeFinding({
      category: "path-traversal" as AttackCategory,
      evidence: {
        request: "GET /file?name=welcome HTTP/1.1\nHost: example.com\n\n",
        response: "",
      },
    });
    const result = await verifyOracleByCategory(finding, "http://example.com");
    expect(result.verified).toBe(true);
  });
});
