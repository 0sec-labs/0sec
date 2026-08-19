import { describe, it, expect } from "vitest";
import {
  H1Client,
  H1AuthError,
  H1ForbiddenError,
  H1RateLimitError,
  H1NetworkError,
  parseRetryAfter,
} from "./client.js";

const SECRET = "S3CR3T_TOKEN_DO_NOT_LEAK_42";
const ID = "0sec-test";

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

describe("H1Client.get — auth + headers", () => {
  it("sends Basic auth, Accept, and User-Agent headers", async () => {
    let captured: { url: string; init: RequestInit } | null = null;
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      captured = { url: String(url), init: init ?? {} };
      return jsonResponse({ data: { id: ID, type: "balance", attributes: {} } });
    }) as typeof fetch;

    const client = new H1Client({ identifier: ID, token: SECRET, fetchImpl });
    await client.get("/v1/hackers/payments/balance");

    expect(captured).not.toBeNull();
    const headers = (captured!.init.headers ?? {}) as Record<string, string>;
    const expectedAuth = "Basic " + Buffer.from(`${ID}:${SECRET}`).toString("base64");
    expect(headers.Authorization).toBe(expectedAuth);
    expect(headers.Accept).toBe("application/json");
    expect(headers["User-Agent"]).toMatch(/^0sec-cli\//);
  });

  it("URL-encodes bracketed query parameters as %5B / %5D", async () => {
    let captured = "";
    const fetchImpl = (async (url: string | URL | Request) => {
      captured = String(url);
      return jsonResponse({ data: [], links: {} });
    }) as typeof fetch;
    const client = new H1Client({ identifier: ID, token: SECRET, fetchImpl });
    await client.get("/v1/hackers/programs", { "page[size]": 100, "page[number]": 2 });
    expect(captured).toContain("page%5Bsize%5D=100");
    expect(captured).toContain("page%5Bnumber%5D=2");
  });
});

describe("H1Client.get — error mapping", () => {
  it("throws H1AuthError on 401", async () => {
    const fetchImpl = (async () => new Response("nope", { status: 401 })) as typeof fetch;
    const client = new H1Client({ identifier: ID, token: SECRET, fetchImpl });
    await expect(client.get("/v1/hackers/programs")).rejects.toBeInstanceOf(H1AuthError);
  });

  it("throws H1ForbiddenError on 403", async () => {
    const fetchImpl = (async () => new Response("nope", { status: 403 })) as typeof fetch;
    const client = new H1Client({ identifier: ID, token: SECRET, fetchImpl });
    await expect(client.get("/v1/hackers/programs/private")).rejects.toBeInstanceOf(H1ForbiddenError);
  });

  it("throws H1NetworkError on fetch rejection", async () => {
    const fetchImpl = (async () => {
      throw new Error("ECONNRESET");
    }) as typeof fetch;
    const client = new H1Client({ identifier: ID, token: SECRET, fetchImpl });
    await expect(client.get("/v1/hackers/programs")).rejects.toBeInstanceOf(H1NetworkError);
  });
});

describe("H1Client.get — 429 retry", () => {
  it("retries once on 429 honouring Retry-After, then succeeds", async () => {
    let calls = 0;
    const slept: number[] = [];
    const fetchImpl = (async () => {
      calls += 1;
      if (calls === 1) {
        return new Response("rate", { status: 429, headers: { "Retry-After": "2" } });
      }
      return jsonResponse({ data: { id: "x", type: "y", attributes: {} } });
    }) as typeof fetch;
    const client = new H1Client({
      identifier: ID,
      token: SECRET,
      fetchImpl,
      sleep: async (ms) => {
        slept.push(ms);
      },
    });
    await client.get("/v1/hackers/programs/x");
    expect(calls).toBe(2);
    expect(slept).toEqual([2000]);
  });

  it("throws H1RateLimitError when retry budget is exhausted", async () => {
    const fetchImpl = (async () =>
      new Response("rate", { status: 429, headers: { "Retry-After": "3" } })) as typeof fetch;
    const client = new H1Client({
      identifier: ID,
      token: SECRET,
      fetchImpl,
      maxRetries429: 0,
      sleep: async () => {},
    });
    await expect(client.get("/v1/hackers/programs")).rejects.toBeInstanceOf(H1RateLimitError);
  });
});

describe("H1Client.paginate", () => {
  it("walks links.next until exhausted", async () => {
    const calls: string[] = [];
    const fetchImpl = (async (url: string | URL | Request) => {
      const u = String(url);
      calls.push(u);
      if (calls.length === 1) {
        return jsonResponse({
          data: [{ id: "1", type: "program", attributes: { handle: "a", name: "A" } }],
          links: { next: "https://api.hackerone.com/v1/hackers/programs?page%5Bnumber%5D=2" },
        });
      }
      return jsonResponse({
        data: [{ id: "2", type: "program", attributes: { handle: "b", name: "B" } }],
        links: {},
      });
    }) as typeof fetch;
    const client = new H1Client({
      identifier: ID,
      token: SECRET,
      fetchImpl,
      pageDelayMs: 0,
      sleep: async () => {},
    });
    const collected = [];
    for await (const page of client.paginate("/v1/hackers/programs", { "page[size]": 100 })) {
      collected.push(page);
    }
    expect(collected.length).toBe(2);
    expect(collected[0].data[0].attributes.handle).toBe("a");
    expect(collected[1].data[0].attributes.handle).toBe("b");
    // The cursor URL on call 2 must come from links.next, not a synthesised URL.
    expect(calls[1]).toBe("https://api.hackerone.com/v1/hackers/programs?page%5Bnumber%5D=2");
  });
});

describe("H1Client — token never leaks", () => {
  // The token must NEVER appear in any thrown error message, no matter
  // what status code or network failure we inject. This is the contract
  // the rest of the CLI depends on for safe `console.error(err.message)`.
  const SECRET_RE = new RegExp(SECRET.replace(/[+/=]/g, (c) => `\\${c}`));

  it("401 error message does not contain the token", async () => {
    const fetchImpl = (async () => new Response("body", { status: 401 })) as typeof fetch;
    const client = new H1Client({ identifier: ID, token: SECRET, fetchImpl });
    let caught: unknown;
    try {
      await client.get("/v1/hackers/programs");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).not.toMatch(SECRET_RE);
  });

  it("network error message does not contain the token even if interpolated", async () => {
    const fetchImpl = (async () => {
      // Simulate a hostile/leaky network layer that includes auth in its error.
      throw new Error(`TLS handshake failed (auth was Basic ${SECRET})`);
    }) as typeof fetch;
    const client = new H1Client({ identifier: ID, token: SECRET, fetchImpl });
    let caught: unknown;
    try {
      await client.get("/v1/hackers/programs");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(H1NetworkError);
    expect((caught as Error).message).not.toMatch(SECRET_RE);
    expect((caught as Error).message).toContain("[REDACTED]");
  });

  it("rate-limit error message does not contain the token", async () => {
    const fetchImpl = (async () =>
      new Response("body", { status: 429, headers: { "Retry-After": "5" } })) as typeof fetch;
    const client = new H1Client({
      identifier: ID,
      token: SECRET,
      fetchImpl,
      maxRetries429: 0,
      sleep: async () => {},
    });
    let caught: unknown;
    try {
      await client.get("/v1/hackers/programs");
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(H1RateLimitError);
    expect((caught as Error).message).not.toMatch(SECRET_RE);
  });
});

describe("parseRetryAfter", () => {
  it("returns the numeric seconds when present", () => {
    expect(parseRetryAfter("3")).toBe(3);
    expect(parseRetryAfter("10")).toBe(10);
  });
  it("clamps to 60 seconds maximum", () => {
    expect(parseRetryAfter("3600")).toBe(60);
  });
  it("returns 1 when header is missing or non-numeric", () => {
    expect(parseRetryAfter(null)).toBe(1);
    expect(parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT")).toBe(1);
  });
});
