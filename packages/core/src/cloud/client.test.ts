import { describe, it, expect } from "vitest";
import {
  CloudClient,
  CloudUnauthorizedError,
  CloudForbiddenError,
  CloudNetworkError,
  CloudError,
} from "./client.js";

const SECRET = "S3CR3T_CLOUD_TOKEN_DO_NOT_LEAK_42";
const HOST = "https://app.example.com";

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

describe("CloudClient.pingHealth — auth + headers", () => {
  it("sends Bearer auth, Accept, and User-Agent headers", async () => {
    let captured: { url: string; init: RequestInit } | null = null;
    const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
      captured = { url: String(url), init: init ?? {} };
      return jsonResponse({ status: "ok" });
    }) as typeof fetch;

    const client = new CloudClient({ host: HOST, token: SECRET, fetchImpl });
    const res = await client.pingHealth();
    expect(res.status).toBe("ok");

    expect(captured).not.toBeNull();
    expect(captured!.url).toBe(`${HOST}/health`);
    const headers = (captured!.init.headers ?? {}) as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${SECRET}`);
    expect(headers.Accept).toBe("application/json");
    expect(headers["User-Agent"]).toMatch(/^0sec-cli\//);
  });
});

describe("CloudClient.pingHealth — error mapping", () => {
  it("throws CloudUnauthorizedError on 401", async () => {
    const fetchImpl = (async () => new Response("nope", { status: 401 })) as typeof fetch;
    const client = new CloudClient({ host: HOST, token: SECRET, fetchImpl });
    await expect(client.pingHealth()).rejects.toBeInstanceOf(CloudUnauthorizedError);
  });

  it("throws CloudForbiddenError on 403", async () => {
    const fetchImpl = (async () => new Response("nope", { status: 403 })) as typeof fetch;
    const client = new CloudClient({ host: HOST, token: SECRET, fetchImpl });
    await expect(client.pingHealth()).rejects.toBeInstanceOf(CloudForbiddenError);
  });

  it("throws generic CloudError on 5xx", async () => {
    const fetchImpl = (async () => new Response("server boom", { status: 503 })) as typeof fetch;
    const client = new CloudClient({ host: HOST, token: SECRET, fetchImpl });
    let caught: unknown;
    try {
      await client.pingHealth();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CloudError);
    expect((caught as CloudError).status).toBe(503);
  });

  it("throws CloudNetworkError on fetch rejection", async () => {
    const fetchImpl = (async () => {
      throw new Error("ECONNRESET");
    }) as typeof fetch;
    const client = new CloudClient({ host: HOST, token: SECRET, fetchImpl });
    await expect(client.pingHealth()).rejects.toBeInstanceOf(CloudNetworkError);
  });
});

describe("CloudClient — token never leaks", () => {
  const SECRET_RE = new RegExp(SECRET.replace(/[+/=]/g, (c) => `\\${c}`));

  it("401 error message does not contain the token", async () => {
    const fetchImpl = (async () => new Response("body", { status: 401 })) as typeof fetch;
    const client = new CloudClient({ host: HOST, token: SECRET, fetchImpl });
    let caught: unknown;
    try {
      await client.pingHealth();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(Error);
    expect((caught as Error).message).not.toMatch(SECRET_RE);
  });

  it("network error message does not contain the token even if interpolated", async () => {
    const fetchImpl = (async () => {
      // Simulate a hostile/leaky network layer that includes auth in its error.
      throw new Error(`TLS handshake failed (auth was Bearer ${SECRET})`);
    }) as typeof fetch;
    const client = new CloudClient({ host: HOST, token: SECRET, fetchImpl });
    let caught: unknown;
    try {
      await client.pingHealth();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(CloudNetworkError);
    expect((caught as Error).message).not.toMatch(SECRET_RE);
    expect((caught as Error).message).toContain("[REDACTED]");
  });
});
