import { describe, expect, it } from "vitest";
import {
  apiSpecToAssets,
  dedupeAssets,
  normalizeDomain,
  runRecon,
  type ReconAsset,
} from "./recon.js";
import type { ApiSpecSummary } from "../api-spec.js";

describe("normalizeDomain", () => {
  it("adds https scheme to a bare host", () => {
    expect(normalizeDomain("example.com")).toBe("https://example.com");
  });

  it("strips path and trailing slash, preserves port + explicit scheme", () => {
    expect(normalizeDomain("http://example.com:8080/api/")).toBe("http://example.com:8080");
  });

  it("throws on empty / invalid input", () => {
    expect(() => normalizeDomain("   ")).toThrow(/empty domain/);
    expect(() => normalizeDomain("http://[bad host")).toThrow(/invalid domain/);
  });
});

describe("dedupeAssets", () => {
  it("collapses duplicate (kind, value) pairs, first occurrence wins", () => {
    const assets: ReconAsset[] = [
      { kind: "endpoint", value: "GET /users", source: "a" },
      { kind: "endpoint", value: "GET /users", source: "b" },
      { kind: "endpoint", value: "POST /users", source: "a" },
    ];
    const out = dedupeAssets(assets);
    expect(out).toHaveLength(2);
    expect(out[0]).toMatchObject({ value: "GET /users", source: "a" });
    expect(out[1]).toMatchObject({ value: "POST /users" });
  });

  it("treats value as case-insensitive for the dedup key", () => {
    const out = dedupeAssets([
      { kind: "subdomain", value: "API.example.com", source: "x" },
      { kind: "subdomain", value: "api.example.com", source: "y" },
    ]);
    expect(out).toHaveLength(1);
  });

  it("keeps assets of different kinds with the same value distinct", () => {
    const out = dedupeAssets([
      { kind: "openapi_spec", value: "https://e/openapi.json", source: "e" },
      { kind: "endpoint", value: "https://e/openapi.json", source: "e" },
    ]);
    expect(out).toHaveLength(2);
  });

  it("enriches first-seen metadata from later duplicates without overwriting", () => {
    const out = dedupeAssets([
      { kind: "mcp_server", value: "https://e/mcp", source: "e", metadata: { status: "200" } },
      { kind: "mcp_server", value: "https://e/mcp", source: "e", metadata: { status: "405", transport: "sse" } },
    ]);
    expect(out).toHaveLength(1);
    // first-seen status wins, new key (transport) is merged in
    expect(out[0].metadata).toEqual({ status: "200", transport: "sse" });
  });

  it("does not mutate the input assets' metadata", () => {
    const input: ReconAsset[] = [
      { kind: "mcp_server", value: "https://e/mcp", source: "e", metadata: { status: "200" } },
      { kind: "mcp_server", value: "https://e/mcp", source: "e", metadata: { transport: "sse" } },
    ];
    dedupeAssets(input);
    expect(input[0].metadata).toEqual({ status: "200" });
  });
});

describe("apiSpecToAssets", () => {
  const spec: ApiSpecSummary = {
    title: "Demo API",
    version: "1.2.3",
    baseUrl: "https://api.demo.test",
    authSchemes: [],
    promptText: "",
    endpoints: [
      { path: "/users", method: "GET", summary: "list users", parameters: [], auth: ["bearer"] },
      { path: "/users/{id}", method: "DELETE", parameters: [] },
    ],
  };

  it("emits one openapi_spec asset plus one endpoint per operation", () => {
    const assets = apiSpecToAssets(spec, "https://api.demo.test/openapi.json");
    expect(assets[0]).toMatchObject({
      kind: "openapi_spec",
      value: "https://api.demo.test/openapi.json",
      metadata: { title: "Demo API", version: "1.2.3", endpointCount: "2" },
    });
    const endpoints = assets.filter((a) => a.kind === "endpoint");
    expect(endpoints.map((e) => e.value)).toEqual(["GET /users", "DELETE /users/{id}"]);
    expect(endpoints[0].metadata).toMatchObject({ method: "GET", auth: "bearer", summary: "list users" });
  });
});

describe("runRecon (with injected fetch)", () => {
  const openApiBody = JSON.stringify({
    openapi: "3.0.0",
    info: { title: "Svc", version: "1.0.0" },
    servers: [{ url: "https://svc.test" }],
    paths: {
      "/health": { get: { summary: "health" } },
      "/items": { get: {}, post: {} },
    },
  });

  function fakeFetch(routes: Record<string, { status: number; body: string }>): typeof fetch {
    return (async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input.toString();
      const path = new URL(url).pathname;
      const match = routes[path] ?? { status: 404, body: "" };
      return new Response(match.body, { status: match.status });
    }) as unknown as typeof fetch;
  }

  it("discovers a spec, extracts endpoints, and dedupes the inventory", async () => {
    const result = await runRecon("svc.test", {
      fetchImpl: fakeFetch({ "/openapi.json": { status: 200, body: openApiBody } }),
      // limit probe surface so the fake only needs the one route
      mcpPaths: [],
    });
    expect(result.domain).toBe("https://svc.test");
    const kinds = result.summary.byKind;
    expect(kinds.openapi_spec).toBe(1);
    expect(kinds.endpoint).toBe(3); // GET /health, GET /items, POST /items
    expect(result.assets.some((a) => a.value === "POST /items")).toBe(true);
  });

  it("flags a live MCP endpoint and skips 404s", async () => {
    const result = await runRecon("svc.test", {
      specPaths: [],
      mcpPaths: ["/mcp", "/sse"],
      fetchImpl: fakeFetch({ "/mcp": { status: 405, body: "" } }),
    });
    const mcp = result.assets.filter((a) => a.kind === "mcp_server");
    expect(mcp).toHaveLength(1);
    expect(mcp[0].value).toBe("https://svc.test/mcp");
    expect(mcp[0].metadata).toEqual({ status: "405" });
  });

  it("records a warning on a network error instead of throwing", async () => {
    const throwingFetch = (async () => {
      throw new Error("ECONNREFUSED");
    }) as unknown as typeof fetch;
    const result = await runRecon("svc.test", {
      specPaths: ["/openapi.json"],
      mcpPaths: [],
      fetchImpl: throwingFetch,
    });
    expect(result.assets).toHaveLength(0);
    expect(result.warnings.join(" ")).toMatch(/ECONNREFUSED/);
  });
});
