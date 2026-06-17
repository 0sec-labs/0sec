import { describe, expect, it } from "vitest";
import { ScopePolicy } from "../scope/scope.js";
import { runJsRecon } from "./js-recon.js";
import type { FetchTextResult } from "./js-artifacts.js";

/** Build an injectable fetchText from a URL→response map. Unknown URLs 404. */
function fakeFetch(routes: Record<string, FetchTextResult>) {
  return async (url: string): Promise<FetchTextResult> => routes[url] ?? { status: 404, body: "" };
}

const inScope = () => ScopePolicy.fromJson({ in_scope: ["app.example.com", "*.example.com"] });

describe("runJsRecon — scope gating (deny-by-default)", () => {
  it("fetches nothing when no scope policy is supplied", async () => {
    let fetched = false;
    const res = await runJsRecon({
      scriptUrls: ["https://app.example.com/a.js"],
      fetchText: async (u) => {
        fetched = true;
        return { status: 200, body: `"/api/x"` };
      },
    });
    expect(fetched).toBe(false);
    expect(res.scanned).toHaveLength(0);
    expect(res.skipped).toContain("https://app.example.com/a.js");
    expect(res.endpoints).toHaveLength(0);
  });

  it("skips out-of-scope JS URLs and only fetches in-scope ones", async () => {
    const fetched: string[] = [];
    const res = await runJsRecon({
      scriptUrls: [
        "https://app.example.com/in.js",
        "https://evil.test/out.js",
      ],
      scope: inScope(),
      fetchText: async (u) => {
        fetched.push(u);
        return { status: 200, body: `fetch("/api/in")` };
      },
    });
    expect(fetched).toEqual(["https://app.example.com/in.js"]);
    expect(res.scanned).toEqual(["https://app.example.com/in.js"]);
    expect(res.skipped).toContain("https://evil.test/out.js");
  });
});

describe("runJsRecon — endpoint discovery feeds surface_sweep shape", () => {
  it("emits endpoints in the ReconAsset (METHOD /path) shape", async () => {
    const res = await runJsRecon({
      scriptUrls: ["https://app.example.com/app.js"],
      scope: inScope(),
      fetchText: fakeFetch({
        "https://app.example.com/app.js": {
          status: 200,
          body: `axios.post("/api/login", c); fetch("/api/v1/orders");`,
        },
      }),
    });
    const values = res.endpoints.map((e) => e.value);
    expect(values).toContain("POST /api/login");
    expect(values).toContain("GET /api/v1/orders");
    // Shape compatible with discover_api_surface / surface_sweep.
    const login = res.endpoints.find((e) => e.value === "POST /api/login")!;
    expect(login.kind).toBe("endpoint");
    expect(login.metadata?.method).toBe("POST");
    expect(login.metadata?.path).toBe("/api/login");
    expect(login.source).toBe("https://app.example.com/app.js");
  });
});

describe("runJsRecon — secret detection + redaction", () => {
  it("detects an embedded AWS key and NEVER returns the raw value", async () => {
    const rawKey = "***REMOVED***";
    const res = await runJsRecon({
      scriptUrls: ["https://app.example.com/app.js"],
      scope: inScope(),
      fetchText: fakeFetch({
        "https://app.example.com/app.js": {
          status: 200,
          body: `const k = "${rawKey}"; fetch("/api/x");`,
        },
      }),
    });
    const aws = res.secrets.find((s) => s.kind === "aws_access_key_id");
    expect(aws).toBeDefined();
    expect(aws!.confidence).toBe("high");
    expect(aws!.chunk).toBe("https://app.example.com/app.js");
    // Redaction guarantee: the raw secret value is never present anywhere.
    expect(aws!.match).not.toContain("EXAMPLE");
    expect(JSON.stringify(res)).not.toContain(rawKey);
  });

  it("ports foxguard patterns: GitLab, npm, private key, generic api_key", async () => {
    const body = [
      `glpat-abcdefghijklmnopqrstuvwx`,
      `***REMOVED***`,
      `-----BEGIN OPENSSH PRIVATE KEY-----`,
      `const config = { api_key: "sk_test_1234567890abcdef" };`,
    ].join("\n");
    const res = await runJsRecon({
      scriptUrls: ["https://app.example.com/c.js"],
      scope: inScope(),
      fetchText: fakeFetch({ "https://app.example.com/c.js": { status: 200, body } }),
    });
    const kinds = new Set(res.secrets.map((s) => s.kind));
    expect(kinds.has("gitlab_token")).toBe(true);
    expect(kinds.has("npm_token")).toBe(true);
    expect(kinds.has("private_key")).toBe(true);
    expect(kinds.has("generic_api_key")).toBe(true);
  });
});

describe("runJsRecon — budget", () => {
  it("respects maxFiles and reports overflow as skipped", async () => {
    const urls = Array.from({ length: 5 }, (_, i) => `https://app.example.com/${i}.js`);
    const routes: Record<string, FetchTextResult> = {};
    for (const u of urls) routes[u] = { status: 200, body: `"/api/r"` };
    const res = await runJsRecon({
      scriptUrls: urls,
      scope: inScope(),
      fetchText: fakeFetch(routes),
      maxFiles: 2,
    });
    expect(res.scanned).toHaveLength(2);
    expect(res.skipped.length).toBe(3);
  });
});
