import { describe, expect, it } from "vitest";
import {
  redactSecret,
  resolveSourceMapUrl,
  scanBody,
  scanJsArtifacts,
  type FetchTextResult,
} from "./js-artifacts.js";

/** Build an injectable fetchText from a URL→response map. Unknown URLs 404. */
function fakeFetch(routes: Record<string, FetchTextResult>) {
  return async (url: string): Promise<FetchTextResult> => routes[url] ?? { status: 404, body: "" };
}

describe("redactSecret", () => {
  it("keeps a short prefix and the length, never the full value", () => {
    const out = redactSecret("AKIAIOSFODNN7EXAMPLE");
    expect(out).toBe("AKIAIO…(20 chars)");
    expect(out).not.toContain("EXAMPLE");
  });
});

describe("resolveSourceMapUrl", () => {
  it("resolves a bare filename against the bundle URL", () => {
    expect(resolveSourceMapUrl("https://e/assets/app.js", "app.js.map")).toBe(
      "https://e/assets/app.js.map",
    );
  });
  it("resolves a root-relative reference", () => {
    expect(resolveSourceMapUrl("https://e/assets/app.js", "/maps/app.js.map")).toBe(
      "https://e/maps/app.js.map",
    );
  });
  it("ignores inline data: maps", () => {
    expect(resolveSourceMapUrl("https://e/app.js", "data:application/json;base64,abc")).toBeUndefined();
  });
});

describe("scanBody — secret classification", () => {
  it("flags a high-signal AWS key, Stripe live key, Google key, and JWT", () => {
    const stripe = ["sk", "live", "4eC39HqLyjWDarjtT1zdp7dcABCD"].join("_");
    const body = [
      "const a='AKIAIOSFODNN7EXAMPLE';",
      `const s='${stripe}';`,
      "const g='AIzaSyB1234567890abcdefghijklmnopqrstuv';",
      "const t='eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.abcDEF123456';",
    ].join("\n");
    const hits = scanBody("https://e/app.js", body);
    const kinds = hits.map((h) => h.kind).sort();
    expect(kinds).toContain("aws_access_key_id");
    expect(kinds).toContain("stripe_live_key");
    expect(kinds).toContain("google_api_key");
    expect(kinds).toContain("jwt");
    expect(hits.every((h) => h.confidence === "high")).toBe(true);
    // matches are redacted
    expect(hits.find((h) => h.kind === "aws_access_key_id")?.match).not.toContain("EXAMPLE");
  });

  it("detects the patterns ported from foxguard (GitLab, npm, GitHub fine-grained, private key, generic api_key, bearer)", () => {
    const body = [
      "glpat-abcdefghijklmnopqrstuvwx",
      "npm_abcdefghijklmnopqrstuvwxyz0123456789",
      "github_pat_11ABCDEFG0abcdefghijkl",
      "-----BEGIN RSA PRIVATE KEY-----",
      `aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY1234"`,
      `const o = { apiKey: "abcdef0123456789abcdef" };`,
      "Authorization: Bearer abcdef0123456789ABCDEFXYZ",
    ].join("\n");
    const kinds = new Set(scanBody("https://e/app.js", body).map((h) => h.kind));
    expect(kinds.has("gitlab_token")).toBe(true);
    expect(kinds.has("npm_token")).toBe(true);
    expect(kinds.has("github_token")).toBe(true);
    expect(kinds.has("private_key")).toBe(true);
    expect(kinds.has("aws_secret_access_key")).toBe(true);
    expect(kinds.has("generic_api_key")).toBe(true);
    expect(kinds.has("bearer_token")).toBe(true);
  });

  it("classifies a PostHog public key as low confidence (expected-public)", () => {
    const body = "posthog.init('phc_AbCdEf0123456789AbCdEf0123456789xyz')";
    const hits = scanBody("https://e/app.js", body);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ kind: "posthog_public_key", confidence: "low" });
  });

  it("classifies a Vercel analytics token as low confidence", () => {
    const hits = scanBody("https://e/app.js", "va_pub_abcdef0123456789ABCDEF");
    expect(hits).toHaveLength(1);
    expect(hits[0].confidence).toBe("low");
  });

  it("does not false-positive on ordinary code", () => {
    const body = "function getUserToken(){ return localStorage.getItem('token'); }";
    expect(scanBody("https://e/app.js", body)).toHaveLength(0);
  });

  it("dedupes a repeated identical secret to a single hit", () => {
    const key = "AKIAIOSFODNN7EXAMPLE";
    const body = `a='${key}';b='${key}';c='${key}';`;
    const hits = scanBody("https://e/app.js", body).filter((h) => h.kind === "aws_access_key_id");
    expect(hits).toHaveLength(1);
  });
});

describe("scanJsArtifacts", () => {
  const bundleWithMapComment = "console.log(1)\n//# sourceMappingURL=app.js.map";

  it("reports an exposed source map when the .map serves 200", async () => {
    const result = await scanJsArtifacts({
      baseUrl: "https://e",
      chunkUrls: ["https://e/assets/app.js"],
      fetchText: fakeFetch({
        "https://e/assets/app.js": { status: 200, body: bundleWithMapComment },
        "https://e/assets/app.js.map": { status: 200, body: '{"version":3}' },
      }),
    });
    expect(result.sourceMaps).toContainEqual({
      url: "https://e/assets/app.js.map",
      exposed: true,
    });
    expect(result.secrets).toHaveLength(0);
  });

  it("matches the real pilot: no source maps (404) and only a public PostHog key", async () => {
    const bundle =
      "!function(){posthog.init('phc_AbCdEf0123456789AbCdEf0123456789xyz')}();\n" +
      "//# sourceMappingURL=main.js.map";
    const result = await scanJsArtifacts({
      baseUrl: "https://pilot.test",
      chunkUrls: ["https://pilot.test/static/main.js"],
      fetchText: fakeFetch({
        "https://pilot.test/static/main.js": { status: 200, body: bundle },
        // map probes 404 — not exposed
      }),
    });
    // Source map probed but NOT exposed (404).
    expect(result.sourceMaps.every((sm) => sm.exposed === false)).toBe(true);
    // Only the public PostHog key, classified low — no high-confidence finding.
    expect(result.secrets.map((s) => s.confidence)).toEqual(["low"]);
    expect(result.secrets[0].kind).toBe("posthog_public_key");
    expect(result.secrets.some((s) => s.confidence === "high")).toBe(false);
  });

  it("skips non-200 / empty chunks without throwing", async () => {
    const result = await scanJsArtifacts({
      baseUrl: "https://e",
      chunkUrls: ["https://e/missing.js"],
      fetchText: fakeFetch({ "https://e/missing.js": { status: 404, body: "" } }),
    });
    expect(result.sourceMaps).toHaveLength(0);
    expect(result.secrets).toHaveLength(0);
  });

  it("surfaces a high-confidence secret leaked in a bundle", async () => {
    const result = await scanJsArtifacts({
      baseUrl: "https://e",
      chunkUrls: ["https://e/app.js"],
      fetchText: fakeFetch({
        "https://e/app.js": { status: 200, body: "const k='AKIAIOSFODNN7EXAMPLE'" },
      }),
    });
    const high = result.secrets.filter((s) => s.confidence === "high");
    expect(high).toHaveLength(1);
    expect(high[0].kind).toBe("aws_access_key_id");
  });
});
