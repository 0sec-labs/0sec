import { describe, it, expect } from "vitest";
import {
  classifyAuthBoundary,
  bodySimilarity,
  normalizeEndpoint,
  runAuthBoundaryProbe,
  summarizeAuthBoundaryReport,
  type FetchLike,
} from "./auth-boundary-prober.js";

// ── Pure verdict logic ──

describe("classifyAuthBoundary", () => {
  it("flags an unauth 2xx with no authed baseline as reachable (medium)", () => {
    const v = classifyAuthBoundary({ status: 200, bodyPreview: "ok" });
    expect(v.unauthReachable).toBe(true);
    expect(v.verdict).toBe("unauth-reachable");
    expect(v.severity).toBe("medium");
  });

  it("treats unauth 401 as auth-required (boundary holds)", () => {
    const v = classifyAuthBoundary({ status: 401, bodyPreview: "" });
    expect(v.unauthReachable).toBe(false);
    expect(v.verdict).toBe("auth-required");
  });

  it("treats unauth 403 as auth-required", () => {
    const v = classifyAuthBoundary({ status: 403, bodyPreview: "forbidden" });
    expect(v.unauthReachable).toBe(false);
    expect(v.verdict).toBe("auth-required");
  });

  it("escalates to HIGH when unauth gets the SAME body as the authed baseline", () => {
    const secret = '{"users":[{"id":1,"email":"a@x.com"},{"id":2,"email":"b@x.com"}]}';
    const v = classifyAuthBoundary(
      { status: 200, bodyPreview: secret },
      { status: 200, bodyPreview: secret },
    );
    expect(v.unauthReachable).toBe(true);
    expect(v.verdict).toBe("unauth-reachable");
    expect(v.severity).toBe("high");
    expect(v.bodySimilarity).toBe(1);
  });

  it("stays medium when unauth 2xx body differs from authed baseline", () => {
    const v = classifyAuthBoundary(
      { status: 200, bodyPreview: "public landing page hello world" },
      { status: 200, bodyPreview: "admin dashboard secret tenant rows 9 8 7" },
    );
    expect(v.unauthReachable).toBe(true);
    expect(v.severity).toBe("medium");
    expect(v.bodySimilarity).toBeLessThan(0.9);
  });

  it("still flags reachable when anon got 2xx but authed leg failed/non-2xx", () => {
    const v = classifyAuthBoundary(
      { status: 200, bodyPreview: "data" },
      { status: 500, bodyPreview: "err" },
    );
    expect(v.unauthReachable).toBe(true);
    expect(v.verdict).toBe("unauth-reachable");
  });

  it("returns not-found when both sides see a 404", () => {
    const v = classifyAuthBoundary(
      { status: 404, bodyPreview: "" },
      { status: 404, bodyPreview: "" },
    );
    expect(v.unauthReachable).toBe(false);
    expect(v.verdict).toBe("not-found");
  });

  it("reads a 404-for-anon + 2xx-for-authed as an auth-gated hide", () => {
    const v = classifyAuthBoundary(
      { status: 404, bodyPreview: "" },
      { status: 200, bodyPreview: "real resource" },
    );
    expect(v.unauthReachable).toBe(false);
    expect(v.verdict).toBe("auth-required");
  });

  it("is inconclusive when the unauth request errored", () => {
    const v = classifyAuthBoundary({ status: 0, bodyPreview: "", error: "ECONNREFUSED" });
    expect(v.unauthReachable).toBe(false);
    expect(v.verdict).toBe("inconclusive");
  });

  it("is inconclusive on ambiguous status (e.g. 500) with no allow/deny signal", () => {
    const v = classifyAuthBoundary({ status: 500, bodyPreview: "boom" });
    expect(v.unauthReachable).toBe(false);
    expect(v.verdict).toBe("inconclusive");
  });
});

describe("bodySimilarity", () => {
  it("scores identical bodies as 1", () => {
    expect(bodySimilarity("hello world", "HELLO   world")).toBe(1);
  });
  it("scores disjoint bodies as 0", () => {
    expect(bodySimilarity("alpha beta", "gamma delta")).toBe(0);
  });
  it("treats two empty bodies as identical", () => {
    expect(bodySimilarity("", "")).toBe(1);
  });
});

describe("normalizeEndpoint", () => {
  it("expands a bare string into a GET endpoint", () => {
    expect(normalizeEndpoint("https://t/api/x")).toEqual({ url: "https://t/api/x", method: "GET" });
  });
  it("uppercases the method on an object endpoint", () => {
    expect(normalizeEndpoint({ url: "https://t/x", method: "post", body: "b" })).toEqual({
      url: "https://t/x",
      method: "POST",
      body: "b",
    });
  });
});

// ── Runner with a mocked fetch (no network) ──

/** Build a FetchLike that returns canned responses keyed by URL + whether
 * an Authorization/Cookie header was present. */
function mockFetch(
  table: Record<string, { unauth: [number, string]; auth?: [number, string] }>,
): FetchLike {
  return async (url, init) => {
    const entry = table[url];
    const hasAuth = Boolean(
      init?.headers &&
        (init.headers.Authorization || init.headers.authorization || init.headers.Cookie),
    );
    const [status, body] = hasAuth && entry?.auth ? entry.auth : (entry?.unauth ?? [404, ""]);
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: () => "application/json" },
      text: async () => body,
    };
  };
}

describe("runAuthBoundaryProbe", () => {
  it("probes each endpoint authed vs unauthed and counts unauth-reachable", async () => {
    const fetchImpl = mockFetch({
      "https://t/api/public": { unauth: [200, "public ok"], auth: [200, "public ok"] },
      "https://t/api/users": { unauth: [200, "leaked rows 1 2 3"], auth: [200, "leaked rows 1 2 3"] },
      "https://t/api/admin": { unauth: [401, ""], auth: [200, "admin panel"] },
      "https://t/api/missing": { unauth: [404, ""], auth: [404, ""] },
    });

    const report = await runAuthBoundaryProbe({
      endpoints: [
        "https://t/api/public",
        "https://t/api/users",
        "https://t/api/admin",
        "https://t/api/missing",
      ],
      auth: { type: "bearer", token: "secret-token" },
      fetchImpl,
    });

    expect(report.endpointCount).toBe(4);
    expect(report.unauthReachableCount).toBe(2);

    const byUrl = Object.fromEntries(report.results.map((r) => [r.url, r]));
    expect(byUrl["https://t/api/public"].unauthReachable).toBe(true);
    expect(byUrl["https://t/api/users"].verdict).toBe("unauth-reachable");
    expect(byUrl["https://t/api/users"].severity).toBe("high");
    expect(byUrl["https://t/api/admin"].verdict).toBe("auth-required");
    expect(byUrl["https://t/api/missing"].verdict).toBe("not-found");
  });

  it("runs unauth-only when no credentials are supplied", async () => {
    const fetchImpl = mockFetch({
      "https://t/api/open": { unauth: [200, "open"] },
    });
    const report = await runAuthBoundaryProbe({
      endpoints: ["https://t/api/open"],
      fetchImpl,
    });
    expect(report.results[0].auth).toBeUndefined();
    expect(report.results[0].unauthReachable).toBe(true);
    expect(report.results[0].severity).toBe("medium");
  });

  it("records a request error as inconclusive without throwing", async () => {
    const fetchImpl: FetchLike = async () => {
      throw new Error("ECONNREFUSED");
    };
    const report = await runAuthBoundaryProbe({
      endpoints: ["https://t/api/down"],
      fetchImpl,
    });
    expect(report.results[0].verdict).toBe("inconclusive");
    expect(report.results[0].unauth.error).toContain("ECONNREFUSED");
  });
});

describe("summarizeAuthBoundaryReport", () => {
  it("lists the unauth-reachable endpoints", async () => {
    const fetchImpl = mockFetch({
      "https://t/a": { unauth: [200, "x"] },
      "https://t/b": { unauth: [401, ""] },
    });
    const report = await runAuthBoundaryProbe({
      endpoints: ["https://t/a", "https://t/b"],
      fetchImpl,
    });
    const text = summarizeAuthBoundaryReport(report);
    expect(text).toContain("1 of 2 endpoint(s) reachable WITHOUT credentials");
    expect(text).toContain("https://t/a");
    expect(text).not.toContain("https://t/b");
  });
});
