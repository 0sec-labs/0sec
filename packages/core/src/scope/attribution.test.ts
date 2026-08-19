import { describe, it, expect } from "vitest";
import {
  resolveAttribution,
  applyAttribution,
  extractAttributionFromScopeJson,
  formatUserAgent,
} from "./attribution.js";
import { ScopePolicy } from "./scope.js";
import { VERSION } from "@0sec/shared";

// ── resolveAttribution ──

describe("resolveAttribution — config sources & precedence (0sec#216)", () => {
  it("returns undefined when no source contributes anything", () => {
    expect(resolveAttribution()).toBeUndefined();
    expect(resolveAttribution({ env: {} })).toBeUndefined();
    expect(resolveAttribution({ cliHeaders: [] })).toBeUndefined();
  });

  it("loads CLI headers from repeatable --attribution-header tokens", () => {
    const cfg = resolveAttribution({
      cliHeaders: ["X-Pentest=engagement-123", "X-Researcher=brian"],
    });
    expect(cfg?.headers).toEqual({
      "X-Pentest": "engagement-123",
      "X-Researcher": "brian",
    });
  });

  it("preserves the value verbatim past the first `=` (allows base64 etc.)", () => {
    const cfg = resolveAttribution({ cliHeaders: ["X-Token=a=b=c"] });
    expect(cfg?.headers["X-Token"]).toBe("a=b=c");
  });

  it("rejects malformed CLI tokens silently (no name, no equals)", () => {
    const cfg = resolveAttribution({
      cliHeaders: ["no-equals", "=just-value", "X-Good=ok"],
    });
    expect(cfg?.headers).toEqual({ "X-Good": "ok" });
  });

  it("loads env headers from 0SEC_ATTRIBUTION_HEADERS JSON", () => {
    const cfg = resolveAttribution({
      env: { "0SEC_ATTRIBUTION_HEADERS": '{"X-Pentest":"env-engagement"}' },
    });
    expect(cfg?.headers["X-Pentest"]).toBe("env-engagement");
  });

  it("throws on malformed 0SEC_ATTRIBUTION_HEADERS JSON", () => {
    expect(() =>
      resolveAttribution({ env: { "0SEC_ATTRIBUTION_HEADERS": "{not json" } }),
    ).toThrow(/0SEC_ATTRIBUTION_HEADERS/);
  });

  it("throws when env headers is not an object of strings", () => {
    expect(() =>
      resolveAttribution({ env: { "0SEC_ATTRIBUTION_HEADERS": '["array"]' } }),
    ).toThrow();
    expect(() =>
      resolveAttribution({ env: { "0SEC_ATTRIBUTION_HEADERS": '{"X-Bad":42}' } }),
    ).toThrow();
  });

  it("loads UA token from env 0SEC_ATTRIBUTION_UA_TOKEN", () => {
    const cfg = resolveAttribution({
      env: { "0SEC_ATTRIBUTION_UA_TOKEN": "env-eng-42" },
    });
    expect(cfg?.userAgentToken).toBe("env-eng-42");
  });

  it("scope file beats env beats CLI on the same header name", () => {
    const cfg = resolveAttribution({
      scopeFileBlock: { headers: { "X-Pentest": "from-file" } },
      env: { "0SEC_ATTRIBUTION_HEADERS": '{"X-Pentest":"from-env"}' },
      cliHeaders: ["X-Pentest=from-cli"],
    });
    expect(cfg?.headers["X-Pentest"]).toBe("from-file");
  });

  it("env beats CLI on the same header name when no scope file value", () => {
    const cfg = resolveAttribution({
      env: { "0SEC_ATTRIBUTION_HEADERS": '{"X-Pentest":"from-env"}' },
      cliHeaders: ["X-Pentest=from-cli"],
    });
    expect(cfg?.headers["X-Pentest"]).toBe("from-env");
  });

  it("merges across sources for distinct keys", () => {
    const cfg = resolveAttribution({
      scopeFileBlock: { headers: { "X-Pentest": "file-pin" } },
      env: { "0SEC_ATTRIBUTION_HEADERS": '{"X-Engagement-ID":"env-42"}' },
      cliHeaders: ["X-Researcher=brian"],
    });
    // Names are canonicalized to title-case (0sec#239), so "X-Engagement-ID"
    // becomes "X-Engagement-Id" in the merged dict.
    expect(cfg?.headers).toEqual({
      "X-Pentest": "file-pin",
      "X-Engagement-Id": "env-42",
      "X-Researcher": "brian",
    });
  });

  it("UA token follows the same precedence (file > env > CLI)", () => {
    const cfg1 = resolveAttribution({
      scopeFileBlock: { user_agent_token: "file-ua" },
      env: { "0SEC_ATTRIBUTION_UA_TOKEN": "env-ua" },
      cliUaToken: "cli-ua",
    });
    expect(cfg1?.userAgentToken).toBe("file-ua");

    const cfg2 = resolveAttribution({
      env: { "0SEC_ATTRIBUTION_UA_TOKEN": "env-ua" },
      cliUaToken: "cli-ua",
    });
    expect(cfg2?.userAgentToken).toBe("env-ua");

    const cfg3 = resolveAttribution({ cliUaToken: "cli-ua" });
    expect(cfg3?.userAgentToken).toBe("cli-ua");
  });

  it("ignores blank UA token strings (treats them as not-set)", () => {
    const cfg = resolveAttribution({
      scopeFileBlock: { user_agent_token: "   " },
      env: { "0SEC_ATTRIBUTION_UA_TOKEN": "real-token" },
    });
    expect(cfg?.userAgentToken).toBe("real-token");
  });

  // ── canonical-case dedup (0sec#239) ──

  it("dedupes header names that differ only in case across sources", () => {
    const cfg = resolveAttribution({
      scopeFileBlock: { headers: { "X-Pentest": "from-file" } },
      env: { "0SEC_ATTRIBUTION_HEADERS": '{"x-pentest":"from-env"}' },
      cliHeaders: ["X-PENTEST=from-cli"],
    });
    expect(Object.keys(cfg!.headers)).toHaveLength(1);
    expect(cfg!.headers["X-Pentest"]).toBe("from-file");
  });

  it("canonicalizes weird casings to title-case", () => {
    const cfg = resolveAttribution({
      cliHeaders: [
        "x-hackerone-research=brian",
        "X-PENTEST=engagement",
        "x-eNgAgEmEnT-iD=42",
      ],
    });
    expect(cfg!.headers).toEqual({
      "X-Hackerone-Research": "brian",
      "X-Pentest": "engagement",
      "X-Engagement-Id": "42",
    });
  });
});

// ── applyAttribution ──

describe("applyAttribution — header injection", () => {
  const attribution = {
    headers: { "X-Pentest": "engagement-123" },
    userAgentToken: "engagement-123",
  };

  it("returns init untouched when attribution is undefined", () => {
    const init = { method: "POST" };
    expect(applyAttribution("https://api.example.com/", init, undefined, undefined)).toBe(init);
  });

  it("injects headers on in-scope hosts", () => {
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const out = applyAttribution(
      "https://api.example.com/health",
      { method: "GET" },
      attribution,
      scope,
    );
    const headers = out!.headers as Record<string, string>;
    expect(headers["X-Pentest"]).toBe("engagement-123");
  });

  it("does NOT inject on out-of-scope hosts even when somehow reached", () => {
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const out = applyAttribution(
      "https://evil.com/exfil",
      { method: "GET" },
      attribution,
      scope,
    );
    // `init.headers` was not set — applyAttribution must not have added any.
    expect((out as RequestInit | undefined)?.headers).toBeUndefined();
  });

  it("does NOT inject on out-of-scope hosts when caller had headers", () => {
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const callerHeaders = { Authorization: "Bearer x" };
    const out = applyAttribution(
      "https://evil.com/exfil",
      { headers: callerHeaders },
      attribution,
      scope,
    );
    // Caller headers preserved, no attribution merged.
    const headers = (out as RequestInit).headers as Record<string, string>;
    expect(headers).toEqual(callerHeaders);
    expect(headers["X-Pentest"]).toBeUndefined();
  });

  it("injects when no scope is loaded but attribution is configured (opt-in)", () => {
    // The "opt-in" behaviour is: if the caller went to the trouble of
    // configuring attribution despite no scope file, they want it on.
    // Out-of-scope leakage prevention happens via scope; without scope
    // there are no out-of-scope hosts.
    const out = applyAttribution(
      "https://anywhere.com/",
      undefined,
      attribution,
      undefined,
    );
    const headers = (out as RequestInit).headers as Record<string, string>;
    expect(headers["X-Pentest"]).toBe("engagement-123");
  });

  it("overrides User-Agent when token is configured", () => {
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const out = applyAttribution(
      "https://api.example.com/",
      undefined,
      attribution,
      scope,
    );
    const headers = (out as RequestInit).headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe(`0sec/${VERSION} (engagement: engagement-123)`);
  });

  it("preserves caller-supplied User-Agent (caller wins)", () => {
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const out = applyAttribution(
      "https://api.example.com/",
      { headers: { "User-Agent": "0sec-crawler/1.0" } },
      attribution,
      scope,
    );
    const headers = (out as RequestInit).headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe("0sec-crawler/1.0");
  });

  it("caller-supplied attribution-shaped headers win over the resolved config", () => {
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const out = applyAttribution(
      "https://api.example.com/",
      { headers: { "X-Pentest": "caller-wins" } },
      attribution,
      scope,
    );
    const headers = (out as RequestInit).headers as Record<string, string>;
    expect(headers["X-Pentest"]).toBe("caller-wins");
  });

  it("merges with caller headers in plain-object form", () => {
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const out = applyAttribution(
      "https://api.example.com/",
      { headers: { "Content-Type": "application/json" } },
      attribution,
      scope,
    );
    const headers = (out as RequestInit).headers as Record<string, string>;
    expect(headers["X-Pentest"]).toBe("engagement-123");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("merges with caller headers in array-of-pairs form", () => {
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const out = applyAttribution(
      "https://api.example.com/",
      { headers: [["Content-Type", "application/json"]] as [string, string][] },
      attribution,
      scope,
    );
    const headers = (out as RequestInit).headers as Record<string, string>;
    expect(headers["X-Pentest"]).toBe("engagement-123");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("only applies UA token (no headers) when only UA configured", () => {
    const onlyUa = { headers: {}, userAgentToken: "engagement-only" };
    const out = applyAttribution(
      "https://api.example.com/",
      undefined,
      onlyUa,
      undefined,
    );
    const headers = (out as RequestInit).headers as Record<string, string>;
    expect(headers["User-Agent"]).toBe(`0sec/${VERSION} (engagement: engagement-only)`);
    expect(Object.keys(headers).filter((k) => k.toLowerCase() !== "user-agent")).toHaveLength(0);
  });
});

// ── extractAttributionFromScopeJson ──

describe("extractAttributionFromScopeJson — scope file ingestion", () => {
  it("returns undefined when no attribution block exists", () => {
    expect(extractAttributionFromScopeJson({ in_scope: ["api.example.com"] })).toBeUndefined();
  });

  it("extracts headers + user_agent_token", () => {
    const block = extractAttributionFromScopeJson({
      in_scope: ["api.example.com"],
      attribution: {
        headers: { "X-Pentest": "engagement-99" },
        user_agent_token: "engagement-99",
      },
    });
    expect(block).toEqual({
      headers: { "X-Pentest": "engagement-99" },
      user_agent_token: "engagement-99",
    });
  });

  it("rejects non-object attribution block", () => {
    expect(() => extractAttributionFromScopeJson({ attribution: "nope" })).toThrow();
    expect(() => extractAttributionFromScopeJson({ attribution: ["bad"] })).toThrow();
  });

  it("rejects non-string header values", () => {
    expect(() =>
      extractAttributionFromScopeJson({ attribution: { headers: { "X-Bad": 42 } } }),
    ).toThrow();
  });

  it("rejects non-string user_agent_token", () => {
    expect(() =>
      extractAttributionFromScopeJson({ attribution: { user_agent_token: 42 } }),
    ).toThrow();
  });

  it("rejects invalid header names", () => {
    expect(() =>
      extractAttributionFromScopeJson({
        attribution: { headers: { "X Bad Spaces": "v" } },
      }),
    ).toThrow();
  });
});

// ── formatUserAgent ──

describe("formatUserAgent", () => {
  it("formats as `0sec/<ver> (engagement: <token>)`", () => {
    expect(formatUserAgent("eng-1")).toBe(`0sec/${VERSION} (engagement: eng-1)`);
  });
});
