import { describe, expect, it, vi } from "vitest";
import { ScopePolicy } from "../scope/scope.js";
import {
  buildCandidateHosts,
  enumerateSubdomainsActive,
  DEFAULT_SUBDOMAIN_WORDLIST,
  MAX_CANDIDATES,
} from "./active-subdomains.js";
import type { ResolvedHost } from "./subdomains.js";

/** Scope policy that allows everything under the apex (and the apex). */
function scopeFor(apex: string): ScopePolicy {
  return ScopePolicy.fromJson({ in_scope: [apex, `*.${apex}`] });
}

describe("buildCandidateHosts", () => {
  it("turns each wordlist label into a host under the apex", () => {
    const hosts = buildCandidateHosts("example.com", ["www", "api"]);
    expect(hosts).toEqual(["www.example.com", "api.example.com"]);
  });

  it("dedupes labels and ignores ones with dots or wildcards", () => {
    const hosts = buildCandidateHosts("example.com", ["api", "api", "a.b", "*", " www "]);
    expect(hosts.sort()).toEqual(["api.example.com", "www.example.com"]);
  });

  it("permutes known leaf labels with prefixes and suffixes", () => {
    const hosts = buildCandidateHosts("example.com", [], ["app.example.com"]);
    // base label "app" → dev-app / staging-app / test-app / api-app + app-dev …
    expect(hosts).toContain("dev-app.example.com");
    expect(hosts).toContain("api-app.example.com");
    expect(hosts).toContain("app-staging.example.com");
    expect(hosts).toContain("app-internal.example.com");
  });

  it("ignores known hosts that are not a direct single-label child of the apex", () => {
    const hosts = buildCandidateHosts("example.com", [], [
      "a.b.example.com", // nested, skipped
      "other.com", // off-apex, skipped
      "example.com", // apex itself, skipped
    ]);
    expect(hosts).toEqual([]);
  });

  it("never exceeds the hard candidate cap", () => {
    const big = Array.from({ length: MAX_CANDIDATES + 500 }, (_, i) => `l${i}`);
    expect(buildCandidateHosts("example.com", big).length).toBe(MAX_CANDIDATES);
  });
});

describe("enumerateSubdomainsActive — gating", () => {
  it("is OFF by default: no resolve calls when `enabled` is unset", async () => {
    const resolve = vi.fn<[string], Promise<ResolvedHost>>();
    const hosts = await enumerateSubdomainsActive({
      domain: "example.com",
      scope: scopeFor("example.com"),
      resolve,
    });
    expect(hosts).toEqual([]);
    expect(resolve).not.toHaveBeenCalled();
  });

  it("resolves nothing when enabled but no scope policy is supplied (deny-by-default)", async () => {
    const resolve = vi.fn<[string], Promise<ResolvedHost>>();
    const hosts = await enumerateSubdomainsActive({
      domain: "example.com",
      enabled: true,
      resolve,
    });
    expect(hosts).toEqual([]);
    expect(resolve).not.toHaveBeenCalled();
  });

  it("only resolves candidates the scope policy allows", async () => {
    // in scope: only api.example.com (exact). Everything else denied.
    const scope = ScopePolicy.fromJson({ in_scope: ["api.example.com"] });
    const resolve = vi.fn(async (host: string): Promise<ResolvedHost> => {
      if (host === "api.example.com") return { addresses: ["10.0.0.5"] };
      throw new Error(`no records for ${host}`);
    });
    const hosts = await enumerateSubdomainsActive({
      domain: "example.com",
      enabled: true,
      scope,
      wordlist: ["api", "admin", "www"],
      resolve,
    });
    expect(hosts).toEqual([{ host: "api.example.com", source: "dns-bruteforce", addresses: ["10.0.0.5"] }]);
    // admin/www were filtered out by scope, never resolved.
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(resolve).toHaveBeenCalledWith("api.example.com");
  });

  it("returns [] on an empty / invalid domain without resolving", async () => {
    const resolve = vi.fn<[string], Promise<ResolvedHost>>();
    const hosts = await enumerateSubdomainsActive({
      domain: "   ",
      enabled: true,
      scope: scopeFor("example.com"),
      resolve,
    });
    expect(hosts).toEqual([]);
    expect(resolve).not.toHaveBeenCalled();
  });
});

describe("enumerateSubdomainsActive — resolution", () => {
  it("keeps only resolving hosts, tags source dns-bruteforce, sorts by host, carries cname", async () => {
    const resolved: Record<string, ResolvedHost> = {
      "api.example.com": { addresses: ["10.0.0.1"], cname: "lb.example.com" },
      "www.example.com": { addresses: ["10.0.0.2"] },
    };
    const resolve = vi.fn(async (host: string): Promise<ResolvedHost> => {
      const r = resolved[host];
      if (!r) throw new Error(`no records for ${host}`);
      return r;
    });
    const hosts = await enumerateSubdomainsActive({
      domain: "example.com",
      enabled: true,
      scope: scopeFor("example.com"),
      wordlist: ["www", "api", "admin"], // admin doesn't resolve → dropped
      resolve,
    });
    expect(hosts).toEqual([
      { host: "api.example.com", source: "dns-bruteforce", addresses: ["10.0.0.1"], cname: "lb.example.com" },
      { host: "www.example.com", source: "dns-bruteforce", addresses: ["10.0.0.2"] },
    ]);
  });

  it("honors the wall-clock kill-switch: stops issuing lookups once the deadline passes", async () => {
    // Clock advances 100ms each read; deadline is 0ms from start → second
    // worker check already past the deadline, so at most the initial in-flight
    // tasks run. With concurrency 1 and maxDurationMs 0, nothing resolves.
    let t = 1_000;
    const now = () => (t += 100);
    const resolve = vi.fn(async (): Promise<ResolvedHost> => ({ addresses: ["10.0.0.9"] }));
    const hosts = await enumerateSubdomainsActive({
      domain: "example.com",
      enabled: true,
      scope: scopeFor("example.com"),
      wordlist: ["a", "b", "c", "d"],
      concurrency: 1,
      maxDurationMs: 0,
      now,
      resolve,
    });
    expect(hosts).toEqual([]);
    expect(resolve).not.toHaveBeenCalled();
  });

  it("uses the built-in wordlist by default", async () => {
    const resolve = vi.fn(async (host: string): Promise<ResolvedHost> => {
      if (host === `www.example.com`) return { addresses: ["1.1.1.1"] };
      throw new Error("nope");
    });
    const hosts = await enumerateSubdomainsActive({
      domain: "example.com",
      enabled: true,
      scope: scopeFor("example.com"),
      resolve,
    });
    expect(hosts).toEqual([{ host: "www.example.com", source: "dns-bruteforce", addresses: ["1.1.1.1"] }]);
    // Sanity: the default wordlist was actually used (more than one candidate tried).
    expect(resolve.mock.calls.length).toBeGreaterThan(1);
    expect(resolve.mock.calls.length).toBe(DEFAULT_SUBDOMAIN_WORDLIST.length);
  });
});
