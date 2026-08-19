/**
 * Tests for the live publishability dedup sources (issue #537 / #539).
 *
 * Every source seam is exercised with a STUB `fetchImpl` (or the offline flag)
 * so these tests are deterministic and never touch the network. They prove the
 * four sources are wired and parse real-shaped responses correctly, and that
 * the aggregate `buildPublishabilityInputs` feeds `checkPublishability` to the
 * right verdicts for the regression-corpus cases.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildPublishabilityInputs,
  makeOwnSubmissionsLookup,
  makeRepoIssueLookup,
  makeSecurityPolicyFetch,
  makeGlobalAdvisoryLookup,
  detectReportingChannel,
  resolveRepository,
  resolveNovelty,
  OWN_SUBMISSIONS_REGISTRY,
} from "./publishability-sources.js";
import { checkPublishability } from "./publishability.js";
import type { AttackCategory, Finding, Severity } from "@0sec/shared";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    templateId: "t1",
    title: "finding",
    description: "desc",
    severity: "medium" as Severity,
    category: "missing-validation" as AttackCategory,
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" } as Finding["evidence"],
    timestamp: Date.now(),
    ...overrides,
  };
}

/** Build a stubbed fetch that returns a JSON body / text for matching URLs. */
function stubFetch(
  routes: Array<{ match: RegExp; status?: number; json?: unknown; text?: string }>,
): typeof fetch {
  return (async (url: string | URL | Request) => {
    const u = typeof url === "string" ? url : url.toString();
    const route = routes.find((r) => r.match.test(u));
    if (!route) {
      return { ok: false, status: 404, async json() { return {}; }, async text() { return ""; } } as unknown as Response;
    }
    return {
      ok: (route.status ?? 200) < 400,
      status: route.status ?? 200,
      headers: { get: () => null },
      async json() { return route.json ?? {}; },
      async text() { return route.text ?? ""; },
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

// ── Source 2 — our own submissions (curated registry) ───────────────────────

describe("makeOwnSubmissionsLookup (Source 2)", () => {
  it("matches the yaml uniqueKeys declined advisory by package + class", async () => {
    const lookup = makeOwnSubmissionsLookup({ ecosystem: "npm" });
    const refs = await lookup("yaml", "missing-validation");
    expect(refs.length).toBe(1);
    expect(refs[0]?.id).toBe("GHSA-3g7m-p75x-hpf6");
    expect(refs[0]?.status).toBe("declined");
    expect(refs[0]?.source).toBe("own_submission");
  });

  it("does not match an unrelated package", async () => {
    const lookup = makeOwnSubmissionsLookup({ ecosystem: "npm" });
    expect(await lookup("lodash", "prototype-pollution")).toEqual([]);
  });

  it("the registry only contains declined/own entries (no accidental global refs)", () => {
    for (const e of OWN_SUBMISSIONS_REGISTRY) {
      expect(e.ref.source).toBe("own_submission");
    }
  });
});

// ── Source 3 — repo open+closed security issues/PRs (GitHub search) ──────────

describe("makeRepoIssueLookup (Source 3)", () => {
  it("returns [] when no repository is configured (no false duplicate)", async () => {
    const lookup = makeRepoIssueLookup({ fetchImpl: stubFetch([]) });
    expect(await lookup("js-yaml", "missing-validation")).toEqual([]);
  });

  it("matches a closed issue about the same class (js-yaml #739)", async () => {
    const lookup = makeRepoIssueLookup({
      repository: "nodeca/js-yaml",
      fetchImpl: stubFetch([
        {
          match: /api\.github\.com\/search\/issues/,
          json: {
            items: [
              { number: 739, title: "Stack overflow / uncontrolled recursion on deep nesting", state: "closed" },
            ],
          },
        },
      ]),
    });
    const refs = await lookup("js-yaml", "missing-validation");
    expect(refs.length).toBe(1);
    expect(refs[0]?.id).toBe("nodeca/js-yaml#739");
    expect(refs[0]?.source).toBe("repo_issue");
  });

  it("drops items whose text does not match the class", async () => {
    const lookup = makeRepoIssueLookup({
      repository: "nodeca/js-yaml",
      fetchImpl: stubFetch([
        {
          match: /search\/issues/,
          json: { items: [{ number: 1, title: "Docs typo", state: "open" }] },
        },
      ]),
    });
    expect(await lookup("js-yaml", "missing-validation")).toEqual([]);
  });

  it("offline → [] (never hits the network)", async () => {
    let called = false;
    const lookup = makeRepoIssueLookup({
      repository: "nodeca/js-yaml",
      offline: true,
      fetchImpl: (async () => { called = true; return {} as Response; }) as unknown as typeof fetch,
    });
    expect(await lookup("js-yaml", "missing-validation")).toEqual([]);
    expect(called).toBe(false);
  });
});

// ── Source 4 — SECURITY.md fetch + reporting-channel detection ───────────────

describe("makeSecurityPolicyFetch (Source 4)", () => {
  it("fetches SECURITY.md from the default branch", async () => {
    const fetchSecurityPolicy = makeSecurityPolicyFetch({
      repository: "webpack/webpack",
      fetchImpl: stubFetch([
        { match: /raw\.githubusercontent\.com\/webpack\/webpack\/main\/SECURITY\.md/, text: "Do not run on untrusted config." },
      ]),
    });
    const text = await fetchSecurityPolicy("webpack");
    expect(text).toContain("untrusted config");
  });

  it("returns null when no repository and offline", async () => {
    expect(await makeSecurityPolicyFetch({})("x")).toBeNull();
    expect(await makeSecurityPolicyFetch({ repository: "a/b", offline: true })("x")).toBeNull();
  });

  it("detectReportingChannel finds Tidelift + emails", () => {
    const ch = detectReportingChannel(
      "Report security issues via Tidelift or email security@nodeca.com. We use private vulnerability reporting.",
    );
    expect(ch.tidelift).toBe(true);
    expect(ch.emails).toContain("security@nodeca.com");
    expect(ch.privateAdvisory).toBe(true);
  });
});

// ── Source 1 — global advisory lookup (offline short-circuits) ───────────────

describe("makeGlobalAdvisoryLookup (Source 1)", () => {
  it("offline → [] without touching the network", async () => {
    let called = false;
    const lookup = makeGlobalAdvisoryLookup({
      offline: true,
      fetchImpl: (async () => { called = true; return {} as Response; }) as unknown as typeof fetch,
    });
    expect(await lookup("formidable", "path-traversal")).toEqual([]);
    expect(called).toBe(false);
  });

  it("unsupported ecosystem → []", async () => {
    // @ts-expect-error — intentionally passing an unsupported ecosystem
    const lookup = makeGlobalAdvisoryLookup({ ecosystem: "rubygems" });
    expect(await lookup("rails", "sql-injection")).toEqual([]);
  });
});

// ── Repository resolver — npm metadata → owner/repo ─────────────────────────

describe("resolveRepository", () => {
  it("resolves owner/repo from npm repository.url (git+https)", async () => {
    const repo = await resolveRepository("js-yaml", {
      ecosystem: "npm",
      fetchImpl: stubFetch([
        {
          match: /registry\.npmjs\.org\/js-yaml/,
          json: { repository: { type: "git", url: "git+https://github.com/nodeca/js-yaml.git" } },
        },
      ]),
    });
    expect(repo).toBe("nodeca/js-yaml");
  });

  it("handles a string repository field", async () => {
    const repo = await resolveRepository("webpack", {
      ecosystem: "npm",
      fetchImpl: stubFetch([
        { match: /registry\.npmjs\.org\/webpack/, json: { repository: "github:webpack/webpack" } },
      ]),
    });
    expect(repo).toBe("webpack/webpack");
  });

  it("encodes the scope slash for scoped packages", async () => {
    let requested = "";
    await resolveRepository("@babel/core", {
      ecosystem: "npm",
      fetchImpl: (async (url: string) => {
        requested = url;
        return { ok: true, status: 200, async json() { return {}; }, async text() { return ""; } } as unknown as Response;
      }) as unknown as typeof fetch,
    });
    expect(requested).toContain("@babel%2fcore");
  });

  it("returns undefined for a non-GitHub repository (never guesses)", async () => {
    const repo = await resolveRepository("somepkg", {
      ecosystem: "npm",
      fetchImpl: stubFetch([
        { match: /registry\.npmjs\.org/, json: { repository: { url: "https://gitlab.com/foo/bar.git" } } },
      ]),
    });
    expect(repo).toBeUndefined();
  });

  it("returns undefined offline / for non-npm ecosystems without hitting the network", async () => {
    let called = false;
    const fetchImpl = (async () => { called = true; return {} as Response; }) as unknown as typeof fetch;
    expect(await resolveRepository("yaml", { ecosystem: "npm", offline: true, fetchImpl })).toBeUndefined();
    // pypi is a valid DedupEcosystem but the resolver only supports npm today.
    expect(await resolveRepository("requests", { ecosystem: "pypi", fetchImpl })).toBeUndefined();
    expect(called).toBe(false);
  });

  it("returns undefined on a 404 / network error (fail-soft)", async () => {
    const repo = await resolveRepository("nope", {
      ecosystem: "npm",
      fetchImpl: stubFetch([{ match: /registry/, status: 404 }]),
    });
    expect(repo).toBeUndefined();
  });
});

// ── Aggregate — buildPublishabilityInputs end-to-end (offline) ──────────────

describe("buildPublishabilityInputs end-to-end", () => {
  it("wires Source 2 so yaml uniqueKeys resolves to by_design via checkPublishability", async () => {
    const inputs = buildPublishabilityInputs({ ecosystem: "npm", offline: true });
    // offline disables the network sources, but the curated own-submissions
    // registry (Source 2) is pure and still fires.
    const r = await checkPublishability(
      makeFinding({ category: "missing-validation", title: "yaml uniqueKeys DoS" }),
      "yaml",
      "2.8.2",
      { ...inputs, reproducesOnLatest: true },
    );
    expect(r.decision).toBe("by_design");
    expect(r.dedupRefs).toContain("GHSA-3g7m-p75x-hpf6");
  });

  it("a clean package with no matches → in_scope (offline)", async () => {
    const inputs = buildPublishabilityInputs({ ecosystem: "npm", offline: true });
    const r = await checkPublishability(
      makeFinding({ category: "sql-injection", title: "novel sqli" }),
      "totally-novel-pkg",
      "1.0.0",
      inputs,
    );
    expect(r.decision).toBe("in_scope");
  });
});

// ── Public-advisory novelty gate (issue #851) ──────────────────────────────

describe("resolveNovelty (issue #851)", () => {
  let cacheDir: string;
  beforeEach(() => {
    cacheDir = mkdtempSync(join(tmpdir(), "0sec-novelty-test-"));
  });
  afterEach(() => {
    rmSync(cacheDir, { recursive: true, force: true });
  });

  // A real-shaped OSV /v1/query response (version-scoped): one CVE-keyed GHSA.
  const OSV_HIT = {
    vulns: [
      {
        id: "GHSA-f82v-jwr5-mffw",
        aliases: ["CVE-2025-29927"],
        summary: "Authorization Bypass in Next.js Middleware",
        database_specific: { severity: "CRITICAL" },
        references: [
          { type: "ADVISORY", url: "https://github.com/advisories/GHSA-f82v-jwr5-mffw" },
        ],
        affected: [
          {
            package: { ecosystem: "npm", name: "next" },
            ranges: [{ type: "SEMVER", events: [{ introduced: "15.0.0" }, { fixed: "15.2.3" }] }],
          },
        ],
      },
    ],
  };

  it("returns matches-CVE-… for a stubbed OSV hit (version-scoped)", async () => {
    const result = await resolveNovelty("next", "npm", "15.1.0", {
      cacheDir,
      fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: OSV_HIT }]),
    });
    expect(result?.verdict).toBe("matches-CVE-2025-29927");
    expect(result?.advisoryMatches.length).toBeGreaterThan(0);
    expect(result?.advisoryMatches[0]).toMatchObject({
      source: "CVE",
      id: "CVE-2025-29927",
      url: "https://github.com/advisories/GHSA-f82v-jwr5-mffw",
    });
  });

  it("returns matches-GHSA-… when the advisory has no CVE alias", async () => {
    const ghsaOnly = {
      vulns: [
        {
          id: "GHSA-abcd-efgh-ijkl",
          aliases: [],
          summary: "Some published advisory with no CVE yet",
          references: [{ type: "WEB", url: "https://example.com/adv" }],
          affected: [{ package: { ecosystem: "npm", name: "leftpad" } }],
        },
      ],
    };
    const result = await resolveNovelty("leftpad", "npm", "1.0.0", {
      cacheDir,
      fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: ghsaOnly }]),
    });
    // OSV ids are upper-cased by parseOsvResponse, so the verdict carries the
    // normalized id (real intel-module behavior).
    expect(result?.verdict).toBe("matches-GHSA-ABCD-EFGH-IJKL");
    expect(result?.advisoryMatches[0]?.source).toBe("GHSA");
  });

  it("returns novel for an empty version-scoped OSV result", async () => {
    const result = await resolveNovelty("totally-novel-pkg", "npm", "1.0.0", {
      cacheDir,
      fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: { vulns: [] } }]),
    });
    expect(result?.verdict).toBe("novel");
    expect(result?.advisoryMatches).toEqual([]);
  });

  it("returns novel for an empty package-level result when no version was supplied (#851)", async () => {
    // No version → package-level OSV query (all versions). ZERO advisories back
    // means the package genuinely has no known issues → novel, not possibly-known.
    const result = await resolveNovelty("some-pkg", "npm", undefined, {
      cacheDir,
      fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: { vulns: [] } }]),
    });
    expect(result?.verdict).toBe("novel");
  });

  it("returns possibly-known WITH advisories for a package-level hit when no version was supplied (#851)", async () => {
    // No version → package-level query that DID return advisories → the package
    // has a known-CVE history we can't version-confirm → possibly-known + matches.
    const result = await resolveNovelty("next", "npm", undefined, {
      cacheDir,
      fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: OSV_HIT }]),
    });
    expect(result?.verdict).toBe("possibly-known");
    expect(result?.advisoryMatches.length).toBeGreaterThan(0);
  });

  // ── #851 fast-follow: `latest`/non-semver degeneracy ──────────────────────
  // Our scan targets pin `latest`, which OSV can't range-match. A floating tag
  // must NOT be sent as a version-scoped query (→ false `novel`); instead we do
  // a package-level query and treat hits conservatively.

  it("does NOT send `latest` as a version (package-level query, not version-scoped)", async () => {
    let sentBody: Record<string, unknown> | undefined;
    const fetchImpl = (async (_url: string, init?: RequestInit) => {
      sentBody = init?.body ? JSON.parse(String(init.body)) : undefined;
      return {
        ok: true,
        status: 200,
        json: async () => ({ vulns: [] }),
        text: async () => JSON.stringify({ vulns: [] }),
      } as unknown as Response;
    }) as unknown as typeof fetch;
    await resolveNovelty("some-pkg", "npm", "latest", { cacheDir, fetchImpl });
    expect(sentBody).toBeDefined();
    // No `version` key → OSV runs a package-level lookup across all versions.
    expect(sentBody).not.toHaveProperty("version");
    expect(sentBody).toMatchObject({ package: { ecosystem: "npm", name: "some-pkg" } });
  });

  it("returns novel for a `latest`-pinned package with a package-level empty result (#851)", async () => {
    const result = await resolveNovelty("totally-novel-pkg", "npm", "latest", {
      cacheDir,
      fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: { vulns: [] } }]),
    });
    // latest = package-level query; ZERO advisories across all versions → novel.
    expect(result?.verdict).toBe("novel");
    expect(result?.advisoryMatches).toEqual([]);
  });

  it("returns possibly-known WITH advisories for a `latest`-pinned known-vulnerable package", async () => {
    // Package-level hit: the package has a known-CVE history but we can't
    // version-confirm `latest` → flag for review, do NOT emit matches-CVE-….
    const result = await resolveNovelty("next", "npm", "latest", {
      cacheDir,
      fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: OSV_HIT }]),
    });
    expect(result?.verdict).toBe("possibly-known");
    expect(result?.advisoryMatches.length).toBeGreaterThan(0);
    expect(result?.advisoryMatches[0]).toMatchObject({ source: "CVE", id: "CVE-2025-29927" });
  });

  it("treats `*` and a non-numeric dist-tag like `latest` — package-level query (empty → novel)", async () => {
    for (const v of ["*", "next", ""]) {
      const result = await resolveNovelty("some-pkg", "npm", v, {
        cacheDir,
        fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: { vulns: [] } }]),
      });
      // Floating tag → package-level query; empty → novel (no known issues).
      expect(result?.verdict, `version=${JSON.stringify(v)}`).toBe("novel");
    }
  });

  it("a non-numeric dist-tag with a package-level HIT → possibly-known + advisories (#851)", async () => {
    const result = await resolveNovelty("next", "npm", "next", {
      cacheDir,
      fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: OSV_HIT }]),
    });
    expect(result?.verdict).toBe("possibly-known");
    expect(result?.advisoryMatches.length).toBeGreaterThan(0);
  });

  it("still version-scopes a `v`-prefixed concrete semver (→ matches-CVE-…)", async () => {
    const result = await resolveNovelty("next", "npm", "v15.1.0", {
      cacheDir,
      fetchImpl: stubFetch([{ match: /api\.osv\.dev/, json: OSV_HIT }]),
    });
    // `v15.1.0` normalizes to a concrete semver → real version-scoped verdict.
    expect(result?.verdict).toBe("matches-CVE-2025-29927");
  });

  it("returns undefined for a non-OSS ecosystem without touching the network", async () => {
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return {} as Response;
    }) as unknown as typeof fetch;
    // "rubygems" is not an OSV-resolvable ecosystem in toOsvEcosystem.
    expect(await resolveNovelty("rails", "rubygems", "7.0.0", { cacheDir, fetchImpl })).toBeUndefined();
    // unset ecosystem (private/SaaS target) → no verdict, no query
    expect(await resolveNovelty("internal-svc", undefined, "1.0.0", { cacheDir, fetchImpl })).toBeUndefined();
    expect(called).toBe(false);
  });

  it("returns undefined when offline (never leaks the target to the public DB)", async () => {
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return {} as Response;
    }) as unknown as typeof fetch;
    expect(await resolveNovelty("next", "npm", "15.1.0", { cacheDir, offline: true, fetchImpl })).toBeUndefined();
    expect(called).toBe(false);
  });

  it("fails soft to possibly-known when the lookup throws", async () => {
    const fetchImpl = (async () => {
      throw new Error("boom");
    }) as unknown as typeof fetch;
    const result = await resolveNovelty("next", "npm", "15.1.0", { cacheDir, fetchImpl });
    expect(result?.verdict).toBe("possibly-known");
  });
});
