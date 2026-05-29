/**
 * Tests for the live publishability dedup sources (issue #537 / #539).
 *
 * Every source seam is exercised with a STUB `fetchImpl` (or the offline flag)
 * so these tests are deterministic and never touch the network. They prove the
 * four sources are wired and parse real-shaped responses correctly, and that
 * the aggregate `buildPublishabilityInputs` feeds `checkPublishability` to the
 * right verdicts for the regression-corpus cases.
 */

import { describe, it, expect } from "vitest";
import {
  buildPublishabilityInputs,
  makeOwnSubmissionsLookup,
  makeRepoIssueLookup,
  makeSecurityPolicyFetch,
  makeGlobalAdvisoryLookup,
  detectReportingChannel,
  resolveRepository,
  OWN_SUBMISSIONS_REGISTRY,
} from "./publishability-sources.js";
import { checkPublishability } from "./publishability.js";
import type { AttackCategory, Finding, Severity } from "@pwnkit/shared";

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
