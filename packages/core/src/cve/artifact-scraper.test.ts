/**
 * artifact-scraper tests. Same pattern as wp-fingerprint.test.ts:
 * a route-table mock fetch substituted via `opts.fetchImpl`, an
 * injected clock for cache-TTL deterministic tests, and a temp
 * cache dir per test so the operator's real `~/.0sec` is never
 * touched.
 *
 * No real network is hit — every URL the scraper would resolve is
 * either in the route table or returns a synthetic 404 from the mock.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, readdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  findCveArtifacts,
  classifyReferences,
  parseNvdResponse,
  parseGhsaResponse,
  parseOsvResponse,
  parseUbuntuTracker,
  parseRedHatTracker,
  findUbuntuTrackerUrls,
  findRedHatTrackerUrls,
  normaliseCveId,
  scoreRepoCandidate,
  scoreCodeCandidate,
  type FetchLike,
} from "./artifact-scraper.js";

// ── Mock fetch infrastructure ──

interface MockResponse {
  status?: number;
  ok?: boolean;
  body?: string;
  json?: unknown;
  headers?: Record<string, string>;
}

type Route = MockResponse | ((url: string) => MockResponse);

interface MockFetchTracker {
  calls: string[];
  fetch: FetchLike;
}

function buildMockFetch(routes: Record<string, Route>): MockFetchTracker {
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (url, _init) => {
    calls.push(url);
    // Match on origin+pathname first, then exact URL.
    let route: Route | undefined;
    try {
      const u = new URL(url);
      route = routes[`${u.origin}${u.pathname}`] ?? routes[url];
    } catch {
      route = routes[url];
    }
    const resolved =
      typeof route === "function"
        ? route(url)
        : (route ?? { status: 404, ok: false, body: "" });
    const status = resolved.status ?? (resolved.ok === false ? 404 : 200);
    const ok = resolved.ok ?? (status >= 200 && status < 300);
    const body = resolved.body ?? "";
    const headers = resolved.headers ?? {};
    return {
      ok,
      status,
      text: async () => body,
      json: async () =>
        resolved.json !== undefined ? resolved.json : JSON.parse(body || "{}"),
      headers: {
        get: (name: string) => headers[name.toLowerCase()] ?? null,
      },
    };
  };
  return { calls, fetch: fetchImpl };
}

function tmpCacheDir(): string {
  return mkdtempSync(join(tmpdir(), "0sec-cve-cache-"));
}

const NVD_URL_PREFIX = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const GHSA_URL_PREFIX = "https://api.github.com/advisories";
const OSV_URL_PREFIX = "https://api.osv.dev/v1/vulns";
const GH_REPOS_PREFIX = "https://api.github.com/search/repositories";
const RH_PREFIX = "https://access.redhat.com/hydra/rest/securitydata/cve";

// ── Pure parser tests ──

describe("normaliseCveId", () => {
  it("uppercases a valid id", () => {
    expect(normaliseCveId("cve-2024-1086")).toBe("CVE-2024-1086");
  });
  it("rejects malformed input", () => {
    expect(() => normaliseCveId("CVE-2024-12")).toThrow();
    expect(() => normaliseCveId("not-a-cve")).toThrow();
    expect(() => normaliseCveId("CVE2024-1086")).toThrow();
  });
});

describe("parseNvdResponse", () => {
  it("extracts description, references, and CPE-based affected ranges", () => {
    const nvdJson = {
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2024-1086",
            published: "2024-01-31T00:00:00.000",
            descriptions: [
              { lang: "en", value: "Use-after-free in nf_tables." },
              { lang: "es", value: "Uso después de liberación." },
            ],
            references: [
              { url: "https://example.com/poc", tags: ["Exploit"] },
              { url: "https://example.com/patch", tags: ["Patch"] },
              { url: "https://github.com/foo/cve-2024-1086", tags: ["Exploit", "Third Party Advisory"] },
            ],
            configurations: [
              {
                nodes: [
                  {
                    cpeMatch: [
                      {
                        vulnerable: true,
                        criteria: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                        versionStartIncluding: "5.14",
                        versionEndExcluding: "6.6.46",
                      },
                    ],
                  },
                ],
              },
            ],
          },
        },
      ],
    };
    const parsed = parseNvdResponse(nvdJson, "CVE-2024-1086");
    expect(parsed.description).toBe("Use-after-free in nf_tables.");
    expect(parsed.published).toBe("2024-01-31T00:00:00.000");
    expect(parsed.references).toHaveLength(3);
    expect(parsed.affected).toHaveLength(1);
    expect(parsed.affected[0].range).toBe(">=5.14,<6.6.46");
    expect(parsed.affected[0].product).toBe("linux_kernel");
    expect(parsed.affected[0].vendor).toBe("linux");
  });

  it("returns empty result when the CVE id is missing", () => {
    const out = parseNvdResponse({ vulnerabilities: [] }, "CVE-2024-1086");
    expect(out.references).toEqual([]);
    expect(out.affected).toEqual([]);
  });
});

describe("parseGhsaResponse", () => {
  it("extracts references and version ranges from /advisories", () => {
    const ghsaJson = [
      {
        ghsa_id: "GHSA-xxxx-yyyy-zzzz",
        cve_id: "CVE-2024-1086",
        summary: "Linux kernel UAF",
        published_at: "2024-02-01T00:00:00Z",
        references: [
          "https://example.com/advisory",
          { url: "https://github.com/foo/poc" },
        ],
        vulnerabilities: [
          {
            package: { name: "linux", ecosystem: "Linux" },
            vulnerable_version_range: "< 6.6.46",
          },
        ],
      },
    ];
    const out = parseGhsaResponse(ghsaJson, "CVE-2024-1086");
    expect(out.description).toBe("Linux kernel UAF");
    expect(out.references).toContain("https://example.com/advisory");
    expect(out.references).toContain("https://github.com/foo/poc");
    expect(out.affected[0].range).toBe("< 6.6.46");
    expect(out.affected[0].product).toBe("linux");
  });

  it("returns empty when /advisories returns []", () => {
    const out = parseGhsaResponse([], "CVE-2024-1086");
    expect(out.references).toEqual([]);
    expect(out.affected).toEqual([]);
  });
});

describe("parseOsvResponse", () => {
  it("extracts references and event-based ranges", () => {
    const osvJson = {
      id: "CVE-2024-1086",
      summary: "Use-after-free in nf_tables",
      published: "2024-01-31T00:00:00Z",
      references: [
        { type: "ADVISORY", url: "https://example.com/advisory" },
        { type: "WEB", url: "https://example.com/writeup" },
      ],
      affected: [
        {
          package: { name: "linux-kernel", ecosystem: "Linux" },
          ranges: [
            {
              type: "ECOSYSTEM",
              events: [
                { introduced: "5.14" },
                { fixed: "6.6.46" },
              ],
            },
          ],
        },
      ],
    };
    const out = parseOsvResponse(osvJson);
    expect(out.description).toBe("Use-after-free in nf_tables");
    expect(out.references).toEqual([
      "https://example.com/advisory",
      "https://example.com/writeup",
    ]);
    expect(out.affected[0].range).toBe(">=5.14,<6.6.46");
  });
});

describe("classifyReferences", () => {
  it("splits github repo references into PoC candidates and writeups", () => {
    const refs = [
      { url: "https://github.com/foo/cve-2024-1086", tags: ["Exploit"] },
      { url: "https://example.com/blog/cve-2024-1086", tags: [] },
      { url: "https://github.com/torvalds/linux/commit/abc123", tags: ["Patch"] },
      { url: "https://gist.github.com/foo/abc123", tags: ["Exploit"] },
    ];
    const out = classifyReferences(refs);
    const pocUrls = out.pocs.map((p) => p.url);
    expect(pocUrls).toContain("https://github.com/foo/cve-2024-1086");
    expect(pocUrls).toContain("https://gist.github.com/foo/abc123");
    // Patch commits are NOT PoC candidates
    expect(pocUrls).not.toContain("https://github.com/torvalds/linux/commit/abc123");
    expect(out.writeups).toContain("https://example.com/blog/cve-2024-1086");
  });
});

describe("findUbuntuTrackerUrls / findRedHatTrackerUrls", () => {
  it("extracts USN URLs from a reference list", () => {
    const refs = [
      "https://ubuntu.com/security/notices/USN-6680-1",
      "https://example.com/other",
    ];
    expect(findUbuntuTrackerUrls(refs)).toEqual([
      "https://ubuntu.com/security/notices/USN-6680-1.json",
    ]);
  });

  it("derives the Red Hat canonical URL even without a reference", () => {
    const urls = findRedHatTrackerUrls([], "CVE-2024-1086");
    expect(urls).toContain(
      "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-1086.json",
    );
  });
});

describe("parseUbuntuTracker", () => {
  it("extracts affected packages from the releases map", () => {
    const json = {
      id: "USN-6680-1",
      releases: {
        jammy: { sources: { linux: { version: "5.15.0-100.110" } } },
        focal: { sources: { linux: { version: "5.4.0-180.200" } } },
      },
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1086"],
    };
    const out = parseUbuntuTracker(json);
    expect(out.affected).toHaveLength(2);
    expect(out.affected[0].vendor).toBe("ubuntu/jammy");
    expect(out.affected[0].range).toBe("<5.15.0-100.110");
    expect(out.references).toContain("https://nvd.nist.gov/vuln/detail/CVE-2024-1086");
  });
});

describe("parseRedHatTracker", () => {
  it("extracts affected_release rows + bugzilla url", () => {
    const json = {
      bugzilla: { url: "https://bugzilla.redhat.com/show_bug.cgi?id=2256490" },
      affected_release: [
        { product_name: "RHEL 9", package: "kernel-5.14.0-427.13.1.el9_4" },
      ],
      references: ["https://access.redhat.com/security/cve/CVE-2024-1086"],
    };
    const out = parseRedHatTracker(json);
    expect(out.affected[0].vendor).toBe("RHEL 9");
    expect(out.affected[0].product).toBe("kernel-5.14.0-427.13.1.el9_4");
    expect(out.references).toContain(
      "https://bugzilla.redhat.com/show_bug.cgi?id=2256490",
    );
  });
});

describe("scoreRepoCandidate", () => {
  it("scores a high-quality, fresh CVE-named PoC repo high", () => {
    const today = new Date().toISOString();
    const { confidence, language } = scoreRepoCandidate(
      {
        full_name: "foo/cve-2024-1086-poc",
        stargazers_count: 250,
        language: "C",
        pushed_at: today,
        fork: false,
      },
      "CVE-2024-1086",
    );
    expect(confidence).toBeGreaterThan(0.5);
    expect(language).toBe("c");
  });
  it("penalises forks", () => {
    const today = new Date().toISOString();
    const forked = scoreRepoCandidate(
      {
        full_name: "bar/cve-2024-1086-fork",
        stargazers_count: 5,
        pushed_at: today,
        fork: true,
      },
      "CVE-2024-1086",
    );
    const orig = scoreRepoCandidate(
      {
        full_name: "bar/cve-2024-1086-fork",
        stargazers_count: 5,
        pushed_at: today,
        fork: false,
      },
      "CVE-2024-1086",
    );
    expect(forked.confidence).toBeLessThan(orig.confidence);
  });
});

describe("scoreCodeCandidate", () => {
  it("ranks <cve>.c filename higher than generic file", () => {
    const named = scoreCodeCandidate(
      { name: "cve-2024-1086.c", path: "src/cve-2024-1086.c", repository: { stargazers_count: 0 } },
      "CVE-2024-1086",
    );
    const generic = scoreCodeCandidate(
      { name: "main.c", path: "src/main.c", repository: { stargazers_count: 0 } },
      "CVE-2024-1086",
    );
    expect(named.confidence).toBeGreaterThan(generic.confidence);
    expect(named.language).toBe("c");
  });
});

// ── End-to-end tests: findCveArtifacts ──

describe("findCveArtifacts — per-source happy paths", () => {
  let cacheDir: string;
  beforeEach(() => {
    cacheDir = tmpCacheDir();
  });

  it("parses NVD + GHSA + GitHub search and ranks PoCs by confidence", async () => {
    const nvdJson = {
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2024-1086",
            published: "2024-01-31T00:00:00.000",
            descriptions: [{ lang: "en", value: "UAF in nf_tables" }],
            references: [
              { url: "https://github.com/Notselwyn/CVE-2024-1086", tags: ["Exploit"] },
              { url: "https://lwn.net/articles/something/", tags: [] },
            ],
            configurations: [
              {
                nodes: [
                  {
                    cpeMatch: [
                      {
                        vulnerable: true,
                        criteria: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                        versionEndExcluding: "6.6.46",
                      },
                    ],
                  },
                ],
              },
            ],
          },
        },
      ],
    };

    const ghsaJson = [
      {
        ghsa_id: "GHSA-aaaa-bbbb-cccc",
        cve_id: "CVE-2024-1086",
        summary: "Linux kernel UAF",
        published_at: "2024-02-01T00:00:00Z",
        references: ["https://github.com/torvalds/linux/commit/abc"],
        vulnerabilities: [
          {
            package: { name: "linux", ecosystem: "Linux" },
            vulnerable_version_range: "< 6.6.46",
          },
        ],
      },
    ];

    const reposJson = {
      total_count: 1,
      items: [
        {
          full_name: "Notselwyn/CVE-2024-1086",
          html_url: "https://github.com/Notselwyn/CVE-2024-1086",
          description: "PoC for CVE-2024-1086",
          stargazers_count: 1000,
          language: "C",
          pushed_at: new Date().toISOString(),
          fork: false,
        },
        {
          full_name: "noise/random-fork",
          html_url: "https://github.com/noise/random-fork",
          description: "random fork",
          stargazers_count: 0,
          language: "C",
          pushed_at: "2018-01-01T00:00:00Z",
          fork: true,
        },
      ],
    };

    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: { ok: true, status: 200, json: nvdJson },
      [`${GHSA_URL_PREFIX}`]: { ok: true, status: 200, json: ghsaJson },
      [`${GH_REPOS_PREFIX}`]: { ok: true, status: 200, json: reposJson },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
    });

    const result = await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cacheDir,
      cache: false,
    });

    expect(result.cve_id).toBe("CVE-2024-1086");
    expect(result.description).toBe("UAF in nf_tables");
    expect(result.affected.some((a) => a.range === "<6.6.46")).toBe(true);
    expect(result.affected.some((a) => a.range === "< 6.6.46")).toBe(true);
    expect(result.poc_urls.length).toBeGreaterThan(0);
    expect(result.poc_urls[0].url).toBe("https://github.com/Notselwyn/CVE-2024-1086");
    expect(result.poc_urls[0].confidence).toBeGreaterThan(0.5);
    expect(result.writeup_urls).toContain("https://lwn.net/articles/something/");
    // OSV was skipped because GHSA had hits
    const osvLog = result.sources.find((s) => s.source === "osv");
    expect(osvLog?.status).toBe("skipped");
  });

  it("falls back to OSV when GHSA is empty", async () => {
    const osvJson = {
      id: "CVE-2024-1086",
      summary: "From OSV",
      references: [{ type: "ADVISORY", url: "https://example.com/osv-advisory" }],
      affected: [
        {
          package: { name: "linux", ecosystem: "Linux" },
          ranges: [{ type: "ECOSYSTEM", events: [{ fixed: "6.6.46" }] }],
        },
      ],
    };
    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: { ok: false, status: 404 },
      [`${GHSA_URL_PREFIX}`]: { ok: true, status: 200, json: [] },
      [`${OSV_URL_PREFIX}/CVE-2024-1086`]: { ok: true, status: 200, json: osvJson },
      [`${GH_REPOS_PREFIX}`]: { ok: true, status: 200, json: { items: [] } },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
    });
    const result = await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cacheDir,
      cache: false,
    });
    expect(result.description).toBe("From OSV");
    expect(result.writeup_urls).toContain("https://example.com/osv-advisory");
    const osvLog = result.sources.find((s) => s.source === "osv");
    expect(osvLog?.status).toBe("ok");
  });

  it("hits Ubuntu USN tracker when a USN reference appears in NVD", async () => {
    const nvdJson = {
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2024-1086",
            descriptions: [{ lang: "en", value: "x" }],
            references: [
              { url: "https://ubuntu.com/security/notices/USN-6680-1", tags: [] },
            ],
            configurations: [],
          },
        },
      ],
    };
    const usnJson = {
      id: "USN-6680-1",
      releases: { jammy: { sources: { linux: { version: "5.15.0-100" } } } },
      references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-1086"],
    };
    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: { ok: true, status: 200, json: nvdJson },
      [`${GHSA_URL_PREFIX}`]: { ok: true, status: 200, json: [] },
      [`${OSV_URL_PREFIX}/CVE-2024-1086`]: { ok: false, status: 404 },
      "https://ubuntu.com/security/notices/USN-6680-1.json": {
        ok: true,
        status: 200,
        json: usnJson,
      },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
      [`${GH_REPOS_PREFIX}`]: { ok: true, status: 200, json: { items: [] } },
    });
    const result = await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cacheDir,
      cache: false,
    });
    expect(
      result.affected.some(
        (a) => a.source === "ubuntu" && a.vendor === "ubuntu/jammy",
      ),
    ).toBe(true);
    const ubuntuLog = result.sources.find((s) => s.source === "ubuntu");
    expect(ubuntuLog?.status).toBe("ok");
  });
});

describe("findCveArtifacts — error handling", () => {
  it("returns an empty CveArtifacts when NVD 404s (no throw)", async () => {
    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: { ok: false, status: 404 },
      [`${GHSA_URL_PREFIX}`]: { ok: false, status: 404 },
      [`${OSV_URL_PREFIX}/CVE-2024-1086`]: { ok: false, status: 404 },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
      [`${GH_REPOS_PREFIX}`]: { ok: false, status: 404 },
    });
    const result = await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cache: false,
    });
    expect(result.cve_id).toBe("CVE-2024-1086");
    expect(result.poc_urls).toEqual([]);
    expect(result.affected).toEqual([]);
    expect(result.writeup_urls).toEqual([]);
    const nvdLog = result.sources.find((s) => s.source === "nvd");
    expect(nvdLog?.status).toBe("miss");
  });

  it("retries 5xx with backoff and surfaces the eventual response", async () => {
    let nvdHits = 0;
    const nvdJson = {
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2024-1086",
            descriptions: [{ lang: "en", value: "ok" }],
            references: [],
            configurations: [],
          },
        },
      ],
    };
    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: () => {
        nvdHits += 1;
        if (nvdHits < 3) {
          return { ok: false, status: 503, body: "transient" };
        }
        return { ok: true, status: 200, json: nvdJson };
      },
      [`${GHSA_URL_PREFIX}`]: { ok: true, status: 200, json: [] },
      [`${OSV_URL_PREFIX}/CVE-2024-1086`]: { ok: false, status: 404 },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
      [`${GH_REPOS_PREFIX}`]: { ok: true, status: 200, json: { items: [] } },
    });
    const result = await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cache: false,
      retries: 3,
      backoffMs: 1,
    });
    expect(nvdHits).toBe(3);
    expect(result.description).toBe("ok");
  });

  it("flags GitHub rate-limit (403 + x-ratelimit-remaining=0) without throwing", async () => {
    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: { ok: false, status: 404 },
      [`${GHSA_URL_PREFIX}`]: {
        ok: false,
        status: 403,
        body: "rl",
        headers: { "x-ratelimit-remaining": "0" },
      },
      [`${OSV_URL_PREFIX}/CVE-2024-1086`]: { ok: false, status: 404 },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
      [`${GH_REPOS_PREFIX}`]: {
        ok: false,
        status: 403,
        headers: { "x-ratelimit-remaining": "0" },
      },
    });
    const result = await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cache: false,
    });
    const ghsaLog = result.sources.find((s) => s.source === "ghsa");
    expect(ghsaLog?.status).toBe("rate-limited");
  });
});

describe("findCveArtifacts — caching", () => {
  it("writes a cache entry on first hit and reads it on the second", async () => {
    const cacheDir = tmpCacheDir();
    const nvdJson = {
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2024-1086",
            descriptions: [{ lang: "en", value: "cached" }],
            references: [],
            configurations: [],
          },
        },
      ],
    };
    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: { ok: true, status: 200, json: nvdJson },
      [`${GHSA_URL_PREFIX}`]: { ok: true, status: 200, json: [] },
      [`${OSV_URL_PREFIX}/CVE-2024-1086`]: { ok: false, status: 404 },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
      [`${GH_REPOS_PREFIX}`]: { ok: true, status: 200, json: { items: [] } },
    });

    const r1 = await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cacheDir,
      skipGithubPocSearch: true,
    });
    expect(r1.description).toBe("cached");
    const callsAfterFirst = mock.calls.length;
    expect(callsAfterFirst).toBeGreaterThan(0);
    // Cache file exists on disk
    expect(existsSync(join(cacheDir, "nvd"))).toBe(true);
    const nvdEntries = readdirSync(join(cacheDir, "nvd"));
    expect(nvdEntries.length).toBeGreaterThan(0);

    const r2 = await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cacheDir,
      skipGithubPocSearch: true,
    });
    expect(r2.description).toBe("cached");
    // NVD call should NOT have been re-issued
    const nvdCallsAfterSecond = mock.calls.filter((u) =>
      u.startsWith(NVD_URL_PREFIX),
    ).length;
    expect(nvdCallsAfterSecond).toBe(1);
    const nvdLog = r2.sources.find((s) => s.source === "nvd");
    expect(nvdLog?.status).toBe("cached");
  });

  it("re-fetches when the cache entry has expired", async () => {
    const cacheDir = tmpCacheDir();
    let nvdHits = 0;
    const nvdJson = {
      vulnerabilities: [
        {
          cve: {
            id: "CVE-2024-1086",
            descriptions: [{ lang: "en", value: "ttl-test" }],
            references: [],
            configurations: [],
          },
        },
      ],
    };
    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: () => {
        nvdHits += 1;
        return { ok: true, status: 200, json: nvdJson };
      },
      [`${GHSA_URL_PREFIX}`]: { ok: true, status: 200, json: [] },
      [`${OSV_URL_PREFIX}/CVE-2024-1086`]: { ok: false, status: 404 },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
      [`${GH_REPOS_PREFIX}`]: { ok: true, status: 200, json: { items: [] } },
    });

    let clock = 1_000_000;
    await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cacheDir,
      cacheTtlMs: 10,
      now: () => clock,
      skipGithubPocSearch: true,
    });
    expect(nvdHits).toBe(1);
    clock += 1000;
    await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cacheDir,
      cacheTtlMs: 10,
      now: () => clock,
      skipGithubPocSearch: true,
    });
    expect(nvdHits).toBe(2);
  });

  it("bypasses cache when cache: false", async () => {
    const cacheDir = tmpCacheDir();
    let nvdHits = 0;
    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: () => {
        nvdHits += 1;
        return {
          ok: true,
          status: 200,
          json: {
            vulnerabilities: [
              {
                cve: {
                  id: "CVE-2024-1086",
                  descriptions: [{ lang: "en", value: "no-cache" }],
                  references: [],
                  configurations: [],
                },
              },
            ],
          },
        };
      },
      [`${GHSA_URL_PREFIX}`]: { ok: true, status: 200, json: [] },
      [`${OSV_URL_PREFIX}/CVE-2024-1086`]: { ok: false, status: 404 },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
      [`${GH_REPOS_PREFIX}`]: { ok: true, status: 200, json: { items: [] } },
    });
    await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cacheDir,
      cache: false,
      skipGithubPocSearch: true,
    });
    await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cacheDir,
      cache: false,
      skipGithubPocSearch: true,
    });
    expect(nvdHits).toBe(2);
  });
});

describe("findCveArtifacts — GitHub auth", () => {
  let originalToken: string | undefined;
  beforeEach(() => {
    originalToken = process.env.GITHUB_TOKEN;
    delete process.env.GITHUB_TOKEN;
  });
  afterEach(() => {
    if (originalToken !== undefined) process.env.GITHUB_TOKEN = originalToken;
    else delete process.env.GITHUB_TOKEN;
  });

  it("skips code search without a token but still does repo search", async () => {
    const mock = buildMockFetch({
      [`${NVD_URL_PREFIX}`]: { ok: false, status: 404 },
      [`${GHSA_URL_PREFIX}`]: { ok: true, status: 200, json: [] },
      [`${OSV_URL_PREFIX}/CVE-2024-1086`]: { ok: false, status: 404 },
      [`${RH_PREFIX}/CVE-2024-1086.json`]: { ok: false, status: 404 },
      [`${GH_REPOS_PREFIX}`]: { ok: true, status: 200, json: { items: [] } },
    });
    const result = await findCveArtifacts("CVE-2024-1086", {
      fetchImpl: mock.fetch,
      cache: false,
    });
    const codeSearchLogs = result.sources.filter(
      (s) => s.source === "github-search" && s.url.includes("search/code"),
    );
    expect(codeSearchLogs.length).toBeGreaterThan(0);
    expect(codeSearchLogs[0].status).toBe("skipped");
  });

  it("includes Authorization header when token is provided via opts", async () => {
    const authHeaders: string[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      const h = (init?.headers ?? {}) as Record<string, string>;
      if (h.authorization) authHeaders.push(h.authorization);
      // Return empty success for everything
      if (url.startsWith(GHSA_URL_PREFIX) || url.startsWith(GH_REPOS_PREFIX)) {
        return {
          ok: true,
          status: 200,
          text: async () => "[]",
          json: async () =>
            url.startsWith(GH_REPOS_PREFIX) ? { items: [] } : [],
          headers: { get: () => null },
        };
      }
      return {
        ok: false,
        status: 404,
        text: async () => "",
        json: async () => ({}),
        headers: { get: () => null },
      };
    };
    await findCveArtifacts("CVE-2024-1086", {
      fetchImpl,
      cache: false,
      githubToken: "ghp_test_token_value",
    });
    expect(authHeaders.some((h) => h.includes("ghp_test_token_value"))).toBe(
      true,
    );
  });
});
