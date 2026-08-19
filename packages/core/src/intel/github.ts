import { cachedJson, IntelCache } from "./cache.js";
import { normalizeSeverity, uniqueReferences, uniqueStrings } from "./normalize.js";
import type { AdvisorySearchInput, FetchOptions, VulnerabilityIntel } from "./types.js";

interface GitHubAdvisory {
  ghsa_id?: string;
  cve_id?: string | null;
  summary?: string;
  description?: string;
  severity?: string;
  html_url?: string;
  references?: string[];
  published_at?: string;
  updated_at?: string;
  identifiers?: Array<{ type?: string; value?: string }>;
  vulnerabilities?: Array<{
    package?: { ecosystem?: string; name?: string };
    vulnerable_version_range?: string;
    first_patched_version?: { identifier?: string } | null;
    vulnerable_functions?: string[];
  }>;
  cvss?: { vector_string?: string; score?: number };
  cwes?: Array<{ cwe_id?: string; name?: string }>;
}

export async function queryGitHubAdvisories(
  input: AdvisorySearchInput,
  opts: FetchOptions = {},
): Promise<VulnerabilityIntel[]> {
  const cache = new IntelCache(input.cacheDir);
  const key = JSON.stringify({
    ecosystem: input.ecosystem,
    packageName: input.packageName,
  });
  const raw = await cachedJson<GitHubAdvisory[]>(
    cache,
    "github-advisories",
    key,
    async () => {
      const query = new URLSearchParams({
        ecosystem: githubEcosystem(input.ecosystem),
        affects: input.packageName,
        per_page: "100",
      });
      return await fetchGitHubAdvisoryPages(
        `https://api.github.com/advisories?${query}`,
        opts,
      );
    },
    { offline: input.offline, ttlMs: input.ttlMs },
  );
  return parseGitHubAdvisories(raw);
}

async function fetchGitHubAdvisoryPages(url: string, opts: FetchOptions): Promise<GitHubAdvisory[]> {
  const out: GitHubAdvisory[] = [];
  let nextUrl: string | undefined = url;
  while (nextUrl) {
    const { data, next } = await fetchGitHubAdvisoryPage(nextUrl, opts);
    out.push(...data);
    nextUrl = next;
  }
  return out;
}

async function fetchGitHubAdvisoryPage(
  url: string,
  opts: FetchOptions,
): Promise<{ data: GitHubAdvisory[]; next?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 20_000);
  try {
    const res = await (opts.fetchImpl ?? fetch)(url, {
      headers: githubHeaders(opts.headers),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return {
      data: await res.json() as GitHubAdvisory[],
      next: parseNextLink(res.headers.get("link")),
    };
  } finally {
    clearTimeout(timer);
  }
}

function parseNextLink(link: string | null): string | undefined {
  if (!link) return undefined;
  for (const part of link.split(",")) {
    const match = part.match(/<([^>]+)>;\s*rel="next"/i);
    if (match?.[1]) return match[1];
  }
  return undefined;
}

export function parseGitHubAdvisories(raw: GitHubAdvisory[]): VulnerabilityIntel[] {
  const now = new Date().toISOString();
  return raw.flatMap((advisory) => {
    const ids = uniqueStrings([
      advisory.ghsa_id,
      advisory.cve_id ?? undefined,
      ...(advisory.identifiers ?? []).map((id) => id.value),
    ]).map((id) => id.toUpperCase());
    const id = advisory.cve_id?.toUpperCase() ?? advisory.ghsa_id?.toUpperCase();
    if (!id) return [];
    const vuln = advisory.vulnerabilities?.[0];
    return [{
      id,
      aliases: ids.length > 0 ? ids : [id],
      source: "github",
      sources: ["github"],
      summary: advisory.summary,
      details: advisory.description,
      package: vuln?.package?.name
        ? {
          ecosystem: vuln.package.ecosystem ?? "",
          name: vuln.package.name,
        }
        : undefined,
      affectedRanges: uniqueStrings((advisory.vulnerabilities ?? []).map((v) => v.vulnerable_version_range)),
      fixedVersions: uniqueStrings((advisory.vulnerabilities ?? []).map((v) => v.first_patched_version?.identifier)),
      severity: normalizeSeverity(advisory.severity),
      cvss: advisory.cvss
        ? { score: advisory.cvss.score, vector: advisory.cvss.vector_string, version: "3.x" }
        : undefined,
      cwes: uniqueStrings((advisory.cwes ?? []).map((cwe) => cwe.cwe_id)).map((cwe) => cwe.toUpperCase()),
      references: uniqueReferences([
        ...(advisory.html_url ? [{ url: advisory.html_url, kind: "advisory", source: "github" as const }] : []),
        ...(advisory.references ?? []).map((url) => ({ url, kind: "reference", source: "github" as const })),
      ]),
      publishedAt: advisory.published_at,
      modifiedAt: advisory.updated_at,
      fetchedAt: now,
    }];
  });
}

function githubEcosystem(ecosystem: string): string {
  const normalized = ecosystem.trim().toLowerCase();
  if (normalized === "pypi" || normalized === "python") return "pip";
  if (normalized === "cargo" || normalized === "crates.io" || normalized === "rust") return "rust";
  return normalized;
}

function githubHeaders(extra: Record<string, string> | undefined): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "0sec-intel/0.1",
    ...(extra ?? {}),
  };
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}
