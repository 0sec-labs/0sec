import { cachedJson, fetchJson, IntelCache } from "./cache.js";
import {
  normalizeCveId,
  normalizeSeverity,
  uniqueReferences,
  uniqueStrings,
} from "./normalize.js";
import { normalizeRepositoryHint } from "./target-history.js";
import type { CveLookupInput, FetchOptions, SimilarSearchInput, TargetHistorySearchInput, VulnerabilityIntel } from "./types.js";

interface NvdDescription {
  lang?: string;
  value?: string;
}

interface NvdMetric {
  cvssData?: {
    baseScore?: number;
    baseSeverity?: string;
    vectorString?: string;
    version?: string;
  };
}

interface NvdWeakness {
  description?: NvdDescription[];
}

interface NvdReference {
  url?: string;
  tags?: string[];
}

interface NvdCve {
  id?: string;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  descriptions?: NvdDescription[];
  metrics?: {
    cvssMetricV40?: NvdMetric[];
    cvssMetricV31?: NvdMetric[];
    cvssMetricV30?: NvdMetric[];
    cvssMetricV2?: NvdMetric[];
  };
  weaknesses?: NvdWeakness[];
  references?: { referenceData?: NvdReference[] } | NvdReference[];
  cisaExploitAdd?: string;
  cisaActionDue?: string;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;
}

interface NvdResponse {
  vulnerabilities?: Array<{ cve?: NvdCve }>;
}

export async function lookupNvdCve(
  input: CveLookupInput,
  opts: FetchOptions = {},
): Promise<VulnerabilityIntel | null> {
  const cveId = normalizeCveId(input.cveId);
  const cache = new IntelCache(input.cacheDir);
  const raw = await cachedJson<NvdResponse>(
    cache,
    "nvd-cve",
    cveId,
    async () => await fetchJson(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`,
      { headers: nvdHeaders(opts.headers) },
      opts,
    ) as NvdResponse,
    { offline: input.offline, ttlMs: input.ttlMs },
  );
  return parseNvdResponse(raw)[0] ?? null;
}

export async function searchNvdSimilar(
  input: SimilarSearchInput,
  opts: FetchOptions = {},
): Promise<VulnerabilityIntel[]> {
  const terms = uniqueStrings([input.cwe, ...(input.keywords ?? [])]);
  if (terms.length === 0) return [];
  const limit = Math.min(Math.max(input.limit ?? 10, 1), 50);
  const key = JSON.stringify({ terms, limit });
  const cache = new IntelCache(input.cacheDir);
  const query = new URLSearchParams({
    keywordSearch: terms.join(" "),
    resultsPerPage: String(limit),
  });
  const raw = await cachedJson<NvdResponse>(
    cache,
    "nvd-search",
    key,
    async () => await fetchJson(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?${query}`,
      { headers: nvdHeaders(opts.headers) },
      opts,
    ) as NvdResponse,
    { offline: input.offline, ttlMs: input.ttlMs },
  );
  return parseNvdResponse(raw);
}

export async function searchNvdTargetHistory(
  input: TargetHistorySearchInput,
  opts: FetchOptions = {},
): Promise<VulnerabilityIntel[]> {
  const terms = targetHistorySearchTerms(input);
  if (terms.length === 0) return [];
  const limit = Math.min(Math.max(input.limit ?? 20, 1), 50);
  const cache = new IntelCache(input.cacheDir);
  const results = await Promise.all(
    terms.slice(0, 8).map(async (term) => {
      const key = JSON.stringify({ term, limit });
      const query = new URLSearchParams({
        keywordSearch: term,
        resultsPerPage: String(limit),
      });
      const raw = await cachedJson<NvdResponse>(
        cache,
        "nvd-target-history",
        key,
        async () => await fetchJson(
          `https://services.nvd.nist.gov/rest/json/cves/2.0?${query}`,
          { headers: nvdHeaders(opts.headers) },
          opts,
        ) as NvdResponse,
        { offline: input.offline, ttlMs: input.ttlMs },
      );
      return parseNvdResponse(raw);
    }),
  );
  return results.flat();
}

function targetHistorySearchTerms(input: TargetHistorySearchInput): string[] {
  const repo = normalizeRepositoryHint(input.repository ?? input.target);
  const repoParts = repo?.split("/") ?? [];
  return uniqueStrings([
    input.product,
    input.packageName,
    input.vendor && input.product ? `${input.vendor} ${input.product}` : undefined,
    repo,
    repoParts[1],
    ...(input.keywords ?? []),
  ]).filter((term) => term.length >= 3);
}

export function parseNvdResponse(raw: NvdResponse): VulnerabilityIntel[] {
  const now = new Date().toISOString();
  return (raw.vulnerabilities ?? []).flatMap((item) => {
    const cve = item.cve;
    if (!cve?.id) return [];
    const metric = pickMetric(cve);
    const cwes = uniqueStrings(
      (cve.weaknesses ?? []).flatMap((w) =>
        (w.description ?? []).map((d) => d.value).filter((value): value is string => /^CWE-\d+$/i.test(value ?? "")),
      ),
    ).map((cwe) => cwe.toUpperCase());
    const references = Array.isArray(cve.references)
      ? cve.references as NvdReference[]
      : cve.references?.referenceData ?? [];

    const kev = cve.cisaExploitAdd
      ? {
        knownExploited: true,
        dateAdded: cve.cisaExploitAdd,
        dueDate: cve.cisaActionDue,
        requiredAction: cve.cisaRequiredAction,
        vulnerabilityName: cve.cisaVulnerabilityName,
      }
      : undefined;

    return [{
      id: cve.id.toUpperCase(),
      aliases: [cve.id.toUpperCase()],
      source: "nvd",
      sources: ["nvd"],
      summary: cve.descriptions?.find((d) => d.lang === "en")?.value,
      affectedRanges: [],
      fixedVersions: [],
      severity: normalizeSeverity(metric?.cvssData?.baseSeverity),
      cvss: metric?.cvssData
        ? {
          score: metric.cvssData.baseScore,
          vector: metric.cvssData.vectorString,
          version: metric.cvssData.version,
        }
        : undefined,
      cwes,
      references: uniqueReferences(
        references
          .filter((ref) => typeof ref.url === "string")
          .map((ref) => ({ url: ref.url!, kind: ref.tags?.join(","), source: "nvd" })),
      ),
      kev,
      publishedAt: cve.published,
      modifiedAt: cve.lastModified,
      fetchedAt: now,
    }];
  });
}

function pickMetric(cve: NvdCve): NvdMetric | undefined {
  return cve.metrics?.cvssMetricV40?.[0] ??
    cve.metrics?.cvssMetricV31?.[0] ??
    cve.metrics?.cvssMetricV30?.[0] ??
    cve.metrics?.cvssMetricV2?.[0];
}

function nvdHeaders(extra: Record<string, string> | undefined): Record<string, string> {
  const headers: Record<string, string> = {
    "User-Agent": "pwnkit-intel/0.1",
    ...(extra ?? {}),
  };
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  return headers;
}
