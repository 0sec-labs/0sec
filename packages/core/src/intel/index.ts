import { lookupKev } from "./cisa-kev.js";
import { queryGitHubAdvisories } from "./github.js";
import { mergeIntel, normalizeCveId, toGraphSnapshot, uniqueStrings } from "./normalize.js";
import { lookupNvdCve, searchNvdSimilar, searchNvdTargetHistory } from "./nvd.js";
import { queryOsvAdvisories } from "./osv.js";
import { buildIntelDossierFromSearch } from "./dossier.js";
import { buildTargetHistoryResult, resolveTargetHistoryInput } from "./target-history.js";
import type {
  AdvisorySearchInput,
  CveLookupInput,
  FetchOptions,
  IntelDossier,
  IntelDossierInput,
  IntelGraphSnapshot,
  IntelTargetHistory,
  SimilarSearchInput,
  TargetHistorySearchInput,
  VulnerabilityIntel,
} from "./types.js";

export type {
  AdvisorySearchInput,
  CveLookupInput,
  FetchOptions,
  IntelCvss,
  IntelDossier,
  IntelDossierInput,
  IntelDossierSummary,
  IntelGraphEdge,
  IntelGraphNode,
  IntelGraphSnapshot,
  IntelInvestigationStep,
  IntelKev,
  IntelPackage,
  IntelPriorVulnerabilityAuditEdge,
  IntelPriorVulnerabilityAuditGraph,
  IntelPriorVulnerabilityAuditNode,
  IntelPriorVulnerabilityPlaybook,
  IntelReference,
  IntelSeverity,
  IntelSource,
  IntelTargetHistory,
  IntelTargetHistorySummary,
  IntelVariantLead,
  SimilarSearchInput,
  TargetHistorySearchInput,
  VulnerabilityIntel,
} from "./types.js";

export { IntelCache, defaultIntelCacheDir } from "./cache.js";
export { queryOsvAdvisories, parseOsvResponse, toOsvEcosystem } from "./osv.js";
export { lookupNvdCve, parseNvdResponse, searchNvdSimilar, searchNvdTargetHistory } from "./nvd.js";
export { lookupKev } from "./cisa-kev.js";
export { queryGitHubAdvisories, parseGitHubAdvisories } from "./github.js";
export { mergeIntel, toGraphSnapshot } from "./normalize.js";
export { buildPriorVulnerabilityAuditGraph } from "./audit-graph.js";
export { formatTargetHistoryForPrompt } from "./prompt.js";
export { buildTargetHistoryResult, inferTargetHistoryInputFromRepo, normalizeRepositoryHint, resolveTargetHistoryInput, targetHistoryHints } from "./target-history.js";

export async function buildIntelDossier(
  input: IntelDossierInput,
  opts: FetchOptions = {},
): Promise<IntelDossier> {
  return await buildIntelDossierFromSearch(input, searchAdvisories, searchSimilar, opts);
}

export async function searchAdvisories(
  input: AdvisorySearchInput,
  opts: FetchOptions = {},
): Promise<{ advisories: VulnerabilityIntel[]; graph: IntelGraphSnapshot }> {
  const sources = ["queryOsvAdvisories", "queryGitHubAdvisories"] as const;
  const results = await Promise.allSettled([
    queryOsvAdvisories(input, opts),
    queryGitHubAdvisories(input, opts),
  ]);
  warnRejectedSources(sources, results, { ecosystem: input.ecosystem, packageName: input.packageName });
  const advisories = mergeIntel(
    results.flatMap((result) => result.status === "fulfilled" ? result.value : []),
  );

  if (input.enrich !== false) {
    const enriched = await enrichCveAliases(advisories, input, opts);
    const merged = mergeIntel([...advisories, ...enriched]);
    return { advisories: merged, graph: toGraphSnapshot(merged) };
  }

  return { advisories, graph: toGraphSnapshot(advisories) };
}

export async function lookupCve(
  input: CveLookupInput,
  opts: FetchOptions = {},
): Promise<VulnerabilityIntel | null> {
  const cveId = normalizeCveId(input.cveId);
  const [nvdResult, kevResult] = await Promise.allSettled([
    lookupNvdCve({ ...input, cveId }, opts),
    lookupKev({ ...input, cveId }, opts),
  ]);
  warnRejectedSources(["lookupNvdCve", "lookupKev"], [nvdResult, kevResult], { cveId });
  const nvd = nvdResult.status === "fulfilled" ? nvdResult.value : null;
  const kev = kevResult.status === "fulfilled" ? kevResult.value : null;
  if (!nvd && !kev) return null;
  if (!nvd) {
    const now = new Date().toISOString();
    return {
      id: cveId,
      aliases: [cveId],
      source: "cisa-kev",
      sources: ["cisa-kev"],
      affectedRanges: [],
      fixedVersions: [],
      severity: "info",
      cwes: [],
      references: [],
      kev: kev ?? undefined,
      fetchedAt: now,
    };
  }
  return {
    ...nvd,
    sources: kev ? mergeSources(nvd.sources, ["cisa-kev"]) : nvd.sources,
    kev: kev ?? nvd.kev,
  };
}

export async function searchSimilar(
  input: SimilarSearchInput,
  opts: FetchOptions = {},
): Promise<{ advisories: VulnerabilityIntel[]; graph: IntelGraphSnapshot }> {
  const advisories = mergeIntel(await searchNvdSimilar(input, opts));
  return { advisories, graph: toGraphSnapshot(advisories) };
}

export async function searchTargetHistory(
  input: TargetHistorySearchInput,
  opts: FetchOptions = {},
): Promise<IntelTargetHistory> {
  const resolvedInput = resolveTargetHistoryInput(input);
  const packageLookup = resolvedInput.ecosystem && resolvedInput.packageName
    ? searchAdvisories({
      ecosystem: resolvedInput.ecosystem,
      packageName: resolvedInput.packageName,
      enrich: false,
      cacheDir: resolvedInput.cacheDir,
      offline: resolvedInput.offline,
      ttlMs: resolvedInput.ttlMs,
    }, opts)
    : Promise.resolve({ advisories: [], graph: { nodes: [], edges: [] } });
  const results = await Promise.allSettled([
    packageLookup,
    searchNvdTargetHistory(resolvedInput, opts),
  ]);
  warnRejectedSources(["searchAdvisories", "searchNvdTargetHistory"], results, {
    target: resolvedInput.target,
    repository: resolvedInput.repository,
    packageName: resolvedInput.packageName,
    product: resolvedInput.product,
  });
  const packageResult = results[0]?.status === "fulfilled" ? results[0].value.advisories : [];
  const nvdAdvisories = results[1]?.status === "fulfilled" ? results[1].value : [];
  return buildTargetHistoryResult(resolvedInput, [...packageResult, ...nvdAdvisories]);
}

async function enrichCveAliases(
  advisories: VulnerabilityIntel[],
  input: Pick<AdvisorySearchInput, "cacheDir" | "offline" | "ttlMs">,
  opts: FetchOptions,
): Promise<VulnerabilityIntel[]> {
  const cves = uniqueStrings(
    advisories.flatMap((advisory) => [advisory.id, ...advisory.aliases])
      .filter((id) => /^CVE-\d{4}-\d{4,}$/i.test(id)),
  );
  const results = await Promise.allSettled(
    cves.slice(0, 10).map((cveId) =>
      lookupCve({ cveId, cacheDir: input.cacheDir, offline: input.offline, ttlMs: input.ttlMs }, opts),
    ),
  );
  return results.flatMap((result) =>
    result.status === "fulfilled" && result.value ? [result.value] : [],
  );
}

function mergeSources(a: VulnerabilityIntel["sources"], b: VulnerabilityIntel["sources"]): VulnerabilityIntel["sources"] {
  return uniqueStrings([...a, ...b]) as VulnerabilityIntel["sources"];
}

function warnRejectedSources(
  sources: readonly string[],
  results: readonly PromiseSettledResult<unknown>[],
  context: Record<string, unknown>,
): void {
  for (const [idx, result] of results.entries()) {
    if (result.status !== "rejected") continue;
    const reason = result.reason instanceof Error ? result.reason.message : String(result.reason);
    console.warn(`[intel] ${sources[idx] ?? "source"} failed`, { reason, context });
  }
}
