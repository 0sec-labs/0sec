import { cachedJson, fetchJson, IntelCache } from "./cache.js";
import {
  normalizeSeverity,
  parseCvssVectorSeverity,
  primaryId,
  uniqueReferences,
  uniqueStrings,
} from "./normalize.js";
import type { AdvisorySearchInput, FetchOptions, VulnerabilityIntel } from "./types.js";

interface OsvVulnerability {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: { severity?: string };
  references?: Array<{ type?: string; url?: string }>;
  affected?: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: Array<{
      type?: string;
      events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
    versions?: string[];
  }>;
  published?: string;
  modified?: string;
}

interface OsvQueryResponse {
  vulns?: OsvVulnerability[];
}

export function toOsvEcosystem(ecosystem: string): string | null {
  const normalized = ecosystem.trim().toLowerCase();
  if (normalized === "npm") return "npm";
  if (normalized === "pypi" || normalized === "python") return "PyPI";
  if (normalized === "cargo" || normalized === "crates.io" || normalized === "rust") return "crates.io";
  if (normalized === "go" || normalized === "golang") return "Go";
  if (normalized === "maven") return "Maven";
  return null;
}

export async function queryOsvAdvisories(
  input: AdvisorySearchInput,
  opts: FetchOptions = {},
): Promise<VulnerabilityIntel[]> {
  const osvEcosystem = toOsvEcosystem(input.ecosystem);
  if (!osvEcosystem) return [];
  const cache = new IntelCache(input.cacheDir);
  const key = JSON.stringify({
    ecosystem: osvEcosystem,
    packageName: input.packageName,
    version: input.version ?? null,
  });
  const raw = await cachedJson<OsvQueryResponse>(
    cache,
    "osv-query",
    key,
    async () => {
      const body: Record<string, unknown> = {
        package: { ecosystem: osvEcosystem, name: input.packageName },
      };
      if (input.version) body.version = input.version;
      return await fetchJson(
        "https://api.osv.dev/v1/query",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        },
        opts,
      ) as OsvQueryResponse;
    },
    { offline: input.offline, ttlMs: input.ttlMs },
  );
  return parseOsvResponse(input.packageName, raw);
}

export function parseOsvResponse(packageName: string, raw: OsvQueryResponse): VulnerabilityIntel[] {
  const now = new Date().toISOString();
  return (raw.vulns ?? []).map((vuln) => {
    const aliases = uniqueStrings([vuln.id, ...(vuln.aliases ?? [])]).map((id) => id.toUpperCase());
    const id = primaryId(aliases, vuln.id ?? "OSV advisory");
    const packageInfo = vuln.affected?.find((a) => a.package?.name)?.package;
    const affectedRanges: string[] = [];
    const fixedVersions: string[] = [];

    for (const affected of vuln.affected ?? []) {
      for (const range of affected.ranges ?? []) {
        const parts = (range.events ?? []).flatMap((event) => {
          const out: string[] = [];
          if (event.introduced) out.push(`introduced:${event.introduced}`);
          if (event.fixed) {
            out.push(`fixed:${event.fixed}`);
            fixedVersions.push(event.fixed);
          }
          if (event.last_affected) out.push(`last_affected:${event.last_affected}`);
          return out;
        });
        if (parts.length > 0) affectedRanges.push(`${range.type ?? "range"}:${parts.join(",")}`);
      }
    }

    const cvss = vuln.severity?.find((s) => typeof s.score === "string")?.score;
    const severity =
      parseCvssVectorSeverity(cvss) ??
      normalizeSeverity(vuln.database_specific?.severity);

    return {
      id,
      aliases: aliases.length > 0 ? aliases : [id],
      source: "osv",
      sources: ["osv"],
      summary: vuln.summary,
      details: vuln.details,
      package: {
        ecosystem: packageInfo?.ecosystem ?? "",
        name: packageInfo?.name ?? packageName,
      },
      affectedRanges: uniqueStrings(affectedRanges),
      fixedVersions: uniqueStrings(fixedVersions),
      severity,
      cvss: cvss ? { vector: cvss } : undefined,
      cwes: [],
      references: uniqueReferences(
        (vuln.references ?? [])
          .filter((ref) => typeof ref.url === "string")
          .map((ref) => ({ url: ref.url!, kind: ref.type, source: "osv" })),
      ),
      publishedAt: vuln.published,
      modifiedAt: vuln.modified,
      fetchedAt: now,
    };
  });
}
