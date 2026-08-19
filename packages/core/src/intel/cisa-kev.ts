import { cachedJson, fetchJson, IntelCache } from "./cache.js";
import { normalizeCveId } from "./normalize.js";
import type { CveLookupInput, FetchOptions, IntelKev } from "./types.js";

const DEFAULT_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevEntry {
  cveID?: string;
  vendorProject?: string;
  product?: string;
  vulnerabilityName?: string;
  dateAdded?: string;
  shortDescription?: string;
  requiredAction?: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
}

interface KevCatalog {
  vulnerabilities?: KevEntry[];
}

export async function lookupKev(
  input: CveLookupInput,
  opts: FetchOptions = {},
): Promise<IntelKev | null> {
  const cveId = normalizeCveId(input.cveId);
  const catalog = await fetchKevCatalog(input, opts);
  const entry = (catalog.vulnerabilities ?? []).find((item) => item.cveID?.toUpperCase() === cveId);
  if (!entry) return null;
  return {
    knownExploited: true,
    dateAdded: entry.dateAdded,
    dueDate: entry.dueDate,
    requiredAction: entry.requiredAction,
    ransomwareUse: entry.knownRansomwareCampaignUse,
    vulnerabilityName: entry.vulnerabilityName,
  };
}

async function fetchKevCatalog(
  input: Pick<CveLookupInput, "cacheDir" | "offline" | "ttlMs">,
  opts: FetchOptions,
): Promise<KevCatalog> {
  const cache = new IntelCache(input.cacheDir);
  const url = process.env["0SEC_CISA_KEV_URL"] ?? DEFAULT_KEV_URL;
  return await cachedJson<KevCatalog>(
    cache,
    "cisa-kev",
    url,
    async () => await fetchJson(url, { headers: { "User-Agent": "0sec-intel/0.1" } }, opts) as KevCatalog,
    { offline: input.offline, ttlMs: input.ttlMs },
  );
}
