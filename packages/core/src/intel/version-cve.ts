import { searchAdvisories } from "./index.js";
import type { FetchOptions, IntelSeverity, IntelSource, VulnerabilityIntel } from "./types.js";

/**
 * A single known vulnerability for a detected framework/library version,
 * flattened from the richer {@link VulnerabilityIntel} shape into the minimal
 * fields a stack-fingerprinting consumer needs to emit a finding.
 */
export interface VersionCve {
  /** Primary advisory id (prefers a CVE id, else GHSA/OSV id). */
  id: string;
  /** Highest-confidence severity available, omitted when only "info". */
  severity?: IntelSeverity;
  summary: string;
  /** Human-readable affected version expression(s), e.g. "SEMVER:introduced:0,fixed:1.2.3". */
  affectedRange?: string;
  /** First patched version, when an advisory publishes one. */
  fixedVersion?: string;
  /** Advisory provenance (osv / github / nvd / cisa-kev). */
  source: IntelSource;
}

export interface VersionCveLookupInput {
  /** Package ecosystem, e.g. "npm", "pypi", "go", "cargo", "maven". */
  ecosystem: string;
  /** Package / library name as published in the ecosystem registry. */
  name: string;
  /** Detected version string, e.g. "15.0.7". */
  version: string;
  cacheDir?: string;
  offline?: boolean;
  ttlMs?: number;
}

/**
 * Generic version → CVE mapper for non-WordPress stacks.
 *
 * Given a framework/library detected during stack fingerprinting plus its
 * version, returns the known advisories that affect it. This is a thin adapter
 * over {@link searchAdvisories}, which already queries OSV (keyless, npm/PyPI/
 * Go/crates/Maven) and GitHub Advisories, enriches via NVD + CISA KEV, and
 * dedupes/merges into {@link VulnerabilityIntel}. We pass `version` through so
 * OSV constrains results to advisories that actually affect this build.
 *
 * Pass a mock `fetchImpl` via {@link FetchOptions} to test without network.
 */
export async function lookupVersionCves(
  input: VersionCveLookupInput,
  opts: FetchOptions = {},
): Promise<VersionCve[]> {
  const { advisories } = await searchAdvisories(
    {
      ecosystem: input.ecosystem,
      packageName: input.name,
      version: input.version,
      cacheDir: input.cacheDir,
      offline: input.offline,
      ttlMs: input.ttlMs,
    },
    opts,
  );

  const byId = new Map<string, VersionCve>();
  for (const advisory of advisories) {
    if (byId.has(advisory.id)) continue;
    byId.set(advisory.id, toVersionCve(advisory));
  }
  return [...byId.values()];
}

function toVersionCve(advisory: VulnerabilityIntel): VersionCve {
  return {
    id: advisory.id,
    severity: advisory.severity === "info" ? undefined : advisory.severity,
    summary: advisory.summary ?? advisory.details ?? advisory.id,
    affectedRange: advisory.affectedRanges[0],
    fixedVersion: advisory.fixedVersions[0],
    source: advisory.source,
  };
}
