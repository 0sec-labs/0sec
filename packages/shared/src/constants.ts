// VERSION resolves to the root package.json "version" field via two paths:
//
//   1. Bundled mode (esbuild via scripts/bundle-cli.mjs): the bundler
//      injects __PWNKIT_VERSION__ as a global define at build time, so
//      VERSION ends up as a string literal baked directly into the
//      published pwnkit.js bundle. Zero runtime fs cost.
//   2. Source / test mode (running tsx, vitest, or any unbundled flow):
//      __PWNKIT_VERSION__ is undefined, so we fall back to a one-time
//      synchronous read of the root package.json relative to this file.
//      The relative path (../../../package.json) is stable across both
//      packages/shared/src/ and packages/shared/dist/.
//
// Either way, the root package.json is the single source of truth for
// the version string. Bumping that one file is sufficient. The previous
// "lockstep + regression test" approach (v0.7.1 → 0.7.2) is gone — drift
// is now impossible at the source level, not just caught in tests.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

declare const __PWNKIT_VERSION__: string;

function loadVersion(): string {
  // Bundled path: esbuild inlines this branch into a string literal.
  if (typeof __PWNKIT_VERSION__ !== "undefined") {
    return __PWNKIT_VERSION__;
  }
  // Source / test path: read root package.json once at module load.
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    // packages/shared/{src,dist}/constants.{ts,js} -> repo root is 3 up
    const pkgPath = join(here, "..", "..", "..", "package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    return typeof pkg.version === "string" ? pkg.version : "0.0.0-dev";
  } catch {
    return "0.0.0-dev";
  }
}

export const VERSION = loadVersion();

export const DEFAULT_MODEL = "claude-sonnet-4-20250514";
export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_MAX_CONCURRENCY = 5;

export const DEPTH_CONFIG = {
  quick: { maxTemplates: 5, maxPayloadsPerTemplate: 1, multiTurn: false },
  default: { maxTemplates: 20, maxPayloadsPerTemplate: 3, multiTurn: false },
  deep: { maxTemplates: Infinity, maxPayloadsPerTemplate: Infinity, multiTurn: true },
} as const;

// ── Severity rank + display order (#582; reconciled #629) ────────
//
// SEVERITY_RANK is the single source of truth: an ASCENDING rank where
// `critical` is highest (4). It gates which findings advance into triage /
// disclosure — compare via `meetsSeverityFloor`, never hard-coded integers.
//
// SEVERITY_ORDER is the DISPLAY sort (critical first, so `critical` = 0). It
// is the exact inverse of SEVERITY_RANK and is DERIVED from it here so the
// two can never drift — the old hand-maintained inverted literal living
// beside the rank was the #629 footgun. To sort critical-first: sort
// ascending by SEVERITY_ORDER, or descending by `severityRank`.

export const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const MAX_SEVERITY_RANK = Math.max(...Object.values(SEVERITY_RANK));

export const SEVERITY_ORDER: Record<string, number> = Object.fromEntries(
  Object.keys(SEVERITY_RANK)
    // critical-first key order preserved for any consumer that iterates keys
    .sort((a, b) => SEVERITY_RANK[b]! - SEVERITY_RANK[a]!)
    .map((sev) => [sev, MAX_SEVERITY_RANK - SEVERITY_RANK[sev]!]),
);

/**
 * Default severity floor. Anything below `medium` (i.e. `low` / `info`) is
 * recorded but NOT routed into triage / disclosure (#582, operator decision).
 */
export const DEFAULT_SEVERITY_FLOOR = "medium";

/**
 * Numeric rank for a severity string, tolerant of casing and the
 * `informational` alias. Unknown severities rank below `info` (-1) so they
 * can never accidentally clear a floor.
 */
export function severityRank(severity: string): number {
  const lower = severity.trim().toLowerCase();
  const key = lower === "informational" ? "info" : lower;
  return SEVERITY_RANK[key] ?? -1;
}

/**
 * The single predicate that gates below-floor findings out of triage /
 * disclosure (#582). True when `severity` is at or above `floor`. Unknown
 * severities never clear the floor.
 */
export function meetsSeverityFloor(
  severity: string,
  floor: string = DEFAULT_SEVERITY_FLOOR,
): boolean {
  const floorRank = severityRank(floor);
  // Unknown floor → fall back to the default floor's rank.
  const effectiveFloor = floorRank === -1 ? severityRank(DEFAULT_SEVERITY_FLOOR) : floorRank;
  return severityRank(severity) >= effectiveFloor;
}
