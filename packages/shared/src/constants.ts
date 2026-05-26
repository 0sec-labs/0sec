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

export const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};
