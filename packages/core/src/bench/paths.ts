/**
 * Resolvers for the bench manifest files shipped inside @0sec/core
 * (0sec#656). The JSON corpora live next to this module in both src (tests)
 * and dist (runtime) — the core build copies `src/bench/*.json` into
 * `dist/bench/`, so `import.meta.url` resolves correctly in either context.
 */

import { fileURLToPath } from "node:url";

/** Absolute path to the frozen labeled corpus v1 (0sec#657). */
export function corpusV1Path(): string {
  return fileURLToPath(new URL("./corpus-v1.json", import.meta.url));
}

/** Absolute path to the references-only example manifest (0sec#556). */
export function exampleManifestPath(): string {
  return fileURLToPath(new URL("./example-manifest.json", import.meta.url));
}
