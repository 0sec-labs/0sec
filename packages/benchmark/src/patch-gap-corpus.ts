/**
 * Patch-gap monitor corpus persistence — mirrors `hunt-corpus.ts` (which in
 * turn mirrors `cybergym-runner.ts`'s `resultToSample`/`appendToCorpus`):
 * the full ranked `PatchGapCandidate[]` from a run, never flattened to
 * CVE-ids-only, appended as JSONL to a committed corpus ("commit receipts to
 * git" convention, same as `results/cybergym-v1.jsonl` and
 * `results/hunt-variant-v1.jsonl`).
 */

import { existsSync, writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join, dirname, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import type { PatchGapCandidate } from "@0sec/core";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** The committed corpus path (per the "commit receipts to git" convention). Relative to the benchmark package. */
export const PATCH_GAP_CORPUS_PATH = "results/patch-gap-v1.jsonl";

/**
 * Resolve the corpus output path. Precedence (first wins): `override` → the
 * `PATCH_GAP_CORPUS_PATH` env → the package-relative default. Mirrors
 * `resolveHuntCorpusPath` / `resolveCorpusPath`.
 */
export function resolvePatchGapCorpusPath(
  override?: string,
  packageRoot: string = join(__dirname, ".."),
): string {
  const requested = override ?? process.env.PATCH_GAP_CORPUS_PATH;
  if (requested && requested.length > 0) {
    return isAbsolute(requested) ? requested : join(process.cwd(), requested);
  }
  return join(packageRoot, PATCH_GAP_CORPUS_PATH);
}

/** One corpus row: a run timestamp + the target tree scanned + the full candidate. */
export interface PatchGapSample {
  scannedAt: string;
  targetTreePath: string;
  candidate: PatchGapCandidate;
}

/** Serialize a sample to a single JSONL line. */
export function patchGapSampleToJsonl(sample: PatchGapSample): string {
  return JSON.stringify(sample);
}

/** Append a run's candidates to the committed corpus, creating it if needed. No-op on an empty candidate list (matches `appendToCorpus`). */
export function appendPatchGapCorpus(
  candidates: readonly PatchGapCandidate[],
  targetTreePath: string,
  corpusPath: string,
  scannedAt: string = new Date().toISOString(),
): void {
  if (candidates.length === 0) return;
  const dir = dirname(corpusPath);
  if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
  const lines = candidates.map((candidate) =>
    patchGapSampleToJsonl({ scannedAt, targetTreePath, candidate }),
  );
  if (existsSync(corpusPath)) {
    appendFileSync(corpusPath, lines.join("\n") + "\n");
  } else {
    writeFileSync(corpusPath, lines.join("\n") + "\n");
  }
}
