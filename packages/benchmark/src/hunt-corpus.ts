/**
 * Hunt-variant corpus persistence — mirrors `cybergym-runner.ts`'s
 * `CyberGymSample`/`resultToSample`/`appendToCorpus` (which in turn mirrors
 * `kernel-weaponization-collector.ts`): the full per-finding tuple, never
 * flattened to titles-only.
 *
 * Before this file, no hunt entry point (`hunt-run.ts`, `hunt-surface.ts`,
 * `0sec hunt`) wrote full finding bodies to disk — only `title`/`severity`
 * (or in `hunt-run.ts`'s case, only titles) survived the run. `runHuntScan`
 * now returns `HuntScanResult.records: HuntFindingRecord[]` (candidate path,
 * model, attempt, the full finding incl. `evidence.request/response/analysis`,
 * plus judge score/reason and skeptic verdict/reason when those gates ran)
 * — this module projects that into JSONL rows and appends them to the
 * committed corpus (same "commit receipts to git" convention as
 * `results/cybergym-v1.jsonl`).
 */

import { existsSync, writeFileSync, appendFileSync, mkdirSync } from "node:fs";
import { join, dirname, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import type { HuntBrief, HuntFindingRecord } from "@0sec/core";
import type { Finding } from "@0sec/shared";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** The committed corpus path (per the "commit receipts to git" convention). Relative to the benchmark package. */
export const HUNT_CORPUS_PATH = "results/hunt-variant-v1.jsonl";

/**
 * Resolve the corpus output path. Precedence (first wins): `override` → the
 * `HUNT_CORPUS_PATH` env → the package-relative default. Mirrors
 * `resolveCorpusPath` in cybergym-runner.ts.
 */
export function resolveHuntCorpusPath(override?: string, packageRoot: string = join(__dirname, "..")): string {
  const requested = override ?? process.env.HUNT_CORPUS_PATH;
  if (requested && requested.length > 0) {
    return isAbsolute(requested) ? requested : join(process.cwd(), requested);
  }
  return join(packageRoot, HUNT_CORPUS_PATH);
}

/** One corpus row: the full per-finding tuple. Never flattened to a title. */
export interface HuntSample {
  id: string;
  candidatePath: string;
  bugClass?: string;
  pattern?: string;
  fixReference?: string;
  model: string;
  attempt: number;
  judgeScore?: number;
  judgeReason?: string;
  skepticConfirmed?: boolean;
  skepticReason?: string;
  duplicate: boolean;
  finding: Finding;
}

/** Project one raw finding record (+ the run's brief, if any) into a stable, JSONL-serializable corpus row. */
export function resultToHuntSample(record: HuntFindingRecord, brief?: HuntBrief): HuntSample {
  return {
    id: `${record.candidatePath}:${record.finding.id}`,
    candidatePath: record.candidatePath,
    ...(brief?.bugClass ? { bugClass: brief.bugClass } : {}),
    ...(brief?.pattern ? { pattern: brief.pattern } : {}),
    ...(brief?.fixReference ? { fixReference: brief.fixReference } : {}),
    model: record.model ?? "default",
    attempt: record.attempt,
    ...(record.judgeScore !== undefined ? { judgeScore: record.judgeScore } : {}),
    ...(record.judgeReason !== undefined ? { judgeReason: record.judgeReason } : {}),
    ...(record.skepticConfirmed !== undefined ? { skepticConfirmed: record.skepticConfirmed } : {}),
    ...(record.skepticReason !== undefined ? { skepticReason: record.skepticReason } : {}),
    duplicate: record.duplicate,
    finding: record.finding,
  };
}

/** Serialize a sample to a single JSONL line. */
export function sampleToJsonl(sample: HuntSample): string {
  return JSON.stringify(sample);
}

/** Append finding records to the committed corpus, creating it if needed. */
export function appendToCorpus(records: readonly HuntFindingRecord[], corpusPath: string, brief?: HuntBrief): void {
  const dir = dirname(corpusPath);
  if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
  const lines = records.map((r) => sampleToJsonl(resultToHuntSample(r, brief)));
  if (lines.length === 0) return;
  if (existsSync(corpusPath)) {
    appendFileSync(corpusPath, lines.join("\n") + "\n");
  } else {
    writeFileSync(corpusPath, lines.join("\n") + "\n");
  }
}
