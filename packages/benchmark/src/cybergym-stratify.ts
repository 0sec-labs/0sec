#!/usr/bin/env node
/**
 * CyberGym stratified-subset generator (issue #1029, epic #1026).
 *
 * Emits a PRE-REGISTERED, stratified task-ID subset for a fair CyberGym pass@1
 * run. Pre-registration is the integrity contract: commit this subset file to
 * git BEFORE the run, then commit the per-task receipt (cybergym-runner's
 * `--corpus-path` output, e.g. results/cybergym-fair-v1.jsonl) AFTER the run.
 * Editing the subset list after the run breaks the claim-gate (see epic #1026).
 *
 * Why this exists: the existing `cybergym-v1.jsonl` / `cybergym-agent-v1.jsonl`
 * receipts are non-random first-pulled subsets (n=6 / n=18), so the ~68%/89%
 * numbers are real data points, NOT defensible benchmark-wide pass@1. Issue
 * #1029 calls for a pre-registered stratified 150–200-task subset (≈10–13% of
 * the 1,507-task corpus), stratified across projects + crash types, with the
 * task-ID list + RNG seed committed before any model call.
 *
 * The full mask_map / HF corpus lives on the `bench` host, NOT in-repo — so
 * this generator takes the corpus as an INPUT path and never hardcodes ids.
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  Usage:
 *   tsx src/cybergym-stratify.ts --corpus /path/to/mask_map.json
 *   tsx src/cybergym-stratify.ts --corpus cybergym_corpus.jsonl \
 *       --target 175 --seed 0xc6f1a5ed --stratify-by project,crashType \
 *       --out results/cybergym-fair-v1.subset.txt
 *
 *  Corpus shapes accepted (auto-detected, tolerant):
 *   1. mask_map.json   {"arvo:10400": "7fa395d7dac0", ...}   (bare id universe)
 *   2. JSONL           one {taskId, project?, crashType?} per line
 *   3. JSON array      [{taskId, ...}, ...]
 *
 *  When the corpus has no project/crashType metadata (case 1, or a JSONL
 *  without those fields), the generator falls back to uniform deterministic
 *  sampling and prints a warning to stderr — still pre-registered + seeded,
 *  just not stratified. For a true stratified run, feed a corpus with project
 *  + crash-type metadata (dumpable from the HF dataset on bench).
 * ─────────────────────────────────────────────────────────────────────────
 */

import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
} from "node:fs";
import { join, dirname, isAbsolute } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Canonical pre-registration seed. Arbitrary but FIXED so the same corpus → same subset. */
export const DEFAULT_FAIR_SEED = 0xc6f1a5ed;

/** Default subset size: the midpoint of the 150–200 range issue #1029 pins. */
export const DEFAULT_FAIR_TARGET = 175;

/** Default strata, per #1029 ("stratify across projects + the 28 crash types"). */
export const DEFAULT_STRATIFY_BY = ["project", "crashType"];

/** Default output (package-relative so `pnpm cybergym:stratify` works from anywhere). */
export const DEFAULT_OUT_PATH = "results/cybergym-fair-v1.subset.txt";

// ── Types ───────────────────────────────────────────────────────────────────

/** A corpus task record after tolerant parsing. */
export interface CorpusTask {
  taskId: string;
  /** Raw stratum fields, whatever the corpus exposed (absent → undefined). */
  fields: Record<string, string | undefined>;
}

export interface StratifyOptions {
  target: number;
  seed: number;
  /** Field names to stratify by, in priority order (e.g. ["project","crashType"]). */
  stratifyBy: string[];
}

export interface StratumBucket {
  key: string;
  size: number;
  allocated: number;
  sampled: number;
  taskIds: string[];
}

export interface StratifyResult {
  /** Selected task IDs, sorted for a stable, diffable file. */
  subset: string[];
  buckets: StratumBucket[];
  total: number;
  /** True iff every requested stratum field was present for at least one task. */
  stratifiedFully: boolean;
  /** The stratum fields that were universally absent in the corpus. */
  missingFields: string[];
}

// ── Deterministic PRNG + sampling (no deps, fully reproducible) ──────────────

/**
 * mulberry32: a tiny, fast, deterministic 32-bit PRNG. Same seed → same stream,
 * which is the whole pre-registration contract. Zero dependencies.
 */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Deterministically pick `k` items from `items` using `rand`. Sorts the input
 * first so the result depends ONLY on (seed, k), not on input order. Returns a
 * new array; does not mutate the input. If k >= items.length, returns all.
 */
export function deterministicSample<T>(
  items: readonly T[],
  k: number,
  rand: () => number,
): T[] {
  const ordered = [...items].sort(); // lexical, for input-order independence
  if (k >= ordered.length) return ordered;
  // Fisher–Yates with the seeded PRNG, then take the first k.
  for (let i = ordered.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [ordered[i], ordered[j]] = [ordered[j], ordered[i]];
  }
  return ordered.slice(0, k);
}

/**
 * Largest-remainder proportional allocation: distribute `target` seats across
 * buckets proportional to their sizes, flooring each then awarding leftover
 * seats to the largest fractional remainders. Guarantees alloc[i] <= size[i].
 * If total <= target, every bucket gets its full size (take-all).
 */
export function allocateProportional(
  bucketSizes: readonly number[],
  target: number,
): number[] {
  const total = bucketSizes.reduce((s, n) => s + n, 0);
  if (total <= target) return [...bucketSizes];
  if (target <= 0) return bucketSizes.map(() => 0);

  const floors = bucketSizes.map((n) => Math.floor((n * target) / total));
  let remaining = target - floors.reduce((s, n) => s + n, 0);
  // Rank buckets by fractional remainder descending; break ties by larger size.
  const order = bucketSizes
    .map((n, i) => ({
      i,
      rem: (n * target) / total - Math.floor((n * target) / total),
      size: n,
    }))
    .sort((a, b) => b.rem - a.rem || b.size - a.size);
  const alloc = [...floors];
  for (const { i } of order) {
    if (remaining <= 0) break;
    if (alloc[i] < bucketSizes[i]) {
      alloc[i] += 1;
      remaining -= 1;
    }
  }
  return alloc;
}

// ── Stratify ────────────────────────────────────────────────────────────────

/**
 * Build a stratified subset from parsed corpus tasks. Pure + deterministic for
 * a given (tasks, options) — the seed decides membership. Tasks missing a
 * stratum field go into that field's `"unknown"` bucket so nothing is silently
 * dropped (the missing-fields are surfaced in the result for the caller to log).
 */
export function stratify(
  tasks: readonly CorpusTask[],
  opts: StratifyOptions,
): StratifyResult {
  const total = tasks.length;
  const target = Math.max(0, Math.min(opts.target, total));

  // Detect which stratum fields are entirely absent (so the caller can warn).
  const presentFields = new Set<string>();
  for (const t of tasks) {
    for (const [k, v] of Object.entries(t.fields)) {
      if (v && v.length > 0) presentFields.add(k);
    }
  }
  const missingFields = opts.stratifyBy.filter((f) => !presentFields.has(f));
  const stratifiedFully = missingFields.length === 0;

  // Bucket key = the tuple of stratum-field values (missing value → "unknown").
  const buckets = new Map<string, string[]>();
  for (const t of tasks) {
    const parts = opts.stratifyBy.map(
      (f) => (t.fields[f] && t.fields[f]!.length > 0 ? t.fields[f] : "unknown")!,
    );
    const key = parts.join("|");
    const arr = buckets.get(key);
    if (arr) arr.push(t.taskId);
    else buckets.set(key, [t.taskId]);
  }

  const bucketEntries = [...buckets.entries()].sort(([a], [b]) =>
    a.localeCompare(b),
  );
  const sizes = bucketEntries.map(([, ids]) => ids.length);
  const alloc = allocateProportional(sizes, target);

  const rand = mulberry32(opts.seed);
  const bucketResults: StratumBucket[] = [];
  const subset: string[] = [];
  bucketEntries.forEach(([, ids], i) => {
    const allocated = alloc[i];
    // Seeding the PRNG once and consuming it across buckets in a fixed bucket
    // order keeps the whole sample a pure function of the seed.
    const picked = deterministicSample(ids, allocated, rand);
    subset.push(...picked);
    bucketResults.push({
      key: bucketEntries[i][0],
      size: ids.length,
      allocated,
      sampled: picked.length,
      taskIds: [...picked].sort(),
    });
  });

  subset.sort(); // diffable, stable output regardless of bucket iteration order
  return { subset, buckets: bucketResults, total, stratifiedFully, missingFields };
}

// ── Corpus parsing (tolerant of mask_map / JSONL / JSON-array shapes) ────────

/** Field aliases the corpus might use for each canonical key. */
const FIELD_ALIASES: Record<string, string[]> = {
  taskId: ["taskId", "task_id", "id", "arvo_id", "name"],
  project: ["project", "proj", "repo", "project_name", "repository"],
  crashType: [
    "crashType",
    "crash_type",
    "bug_type",
    "bugType",
    "sanitizer",
    "vuln_type",
    "vulnerability_type",
    "bug_class",
  ],
};

function pickField(
  obj: Record<string, unknown>,
  canonical: string,
): string | undefined {
  for (const alias of FIELD_ALIASES[canonical] ?? [canonical]) {
    const v = obj[alias];
    if (typeof v === "string" && v.length > 0) return v;
    if (typeof v === "number" && Number.isFinite(v)) return String(v);
  }
  return undefined;
}

/** Parse one JSON object into a CorpusTask, or undefined when it has no taskId. */
function recordToTask(obj: unknown): CorpusTask | undefined {
  if (!obj || typeof obj !== "object") return undefined;
  const rec = obj as Record<string, unknown>;
  // Skip summary rows (e.g. the {"kind":"summary"} line in cybergym-v1.jsonl).
  if (rec.kind === "summary") return undefined;
  const taskId = pickField(rec, "taskId");
  if (!taskId) return undefined;
  const fields: Record<string, string | undefined> = {};
  for (const canonical of ["project", "crashType"]) {
    const v = pickField(rec, canonical);
    if (v !== undefined) fields[canonical] = v;
  }
  return { taskId, fields };
}

/**
 * Parse a corpus file into CorpusTask records, tolerating three shapes:
 *   1. mask_map.json  — {"arvo:10400": "<masked-id>", ...}  (bare id universe)
 *   2. JSONL          — one record per line (summary/non-task rows skipped)
 *   3. JSON array     — [{...}, ...]
 * Throws on a totally unrecognized shape so the operator sees the failure
 * before committing a bad subset.
 */
export function parseCorpus(content: string): CorpusTask[] {
  const trimmed = content.trim();
  if (trimmed.length === 0) return [];

  // Try whole-file JSON first (mask_map object, or an array of records).
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      return parsed
        .map(recordToTask)
        .filter((t): t is CorpusTask => t !== undefined);
    }
    if (parsed && typeof parsed === "object") {
      const obj = parsed as Record<string, unknown>;
      // mask_map shape: keys are task ids, values are opaque masked ids.
      // (also tolerates a top-level {"tasks": [...]} or {"records": [...]} wrapper)
      const wrapped =
        Array.isArray(obj.tasks) ? obj.tasks :
        Array.isArray(obj.records) ? obj.records :
        Array.isArray(obj.data) ? obj.data : null;
      if (wrapped) {
        return wrapped
          .map(recordToTask)
          .filter((t): t is CorpusTask => t !== undefined);
      }
      return Object.keys(obj)
        .filter((k) => {
          // treat "<prefix>:<digits>" (e.g. arvo:10400) as a task id key.
          return /:\d+/.test(k) || /^arvo:/.test(k);
        })
        .map((taskId) => ({ taskId, fields: {} }));
    }
  } catch {
    // not whole-file JSON → fall through to JSONL
  }

  // JSONL: one JSON object per line; skip blank/comment/non-object lines.
  const tasks: CorpusTask[] = [];
  for (const line of trimmed.split(/\r?\n/)) {
    const l = line.trim();
    if (l.length === 0 || l.startsWith("#")) continue;
    try {
      const t = recordToTask(JSON.parse(l));
      if (t) tasks.push(t);
    } catch {
      // skip un-parseable lines (a slightly malformed corpus shouldn't abort)
    }
  }
  if (tasks.length > 0) return tasks;

  throw new Error(
    "Unrecognized corpus shape — expected mask_map.json (object of id→masked-id), " +
      "a JSONL of task records, or a JSON array of records.",
  );
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function parseArgs(argv: string[]) {
  const has = (f: string) => argv.includes(f);
  const val = (f: string) => (has(f) ? argv[argv.indexOf(f) + 1] : undefined);
  const seedRaw = val("--seed");
  const seed =
    seedRaw !== undefined
      ? /^0x/i.test(seedRaw)
        ? parseInt(seedRaw, 16)
        : parseInt(seedRaw, 10)
      : DEFAULT_FAIR_SEED;
  const stratifyBy = (val("--stratify-by") ?? DEFAULT_STRATIFY_BY.join(","))
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return {
    corpus: val("--corpus") ?? process.env.CYBERGYM_CORPUS,
    target: has("--target") ? parseInt(val("--target")!, 10) : DEFAULT_FAIR_TARGET,
    seed: Number.isFinite(seed) ? seed >>> 0 : DEFAULT_FAIR_SEED,
    stratifyBy,
    out: val("--out") ?? DEFAULT_OUT_PATH,
    stdout: has("--stdout"),
    json: has("--json"),
  };
}

function resolveDefaultOut(override: string | undefined): string {
  if (!override) return join(__dirname, "..", DEFAULT_OUT_PATH);
  return isAbsolute(override) ? override : join(process.cwd(), override);
}

function sha256Of(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}

async function main(): Promise<void> {
  const cfg = parseArgs(process.argv.slice(2));
  if (!cfg.corpus || cfg.corpus.length === 0) {
    console.error(
      "Usage: tsx src/cybergym-stratify.ts --corpus <mask_map.json|corpus.jsonl> " +
        "[--target N] [--seed S] [--stratify-by project,crashType] [--out <file> | --stdout] [--json]",
    );
    console.error("  (the corpus lives on the bench host; it is never hardcoded here)");
    process.exit(2);
  }
  if (!existsSync(cfg.corpus)) {
    console.error(`Corpus not found: ${cfg.corpus}`);
    process.exit(2);
  }

  const corpusContent = readFileSync(cfg.corpus, "utf8");
  const tasks = parseCorpus(corpusContent);
  if (tasks.length === 0) {
    console.error(`No task ids parsed from ${cfg.corpus}`);
    process.exit(2);
  }

  const result = stratify(tasks, {
    target: cfg.target,
    seed: cfg.seed,
    stratifyBy: cfg.stratifyBy,
  });

  // Integrity stamp: the subset file records exactly what was committed and when.
  const sourceHash = sha256Of(corpusContent);
  const generated = new Date().toISOString();
  const header = [
    `# CyberGym fair-config PRE-REGISTERED stratified subset (issue #1029, epic #1026)`,
    `# source: ${cfg.corpus} (sha256: ${sourceHash.slice(0, 16)})`,
    `# generated: ${generated}`,
    `# target: ${cfg.target}  seed: 0x${cfg.seed.toString(16)}  stratify-by: ${cfg.stratifyBy.join(",")}`,
    `# universe: ${result.total} tasks across ${result.buckets.length} strata  ->  sampled ${result.subset.length}`,
    `#`,
    `# PRE-REGISTRATION = CLAIM-GATE INTEGRITY:`,
    `#   1. Commit THIS file before any model run (the task-id list + seed are frozen).`,
    `#   2. Run cybergym-runner --subset <this-file> --corpus-path results/cybergym-fair-v1.jsonl`,
    `#   3. Commit the per-task JSONL receipt AFTER the run.`,
    `# Editing this list post-run breaks the claim-gate (epic #1026).`,
  ].join("\n");

  if (cfg.stratifyBy.some((f) => result.missingFields.includes(f))) {
    console.error(
      `warning: corpus has no metadata for stratum field(s): ${result.missingFields.join(", ")}. ` +
        `Fell back to uniform deterministic sampling on the remaining field(s). ` +
        `For a true stratified run, feed a corpus with project + crashType (dumpable from the HF dataset on bench).`,
    );
  }

  if (cfg.json) {
    // Machine-readable provenance to stderr/stdout for logs.
    console.log(
      JSON.stringify(
        {
          source: cfg.corpus,
          sourceSha256: sourceHash,
          generated,
          target: cfg.target,
          seed: cfg.seed,
          stratifyBy: cfg.stratifyBy,
          universe: result.total,
          strata: result.buckets.length,
          sampled: result.subset.length,
          stratifiedFully: result.stratifiedFully,
          missingFields: result.missingFields,
        },
        null,
        2,
      ),
    );
    return;
  }

  const body = result.subset.map((id) => `${id}\n`).join("");
  const file = `${header}\n${body}`;

  if (cfg.stdout) {
    process.stdout.write(file);
    return;
  }

  const outPath = resolveDefaultOut(cfg.out);
  const dir = dirname(outPath);
  if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
  writeFileSync(outPath, file);
  console.error(
    `wrote ${result.subset.length} task ids (of ${result.total}, seed 0x${cfg.seed.toString(16)}, ` +
      `${result.buckets.length} strata) -> ${outPath}`,
  );
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  main()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error("cybergym-stratify failed:", err);
      process.exit(1);
    });
}
