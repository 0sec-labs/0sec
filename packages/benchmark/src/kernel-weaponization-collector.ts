#!/usr/bin/env node

/**
 * Kernel Weaponization Training-Data Collector
 *
 * Extracts (input, label) rows from autonomous kernel-exploit chain runs and
 * emits a reusable JSONL corpus — the supervision signal for a model that, given
 * a bug's primitive + the structured exploit plan the chain derived, predicts
 * how far up the escalation ladder the run can actually climb (and which
 * oracle-REFUSED dead-ends to avoid).
 *
 * WHY THIS EXISTS: the chain COMPUTES a rich per-run tuple (write profile, ranked
 * sprays, root-tail plan, per-step rung verdicts) but the persistence path used
 * to FLATTEN it to ~4 scalars + an exploit-C blob. The capture chain now carries
 * the full tuple into `verification_runs.result.weaponization` (summary +
 * `.detail.perStep` + `.detail.exploitContext`). This collector reads those rows
 * back and serializes them so the data stops being thrown away.
 *
 * Source shape (one per chain run) — the parsed `verification_runs.result` jsonb,
 * or the raw `0sec exploit` JSON. Both carry the same fields; this collector
 * tolerates either by reading defensively (snake_case from the CLI JSON,
 * camelCase from the orchestrator summary).
 *
 * Output: JSONL, one row per chain run, fields:
 *   { input: {...}, label: {...}, source }
 * where
 *   input = { finding/kasan, primitive, writeProfile, sprayPlans, rootTailPlan,
 *             cacheKey/config provenance }
 *   label = { highestRung, lpeAchieved, reclaimLanded, perStep verdicts,
 *             refusedReasons }
 *
 * The oracle-REFUSED negative rows ride along in `label.perStep[]` whenever a
 * step's `reachedRung` is below its `attemptedRung` (with the `reason`), so the
 * corpus is not silently positives-only.
 *
 * Usage:
 *   tsx src/kernel-weaponization-collector.ts --runs <runs.json> [--output <out.jsonl>]
 * where `runs.json` is a JSON array (or `{ runs: [...] }`) of run objects.
 */

import {
  readFileSync,
  writeFileSync,
  appendFileSync,
  existsSync,
  mkdirSync,
} from "node:fs";
import { join, dirname, isAbsolute } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** The escalation rungs, weakest → strongest. Mirrors core's `EscalationRung`. */
export const ESCALATION_RUNGS = [
  "none",
  "attempted",
  "reclaim",
  "arb-read",
  "arb-write",
  "root",
] as const;
export type WeaponizationRung = (typeof ESCALATION_RUNGS)[number];

/** A normalized per-step record: the oracle's verdict for one chain step. */
export interface WeaponizationStepRow {
  /** Strategy / node identifier driving this step. */
  stepId: string;
  /** Human-readable step title (when present). */
  title: string;
  /** The ladder rung this step was driving toward. */
  attemptedRung: string;
  /** The highest rung the deterministic oracle confirmed for this step. */
  reachedRung: string;
  /** Free-form reason — the oracle-REFUSED explanation when `reached < attempted`. */
  reason: string;
  /** True when the oracle refused to confirm the attempted rung (negative row). */
  refused: boolean;
}

/** One corpus row: the chain run's input tuple + its outcome label. */
export interface WeaponizationSample {
  /** Stable de-dup id for the row. */
  id: string;
  input: {
    /** Finding id / target provenance, when known. */
    findingId?: string;
    /** The KASAN/crash signature or dmesg snippet that seeded the chain. */
    kasan?: string;
    /** Classified bug primitive (kind / control / exploitability). */
    primitive?: unknown;
    /** Derived controlled-write profile. */
    writeProfile?: unknown;
    /** Ranked heap-spray reclaim plans. */
    sprayPlans?: unknown;
    /** Targeted root-tail finisher plan. */
    rootTailPlan?: unknown;
    /** Booted kernel-image identity / config provenance, when carried. */
    cacheKey?: string;
  };
  label: {
    /** Highest rung the run reached end-to-end. */
    highestRung: string;
    /** Whether root (LPE) was deterministically achieved. */
    lpeAchieved: boolean;
    /** Whether a controlled reclaim was observed to land. */
    reclaimLanded: boolean;
    /** Per-step oracle verdicts, incl. the REFUSED negatives. */
    perStep: WeaponizationStepRow[];
    /** Just the REFUSED reasons, pulled out for quick negative-mining. */
    refusedReasons: string[];
  };
  /** Where the row came from (run id / target), for provenance. */
  source: string;
}

/** Defensive accessor: first defined value among the given keys. */
function pick(obj: Record<string, unknown> | undefined, ...keys: string[]): unknown {
  if (!obj) return undefined;
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

function asString(v: unknown): string {
  return typeof v === "string" ? v : v === undefined || v === null ? "" : String(v);
}

function rungRank(rung: string): number {
  const idx = ESCALATION_RUNGS.indexOf(rung as WeaponizationRung);
  return idx; // -1 for unknown rungs — sorts below "none", harmlessly
}

/**
 * Normalize a raw per-step record (StrategyAttempt from the CLI JSON, or
 * ChainRunStep from the chain) into a `WeaponizationStepRow`. Tolerates both the
 * snake_case (CLI) and camelCase (engine) field spellings. A step counts as
 * oracle-REFUSED when its confirmed rung is below the rung it attempted — that
 * is the negative-training signal the corpus must preserve.
 */
export function normalizeStep(raw: unknown): WeaponizationStepRow {
  const r = (raw ?? {}) as Record<string, unknown>;
  const attemptedRung = asString(pick(r, "attempted_rung", "attemptedRung", "target_rung", "targetRung"));
  const reachedRung = asString(pick(r, "reached_rung", "reachedRung"));
  const reason = asString(pick(r, "reason"));
  const refused =
    attemptedRung !== "" &&
    reachedRung !== "" &&
    rungRank(reachedRung) < rungRank(attemptedRung);
  return {
    stepId: asString(pick(r, "strategy_id", "strategyId", "node_id", "nodeId")),
    title: asString(pick(r, "title")),
    attemptedRung,
    reachedRung,
    reason,
    refused,
  };
}

/**
 * Extract a corpus sample from a single chain-run object. Accepts either the
 * parsed `verification_runs.result` jsonb (weaponization summary nested under
 * `result.weaponization`) or the raw `0sec exploit` CLI JSON (flat
 * `highest_rung` / `per_step` / `exploit_context`). Returns `undefined` when the
 * object carries no recognizable weaponization outcome.
 */
export function collectSampleFromRun(
  run: unknown,
  index = 0,
): WeaponizationSample | undefined {
  if (!run || typeof run !== "object") return undefined;
  const root = run as Record<string, unknown>;

  // The orchestrator result jsonb nests the summary under `weaponization`
  // (with a `.detail` sibling); the CLI JSON is flat. Resolve both.
  const result =
    (root["result"] as Record<string, unknown> | undefined) ?? root;
  const weap =
    (result["weaponization"] as Record<string, unknown> | undefined) ?? result;
  const detail = (weap["detail"] as Record<string, unknown> | undefined) ?? weap;

  const highestRung = asString(pick(weap, "highestRung", "highest_rung"));
  if (highestRung === "") return undefined; // no usable outcome — skip

  const rawSteps = pick(detail, "perStep", "per_step", "attempts");
  const perStep = Array.isArray(rawSteps) ? rawSteps.map(normalizeStep) : [];

  const exploitContext =
    (pick(detail, "exploitContext", "exploit_context") as
      | Record<string, unknown>
      | undefined) ?? undefined;

  const findingId = asString(
    pick(root, "finding_id", "findingId") ||
      pick(result, "finding_id", "findingId") ||
      pick(weap, "finding_id", "findingId"),
  );
  const runId = asString(pick(root, "run_id", "runId", "id"));
  const source = runId || findingId || `run-${index}`;

  return {
    id: source,
    input: {
      ...(findingId ? { findingId } : {}),
      ...(asString(pick(root, "kasan", "signature", "crash_dmesg"))
        ? { kasan: asString(pick(root, "kasan", "signature", "crash_dmesg")) }
        : {}),
      ...(pick(root, "primitive") ? { primitive: pick(root, "primitive") } : {}),
      ...(pick(exploitContext, "writeProfile", "write_profile")
        ? { writeProfile: pick(exploitContext, "writeProfile", "write_profile") }
        : {}),
      ...(pick(exploitContext, "sprayPlans", "spray_plans")
        ? { sprayPlans: pick(exploitContext, "sprayPlans", "spray_plans") }
        : {}),
      ...(pick(exploitContext, "rootTailPlan", "root_tail_plan")
        ? { rootTailPlan: pick(exploitContext, "rootTailPlan", "root_tail_plan") }
        : {}),
      ...(asString(pick(root, "cache_key", "cacheKey"))
        ? { cacheKey: asString(pick(root, "cache_key", "cacheKey")) }
        : {}),
    },
    label: {
      highestRung,
      lpeAchieved: Boolean(pick(weap, "lpeAchieved", "lpe_achieved")),
      reclaimLanded: Boolean(pick(weap, "reclaimLanded", "reclaim_landed")),
      perStep,
      refusedReasons: perStep
        .filter((s) => s.refused && s.reason !== "")
        .map((s) => s.reason),
    },
    source,
  };
}

/**
 * Collect every recognizable run from a JSON file. Accepts a top-level array,
 * `{ runs: [...] }`, or `{ rows: [...] }`. Skips objects without an outcome.
 */
export function collectFromRunsFile(path: string): WeaponizationSample[] {
  const data = JSON.parse(readFileSync(path, "utf8")) as unknown;
  const runs: unknown[] = Array.isArray(data)
    ? data
    : Array.isArray((data as Record<string, unknown>)?.runs)
      ? ((data as Record<string, unknown>).runs as unknown[])
      : Array.isArray((data as Record<string, unknown>)?.rows)
        ? ((data as Record<string, unknown>).rows as unknown[])
        : [];
  const samples: WeaponizationSample[] = [];
  runs.forEach((run, i) => {
    const s = collectSampleFromRun(run, i);
    if (s) samples.push(s);
  });
  return samples;
}

/** Serialize a sample to a single JSONL line (stable key order). */
export function toJsonl(sample: WeaponizationSample): string {
  return JSON.stringify({
    id: sample.id,
    input: sample.input,
    label: sample.label,
    source: sample.source,
  });
}

/**
 * The committed corpus path (per the "commit receipts to git, never artifacts"
 * convention — the JSONL IS the receipt). Relative to the benchmark package.
 */
export const KERNEL_WEAPONIZATION_CORPUS_PATH =
  "results/kernel-weaponization-v1.jsonl";

/**
 * Resolve the corpus output path. Precedence (first wins): an explicit
 * `override` → the `KERNEL_WEAPONIZATION_CORPUS_PATH` env → the package-relative
 * default (`results/kernel-weaponization-v1.jsonl`). A relative override is
 * resolved against the process CWD (standard CLI behaviour); the default is
 * resolved against the benchmark package root so the committed receipt is
 * always written in the same place regardless of who invokes it. Mirrors
 * `resolveCorpusPath` in `cybergym-runner.ts`.
 */
export function resolveKernelWeaponizationCorpusPath(
  override?: string,
  packageRoot: string = join(__dirname, ".."),
): string {
  const requested = override ?? process.env.KERNEL_WEAPONIZATION_CORPUS_PATH;
  if (requested && requested.length > 0) {
    return isAbsolute(requested) ? requested : join(process.cwd(), requested);
  }
  return join(packageRoot, KERNEL_WEAPONIZATION_CORPUS_PATH);
}

/**
 * Append a SINGLE weaponization run to the corpus INLINE, the moment its
 * outcome is produced — the auto-populate path (issue #1126) that makes this
 * corpus fill itself the way `cybergym-runner.ts` fills `cybergym-v1.jsonl`,
 * instead of relying on the manual `--runs` batch extraction that was never run.
 *
 * `run` is any object `collectSampleFromRun` understands (the nested
 * `result.weaponization` shape or the flat CLI shape). Oracle-REFUSED negatives
 * ride along inside `label.perStep[]` exactly as the batch collector emits them
 * — a run that did not reach root is itself a labeled negative. The tuple
 * shaping + serialization are REUSED from `collectSampleFromRun` / `toJsonl`;
 * this function only owns the benchmark-relative path + append semantics.
 *
 * BEST-EFFORT by contract: any failure (unwritable path, malformed run) is
 * swallowed and reported to `logger` — a corpus-write must NEVER break the
 * weaponization run that produced the tuple. Returns true iff a row was written.
 */
export function appendWeaponizationRun(
  run: unknown,
  opts: { corpusPath?: string; logger?: (line: string) => void } = {},
): boolean {
  try {
    const sample = collectSampleFromRun(run);
    if (!sample) return false; // no recognizable outcome — nothing to append
    const corpus = resolveKernelWeaponizationCorpusPath(opts.corpusPath);
    const dir = dirname(corpus);
    if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
    const line = toJsonl(sample) + "\n";
    if (existsSync(corpus)) {
      appendFileSync(corpus, line);
    } else {
      writeFileSync(corpus, line);
    }
    return true;
  } catch (err) {
    opts.logger?.(
      `[weaponization-corpus] append skipped: ${err instanceof Error ? err.message : String(err)}`,
    );
    return false;
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const runsIdx = args.indexOf("--runs");
  if (runsIdx === -1) {
    console.error("usage: kernel-weaponization-collector --runs <runs.json> [--output <out.jsonl>]");
    process.exit(1);
  }
  const runsPath = args[runsIdx + 1];
  const samples = collectFromRunsFile(runsPath);

  const lpe = samples.filter((s) => s.label.lpeAchieved).length;
  const refused = samples.filter((s) => s.label.refusedReasons.length > 0).length;
  console.error("\n=== Kernel Weaponization Corpus ===");
  console.error(`  Runs collected:   ${samples.length}`);
  console.error(`  LPE achieved:     ${lpe}`);
  console.error(`  With REFUSED rows: ${refused}`);

  const outIdx = args.indexOf("--output");
  const outputPath = outIdx !== -1 ? args[outIdx + 1] : undefined;
  const lines = samples.map(toJsonl);

  if (outputPath) {
    const dir = dirname(outputPath);
    if (dir && dir !== ".") mkdirSync(dir, { recursive: true });
    writeFileSync(outputPath, lines.length > 0 ? lines.join("\n") + "\n" : "");
    console.error(`  Written to: ${outputPath}`);
  } else {
    const corpus = join(__dirname, "..", KERNEL_WEAPONIZATION_CORPUS_PATH);
    if (existsSync(dirname(corpus))) {
      writeFileSync(corpus, lines.length > 0 ? lines.join("\n") + "\n" : "");
      console.error(`  Written to: ${corpus}`);
    } else {
      for (const line of lines) console.log(line);
    }
  }
}

// Only run main() when invoked as a script, not when imported (e.g. by vitest).
const isScript =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isScript) {
  main().catch((err) => {
    console.error("Kernel weaponization collection failed:", err);
    process.exit(1);
  });
}
