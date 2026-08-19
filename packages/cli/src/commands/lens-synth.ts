/**
 * `pwnkit lens-synth --miss-input <path>` — run the SELF-IMPROVING LENS LOOP
 * on a miss-input once, manually.
 *
 *   miss-capture ─▶ synthesize (LLM) ─▶ validate (bench tournament, fail-closed)
 *        ─▶ register (only a validated champion is appended to the appsec registry)
 *
 * The miss-input JSON supplies the two miss signals + a validation corpus:
 *
 *   {
 *     "misses": {
 *       "confirmedMisses": [{ "classHint","sinkPattern","file","line?","whyMissed" }],
 *       "incompleteCoverage": [{ "file","lensId","reason":"timeout","budgetMs" }]
 *     },
 *     "corpus": {
 *       "positives": [{ "id","path","note?" }],          // must exhibit the miss
 *       "negativeControls": [{ "id","path","note?" }]     // must stay clean
 *     }
 *   }
 *
 * Defaults wire the REAL synthesis model (LlmApiRuntime, routed — no raw key) and
 * the REAL finder-backed probe (runHuntScan over each fixture). The command
 * validates without writing by default; `--promote` is required to register a
 * champion. Autonomous nightly triggering is a FOLLOW-UP.
 *
 * Exit codes: 0 = the loop ran (with or without a registration — a clean
 * no-registration run is a valid outcome); 3 = error (bad flags / unreadable or
 * malformed miss-input).
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Command } from "commander";
import {
  makeFinderLensProbe,
  runLensSynthesisLoop,
  type LensProbe,
  type LensSynthesisInput,
  type LensSynthesisModel,
  type LensSynthesisResult,
  type MissInput,
  type ValidationCorpus,
  type ValidationFixture,
} from "@pwnkit/core";

// ── Miss-input parsing (defensive) ────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseFixtures(value: unknown, label: string): ValidationFixture[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value.map((entry, i) => {
    if (!isRecord(entry)) throw new Error(`${label}[${i}] must be an object`);
    const id = entry.id;
    const path = entry.path;
    if (typeof id !== "string" || id.trim() === "") throw new Error(`${label}[${i}].id must be a non-empty string`);
    if (typeof path !== "string" || path.trim() === "") throw new Error(`${label}[${i}].path must be a non-empty string`);
    return { id, path, ...(typeof entry.note === "string" ? { note: entry.note } : {}) };
  });
}

/** Validate + normalize the miss-input file into a {@link LensSynthesisInput}. */
export function parseMissInputFile(raw: unknown): LensSynthesisInput {
  if (!isRecord(raw)) throw new Error("miss-input must be a JSON object");
  const missesRaw = isRecord(raw.misses) ? raw.misses : {};
  const corpusRaw = isRecord(raw.corpus) ? raw.corpus : {};

  const misses: MissInput = {
    ...(Array.isArray(missesRaw.confirmedMisses) ? { confirmedMisses: missesRaw.confirmedMisses as MissInput["confirmedMisses"] } : {}),
    ...(Array.isArray(missesRaw.incompleteCoverage) ? { incompleteCoverage: missesRaw.incompleteCoverage as MissInput["incompleteCoverage"] } : {}),
  };
  const corpus: ValidationCorpus = {
    positives: parseFixtures(corpusRaw.positives, "corpus.positives"),
    negativeControls: parseFixtures(corpusRaw.negativeControls, "corpus.negativeControls"),
  };
  if (corpus.positives.length === 0) {
    throw new Error("corpus.positives must contain at least one fixture (the seeded miss) — the loop is fail-closed without it");
  }
  return { misses, corpus };
}

// ── Command core (injectable for tests) ───────────────────────────────────

export interface LensSynthCommandOptions {
  missInput: string;
  registry?: string;
  maxRegister?: number;
  model?: string;
  promote?: boolean;
}

export interface LensSynthCommandDeps {
  /** Override the synthesis model (tests inject a fake). */
  model?: LensSynthesisModel;
  /** Override the validation probe (tests inject a fake). */
  probe?: LensProbe;
  log?: (msg: string) => void;
}

/**
 * Parse the miss-input and run the loop. Pure wrt IO except the miss-input read
 * and the registry write; the model + probe are injectable so this is testable
 * end-to-end without an LLM or a real finder. Registration is dry-run by
 * default and requires an explicit promotion request.
 */
export async function runLensSynthCommand(
  opts: LensSynthCommandOptions,
  deps: LensSynthCommandDeps = {},
): Promise<LensSynthesisResult> {
  const log = deps.log ?? (() => {});
  const raw = JSON.parse(readFileSync(resolve(opts.missInput), "utf8")) as unknown;
  const input = parseMissInputFile(raw);
  const probe = deps.probe ?? makeFinderLensProbe({ log });
  return runLensSynthesisLoop(input, {
    ...(deps.model ? { model: deps.model } : {}),
    ...(opts.model ? { modelId: opts.model } : {}),
    probe,
    ...(opts.registry ? { registryPath: resolve(opts.registry) } : {}),
    maxRegistrations: opts.maxRegister ?? 1,
    dryRun: !opts.promote,
    log,
  });
}

/** Human summary of a loop result. */
export function formatLensSynthResult(result: LensSynthesisResult, dryRun: boolean): string {
  const lines = [
    `captured ${result.candidatesCaptured} miss candidate(s) → ${result.clusters} cluster(s) → ${result.synthesized.length} synthesized`,
  ];
  for (const v of result.validations) {
    lines.push(`  validate ${v.lensId}: ${v.passed ? "CHAMPION" : "rejected"} — ${v.reason}`);
  }
  if (dryRun) {
    lines.push(`dry-run: ${result.validations.filter((v) => v.passed).length} champion(s) would register (nothing written)`);
  } else {
    lines.push(
      result.registered.length > 0
        ? `REGISTERED ${result.registered.length} lens(es): ${result.registered.map((r) => r.uid).join(", ")}`
        : "registered 0 lenses",
    );
  }
  for (const r of result.rejected) lines.push(`  rejected ${r.id}: ${r.reason}`);
  for (const w of result.warnings) lines.push(`  warning: ${w}`);
  return lines.join("\n");
}

// ── Commander wiring ──────────────────────────────────────────────────────

export function registerLensSynthCommand(program: Command): void {
  program
    .command("lens-synth")
    .description("Run the self-improving lens loop: turn a confirmed finder miss into a validated, registered appsec lens")
    .requiredOption("--miss-input <path>", "miss-input JSON ({ misses, corpus })")
    .option("--registry <path>", "appsec registry to append to (defaults to the bundled seed registry)")
    .option("--max-register <n>", "cap how many lenses this run may register", (v) => Number.parseInt(v, 10))
    .option("--model <id>", "synthesis model override")
    .option("--promote", "register a validated champion in the selected registry", false)
    .option("--json", "print the full result as JSON", false)
    .action(async (opts) => {
      try {
        const result = await runLensSynthCommand(
          {
            missInput: String(opts.missInput),
            ...(opts.registry ? { registry: String(opts.registry) } : {}),
            ...(Number.isInteger(opts.maxRegister) ? { maxRegister: Number(opts.maxRegister) } : {}),
            ...(opts.model ? { model: String(opts.model) } : {}),
            promote: Boolean(opts.promote),
          },
          { log: (m) => process.stderr.write(`${m}\n`) },
        );
        process.stdout.write(
          opts.json ? `${JSON.stringify(result, null, 2)}\n` : `${formatLensSynthResult(result, !opts.promote)}\n`,
        );
      } catch (err) {
        process.stderr.write(`lens-synth: ${err instanceof Error ? err.message : String(err)}\n`);
        process.exitCode = 3;
      }
    });
}
