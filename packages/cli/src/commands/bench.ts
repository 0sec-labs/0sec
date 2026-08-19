/**
 * `0sec bench` — A/B variant tournament + CI regression gate over the
 * labeled corpus (0sec#656).
 *
 * Lives in the 0sec CLI (not the remote `0cloud` HTTP client) because a
 * tournament runs the engine locally — it installs packages, runs audits, and
 * grades against the in-tree corpus. Two subcommands:
 *
 *   0sec bench run   — run N variants over the corpus, emit per-variant
 *                        scorecards + pairwise Wilson-95 deltas, append the
 *                        champion to a benchmark ledger, and (with --gate)
 *                        fail when the champion regressed vs the last green.
 *   0sec bench diff  — compare two recorded runs (by id) in a ledger.
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import type { Command } from "commander";
import chalk from "chalk";
import type { RuntimeMode, ScanDepth } from "@0sec/shared";
import {
  loadManifest,
  subsetManifest,
  corpusV1Path,
  runTournament,
  formatTournamentSummary,
  compareScorecards,
  createDefaultVariantScan,
  createDockerWebProvisioner,
  objectiveOracleEvaluatorAttestation,
  loadLedger,
  saveLedger,
  appendLedgerEntry,
  lastGreen,
  evaluateRegression,
  type BenchVariant,
  type LedgerEntry,
  type BenchManifest,
} from "@0sec/core";
import {
  registerBenchImprovementCommand,
  writeCanonicalJsonAtomic,
} from "./bench-improvement.js";
import { registerBenchCalibrationCommand } from "./bench-calibration.js";

const DEFAULT_LEDGER = "benchmark-ledger.json";

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

export function selectRunManifest(
  source: BenchManifest,
  opts: { caseId?: string[]; manifestId?: string; ciSubset?: boolean },
): BenchManifest {
  const caseIds = opts.caseId ?? [];
  if (caseIds.length === 0) {
    if (opts.manifestId) throw new Error("--manifest-id requires at least one --case-id");
    return source;
  }
  if (opts.ciSubset) throw new Error("--case-id cannot be combined with --ci-subset");
  if (!opts.manifestId) throw new Error("--manifest-id is required with --case-id");
  return subsetManifest(source, caseIds, opts.manifestId);
}

export function resolveManifestPath(
  manifestPath: string | undefined,
  bundledCorpusPath: string = corpusV1Path(),
): string {
  if (manifestPath) return manifestPath;
  if (existsSync(bundledCorpusPath)) return bundledCorpusPath;
  throw new Error(
    "No bundled benchmark corpus is available. Pass --manifest <path> to run an external or public corpus.",
  );
}

export function validateCaptureDestination(outputValue: string, ledgerValue: string): void {
  const output = resolve(outputValue);
  if (output === resolve(ledgerValue)) {
    throw new Error("--tournament-output must differ from --ledger");
  }
  if (existsSync(output)) throw new Error(`tournament output already exists: ${output}`);
}

export async function measureOperation<T>(
  operation: () => Promise<T>,
  monotonicClock: () => number = () => performance.now(),
): Promise<{ value: T; elapsedMs: number }> {
  const startedAt = monotonicClock();
  const value = await operation();
  const completedAt = monotonicClock();
  if (!Number.isFinite(startedAt) || !Number.isFinite(completedAt) || completedAt < startedAt) {
    throw new Error("monotonic tournament clock produced an invalid interval");
  }
  return { value, elapsedMs: Math.ceil(completedAt - startedAt) };
}

function parseVariants(opts: Record<string, unknown>): BenchVariant[] {
  // Explicit variant file wins; otherwise build a single "champion" variant
  // from the shorthand --model/--runtime/--depth flags.
  if (opts.variants) {
    const path = String(opts.variants);
    const raw = existsSync(path) ? readFileSync(path, "utf8") : String(opts.variants);
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`--variants must be a JSON array of variants or a path to one`);
    }
    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error(`--variants must be a non-empty JSON array`);
    }
    return parsed as BenchVariant[];
  }
  return [
    {
      id: String(opts.variantId ?? "champion"),
      model: opts.model ? String(opts.model) : undefined,
      runtime: opts.runtime ? (String(opts.runtime) as RuntimeMode) : undefined,
      depth: opts.depth ? (String(opts.depth) as ScanDepth) : undefined,
      costCeilingUsdPerAttempt: opts.costCeiling ? Number(opts.costCeiling) : undefined,
    },
  ];
}

export function registerBenchCommand(program: Command): void {
  const bench = program
    .command("bench")
    .description("A/B variant tournament + CI regression gate over the labeled corpus (#656)");

  registerBenchImprovementCommand(bench);
  registerBenchCalibrationCommand(bench);

  // ── bench run ──
  bench
    .command("run")
    .description("Run a variant tournament over the corpus and update the benchmark ledger")
    .option("--manifest <path>", "Corpus manifest path (required when no bundled corpus is present)")
    .option("--case-id <id>", "exact case id in a pre-registered manifest slice (repeatable)", collect, [])
    .option("--manifest-id <id>", "sealed slice id (required with --case-id)")
    .option("--variants <json|path>", "JSON array of variant descriptors, or a path to one")
    .option("--variant-id <id>", "Id for the implicit single variant", "champion")
    .option("--model <model>", "Model override for the implicit single variant")
    .option("--runtime <runtime>", "Runtime override (api/claude/codex/…)")
    .option("--depth <depth>", "Scan/audit depth override (quick/deep/…)")
    .option("--pass-at-k <n>", "pass@k attempts per case", "1")
    .option("--max-turns <n>", "Turn budget per attempt", "40")
    .option("--cost-ceiling <usd>", "Per-attempt cost ceiling (USD)")
    .option("--ci-subset", "Run only the fast CI subset (cases flagged ci:true)", false)
    .option("--ledger <path>", "Benchmark ledger path", DEFAULT_LEDGER)
    .option("--tournament-output <path>", "create-once canonical {manifest,tournament} evidence")
    .option("--run-id <id>", "Run id recorded in the ledger (default: ISO timestamp)")
    .option("--gate", "Evaluate the regression gate and exit non-zero on a regression", false)
    .option("--max-success-drop <f>", "Max success-rate drop vs last green", "0.05")
    .option("--max-fp-rise <f>", "Max FP-rate rise vs last green", "0.05")
    .option("--format <format>", "Output format: terminal, json", "terminal")
    .action(async (opts) => {
      const isJson = String(opts.format) === "json";
      let variants: BenchVariant[];
      let manifestPath: string;
      try {
        variants = parseVariants(opts);
        manifestPath = resolveManifestPath(opts.manifest ? String(opts.manifest) : undefined);
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exit(2);
        return;
      }

      const sourceManifest = await loadManifest(manifestPath);
      const manifest = selectRunManifest(sourceManifest, {
        caseId: opts.caseId as string[],
        manifestId: opts.manifestId ? String(opts.manifestId) : undefined,
        ciSubset: Boolean(opts.ciSubset),
      });
      const provisioner = createDockerWebProvisioner(manifest.corpusRoot);
      if (opts.tournamentOutput) {
        validateCaptureDestination(String(opts.tournamentOutput), String(opts.ledger));
      }

      if (!isJson) {
        console.log("");
        console.log(chalk.red.bold("  0sec bench — variant tournament"));
        console.log(chalk.dim(`  corpus:   ${manifest.id} (${manifest.cases.length} cases)`));
        console.log(chalk.dim(`  variants: ${variants.map((v) => v.id).join(", ")}`));
        console.log(chalk.dim(`  pass@k:   ${opts.passAtK}${opts.ciSubset ? "  (CI subset)" : ""}`));
        console.log("");
      }

      const evaluatorBefore = objectiveOracleEvaluatorAttestation();
      const measuredTournament = await measureOperation(() => runTournament(manifest, {
        variants,
        variantScan: (v) => createDefaultVariantScan(v),
        provisioner,
        passAtK: Number(opts.passAtK),
        maxTurns: Number(opts.maxTurns),
        costCeilingUsd: opts.costCeiling ? Number(opts.costCeiling) : undefined,
        ciSubset: Boolean(opts.ciSubset),
        clock: () => new Date().toISOString(),
        onVariant: isJson
          ? undefined
          : (r) => console.log(chalk.dim(`  · ${r.variant.id} done`)),
      }));
      const tournament = measuredTournament.value;
      const evaluatorAfter = objectiveOracleEvaluatorAttestation();

      if (opts.tournamentOutput) {
        writeCanonicalJsonAtomic(String(opts.tournamentOutput), {
          schemaVersion: 1,
          elapsedMs: measuredTournament.elapsedMs,
          evaluatorBefore,
          evaluatorAfter,
          manifest,
          tournament,
        });
      }

      const champion = tournament.variants.find((v) => v.variant.id === tournament.championId)!;

      // Regression gate against the last green ledger entry.
      const ledgerPath = String(opts.ledger);
      const ledger = await loadLedger(ledgerPath);
      const baseline = lastGreen(ledger);
      const regression = evaluateRegression(champion.scorecard, baseline, {
        maxSuccessRateDrop: Number(opts.maxSuccessDrop),
        maxFpRateRise: Number(opts.maxFpRise),
      });

      const runId = opts.runId ? String(opts.runId) : new Date().toISOString();
      const entry: LedgerEntry = {
        runId,
        manifestId: manifest.id,
        championId: tournament.championId,
        scorecard: champion.scorecard,
        green: regression.passed,
        meta: { variantIds: tournament.config.variantIds, ciSubset: Boolean(opts.ciSubset) },
      };
      await saveLedger(ledgerPath, appendLedgerEntry(ledger, entry));

      if (isJson) {
        console.log(JSON.stringify({ tournament, regression, runId }, null, 2));
      } else {
        console.log("");
        console.log(formatTournamentSummary(tournament));
        console.log("");
        console.log(chalk.bold(`  champion: ${tournament.championId}`));
        if (regression.passed) {
          console.log(chalk.green(`  gate: PASS${baseline ? ` (vs ${baseline.runId})` : " (first run, no baseline)"}`));
        } else {
          console.log(chalk.red(`  gate: FAIL`));
          for (const r of regression.reasons) console.log(chalk.red(`    - ${r}`));
        }
        console.log(chalk.dim(`  ledger: ${ledgerPath} (run ${runId})`));
        console.log("");
      }

      if (opts.gate && !regression.passed) process.exit(1);
    });

  // ── bench diff ──
  bench
    .command("diff")
    .description("Compare two recorded runs in a benchmark ledger")
    .requiredOption("--a <runId>", "Baseline run id")
    .requiredOption("--b <runId>", "Comparison run id")
    .option("--ledger <path>", "Benchmark ledger path", DEFAULT_LEDGER)
    .option("--format <format>", "Output format: terminal, json", "terminal")
    .action(async (opts) => {
      const ledger = await loadLedger(String(opts.ledger));
      const a = ledger.entries.find((e) => e.runId === String(opts.a));
      const b = ledger.entries.find((e) => e.runId === String(opts.b));
      if (!a || !b) {
        console.error(chalk.red(`run id not found in ledger: ${!a ? opts.a : opts.b}`));
        process.exit(2);
        return;
      }
      const delta = compareScorecards(a.scorecard, b.scorecard);
      if (String(opts.format) === "json") {
        console.log(JSON.stringify({ a: a.runId, b: b.runId, delta }, null, 2));
        return;
      }
      console.log("");
      console.log(chalk.bold(`  ${a.runId}  vs  ${b.runId}`));
      console.log(
        `  Δsuccess ${(delta.successRateDelta * 100).toFixed(1)}pp · ` +
          `Δfp ${(delta.fpRateDelta * 100).toFixed(1)}pp · ` +
          `Δcost/success ${delta.costPerSuccessDelta == null ? "n/a" : `$${delta.costPerSuccessDelta.toFixed(3)}`} · ` +
          (delta.significant ? chalk.green("significant") : chalk.yellow("not significant")),
      );
      console.log("");
    });
}
