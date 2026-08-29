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
  createBenchIntegrationRegistry,
  createCoreBenchIntegration,
  createVariantExecutionFactory,
  loadManifest,
  subsetManifest,
  corpusV1Path,
  runTournament,
  formatTournamentSummary,
  compareScorecards,
  loadLedger,
  saveLedger,
  appendLedgerEntry,
  lastGreen,
  evaluateRegression,
  type BenchAttemptPolicy,
  type BenchIntegration,
  type BenchManifest,
  type BenchVariant,
  type LedgerEntry,
  type TournamentSchedule,
  type VariantExecutionFactory,
} from "@0sec/core";
import {
  createCyberGymBenchIntegration,
  createCyberGymManifest,
  createXbowBenchIntegration,
  createXbowManifestFromPath,
  loadCyberGymTaskIds,
} from "@0sec/benchmark/bench-integrations";
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
      harnessId: opts.harness ? String(opts.harness) : undefined,
      model: opts.model ? String(opts.model) : undefined,
      runtime: opts.runtime ? (String(opts.runtime) as RuntimeMode) : undefined,
      depth: opts.depth ? (String(opts.depth) as ScanDepth) : undefined,
      costCeilingUsdPerAttempt: opts.costCeiling ? Number(opts.costCeiling) : undefined,
    },
  ];
}

export function parseAttemptPolicy(value: unknown): BenchAttemptPolicy {
  if (value === "pass-at-k" || value === "independent-repeat") return value;
  throw new Error("--attempt-policy must be pass-at-k or independent-repeat");
}

export function parseTournamentSchedule(value: unknown): TournamentSchedule {
  if (value === "variant-major" || value === "case-major") return value;
  throw new Error("--schedule must be variant-major or case-major");
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
    .option("--integration <id>", "Target-suite integration: core, xbow, cybergym", "core")
    .option("--manifest <path>", "Corpus manifest path; optional for xbow/cybergym integration defaults")
    .option("--xbow-path <dir>", "XBOW checkout used by the xbow integration")
    .option("--white-box", "Expose XBOW source paths to the selected agent", false)
    .option("--cybergym-harness <dir>", "CyberGym checkout used by the cybergym integration")
    .option("--cybergym-subset <path>", "Pre-registered CyberGym task-id file")
    .option("--cybergym-difficulty <level>", "CyberGym task difficulty", "level1")
    .option("--cybergym-best-of-n <n>", "CyberGym trajectory count; default strict pass@1", "1")
    .option("--cybergym-max-submits <n>", "Official CyberGym submits per task; default strict pass@1", "1")
    .option("--case-id <id>", "exact case id in a pre-registered manifest slice (repeatable)", collect, [])
    .option("--manifest-id <id>", "sealed slice id (required with --case-id)")
    .option("--variants <json|path>", "JSON array of variant descriptors, or a path to one")
    .option("--variant-id <id>", "Id for the implicit single variant", "champion")
    .option("--harness <id>", "Harness identity for the implicit single variant")
    .option("-m, --model <model>", "Model override for the implicit single variant")
    .option("--runtime <runtime>", "Runtime override (api/claude/codex/…)")
    .option("--depth <depth>", "Scan/audit depth override (quick/deep/…)")
    .option("--pass-at-k <n>", "Attempts per case (pass@k or independent repeats)", "1")
    .option("--attempt-policy <policy>", "pass-at-k or independent-repeat", "pass-at-k")
    .option("--schedule <schedule>", "variant-major or case-major", "variant-major")
    .option("--max-turns <n>", "Hard attack-turn budget per attempt", "40")
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
      let manifest: BenchManifest;
      let integration: BenchIntegration;
      let integrationId: string;
      let attemptPolicy: BenchAttemptPolicy;
      let schedule: TournamentSchedule;
      let executionFactory: VariantExecutionFactory;
      try {
        variants = parseVariants(opts);
        integrationId = String(opts.integration ?? "core");
        attemptPolicy = parseAttemptPolicy(opts.attemptPolicy);
        schedule = parseTournamentSchedule(opts.schedule);

        let sourceManifest: BenchManifest;
        switch (integrationId) {
          case "core": {
            const manifestPath = resolveManifestPath(
              opts.manifest ? String(opts.manifest) : undefined,
            );
            sourceManifest = await loadManifest(manifestPath);
            integration = createCoreBenchIntegration({
              corpusRoot: sourceManifest.corpusRoot,
            });
            break;
          }
          case "xbow":
            sourceManifest = opts.manifest
              ? await loadManifest(String(opts.manifest))
              : createXbowManifestFromPath(
                  opts.xbowPath ? String(opts.xbowPath) : undefined,
                );
            integration = createXbowBenchIntegration({
              ...(opts.xbowPath ? { xbowPath: String(opts.xbowPath) } : {}),
              whiteBox: Boolean(opts.whiteBox),
            });
            break;
          case "cybergym": {
            if (opts.manifest) {
              sourceManifest = await loadManifest(String(opts.manifest));
            } else {
              if (!opts.cybergymSubset) {
                throw new Error("--cybergym-subset is required without --manifest");
              }
              sourceManifest = createCyberGymManifest(
                loadCyberGymTaskIds(String(opts.cybergymSubset)),
                { difficulty: String(opts.cybergymDifficulty) },
              );
            }
            integration = createCyberGymBenchIntegration({
              ...(opts.cybergymHarness
                ? { harnessDir: String(opts.cybergymHarness) }
                : {}),
              difficulty: String(opts.cybergymDifficulty),
              bestOfN: Number(opts.cybergymBestOfN),
              maxSubmits: Number(opts.cybergymMaxSubmits),
            });
            break;
          }
          default:
            throw new Error(`unknown bench integration: ${integrationId}`);
        }

        manifest = selectRunManifest(sourceManifest, {
          caseId: opts.caseId as string[],
          manifestId: opts.manifestId ? String(opts.manifestId) : undefined,
          ciSubset: Boolean(opts.ciSubset),
        });
        const registry = createBenchIntegrationRegistry([integration]);
        executionFactory = createVariantExecutionFactory(registry, integrationId);
        if (opts.tournamentOutput) {
          validateCaptureDestination(String(opts.tournamentOutput), String(opts.ledger));
        }
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exit(2);
        return;
      }

      if (!isJson) {
        console.log("");
        console.log(chalk.red.bold("  0sec bench — canonical tournament"));
        console.log(chalk.dim(`  integration: ${integrationId}`));
        console.log(chalk.dim(`  corpus:      ${manifest.id} (${manifest.cases.length} cases)`));
        console.log(chalk.dim(`  variants:    ${variants.map((v) => v.id).join(", ")}`));
        console.log(chalk.dim(`  attempts:    ${opts.passAtK} (${attemptPolicy}, ${schedule})${opts.ciSubset ? "  (CI subset)" : ""}`));
        console.log("");
      }

      const evaluatorBefore = integration.evaluatorAttestation();
      const measuredTournament = await measureOperation(() => runTournament(manifest, {
        variants,
        executionFactory,
        passAtK: Number(opts.passAtK),
        attemptPolicy,
        schedule,
        maxTurns: Number(opts.maxTurns),
        costCeilingUsd: opts.costCeiling ? Number(opts.costCeiling) : undefined,
        ciSubset: Boolean(opts.ciSubset),
        clock: () => new Date().toISOString(),
        onVariant: isJson
          ? undefined
          : (r) => console.log(chalk.dim(`  · ${r.variant.id} done`)),
      }));
      const tournament = measuredTournament.value;
      const evaluatorAfter = integration.evaluatorAttestation();

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
        meta: {
          integrationId,
          variantIds: tournament.config.variantIds,
          attemptPolicy,
          schedule,
          ciSubset: Boolean(opts.ciSubset),
        },
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
