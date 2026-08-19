import type { Command } from "commander";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  loadManifest,
  objectiveOracleEvaluatorAttestation,
  objectiveOracleEvaluatorCodeBytes,
  objectiveOracleEvaluatorConfigJson,
  runTournament,
  subsetManifest,
  type BenchManifest,
  type TournamentResult,
} from "@0sec/core";

import { sha256Bytes, writeCanonicalJsonAtomic } from "./bench-improvement.js";

export const CALIBRATION_CHAMPION_ID = "calibration-champion";
export const CALIBRATION_CHALLENGER_ID = "calibration-challenger";

export interface ZeroCostCalibrationEnvelope {
  schemaVersion: 1;
  calibration: {
    schemaVersion: 1;
    mode: "zero-cost-no-uplift";
    networkAllowed: false;
    providerAllowed: false;
    expectedOutcome: "reject";
  };
  elapsedMs: 0;
  evaluatorBefore: ReturnType<typeof objectiveOracleEvaluatorAttestation>;
  evaluatorAfter: ReturnType<typeof objectiveOracleEvaluatorAttestation>;
  manifest: BenchManifest;
  tournament: TournamentResult;
}

/** Materialize the exact evaluator bytes named by the sealed attestations. */
export function materializeObjectiveOracleEvaluator(outputDirectoryValue: string): void {
  const outputDirectory = resolve(outputDirectoryValue);
  if (existsSync(outputDirectory)) {
    throw new Error(`evaluator output already exists: ${outputDirectory}`);
  }
  mkdirSync(outputDirectory, { recursive: false, mode: 0o700 });
  try {
    const code = objectiveOracleEvaluatorCodeBytes();
    const config = Buffer.from(objectiveOracleEvaluatorConfigJson());
    const attestation = objectiveOracleEvaluatorAttestation();
    if (sha256Bytes(code) !== attestation.codeDigest) {
      throw new Error("loaded evaluator code bytes do not match their attestation");
    }
    if (sha256Bytes(config) !== attestation.configDigest) {
      throw new Error("evaluator config bytes do not match their attestation");
    }
    const bundle = Buffer.from(`${JSON.stringify({
      schemaVersion: 1,
      codeDigest: attestation.codeDigest,
      configDigest: attestation.configDigest,
    })}\n`);
    if (sha256Bytes(bundle) !== attestation.bundleDigest) {
      throw new Error("evaluator bundle bytes do not match their attestation");
    }
    writeFileSync(join(outputDirectory, "evaluator.js"), code, { flag: "wx", mode: 0o600 });
    writeFileSync(join(outputDirectory, "evaluator-config.json"), config, { flag: "wx", mode: 0o600 });
    writeFileSync(join(outputDirectory, "evaluator-bundle.json"), bundle, { flag: "wx", mode: 0o600 });
    writeFileSync(join(outputDirectory, "COMPLETE"), "{\"schemaVersion\":1}\n", {
      flag: "wx",
      mode: 0o600,
    });
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    throw error;
  }
}

/**
 * Exercise the real tournament runner and ObjectiveOracle without executing a
 * target, provider, model, or network operation. This is contract calibration,
 * not evidence that either variant can discover a vulnerability.
 */
export async function runZeroCostCalibration(
  manifest: BenchManifest,
): Promise<ZeroCostCalibrationEnvelope> {
  if (manifest.cases.length === 0) throw new Error("calibration manifest must not be empty");

  const evaluatorBefore = objectiveOracleEvaluatorAttestation();
  const tournament = await runTournament(manifest, {
    variants: [
      { id: CALIBRATION_CHAMPION_ID, label: "zero-cost calibration champion" },
      { id: CALIBRATION_CHALLENGER_ID, label: "zero-cost calibration challenger" },
    ],
    variantScan: () => async () => ({
      findings: [],
      benchmarkMeta: { estimatedCostUsd: 0, attackTurns: 0, totalTokens: 0 },
      durationMs: 0,
    }),
    passAtK: 1,
    maxTurns: 1,
  });
  const evaluatorAfter = objectiveOracleEvaluatorAttestation();

  if (JSON.stringify(evaluatorBefore) !== JSON.stringify(evaluatorAfter)) {
    throw new Error("ObjectiveOracle changed during calibration");
  }
  for (const variant of tournament.variants) {
    if (
      variant.scorecard.totals.verified !== 0 ||
      variant.scorecard.totals.inconclusive !== 0 ||
      variant.scorecard.falsePositives !== 0 ||
      variant.scorecard.successRate !== 0 ||
      variant.scorecard.fpRate !== 0 ||
      variant.scorecard.costPerSuccessUsd !== null ||
      variant.scorecard.totalCostUsd !== 0 ||
      variant.scorecard.totalAttackTurns !== 0
    ) {
      throw new Error("zero-cost calibration did not produce a refuted-only zero-uplift scorecard");
    }
    if (variant.scorecard.cases.some((entry) =>
      entry.attempts.length !== 1 ||
      entry.attempts[0]?.costUsd !== 0 ||
      entry.attempts[0]?.attackTurns !== 0 ||
      entry.attempts[0]?.durationMs !== 0
    )) {
      throw new Error("zero-cost calibration emitted an invalid attempt receipt");
    }
  }
  const delta = tournament.pairwise[0];
  if (
    tournament.pairwise.length !== 1 ||
    delta?.successRateDelta !== 0 ||
    delta.fpRateDelta !== 0 ||
    delta.costPerSuccessDelta !== null ||
    delta.significant !== false
  ) {
    throw new Error("zero-cost calibration did not produce the fixed non-significant zero delta");
  }

  return {
    schemaVersion: 1,
    calibration: {
      schemaVersion: 1,
      mode: "zero-cost-no-uplift",
      networkAllowed: false,
      providerAllowed: false,
      expectedOutcome: "reject",
    },
    elapsedMs: 0,
    evaluatorBefore,
    evaluatorAfter,
    manifest,
    tournament,
  };
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

export function registerBenchCalibrationCommand(bench: Command): void {
  bench
    .command("calibrate")
    .description("Emit a sealed, provider-free no-uplift tournament for 0research calibration")
    .requiredOption("--manifest <path>", "corpus manifest path")
    .option("--case-id <id>", "exact pre-registered case id (repeatable)", collect, [])
    .requiredOption("--manifest-id <id>", "sealed calibration slice id")
    .requiredOption("--tournament-output <path>", "create-once sealed calibration evidence")
    .option("--evaluator-output-dir <path>", "create-once exact evaluator code/config/bundle")
    .action(async (opts) => {
      const caseIds = opts.caseId as string[];
      if (caseIds.length === 0) throw new Error("--case-id must be supplied at least once");
      if (existsSync(resolve(String(opts.tournamentOutput)))) {
        throw new Error(`tournament output already exists: ${resolve(String(opts.tournamentOutput))}`);
      }
      if (opts.evaluatorOutputDir && existsSync(resolve(String(opts.evaluatorOutputDir)))) {
        throw new Error(`evaluator output already exists: ${resolve(String(opts.evaluatorOutputDir))}`);
      }
      const source = await loadManifest(String(opts.manifest));
      const manifest = subsetManifest(source, caseIds, String(opts.manifestId));
      const envelope = await runZeroCostCalibration(manifest);
      if (opts.evaluatorOutputDir) {
        materializeObjectiveOracleEvaluator(String(opts.evaluatorOutputDir));
        const materialized = objectiveOracleEvaluatorAttestation();
        if (JSON.stringify(materialized) !== JSON.stringify(envelope.evaluatorAfter)) {
          throw new Error("materialized evaluator changed after calibration execution");
        }
      }
      writeCanonicalJsonAtomic(String(opts.tournamentOutput), envelope);
      process.stdout.write(`${String(opts.tournamentOutput)}\n`);
    });
}
