/**
 * Lens-synthesis stage 3 — VALIDATE (fail-closed).
 *
 * Route a synthesized candidate lens through the bench A/B tournament: run the
 * BASELINE (current registry only) and the CHALLENGER (registry + candidate)
 * over the same corpus, aggregate each into a scorecard with the bench harness'
 * own `aggregateScorecard`, and adjudicate with `pickChampion`.
 *
 * A candidate is a champion ONLY when it clears every gate:
 *   1. caughtMiss       — every POSITIVE fixture surfaces under the challenger.
 *   2. noFpRegression   — the challenger adds NO false positive over baseline
 *                         on the negative-control corpus.
 *   3. strictlyBetter   — the challenger's success rate is strictly above
 *                         baseline (it catches something baseline missed).
 *   4. isChampion       — `pickChampion` picks the challenger.
 *
 * Fail-closed everywhere: a probe error grades a fixture `inconclusive` (never
 * `verified`), so an error can neither satisfy "catch the miss" nor register a
 * false positive; and gate 2 is checked SEPARATELY from `pickChampion` (which
 * ranks by success rate first) precisely so a candidate that catches the miss
 * but FP-regresses is still rejected. This reuses the bench scorecard/champion
 * primitives verbatim — it does not reimplement scoring.
 */

import { statSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import type { RuntimeMode } from "@0sec/shared";
import {
  aggregateScorecard,
  pickChampion,
  type BenchAttemptResult,
  type BenchCaseResult,
  type BenchScorecard,
  type BenchVerdict,
  type RunSuiteResult,
  type VariantRunResult,
} from "../../bench/index.js";
import { loadAppsecFinderLenses } from "../appsec-catalog.js";
import { runHuntScan, type FinderLens } from "../hunt-scan.js";
import type {
  LensProbe,
  LensProbeOutcome,
  LensScorecardSummary,
  LensValidationReport,
  SynthesizedArchetype,
  ValidationCorpus,
  ValidationFixture,
} from "./types.js";

// ── Default finder-backed probe ───────────────────────────────────────────

export interface FinderLensProbeOptions {
  /** Runtime forwarded to the finder. Default "auto". */
  runtime?: RuntimeMode;
  /** Finder models (diversity). Default: the configured provider. */
  models?: string[];
  /** Per-finder depth. Default "quick". */
  depth?: "quick" | "deep";
  /** Max finders in flight. Default 4. */
  concurrency?: number;
  /**
   * The baseline lens set the challenger is measured against. Defaults to the
   * CURRENT appsec registry — so the A/B isolates the candidate lens' effect.
   */
  baseLenses?: () => FinderLens[];
  log?: (msg: string) => void;
}

/** Resolve a fixture path into a (sourceRoot, candidate path) pair for runHuntScan. */
function fixtureTarget(fixture: ValidationFixture): { sourceRoot: string; candidatePath: string } {
  const abs = resolve(fixture.path);
  let isDir = false;
  try {
    isDir = statSync(abs).isDirectory();
  } catch {
    // A missing path is left to the finder; treat it as a directory root so the
    // scan surfaces nothing rather than throwing here.
    isDir = true;
  }
  return isDir
    ? { sourceRoot: abs, candidatePath: "." }
    : { sourceRoot: dirname(abs), candidatePath: basename(abs) };
}

/**
 * A real, manually-runnable probe: run the finder over the fixture with the
 * baseline lens set (candidateLens = null) or baseline + candidate, and report
 * whether ANY finding was surfaced. No verify gate is wired — the probe asks
 * only "did the finder SURFACE this class", which is the lens-coverage question
 * validation grades. Any thrown error is captured as `outcome.error` so the
 * gate can grade the fixture inconclusive (fail-closed).
 */
export function makeFinderLensProbe(opts: FinderLensProbeOptions = {}): LensProbe {
  const baseLenses = opts.baseLenses ?? loadAppsecFinderLenses;
  return async (candidateLens, fixture) => {
    try {
      const lenses = candidateLens ? [...baseLenses(), candidateLens] : [...baseLenses()];
      const { sourceRoot, candidatePath } = fixtureTarget(fixture);
      const result = await runHuntScan({
        sourceRoot,
        candidates: [{ path: candidatePath }],
        runtime: opts.runtime ?? "auto",
        ...(opts.models ? { models: opts.models } : {}),
        depth: opts.depth ?? "quick",
        concurrency: opts.concurrency ?? 4,
        lenses,
        ...(opts.log ? { log: opts.log } : {}),
      });
      return { surfaced: result.findings.length > 0 };
    } catch (err) {
      return { surfaced: false, error: err instanceof Error ? err.message : String(err) };
    }
  };
}

// ── Scorecard construction (reuses aggregateScorecard) ────────────────────

/** One probed fixture → a bench case result (the harness' own shape). */
function fixtureCase(
  fixture: ValidationFixture,
  knownNegative: boolean,
  outcome: LensProbeOutcome,
): BenchCaseResult {
  const status: BenchVerdict = outcome.error
    ? "inconclusive"
    : outcome.surfaced
      ? "verified"
      : "refuted";
  const attempt: BenchAttemptResult = {
    attemptIndex: 0,
    status,
    confidence: null,
    notes: outcome.error ?? (outcome.surfaced ? "finder surfaced a finding" : "finder surfaced nothing"),
    costUsd: 0,
    attackTurns: 0,
    inputTokens: 0,
    outputTokens: 0,
    totalTokens: 0,
    durationMs: 0,
  };
  return {
    id: fixture.id,
    kind: "source-audit",
    objective: "finding-match",
    knownNegative,
    tags: [],
    passAtK: 1,
    attemptPolicy: "pass-at-k",
    attempts: [attempt],
    verdict: status,
    falsePositive: knownNegative && status === "verified",
    costUsd: 0,
    attackTurns: 0,
    inputTokens: 0,
    outputTokens: 0,
    totalTokens: 0,
  };
}

/** Probe the whole corpus for one variant (candidateLens = null for baseline). */
async function scoreVariant(
  variantId: string,
  candidateLens: FinderLens | null,
  corpus: ValidationCorpus,
  probe: LensProbe,
): Promise<BenchScorecard> {
  const cases: BenchCaseResult[] = [];
  for (const fx of corpus.positives) {
    cases.push(fixtureCase(fx, false, await probe(candidateLens, fx)));
  }
  for (const fx of corpus.negativeControls) {
    cases.push(fixtureCase(fx, true, await probe(candidateLens, fx)));
  }
  const suite: RunSuiteResult = {
    manifestId: `lens-validation:${variantId}`,
    ciSubset: false,
    passAtK: 1,
    attemptPolicy: "pass-at-k",
    maxTurns: 1,
    costCeilingUsd: null,
    cases,
  };
  return aggregateScorecard(suite);
}

function summarize(variantId: string, s: BenchScorecard): LensScorecardSummary {
  return {
    variantId,
    successRate: s.successRate,
    fpRate: s.fpRate,
    verified: s.totals.verified,
    falsePositives: s.falsePositives,
  };
}

// ── The gate ────────────────────────────────────────────────────────────────

export interface ValidateOptions {
  probe: LensProbe;
  log?: (msg: string) => void;
}

/**
 * Validate ONE synthesized candidate. Never throws: an internal error resolves
 * to a `passed: false` report (fail-closed), so a validation fault can never
 * register a lens.
 */
export async function validateCandidateLens(
  archetype: SynthesizedArchetype,
  corpus: ValidationCorpus,
  opts: ValidateOptions,
): Promise<LensValidationReport> {
  const lensId = archetype.content.id;
  const candidateLens: FinderLens = { id: lensId, challengeHint: archetype.content.challenge_hint };
  const baselineSummary: LensScorecardSummary = { variantId: "baseline", successRate: 0, fpRate: 0, verified: 0, falsePositives: 0 };
  const challengerSummary: LensScorecardSummary = { variantId: "challenger", successRate: 0, fpRate: 0, verified: 0, falsePositives: 0 };

  if (corpus.positives.length === 0) {
    return {
      lensId, isChampion: false, caughtMiss: false, noFpRegression: false, passed: false,
      reason: "no positive fixtures — cannot prove the lens catches the miss (fail-closed)",
      baseline: baselineSummary, challenger: challengerSummary,
    };
  }

  let baseline: BenchScorecard;
  let challenger: BenchScorecard;
  try {
    baseline = await scoreVariant("baseline", null, corpus, opts.probe);
    challenger = await scoreVariant("challenger", candidateLens, corpus, opts.probe);
  } catch (err) {
    return {
      lensId, isChampion: false, caughtMiss: false, noFpRegression: false, passed: false,
      reason: `validation errored (fail-closed): ${err instanceof Error ? err.message : String(err)}`,
      baseline: baselineSummary, challenger: challengerSummary,
    };
  }

  const base = summarize("baseline", baseline);
  const chal = summarize("challenger", challenger);

  // Gate 1: every positive fixture must be verified under the challenger. An
  // inconclusive (probe error) positive fails this — fail-closed.
  const verifiedPositives = challenger.cases.filter((c) => !c.knownNegative && c.verdict === "verified").length;
  const caughtMiss = verifiedPositives === corpus.positives.length;

  // Gate 2: no false-positive regression on the negative controls. Checked
  // independently of pickChampion (which ranks by success rate first).
  const noFpRegression = chal.falsePositives <= base.falsePositives && chal.fpRate <= base.fpRate;

  // Gate 3: a strict improvement (it catches something baseline missed).
  const strictlyBetter = chal.successRate > base.successRate;

  // Gate 4: the tournament champion is the challenger.
  const variants: VariantRunResult[] = [
    { variant: { id: "baseline" }, scorecard: baseline },
    { variant: { id: "challenger" }, scorecard: challenger },
  ];
  const isChampion = pickChampion(variants) === "challenger";

  const passed = caughtMiss && noFpRegression && strictlyBetter && isChampion;
  const reasonParts: string[] = [];
  if (!caughtMiss) reasonParts.push(`missed ${corpus.positives.length - verifiedPositives}/${corpus.positives.length} positive fixture(s)`);
  if (!noFpRegression) reasonParts.push(`FP regression: challenger ${chal.falsePositives} vs baseline ${base.falsePositives} false positive(s)`);
  if (!strictlyBetter) reasonParts.push(`no improvement over baseline (success ${(chal.successRate * 100).toFixed(0)}% vs ${(base.successRate * 100).toFixed(0)}%)`);
  if (!isChampion) reasonParts.push("challenger is not the tournament champion");
  const reason = passed
    ? `champion: caught ${verifiedPositives}/${corpus.positives.length} positives, ${chal.falsePositives} FP (baseline ${base.falsePositives}), success ${(chal.successRate * 100).toFixed(0)}% > ${(base.successRate * 100).toFixed(0)}%`
    : `rejected: ${reasonParts.join("; ")}`;

  opts.log?.(`[lens-synth] validate ${lensId}: ${reason}`);
  return { lensId, isChampion, caughtMiss, noFpRegression, passed, reason, baseline: base, challenger: chal };
}
