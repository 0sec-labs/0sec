/**
 * Bench tournament — A/B(/N) variant comparison on the #556 pass@k harness
 * (0sec#656).
 *
 * Runs every variant over the SAME labeled corpus, aggregates each into a
 * scorecard, then computes pairwise deltas with a Wilson-95 non-overlap test
 * as the significance signal and picks a champion. This is the engine that
 * makes every prompt/model/flag change falsifiable: "variant B beats variant
 * A at pass@k (CIs non-overlapping) for less cost-per-success".
 *
 * Pure-ish + deterministic: the scan is injected (via a VariantScanFactory),
 * `aggregateScorecard` is pure, and `generatedAt` is only stamped when a clock
 * is supplied — so a mocked-scan tournament is byte-stable in unit tests.
 */

import type { BenchManifest } from "./manifest.js";
import { selectCiCases } from "./manifest.js";
import type { BenchExecution, VariantExecutionFactory } from "./integration.js";
import type { BenchOracle } from "./oracle.js";
import {
  runBenchCase,
  runBenchSuite,
  type BenchAttemptPolicy,
  type TargetProvisioner,
  type BenchCaseResult,
  type RunSuiteResult,
} from "./runner.js";
import {
  aggregateScorecard,
  type BenchScorecard,
} from "./scorecard.js";
import { snapshotBenchVariant, type BenchVariant, type VariantScanFactory } from "./variant.js";

// ── Result shapes ─────────────────────────────────────────────────────

export interface VariantRunResult {
  variant: BenchVariant;
  scorecard: BenchScorecard;
}

export interface PairwiseDelta {
  /** Variant ids being compared; deltas are `a` minus `b`. */
  a: string;
  b: string;
  successRateDelta: number;
  fpRateDelta: number;
  /** null when either side had no successes (cost-per-success undefined). */
  costPerSuccessDelta: number | null;
  /**
   * True when the two success-rate 95% Wilson intervals DO NOT overlap — the
   * conservative "this difference is real, not noise" signal. A non-significant
   * delta means the corpus/sample isn't yet big enough to separate them.
   */
  significant: boolean;
}

export type TournamentSchedule = "variant-major" | "case-major";

export interface TournamentResult {
  manifestId: string;
  generatedAt?: string;
  config: {
    passAtK: number;
    attemptPolicy: BenchAttemptPolicy;
    maxTurns: number;
    costCeilingUsd: number | null;
    ciSubset: boolean;
    schedule: TournamentSchedule;
    variantIds: string[];
  };
  variants: VariantRunResult[];
  /** All unordered variant pairs, `a` = the better-or-equal of the two. */
  pairwise: PairwiseDelta[];
  /** Winning variant id (see {@link pickChampion}). */
  championId: string;
}

// ── Significance + comparison ─────────────────────────────────────────

/** Do two closed intervals overlap (touching counts as overlap)? */
function intervalsOverlap(x: [number, number], y: [number, number]): boolean {
  return x[0] <= y[1] && y[0] <= x[1];
}

/**
 * Compare two scorecards. Deltas are `a` minus `b`; `significant` is true when
 * their success-rate Wilson-95 intervals do not overlap.
 */
export function compareScorecards(
  a: BenchScorecard,
  b: BenchScorecard,
): Omit<PairwiseDelta, "a" | "b"> {
  const costPerSuccessDelta =
    a.costPerSuccessUsd == null || b.costPerSuccessUsd == null
      ? null
      : a.costPerSuccessUsd - b.costPerSuccessUsd;
  return {
    successRateDelta: a.successRate - b.successRate,
    fpRateDelta: a.fpRate - b.fpRate,
    costPerSuccessDelta,
    significant: !intervalsOverlap(a.successRateCI95, b.successRateCI95),
  };
}

/**
 * Pick the champion: highest success rate, breaking ties by lower FP rate,
 * then by lower cost-per-success (a null cost — no successes — loses to any
 * finite cost), then by id for total determinism.
 */
export function pickChampion(results: VariantRunResult[]): string {
  if (results.length === 0) throw new Error("pickChampion: no variants");
  const ranked = [...results].sort((x, y) => {
    const sx = x.scorecard;
    const sy = y.scorecard;
    if (sy.successRate !== sx.successRate) return sy.successRate - sx.successRate;
    if (sx.fpRate !== sy.fpRate) return sx.fpRate - sy.fpRate;
    const cx = sx.costPerSuccessUsd ?? Number.POSITIVE_INFINITY;
    const cy = sy.costPerSuccessUsd ?? Number.POSITIVE_INFINITY;
    if (cx !== cy) return cx - cy;
    return x.variant.id < y.variant.id ? -1 : x.variant.id > y.variant.id ? 1 : 0;
  });
  return ranked[0].variant.id;
}

/** Every unordered pair, oriented so `a` is the better-or-equal scorecard. */
export function pairwiseDeltas(results: VariantRunResult[]): PairwiseDelta[] {
  const out: PairwiseDelta[] = [];
  for (let i = 0; i < results.length; i++) {
    for (let j = i + 1; j < results.length; j++) {
      let hi = results[i];
      let lo = results[j];
      // Orient by the same ranking pickChampion uses (success, then -fp).
      const better =
        hi.scorecard.successRate > lo.scorecard.successRate ||
        (hi.scorecard.successRate === lo.scorecard.successRate &&
          hi.scorecard.fpRate <= lo.scorecard.fpRate);
      if (!better) [hi, lo] = [lo, hi];
      out.push({ a: hi.variant.id, b: lo.variant.id, ...compareScorecards(hi.scorecard, lo.scorecard) });
    }
  }
  return out;
}

// ── Tournament runner ─────────────────────────────────────────────────

export interface RunTournamentOptions {
  variants: BenchVariant[];
  /**
   * Legacy scan-only factory. Supply this or `executionFactory`, not both.
   * The shared oracle/provisioner fields below remain available for it.
   */
  variantScan?: VariantScanFactory;
  /**
   * Full integration factory. It may select a different scan adapter,
   * provisioner, and oracle per variant while the generic runner remains the
   * one orchestration path.
   */
  executionFactory?: VariantExecutionFactory;
  /** Defaults to the harness ObjectiveOracle (legacy scan-only factory). */
  oracle?: BenchOracle;
  /** Provisioner for legacy scan-only factories. */
  provisioner?: TargetProvisioner;
  passAtK?: number;
  attemptPolicy?: BenchAttemptPolicy;
  maxTurns?: number;
  costCeilingUsd?: number;
  /** Run only the corpus CI subset (cases flagged `ci: true`). */
  ciSubset?: boolean;
  /**
   * `variant-major` completes one variant before the next. `case-major`
   * interleaves variants on each case while keeping every target execution
   * serial, reducing provider/time drift without Docker contention.
   */
  schedule?: TournamentSchedule;
  /** Supply to stamp `generatedAt` on the result + scorecards. */
  clock?: () => string;
  /** Progress hook, one call per completed variant. */
  onVariant?: (result: VariantRunResult, index: number, total: number) => void;
  /** Progress hook, threaded into each suite run (per completed case). */
  onCase?: (result: BenchCaseResult, variantId: string) => void;
}

function resolveExecution(
  variant: Readonly<BenchVariant>,
  opts: RunTournamentOptions,
): BenchExecution {
  if (opts.executionFactory) return opts.executionFactory(variant);
  if (!opts.variantScan) {
    throw new Error("runTournament requires variantScan or executionFactory");
  }
  return {
    scan: opts.variantScan(variant),
    ...(opts.oracle ? { oracle: opts.oracle } : {}),
    ...(opts.provisioner ? { provisioner: opts.provisioner } : {}),
  };
}

function suiteOptions(
  execution: BenchExecution,
  opts: RunTournamentOptions,
) {
  return {
    scan: execution.scan,
    ...(execution.oracle ? { oracle: execution.oracle } : {}),
    ...(execution.provisioner ? { provisioner: execution.provisioner } : {}),
    ...(execution.executionMetadata ? { executionMetadata: execution.executionMetadata } : {}),
    ...(opts.passAtK !== undefined ? { passAtK: opts.passAtK } : {}),
    ...(opts.attemptPolicy ? { attemptPolicy: opts.attemptPolicy } : {}),
    ...(opts.maxTurns !== undefined ? { maxTurns: opts.maxTurns } : {}),
    ...(opts.costCeilingUsd !== undefined ? { costCeilingUsd: opts.costCeilingUsd } : {}),
  };
}

/**
 * Run a full N-variant tournament over the manifest. Every target execution
 * remains serial. `case-major` changes only the ordering, not the execution
 * contract, so it is safe for resource-heavy Docker/QEMU integrations.
 */
export async function runTournament(
  manifest: BenchManifest,
  opts: RunTournamentOptions,
): Promise<TournamentResult> {
  if (opts.variants.length === 0) throw new Error("runTournament: no variants supplied");
  if (opts.variantScan && opts.executionFactory) {
    throw new Error("runTournament accepts variantScan or executionFactory, not both");
  }

  const schedule = opts.schedule ?? "variant-major";
  const variantSnapshots = opts.variants.map((variant) => snapshotBenchVariant(variant));
  const executions = variantSnapshots.map((variant) => resolveExecution(variant, opts));
  const variants: VariantRunResult[] = [];

  if (schedule === "variant-major") {
    for (let i = 0; i < variantSnapshots.length; i++) {
      const variant = variantSnapshots[i];
      const suite = await runBenchSuite(manifest, {
        ...suiteOptions(executions[i], opts),
        ciSubset: opts.ciSubset,
        onCase: opts.onCase ? (result) => opts.onCase!(result, variant.id) : undefined,
      });
      const scorecard = aggregateScorecard(suite, opts.clock ? { clock: opts.clock } : {});
      const result: VariantRunResult = { variant, scorecard };
      variants.push(result);
      opts.onVariant?.(result, i, variantSnapshots.length);
    }
  } else {
    const ciSubset = opts.ciSubset ?? false;
    const cases = ciSubset ? selectCiCases(manifest) : manifest.cases;
    const caseResults = variantSnapshots.map((): BenchCaseResult[] => []);
    for (const c of cases) {
      for (let i = 0; i < variantSnapshots.length; i++) {
        const variant = variantSnapshots[i];
        const result = await runBenchCase(c, suiteOptions(executions[i], opts));
        caseResults[i].push(result);
        opts.onCase?.(result, variant.id);
      }
    }
    for (let i = 0; i < variantSnapshots.length; i++) {
      const suite: RunSuiteResult = {
        manifestId: manifest.id,
        ciSubset,
        passAtK: opts.passAtK ?? 1,
        attemptPolicy: opts.attemptPolicy ?? "pass-at-k",
        maxTurns: opts.maxTurns ?? 40,
        costCeilingUsd: opts.costCeilingUsd ?? null,
        cases: caseResults[i],
      };
      const scorecard = aggregateScorecard(suite, opts.clock ? { clock: opts.clock } : {});
      const result: VariantRunResult = { variant: variantSnapshots[i], scorecard };
      variants.push(result);
      opts.onVariant?.(result, i, variantSnapshots.length);
    }
  }

  const championId = pickChampion(variants);
  const first = variants[0].scorecard;

  return {
    manifestId: manifest.id,
    ...(opts.clock ? { generatedAt: opts.clock() } : {}),
    config: {
      passAtK: first.config.passAtK,
      attemptPolicy: first.config.attemptPolicy,
      maxTurns: first.config.maxTurns,
      costCeilingUsd: first.config.costCeilingUsd,
      ciSubset: first.config.ciSubset,
      schedule,
      variantIds: variantSnapshots.map((v) => v.id),
    },
    variants,
    pairwise: pairwiseDeltas(variants),
    championId,
  };
}

/** One-line-per-variant human summary of a tournament, for CLI/CI logs. */
export function formatTournamentSummary(t: TournamentResult): string {
  const lines: string[] = [];
  for (const v of t.variants) {
    const s = v.scorecard;
    const champ = v.variant.id === t.championId ? " ★" : "";
    const cps = s.costPerSuccessUsd == null ? "n/a" : `$${s.costPerSuccessUsd.toFixed(3)}`;
    const attemptRate = s.config.attemptPolicy === "independent-repeat"
      ? ` attempt ${(s.attemptSuccessRate * 100).toFixed(1)}%`
      : "";
    lines.push(
      `${v.variant.id}${champ}: success ${(s.successRate * 100).toFixed(1)}% ` +
        `[${(s.successRateCI95[0] * 100).toFixed(1)}–${(s.successRateCI95[1] * 100).toFixed(1)}%]` +
        `${attemptRate} fp ${(s.fpRate * 100).toFixed(1)}% cost/success ${cps}`,
    );
  }
  for (const d of t.pairwise) {
    const sig = d.significant ? "significant" : "not significant";
    lines.push(
      `  ${d.a} vs ${d.b}: Δsuccess ${(d.successRateDelta * 100).toFixed(1)}pp, ` +
        `Δfp ${(d.fpRateDelta * 100).toFixed(1)}pp (${sig})`,
    );
  }
  return lines.join("\n");
}
