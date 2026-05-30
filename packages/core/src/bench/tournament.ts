/**
 * Bench tournament — A/B(/N) variant comparison on the #556 pass@k harness
 * (pwnkit#656).
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
import type { BenchOracle } from "./oracle.js";
import {
  runBenchSuite,
  type TargetProvisioner,
  type BenchCaseResult,
} from "./runner.js";
import {
  aggregateScorecard,
  type BenchScorecard,
} from "./scorecard.js";
import type { BenchVariant, VariantScanFactory } from "./variant.js";

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

export interface TournamentResult {
  manifestId: string;
  generatedAt?: string;
  config: {
    passAtK: number;
    maxTurns: number;
    costCeilingUsd: number | null;
    ciSubset: boolean;
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
  /** Builds the scan for each variant. Injected so tests use mocked scans. */
  variantScan: VariantScanFactory;
  /** Defaults to the harness ObjectiveOracle (see runner.ts). */
  oracle?: BenchOracle;
  /** Provisioner for web/kernel cases; source-audit needs none. */
  provisioner?: TargetProvisioner;
  passAtK?: number;
  maxTurns?: number;
  costCeilingUsd?: number;
  /** Run only the corpus CI subset (cases flagged `ci: true`). */
  ciSubset?: boolean;
  /** Supply to stamp `generatedAt` on the result + scorecards. */
  clock?: () => string;
  /** Progress hook, one call per completed variant. */
  onVariant?: (result: VariantRunResult, index: number, total: number) => void;
  /** Progress hook, threaded into each suite run (per completed case). */
  onCase?: (result: BenchCaseResult, variantId: string) => void;
}

/**
 * Run a full N-variant tournament over the manifest. Variants run
 * sequentially (each suite already provisions resource-heavy targets
 * sequentially; running variants in parallel would contend further).
 */
export async function runTournament(
  manifest: BenchManifest,
  opts: RunTournamentOptions,
): Promise<TournamentResult> {
  if (opts.variants.length === 0) throw new Error("runTournament: no variants supplied");

  const variants: VariantRunResult[] = [];
  for (let i = 0; i < opts.variants.length; i++) {
    const variant = opts.variants[i];
    const suite = await runBenchSuite(manifest, {
      scan: opts.variantScan(variant),
      oracle: opts.oracle,
      provisioner: opts.provisioner,
      passAtK: opts.passAtK,
      maxTurns: opts.maxTurns,
      costCeilingUsd: opts.costCeilingUsd,
      ciSubset: opts.ciSubset,
      onCase: opts.onCase ? (r) => opts.onCase!(r, variant.id) : undefined,
    });
    const scorecard = aggregateScorecard(suite, opts.clock ? { clock: opts.clock } : {});
    const result: VariantRunResult = { variant, scorecard };
    variants.push(result);
    opts.onVariant?.(result, i, opts.variants.length);
  }

  const championId = pickChampion(variants);
  const first = variants[0].scorecard;

  return {
    manifestId: manifest.id,
    ...(opts.clock ? { generatedAt: opts.clock() } : {}),
    config: {
      passAtK: first.config.passAtK,
      maxTurns: first.config.maxTurns,
      costCeilingUsd: first.config.costCeilingUsd,
      ciSubset: first.config.ciSubset,
      variantIds: opts.variants.map((v) => v.id),
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
    lines.push(
      `${v.variant.id}${champ}: success ${(s.successRate * 100).toFixed(1)}% ` +
        `[${(s.successRateCI95[0] * 100).toFixed(1)}–${(s.successRateCI95[1] * 100).toFixed(1)}%] ` +
        `fp ${(s.fpRate * 100).toFixed(1)}% cost/success ${cps}`,
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
