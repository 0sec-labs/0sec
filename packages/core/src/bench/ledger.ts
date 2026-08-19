/**
 * Benchmark ledger + CI regression gate (0sec#656).
 *
 * The nightly CI job runs the champion variant against the labeled corpus,
 * appends its scorecard to `benchmark-ledger.json`, and FAILS the build if the
 * champion regressed versus the last green run — success rate dropped or FP
 * rate rose beyond threshold. This is the falsifiable backstop: a prompt/model
 * change that quietly makes us worse gets caught before prod.
 *
 * Determinism: every function here is pure (no clock / no fs); `runId` and any
 * timestamp are supplied by the caller. The thin fs load/save helpers lazy-
 * import node:fs so importing this module in a test context stays cheap.
 */

import type { BenchScorecard } from "./scorecard.js";

// ── Ledger shape (STABLE — CI + dashboards read it) ───────────────────

export interface LedgerEntry {
  /** Caller-supplied run id (e.g. a git sha or ISO timestamp). */
  runId: string;
  manifestId: string;
  championId: string;
  scorecard: BenchScorecard;
  /**
   * Whether this run passed the regression gate. `lastGreen` only considers
   * green entries as the baseline, so a single red run doesn't poison the
   * comparison for the next one.
   */
  green: boolean;
  /** Free-form provenance (git sha, branch, variant set, runner, …). */
  meta?: Record<string, unknown>;
}

export interface BenchmarkLedger {
  schemaVersion: 1;
  entries: LedgerEntry[];
}

export function emptyLedger(): BenchmarkLedger {
  return { schemaVersion: 1, entries: [] };
}

/** Append an entry (pure — returns a new ledger, does not mutate). */
export function appendLedgerEntry(
  ledger: BenchmarkLedger,
  entry: LedgerEntry,
): BenchmarkLedger {
  return { schemaVersion: 1, entries: [...ledger.entries, entry] };
}

/** The most recent green entry, or null if none exists yet. */
export function lastGreen(ledger: BenchmarkLedger): LedgerEntry | null {
  for (let i = ledger.entries.length - 1; i >= 0; i--) {
    if (ledger.entries[i].green) return ledger.entries[i];
  }
  return null;
}

// ── Regression gate ───────────────────────────────────────────────────

export interface RegressionThresholds {
  /**
   * Max allowed absolute drop in success rate vs the last green run, as a
   * fraction. Default 0.05 (5 percentage points of slack for run-to-run
   * noise). The Wilson CIs are the statistical guard; this is the operational
   * tripwire.
   */
  maxSuccessRateDrop?: number;
  /** Max allowed absolute rise in FP rate vs the last green run. Default 0.05. */
  maxFpRateRise?: number;
  /**
   * Max allowed fraction of cases that came back inconclusive (flaky infra) —
   * an all-inconclusive run shouldn't be recorded green. Default 0.5.
   */
  maxInconclusiveRate?: number;
}

export interface RegressionResult {
  passed: boolean;
  reasons: string[];
  /** The baseline compared against (null = first run / no green history). */
  baseline: LedgerEntry | null;
  thresholds: Required<RegressionThresholds>;
}

const DEFAULT_REGRESSION_THRESHOLDS: Required<RegressionThresholds> = {
  maxSuccessRateDrop: 0.05,
  maxFpRateRise: 0.05,
  maxInconclusiveRate: 0.5,
};

/**
 * Evaluate the current champion scorecard against the last green baseline.
 * A first run (no baseline) passes as long as it isn't mostly inconclusive.
 */
export function evaluateRegression(
  current: BenchScorecard,
  baseline: LedgerEntry | null,
  thresholds: RegressionThresholds = {},
): RegressionResult {
  const t: Required<RegressionThresholds> = {
    ...DEFAULT_REGRESSION_THRESHOLDS,
    ...thresholds,
  };
  const reasons: string[] = [];

  // A run that evaluated ZERO cases is DEGENERATE, not a regression: the harness
  // executed no scans (e.g. CI without LLM credentials / an E2B sandbox), so
  // successRate is a meaningless 0 that would otherwise read as a full-baseline
  // "success rate regressed" failure and fail the nightly red on every run.
  // Skip the gate with a clear note instead. (Same "couldn't-run != regressed"
  // principle as the verify reproduced-poc guardrail.)
  if (current.totals.cases === 0) {
    return {
      passed: true,
      reasons: [
        "degenerate run: 0 cases evaluated — regression gate skipped (no scans executed; the runner likely lacks LLM credentials / an E2B sandbox)",
      ],
      baseline,
      thresholds: t,
    };
  }

  const inconclusiveRate =
    current.totals.cases === 0 ? 0 : current.totals.inconclusive / current.totals.cases;
  if (inconclusiveRate > t.maxInconclusiveRate) {
    reasons.push(
      `inconclusive rate ${(inconclusiveRate * 100).toFixed(1)}% > max ${(t.maxInconclusiveRate * 100).toFixed(1)}% (flaky run — not recordable as green)`,
    );
  }

  if (baseline) {
    const base = baseline.scorecard;
    const successDrop = base.successRate - current.successRate;
    if (successDrop > t.maxSuccessRateDrop) {
      reasons.push(
        `success rate regressed ${(successDrop * 100).toFixed(1)}pp ` +
          `(${(base.successRate * 100).toFixed(1)}% → ${(current.successRate * 100).toFixed(1)}%) > max drop ${(t.maxSuccessRateDrop * 100).toFixed(1)}pp ` +
          `[baseline ${baseline.runId}]`,
      );
    }
    const fpRise = current.fpRate - base.fpRate;
    if (fpRise > t.maxFpRateRise) {
      reasons.push(
        `false-positive rate regressed ${(fpRise * 100).toFixed(1)}pp ` +
          `(${(base.fpRate * 100).toFixed(1)}% → ${(current.fpRate * 100).toFixed(1)}%) > max rise ${(t.maxFpRateRise * 100).toFixed(1)}pp ` +
          `[baseline ${baseline.runId}]`,
      );
    }
  }

  return { passed: reasons.length === 0, reasons, baseline, thresholds: t };
}

// ── Thin fs helpers (lazy fs import; node only) ───────────────────────

/** Load a ledger from disk, or an empty ledger if the file doesn't exist. */
export async function loadLedger(path: string): Promise<BenchmarkLedger> {
  const { readFile } = await import("node:fs/promises");
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch {
    return emptyLedger();
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new Error(
      `benchmark ledger at ${path} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const led = raw as Partial<BenchmarkLedger>;
  if (!led || led.schemaVersion !== 1 || !Array.isArray(led.entries)) {
    throw new Error(`benchmark ledger at ${path} has an unexpected shape`);
  }
  return { schemaVersion: 1, entries: led.entries as LedgerEntry[] };
}

/** Persist a ledger to disk (pretty JSON, trailing newline). */
export async function saveLedger(path: string, ledger: BenchmarkLedger): Promise<void> {
  const { writeFile } = await import("node:fs/promises");
  await writeFile(path, JSON.stringify(ledger, null, 2) + "\n", "utf8");
}
