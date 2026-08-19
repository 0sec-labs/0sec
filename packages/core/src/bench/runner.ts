/**
 * Bench runner — runs 0sec end-to-end against a manifest at a configurable
 * pass@k and token/turn budget, then hands each attempt's scan result to an
 * oracle for a per-case verdict (0sec#556).
 *
 * Everything that touches the outside world is injectable so the harness is
 * deterministically unit-testable with a mocked LLM / fixed seeds:
 *   - `scan`        — runs the engine against a provisioned target.
 *   - `provisioner` — spins the target up / tears it down (Docker, QEMU, …).
 *   - `oracle`      — grades the scan result (defaults to ObjectiveOracle).
 *
 * The default provisioner reuses the same Docker patterns as the XBOW
 * runner (docker run / compose), and the default scan adapter drives
 * `agenticScan` — but both are optional and replaced wholesale in tests.
 */

import type { BenchCase, BenchManifest } from "./manifest.js";
import { selectCiCases } from "./manifest.js";
import {
  ObjectiveOracle,
  type BenchOracle,
  type BenchOracleOutcome,
  type BenchScanResult,
  type BenchVerdict,
} from "./oracle.js";

// ── Provisioning ──────────────────────────────────────────────────────

/** A live target handle the scan can point at. */
export interface ProvisionedTarget {
  /** Base URL (web) or opaque locator (kernel) the scan adapter consumes. */
  target: string;
  /** Provisioner-specific teardown context. */
  handle?: unknown;
}

export interface TargetProvisioner {
  /** Bring the case's target up. Throw to mark the attempt inconclusive. */
  up(c: BenchCase, attemptIndex: number): Promise<ProvisionedTarget>;
  /** Tear it down. Best-effort; must not throw. */
  down(c: BenchCase, provisioned: ProvisionedTarget): Promise<void>;
}

// ── Scan adapter ──────────────────────────────────────────────────────

export interface BenchScanInput {
  case: BenchCase;
  attemptIndex: number;
  /** Provisioned target locator. */
  target: string;
  /** Turn budget for this attempt (the resolved per-case / per-run value). */
  maxTurns: number;
}

/**
 * Runs the engine against a provisioned target and returns a structural
 * scan result. Implementations should set `error` (rather than throw) when
 * the scan fails to complete so the oracle can return `inconclusive`.
 */
export type BenchScan = (input: BenchScanInput) => Promise<BenchScanResult>;

// ── Result shapes ─────────────────────────────────────────────────────

export interface BenchAttemptResult {
  attemptIndex: number;
  status: BenchVerdict;
  confidence: number | null;
  notes: string;
  costUsd: number;
  attackTurns: number;
  durationMs: number;
}

export interface BenchCaseResult {
  id: string;
  name?: string;
  kind: "web" | "kernel" | "source-audit";
  objective: BenchCase["objective"]["type"];
  knownNegative: boolean;
  tags: string[];
  passAtK: number;
  attempts: BenchAttemptResult[];
  /**
   * Case-level verdict. `verified` when ANY attempt proved the objective
   * (pass@k). `inconclusive` when every attempt was inconclusive (no clean
   * pass/fail). Otherwise `refuted`.
   */
  verdict: BenchVerdict;
  /** True when a known-negative produced a `verified` attempt (a false exploit). */
  falsePositive: boolean;
  costUsd: number;
  attackTurns: number;
}

// ── Run options ───────────────────────────────────────────────────────

export interface RunBenchOptions {
  scan: BenchScan;
  /** Defaults to {@link ObjectiveOracle}. */
  oracle?: BenchOracle;
  /**
   * Required for real runs. Omit only when the injected `scan` adapter
   * provisions its own target (e.g. a fully mocked test adapter).
   */
  provisioner?: TargetProvisioner;
  /** Run-level pass@k. Per-case `passAtK` overrides. Default 1. */
  passAtK?: number;
  /** Run-level turn budget. Per-case `maxTurns` overrides. Default 40. */
  maxTurns?: number;
  /**
   * Cumulative per-case cost ceiling (USD). When cumulative attempt cost
   * reaches it, remaining attempts for that case are skipped. Default: none.
   */
  costCeilingUsd?: number;
}

const DEFAULT_PASS_AT_K = 1;
const DEFAULT_MAX_TURNS = 40;

const NOOP_PROVISIONER: TargetProvisioner = {
  async up(c) {
    // Hand the scan adapter a sensible locator per kind. Web → empty (the
    // adapter provisions its own); kernel → reproducerRef; source-audit → the
    // package coordinate (the audit engine installs it itself).
    switch (c.target.kind) {
      case "web":
        return { target: "" };
      case "kernel":
        return { target: c.target.reproducerRef };
      case "source-audit":
        return { target: `${c.target.ecosystem}:${c.target.package}@${c.target.version}` };
    }
  },
  async down() {
    /* nothing to tear down */
  },
};

// ── Single case ───────────────────────────────────────────────────────

/**
 * Run one case at pass@k. Independent attempts; for a positive case we stop
 * early on the first `verified` (pass@k semantics), and for a known-negative
 * we stop early on the first `verified` too — that's already a confirmed
 * false positive, no need to burn more budget. The per-case cost ceiling
 * also short-circuits the loop.
 */
export async function runBenchCase(
  c: BenchCase,
  opts: RunBenchOptions,
): Promise<BenchCaseResult> {
  const oracle = opts.oracle ?? new ObjectiveOracle();
  const provisioner = opts.provisioner ?? NOOP_PROVISIONER;
  const passAtK = c.passAtK ?? opts.passAtK ?? DEFAULT_PASS_AT_K;
  const maxTurns = c.maxTurns ?? opts.maxTurns ?? DEFAULT_MAX_TURNS;

  const attempts: BenchAttemptResult[] = [];
  let cumulativeCost = 0;

  for (let i = 0; i < passAtK; i++) {
    let outcome: BenchOracleOutcome;
    let report: BenchScanResult = {};
    let provisioned: ProvisionedTarget | null = null;

    try {
      provisioned = await provisioner.up(c, i);
      report = await opts.scan({
        case: c,
        attemptIndex: i,
        target: provisioned.target,
        maxTurns,
      });
      outcome = await oracle.evaluate({ case: c, report, attemptIndex: i });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      report = { error: msg };
      outcome = {
        status: "inconclusive",
        confidence: null,
        notes: `[runner] attempt ${i} failed before grading: ${msg}`,
      };
    } finally {
      if (provisioned) {
        try {
          await provisioner.down(c, provisioned);
        } catch {
          /* best-effort teardown */
        }
      }
    }

    const costUsd = report.benchmarkMeta?.estimatedCostUsd ?? 0;
    const attackTurns = report.benchmarkMeta?.attackTurns ?? 0;
    cumulativeCost += costUsd;

    attempts.push({
      attemptIndex: i,
      status: outcome.status,
      confidence: outcome.confidence,
      notes: outcome.notes,
      costUsd,
      attackTurns,
      durationMs: report.durationMs ?? 0,
    });

    if (outcome.status === "verified") break;
    if (opts.costCeilingUsd != null && cumulativeCost >= opts.costCeilingUsd) break;
  }

  const anyVerified = attempts.some((a) => a.status === "verified");
  const allInconclusive =
    attempts.length > 0 && attempts.every((a) => a.status === "inconclusive");
  const verdict: BenchVerdict = anyVerified
    ? "verified"
    : allInconclusive
      ? "inconclusive"
      : "refuted";

  return {
    id: c.id,
    name: c.name,
    kind: c.target.kind,
    objective: c.objective.type,
    knownNegative: c.knownNegative,
    tags: c.tags,
    passAtK,
    attempts,
    verdict,
    falsePositive: c.knownNegative && anyVerified,
    costUsd: attempts.reduce((s, a) => s + a.costUsd, 0),
    attackTurns: attempts.reduce((s, a) => s + a.attackTurns, 0),
  };
}

// ── Suite ─────────────────────────────────────────────────────────────

export interface RunSuiteOptions extends RunBenchOptions {
  /** Run only the fast CI subset (cases flagged `ci: true`). Default false. */
  ciSubset?: boolean;
  /** Optional progress hook, one call per completed case. */
  onCase?: (result: BenchCaseResult, index: number, total: number) => void;
}

export interface RunSuiteResult {
  manifestId: string;
  ciSubset: boolean;
  passAtK: number;
  maxTurns: number;
  costCeilingUsd: number | null;
  cases: BenchCaseResult[];
}

/**
 * Run every case in the manifest (or the CI subset) sequentially. Sequential
 * by design: Docker/QEMU target provisioning is resource-heavy and parallel
 * runs would contend for ports and memory; the scorecard is order-independent
 * regardless.
 */
export async function runBenchSuite(
  manifest: BenchManifest,
  opts: RunSuiteOptions,
): Promise<RunSuiteResult> {
  const ciSubset = opts.ciSubset ?? false;
  const cases = ciSubset ? selectCiCases(manifest) : manifest.cases;
  const passAtK = opts.passAtK ?? DEFAULT_PASS_AT_K;
  const maxTurns = opts.maxTurns ?? DEFAULT_MAX_TURNS;

  const results: BenchCaseResult[] = [];
  for (let i = 0; i < cases.length; i++) {
    const result = await runBenchCase(cases[i], opts);
    results.push(result);
    opts.onCase?.(result, i, cases.length);
  }

  return {
    manifestId: manifest.id,
    ciSubset,
    passAtK,
    maxTurns,
    costCeilingUsd: opts.costCeilingUsd ?? null,
    cases: results,
  };
}
