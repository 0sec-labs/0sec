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
  type BenchExecutionMetadata,
  type BenchOracle,
  type BenchOracleOutcome,
  type BenchScanResult,
  type BenchVerdict,
  type BenchVerificationReceipt,
} from "./oracle.js";

// ── Provisioning ──────────────────────────────────────────────────────

/** A live target handle the scan can point at. */
export interface ProvisionedTarget {
  /** Base URL (web) or opaque locator (kernel/suite task) the scan consumes. */
  target: string;
  /** Per-attempt objective override, e.g. a freshly injected XBOW flag. */
  objective?: BenchCase["objective"];
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
  /** Case with a provisioner-supplied per-attempt objective when applicable. */
  case: BenchCase;
  attemptIndex: number;
  /** Provisioned target locator. */
  target: string;
  /** Full provisioned handle for integration-specific task state. */
  provisioned: ProvisionedTarget;
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
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
  durationMs: number;
  execution?: BenchExecutionMetadata;
  verification?: BenchVerificationReceipt;
}

export type BenchAttemptPolicy = "pass-at-k" | "independent-repeat";

export interface BenchCaseResult {
  id: string;
  name?: string;
  kind: BenchCase["target"]["kind"];
  objective: BenchCase["objective"]["type"];
  knownNegative: boolean;
  tags: string[];
  /** Requested attempts: pass@k in pass-at-k mode, repeats otherwise. */
  passAtK: number;
  attemptPolicy: BenchAttemptPolicy;
  attempts: BenchAttemptResult[];
  /**
   * Case-level verdict. `verified` when ANY attempt proved the objective;
   * `inconclusive` when every attempt was inconclusive. Otherwise `refuted`.
   */
  verdict: BenchVerdict;
  /** True when a known-negative produced a `verified` attempt (a false exploit). */
  falsePositive: boolean;
  costUsd: number;
  attackTurns: number;
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
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
  /**
   * Stop at the first proof (`pass-at-k`) or retain every independent trial
   * (`independent-repeat`). Default: pass-at-k.
   */
  attemptPolicy?: BenchAttemptPolicy;
  /** Run-level turn budget. Per-case `maxTurns` overrides. Default 40. */
  maxTurns?: number;
  /**
   * Cumulative per-case cost ceiling (USD). When cumulative attempt cost
   * reaches it, remaining attempts for that case are skipped. Default: none.
   */
  costCeilingUsd?: number;
  /** Static identity supplied by the selected integration for every attempt. */
  executionMetadata?: BenchExecutionMetadata;
}

const DEFAULT_PASS_AT_K = 1;
const DEFAULT_ATTEMPT_POLICY: BenchAttemptPolicy = "pass-at-k";
const DEFAULT_MAX_TURNS = 40;

const NOOP_PROVISIONER: TargetProvisioner = {
  async up(c) {
    // Hand the scan adapter a sensible locator per kind. Web → empty (the
    // adapter provisions its own); kernel → reproducerRef; source-audit → the
    // package coordinate; suite-task → its suite-owned task reference.
    switch (c.target.kind) {
      case "web":
        return { target: "" };
      case "kernel":
        return { target: c.target.reproducerRef };
      case "source-audit":
        return { target: `${c.target.ecosystem}:${c.target.package}@${c.target.version}` };
      case "suite-task":
        return { target: c.target.taskRef };
    }
  },
  async down() {
    /* nothing to tear down */
  },
};

// ── Single case ───────────────────────────────────────────────────────

/**
 * Run one case under either pass@k or independent-repeat semantics. Both modes
 * provision fresh targets per attempt. Only pass@k short-circuits after proof;
 * independent-repeat retains every scheduled trial for an honest attempt rate.
 */
export async function runBenchCase(
  c: BenchCase,
  opts: RunBenchOptions,
): Promise<BenchCaseResult> {
  const oracle = opts.oracle ?? new ObjectiveOracle();
  const provisioner = opts.provisioner ?? NOOP_PROVISIONER;
  const passAtK = c.passAtK ?? opts.passAtK ?? DEFAULT_PASS_AT_K;
  const attemptPolicy = opts.attemptPolicy ?? DEFAULT_ATTEMPT_POLICY;
  const maxTurns = c.maxTurns ?? opts.maxTurns ?? DEFAULT_MAX_TURNS;

  const attempts: BenchAttemptResult[] = [];
  let cumulativeCost = 0;

  for (let i = 0; i < passAtK; i++) {
    let outcome: BenchOracleOutcome;
    let report: BenchScanResult = {};
    let provisioned: ProvisionedTarget | null = null;

    try {
      provisioned = await provisioner.up(c, i);
      const attemptCase = provisioned.objective
        ? { ...c, objective: provisioned.objective }
        : c;
      report = await opts.scan({
        case: attemptCase,
        attemptIndex: i,
        target: provisioned.target,
        provisioned,
        maxTurns,
      });
      outcome = await oracle.evaluate({ case: attemptCase, report, attemptIndex: i });
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

    const meta = report.benchmarkMeta;
    const costUsd = meta?.estimatedCostUsd ?? 0;
    const execution = {
      ...opts.executionMetadata,
      ...meta?.execution,
      ...(meta?.model ? { model: meta.model } : {}),
      ...(meta?.provider ? { provider: meta.provider } : {}),
      ...(meta?.runtime ? { runtime: meta.runtime } : {}),
    };
    cumulativeCost += costUsd;

    attempts.push({
      attemptIndex: i,
      status: outcome.status,
      confidence: outcome.confidence,
      notes: outcome.notes,
      costUsd,
      attackTurns: meta?.attackTurns ?? 0,
      inputTokens: meta?.inputTokens ?? 0,
      outputTokens: meta?.outputTokens ?? 0,
      totalTokens: meta?.totalTokens ?? (meta?.inputTokens ?? 0) + (meta?.outputTokens ?? 0),
      durationMs: report.durationMs ?? 0,
      ...(Object.keys(execution).length > 0 ? { execution } : {}),
      ...(report.verification ? { verification: report.verification } : {}),
    });

    if (attemptPolicy === "pass-at-k" && outcome.status === "verified") break;
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
    attemptPolicy,
    attempts,
    verdict,
    falsePositive: c.knownNegative && anyVerified,
    costUsd: attempts.reduce((s, a) => s + a.costUsd, 0),
    attackTurns: attempts.reduce((s, a) => s + a.attackTurns, 0),
    inputTokens: attempts.reduce((s, a) => s + a.inputTokens, 0),
    outputTokens: attempts.reduce((s, a) => s + a.outputTokens, 0),
    totalTokens: attempts.reduce((s, a) => s + a.totalTokens, 0),
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
  attemptPolicy: BenchAttemptPolicy;
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
  const attemptPolicy = opts.attemptPolicy ?? DEFAULT_ATTEMPT_POLICY;
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
    attemptPolicy,
    maxTurns,
    costCeilingUsd: opts.costCeilingUsd ?? null,
    cases: results,
  };
}
