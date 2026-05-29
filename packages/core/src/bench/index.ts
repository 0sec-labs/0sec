/**
 * Scan-level pass@k bench harness (pwnkit#556).
 *
 * Public surface:
 *   - manifest:  loader + zod schema for the (corpus-referencing) manifest.
 *   - oracle:    deterministic objective grader + the BenchOracle contract
 *                (verified|refuted|inconclusive), shared with the cloud
 *                verify runners so they can be adapted in from services.
 *   - runner:    pass@k + token/turn-budget execution over the manifest.
 *   - scorecard: scan-level aggregation (success rate, FP rate vs
 *                known-negatives, cost-per-success) + the CI regression gate.
 *   - adapters:  production defaults (agenticScan + Docker provisioner).
 *
 * See `bench/example-manifest.json` for the manifest shape. The real
 * uncontaminated/post-cutoff corpus is referenced, never committed.
 */

export {
  parseManifest,
  loadManifest,
  selectCiCases,
  partitionCases,
  BenchManifestSchema,
  BenchCaseSchema,
  BenchObjectiveSchema,
  BenchTargetSchema,
} from "./manifest.js";
export type {
  BenchManifest,
  BenchCase,
  BenchTarget,
  BenchObjective,
  BenchObjectiveType,
} from "./manifest.js";

export {
  ObjectiveOracle,
  objectiveOracle,
  harvestEvidenceText,
} from "./oracle.js";
export type {
  BenchOracle,
  BenchOracleInput,
  BenchOracleOutcome,
  BenchScanResult,
  BenchVerdict,
  ObjectiveOracleOptions,
} from "./oracle.js";

export { runBenchCase, runBenchSuite } from "./runner.js";
export type {
  BenchScan,
  BenchScanInput,
  TargetProvisioner,
  ProvisionedTarget,
  BenchAttemptResult,
  BenchCaseResult,
  RunBenchOptions,
  RunSuiteOptions,
  RunSuiteResult,
} from "./runner.js";

export {
  aggregateScorecard,
  evaluateGate,
  formatScorecardSummary,
  wilson95,
} from "./scorecard.js";
export type {
  BenchScorecard,
  AggregateOptions,
  GateThresholds,
  GateResult,
} from "./scorecard.js";

export {
  createAgenticScanAdapter,
  createDockerWebProvisioner,
  scanReportToBenchResult,
} from "./adapters.js";
export type { AgenticScanAdapterOptions } from "./adapters.js";
