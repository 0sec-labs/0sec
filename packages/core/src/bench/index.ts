/**
 * Scan-level pass@k bench harness (0sec#556).
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
  subsetManifest,
  partitionCases,
  BenchManifestSchema,
  BenchCaseSchema,
  BenchObjectiveSchema,
  BenchTargetSchema,
  SourceAuditTargetSchema,
  FindingMatchObjectiveSchema,
  FlagCaptureObjectiveSchema,
  SuiteOracleObjectiveSchema,
  SuiteTaskTargetSchema,
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
  objectiveOracleEvaluatorAttestation,
  objectiveOracleEvaluatorCodeBytes,
  objectiveOracleEvaluatorConfigJson,
  harvestEvidenceText,
} from "./oracle.js";
export type {
  BenchOracle,
  BenchOracleInput,
  BenchOracleOutcome,
  BenchScanResult,
  BenchScanMetadata,
  BenchExecutionMetadata,
  BenchVerificationReceipt,
  BenchVerdict,
  ObjectiveOracleOptions,
  BenchEvaluatorAttestation,
} from "./oracle.js";

export { runBenchCase, runBenchSuite } from "./runner.js";
export type {
  BenchScan,
  BenchScanInput,
  TargetProvisioner,
  ProvisionedTarget,
  BenchAttemptResult,
  BenchAttemptPolicy,
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
  createPackageAuditScanAdapter,
  createDockerWebProvisioner,
  scanReportToBenchResult,
  auditReportToBenchResult,
} from "./adapters.js";
export type {
  AgenticScanAdapterOptions,
  PackageAuditAdapterOptions,
} from "./adapters.js";

export {
  BenchIntegrationRegistry,
  createBenchIntegrationRegistry,
  createVariantExecutionFactory,
} from "./integration.js";
export type {
  BenchExecution,
  BenchIntegration,
  VariantExecutionFactory,
} from "./integration.js";

export { createCoreBenchIntegration } from "./core-integration.js";
export type { CoreBenchIntegrationOptions } from "./core-integration.js";

export { corpusV1Path, exampleManifestPath } from "./paths.js";

export {
  createDefaultVariantScan,
  snapshotBenchVariant,
  withVariantFeatureFlags,
} from "./variant.js";
export type {
  BenchVariant,
  VariantScanFactory,
  DefaultVariantScanOptions,
} from "./variant.js";

export {
  runTournament,
  compareScorecards,
  pickChampion,
  pairwiseDeltas,
  formatTournamentSummary,
} from "./tournament.js";
export type {
  VariantRunResult,
  PairwiseDelta,
  TournamentSchedule,
  TournamentResult,
  RunTournamentOptions,
} from "./tournament.js";

export {
  emptyLedger,
  appendLedgerEntry,
  lastGreen,
  evaluateRegression,
  loadLedger,
  saveLedger,
} from "./ledger.js";

export {
  digestBenchManifest,
  projectResearchImprovementResult,
} from "./improvement.js";
export {
  projectResearchExecutionEvidence,
  researchExecutionEvidenceDigest,
  researchExecutionEvidenceRef,
  researchCandidateChangeDigest,
  researchVariantDescriptor,
  researchVariantDescriptorDigest,
} from "./execution-evidence.js";
export type {
  ResearchExecutionLane,
  ResearchExecutionEvidence,
  ResearchExecutionLaneInput,
  ProjectResearchExecutionEvidenceOptions,
} from "./execution-evidence.js";
export type {
  ResearchScoreSnapshot,
  ResearchNegativeControlSnapshot,
  ResearchImprovementResult,
  ResearchTournamentRun,
  ProjectResearchResultOptions,
} from "./improvement.js";
export type {
  LedgerEntry,
  BenchmarkLedger,
  RegressionThresholds,
  RegressionResult,
} from "./ledger.js";
