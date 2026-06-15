/**
 * Finding Triage Module
 *
 * Layer 1 (feature extraction) of the hybrid triage model.
 * Future layers: CodeBERT embeddings, cross-attention fusion, structured LLM verify.
 */

export { extractFeatures, FEATURE_NAMES } from "./feature-extractor.js";
export {
  canAutoSuppress,
  canAutoSuppressDetailed,
  AUTO_SUPPRESS_PROTECTED_SEVERITIES,
  AUTO_SUPPRESS_HIGH_IMPACT_CATEGORIES,
} from "./can-auto-suppress.js";
export type { AutoSuppressDecision, AutoSuppressGuard } from "./can-auto-suppress.js";
export {
  isDisclosureWorthy,
  evidenceKindForFinding,
  VERIFY_EVIDENCE_KINDS,
  VERIFY_EVIDENCE_KINDS_ENGINE_EXT,
} from "./verify-verdict.js";
export type {
  VerifyVerdict,
  VerifyOutcome,
  VerifySignal,
  VerifyEvidenceKind,
  VerdictLike,
  DisclosureDecision,
} from "./verify-verdict.js";
export { isHoldingItWrong } from "./holding-it-wrong.js";
export type { HoldingItWrongResult } from "./holding-it-wrong.js";
export {
  checkPublishability,
  checkThreatModelExclusion,
  classifyDedup,
  isLatestVersion,
  isPublicApiReachable,
  isPublishable,
  PUBLISHABLE_DECISIONS,
} from "./publishability.js";
export type {
  PublishabilityResult,
  PublishabilityInputs,
  AdvisoryRef,
  AdvisorySource,
  AdvisoryStatus,
  ThreatModelResult,
  DedupResult,
  DedupVerdict,
} from "./publishability.js";
export {
  buildPublishabilityInputs,
  makeGlobalAdvisoryLookup,
  makeOwnSubmissionsLookup,
  makeRepoIssueLookup,
  makeSecurityPolicyFetch,
  detectReportingChannel,
  resolveRepository,
  resolveNovelty,
  OWN_SUBMISSIONS_REGISTRY,
} from "./publishability-sources.js";
export type {
  PublishabilitySourceOptions,
  DedupEcosystem,
  ReportingChannel,
  NoveltyResult,
  ResolveNoveltyOptions,
} from "./publishability-sources.js";
export { checkReachability, extractSinkLocation } from "./reachability.js";
export type { ReachabilityResult, SinkLocation } from "./reachability.js";
export {
  analyzeInputControllability,
  extractTaintedParam,
  controllabilityDowngradeTarget,
  isLowerSeverity,
  CONTROLLABILITY_IDENTIFIER_PARAMS,
  CONTROLLABILITY_ANALYZABLE_CATEGORIES,
} from "./input-controllability.js";
export type { Controllability, ControllabilityResult } from "./input-controllability.js";
export {
  verifySqli,
  verifyReflectedXss,
  verifySsrf,
  verifyRce,
  verifyPathTraversal,
  verifyIdor,
  verifyOracleByCategory,
  parseRequest,
} from "./oracles.js";
export type { OracleResult } from "./oracles.js";
export {
  generatePov,
  judgePovEvidence,
  isReproducedMemCorruption,
  memCorruptionVerdict,
} from "./pov-gate.js";
export type { PovResult, PovArtifactType, GeneratePovOptions } from "./pov-gate.js";
export {
  checkMultiModalAgreement,
  fuseTriageSignals,
  parseFoxguardSarif,
  detectFoxguard,
} from "./multi-modal.js";
export type {
  MultiModalResult,
  FoxguardFinding,
  Agreement,
  FusedTriageSignals,
  FusedTriageResult,
  FusedDecision,
} from "./multi-modal.js";
export { MemoryStore, scoreMemory, inferPackage } from "./memories.js";
export { routeFinding } from "./learned-router.js";
export type { RouterResult, RouterDecision } from "./learned-router.js";
export { hybridRoute } from "./hybrid-router.js";
export type { HybridRouterResult, LlmVerdict } from "./hybrid-router.js";
export {
  LAYER_REGISTRY,
  LAYER_REGISTRY_BY_ID,
  DEFAULT_STATIC_LAYER_SET,
  FREE_LAYER_SET,
  EXPENSIVE_LAYER_SET,
  extractRoutingFeatures,
  classifySubsystem,
  summarizePriorVerdicts,
  RuleBasedRouter,
  decideLayers,
  setRouterModel,
  getRouterModel,
  resetRouterModel,
  buildTraceRecord,
  emitRoutingTrace,
  appendRoutingTraceRecord,
} from "./router/index.js";
export type {
  LayerId,
  LayerRegistryEntry,
  RoutingFeatures,
  RoutingSubsystem,
  PriorLayerSignals,
  RoutingDecision,
  RouterModel,
  FpPatternMatcher,
  RoutingTraceRecord,
  TraceEmitOptions,
  DecisionForTrace,
} from "./router/index.js";
export { verifyKernelCrash, compileAndRunReproducer, matchCrashSignature, validateCrashReportConsistency } from "./kernel-oracle.js";
export type { KernelOracleResult, ReproducerResult, CrashSignatureMatch, ConsistencyResult } from "./kernel-oracle.js";
export {
  classifyKernelPrimitive,
  classifyPrimitiveFromDmesg,
  buildControlDemo,
  attemptControlDemo,
  exploitabilityAdjustedSeverity,
  describeKernelPrimitive,
  maxSeverity,
} from "./kernel-primitive.js";
export type {
  KernelPrimitive,
  KernelPrimitiveKind,
  PrimitiveControl,
  ControlDemoStep,
} from "./kernel-primitive.js";
export {
  classifyUserspacePrimitive,
  sniffMemPrimitive,
  describeExploitabilityVerdict,
  maxMemSeverity,
} from "./userspace-primitive.js";
export type {
  MemSafetyTarget,
  MemPrimitive,
  CrashArtifact,
  FuzzLoopResult,
  ExploitabilityVerdict,
} from "./memsafety-types.js";
export type {
  TriageMemory,
  MemoryScope,
  MemoryStoreOptions,
  MemoryDbHandle,
} from "./memories.js";
