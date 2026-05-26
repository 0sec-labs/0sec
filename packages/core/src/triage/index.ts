/**
 * Finding Triage Module
 *
 * Layer 1 (feature extraction) of the hybrid triage model.
 * Future layers: CodeBERT embeddings, cross-attention fusion, structured LLM verify.
 */

export { extractFeatures, FEATURE_NAMES } from "./feature-extractor.js";
export { isHoldingItWrong } from "./holding-it-wrong.js";
export type { HoldingItWrongResult } from "./holding-it-wrong.js";
export { checkReachability, extractSinkLocation } from "./reachability.js";
export type { ReachabilityResult, SinkLocation } from "./reachability.js";
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
export { generatePov, judgePovEvidence } from "./pov-gate.js";
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
export type {
  TriageMemory,
  MemoryScope,
  MemoryStoreOptions,
  MemoryDbHandle,
} from "./memories.js";
