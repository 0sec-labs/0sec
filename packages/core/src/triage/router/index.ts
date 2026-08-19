/**
 * Dynamic Triage Router — public exports.
 *
 * See `router.ts` for the design and 0sec#113 for the issue.
 */

export {
  LAYER_REGISTRY,
  LAYER_REGISTRY_BY_ID,
  DEFAULT_STATIC_LAYER_SET,
  FREE_LAYER_SET,
  EXPENSIVE_LAYER_SET,
} from "./layer-registry.js";
export type { LayerId, LayerRegistryEntry } from "./layer-registry.js";

export {
  extractRoutingFeatures,
  classifySubsystem,
  summarizePriorVerdicts,
  FEATURE_NAMES,
} from "./features.js";
export type {
  RoutingFeatures,
  RoutingSubsystem,
  PriorLayerSignals,
} from "./features.js";

export {
  RuleBasedRouter,
  decideLayers,
  setRouterModel,
  getRouterModel,
  resetRouterModel,
  buildTraceRecord,
} from "./router.js";
export type {
  RoutingDecision,
  RouterModel,
  FpPatternMatcher,
  RoutingTraceRecord,
} from "./router.js";

export {
  emitRoutingTrace,
  appendRoutingTraceRecord,
} from "./trace.js";
export type { TraceEmitOptions, DecisionForTrace } from "./trace.js";
