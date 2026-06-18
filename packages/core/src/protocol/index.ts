/**
 * protocol/ — protocol-conformance + vuln-discovery capability (issue #972).
 *
 * Tier-1 foundational slice: HTTP/text-protocol spec-vs-implementation
 * conformance differential. The LLM proposes divergence hypotheses
 * (conformance-gen) and a DETERMINISTIC oracle (oracle-http) decides
 * confirmed/refuted under a conservative FP discipline; confirmed divergences
 * become hypothesis-promoted Findings via the Tier-1 flow.
 *
 * Deliberately NOT in this slice (later / design-gated, see #972): the
 * binary/framed protocol driver, non-crash oracles beyond HTTP, machine-
 * readable spec ingestion (RFC/ABNF/ASN.1 → model), and state-machine inference.
 */
export type {
  ProtocolModel,
  ConformanceRule,
  ConformancePrediction,
  DivergenceHypothesis,
  DivergenceVerdict,
  DivergenceStatus,
  ObservedHttpResponse,
  HttpExercise,
  RequirementLevel,
  HttpRuleSurface,
} from "./model.js";

export {
  generateConformanceModel,
  structurallyValidateConformanceModel,
  extractJsonBlock,
} from "./conformance-gen.js";
export type {
  ConformanceModel,
  ConformanceGenOptions,
  ConformanceGenResult,
  ConformanceValidator,
  ConformanceValidationResult,
  ConformanceValidationError,
} from "./conformance-gen.js";

export { judgeHttpDivergence } from "./oracle-http.js";

export { runHttpConformanceCheck } from "./http-conformance.js";
export type {
  HttpSender,
  HttpSendResult,
  HttpConformanceResult,
  HttpConformanceOptions,
  ConformanceAttempt,
} from "./http-conformance.js";

export { createLiveHttpSender } from "./http-sender.js";
export type { LiveHttpSenderOptions } from "./http-sender.js";
