/**
 * Self-improving lens loop — public surface.
 *
 * miss-capture ─▶ synthesize ─▶ validate (fail-closed) ─▶ register, composed by
 * {@link runLensSynthesisLoop}. Turns a confirmed finder MISS into a new,
 * validated, registered appsec finder lens. See loop.ts for the guardrails.
 */

export { captureLensCandidates, coverageGapToCandidate, confirmedMissToCandidate, persistMisses } from "./miss-capture.js";
export {
  synthesizeArchetypes,
  clusterCandidates,
  makeDefaultLensSynthesisModel,
  isCrossLanguageHint,
  parseSynthesizedContent,
  SYNTH_TOOL,
  SYNTH_TOOL_NAME,
} from "./synthesize.js";
export type { LensSynthesisModel, LensCandidateCluster, SynthesizeOptions } from "./synthesize.js";
export { validateCandidateLens, makeFinderLensProbe, prepareValidationCorpus } from "./validate.js";
export type { FinderLensProbeOptions, ValidateOptions } from "./validate.js";
export {
  registerArchetype,
  buildRegistryEntry,
  inspectLensRegistry,
  retireArchetype,
} from "./register.js";
export type {
  LensRegistryStatus,
  RegisterOutcome,
  RetireOutcome,
} from "./register.js";
export {
  captureObservation,
  listObservations,
  approveObservation,
  rejectObservation,
  observationQueueSummary,
  claimForProcessing,
  markProcessed,
  getObservation,
  observationDigest,
  releaseClaim,
  parseObservationInput,
  parseApprovedObservationShape,
} from "./feedback.js";
export type {
  LearningObservation,
  ObservationStatus,
  ObservationSource,
  ObservationFilter,
  CaptureObservationInput,
  ApprovedObservationShape,
  EvidenceRef,
  ObservationQueueSummary,
  ObservationQueueOptions,
  ClaimedApprovedObservation,
} from "./feedback.js";
export { runLensSynthesisLoop } from "./loop.js";
export type {
  LensCandidate,
  LensCandidateSource,
  ConfirmedMiss,
  MissInput,
  SynthesizedArchetype,
  SynthesizedArchetypeContent,
  ValidationFixture,
  ValidationCorpus,
  PreparedValidationCorpus,
  LensBaselineSnapshot,
  LensProbe,
  LensProbeFinding,
  LensProbeOutcome,
  LensTrialSummary,
  LensValidationReceipt,
  LensValidationReport,
  LensScorecardSummary,
  RegisteredLens,
  LensSynthesisInput,
  LensSynthesisDeps,
  LensSynthesisResult,
} from "./types.js";
