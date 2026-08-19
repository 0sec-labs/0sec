/**
 * Public surface for the Tier 2 kernel-finding verifier (#271) and the
 * deterministic replay runner (#193).
 */

export {
  verifyStaticKernelFinding,
  applyVerificationToFinding,
  defaultKernelVerifyRunner,
  tier1VerdictToOracleResult,
} from "./kernel-verify.js";
export type {
  KernelVerifyStatus,
  KernelVerifyResult,
  KernelVerifyAttempt,
  KernelVerifyOptions,
  KernelVerifyAgentInvoker,
  KernelVerifyInvokerContext,
} from "./kernel-verify.js";
export type {
  KernelVerifyOracleResult,
  KernelVerifyPhase,
  KernelVerifyRunner,
  KernelVerifyRunnerInput,
} from "./kernel-verify-types.js";
export { validatePatchRemovesCrash } from "./patch-validate.js";
export type {
  CandidatePatch,
  PatchGenerator,
  PatchApplier,
  PatchReverter,
  PatchValidateStatus,
  PatchValidateResult,
  PatchValidateOptions,
} from "./patch-validate.js";
export {
  minimizeReproducer,
  splitProgram,
  ddmin,
  makeKernelMinimizeOracle,
} from "./reproducer-minimize.js";
export type {
  ReproducerLang,
  MinimizeOracle,
  MinimizeOracleResult,
  MinimizeOptions,
  MinimizeResult,
  SplitProgram,
  KernelMinimizeOracleDeps,
} from "./reproducer-minimize.js";
export {
  buildKernelVerifySystemPrompt,
  buildKernelVerifyInitialPrompt,
  buildCoverageFeedbackPrompt,
  extractKernelFindingMetadata,
  selectSubsystemSourceSlice,
  subsystemToKernelPath,
  SUBSYSTEM_SLICE_MAX_BYTES,
} from "./kernel-prompts.js";
export type { KernelFindingMetadata } from "./kernel-prompts.js";
export {
  KERNEL_RUN_TOOL_DEFINITION,
  KERNEL_RUN_PROGRAM_MAX_BYTES,
  validateKernelRunArgs,
  executeKernelRun,
} from "../agent/tools/kernel-run.js";
export type {
  KernelRunArgs,
  KernelRunInvocation,
  KernelRunResult,
} from "../agent/tools/kernel-run.js";

// pwnkit#193 — deterministic replay runner public surface.
export {
  runDeterministicReplay,
  LocalShellRunner,
  DockerRunner,
  QemuRunner,
  NotImplementedError,
  argvForStep,
  assertionFromStepExpect,
  evaluateAssertion,
  excerpt,
  persistArtifact,
  STREAM_EXCERPT_BYTES,
  DEFAULT_STEP_TIMEOUT_MS,
  MAX_STREAM_CAPTURE_BYTES,
} from "./replay-runner.js";
export type {
  AssertionInput,
  DeterministicReplayOutcome,
  ReplayRunner,
  ReplayRunnerContext,
  RunDeterministicReplayOpts,
  StepResult,
} from "./replay-runner.js";
