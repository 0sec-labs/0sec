export {
  foxguardFindingToKernelVariantFinding,
  runKernelVariantHunt,
} from "./variant-hunt.js";
export type {
  KernelVariantHuntOptions,
  KernelVariantHuntReport,
} from "./variant-hunt.js";

export {
  isKernelGitTree,
  mineFixCommits,
  checkAlreadyFixed,
} from "./fix-commit-intel.js";
export type {
  FixCommit,
  AlreadyFixedResult,
  MineFixCommitsOptions,
  CheckAlreadyFixedOptions,
} from "./fix-commit-intel.js";

export {
  familyStem,
  siblingDefsForStem,
  huntIncompleteFixSiblings,
  incompleteFixLeadToFinding,
} from "./incomplete-fix-hunt.js";
export type {
  SiblingDef,
  IncompleteFixLead,
  IncompleteFixHuntOptions,
} from "./incomplete-fix-hunt.js";

export {
  KNOWN_ATTACK_SURFACES,
  DISTRO_DEFAULTS,
  parseKernelConfig,
  parseAutoconfHeader,
  scanForModuleInit,
  computePriorityScore,
  enumerateAttackSurfaces,
  formatAttackSurfaceForPrompt,
} from "./attack-surface.js";
export type {
  KernelAttackSurface,
  AttackSurfaceEntry,
  AttackSurfaceEnumResult,
  EnumerateAttackSurfacesOptions,
} from "./attack-surface.js";

export {
  KERNEL_SUBSYSTEMS,
  KNOWN_CROSS_SUBSYSTEM_FLOWS,
  identifySubsystem,
  detectBoundaryCrossing,
  scanCrossSubsystemFlows,
  formatCrossSubsystemFlowsForPrompt,
  getFlowsForSubsystem,
  describeAssumptionMismatch,
} from "./cross-subsystem-flow.js";
export type {
  KernelSubsystem,
  CrossSubsystemFlow,
  BoundaryCrossing,
  CrossSubsystemScanResult,
  FlowSummary,
  CrossSubsystemScanOptions,
} from "./cross-subsystem-flow.js";

// Static sink → syscall reachability ranking (technique #5). Ranked HINTS to
// direct fuzzing/repro at LLM-flagged sinks; see the honesty caveat in the
// module. Planned consumer: kernel-prompts.ts (separate PR).
export { rankSinkReachability } from "./reachability-rank.js";
export type {
  SinkLocation,
  CallEdge,
  EdgeConfidence,
  ReachabilityCandidate,
  RankSinkReachabilityResult,
  RankSinkReachabilityOptions,
} from "./reachability-rank.js";
// KernelGPT-style LLM → syzlang spec generation — the front of the
// LLM-review → spec → fuzz loop. Infer → structural-validate → repair, with a
// pluggable validator so the syzkaller `syz-check` validator drops in later.
export {
  generateSyzlangSpec,
  structurallyValidateSyzlang,
  extractSyzlang,
} from "./spec-gen.js";
export type {
  SpecGenOptions,
  SpecGenResult,
  SyzlangValidator,
  SyzlangValidationError,
  SyzlangValidationResult,
} from "./spec-gen.js";

// Weaponization pipeline — engine bricks (ADR-055 Phase 1). Escalation ladder,
// primitive strategy library + C templates, deterministic success oracle,
// kernel-VM harness, and the control-demo probe. P2 (0cloud dispatch) and P3
// (autonomy) build on this surface.
export * from "./exploit/index.js";
