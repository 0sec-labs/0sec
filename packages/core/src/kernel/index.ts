export {
  foxguardFindingToKernelVariantFinding,
  runKernelVariantHunt,
} from "./variant-hunt.js";
export type {
  KernelVariantHuntOptions,
  KernelVariantHuntReport,
} from "./variant-hunt.js";

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

// Weaponization pipeline — engine bricks (ADR-055 Phase 1). Escalation ladder,
// primitive strategy library + C templates, deterministic success oracle,
// kernel-VM harness, and the control-demo probe. P2 (0cloud dispatch) and P3
// (autonomy) build on this surface.
export * from "./exploit/index.js";
