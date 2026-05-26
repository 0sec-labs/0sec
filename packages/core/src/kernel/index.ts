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
