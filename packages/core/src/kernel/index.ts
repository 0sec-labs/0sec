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
  findBadFixes,
  badFixLeadToBrief,
} from "./incomplete-fix-hunt.js";
export type {
  SiblingDef,
  IncompleteFixLead,
  IncompleteFixHuntOptions,
  BadFixLead,
  BadFixHuntOptions,
} from "./incomplete-fix-hunt.js";

export { scoreGeometry, rankByGeometry } from "./geometry-score.js";
export type { GeometryScore } from "./geometry-score.js";

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

// SyzBridge-style upstream PoC → downstream distro/LTS adaptation (NDSS'24).
// Analysis-only: produces a config/env delta + precondition plan (and optional
// LLM-suggested source adjustments) to run an upstream reproducer on an older
// distro/LTS kernel. Serves the older-LTS/distro hunt (CopyFail page-cache LPE,
// rxrpc CVE-2026-43500). Intended consumer: triage/kernel-vm-runner.ts.
export {
  adaptReproForDistro,
  detectReproFeatures,
  detectSubsystems,
  DISTRO_PROFILES,
} from "./distro-adapt.js";
export type {
  AdaptKernel,
  AdaptReproOptions,
  AdaptationPlan,
  ConfigDelta,
  DistroProfile,
  Precondition,
  ReproAdjustment,
  ReproFeature,
} from "./distro-adapt.js";

// ACTOR-style bug-template DSL (USENIX Sec'23). Encode a known bug CLASS as a
// temporal pattern of actions over a shared data structure, then derive (a) a
// static matcher hint for variant-hunt and (b) a structured fuzzing objective
// (syscall action-sequence) for spec-gen / the fuzzer. Analysis/encoding only —
// produces objectives, does not run the fuzzer. Grounds: CopyFail
// (CVE-2026-31431), skb in-place splice, UAF/refcount classes.
export {
  BUG_TEMPLATES,
  BUG_TEMPLATE_LIST,
  COPYFAIL_INPLACE_PAGECACHE,
  SKB_INPLACE_SPLICE,
  UAF_CROSS_THREAD,
  REFCOUNT_UNDERFLOW,
  getBugTemplate,
  matchTemplate,
  matchAllTemplates,
  templateToFuzzObjective,
  allFuzzObjectives,
} from "./bug-templates.js";
export type {
  ActionKind,
  TemplateAction,
  VariantSignal,
  BugTemplate,
  TemplateMatch,
  FuzzObjectiveStep,
  FuzzObjective,
} from "./bug-templates.js";
// Patch-to-PoC directed n-day pipeline (arXiv:2602.07287 + Project Zero Big
// Sleep). Analysis-only: turns an upstream security fix commit/diff into a PoC
// PLAN (bug class + sink + reaching syscalls + trigger steps + reproducer
// skeleton) for an unpatched downstream LTS/distro target, then hands off to the
// EXISTING verify lane for KASAN-confirm. Reuses reachability-rank (sink→syscall)
// and the fix-commit-intel bug/Fixes: vocabulary; pairs with distro-adapt (#953,
// downstream targeting). Serves the older-LTS / CopyFail / rxrpc hunt.
export {
  analyzePatch,
  patchToPocPlan,
  handoffToVerifyInput,
} from "./patch-to-poc.js";
export type {
  BugClass,
  TouchedFile,
  PatchAnalysis,
  TargetKernel,
  TargetApplicability,
  TriggerStep,
  VerifyHandoff,
  PatchToPocPlan,
  PatchToPocOptions,
} from "./patch-to-poc.js";

// Syzbot invalid / auto-closed queue mining (LPE-hunt upgrade #0) — a net-new
// bug-SUPPLY channel. Ingestion + candidate-mapping only: fetch syzbot's
// discarded bucket listings, parse into ranked candidates, and map to
// hunt-scan HuntCandidate[] / HuntBrief for the existing (bench-gated) repro
// path. Deterministic HTML parsing, injected fetcher (offline-testable).
export {
  DEFAULT_TARGET_SUBSYSTEMS,
  parseListingRow,
  parseListing,
  parseBugDetailKernelVersion,
  rankCandidates,
  syzbotQueueBrief,
  toHuntCandidate,
  toHuntCandidates,
  defaultSyzbotFetcher,
  mineSyzbotQueue,
} from "./syzbot-queue-mine.js";
export type {
  SyzbotFetcher,
  SyzbotBucket,
  SyzbotCandidate,
  SyzbotQueueMineOptions,
  SyzbotQueueMineResult,
} from "./syzbot-queue-mine.js";

// Weaponization pipeline — engine bricks (ADR-055 Phase 1). Escalation ladder,
// primitive strategy library + C templates, deterministic success oracle,
// kernel-VM harness, and the control-demo probe. P2 (0cloud dispatch) and P3
// (autonomy) build on this surface.
export * from "./exploit/index.js";

// kernelCTF patch-gap 1day monitor: upstream-fixed CVE feed → target-tree
// presence check → kernelCTF reachability gate → ranked candidates ready
// for the weaponize pipeline. Serves the "un-backported fix = live 1day"
// kernelCTF-winning technique (distinct from generic source-hunting above).
export { parseVulnsCveRecord, loadVulnsFeedFromDir, defaultVulnsFeedIo } from "./patch-gap-feed.js";
export type { UpstreamFixEntry, RawVulnsCveRecord, VulnsFeedIo, LoadVulnsFeedOptions } from "./patch-gap-feed.js";
export { checkFixPresentInTarget, checkNotYetIntroduced, defaultGitExec } from "./patch-gap-check.js";
export type {
  GitExec,
  FixPresenceResult,
  FixPresenceMethod,
  NotYetIntroducedResult,
  NotYetIntroducedMethod,
} from "./patch-gap-check.js";
export { classifyPatchGapReachability } from "./patch-gap-reachability.js";
export type { PatchGapReachability, PatchGapReachabilityResult } from "./patch-gap-reachability.js";
export { scanForPatchGapCandidates } from "./patch-gap.js";
export type { PatchGapCandidate, PatchGapScanOptions, PatchGapScanResult } from "./patch-gap.js";
