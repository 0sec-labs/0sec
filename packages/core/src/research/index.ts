export { runResearch } from "./research-runner.js";
export {
  canonicalProposalJson,
  createResearchProposal,
  digestTargetSnapshot,
  normalizeProposalPath,
  proposalDigest,
  validateResearchProposal,
} from "./proposal.js";
export type {
  CreateResearchProposalInput,
  ProposalCitation,
  ProposalCitationInput,
  ProposalFeatures,
  ProposalKind,
  ProposalOrigin,
  ResearchProposal,
  TargetSourceFile,
  TargetSourceSnapshot,
} from "./proposal.js";
export {
  appendProposalAttempt,
  createProposalAttempt,
  proposalReplayDigest,
  proposalTrainingExamples,
  readProposalReplay,
  serializeProposalReplay,
  validateProposalAttempt,
  validateProposalReplay,
} from "./proposal-replay.js";
export { runProposalLearningLoop } from "./proposal-learning-loop.js";
export type {
  ProposalLearningContext,
  ProposalLearningLoopResult,
  RunProposalLearningLoopOptions,
} from "./proposal-learning-loop.js";
export {
  rankResearchProposals,
  scoreResearchProposal,
  trainProposalRanker,
} from "./proposal-ranker.js";
export { proposalsFromInvariantViolations } from "./target-proposal-generator.js";
export type { InvariantViolationProposalInput } from "./target-proposal-generator.js";
export type {
  ProposalRankerModel,
  RankedProposal,
  RankProposalOptions,
  TrainProposalRankerOptions,
} from "./proposal-ranker.js";
export type {
  CreateProposalAttemptInput,
  EvidenceKind,
  ProposalAttempt,
  ProposalEvidenceReceipt,
  ProposalOutcome,
  ProposalTrainingExample,
} from "./proposal-replay.js";
export type { RunResearchOptions } from "./research-runner.js";
export type {
  ResearchStage,
  ResearchStageStatus,
  ResearchTarget,
  ResearchCandidate,
  ResearchEvidence,
  ResearchFinding,
  ResearchHandoff,
  ResearchContext,
  ResearchStageResult,
  ResearchRunResult,
  TargetResearchAdapter,
} from "./target-research-adapter.js";
export { ProtocolHttpResearchAdapter } from "./adapters/protocol-http-adapter.js";
export type {
  ProtocolHttpTarget,
  ProtocolHttpTargetConfig,
  ProtocolHttpCandidate,
} from "./adapters/protocol-http-adapter.js";
export { UserspaceMemSafetyResearchAdapter } from "./adapters/userspace-memsafety-adapter.js";
export type {
  UserspaceMemSafetyTarget,
  UserspaceMemSafetyTargetConfig,
  UserspaceCampaignCandidate,
  UserspaceHarnessPlan,
  UserspaceExecution,
} from "./adapters/userspace-memsafety-adapter.js";
export { HuntResearchAdapter } from "./adapters/hunt-adapter.js";
export type {
  HuntResearchTarget,
  HuntResearchTargetConfig,
  HuntRecordCandidate,
} from "./adapters/hunt-adapter.js";
export { runDifferential } from "./differential-runner.js";
export type {
  DifferentialSide,
  DifferentialPair,
  DifferentialObservation,
  DifferentialComparison,
  DifferentialRunResult,
  DifferentialExecutor,
  DifferentialComparator,
} from "./differential-runner.js";
export { checkResearchNovelty } from "./novelty-provider.js";
export type {
  NoveltySourceResult,
  ResearchNoveltyProvider,
  AggregateNoveltyResult,
} from "./novelty-provider.js";
export { ResearchAdapterRegistry, createDefaultResearchRegistry } from "./adapter-registry.js";
export { MobileStaticResearchAdapter } from "./adapters/mobile-static-adapter.js";
export type {
  MobileStaticTarget,
  MobileStaticTargetConfig,
  MobileStaticCandidate,
} from "./adapters/mobile-static-adapter.js";
export { LinuxKernelResearchAdapter } from "./adapters/linux-kernel-adapter.js";
export type {
  LinuxKernelTarget,
  LinuxKernelTargetConfig,
  LinuxKernelCandidate,
  LinuxKernelHarness,
  LinuxKernelExecution,
} from "./adapters/linux-kernel-adapter.js";
export { LinuxBootMatrixImportAdapter } from "./adapters/linux-boot-matrix-adapter.js";
export type {
  LinuxBootMatrixTarget,
  LinuxBootMatrixTargetConfig,
  LinuxBootMatrixCandidate,
  BootMatrixObservation,
  BootMatrixVerdict,
} from "./adapters/linux-boot-matrix-adapter.js";
export { WindowsHyperVImportAdapter } from "./adapters/windows-hyperv-adapter.js";
export type {
  WindowsHyperVTarget,
  WindowsHyperVTargetConfig,
  WindowsHyperVCandidate,
  WindowsHyperVImportVerdict,
  ZeroverseHyperVEvidence,
  ZeroverseHyperVObservation,
} from "./adapters/windows-hyperv-adapter.js";
export { WindowsVariantResearchAdapter } from "./adapters/windows-variant-adapter.js";
export type {
  WindowsVariantArtifactBinding,
  WindowsVariantTargetConfig,
  WindowsVariantTarget,
  WindowsVariantRankRequest,
  WindowsVariantRankExecution,
  WindowsVariantRankRunner,
  WindowsVariantCandidate,
} from "./adapters/windows-variant-adapter.js";
export { XnuIokitResearchAdapter } from "./adapters/xnu-iokit-adapter.js";
export type {
  XnuIokitTarget,
  XnuIokitTargetConfig,
  XnuSelectorCandidate,
  XnuHarnessPlan,
  XnuExecution,
} from "./adapters/xnu-iokit-adapter.js";
export { UnifiedPipelineResearchAdapter } from "./adapters/unified-pipeline-adapter.js";
export type {
  UnifiedPipelineTarget,
  UnifiedPipelineTargetConfig,
  UnifiedPipelineCandidate,
} from "./adapters/unified-pipeline-adapter.js";
export { LiveAgenticScanResearchAdapter } from "./adapters/live-agentic-scan-adapter.js";
export type {
  LiveAgenticScanTarget,
  LiveAgenticScanTargetConfig,
  LiveAgenticScanCandidate,
} from "./adapters/live-agentic-scan-adapter.js";
