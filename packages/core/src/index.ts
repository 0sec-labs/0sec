// Programmatic scope ingestion (pwnkit#215). `loadScope` reads a JSON
// scope file; `ScopePolicy` is the matcher used by every URL chokepoint
// in the agent (validateTargetUrl + 5 fetch sites + shellExec URL
// extraction + redirect-final-URL re-check in the crawler).
export { loadScope, matchUrl, ScopePolicy, extractUrls } from "./scope/scope.js";
export type { ScopeJson, ScopeMatch, ScopeRule } from "./scope/scope.js";

// Attribution-header injection (pwnkit#216). Builds on scope ingestion:
// configures per-engagement headers + UA override that get merged into
// every in-scope outbound request, so coordinated-disclosure venues can
// deconflict pwnkit traffic from real attacks.
export {
  resolveAttribution,
  applyAttribution,
  extractAttributionFromScopeJson,
  formatUserAgent,
} from "./scope/attribution.js";
export type {
  AttributionConfig,
  AttributionInputs,
  AttributionScopeBlock,
  AttributionScopeJson,
} from "./scope/attribution.js";

export { scan } from "./scanner.js";
export type { ScanEvent, ScanListener, ScanEventType } from "./scanner.js";
export { agenticScan } from "./agentic-scanner.js";
export type { AgenticScanOptions } from "./agentic-scanner.js";
export { createScanContext, addFinding, addAttackResult, finalize } from "./context.js";
export { sendPrompt, extractResponseText, isMcpTarget } from "./http.js";
export { createRuntime, ProcessRuntime, LlmApiRuntime, OpenRouterRuntime, DEFAULT_ENSEMBLE_MODELS, RUNTIME_REGISTRY, pickRuntimeForStage, detectAvailableRuntimes, getRuntimeInfo } from "./runtime/index.js";
export type { Runtime, RuntimeConfig, RuntimeContext, RuntimeResult, RuntimeType, NativeRuntime, NativeMessage, NativeContentBlock, NativeToolDef, NativeRuntimeResult, OpenRouterConfig } from "./runtime/index.js";
export { buildDeepScanPrompt, buildMcpAuditPrompt, buildSourceAnalysisPrompt } from "./prompts.js";
export { resolveMcpEndpoint, listMcpTools, callMcpTool, discoverMcpTarget, runMcpSecurityChecks } from "./mcp.js";
export { runLlmIpiAudit, breakRecordToFinding } from "./llm-ipi-audit.js";

// Analysis prompts
export { auditAgentPrompt, reviewAgentPrompt } from "./analysis-prompts.js";

// Agent runner
export { runAnalysisAgent } from "./agent-runner.js";
export type { AnalysisAgentOptions } from "./agent-runner.js";

// Package audit
export { packageAudit } from "./audit.js";
export type { PackageAuditOptions } from "./audit.js";

// Source code review
export { sourceReview } from "./review.js";
export type { SourceReviewOptions } from "./review.js";
export {
  buildTier1Harness,
  scaffoldTier1Harness,
  scaffoldTier2Harness,
} from "./review/c-cpp-profile.js";
export type {
  FunctionSignature,
  Tier1HarnessScaffold,
  Tier1HarnessScaffoldOptions,
  Tier2HarnessScaffold,
  Tier2HarnessScaffoldOptions,
} from "./review/c-cpp-profile.js";
export {
  buildTier2Harness,
  detectBuildSystem,
  discoverObjectSubset,
} from "./review/c-cpp-tier2.js";
export type {
  BuildSystem,
  Sanitizer,
  Tier2HarnessOptions,
  Tier2HarnessArtifact,
} from "./review/c-cpp-tier2.js";
export { extractCorpus, DEFAULT_SEED_DIRS } from "./review/corpus.js";
export type { ExtractCorpusOptions } from "./review/corpus.js";
export { parseSanitizerLog, renderSanitizerVerdict } from "./review/sanitizer-log.js";
export type {
  SanitizerFrame,
  SanitizerName,
  SanitizerPrimitive,
  SanitizerVerdict,
} from "./review/sanitizer-log.js";
export {
  runTier3Validation,
  promoteFindingsWithTier3Result,
} from "./review/c-cpp-tier3.js";
export type {
  Tier3Status,
  Tier3ValidationOptions,
  Tier3ValidationResult,
} from "./review/c-cpp-tier3.js";

// Userspace / Rust memory-safety pipeline ("Monty-mode") — closed fuzz loop
// + shared contract (docs/pwnkit-rust-memsafety-pipeline.md, Track B).
export { runUserspaceFuzzLoop, parseCrashOutput } from "./triage/userspace-fuzz-runner.js";
export type { UserspaceFuzzOptions } from "./triage/userspace-fuzz-runner.js";
export type {
  MemSafetyTarget,
  MemPrimitive,
  CrashArtifact,
  FuzzLoopResult,
  ExploitabilityVerdict,
} from "./triage/memsafety-types.js";
// Integration spine (pwnkit#700): the A→B→C memory-safety scan stage that
// chains the playbook, fuzz loop, and crash triage into Findings.
export {
  runMemSafetyScan,
  crashArtifactToFinding,
  memPrimitiveToCategory,
} from "./stages/memsafety-scan.js";
export type {
  MemSafetyScanOptions,
  MemSafetyScanResult,
  MemSafetyFinding,
} from "./stages/memsafety-scan.js";
// Craft scan stage (agentic reason→craft→submit→refine, injectable PoC oracle):
// the sibling of the fuzz path that needs no target build.
export { runCraftScan, craftedPocToFinding } from "./stages/craft-scan.js";
// Exploit scan stage (agentic weaponize-to-root, injectable target executor).
export { runExploitScan } from "./stages/exploit-scan.js";
export type { ExploitTarget, ExploitExecutor, ExploitScanOptions, ExploitScanResult } from "./stages/exploit-scan.js";
// Hunt scan stage (parallel novel-bug discovery: fan-out finders -> skeptic+prover gate).
export { runHuntScan, makeSkepticVerifier, composeGate } from "./stages/hunt-scan.js";
export {
  checkNovelty,
  syncLoreMirror,
  discoverEpochs,
  localMirrors,
  deriveSearchTerms,
  findingToQuery,
  makeLloreJudge,
  liveGit,
  OWN_FROM_MARKERS,
} from "./stages/novelty-check.js";
export type {
  NoveltyQuery,
  LoreNoveltyResult,
  NoveltyCheckOptions,
  NoveltyJudge,
  JudgeVerdict,
  LoreCandidate,
  LoreMirror,
  LoreSyncOptions,
  DuplicateRef,
  GitRunner,
} from "./stages/novelty-check.js";
export { generateVariantCandidates } from "./stages/variant-candidates.js";
export type { VariantHuntInput, VariantHuntPlan } from "./stages/variant-candidates.js";
export { extractSpecInvariants, mapInvariantsToImplementation, runSpecdriftScan } from "./specdrift/index.js";
export type {
  ExtractSpecInvariantsOptions,
  ImplementationCandidate,
  MapInvariantsToImplementationOptions,
  RunSpecdriftScanOptions,
  SpecCitation,
  SpecInvariant,
  SpecInvariantKind,
  SpecdriftExtractResult,
  SpecdriftScanResult,
} from "./specdrift/index.js";
export type {
  HuntCandidate,
  HuntBrief,
  HuntVerifier,
  HuntScanOptions,
  HuntScanResult,
} from "./stages/hunt-scan.js";
export type {
  CraftTarget,
  CraftPocVerdict,
  CraftPocEvaluator,
  CraftScanOptions,
  CraftScanResult,
} from "./stages/craft-scan.js";
// Cross-task learning memory (the 5-tier "Crystalline-style" moat).
export { CraftMemoryStore, preseedMemory, consolidateMemory } from "./craft-memory/index.js";
export type { Memory, MemoryLevel } from "./craft-memory/index.js";

// Unified pipeline: prepare + static analysis
export { prepare, detectTargetType } from "./prepare.js";
export type { TargetType, PrepareResult, PrepareOptions } from "./prepare.js";
export {
  expandHomePath,
  isExistingLocalTargetPath,
  isExplicitLocalTargetPath,
  resolveLocalTargetPath,
} from "./path-resolution.js";
export type { LocalPathResolutionOptions } from "./path-resolution.js";
export { runStaticAnalysis } from "./static-analysis.js";
export type { StaticAnalysisResult } from "./static-analysis.js";

// Passive mobile app static intake.
export { runMobileStaticIntake } from "./mobile/intake.js";
export type {
  AndroidMetadata,
  IosMetadata,
  MobileEndpointIndicator,
  MobilePlatform,
  MobileRiskIndicator,
  MobileStaticIntakeOptions,
  MobileStaticIntakeReport,
} from "./mobile/intake.js";

// Unified pipeline
export { runPipeline, parseSubsystems } from "./unified-pipeline.js";
export type { PipelineOptions, PipelineReport } from "./unified-pipeline.js";

// External seed findings (pwnkit#368). Parser + reader for ND-JSON leads
// supplied by upstream probes like GemmaForge (`gemmaforge.leads/v1`).
export {
  parseSeedFindings,
  readSeedFindings,
  GEMMAFORGE_LEADS_SCHEMA,
} from "./seed-findings.js";
export type { ParseSeedFindingsOptions } from "./seed-findings.js";

// Agent system
export { runAgentLoop, runNativeAgentLoop, ToolExecutor, getToolsForRole, TOOL_DEFINITIONS, features, estimateCost } from "./agent/index.js";
export { runEGATS, runEGATSWithDefaults, scoreEvidence, summariseTree } from "./agent/egats.js";
export {
  clearSkillRegistry,
  formatJitSkillsInstruction,
  getSkillById,
  listSkillSummaries,
  loadSkillRegistry,
  matchTriggers,
} from "./agent/skills/index.js";
export type { SkillDefinition, SkillSummary } from "./agent/skills/index.js";
export {
  branchJournal,
  createJournalWriter,
  defaultJournalRootDir,
  loadJournal,
  migrateJournalEntry,
  rehydrateContext,
  resolveJournalPaths,
  streamJournal,
  DEFAULT_JOURNAL_SIDECAR_THRESHOLD_BYTES,
  JOURNAL_SCHEMA_VERSION,
} from "./agent/journal/index.js";
export type {
  BranchJournalOptions,
  BranchJournalResult,
  ConversationState,
  JournalArtifact,
  JournalArtifactInline,
  JournalArtifactInput,
  JournalArtifactRef,
  JournalDecisionEntry,
  JournalDispatchEntry,
  JournalDoneEntry,
  JournalEntry,
  JournalEntryInput,
  JournalEntryKind,
  JournalErrorEntry,
  JournalFindingEntry,
  JournalHypothesisEntry,
  JournalLoadOptions,
  JournalNoteEntry,
  JournalObservationEntry,
  JournalPaths,
  JournalReplayOptions,
  JournalSchemaVersion,
  JournalToolCallEntry,
  JournalToolResultEntry,
  JournalWriter,
  JournalWriterOptions,
  RehydratedHypothesis,
  RehydratedToolStep,
} from "./agent/journal/index.js";
export type { AttackNode, AttackTreeResult, EGATSConfig, Evidence as EGATSEvidence, NodeStatus as EGATSNodeStatus } from "./agent/egats.js";
export { discoveryPrompt, attackPrompt, verifyPrompt, reportPrompt, sourceVerifyPrompt, researchPrompt, blindVerifyPrompt } from "./agent/prompts.js";
export type {
  AgentRole,
  AgentConfig,
  AgentState,
  AgentMessage,
  ToolDefinition,
  ToolCall,
  ToolResult,
  ToolContext,
  AgentLoopOptions,
  NativeAgentConfig,
  NativeAgentLoopOptions,
  NativeAgentState,
} from "./agent/index.js";

// Strategy racing (best-of-N)
export { raceStrategies, raceWithDefaults, DEFAULT_STRATEGIES } from "./racing.js";
export type { AttackStrategy, RaceConfig, RaceResult, StrategyResult } from "./racing.js";

// Per-host rate limiter (#214)
export {
  TokenBucket,
  RateLimiter,
  parseRateLimitFlag,
  parseRetryAfter,
} from "./scope/rate-limit.js";
export type {
  HostRateConfig,
  RateLimiterConfig,
} from "./scope/rate-limit.js";

// http_audit enforcement (path allowlist + counters + kill switch)
export { PathPolicy, EnforcementTracker } from "./scope/enforcement.js";
export type { EnforcementSummary, PathMatch } from "./scope/enforcement.js";

export type { DBScan, DBFinding, DBTarget, DBAttackResult } from "./db/schema.js";

// API spec parser
export { parseApiSpec } from "./api-spec.js";
export type { ApiSpecSummary, ApiSpecEndpoint, ApiSpecParameter, ApiSpecAuthScheme } from "./api-spec.js";

// Vulnerability intelligence tools (pwnkit#439)
export {
  defaultIntelCacheDir,
  IntelCache,
  buildIntelDossier,
  buildPriorVulnerabilityAuditGraph,
  formatTargetHistoryForPrompt,
  lookupCve,
  lookupKev,
  lookupNvdCve,
  mergeIntel,
  parseGitHubAdvisories,
  parseNvdResponse as parseIntelNvdResponse,
  parseOsvResponse as parseIntelOsvResponse,
  queryGitHubAdvisories,
  queryOsvAdvisories,
  searchAdvisories,
  searchNvdSimilar,
  searchNvdTargetHistory,
  searchSimilar,
  searchTargetHistory,
  inferTargetHistoryInputFromRepo,
  resolveTargetHistoryInput,
  toGraphSnapshot,
  toOsvEcosystem,
} from "./intel/index.js";
export type {
  AdvisorySearchInput,
  CveLookupInput,
  FetchOptions,
  IntelCvss,
  IntelDossier,
  IntelDossierInput,
  IntelDossierSummary,
  IntelGraphEdge,
  IntelGraphNode,
  IntelGraphSnapshot,
  IntelInvestigationStep,
  IntelKev,
  IntelPackage,
  IntelPriorVulnerabilityAuditEdge,
  IntelPriorVulnerabilityAuditGraph,
  IntelPriorVulnerabilityAuditNode,
  IntelPriorVulnerabilityPlaybook,
  IntelReference,
  IntelSeverity,
  IntelSource,
  IntelTargetHistory,
  IntelTargetHistorySummary,
  IntelVariantLead,
  SimilarSearchInput,
  TargetHistorySearchInput,
  VulnerabilityIntel,
} from "./intel/index.js";

// Structured verification pipeline — `verify()` is the unified entrypoint;
// the trio (runStructuredVerify / runSelfConsistencyVerify) remain as the
// single-pass + self-consistency implementations it delegates to.
export {
  verify,
  toVerifyVerdict,
  runStructuredVerify,
  runSelfConsistencyVerify,
  tallyConsensus,
} from "./triage/structured-verify.js";
export type {
  VerifyResult,
  VerifyOptions,
  StepResult,
  StructuredOutcome,
  VerifyStepName,
  ConsensusResult,
  SelfConsistencyOptions,
  VerifyMemoryOptions,
} from "./triage/structured-verify.js";
// Unified verify funnel — one verdict contract + one disclosure predicate.
export { isDisclosureWorthy } from "./triage/verify-verdict.js";
export type {
  VerifyVerdict,
  VerifyOutcome,
  VerifySignal,
  VerdictLike,
  DisclosureDecision,
} from "./triage/verify-verdict.js";

// Triage memories (Semgrep-style persistent FP learning)
export { MemoryStore, scoreMemory, inferPackage } from "./triage/memories.js";
export type {
  TriageMemory,
  MemoryScope,
  MemoryStoreOptions,
  MemoryDbHandle,
} from "./triage/memories.js";

// Public-advisory novelty gate (issue #851). The `0cloud findings
// novelty-recheck` command resolves `mod.resolveNovelty` off this root import
// (a non-literal dynamic `import("@pwnkit/core")`), so it MUST be re-exported
// here, not only via the triage barrel — otherwise the recheck throws
// "mod.resolveNovelty is not a function" for every finding.
export { resolveNovelty } from "./triage/publishability-sources.js";
export type {
  NoveltyResult,
  ResolveNoveltyOptions,
} from "./triage/publishability-sources.js";

// PoV (Proof-of-Vulnerability) gate
export {
  generatePov,
  judgePovEvidence,
  isReproducedMemCorruption,
  memCorruptionVerdict,
} from "./triage/pov-gate.js";
export type { PovResult, PovArtifactType, GeneratePovOptions } from "./triage/pov-gate.js";

// Userspace / Rust memory-safety pipeline (#698)
export {
  classifyUserspacePrimitive,
  sniffMemPrimitive,
  describeExploitabilityVerdict,
  maxMemSeverity,
} from "./triage/userspace-primitive.js";
// (shared memsafety-types are re-exported above, beside the Track B fuzz-loop exports)

// Handcrafted feature extractor (45-element vector for triage classifiers)
export { extractFeatures, FEATURE_NAMES } from "./triage/feature-extractor.js";

// Remediation guidance
export { generateRemediation, generateRemediationWithLLM } from "./remediation.js";
export type { Remediation, RemediationCodeExample } from "./remediation.js";

// Adversarial eval runner (fast AI safety scorecard)
export { runEval, getEvalCategories } from "./eval-runner.js";
export type { EvalScorecard, EvalCategoryResult, EvalCategory, EvalCategoryVerdict, EvalVerdict, EvalRunnerOptions } from "./eval-runner.js";

// Scan TUI state reducers (pure, consumed by the CLI's renderScan.ts).
export {
  appendStageAction,
  formatStageDetail,
  normalizeStageAction,
  normalizeStageEndDetail,
  selectVisibleActions,
  truncateStageAction,
  STAGE_ACTION_HISTORY_CAP,
  VERBOSE_ACTIONS_RENDER_CAP,
  COMPACT_ACTIONS_RENDER_CAP,
  COMPACT_ACTION_CHARS,
  VERBOSE_ACTION_CHARS,
  COMPACT_DETAIL_CHARS,
} from "./scan-ui-state.js";
export type { VisibleActions } from "./scan-ui-state.js";

// Tool call preview formatter (pure, used by scan TUI sub-action emission
// in the agentic scanner and reusable by logs / cloud-sink / dashboard).
export { toolCallPreview, summariseTurnToolCalls } from "./agent/tool-preview.js";

// Opt-in cloud-sink: POST findings/leads to the orchestrator
// (`POST /scans/:id/findings`) when PWNKIT_CLOUD_SINK + PWNKIT_CLOUD_SCAN_ID are
// set. Exposed so `pwnkit hunt` can ingest its gated leads as candidate
// findings the same way scan/review reach the cloud (#1051).
export { getCloudSinkConfig, postFinding } from "./cloud-sink.js";
export type { CloudSinkConfig } from "./cloud-sink.js";

// Kernel crash ingest (crash report → Finding pipeline)
export { parseCrashReport, crashToFinding, ingestArtifactsFromDirectory, ingestArtifactsFromFile, ingestFile, ingestDirectory, crashTypeToCategory, crashSeverity, reviewKernelCrashSubsystems } from "./ingest/index.js";
export type { KernelCrashArtifact, KernelSubsystemReviewOptions, KernelSubsystemReviewResult, KernelSubsystemReviewRunner, KernelSubsystemReviewRunnerInput, KernelSubsystemReviewSkip } from "./ingest/index.js";

// Kernel advisory variant hunting (foxguard SARIF → pwnkit findings)
export {
  foxguardFindingToKernelVariantFinding,
  runKernelVariantHunt,
} from "./kernel/index.js";
export type {
  KernelVariantHuntOptions,
  KernelVariantHuntReport,
} from "./kernel/index.js";

// Kernel attack surface enumeration (pwnkit#471)
export {
  KNOWN_ATTACK_SURFACES,
  DISTRO_DEFAULTS,
  parseKernelConfig,
  parseAutoconfHeader,
  scanForModuleInit,
  computePriorityScore,
  enumerateAttackSurfaces,
  formatAttackSurfaceForPrompt,
} from "./kernel/index.js";
export type {
  KernelAttackSurface,
  AttackSurfaceEntry,
  AttackSurfaceEnumResult,
  EnumerateAttackSurfacesOptions,
} from "./kernel/index.js";

// Weaponization pipeline — engine bricks (ADR-055 Phase 1). Escalation ladder,
// primitive strategy library + C templates, deterministic success oracle,
// kernel-VM harness, and the control-demo probe that backs `attemptControlDemo`.
// P2 (0cloud dispatch) / P3 (autonomy) build on this surface.
export {
  ESCALATION_LADDER,
  maxRung,
  ratchet,
  rungAtLeast,
  ladderUpTo,
  RUNG_MARKER_TAG,
  markerLine,
  markerFired,
  adjudicate,
  emitWeaponizationC,
  PRIMITIVE_LIBRARY,
  selectStrategies,
  getStrategy,
  runWeaponization,
  runStrategy,
  kernelVmArtifactsReady,
  bootedCacheKey,
  mintCanary,
  makeKernelVmProbe,
  controlRungForDemo,
  runKernelExploitChain,
} from "./kernel/index.js";
export { rungRank as escalationRungRank, selectSprayPlans, introspectExploitConfig } from "./kernel/exploit/index.js";
export type {
  EscalationRung,
  OracleVerdict,
  AdjudicateInput,
  ExploitTemplateParams,
  PrimitiveStrategy,
  RootTail,
  KernelVmRunner,
  RunWeaponizationOptions,
  StrategyAttempt,
  WeaponizationResult,
  KernelVmProbeOptions,
  RunKernelExploitChainOptions,
  RunKernelExploitChainResult,
  ChainRunStep,
  KernelExploitContext,
  WeaponizationSummary,
} from "./kernel/index.js";

// Bug-to-primitive classifier (the input to the weaponization harness).
export {
  classifyKernelPrimitive,
  classifyPrimitiveFromDmesg,
  describeKernelPrimitive,
} from "./triage/kernel-primitive.js";
export type {
  KernelPrimitive,
  KernelPrimitiveKind,
  PrimitiveControl,
  ControlDemoStep,
} from "./triage/kernel-primitive.js";

// Kernel crash verification oracle
export { verifyKernelCrash, verifyStandaloneKernelReproducer, compileAndRunReproducer, matchCrashSignature, validateCrashReportConsistency } from "./triage/kernel-oracle.js";
export type { KernelOracleResult, ReproducerResult, CrashSignatureMatch, ConsistencyResult } from "./triage/kernel-oracle.js";
export { prepareKernelVmArtifacts, verifyKernelFinding, writeProofFileReadOnly, defaultDmesgOutPath, loadKernelVmConfigFromEnv } from "./triage/kernel-vm-runner.js";
export type {
  KernelVmArtifacts,
  KernelBuildOptions,
  KernelConfigProfile,
  KernelFindingStatus,
  KernelFindingVerification,
  VerifyKernelFindingOptions,
} from "./triage/kernel-vm-runner.js";

// Tier 2 kernel-finding verification (#271). Agent-driven loop that takes a
// static `hypothesis: true, confidence: 0.4` kernel-review Finding and drives
// a constrained reproducer-generation loop until the Tier 1 oracle confirms
// (or the attempt/wall-clock budget is exhausted).
export {
  verifyStaticKernelFinding,
  applyVerificationToFinding,
  defaultKernelVerifyRunner,
  buildKernelVerifySystemPrompt,
  buildKernelVerifyInitialPrompt,
  extractKernelFindingMetadata,
  selectSubsystemSourceSlice,
  KERNEL_RUN_TOOL_DEFINITION,
  KERNEL_RUN_PROGRAM_MAX_BYTES,
  validateKernelRunArgs,
  executeKernelRun,
} from "./verify/index.js";
export type {
  KernelVerifyStatus,
  KernelVerifyResult,
  KernelVerifyAttempt,
  KernelVerifyOptions,
  KernelVerifyAgentInvoker,
  KernelVerifyInvokerContext,
  KernelVerifyOracleResult,
  KernelVerifyRunner,
  KernelVerifyRunnerInput,
  KernelFindingMetadata,
  KernelRunArgs,
  KernelRunInvocation,
  KernelRunResult,
} from "./verify/index.js";

// Autonomous CVE PoC adaptation (issue #272 v0 part 2). The scraper that
// produces `CveArtifacts` lives on a sibling branch and is wired in at
// merge time via the typed `CveArtifactProvider` seam.
export {
  fetchPoc,
  extractInlineCodeBlock,
  PocFetchError,
  MAX_POC_BYTES,
  adaptAndVerify,
  applyUnifiedDiff,
  renderAdaptationPrompt,
} from "./cve/index.js";
export type {
  AdaptAndVerifyOptions,
  AdaptationAgent,
  AdaptationAgentInput,
  AdaptationResult,
  AdaptationStatus,
  AttemptRecord,
  CveArtifactProvider,
  CveArtifacts,
  FetchPocOptions,
  FetchedPoc,
  PocCandidate,
  VerifyKernelFinding,
} from "./cve/index.js";

// Cloud event-bus sink (PWNKIT_CLOUD_EVENTS=1 → emit `PWNKIT_EVENT_<TYPE>`
// lines on stdout for the pwnkit-cloud worker-controller to relay).
// The CLI entry must call `maybeSubscribeCloudEventSink()` so the sink
// subscribes once; without that call the sink module is dead code and
// the cloud's live-trace UI stays dark for every scan.
export {
  eventBus,
  cloudEventSink,
  maybeSubscribeCloudEventSink,
  isCloudEventSinkActive,
} from "./events/bus.js";
export type {
  CostBreakdownEntry,
  ScanCompletedPayload,
} from "./events/bus.js";

// Live-agent state reducer (CLI TUI panel). Pure transform of
// eventBus payloads into a "what the agent is doing right now"
// snapshot, with replace-in-place semantics so the terminal stays
// readable on long scans.
export {
  hasLiveAgentState,
  reduceLiveAgentState,
} from "./agent/live-agent-state.js";
export type { LiveAgentState } from "./agent/live-agent-state.js";

// Verification spec evaluator (pwnkit#193 / pwnkit-cloud#111). Re-checks a
// finding's `verificationSpec` predicates against a repo on disk so cloud's
// canary watcher (and any OSS caller) can deterministically decide whether
// a finding is still real after upstream changes.
export {
  evaluateVerificationSpec,
  runCliPathTraversalReplayFixture,
} from "./verification-spec/index.js";
export type {
  CliPathTraversalFixtureOptions,
  DeterministicReplayResult,
  PredicateResult,
  ReplayAssertion,
  ReplayCommand,
  ReplayStatus,
  VerificationResult,
} from "./verification-spec/index.js";

// Deterministic replay runner skeleton (pwnkit#193). Consumes a finding's
// `pocSteps`, sequentially executes them via a pluggable runner (local
// shell today; docker/qemu interfaces only), and emits a canonical
// `VerificationResult` payload matching `@pwnkit/shared/verification`.
// Cloud's worker-controller can call this directly in-process without
// shelling out to the CLI.
//
// Names that would collide with existing exports (StepResult,
// DEFAULT_STEP_TIMEOUT_MS) are re-exported under prefixed aliases so
// callers can pick a side without ambiguity.
export {
  runDeterministicReplay,
  LocalShellRunner,
  DockerRunner,
  QemuRunner,
  NotImplementedError as VerifyNotImplementedError,
  argvForStep as verifyArgvForStep,
  assertionFromStepExpect,
  evaluateAssertion,
  excerpt as verifyExcerpt,
  persistArtifact as verifyPersistArtifact,
  STREAM_EXCERPT_BYTES as VERIFY_STREAM_EXCERPT_BYTES,
  DEFAULT_STEP_TIMEOUT_MS as VERIFY_DEFAULT_STEP_TIMEOUT_MS,
  MAX_STREAM_CAPTURE_BYTES as VERIFY_MAX_STREAM_CAPTURE_BYTES,
} from "./verify/index.js";
export type {
  AssertionInput,
  DeterministicReplayOutcome,
  ReplayRunner,
  ReplayRunnerContext,
  RunDeterministicReplayOpts,
  StepResult as VerifyStepResult,
} from "./verify/index.js";

// HackerOne hacker-API integration (read-only). `pwnkit h1 …` CLI lives
// in the cli package; this surface is the programmatic entry point.
export {
  loadH1Credentials,
  H1AuthMissingError,
  H1Client,
  H1Error,
  H1AuthError,
  H1ForbiddenError,
  H1RateLimitError,
  H1NetworkError,
  listPrograms,
  getProgram,
  getStructuredScopes,
  automationVerdict,
  summariseScopes,
  toScopeFile,
  toScopeJson,
} from "./h1/index.js";
export type {
  H1Credentials,
  LoadH1CredentialsOptions,
  FetchImpl,
  H1ClientOptions,
  ListProgramsOptions,
  AutomationVerdict,
  H1ProgramPage,
  ToScopeFileOptions,
  ScopeExportResult,
  H1Resource,
  H1Collection,
  H1Single,
  H1Program,
  H1ProgramAttributes,
  H1Scope,
  H1StructuredScopeAttributes,
  H1BalanceAttributes,
} from "./h1/index.js";

// pwnkit-cloud auth + HTTP client (CLI half of #303). The server-side
// token-mint endpoint lives in pwnkit-cloud and is out of scope here;
// see ./cloud/credentials.ts and ./cloud/client.ts for details.
export {
  loadCloudCredentials,
  CloudAuthMissingError,
  CloudAuthError,
  DEFAULT_CLOUD_HOST,
  CloudClient,
  CloudError,
  CloudUnauthorizedError,
  CloudForbiddenError,
  CloudNetworkError,
} from "./cloud/index.js";
export type {
  CloudCredentials,
  LoadCloudCredentialsOptions,
  CloudClientOptions,
  CloudHealthResponse,
} from "./cloud/index.js";

// CVE artifact scraping (#272 v0 part 1). Finds public PoC artifacts,
// write-ups, and affected-version metadata for a given CVE id by hitting
// NVD, GHSA, OSV, distro trackers, and GitHub search. Building/running
// the PoC is the next slice (depends on #271 Tier-1 plumbing).
export {
  findCveArtifacts,
  normaliseCveId,
  classifyReferences,
  parseNvdResponse,
  parseGhsaResponse,
  parseOsvResponse,
  parseUbuntuTracker,
  parseRedHatTracker,
  findUbuntuTrackerUrls,
  findRedHatTrackerUrls,
  scoreRepoCandidate,
  scoreCodeCandidate,
} from "./cve/index.js";
export type {
  ScrapedCveArtifacts,
  ScrapedPocCandidate,
  PocSource,
  PocLanguage,
  AffectedVersionRange,
  SourceFetched,
  FindCveArtifactsOptions,
  FetchLike as CveFetchLike,
} from "./cve/index.js";

// Disclosure bundle assembly (finding → GHSA-ready advisory markdown)
export { suggestCwesForCategory, formatCweSection, suggestCvss, renderAdvisoryMarkdown, EmptyPocError, redactSensitiveHeaders, renderExploitScreenshot, isFreezeAvailable, composeExploitSession, composeStepSession, verifyAgainstRef, extractFileRefs, formatPatchStatusSection, detectVersionRange, formatVersionRangeLine, extractSiblingFix, executePocSteps, setRuntimeDeps, MAX_CAPTURE_BYTES, DEFAULT_STEP_TIMEOUT_MS, decideFilingState, assembleBundleIndex, formatDroppedReason, droppedFilename, dropSlug } from "./disclose/index.js";
export type { CweEntry, CvssSuggestion, AdvisoryContext, AdvisoryScreenshot, RenderedAdvisory, ScreenshotResult, ScreenshotOptions, PatchStatus, FileRef, ReverifyResult, ReverifyOptions, VersionRangeResult, VersionRangeOptions, SiblingFixCandidate, SiblingFixOptions, PocExecutionTarget, PocExecutionReport, PocStepResult, PocStepVerdict, PocOverallVerdict, FilingState, BundleEntry, AssembleIndexOptions } from "./disclose/index.js";

// #928 — disclosure-process tracking (status state machine + timeline) and the
// evidence-pack assembler (finding → vendor-notification draft). DRAFT-only,
// never sends.
export { DISCLOSURE_STATUSES, TERMINAL_STATUSES, PUBLIC_STATUSES, allowedNextStatuses, canTransition, createDisclosureRecord, transition, isPubliclyDisclosed, IllegalTransitionError, assembleEvidencePack, renderVendorNotificationMarkdown, UnreproducedFindingError } from "./disclose/index.js";
export type { DisclosureStatus, DisclosureRecord, DisclosureTimelineEvent, TransitionInput, VendorNotificationDraft, EvidencePackOptions } from "./disclose/index.js";

// PR-shaped finding output (pwnkit#377). `emitFindingsAsPRs` turns reproduced
// findings into one GitHub PR each (repro + suggested patch from a fix-template
// registry); non-reproduced findings roll up into a single hypotheses.md.
export {
  emitFindingsAsPRs,
  isReproduced,
  buildBranchName,
  buildPrTitle,
  buildPrBody,
  buildReproReadme,
  buildHypothesesMarkdown,
  FixTemplateRegistry,
  createDefaultFixTemplateRegistry,
  hardCodedSecretTemplate,
  missingInputValidationTemplate,
  integerTruncationGuardTemplate,
  renderUnifiedDiff,
  templateIdForCategory,
} from "./emit/index.js";
export type {
  EmitFindingsAsPRsOptions,
  EmitFindingsAsPRsReport,
  EvidenceArtifact,
  FsClient as EmitFsClient,
  GhClient,
  GitClient,
  PrEmitOutcome,
  PrEmitResult,
  FixTemplate,
  UnifiedDiff,
  UnifiedDiffHunk,
} from "./emit/index.js";

// ── Scan-level pass@k bench harness (pwnkit#556) ──
// Turns the per-finding verify oracles into a scan-level scorecard
// (success rate, FP rate vs known-negatives, cost-per-success) + CI gate.
export * from "./bench/index.js";

// ── Recon mode: domain surface enumeration (pwnkit#769) ──
// Given a domain, probes well-known OpenAPI/Swagger + MCP endpoints and emits
// a deduped, structured asset inventory consumable as discovered_assets.
export {
  runRecon,
  dedupeAssets,
  apiSpecToAssets,
  normalizeDomain,
  enumerateSubdomains,
  DEFAULT_SPEC_PATHS,
  DEFAULT_MCP_PATHS,
} from "./recon/recon.js";
export type {
  ReconAsset,
  ReconAssetKind,
  ReconResult,
  ReconOptions,
} from "./recon/recon.js";
// Active subdomain brute-force (pwnkit#924) — OFF by default, scope-gated +
// time-boxed; merges into runRecon's subdomain assets when enabled.
export {
  enumerateSubdomainsActive,
  buildCandidateHosts,
  DEFAULT_SUBDOMAIN_WORDLIST,
  MAX_CANDIDATES,
  DEFAULT_CONCURRENCY,
  DEFAULT_MAX_DURATION_MS,
} from "./recon/active-subdomains.js";
export type { ActiveEnumerateOptions } from "./recon/active-subdomains.js";
// JS-driven endpoint + secret discovery (pwnkit#927) — scope-gated,
// deny-by-default; mines a site's JS bundles for endpoints + redacted secrets.
export { runJsRecon, MAX_JS_FILES } from "./recon/js-recon.js";
export type { JsReconOptions, JsReconResult } from "./recon/js-recon.js";
export type { SecretHit, FetchTextResult } from "./recon/js-artifacts.js";
// Extract JS chunk URLs from a page's HTML (resolves relative, dedupes,
// .js/.mjs only) — feeds runJsRecon's scriptUrls from a single page fetch.
export { enumerateJsChunkUrls } from "./recon/stack-fingerprint.js";
// Live cloud-surface probes (pwnkit#925) — read-only, gated behind the
// PWNKIT_FEATURE_CLOUD_SURFACE flag AND an engagement ScopePolicy.
export {
  probeS3Bucket,
  classifyTakeover,
  bucketInScope,
  bucketEndpoint,
  validateAwsCredentials,
  assertReadOnlyAction,
} from "./agent/cloud-surface.js";
export type {
  BucketProbeResult,
  TakeoverVerdict,
  CredentialValidationResult,
  CloudScopeMatcher,
} from "./agent/cloud-surface.js";

// Protocol-conformance capability (issue #972) — Tier-1 HTTP spec-vs-impl
// differential: LLM hypothesizes divergences, a deterministic oracle confirms.
export {
  generateConformanceModel,
  structurallyValidateConformanceModel,
  judgeHttpDivergence,
  runHttpConformanceCheck,
  createLiveHttpSender,
} from "./protocol/index.js";
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
  ConformanceModel,
  ConformanceGenResult,
  ConformanceValidator,
  ConformanceGenOptions,
  HttpSender,
  HttpConformanceResult,
  HttpConformanceOptions,
  ConformanceAttempt,
  LiveHttpSenderOptions,
} from "./protocol/index.js";

// xnu-fuzz — IOKit user-client fuzzer (dynamic sibling to the xnu-re review
// profile). See docs/pwnkit-iokit-fuzzer.md and src/xnu-fuzz/.
export * from "./xnu-fuzz/index.js";
