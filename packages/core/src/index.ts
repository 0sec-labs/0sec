// Programmatic scope ingestion (0sec#215). `loadScope` reads a JSON
// scope file; `ScopePolicy` is the matcher used by every URL chokepoint
// in the agent (validateTargetUrl + 5 fetch sites + shellExec URL
// extraction + redirect-final-URL re-check in the crawler).
export { loadScope, matchUrl, ScopePolicy, extractUrls } from "./scope/scope.js";
export type { ScopeJson, ScopeMatch, ScopeRule } from "./scope/scope.js";
export {
  describeScopeGuards,
  isScopeRequired,
  networkScopeRequiredRefusal,
  scopeRequiredRefusal,
  targetRequiresScope,
  SCOPE_DEPENDENT_BASH_GUARDS,
  SCOPE_GUARDS_INERT_EVENT,
} from "./scope/scope-guard.js";
export type { ScopeGuardStatus } from "./scope/scope-guard.js";

// Attribution-header injection (0sec#216). Builds on scope ingestion:
// configures per-engagement headers + UA override that get merged into
// every in-scope outbound request, so coordinated-disclosure venues can
// deconflict 0sec traffic from real attacks.
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

// Engagement hardening profile. One opt-in posture that makes the engine
// behave conservatively on an authorized engagement (no reset-endpoint burst
// probe, rate-limited web-recon pre-pass, no WAF-evasion ladder, jittered
// pacing, reduced rps) plus the auditable record of what was applied.
export {
  resolveEngagementProfile,
  parseEngagementProfileName,
  extractEngagementFromScopeJson,
  describeEngagementPosture,
  effectiveFallbackRps,
  isWafEvasionLadderEnabled,
  ENGAGEMENT_PROFILE_NAMES,
  CONSERVATIVE_RPS,
  CONSERVATIVE_JITTER_MS,
  STANDARD_RPS,
} from "./scope/engagement-profile.js";
export type {
  EngagementPosture,
  EngagementProfileName,
  EngagementProfileInputs,
  EngagementScopeBlock,
  EngagementSource,
} from "./scope/engagement-profile.js";

export { scan } from "./scanner.js";
export type { ScanEvent, ScanListener, ScanEventType } from "./scanner.js";
export { agenticScan } from "./agentic-scanner.js";
export type { AgenticScanOptions } from "./agentic-scanner.js";
export { createScanContext, addFinding, addAttackResult, finalize } from "./context.js";
export { sendPrompt, extractResponseText, isMcpTarget } from "./http.js";
export { createRuntime, ProcessRuntime, LlmApiRuntime, QuotaExhaustedError, OperatorAbortError, parseUsageLimitReached, OpenRouterRuntime, DEFAULT_ENSEMBLE_MODELS, RUNTIME_REGISTRY, pickRuntimeForStage, detectAvailableRuntimes, getRuntimeInfo } from "./runtime/index.js";
export type { Runtime, RuntimeConfig, RuntimeContext, RuntimeResult, RuntimeType, NativeRuntime, NativeMessage, NativeContentBlock, NativeToolDef, NativeRuntimeResult, OpenRouterConfig, UsageLimitDetails } from "./runtime/index.js";
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
// + shared contract (docs/0sec-rust-memsafety-pipeline.md, Track B).
export { runUserspaceFuzzLoop, parseCrashOutput } from "./triage/userspace-fuzz-runner.js";
export type { UserspaceFuzzOptions } from "./triage/userspace-fuzz-runner.js";
// Race-winning widening-gadget engine (#1120): turn a race candidate into a
// reliably-won one via a widening-gadget library + LLM selector + prover glue.
export {
  timerfdInterruptGadget,
  epollWaitqueueFloodGadget,
  cacheMissStallGadget,
  mutexSleepWidenGadget,
  futexHoldGadget,
  GADGET_FACTORIES,
  GADGET_KINDS,
  GADGET_SETUP_MARKER,
  instantiateGadget,
  composeGadgetSetup,
  selectRaceGadgets,
  defaultGadgetsFor,
  attemptWinRace,
  makeKernelVmRaceProver,
  spliceGadgetSetup,
  buildWidenEnv,
  mapVerificationToOutcome,
  setEnv,
} from "./triage/race-gadgets.js";
export type {
  RaceCandidate,
  KcsanRaceCandidate,
  SmellRaceCandidate,
  RaceAccess,
  GadgetKind,
  RaceGadget,
  ComposedGadgets,
  WidenSpec,
  SelectGadgetsOptions,
  RaceProver,
  RaceProverInput,
  RaceProverOutcome,
  AttemptWinRaceOptions,
  AttemptWinRaceResult,
  KernelVmRaceProverBase,
} from "./triage/race-gadgets.js";
export type {
  MemSafetyTarget,
  MemPrimitive,
  CrashArtifact,
  FuzzLoopResult,
  ExploitabilityVerdict,
} from "./triage/memsafety-types.js";
// Integration spine (0sec#700): the A→B→C memory-safety scan stage that
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
// npm-ecosystem dynamic-discovery stage + its extensible DETECTOR registry
// (sspp-fuzz, read-unstable, parser-diff). LLM-proposes / harness-disposes;
// confirmed only on an observed runtime consequence (assume-FP). New bug classes
// plug in as detectors — see docs/operations/detector-from-finding.md.
export {
  runNpmDynamicDiscovery,
  leadToFinding,
} from "./stages/npm-dynamic-discovery.js";
export type {
  NpmDynamicDiscoveryOptions,
  NpmDynamicDiscoveryResult,
  DetectorStat,
} from "./stages/npm-dynamic-discovery.js";
export {
  DETECTOR_REGISTRY,
  DETECTOR_REGISTRY_BY_ID,
  getDetectorById,
  listDetectorIds,
  resolveDetectors,
  runDetectorOnPackage,
  guardPackage,
  dedupConfirmation,
  createOsvAdvisoryLookup,
  deriveForkSiblings,
  OsvLookupError,
  inProcessProbe,
  staticProbe,
  createSandboxPackageRunner,
  localSandboxProvider,
  ssppFuzzDetector,
  readUnstableDetector,
  parserDiffDetector,
} from "./stages/npm-detectors/index.js";
export type {
  Detector,
  DetectorCandidate,
  DetectorConfirmation,
  DedupHints,
  DedupVerdict,
  PackageProbe,
  PackageRef,
  AnyDetector,
  DiscoveryGuards,
  DetectorLead,
  DetectorRunOutcome,
  AdvisoryLookup,
  OsvLookupOptions,
  NpmPackageRunner,
  PackageRunResult,
  SandboxProvider,
  SandboxSession,
  SandboxCommandResult,
  SandboxRunnerOptions,
} from "./stages/npm-detectors/index.js";
// Craft scan stage (agentic reason→craft→submit→refine, injectable PoC oracle):
// the sibling of the fuzz path that needs no target build.
export { runCraftScan, craftedPocToFinding } from "./stages/craft-scan.js";
export { buildCraftCpgContext, extractCraftCpgTargets } from "./stages/craft-cpg-context.js";
export type { CraftCpgContext, CraftCpgLocalization } from "./stages/craft-cpg-context.js";
export {
  buildCraftTargetSpec,
  findCraftFuzzerEntrypoints,
  renderCraftTargetSpec,
} from "./stages/craft-target-spec.js";
export type {
  CraftFuzzerEntrypoint,
  CraftTargetSpec,
  CraftTargetSpecInput,
} from "./stages/craft-target-spec.js";
export {
  defaultCraftCandidateReviewer,
  parseCraftCandidateReview,
} from "./stages/craft-adversarial-review.js";
export type {
  CraftCandidateReview,
  CraftCandidateReviewInput,
  CraftCandidateReviewer,
  CraftCandidateReviewVerdict,
} from "./stages/craft-adversarial-review.js";
// Ensemble craft stage (multi-model best-of-N craft + LLM judge → one PoC).
export {
  runEnsembleCraft,
  judgeCraftCandidatesWithLlm,
  buildCandidateJudgePrompt,
  parseJudgeJson as parseCraftJudgeJson,
  heuristicCraftCandidateScore,
  sanitizerOutputFromCraftResult,
  parseEnsembleModels,
  resolveEnsembleModels,
} from "./stages/ensemble-craft.js";
export type {
  EnsembleCraftOptions,
  EnsembleCraftCandidate,
  CraftCandidateScore,
  CraftCandidateJudge,
} from "./stages/ensemble-craft.js";
// Exploit scan stage (agentic weaponize-to-root, injectable target executor).
export { runExploitScan } from "./stages/exploit-scan.js";
export type { ExploitTarget, ExploitExecutor, ExploitScanOptions, ExploitScanResult } from "./stages/exploit-scan.js";
// Nonce-bound root proof + out-of-band module-load denial for the exploit lane.
// A `uid=0` regex over model-influenced output is NOT a root proof; adapters
// (ExploitGym) must verify their own proof artifact against the same challenge.
export {
  mintRootProofChallenge,
  verifyRootProof,
  rootProofInstructions,
} from "./stages/exploit-stage-gate.js";
export type { RootProofChallenge, RootProofVerdict, RootProofInput } from "./stages/exploit-stage-gate.js";
export { detectOutOfBandModuleLoad } from "./triage/bug-attribution.js";
export type { OutOfBandModuleLoad } from "./triage/bug-attribution.js";
// Domain-agnostic exploit-chain model + web/app planner (#976). Generalizes
// ADR-058's kernel chain-planner over the capability alphabet; the web instance
// (ADR-059's deferred `WebPrimitiveNode`) composes SSRF→metadata→RCE, IDOR→ATO,
// SSTI→RCE, etc. The kernel planner (`kernel/exploit/chain/`) is left untouched.
export {
  planChains,
  buildCompositionGraph,
  isPlannable,
  planWebChains,
  buildWebCompositionGraph,
  buildWebPrimitiveNode,
  webFindingToPrimitiveNode,
  categoryToWebKind,
  defaultProvides,
  defaultNeeds,
  GOAL_WEB_RCE,
  GOAL_WEB_DATA_EXFIL,
  GOAL_WEB_ACCOUNT_TAKEOVER,
  GOAL_WEB_SSRF_INTERNAL,
  WEB_GOALS,
  CANONICAL_WEB_CHAINS,
  CHAIN_SSRF_METADATA_RCE,
  CHAIN_IDOR_PRIVESC_ATO,
  CHAIN_SSTI_RCE,
  CHAIN_AUTHBYPASS_SQLI_EXFIL,
} from "./exploit/chain/index.js";
export type {
  ChainDomain,
  ChainNode,
  ChainGoal,
  CandidateChain,
  CompositionEdge,
  PlanOptions,
  WebCapability,
  WebPrimitiveKind,
  WebPrimitiveNode,
  WebNodeContext,
  WebFindingToNodeOptions,
  CanonicalWebChain,
} from "./exploit/chain/index.js";
// Hunt scan stage (parallel novel-bug discovery: fan-out finders -> skeptic+prover gate).
export { runHuntScan, makeSkepticVerifier, composeGate, makeMultiLensVerifier } from "./stages/hunt-scan.js";
// Deployment-context classification — path heuristics + severity cap for findings
// that target dev/test/build-only code paths (issue #1215, deep-review postmortem).
export { classifyDeploymentContext, applyDeploymentContextCap, stampDeploymentContext, hasTrustBoundaryBypass } from "./stages/deployment-context.js";
export type { DeploymentContext } from "@0sec/shared";
// Depth-method specialized-lens sets, per on-chain review profile. These are
// the ready-made `*FinderLenses` / `*VerifyLenses` fan-out + verify-quorum
// axes the seedless `deep-review` command wires into runHuntScan (G-A).
export { evmFinderLenses, evmVerifyLenses } from "./review/evm-onchain-profile.js";
export { solanaFinderLenses, solanaVerifyLenses } from "./review/solana-onchain-profile.js";
export { cardanoFinderLenses, cardanoVerifyLenses } from "./review/cardano-onchain-profile.js";
export { cairoFinderLenses, cairoVerifyLenses } from "./review/cairo-onchain-profile.js";
export { moveFinderLenses, moveVerifyLenses } from "./review/move-onchain-profile.js";
// Deterministic source-file walkers (shared by the review pipeline + the
// seedless deep-review candidate enumeration + its 5000-file scope cap).
export { collectScopeFiles, countScopeFilesUpTo } from "./source-files.js";
// Hunt best-of-N LLM judge (disambiguates multi-attempt findings before the skeptic gate).
export { judgeHuntCandidatesWithLlm, heuristicCandidateScore } from "./stages/hunt-judge.js";
export type { HuntCandidateJudge, HuntCandidateScore } from "./stages/hunt-judge.js";
// Hunt memory flywheel (0SEC_HUNT_FLYWHEEL=1, ported from 0verse's
// flywheel.py): a preseeded 5-layer memory that PRIMES the best-of-N judge
// ordering + attempt-budget cost-router — it never confirms; see
// hunt-flywheel.ts's header for the invariant.
export {
  huntFlywheelEnabled,
  classTokens,
  jaccard,
  memoryTokens,
  findingTokens,
  primedOrderKey,
  loadHuntCorpusRows,
  HuntMemory,
  PRIME_MIN,
  HUNT_MEMORY_LAYERS,
  provePriming,
} from "./stages/hunt-flywheel.js";
export type {
  HuntMemoryLayer,
  HuntMemoryRecord,
  HuntRecall,
  HuntPriming,
  HuntMemoryOptions,
  HuntCorpusRow,
  HuntProofReport,
} from "./stages/hunt-flywheel.js";
// Learned negatives (0SEC_HUNT_NEGATIVES, default ON): a known-refuted-shape
// memory that attaches prior refute reasons to the skeptic prompt as context.
// Never auto-rejects, and inert until a caller supplies a corpus; see
// hunt-negatives.ts's header.
export {
  huntNegativesEnabled,
  loadKnownNegatives,
  loadKnownNegativesFromEnv,
  matchNegative,
  negativeContext,
  NEGATIVE_MIN,
  MAX_KNOWN_NEGATIVES,
  MAX_NEGATIVE_REASON_CHARS,
  loadKnownNegativesFromLedger,
} from "./stages/hunt-negatives.js";
export type { KnownNegative, NegativeMatch } from "./stages/hunt-negatives.js";
// Shared hunt evidence ledger: the append-only, concurrency-safe claim store a
// hunt CAMPAIGN coordinates through — claims carry their evidence and
// dependencies, observations stay distinguishable from assumptions, and
// disproven claims persist so parallel and sequential workers stop re-walking
// dead ends. Complements the end-of-run corpus (which can only describe hunts
// that already finished); see hunt-evidence-ledger.ts's header.
export {
  appendHuntClaim,
  createHuntClaim,
  validateHuntClaimRecord,
  readHuntLedger,
  loadHuntLedger,
  resolveHuntLedger,
  disprovenHuntClaims,
  unresolvedHuntClaims,
  staleHuntClaims,
  HUNT_CLAIM_SCHEMA_VERSION,
  MAX_CLAIM_STATEMENT_CHARS,
  MAX_EVIDENCE_PER_CLAIM,
} from "./stages/hunt-evidence-ledger.js";
export type {
  EvidenceStance,
  ClaimStatus,
  HuntEvidence,
  HuntClaimShape,
  HuntClaimRecord,
  RecordHuntClaimInput,
  ResolvedHuntClaim,
  ReadHuntLedgerOptions,
} from "./stages/hunt-evidence-ledger.js";
// Cross-family adversarial refuter (0SEC_HUNT_CROSS_FAMILY, default ON, issue
// #661): force the refute pass onto a DIFFERENT model family than the finder
// before a finding is promoted, so their errors decorrelate. Degrades to the
// same-family refute (never to a dropped finding) when only one provider is
// configured; see hunt-cross-family.ts's header for the assume-FP-safe invariant.
export {
  crossFamilyRefuteEnabled,
  selectCrossFamilyRefuter,
  availableRefuterCandidates,
  refuterFamily,
  describeRefuterChoice,
} from "./stages/hunt-cross-family.js";
export type {
  CrossFamilyRefuteConfig,
  CrossFamilyRefuteChoice,
  CrossFamilyStatus,
} from "./stages/hunt-cross-family.js";
export type { RefuteDecorrelation } from "./stages/hunt-scan.js";
// Kernel archetype catalog (multi-archetype hunt seeding; ported from 0verse's
// 90-archetype registry, kernel-domain subset). Data + brief mapping are always
// inert/available; `planArchetypeSweep` is env-gated (0SEC_ARCHETYPE_SWEEP=1).
export {
  kernelArchetypesPath,
  loadKernelArchetypes,
  freebsdArchetypesPath,
  loadFreebsdArchetypes,
  FREEBSD_BARE_KERNEL_WORDS,
  chromiumArchetypesPath,
  loadChromiumArchetypes,
  CHROMIUM_BARE_WORDS,
  needsKernelVerify,
  hypothesisOnly,
  filterArchetypes,
  archetypeToHuntBrief,
  symbolsFromDetectionSignature,
  candidateGrepPatterns,
  generateArchetypeCandidates,
  archetypeSweepEnabled,
  planArchetypeSweep,
} from "./stages/archetype-catalog.js";
export type {
  ArchetypeRoute,
  ArchetypeDomain,
  KernelArchetype,
  ArchetypeFilter,
  ArchetypeCandidateOptions,
  ArchetypeSweepPlan,
  ArchetypeSweepOptions,
  ArchetypeSweepResult,
} from "./stages/archetype-catalog.js";
// The cross-language appsec lens registry — the data-driven sibling of the
// kernel/FreeBSD/Chromium archetype packs, mapped straight to FinderLens[] for
// the seedless finder surfaces (`deep-review` / `hunt`). See appsec-catalog.ts.
export {
  appsecArchetypesPath,
  loadAppsecArchetypes,
  appsecArchetypeToFinderLens,
  loadAppsecFinderLenses,
} from "./stages/appsec-catalog.js";
export type { AppsecRoute, AppsecArchetype, RawAppsecArchetype } from "./stages/appsec-catalog.js";
// Self-improving lens loop — miss ─▶ synthesize ─▶ bench-validate ─▶ register.
// Turns a confirmed finder MISS into a new, validated, registered appsec lens.
// Fail-closed; adds LENSES, never confirms FINDINGS. See stages/lens-synthesis/.
export {
  runLensSynthesisLoop,
  captureLensCandidates,
  coverageGapToCandidate,
  confirmedMissToCandidate,
  persistMisses,
  synthesizeArchetypes,
  clusterCandidates,
  makeDefaultLensSynthesisModel,
  isCrossLanguageHint,
  parseSynthesizedContent,
  SYNTH_TOOL,
  SYNTH_TOOL_NAME,
  validateCandidateLens,
  makeFinderLensProbe,
  registerArchetype,
  buildRegistryEntry,
} from "./stages/lens-synthesis/index.js";
export type {
  LensCandidate,
  LensCandidateSource,
  ConfirmedMiss,
  MissInput,
  SynthesizedArchetype,
  SynthesizedArchetypeContent,
  ValidationFixture,
  ValidationCorpus,
  LensProbe,
  LensProbeOutcome,
  LensValidationReport,
  LensScorecardSummary,
  RegisteredLens,
  LensSynthesisInput,
  LensSynthesisDeps,
  LensSynthesisResult,
  LensSynthesisModel,
  LensCandidateCluster,
  SynthesizeOptions,
  FinderLensProbeOptions,
  ValidateOptions,
  RegisterOutcome,
} from "./stages/lens-synthesis/index.js";
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
// Base-vs-patch differential dedup gate + per-sanitizer-class stack-trace crash
// dedup (issue #1501, ATLANTIS). The gate is a HuntVerifier, so it drops into
// runHuntScan's `opts.verify` slot or composes after skeptic+prover via composeGate.
export {
  normalizeFrame,
  crashSignatureFromText,
  crashSignatureFromReport,
  signatureKey,
  sameCrash,
  dedupByCrashSignature,
  dedupFindingsByCrashSignature,
  makeDifferentialGate,
} from "./stages/differential-dedup.js";
export type {
  CrashSignature,
  CrashGroup,
  BuildVersion,
  CrashRunResult,
  DifferentialReproducer,
  DifferentialGateOptions,
} from "./stages/differential-dedup.js";
// Invariant-checker candidate-gen (kernelCTF Pipeline #2): recover a subsystem's
// lock/refcount/state invariant, then hypothesize concurrent unprivileged
// violations. Sibling of variant-candidates; plugs into runHuntScan.
export { generateInvariantCandidates } from "./stages/invariant-candidates.js";
export type {
  InvariantHuntInput,
  InvariantHuntPlan,
  InvariantSpec,
  InvariantCandidate,
} from "./stages/invariant-candidates.js";
// Recency flywheel (kernelCTF freshness window): git diff a fresh linux-next
// range → reachability filter → semantic-vs-cosmetic classifier → the refined
// invariant engine → adversarial verify → ranked report. Beats the audit-density
// wall by hunting just-committed code before syzbot/top-groups harden it.
export {
  runRecencyHunt,
  runRecencyExtraDetectors,
  runRecencyDualViewDetector,
  classifySemanticVsCosmetic,
  lifetimeTokenSignal,
  isReachablePath,
  resolveRange,
  countCommits,
  changedFilesInRange,
  parseNameStatus,
  fileDiff,
  renderRecencyReportMarkdown,
  RECENCY_REACHABLE_ALLOWLIST,
  RECENCY_DENYLIST,
  RECENCY_DETECTORS_ALL,
  RECENCY_DETECTORS_FULL,
  SEMANTIC_COSMETIC_RUBRIC,
} from "./stages/recency-hunt.js";
export type {
  RecencyHuntInput,
  RecencyHuntReport,
  RecencyHuntDeps,
  RecencyFileRecord,
  RecencySurvivor,
  RecencyDetector,
  DetectorCounts,
  DetectorOutcome,
  RecencyExtraDetectInput,
  RecencyExtraDetectResult,
  RecencyDynamicWitnessConfig,
  RecencyDualViewInput,
  RecencyDualViewResult,
  WitnessEvidence,
  ReachVerdict,
  ReachRule,
  LifetimeSignal,
  ClassifyInput,
  CosmeticVerdict,
  ChangedFile,
} from "./stages/recency-hunt.js";
export { renderRaceHarness, makeTemplateRacePocSynth } from "./stages/race-poc-synth.js";
export type { RacePocRequest, RacePocSynth } from "./stages/race-poc-synth.js";
// Whole-subsystem invariant-model hunting (Engine A, the SEEDLESS discovery
// axis): an LLM builds a stored per-object lock/refcount/lifetime model ONCE,
// then a deterministic tree-sitter dataflow checker (c-dataflow.ts) re-finds
// violations against every new revision for free. `InvariantHuntPlan` is
// aliased — invariant-candidates (above) already owns that name in the barrel.
export {
  buildInvariantModel,
  storeInvariantModel,
  loadInvariantModel,
  findInvariantViolations,
  findInvariantViolationsTokenLevel,
  violationsToHuntPlan,
  runSubsystemInvariantHunt,
  INVARIANT_MODEL_VERSION,
} from "./stages/subsystem-invariant-model.js";
export type {
  LockRule,
  RefcountRule,
  LifecycleRule,
  InvariantObjectModel,
  InvariantModel,
  ViolationKind,
  InvariantViolation,
  BuildModelInput,
  FindViolationsOptions,
  InvariantHuntPlan as SubsystemInvariantHuntPlan,
  SubsystemInvariantHuntInput,
  SubsystemInvariantHuntResult,
} from "./stages/subsystem-invariant-model.js";
// Assumption-mining (Engine A', the FOURTH seedless axis): an LLM MINES the
// implicit relied-on preconditions each function makes (+ the token a caller/
// lock/API uses to establish each) ONCE; then a deterministic 1b cross-check +
// establisher-propagation caller-scan (no LLM) hunts reachable callers that
// reach a relied-on subject WITHOUT establishing its precondition — the
// dual-view/DirtyCred/AF_UNIX-GC/io_uring shape our fixed-schema checkers cannot
// represent. `AssumptionHuntPlan` is aliased to avoid a barrel name clash.
export {
  mineAssumptions,
  normalizeAssumptions,
  storeAssumptionModel,
  loadAssumptionModel,
  crossCheckAssumptions,
  isMechanizableEstablisher,
  buildFunctionBodyIndex,
  computeEstablisherSets,
  computeEstablisherWrappers,
  scanViolatingContexts,
  subjectSelfEnforces,
  isCrossApiAssumption,
  objectTypeToken,
  scanDualViewContexts,
  assumptionsToHuntPlan,
  buildFocusedCandidates,
  runAssumptionHunt,
  ASSUMPTION_MODEL_VERSION,
} from "./stages/assumption-mining.js";
export type {
  AssumptionKind,
  AssumptionProvenance,
  SecurityRelevance,
  ViolationOracle,
  Assumption,
  AssumptionModel,
  MineAssumptionsInput,
  DroppedAssumption,
  CrossCheckResult,
  ViolatingContext,
  CallerScanOptions,
  DualViewOptions,
  AssumptionHuntPlan as AssumptionMiningHuntPlan,
  AssumptionHuntInput,
  AssumptionHuntResult,
} from "./stages/assumption-mining.js";
// v3 DYNAMIC WITNESS — the dynamic oracle for dual-view/cross-phase candidates the
// static skeptic structurally cannot judge (synthesize PoC → boot in KASAN →
// witness an object-bound splat).
export {
  witnessAssumptionViolation,
  witnessDualViewContexts,
  dualViewCandidateFromContext,
  checkWitness,
  pocFabricatesSplat,
  extractCFromLlmOutput,
  extractSplatRegion,
  candidateReferenceTokens,
  buildSynthesisPrompt,
  makeDefaultSynthesizePoc,
  defaultBootPoc,
} from "./stages/dynamic-witness.js";
export type {
  DualViewCandidate,
  CandidateSource,
  PocSynthesisInput,
  PocSynthesisResult,
  SynthesizePocFn,
  BootPocFn,
  WitnessCheck,
  WitnessVerdict,
  WitnessAttempt,
  WitnessResult,
  DynamicWitnessDeps,
  WitnessDualViewInput,
  WitnessDualViewResult,
} from "./stages/dynamic-witness.js";
// The deterministic intra-procedural C dataflow engine behind
// findInvariantViolations (tree-sitter-c AST → per-function CFG → lock-set /
// reaching-free fixpoints). Exported so other checkers can reuse the analysis.
export { parseC, findViolationsDataflow } from "./stages/c-dataflow.js";
export type { DataflowFindOptions } from "./stages/c-dataflow.js";
// Engine A → seeded-hunt adapter (`0sec hunt --invariant`): derive the
// subsystem scope from the seed diff, build-or-load its invariant model, and
// format the model + deterministic violation hypotheses as a finder-prompt
// block appended to the hunt brief.
export {
  deriveSubsystemScope,
  buildInvariantHuntContext,
  formatInvariantPromptBlock,
} from "./stages/invariant-hunt-context.js";
export type {
  SubsystemScope,
  InvariantHuntContextInput,
  InvariantHuntContext,
} from "./stages/invariant-hunt-context.js";
// Graph-slice finder stage (`0sec hunt --graph-slice`): the deterministic
// interprocedural slicer over a pre-exported Joern CPG (graphson JSON) + its
// seed-diff adapter. Feeds the finder a compact cross-function/cross-file
// reachability slice around the fix site — the multi-step chain the flat
// per-file read cannot assemble. See
// docs/operations/graph-native-lpe-harness-2026-07-21.md.
export {
  Cpg,
  loadCpg,
  injectOps,
  findTargets,
  buildSlice,
  renderSlice,
  sliceAroundTargets,
  LIFETIME_SINKS,
} from "./stages/graph-slice.js";
export type {
  CpgNode,
  CallEdge,
  OpsMap,
  OpsSynthEdge,
  SliceResult,
  SliceRenderStats,
  SourceLoader,
} from "./stages/graph-slice.js";
export {
  buildGraphSliceHuntContext,
  extractTouchedFunctions,
  formatGraphSlicePromptBlock,
} from "./stages/graph-slice-hunt-context.js";
export type {
  GraphSliceHuntContextInput,
  GraphSliceHuntContext,
} from "./stages/graph-slice-hunt-context.js";
// Race-widening smell-hunter (kernelCTF Pipeline #3): the LLM hunts the
// ExpRace/Calif smell — unlock(A) -> [sleep/mutex/GFP_KERNEL alloc/copy_from_user]
// -> lock(B) with attacker state across the gap — and maps each smell's
// `widenHint` onto the 0SEC_KERNEL_QEMU_WIDEN_* prover knobs. Sibling of
// variant/invariant-candidates; plugs into runHuntScan.
export { generateRaceSmellCandidates, widenEnvFor, KERNELCTF_TIER1_RACE_GRID } from "./stages/race-smell-candidates.js";
export type {
  RaceSmellHuntInput,
  RaceSmellHuntPlan,
  RaceSmellCandidate,
  RaceWidenHint,
  RaceWidenEnv,
} from "./stages/race-smell-candidates.js";
// kernelCTF-reachability gate for hunt candidate selection (path-based; see
// services/orchestrator/src/kernelctf-config.ts for the CONFIG-symbol ground truth).
export { classifyPathReachability, applyReachabilityGate } from "./stages/hunt-reachability.js";
export type { PathReachability, ReachabilityGateOptions, ReachabilityGateResult } from "./stages/hunt-reachability.js";
// Surface-desirability score for the generic fresh-surface hunt: prioritize
// hard-to-fuzz stateful parsers of untrusted input that are NOT recently swept
// (where source review beats fuzzing). Opt-in; default OFF = size-only ranking.
export {
  applySurfaceRanking,
  scoreSurfaceDesirability,
  computeSurfaceScore,
  gatherSurfaceSignals,
  isHardToFuzzSurface,
  HARD_TO_FUZZ_PATH_PREFIXES,
} from "./stages/surface-desirability.js";
export type {
  SurfaceSignals,
  SurfaceScore,
  SurfaceDesirabilityOptions,
  SurfaceRankingOptions,
  SurfaceRankingResult,
} from "./stages/surface-desirability.js";
// Second-audit (kernelCTF Pipeline #2, deepen-before-verify): treat every crash as
// shallow-by-default; hunt the deeper root cause + whether an existing fix is
// bypassable. Plugs into runHuntScan as the `refine` hook (deepen, then verify).
export { runSecondAudit, defaultSecondAuditModel, makeSecondAuditRefiner } from "./stages/second-audit.js";
export type { SecondAuditInput, SecondAuditResult, SecondAuditModel } from "./stages/second-audit.js";
// Threat-model planner stage — pre-candidate-selection trust-boundary lanes.
export { runThreatModelPlanner, parseThreatLaneJson, allocateCandidatesAcrossLanes, matchesLane } from "./stages/threat-lanes.js";
export type { ThreatLane } from "./stages/threat-lanes.js";
export { extractSpecInvariants, mapInvariantsToImplementation, planSpecdriftHypotheses, runSpecdriftPlan, runSpecdriftScan } from "./specdrift/index.js";
export type {
  DriftHypothesis,
  ExtractSpecInvariantsOptions,
  ImplementationCandidate,
  MapInvariantsToImplementationOptions,
  PlanSpecdriftHypothesesOptions,
  RunSpecdriftScanOptions,
  RunSpecdriftPlanOptions,
  SpecCitation,
  SpecdriftAdapterKind,
  SpecInvariant,
  SpecInvariantKind,
  SpecdriftExtractResult,
  SpecdriftPlanResult,
  SpecdriftScanResult,
} from "./specdrift/index.js";
export type {
  HuntCandidate,
  HuntBrief,
  HuntVerifier,
  HuntScanOptions,
  HuntScanResult,
  HuntFindingRecord,
  HuntDroppedFinding,
  CoverageGap,
  FinderLens,
  VerifyLens,
  MultiLensVerifierOptions,
} from "./stages/hunt-scan.js";
export type {
  CraftTarget,
  CraftPocVerdict,
  CraftPocEvaluator,
  CraftScanOptions,
  CraftScanResult,
} from "./stages/craft-scan.js";
export type {
  CraftEvidenceInput,
  CraftEvidenceKind,
  CraftEvidenceRecord,
  CraftEvidenceStage,
  CraftEvidenceStatus,
} from "./stages/craft-evidence-ledger.js";
export { mergeCraftEvidence } from "./stages/craft-evidence-ledger.js";
export {
  CraftStagedOrchestrator,
  parseCraftStageCitations,
} from "./stages/craft-staged-orchestrator.js";
export type {
  CraftStageCitation,
  CraftStageTransition,
  CraftStagedOrchestratorOptions,
} from "./stages/craft-staged-orchestrator.js";
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

// External seed findings (0sec#368). Parser + reader for ND-JSON leads
// supplied by upstream probes like GemmaForge (`gemmaforge.leads/v1`).
export {
  parseSeedFindings,
  readSeedFindings,
  GEMMAFORGE_LEADS_SCHEMA,
} from "./seed-findings.js";
export type { ParseSeedFindingsOptions } from "./seed-findings.js";

// Agent system
export { runAgentLoop, runNativeAgentLoop, ToolExecutor, getToolsForRole, TOOL_DEFINITIONS, features, estimateCost } from "./agent/index.js";
// Named bundles of 0SEC_FEATURE_* vars — the documented way to enable the
// full FP moat for an A/B run. See `agent/feature-presets.ts`.
export {
  FEATURE_PRESETS,
  applyFeaturePreset,
  applyFeaturePresetFromEnv,
  resolveFeaturePreset,
} from "./agent/feature-presets.js";
export type { FeaturePresetName, PresetApplication } from "./agent/feature-presets.js";
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
  ScopedAuditEscalationRequest,
  OperatorQuestion,
  OperatorQuestionOption,
  OperatorQuestionRequest,
  OperatorQuestionAnswer,
  OperatorQuestionAnswerItem,
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
  JitterConfig,
} from "./scope/rate-limit.js";

// http_audit enforcement (path allowlist + counters + kill switch)
export { PathPolicy, EnforcementTracker } from "./scope/enforcement.js";
export type { EnforcementSummary, PathMatch } from "./scope/enforcement.js";

export type { DBScan, DBFinding, DBTarget, DBAttackResult } from "./db/schema.js";

// API spec parser
export { parseApiSpec } from "./api-spec.js";
export type { ApiSpecSummary, ApiSpecEndpoint, ApiSpecParameter, ApiSpecAuthScheme } from "./api-spec.js";

// Vulnerability intelligence tools (0sec#439)
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
export { isDisclosureWorthy, evidenceKindForFinding } from "./triage/verify-verdict.js";
export type {
  VerifyVerdict,
  VerifyOutcome,
  VerifySignal,
  VerifyEvidenceKind,
  VerdictLike,
  DisclosureDecision,
} from "./triage/verify-verdict.js";
// #659 / #1278 — the pov_oracle bucketing (which categories delegate to the
// out-of-band OAST-callback oracle). Consumed by `0sec verify` to decide when
// a finding's PoV provenance is an OAST callback.
export { oracleForCategory } from "./triage/pov-gate.js";
export type { PovOracle } from "./triage/pov-gate.js";

// Auto-triage gate (#1101): source-fixed / dedup / reachability + false-refute fix
export {
  autoTriage,
  alreadyFixedInTarget,
  knownDupe,
  reachabilityGate,
  extractDupeSignature,
  classifyVerifyOutcome,
  verifyStatusFromOutcome,
  makeTargetTreeLookup,
} from "./triage/auto-triage.js";
export type {
  AutoTriageVerdict,
  AutoTriageOptions,
  AutoTriageResult,
  CheckVerdict,
  ReachabilityTier,
  ReachabilityVerdict,
  ReachabilityOptions,
  AlreadyFixedOptions,
  SourceLookupHit,
  TargetSourceLookup,
  DupeSignature,
  DupeMatch,
  DupeFeedLookup,
  VerifyFailureKind,
  VerifyOutcomeInput,
  VerifyOutcomeDecision,
  VerifyStatus,
} from "./triage/auto-triage.js";

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
// (a non-literal dynamic `import("@0sec/core")`), so it MUST be re-exported
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

// Per-finding triage provenance — which FP-moat layers actually ran, derived
// from the recorded `layerVerdicts` rather than the current env. See
// `triage/provenance.ts` for why that distinction is load-bearing.
export {
  summarizeTriageProvenance,
  formatTriageProvenance,
  UNINSTRUMENTED_LAYERS,
  OPT_IN_MOAT_LAYERS,
} from "./triage/provenance.js";
export type {
  TriageProvenance,
  LayerProvenance,
  LayerExecutionStatus,
} from "./triage/provenance.js";

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

// Action-level durable action log: the per-invocation `tool_calls` payload
// shape, its redacted args preview, the `tool_calls` ↔ `tool_artifact`
// correlation id, and a reader that tolerates pre-upgrade (turn-level) rows.
export {
  newCorrelationId,
  redactedArgsPreview,
  buildToolCallLogEntry,
  buildToolCallsPayload,
  readToolCallNames,
  ACTION_LOG_ARG_VALUE_MAX,
  ACTION_LOG_ARGS_MAX,
} from "./agent/action-log.js";
export type { ToolCallLogEntry, ToolCallsLogPayload } from "./agent/action-log.js";

// Opt-in cloud-sink: POST findings/leads to the orchestrator
// (`POST /scans/:id/findings`) when 0SEC_CLOUD_SINK + 0SEC_CLOUD_SCAN_ID are
// set. Exposed so `0sec hunt` can ingest its gated leads as candidate
// findings the same way scan/review reach the cloud (#1051).
export { getCloudSinkConfig, postFinding } from "./cloud-sink.js";
export type { CloudSinkConfig } from "./cloud-sink.js";

// Kernel crash ingest (crash report → Finding pipeline)
export { parseCrashReport, crashToFinding, ingestArtifactsFromDirectory, ingestArtifactsFromFile, ingestFile, ingestDirectory, crashTypeToCategory, crashSeverity, reviewKernelCrashSubsystems } from "./ingest/index.js";
export type { KernelCrashArtifact, KernelSubsystemReviewOptions, KernelSubsystemReviewResult, KernelSubsystemReviewRunner, KernelSubsystemReviewRunnerInput, KernelSubsystemReviewSkip } from "./ingest/index.js";

// Kernel advisory variant hunting (foxguard SARIF → 0sec findings)
export {
  foxguardFindingToKernelVariantFinding,
  runKernelVariantHunt,
} from "./kernel/index.js";
export type {
  KernelVariantHuntOptions,
  KernelVariantHuntReport,
} from "./kernel/index.js";

// Kernel attack surface enumeration (0sec#471)
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

// Syzbot invalid / auto-closed queue mining (LPE-hunt upgrade #0) — a net-new
// bug-supply channel that mines syzbot's DISCARDED reports (invalid / no-repro /
// moderation) into ranked hunt candidates. Ingestion + candidate-mapping only;
// the dynamic repro is handed to the existing (bench-gated) kernel-vm path.
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
  generateSyzChoiceWeights,
  syzChoiceWeightsFromPlan,
} from "./kernel/index.js";
export type {
  SyzChoiceWeightsOptions,
  SyzChoiceWeightsFile,
  SyzChoiceWeightsResult,
} from "./kernel/index.js";
export type {
  SyzbotFetcher,
  SyzbotBucket,
  SyzbotCandidate,
  SyzbotQueueMineOptions,
  SyzbotQueueMineResult,
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
// Autonomous LLM-composed weaponization climb (feat/autonomous-climb-loop).
export {
  autonomousClimb,
  defaultComposerModel,
  TECHNIQUE_LIBRARY,
  getTechnique,
  techniquesForBug,
  renderLibraryBrief,
  renderTriggerSeed,
  renderRungReliabilitySeeds,
  triggerTechniquesForFamily,
  emitMarkerHelper,
  arbWriteTargetV,
  arbWriteFaultWitnessed,
  arbReadValueWitnessed,
  triggerSplatWitnessed,
  fnv1a64,
  hex64,
} from "./kernel/exploit/index.js";
export type {
  AutonomousClimbBug,
  AutonomousClimbOptions,
  AutonomousClimbResult,
  ClimbRound,
  ComposerModel,
  ExploitTechnique,
  TechniqueConstraint,
  TechniquePrecondition,
  TechniqueBugClass,
} from "./kernel/exploit/index.js";

// kernelCTF patch-gap 1day monitor (upstream-fixed CVE feed → target-tree
// presence check → kernelCTF reachability gate → ranked candidates). See
// 0sec/packages/core/src/kernel/patch-gap.ts.
export { parseVulnsCveRecord, loadVulnsFeedFromDir, defaultVulnsFeedIo } from "./kernel/index.js";
export type { UpstreamFixEntry, RawVulnsCveRecord, VulnsFeedIo, LoadVulnsFeedOptions } from "./kernel/index.js";
export {
  checkFixPresentInTarget,
  checkNotYetIntroduced,
  defaultGitExec as defaultPatchGapGitExec,
} from "./kernel/index.js";
export type {
  GitExec as PatchGapGitExec,
  FixPresenceResult,
  FixPresenceMethod,
  NotYetIntroducedResult,
  NotYetIntroducedMethod,
} from "./kernel/index.js";
export { classifyPatchGapReachability } from "./kernel/index.js";
export type { PatchGapReachability, PatchGapReachabilityResult } from "./kernel/index.js";
export { scanForPatchGapCandidates } from "./kernel/index.js";
export type { PatchGapCandidate, PatchGapScanOptions, PatchGapScanResult } from "./kernel/index.js";
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
  classifyDmesgDanger,
  rankDanger,
  maxDangerClass,
  isDangerUpgrade,
  BENIGN_MAX_CLASS,
  UPGRADE_MIN_CLASS,
} from "./triage/kernel-primitive.js";
export type {
  KernelPrimitive,
  KernelPrimitiveKind,
  PrimitiveControl,
  ControlDemoStep,
  UpgradeClass,
} from "./triage/kernel-primitive.js";

// Execution-verified exploitability-upgrade oracle — the PROVE stage (#1119).
export {
  makeDiversifyOracle,
  makeDifferentialOracle,
  attemptExploitabilityUpgrade,
  foldExploitabilityIntoSeverity,
  shouldWeaponize,
  makeExploitabilityGate,
  // The `weaponize` slot fillers: `makeWeaponizeHook` adapts any
  // `runWeaponization`-shaped driver into the gate's dependency;
  // `weaponizationProven` / `foldWeaponizationIntoVerdict` are the conservative
  // fold (only a demonstrated arb-write/root rung may move a verdict).
  makeWeaponizeHook,
  weaponizationProven,
  foldWeaponizationIntoVerdict,
  WEAPONIZATION_PROVEN_BAR,
  reachableTargets,
  parseWidenTarget,
  primitiveBaselineClass,
  provenExploitabilityScore,
} from "./triage/exploitability-upgrade.js";
// Per-finding PROVE stage — the adapter that makes the kernel-VM exploitability
// oracle reachable as `runHuntScan`'s `opts.exploitability` (see the module
// header for why the gate must be built per finding, not once per hunt).
export {
  makeHuntProveStage,
  defaultReproducerFor,
  defaultDmesgFor,
} from "./triage/hunt-prove-stage.js";
export type {
  HuntProveStageDeps,
  ProveOracles,
  ProveOracleInput,
} from "./triage/hunt-prove-stage.js";

// SyzScope-style impact-ceiling gate (triage/escalation-gate.ts) — the CHEAP,
// VM-free pre-filter in front of the PROVE oracle above.
//
// NOTE on the deliberate alias: `escalation-gate.ts` also exports a
// `shouldWeaponize`, but it is a DIFFERENT predicate from the one exported above
// from `exploitability-upgrade.ts` (ceiling >= bar vs. oracle-proven upgrade).
// Both are legitimate; exporting both under one name is what previously kept the
// escalation gate off this public surface entirely. It is re-exported here as
// `ceilingClearsWeaponizeBar` so callers must say which question they mean.
export {
  assessEscalation,
  describeEscalation,
  maxCeiling,
  parseLlmEscalation,
  shouldWeaponize as ceilingClearsWeaponizeBar,
} from "./triage/escalation-gate.js";
export type {
  EscalationVerdict,
  ImpactCeiling,
  EscalationBasis,
  AssessEscalationOptions,
} from "./triage/escalation-gate.js";

export type {
  ExploitabilityVerdict as KernelExploitabilityVerdict,
  EscalationPreGate,
  UpgradeTrial,
  PrivescTarget,
  DiversifyOracle,
  DiversifyRunner,
  DiversifyTrialInput,
  DiversifyTrialResult,
  DiversifyOptions,
  DiversifyResult,
  DifferentialOracle,
  DifferentialRunner,
  DifferentialBootInput,
  DifferentialBootResult,
  DifferentialOptions,
  DifferentialResult,
  AttemptUpgradeOptions,
  FoldSeverityOptions,
  PrimitiveResolver,
  ExploitabilityGateDeps,
  WeaponizeContext,
  WeaponizationOutcome,
  WeaponizationRecord,
  WeaponizationRunner,
} from "./triage/exploitability-upgrade.js";

// REAL kernel-VM adapter for the PROVE oracle — the prod observation source
// (LPE upgrade-plan #2). Builds the DiversifyRunner/DifferentialRunner seams over
// the real kernel-vm-runner lanes; injectable so tests stay fully offline.
export {
  makeKernelVmDiversifyRunner,
  makeKernelVmDifferentialRunner,
  makeKernelVmOracles,
  makeKernelVmExploitabilityGate,
  defaultDifferentialRootDetector,
  withEnvOverrides,
  // Terminal rung-ranking gate — highest PROVEN rung on a real KASAN/KCSAN boot.
  rungRankingEnabled,
  makeKernelVmRungAdjudicator,
  makeRungRankingGate,
  rankBugsByProvenRung,
} from "./triage/exploitability-oracle-runner.js";
export type {
  KernelVmBootFn,
  EnvBag,
  KernelVmDiversifyRunnerDeps,
  KernelVmDifferentialRunnerDeps,
  KernelVmDifferentialExploit,
  DifferentialRootDetector,
  KernelVmOraclesDeps,
  KernelVmProfileArtifacts,
  ProvenRungResult,
  KernelVmRungAdjudicatorDeps,
  RankedBug,
  RungExploitResolver,
  RungRankingGateDeps,
} from "./triage/exploitability-oracle-runner.js";

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

// Kernel promotion envelope — pure evidence aggregator (no I/O, no mutation).
export {
  buildKernelPromotionEnvelope,
  isConfirmed,
  isHypothesisOnly,
  hasValidValidation,
} from "./triage/kernel-promotion-envelope.js";
export type {
  KernelPromotionEnvelope,
  KernelPromotionInputs,
  KernelPromotionStatus,
  KernelCandidateIdentity,
  KernelSourceSinkContext,
  KernelCleanControlReceipt,
  SemanticValidationStatus,
} from "./triage/kernel-promotion-envelope.js";

// KCSAN data-race triage (kernelCTF Pipeline #1, issue #1112).
export { parseKcsanReport } from "./triage/kcsan-race.js";
export type { KcsanRace, KcsanAccess } from "./triage/kcsan-race.js";
export {
  triageKcsanRace,
  kcsanRaceToBrief,
  kcsanRaceToFinding,
  makeRaceWidenProver,
  raceWidenEnv,
  detectKasanSplat,
  DEFAULT_RACE_WIDEN_DELAY_MS,
} from "./triage/kcsan-triage.js";
export type {
  KcsanProverConfig,
  TriageKcsanOptions,
  TriageKcsanResult,
} from "./triage/kcsan-triage.js";

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

// Cloud event-bus sink (0SEC_CLOUD_EVENTS=1 → emit `0SEC_EVENT_<TYPE>`
// lines on stdout for the 0sec-cloud worker-controller to relay).
// The CLI entry must call `maybeSubscribeCloudEventSink()` so the sink
// subscribes once; without that call the sink module is dead code and
// the cloud's live-trace UI stays dark for every scan.
export {
  eventBus,
  cloudEventSink,
  maybeSubscribeCloudEventSink,
  isCloudEventSinkActive,
} from "./events/bus.js";
// herdr pane-state sink. Reports only 0sec's coarse working/idle state and
// non-identifying counters to the local herdr socket, so a 0sec pane stops
// showing as "unknown" in herdr's sidebar. Inert unless HERDR_ENV=1 with a
// socket and pane id present. Never carries engagement content — the socket
// is readable by any process running as this user.
export { HerdrEventSink, createHerdrEventSink } from "./integrations/herdr.js";
// Structured diagnostics. Defaults to stderr so non-interactive runs never
// lose a quota or retry notice; the TUI claims the channel at mount so the
// same messages land in the transcript instead of over the framebuffer.
export * from "./diagnostics/channel.js";
// Agent coordination hub: peer roster + a crash-safe local message spool.
// Messages are inert prose by construction — nothing in one can grant scope,
// approve a tool, or alter another session's authorization state.
export {
  BROADCAST_ID,
  MAX_BODY_CHARS,
  MAX_INBOX_MESSAGES,
  decodeMessage,
  drainInbox,
  encodeMessage,
  hubDir,
  isValidPeerId,
  newMessageId,
  peekInbox,
  sendMessage,
  stripUnsafeText,
} from "./hub/mailbox.js";
export type { HubMessage, SendResult, SendFailure } from "./hub/mailbox.js";
// Agent-to-agent addressing policy + the operator→child steering path. The
// policy is pure and inert (it grants nothing); `sendOperatorMessage` is the
// one supported way the console steers a specific running subagent's mailbox.
export {
  decideAddressing,
  clampOutboundBody,
  sendOperatorMessage,
} from "./agent/agent-messaging.js";
export type {
  MessagingRuntime,
  PeerRole,
  AddressDecision,
  OperatorMessageResult,
} from "./agent/agent-messaging.js";
// Persistent cross-session hunt memory: a redacted, crash-safe findings/pattern
// store so one target's learnings inform the next.
export * from "./memory/index.js";
// Plugin manifest + capability model. Capabilities translate into the SAME
// gate maps the built-in tools use, so a plugin tool cannot acquire a
// second, weaker authorization path. Fail-closed: an undeclared or unknown
// capability set yields the most restrictive treatment, never read-only.
export {
  validatePluginManifest,
  gateFlagsFor,
  PLUGIN_CAPABILITIES,
  type PluginCapability,
  type PluginToolManifest,
  type PluginManifest,
  type ValidationResult,
} from "./plugins/manifest.js";
// Monotonic, deny-only guard layer beneath the name-keyed gates. Guards can
// only ever narrow what is permitted: there is no value a guard can return
// that means "allow", so composing more guards cannot loosen policy and a
// plugin cannot suppress the authorization chain.
export {
  evaluateGuards,
  composeGuards,
  sanitizeReason,
  guardNetworkRequiresScope,
  guardApprovalUnavailable,
  guardUnresolvedCapabilities,
  BUILTIN_GUARDS,
  type ToolGuard,
  type GuardContext,
  type GuardVerdict,
} from "./plugins/guards.js";
// Model-authored session extensions. A contribution carries tool
// definitions and DENY-ONLY guards and nothing else — no hook, interceptor
// or listener is expressible, so it cannot suppress the authorization chain
// the way dsh's pre-execute waterfall can. Off by default.
export {
  SelfExtensionRegistry,
  SELF_EXTENSION_SETTING_DEF,
  MAX_EXTENSIONS_PER_SESSION,
  MAX_TOOLS_PER_EXTENSION,
  MAX_TOOLS_PER_SESSION,
  MAX_GUARDS_PER_EXTENSION,
  MAX_MANIFEST_BYTES,
} from "./plugins/self-extension.js";
export type {
  ExtensionSubmission,
  ExtensionGateFlags,
  RegisteredExtensionTool,
  SelfExtensionRecord,
  SelfExtensionEvent,
  RegistrationResult,
  ExtensionDisposer,
  ExtensionOrigin,
} from "./plugins/self-extension.js";
// ── Third-party plugin lifecycle (install → enable → run → hot-swap) ──────────
// These are the primitives the `0sec plugin` CLI surface drives. They are the
// SAME modules the console loads plugins through, so the CLI never duplicates
// loader/registry/enablement logic — it imports it. Every security invariant
// (install ≠ enablement, the single capability→gate translation, the re-approval
// rule on a widened capability set, the subprocess boundary) lives in these
// modules and is not re-implemented at the CLI layer.
//
// Per-project enablement store. `enable`/`disable` write ONE json record and
// spawn nothing; `reconcile` + `loadableIds` enforce the re-approval rule so a
// plugin whose on-disk capabilities widened past what the operator approved is
// never handed to the loader.
export {
  ENABLEMENT_DIR_NAME,
  ENABLEMENT_DIR_MODE,
  ENABLEMENT_FILE_MODE,
  ENABLEMENT_SCHEMA_VERSION,
  emptyEnablement,
  aggregateCapabilities,
  isEnabled,
  enable,
  disable,
  reconcile,
  loadableIds,
  coerceEnablementRecord,
  enablementDir,
  enablementFilePath,
  readEnablement,
  writeEnablement,
} from "./plugins/enablement.js";
export type {
  EnabledPluginRecord,
  EnablementRecord,
  InstalledPluginView,
  EnablementStatus,
  ReconciledPlugin,
  EnableResult,
} from "./plugins/enablement.js";
// Loader / host. `PluginHost` is the ONLY module that spawns a plugin; it runs
// every contributed tool through `gateFlagsFor` and refuses any id absent from
// the caller-supplied `enabled` set. `reload()` is a genuine kill+respawn that
// is refused while a call is in flight — hot-swap without dropping a turn.
export {
  PLUGINS_ROOT_NAME,
  PLUGIN_MANIFEST_FILE,
  PLUGIN_ENTRY_FILE,
  PLUGIN_DIR_MODE,
  PLUGIN_FILE_MODE,
  DEFAULT_HANDSHAKE_TIMEOUT_MS,
  DEFAULT_CALL_TIMEOUT_MS,
  MAX_INFLIGHT_CALLS,
  MAX_PROTOCOL_ERRORS,
  isSafePluginId,
  pluginsRootDir,
  ensurePluginsRoot,
  listInstalledPluginIds,
  readInstalledPlugin,
  buildPluginEnv,
  nodeChildSpawner,
  manifestDrift,
  satisfiesMinVersion,
  PluginHost,
} from "./plugins/loader.js";
export type {
  DiscoveredPlugin,
  DiscoveryResult,
  PluginSpawnSpec,
  PluginChannel,
  PluginChannelHandlers,
  PluginSpawner,
  RegisteredPluginTool,
  PluginGateMaps,
  PluginHostEvent,
  LoadResult,
  PluginCallResult,
  PluginHostOptions,
} from "./plugins/loader.js";
// Marketplace registry client. Fetches + validates an index (HTTPS only) and
// applies the signature policy; the index is DATA, never code — nothing here
// executes anything. No endpoint ships (`DEFAULT_REGISTRY_URL` is empty).
export {
  DEFAULT_REGISTRY_URL,
  unconfiguredVerifier,
  createStubSignatureVerifier,
  canonicalEntryPayload,
  evaluateSignature,
  installableFromEntry,
  parseRegistryIndex,
  fetchRegistryIndex,
  searchInstallable,
  findInstallable,
} from "./plugins/registry-client.js";
export type {
  RegistrySource,
  RawRegistryEntry,
  RawRegistryIndex,
  SignatureState,
  InstallableEntry,
  DroppedEntry,
  RegistryResult,
  SignatureVerifier,
  ParseOptions,
  FetchRegistryOptions,
  FetchRegistryResult,
} from "./plugins/registry-client.js";
// Plugin wire protocol (pure). Message shapes + total decoders shared by the
// host, tests, and any third-party plugin SDK.
export {
  PROTOCOL_VERSION,
  MAX_FRAME_CHARS,
  MAX_RESULT_CHARS,
  RESULT_TRUNCATION_MARKER,
  MAX_TOOLS_IN_LIST,
  clampResultContent,
  encodeHostMessage,
  encodePluginMessage,
  decodePluginMessage,
  decodeHostMessage,
  FrameReader,
} from "./plugins/protocol.js";
export type {
  HostListToolsMessage,
  HostCallToolMessage,
  HostMessage,
  PluginHandshakeMessage,
  PluginListToolsMessage,
  PluginToolResultMessage,
  PluginErrorMessage,
  PluginMessage,
  ProtocolDecodeFailureReason,
  ProtocolDecodeFailure,
  DecodeResult,
  FrameBatch,
} from "./plugins/protocol.js";
export type {
  CostBreakdownEntry,
  ScanCompletedPayload,
  SubagentLifecyclePayload,
} from "./events/bus.js";
export { ScanCostLedger } from "./agent/cost-ledger.js";

// Live-agent state reducer (CLI TUI panel). Pure transform of
// eventBus payloads into a "what the agent is doing right now"
// snapshot, with replace-in-place semantics so the terminal stays
// readable on long scans.
export {
  hasLiveAgentState,
  reduceLiveAgentState,
} from "./agent/live-agent-state.js";
export type { LiveAgentState } from "./agent/live-agent-state.js";

// Verification spec evaluator (0sec#193 / 0sec-cloud#111). Re-checks a
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

// Source fix-and-retest workflow. Generates a scoped local patch only for an
// already reproduced finding, validates it in an isolated Git worktree, then
// optionally applies the same patch after the source contract and test command
// both pass.
export { runSourceFix } from "./fix/index.js";
export type {
  SourceFixAttempt,
  SourceFixOptions,
  SourceFixResult,
  SourceFixStatus,
  SourceFixTestResult,
} from "./fix/index.js";

// Deterministic replay runner skeleton (0sec#193). Consumes a finding's
// `pocSteps`, sequentially executes them via a pluggable runner (local
// shell today; docker/qemu interfaces only), and emits a canonical
// `VerificationResult` payload matching `@0sec/shared/verification`.
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

// HackerOne hacker-API integration (read-only). `0sec h1 …` CLI lives
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

// 0sec-cloud auth + HTTP client (CLI half of #303). The server-side
// token-mint endpoint lives in 0sec-cloud and is out of scope here;
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
  WindowsEvidenceWorkerClient,
  WindowsEvidenceWorkerTransportError,
} from "./cloud/index.js";
export type {
  CloudCredentials,
  LoadCloudCredentialsOptions,
  CloudClientOptions,
  CloudHealthResponse,
  WindowsEvidenceStoredBlob,
  WindowsEvidenceSubmissionReceipt,
  WindowsEvidenceWorkerBlob,
  WindowsEvidenceWorkerClientOptions,
  WindowsEvidenceWorkerHandoff,
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
export { suggestCwesForCategory, formatCweSection, suggestCvss, renderAdvisoryMarkdown, EmptyPocError, redactSensitiveHeaders, renderExploitScreenshot, isFreezeAvailable, composeExploitSession, composeStepSession, verifyAgainstRef, extractFileRefs, formatPatchStatusSection, detectVersionRange, formatVersionRangeLine, extractSiblingFix, executePocSteps, setRuntimeDeps, MAX_CAPTURE_BYTES, DEFAULT_STEP_TIMEOUT_MS, decideFilingState, assembleBundleIndex, formatDroppedReason, droppedFilename, dropSlug, suggestCvss4, computeCvss4BaseScore, parseCvss4Vector, formatCvss4Vector, scoreCvss4Vector, cvss4Severity, renderCvssSection, Cvss4ParseError, reportTemplate, renderPlatformReport, REPORT_PLATFORMS } from "./disclose/index.js";
export type { CweEntry, CvssSuggestion, AdvisoryContext, AdvisoryScreenshot, RenderedAdvisory, ScreenshotResult, ScreenshotOptions, PatchStatus, FileRef, ReverifyResult, ReverifyOptions, VersionRangeResult, VersionRangeOptions, SiblingFixCandidate, SiblingFixOptions, PocExecutionTarget, PocExecutionReport, PocStepResult, PocStepVerdict, PocOverallVerdict, FilingState, BundleEntry, AssembleIndexOptions, Cvss4Selection, Cvss4Score, Cvss4BaseKey, ReportPlatform, ReportSection, RenderedPlatformReport, PlatformReportTemplate } from "./disclose/index.js";

// #928 — disclosure-process tracking (status state machine + timeline) and the
// evidence-pack assembler (finding → vendor-notification draft). DRAFT-only,
// never sends.
export { DISCLOSURE_STATUSES, TERMINAL_STATUSES, PUBLIC_STATUSES, allowedNextStatuses, canTransition, createDisclosureRecord, transition, isPubliclyDisclosed, IllegalTransitionError, assembleEvidencePack, renderVendorNotificationMarkdown, UnreproducedFindingError } from "./disclose/index.js";
export type { DisclosureStatus, DisclosureRecord, DisclosureTimelineEvent, TransitionInput, VendorNotificationDraft, EvidencePackOptions } from "./disclose/index.js";

// PR-shaped finding output (0sec#377). `emitFindingsAsPRs` turns reproduced
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

// ── Scan-level pass@k bench harness (0sec#556) ──
// Turns the per-finding verify oracles into a scan-level scorecard
// (success rate, FP rate vs known-negatives, cost-per-success) + CI gate.
export * from "./bench/index.js";

// ── Interactive operator console: unified conversational front-end that drives
// the full tool registry through the real ToolExecutor + LlmApiRuntime. ──
export {
  createConsoleSession,
  createConsoleRuntime,
  buildConsoleSystemPrompt,
} from "./console/index.js";
export type {
  ConsoleSession,
  ConsoleSessionConfig,
  ConsoleRenderCallbacks,
  ConsoleTurnOutcome,
  ConsoleStopReason,
  ConsoleAutonomyMode,
  ConsoleScopeRequest,
  ConsoleScopeResolution,
  ConsoleLocalScopeRequest,
  ConsoleLocalScopeResolution,
  ConsoleTurnBudget,
  ConsoleUsageReport,
} from "./console/index.js";

// ── Recon mode: domain surface enumeration (0sec#769) ──
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
// Active subdomain brute-force (0sec#924) — OFF by default, scope-gated +
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

// Target-neutral research control plane. Existing engines remain native and
// opt in through adapters; the common runner owns stage order and evidence.
export * from "./research/index.js";
// JS-driven endpoint + secret discovery (0sec#927) — scope-gated,
// deny-by-default; mines a site's JS bundles for endpoints + redacted secrets.
export { runJsRecon, MAX_JS_FILES } from "./recon/js-recon.js";
export type { JsReconOptions, JsReconResult } from "./recon/js-recon.js";
export type { SecretHit, FetchTextResult } from "./recon/js-artifacts.js";
// Extract JS chunk URLs from a page's HTML (resolves relative, dedupes,
// .js/.mjs only) — feeds runJsRecon's scriptUrls from a single page fetch.
export { enumerateJsChunkUrls } from "./recon/stack-fingerprint.js";
// Live cloud-surface probes (0sec#925) — read-only, gated behind the
// 0SEC_FEATURE_CLOUD_SURFACE flag AND an engagement ScopePolicy.
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
// profile). See docs/0sec-iokit-fuzzer.md and src/xnu-fuzz/.
export * from "./xnu-fuzz/index.js";
export * from "./adgraph/index.js";
export * from "./identity/index.js";
export * from "./attack/index.js";

// Local, redacted reproducibility manifests for verified findings.
export {
  assembleReproducibilityManifest,
  renderReproducibilityManifest,
  UnverifiedFindingError,
  IncompleteEvidenceError,
} from "./disclose/reproducibility-manifest.js";
export type {
  ReproducibilityManifest,
  ManifestOptions,
} from "./disclose/reproducibility-manifest.js";
// file-review — deepsec-pattern whole-repo review harness (scan → coverage
// gate → batched AI investigation with refusal audit/field repair →
// static revalidation), resumable with cost/duration caps.
export * from "./file-review/index.js";

// Improvement-plane promotion policy. This evaluates sealed benchmark
// receipts and appends tamper-evident decision records; it never executes or
// deploys a candidate into an active engagement worker.
export {
  DEFAULT_IMPROVEMENT_PROMOTION_POLICY,
  appendImprovementLedgerEntry,
  evaluateImprovementPromotion,
  verifyImprovementLedger,
} from "./bench/improvement-promotion.js";
export type {
  ImprovementCandidate,
  ImprovementCandidateKind,
  ImprovementLedgerEntry,
  ImprovementLedgerEventType,
  ImprovementLedgerVerification,
  ImprovementPromotionCheck,
  ImprovementPromotionDecision,
  ImprovementPromotionPolicy,
  ImprovementPromotionStatus,
} from "./bench/improvement-promotion.js";
