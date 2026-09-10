/**
 * Self-improving lens loop — shared contract.
 *
 * The loop turns a confirmed finder MISS into a new, validated, registered
 * appsec finder lens (the moat). Four composable stages, all fail-closed:
 *
 *   1. miss-capture  — normalize (a) hunt-scan `incompleteCoverage` cells and
 *                      (b) confirmed misses into typed {@link LensCandidate}s.
 *   2. synthesize    — cluster candidates and LLM-generate a candidate appsec
 *                      archetype in the registry schema (native tool call).
 *   3. validate      — route the candidate lens through the bench tournament:
 *                      it MUST catch the seeded miss AND NOT regress the
 *                      negative-control corpus. A non-champion is DISCARDED.
 *   4. register      — append ONLY a validated champion to the appsec registry
 *                      via a schema-preserving, id-idempotent safe writer.
 *
 * ============================================================================
 * INVARIANT (inherited from the flywheel): this loop adds LENSES; it never
 * confirms FINDINGS. Miss-capture persists CANDIDATE lenses into a store that
 * is disjoint from the 5-layer priming memory, so `HuntMemory.recall/prime`
 * (the "primes, never confirms" path) is byte-unaffected. See
 * hunt-flywheel.ts's `recordMiss`.
 * ============================================================================
 */

import type { Finding } from "@0sec/shared";
import type { CoverageGap, FinderLens } from "../hunt-scan.js";

// ── Stage 1: miss capture ─────────────────────────────────────────────────

/** Where a {@link LensCandidate} came from. */
export type LensCandidateSource = "confirmed-miss" | "incomplete-coverage";

/**
 * A typed record of ONE coverage miss — the raw material stage 2 clusters and
 * synthesizes into a lens. This is a CANDIDATE (a proposal to hunt a class),
 * never a confirmed finding.
 */
export interface LensCandidate {
  /** The bug class the finder missed (a CWE code and/or a class phrase). */
  classHint: string;
  /** The concrete sink shape, when known ("" for a bare coverage-timeout gap). */
  sinkPattern: string;
  /** "path/to/file.ext:line" (or just the file/dir) where the miss lives. */
  exampleFileLine: string;
  /** Why the finder didn't surface it (timeout, under-weighted class, …). */
  whyMissed: string;
  source: LensCandidateSource;
}

/**
 * A bug that a verify step or a human confirmed is REAL but the finder did not
 * surface. The strongest miss signal — stage 1 turns it into a
 * `source: "confirmed-miss"` {@link LensCandidate}.
 */
export interface ConfirmedMiss {
  /** The confirmed bug class (a CWE code and/or class phrase). */
  classHint: string;
  /** The concrete sink shape the finder should have flagged. */
  sinkPattern: string;
  /** File the miss lives in. */
  file: string;
  /** 1-based line, when known. */
  line?: number;
  /** Why the finder missed it (the lens gap this loop should close). */
  whyMissed: string;
}

/** The two miss inputs stage 1 ingests. */
export interface MissInput {
  /** hunt-scan's structured "(file × lens) cell never fully hunted" signal. */
  incompleteCoverage?: CoverageGap[];
  /** Bugs confirmed real that the finder didn't surface. */
  confirmedMisses?: ConfirmedMiss[];
  /**
   * Independently approved feedback candidates, preserving their original
   * source — NOT a finding confirmation. These are LensCandidates that
   * passed human or automated review and are ready for synthesis alongside
   * coverage-gap and confirmed-miss candidates. The source field is
   * preserved as-is from the originating feedback pipeline.
   */
  curatedCandidates?: LensCandidate[];
}

// ── Stage 2: synthesis ────────────────────────────────────────────────────

/**
 * The content fields the synthesis LLM produces for one candidate archetype —
 * exactly the human-authored subset of the registry schema. The loop fills the
 * deterministic/fixed fields (`domain`, `route`, `engine_lens`, `uid`) and the
 * provenance fields (`source`, `validated_at`, `miss_refs`) itself; the model
 * never sets those.
 */
export interface SynthesizedArchetypeContent {
  /** kebab-case class id, e.g. "ssrf-url-fetch". Becomes the FinderLens id. */
  id: string;
  name: string;
  /** e.g. "CWE-918" or "CWE-918 / CWE-611". */
  cwe: string;
  subsystem: string;
  pattern: string;
  detection_signature: string;
  /** The load-bearing, cross-language, sink-citing hunt angle (FinderLens.challengeHint). */
  challenge_hint: string;
  grounding: string[];
  confirmable: string;
}

/** A synthesized candidate archetype + the misses that motivated it. */
export interface SynthesizedArchetype {
  content: SynthesizedArchetypeContent;
  /** exampleFileLine refs of the {@link LensCandidate}s in this cluster. */
  missRefs: string[];
  /** How many candidates clustered into this archetype. */
  clusterSize: number;
}

// ── Stage 3: validation ───────────────────────────────────────────────────

/**
 * One corpus fixture the validation probe hunts. `path` is a source file or
 * directory on disk. Positives EXHIBIT the missed bug (the lens must catch
 * them); negative controls are clean (the lens must not raise a finding).
 */
export interface ValidationFixture {
  id: string;
  /** Absolute or cwd-relative path to a source file or directory. */
  path: string;
  /** Optional human note (what the fixture exhibits). */
  note?: string;
  /**
   * The independent expected CWE code, e.g. "CWE-918". Required for positives.
   * The host evaluator compares this with reported finding identity;
   * a probe's own match assertion is not evidence.
   */
  expectedCwe?: string;
  /**
   * Expected source-root-relative path, or absolute path within the fixture.
   * A file fixture uses its parent as source root; a directory uses itself.
   * Required for positives. Comparison preserves the complete relative path.
   */
  expectedFile?: string;
  /** Expected 1-based line where the intended finding should be raised. */
  expectedLine?: number;
  /** Inclusive [start, end]; takes precedence over expectedLine when both exist. */
  expectedRange?: [number, number];
  /**
   * sha256 content digest of the fixture at validation time. When set, the
   * validation compares it against the current file content to detect drift,
   * rejecting the run on mismatch (fail-closed).
   */
  contentDigest?: string;
  /**
   * For negative controls: provenance evidence that this fixture was clean
   * at the time it was added (e.g. a scan receipt, ledger entry, or prior
   * validation report digest).
   */
  cleanProvenance?: string;
}

/** The validation corpus split. At least one positive and one negative control are required. */
export interface ValidationCorpus {
  /** Must-catch fixtures — exhibit the missed bug. At least one is required. */
  positives: ValidationFixture[];
  /**
   * Must-stay-clean fixtures — the FP-regression guard. At least one is
   * required; an empty array is rejected as fail-closed (without controls
   * the loop cannot measure FP regression).
   */
  negativeControls: ValidationFixture[];
  /**
   * Held-out positives the candidate must also catch but was not developed
   * or synthesized against. These are evaluated separately from the
   * development positives and reported as an additional gate: the candidate
   * must demonstrate lift on held-out cases to be a champion.
   */
  heldOut?: ValidationFixture[];
  /**
   * Baseline lens snapshot digest — sha256 of the canonical baseline lens
   * array at tournament start. The validation re-computes this from the
   * current probe baseline and rejects on drift (fail-closed).
   */
  baselineDigest?: string;
}

/** Validated corpus with every required evaluation lane present. */
export interface PreparedValidationCorpus extends ValidationCorpus {
  heldOut: ValidationFixture[];
}

/**
 * A finding that the probe detected at a fixture, with the identifying
 * characteristics the gate uses to verify it matches the intended
 * vulnerability.
 */
export interface LensProbeFinding {
  /** The CWE or attack category the probe matched, if available. */
  cwe?: string;
  /** File path where the finding was raised. */
  file?: string;
  /** 1-based line where the finding was raised. */
  line?: number;
  /** The lens id that triggered this finding. */
  lensId?: string;
  lensVersionDigest?: string;
  /** sha256 content digest of the finding evidence for the validation receipt. */
  findingDigest?: string;
  /** Original finder evidence retained by the production probe, not a confirmation. */
  evidence?: Finding;
}

/** Outcome of probing one fixture with (or without) the candidate lens. */
export interface LensProbeOutcome {
  /** Informational discovery flag. The host grades findings, not this assertion. */
  surfaced: boolean;
  /**
   * Set when the probe could not run to completion. A fixture that errored is
   * graded `inconclusive` (never `verified`) — so an error can never satisfy
   * "catch the miss" and can never be a false positive: the gate stays
   * fail-closed.
   */
  error?: string;
  /**
   * All discoveries, including unrelated findings on clean controls.
   * Never filter these using the expected answer. The host independently
   * matches positive identity and counts every negative-control discovery.
   */
  findings?: LensProbeFinding[];
  /** Actual measured cost in USD for probing this fixture. */
  costUsd?: number;
  /** Actual measured wall-clock duration in ms for probing this fixture. */
  durationMs?: number;
  /** Input tokens consumed during probing. */
  inputTokens?: number;
  /** Output tokens consumed during probing. */
  outputTokens?: number;
}

export interface LensBaselineSnapshot {
  lenses: readonly FinderLens[];
  digest: string;
}

/**
 * Probes whether the finder surfaces a finding at `fixture`. `candidateLens`
 * is the lens under test, or `null` for the BASELINE (current registry only).
 * Injectable: the default {@link makeFinderLensProbe} runs the real finder;
 * tests inject a deterministic fake.
 *
 * A LensProbe is ALSO a callable — the same async function signature — so
 * callers invoke it as `probe(candidateLens, fixture)`. Concrete probes
 * additionally expose `baselineSnapshot` for the validator to detect drift
 * of the baseline lens set across multi-trial validation.
 */
export interface LensProbe {
  (candidateLens: FinderLens | null, fixture: ValidationFixture): Promise<LensProbeOutcome>;
  /**
   * Returns a frozen, structured-cloned snapshot of the baseline lens set
   * (the lenses active WITHOUT the candidate) at the time the probe was
   * created, along with its content digest. The validator uses this to
   * detect baseline drift across validation trials — if the digest changes
   * mid-validation the run fails closed.
   *
   * Required for every probe, including deterministic test probes.
   */
  baselineSnapshot: () => LensBaselineSnapshot;
}

/** Per-trial summary of a multi-trial validation. */
export interface LensTrialSummary {
  /** 0-based trial index. */
  trialIndex: number;
  /** Did the challenger catch ALL positives in this trial? */
  caughtMiss: boolean;
  /** Did the challenger avoid FP regression in this trial? */
  noFpRegression: boolean;
  /** Challenger success rate (verified positives / total positives). */
  challengerSuccessRate: number;
  /** Baseline success rate for this trial. */
  baselineSuccessRate: number;
  /** Challenger false-positive rate for this trial. */
  challengerFpRate: number;
  /** Baseline false-positive rate for this trial. */
  baselineFpRate: number;
  /** Actual challenger cost in USD, or null if unknown. */
  challengerCostUsd: number | null;
  /** Actual baseline cost in USD, or null if unknown. */
  baselineCostUsd: number | null;
}

/**
 * Content-addressed validation receipt. Provides a tamper-evident record
 * of the full validation state at the time of evaluation.
 */
export interface LensValidationReceipt {
  schemaVersion: 1;
  candidateDigest: string;
  baselineLenses: readonly FinderLens[];
  corpus: ValidationCorpus;
  passed: boolean;
  rejectionReasons: string[];
  heldOutTrials: LensTrialSummary[];
  cases: Array<{
    trialIndex: number;
    lane: "development" | "held-out";
    variant: "baseline" | "challenger";
    fixtureId: string;
    negativeControl: boolean;
    outcome: LensProbeOutcome;
  }>;
  /** sha256 of the full canonical validation state. */
  receiptDigest: string;
  /** sha256 of the baseline lens snapshot at validation time. */
  baselineSnapshotDigest: string;
  /** sha256 of the fixture corpus bytes at validation time. */
  fixtureCorpusDigest: string;
  /** Per-trial results. */
  trials: LensTrialSummary[];
}

/** The scan-level numbers the gate reads off a variant's scorecard. */
export interface LensScorecardSummary {
  variantId: string;
  successRate: number;
  fpRate: number;
  verified: number;
  falsePositives: number;
}

/** The full, auditable validation record for one candidate lens. */
export interface LensValidationReport {
  lensId: string;
  /** Did the challenger win the tournament (see `pickChampion`)? */
  isChampion: boolean;
  /** Every positive fixture surfaced under the challenger. */
  caughtMiss: boolean;
  /** Challenger did not add any false positive over baseline. */
  noFpRegression: boolean;
  /** The overall fail-closed verdict: `caughtMiss && noFpRegression && isChampion && strictlyBetter`. */
  passed: boolean;
  /** Human-readable reason, always populated (esp. on failure). */
  reason: string;
  baseline: LensScorecardSummary;
  challenger: LensScorecardSummary;
  /** Content-addressed evaluation receipt. */
  receipt?: LensValidationReceipt;
  /** Held-out corpus result. Always present — held-out fixtures are required. */
  heldOut: { caught: boolean; details: string };
}

// ── Stage 4: registration ─────────────────────────────────────────────────

/** What actually got written to the registry. */
export interface RegisteredLens {
  id: string;
  uid: string;
  validatedAt: string;
  missRefs: string[];
  /** sha256 digest of the registered lens archetype. Propagated to consumers. */
  lensVersionDigest: string;
}

// ── Loop orchestration ────────────────────────────────────────────────────

export interface LensSynthesisInput {
  misses: MissInput;
  corpus: ValidationCorpus;
}

export interface LensSynthesisDeps {
  /** Injectable LLM step for stage 2. Defaults to the LlmApiRuntime-backed impl. */
  model?: import("./synthesize.js").LensSynthesisModel;
  /** REQUIRED validation probe. Use {@link makeFinderLensProbe} for a real run. */
  probe: LensProbe;
  /**
   * Durable overlay file to append to. Defaults to the operator-owned
   * `~/.0sec/lenses/appsec-archetypes.json`, never the bundled seed registry.
   */
  registryPath?: string;
  /** Hard cap on how many lenses ONE run may register. Default 1. */
  maxRegistrations?: number;
  /** Validate + report but never write the registry (a champion is reported, not registered). */
  dryRun?: boolean;
  /** Model override id for the default synthesis model. */
  modelId?: string;
  /** Clock for the `validated_at` provenance stamp. Defaults to `Date.now`-based ISO. */
  now?: () => string;
  /** Number of repeated validation trials. Default 2. Bounded at 10. Minimum 2 ensures independent replication. */
  trials?: number;
  /** AbortSignal to cancel a long-running loop. Checked before each expensive stage and immediately before registration. */
  signal?: AbortSignal;
  log?: (msg: string) => void;
}

export interface LensSynthesisResult {
  candidatesCaptured: number;
  clusters: number;
  synthesized: SynthesizedArchetype[];
  validations: LensValidationReport[];
  registered: RegisteredLens[];
  /** Candidates that did not register, each with the fail-closed reason. */
  rejected: Array<{ id: string; reason: string }>;
  warnings: string[];
}