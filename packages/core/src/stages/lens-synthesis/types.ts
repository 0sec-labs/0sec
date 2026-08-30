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

import type { FinderLens } from "../hunt-scan.js";

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
  incompleteCoverage?: import("../hunt-scan.js").CoverageGap[];
  /** Bugs confirmed real that the finder didn't surface. */
  confirmedMisses?: ConfirmedMiss[];
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
}

/** The validation corpus split. */
export interface ValidationCorpus {
  /** Must-catch fixtures — exhibit the missed bug. At least one is required. */
  positives: ValidationFixture[];
  /** Must-stay-clean fixtures — the FP-regression guard. */
  negativeControls: ValidationFixture[];
}

/** Outcome of probing one fixture with (or without) the candidate lens. */
export interface LensProbeOutcome {
  /** True when the finder surfaced a finding at this fixture. */
  surfaced: boolean;
  /**
   * Set when the probe could not run to completion. A fixture that errored is
   * graded `inconclusive` (never `verified`) — so an error can never satisfy
   * "catch the miss" and can never be a false positive: the gate stays
   * fail-closed.
   */
  error?: string;
}

/**
 * Probes whether the finder surfaces a finding at `fixture`. `candidateLens`
 * is the lens under test, or `null` for the BASELINE (current registry only).
 * Injectable: the default {@link makeFinderLensProbe} runs the real finder;
 * tests inject a deterministic fake.
 */
export type LensProbe = (
  candidateLens: FinderLens | null,
  fixture: ValidationFixture,
) => Promise<LensProbeOutcome>;

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
}

/** The scan-level numbers the gate reads off a variant's scorecard. */
export interface LensScorecardSummary {
  variantId: string;
  successRate: number;
  fpRate: number;
  verified: number;
  falsePositives: number;
}

// ── Stage 4: registration ─────────────────────────────────────────────────

/** What actually got written to the registry. */
export interface RegisteredLens {
  id: string;
  uid: string;
  validatedAt: string;
  missRefs: string[];
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
