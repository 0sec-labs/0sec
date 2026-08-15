// Shared type contract for the file-review harness — the deepsec-pattern
// review pipeline (0sec docs/operations/deepsec-vs-pwnkit-study-2026-08-13):
// one record per source file, directory-grouped batches, lock-based claiming,
// append-only analysis history, coverage gate, static revalidation with
// alias reconciliation, refusal audit, reinvestigate waves, cost/duration
// caps with resumable exit codes.
//
// This file is the contract every file-review module builds on. Types only —
// no behavior. Severities stay pwnkit-lowercase (shared Severity), NOT
// deepsec's uppercase enum; deepsec's vuln-slug taxonomy is kept because the
// prompt layer's per-slug notes reference it.

import type { Severity } from "@pwnkit/shared";

// ── Surface inventory ──────────────────────────────────────────────────────

/** Kinds of ingress surfaces the inventory can name (deepsec coverage.ts:5-14). */
export type ReviewSurfaceKind =
  | "http"
  | "rpc"
  | "queue"
  | "cron"
  | "cli"
  | "webhook"
  | "agent-tool"
  | "other";

/** How exposed a surface is (deepsec coverage.ts:16-22). */
export type ReviewSurfaceExposure =
  | "public"
  | "authenticated"
  | "internal"
  | "mixed"
  | "unknown";

export interface ReviewSurfaceInventoryItem {
  /** Stable kebab-case id, unique within an inventory. */
  id: string;
  kind: ReviewSurfaceKind;
  description: string;
  /** Glob patterns (relative to the review root) selecting surface files. */
  fileGlobs: string[];
  /** Files the inventory names as representative of the surface. */
  representativeFiles: string[];
  exposure: ReviewSurfaceExposure;
  /** Optional regexes that anchor the surface (route registration etc.). */
  anchorPatterns?: Array<{ source: string; flags?: string }>;
  /** Auth primitives the surface is expected to use (auth checks, guards). */
  expectedAuthPrimitives?: string[];
}

/** Inventory plus the file universe it was grounded against. */
export interface ReviewSurfaceInventory {
  items: ReviewSurfaceInventoryItem[];
  /** Normalized non-ignored source files the globs expanded against. */
  sourceFiles: string[];
  /** Validation issues found while checking the inventory. */
  issues: Array<{ itemId?: string; field: string; message: string }>;
  /** Files matched by each item's globs, keyed by surface id. */
  expanded: Record<string, string[]>;
}

// ── Candidate matches (scan stage output) ─────────────────────────────────

export interface ReviewCandidateMatch {
  /** Matcher slug that fired (or `surface-<id>` for surface-only hits). */
  vulnSlug: string;
  /** 1-indexed source lines. */
  lineNumbers: number[];
  /** Short excerpt around the first match. */
  snippet: string;
  /** Human-readable label of the pattern that matched. */
  matchedPattern: string;
}

// ── Findings ───────────────────────────────────────────────────────────────

/** The structured finding one investigation emits (pwnkit severities). */
export interface ReviewFinding {
  severity: Severity;
  /** Matcher slug, or `other-<topic>` when no matcher fits. */
  vulnSlug: string;
  title: string;
  description: string;
  lineNumbers: number[];
  recommendation: string;
  confidence: "high" | "medium" | "low";
  /** Stable identity once stored (assigned by the store, not the agent). */
  findingId?: string;
  /** Verdict from a revalidation pass, when one has run. */
  revalidation?: ReviewRevalidation;
}

export type ReviewRevalidationVerdict =
  | "true-positive"
  | "false-positive"
  | "fixed"
  | "uncertain"
  | "duplicate";

export interface ReviewRevalidation {
  verdict: ReviewRevalidationVerdict;
  /** Detailed reasoning; includes git-history evidence for `fixed`. */
  reasoning: string;
  /** Set when revalidation re-rates the finding. */
  adjustedSeverity?: Severity;
  /** findingId of the primary when verdict is `duplicate`. */
  duplicateOf?: string;
  revalidatedAt: string;
  runId: string;
  model?: string;
}

// ── Refusal audit (deepsec REFUSAL_FOLLOWUP_PROMPT pattern) ────────────────

export interface ReviewRefusalReport {
  refused: boolean;
  reason?: string;
  skipped?: Array<{ filePath?: string; reason: string }>;
  /** Trimmed raw model answer, for forensics. */
  raw?: string;
}

// ── Per-file record (the append-only accumulator) ──────────────────────────

export type ReviewFileStatus = "pending" | "processing" | "analyzed" | "error";

/** One per source file; every stage ADDS to this record, nothing overwrites. */
export interface ReviewFileRecord {
  /** Path relative to the review root (POSIX separators). */
  filePath: string;
  projectId: string;
  candidates: ReviewCandidateMatch[];
  lastScannedAt?: string;
  /** Content hash at the last COMPLETED analysis — resume skip key. */
  analyzedHash?: string;
  lastScannedRunId?: string;
  /** sha-256 of the source at last scan — unchanged files skip re-work. */
  fileHash?: string;
  findings: ReviewFinding[];
  /** Append-only log of every investigation; never truncated. */
  analysisHistory: ReviewAnalysisEntry[];
  status: ReviewFileStatus;
  /** When set, a run holds this file; cleared on completion. */
  lockedByRunId?: string;
  lockedAt?: string;
  /** Last error message when status is `error`. */
  errorMessage?: string;
}

/** One entry per AI investigation of a file (deepsec AnalysisEntry shape). */
export interface ReviewAnalysisEntry {
  runId: string;
  investigatedAt: string;
  durationMs: number;
  agentType: string;
  model?: string;
  findingCount: number;
  numTurns?: number;
  costUsd?: number;
  usage?: {
    inputTokens: number;
    outputTokens: number;
    cachedInputTokens?: number;
  };
  refusal?: ReviewRefusalReport;
  /** Wave marker from `--reinvestigate <N>`; same N skips done files. */
  reinvestigateMarker?: number;
  /** Session/thread id for reproducing or replaying the investigation. */
  agentSessionId?: string;
}

// ── Run metadata ───────────────────────────────────────────────────────────

export type ReviewRunType = "scan" | "process" | "revalidate";
export type ReviewRunPhase = "running" | "done" | "error" | "limit";

export interface ReviewRunMeta {
  /** `<YYYYMMDDHHMMSS>-<rand4>`, sortable. */
  runId: string;
  projectId: string;
  rootPath: string;
  createdAt: string;
  completedAt?: string;
  type: ReviewRunType;
  phase: ReviewRunPhase;
  hostname?: string;
  pid?: number;
  stats: {
    filesScanned?: number;
    candidatesFound?: number;
    findingsCount?: number;
    totalCostUsd?: number;
    truePositives?: number;
    falsePositives?: number;
  };
  /** Set when a cost/duration limit stopped the run (phase `limit`). */
  limitReached?: { kind: "cost" | "duration"; limitUsd?: number; actualUsd?: number };
}

// ── Coverage gate ──────────────────────────────────────────────────────────

/** Numeric policy the coverage gate enforces (deepsec DEFAULT_COVERAGE_POLICY). */
export interface ReviewCoveragePolicy {
  version: 1;
  /** Surfaces with fewer files than this need every representative covered. */
  smallSurfaceFileThreshold: number;
  /** Large surfaces: minimum covered fraction of representative files. */
  largeSurfaceRepresentativeRatio: number;
  /** Large surfaces: minimum covered fraction of all surface files. */
  largeSurfaceUniverseRatio: number;
  /** Kinds whose zero coverage fails the gate. */
  zeroCoverageKinds: readonly ReviewSurfaceKind[];
  /** Exposures whose zero coverage fails the gate. */
  zeroCoverageExposures: readonly ReviewSurfaceExposure[];
  /** Dominant-language blind-spot thresholds. */
  dominantLanguageMinimumShare: number;
  dominantLanguageMinimumFiles: number;
  lowLanguageMatchRate: number;
  /** A single matcher may not hit more than this many files / source share. */
  matcherMaximumFiles: number;
  matcherMaximumSourceRatio: number;
  uncoveredExamplesLimit: number;
}

export interface ReviewSurfaceCoverage {
  id: string;
  kind: ReviewSurfaceKind;
  exposure: ReviewSurfaceExposure;
  fileCount: number;
  coveredFileCount: number;
  fileCoverageRatio: number;
  representativeFileCount: number;
  coveredRepresentativeFileCount: number;
  representativeCoverageRatio: number;
  uncoveredExamples: string[];
  passed: boolean;
  reasons: string[];
}

export interface ReviewCoverageReport {
  policyVersion: 1;
  passed: boolean;
  sourceFileCount: number;
  candidateFileCount: number;
  surfaces: ReviewSurfaceCoverage[];
  languageWarnings: Array<{
    language: string;
    scannedFiles: number;
    sourceShare: number;
    matchRate: number;
    reason: string;
  }>;
  explosionWarnings: Array<{
    matcherSlug: string;
    matchedFiles: number;
    sourceRatio: number;
    reason: string;
  }>;
  reasons: string[];
}

// ── Declarative matchers (scan stage) ──────────────────────────────────────

/**
 * Data-only matcher spec. Compiled, never evaluated — the generated/hand
 * matcher boundary from deepsec: specs are strict JSON data with safety
 * validation, no code execution.
 */
export interface ReviewMatcherSpec {
  version: 1;
  slug: string;
  description: string;
  noiseTier: "precise" | "normal" | "noisy";
  filePatterns: string[];
  patterns: Array<{ source: string; flags?: string; label: string }>;
  excludeFilePatterns?: string[];
  /** Inline examples that MUST match at least one pattern (self-test). */
  examples?: string[];
}

// ── LLM invocation seam ────────────────────────────────────────────────────

/** One model call's result, as reported by whichever runtime ran it. */
export interface ReviewInvocation {
  /** Raw model output text (contains the fenced JSON block). */
  output: string;
  usage?: { inputTokens: number; outputTokens: number; cachedInputTokens?: number };
  durationMs: number;
  model?: string;
  numTurns?: number;
  sessionId?: string;
  costUsd?: number;
}

/**
 * The seam every file-review stage calls through. Injected by the pipeline
 * caller (CLI wires a Runtime-backed implementation; tests inject fakes).
 * `label` names the stage for logging/cost attribution ("investigate",
 * "field-repair", "refusal", "revalidate").
 */
export type ReviewInvoker = (prompt: string, label: string) => Promise<ReviewInvocation>;

// ── Pipeline result ────────────────────────────────────────────────────────

export interface ReviewPipelineResult {
  exitCode: ReviewExitCode;
  runId: string;
  projectId: string;
  stats: {
    filesScanned: number;
    candidatesFound: number;
    findingsCount: number;
    netNewFindings: number;
    truePositives: number;
    falsePositives: number;
    totalCostUsd: number;
    coveragePassed?: boolean;
  };
}

// ── Pipeline exit codes (deepsec protocol.ts contract) ─────────────────────

/**
 * 0 = clean (no net-new findings), 1 = findings produced, 2 = needs input,
 * 3 = cost/duration limit reached at a resumable checkpoint — re-running the
 * same command resumes.
 */
export type ReviewExitCode = 0 | 1 | 2 | 3;

export class ReviewLimitError extends Error {
  readonly kind: "cost" | "duration";
  constructor(kind: "cost" | "duration", message: string) {
    super(message);
    this.name = "ReviewLimitError";
    this.kind = kind;
  }
}
