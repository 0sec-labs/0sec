/**
 * Kernel Promotion Envelope
 *
 * Pure deterministic builder that aggregates all available evidence for a
 * single kernel candidate without performing lookup, execution, mutation, or
 * hidden promotion.
 *
 * The envelope binds candidate identity, source/sink/preconditions, full
 * ranked reachability output from `rankSinkReachability`, optional semantic
 * compile-validation result, supplied novelty, supplied clean control, and
 * supplied existing verification receipt.
 *
 * **Status derivation (fail-closed):**
 *
 *   `confirmed` — EVERY required input is present and independently confirms:
 *     1. semantic validation === `compiled-and-valid`
 *     2. clean control === `clean: true`
 *     3. normalized novelty state === `novel`
 *     4. verification receipt status === `reproduced`
 *
 *   `hypothesis-only` — any of the above is absent or non-confirming. The
 *   `reason` enumerates every deficient field so callers know what to fix.
 *
 * This module contains zero I/O, zero side effects, and zero agent calls.
 */

import type {
  VerificationResult,
  ResearchNoveltyReceipt,
} from "@0sec/shared";
import { normalizeResearchNovelty } from "@0sec/shared";
import type {
  RankSinkReachabilityResult,
  SinkLocation,
} from "../kernel/reachability-rank.js";

// ── Semantic validation ─────────────────────────────────────────────────────
//
// Consumed via `SyzlangValidator`'s existing structural-validation seam.
// We define the concrete status here so callers map their validator output
// into one of these variants.

/**
 * Outcome of a semantic compile-validation attempt on the candidate's
 * reproducer / trigger program.
 *
 * This type replaces raw boolean casts; callers convert their validator's
 * return into one of these explicit variants. An absent value (undefined)
 * means validation was not attempted.
 */
export type SemanticValidationStatus =
  | { kind: "compiled-and-valid" }
  | { kind: "invalid"; reason: string }
  | { kind: "unavailable-toolchain" }
  | { kind: "execution-error"; detail: string };

// ── Candidate identity ──────────────────────────────────────────────────────

/**
 * Identity of the kernel candidate this envelope describes.
 * Mirrors the fields from crash-report parsing but keeps the envelope
 * independent of the ingest-layer `CrashReport` type.
 */
export interface KernelCandidateIdentity {
  /** Canonical crash type label, e.g. "kasan-uaf", "kasan-oob", "null-deref". */
  crashType: string;
  /** Faulting function/symbol extracted from the crash report. */
  faultingFunction: string;
  /** Source file path or target module, when available. */
  sourcePath?: string;
  /** Subsystem hint, e.g. "nfs", "tcp", "ext4". */
  subsystem?: string;
  /** Upstream kernel version, tag, or commit hash. */
  kernelVersion?: string;
}

// ── Source / sink / preconditions ──────────────────────────────────────────

/**
 * Source-to-sink context for the candidate.
 *
 * `source` describes the entry / trigger path; `sink` describes the vulnerable
 * code path; `preconditions` enumerates what must be true for the sink to be
 * exercised.
 */
export interface KernelSourceSinkContext {
  /** Entry-point / trigger description, e.g. "sys_setsockopt". */
  source: string;
  /** Vulnerable code path, e.g. "nfs4_proc_getattr". */
  sink: string;
  /** Resolved sink file + symbol from reachability analysis. */
  sinkLocation?: SinkLocation;
  /** Preconditions that must hold for the sink to fire. */
  preconditions: string[];
}

// ── Clean control receipt ──────────────────────────────────────────────────

/**
 * Receipt from a clean-control experiment — the same input was exercised
 * against a known-non-vulnerable (or patched) target and did NOT reproduce
 * the crash.
 *
 * Supplied by the caller; this module does not generate or verify it.
 */
export interface KernelCleanControlReceipt {
  /** `true` when the control system did NOT reproduce the crash. */
  clean: boolean;
  /** Description of what was run (kernel version, config, harness). */
  controlMethod: string;
  /** Human-readable summary of the control outcome. */
  evidence: string;
  /** Verification receipt hash when the control run produced one. */
  receiptSha256?: string;
}

// ── Derived status ─────────────────────────────────────────────────────────

/**
 * Promotion status derived from the supplied evidence.
 *
 * Fail-closed:
 *   - `confirmed` — ALL four gates pass (validation, clean control, novelty,
 *     verification receipt).
 *   - `hypothesis-only` — one or more gates are absent or non-confirming.
 *     `reason` enumerates every deficient field.
 */
export type KernelPromotionStatus =
  | { kind: "hypothesis-only"; reason: string }
  | { kind: "confirmed"; basis: string };

// ── Inputs ──────────────────────────────────────────────────────────────────

/**
 * All inputs the caller must supply to build an envelope.
 * Every field is caller-provided; the envelope does not query, validate, or
 * mutate anything outside these arguments.
 */
export interface KernelPromotionInputs {
  /** Opaque stable identifier for this candidate. */
  candidateId: string;
  /** Run / provenance identifier. */
  runId: string;
  /** Candidate identity from crash report parsing. */
  identity: KernelCandidateIdentity;
  /** Source / sink / preconditions context. */
  context: KernelSourceSinkContext;
  /**
   * Full ranked reachability output from `rankSinkReachability`
   * (kernel reachability ranker with ranked candidates, warnings, edge
   * confidence, and path traces).
   */
  reachability: RankSinkReachabilityResult;
  /** Optional semantic compile-validation result. */
  validation?: SemanticValidationStatus;
  /** Supplied novelty result (normalized internally via normalizeResearchNovelty). */
  novelty: ResearchNoveltyReceipt;
  /** Supplied clean-control receipt, if a control experiment was run. */
  cleanControl?: KernelCleanControlReceipt;
  /** Supplied existing verification receipt, if a verification run produced one. */
  verificationReceipt?: VerificationResult;
}

// ── Envelope ────────────────────────────────────────────────────────────────

/**
 * Complete promotion-evidence envelope for a single kernel candidate.
 *
 * This is a **pure data value**: the `buildKernelPromotionEnvelope` factory
 * derives `status` from the supplied inputs and returns a frozen-like object.
 * Callers never set `status` or `readonly`-marked fields directly.
 */
export interface KernelPromotionEnvelope {
  schemaVersion: 1;
  /** Opaque stable identifier for this candidate. */
  candidateId: string;
  /** Run / provenance identifier. */
  runId: string;

  /** Candidate identity. */
  identity: KernelCandidateIdentity;
  /** Source / sink / preconditions context. */
  context: KernelSourceSinkContext;
  /** Full ranked reachability output from `rankSinkReachability`. */
  reachability: RankSinkReachabilityResult;

  /** Optional semantic compile-validation result. */
  validation?: SemanticValidationStatus;

  /** Supplied novelty result (normalized via normalizeResearchNovelty). */
  novelty: ResearchNoveltyReceipt;

  /** Supplied clean-control receipt. */
  cleanControl?: KernelCleanControlReceipt;

  /** Supplied existing verification receipt. */
  verificationReceipt?: VerificationResult;

  // ── Derived ────────────────────────────────────────────────────────────

  /**
   * Promotion status derived from the supplied evidence.
   *
   * Fail-closed — requires ALL of:
   *   - validation === `compiled-and-valid`
   *   - cleanControl === `clean: true`
   *   - normalized novelty state === `novel`
   *   - verificationReceipt status === `reproduced`
   *
   * Any absent or non-confirming input yields `hypothesis-only` with a
   * concrete `reason` enumerating every deficiency.
   */
  readonly status: KernelPromotionStatus;
}

// ── Builder ─────────────────────────────────────────────────────────────────

/**
 * Build a kernel promotion envelope from the supplied evidence.
 *
 * Pure function — no I/O, no lookup, no mutation of any external state.
 * The `status` field is derived deterministically from the inputs.
 *
 * @param inputs - All available evidence for this candidate.
 * @returns A fully-populated envelope.
 */
export function buildKernelPromotionEnvelope(
  inputs: KernelPromotionInputs,
): KernelPromotionEnvelope {
  const status = deriveStatus(inputs);

  return {
    schemaVersion: 1,
    candidateId: inputs.candidateId,
    runId: inputs.runId,
    identity: inputs.identity,
    context: inputs.context,
    reachability: inputs.reachability,
    validation: inputs.validation,
    novelty: normalizeResearchNovelty(inputs.novelty),
    cleanControl: inputs.cleanControl,
    verificationReceipt: inputs.verificationReceipt,
    status,
  };
}

// ── Status derivation (fail-closed) ─────────────────────────────────────────

/**
 * Pure status derivation. Every required evidence gate must be present and
 * independently confirming; the first missing/non-confirming gate short-circuits
 * with a concrete reason listing all deficiencies.
 */
function deriveStatus(inputs: KernelPromotionInputs): KernelPromotionStatus {
  const gaps: string[] = [];

  // 1. Semantic validation
  if (!inputs.validation) {
    gaps.push("validation: absent");
  } else if (inputs.validation.kind !== "compiled-and-valid") {
    gaps.push(`validation: ${inputs.validation.kind}`);
  }

  // 2. Clean control
  if (!inputs.cleanControl) {
    gaps.push("cleanControl: absent");
  } else if (inputs.cleanControl.clean !== true) {
    gaps.push(
      `cleanControl: clean=${inputs.cleanControl.clean} — ${inputs.cleanControl.evidence}`,
    );
  }

  // 3. Novelty (normalized — fail-closed: no sources means "unchecked", not novel)
  const normNovelty = normalizeResearchNovelty(inputs.novelty);
  if (normNovelty.state !== "novel") {
    gaps.push(`novelty: ${normNovelty.state}`);
  }

  // 4. Verification receipt
  if (!inputs.verificationReceipt) {
    gaps.push("verificationReceipt: absent");
  } else if (inputs.verificationReceipt.status !== "reproduced") {
    gaps.push(
      `verificationReceipt: status=${inputs.verificationReceipt.status}`,
    );
  }

  if (gaps.length === 0) {
    return {
      kind: "confirmed",
      basis:
        "Validation, clean control, novelty (novel), and an existing reproduced verification receipt independently confirm.",
    };
  }

  return {
    kind: "hypothesis-only",
    reason: gaps.join("; "),
  };
}

// ── Predicates ──────────────────────────────────────────────────────────────

/**
 * Whether the envelope's status is `confirmed`.
 */
export function isConfirmed(
  envelope: KernelPromotionEnvelope,
): boolean {
  return envelope.status.kind === "confirmed";
}

/**
 * Whether the envelope's status is `hypothesis-only`.
 */
export function isHypothesisOnly(
  envelope: KernelPromotionEnvelope,
): boolean {
  return envelope.status.kind === "hypothesis-only";
}

/**
 * Whether the envelope carries a semantic-validation result that
 * indicates a compilable, valid reproducer.
 */
export function hasValidValidation(
  envelope: KernelPromotionEnvelope,
): boolean {
  return envelope.validation?.kind === "compiled-and-valid";
}