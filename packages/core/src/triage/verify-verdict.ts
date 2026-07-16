/**
 * The verify funnel — one verdict contract + one disclosure predicate.
 *
 * Verification in pwnkit happens on two separate scan loops that stay separate
 * by design (different domains):
 *   - the agentic/web path (`agentic-scanner.ts` → structured verify +
 *     self-consistency, then `runNativeVerify`), and
 *   - the static/code path (`unified-pipeline.ts` → `blindVerifyPrompt`).
 *
 * They used to converge nowhere: each emitted its own ad-hoc result shape and
 * each decided keep-vs-drop with hand-placed guard logic (or none at all). This
 * module is the single point of convergence at the RESULT level:
 *
 *   1. {@link VerifyVerdict} — the one verdict contract both paths emit.
 *   2. {@link isDisclosureWorthy} — the one predicate that owns keep/drop,
 *      delegating the severity/class guard to {@link canAutoSuppressDetailed}.
 *
 * The two scan loops still run independently; only their *verdicts* are unified.
 *
 * SINGLE SOURCE / PARITY (#650): the 0cloud orchestrator keeps the same
 * predicate in `@0cloud/cloud-contracts` `disclosure-worthiness.ts` (the engine
 * and orchestrator are decoupled — neither can import the other's package). This
 * module is the engine's authoritative copy; the guard data is parity-checked in
 * `can-auto-suppress.parity.test.ts`. Keep the two `isDisclosureWorthy`
 * implementations behaviour-compatible.
 */

import type { Finding } from "@pwnkit/shared";
import {
  canAutoSuppressDetailed,
  type AutoSuppressGuard,
} from "./can-auto-suppress.js";

/**
 * Terminal outcome of a verification pass.
 *
 * `inconclusive` is distinct from `rejected` on purpose: a verifier that errored
 * out, timed out, or had no runtime available did NOT decide the finding is a
 * false positive — it failed to decide. Treating that as a rejection is the
 * #518 failure mode (silently burying a real finding). {@link isDisclosureWorthy}
 * only ever allows a `rejected` verdict to drop a finding.
 */
export type VerifyOutcome = "confirmed" | "rejected" | "inconclusive";

/**
 * Evidence basis behind a verdict (EPIC #674 / #666). Distinct from
 * {@link VerifyOutcome}: a finding can be `confirmed` on source analysis alone
 * (`source-only`) or because a PoC actually reproduced in an isolated env
 * (`reproduced-poc`). The disclosure-eligibility gate (#674 Part C) promotes a
 * finding to `in_scope` only when the verdict is `confirmed` AND
 * `evidenceKind === "reproduced-poc"` — "there's something in the source" is
 * never enough. `source-only` confirmations stay held (needs_verify), never
 * silently dropped (#518).
 *
 * SINGLE SOURCE / PARITY (#650): the 0cloud side keeps the same union in
 * `@0cloud/cloud-contracts` (`VerifyEvidenceKind`, PR #681). The engine and
 * orchestrator are decoupled — neither imports the other — so the strings are
 * parity-checked in `verify-evidence-kind.parity.test.ts` against the locked
 * cloud table. Keep the two in lockstep.
 *
 * Exported as a runtime tuple so the parity test (and any exhaustive consumer)
 * has a value to assert, mirroring the `AUTO_SUPPRESS_*` arrays in
 * `can-auto-suppress.ts`.
 *
 * NOTE: this tuple is the 0cloud-PARITY-LOCKED set — it is asserted verbatim in
 * `verify-evidence-kind.parity.test.ts` against the cloud-contracts table. Do
 * NOT add a kind here until the SAME string has been added to the cloud-contracts
 * `VERIFY_EVIDENCE_KINDS` table in the same coordinated change (#701), or the
 * parity check asserts against a table the cloud side does not actually carry.
 * Engine-only kinds the cloud side does not yet derive stage in
 * {@link VERIFY_EVIDENCE_KINDS_ENGINE_EXT} until they graduate here, and are
 * folded into the {@link VerifyEvidenceKind} union below.
 *
 * `reproduced-memcorruption-poc` graduated from the engine-ext set into this
 * parity-locked tuple in the coordinated change of #701 (adopted by cloud-
 * contracts in lockstep): a PoC actually fired under the sanitizer / Miri build —
 * a real {@link CrashArtifact} reproduced (ASan/UBSan/MSan/Miri), not just a
 * static or source signal. It is the memory-safety analogue of `reproduced-poc`,
 * kept as a distinct string so the disclosure/telemetry layers can tell a
 * sanitizer-reproduced crash apart from a web/static PoC.
 */
export const VERIFY_EVIDENCE_KINDS = [
  "reproduced-poc",
  "source-only",
  "reproduced-memcorruption-poc",
] as const;

/**
 * Engine-only evidence kinds, additive over the parity-locked cloud set — those
 * the engine derives but the cloud contract does not yet carry. A kind stages
 * here only while its coordinated cloud-contracts adoption is in flight; once
 * cloud-contracts carries it, it graduates into {@link VERIFY_EVIDENCE_KINDS}
 * above and is removed from here (that is what #701 did for
 * `reproduced-memcorruption-poc`, the sole prior occupant).
 *
 * Currently EMPTY. Kept as an exported extension point (mirroring the
 * `AUTO_SUPPRESS_*` arrays) so the next engine-only kind has a parity-safe
 * staging home and consumers of the barrel export do not break. While empty its
 * `[number]` is `never`, so the {@link VerifyEvidenceKind} union below is exactly
 * {@link VERIFY_EVIDENCE_KINDS}.
 */
export const VERIFY_EVIDENCE_KINDS_ENGINE_EXT = [] as const;

export type VerifyEvidenceKind =
  | (typeof VERIFY_EVIDENCE_KINDS)[number]
  | (typeof VERIFY_EVIDENCE_KINDS_ENGINE_EXT)[number];

/**
 * Layer verdicts whose `pass` outcome means a PoC actually reproduced (a
 * working PoV, a deterministic oracle hit, or the #666 static-finding PoC-gen
 * synthesising runnable `pocSteps`). Used by {@link evidenceKindForFinding}.
 */
const REPRODUCING_LAYERS = new Set(["poc_gen", "pov_gate", "oracle"]);

/**
 * Classify a finding's evidence basis from what the engine already emits —
 * the same predicate the 0cloud worker derives, kept identical so native
 * emission and cloud derivation never diverge:
 *
 *   `reproduced-poc` ⇔ the finding carries a non-empty `pocSteps` graph AND a
 *                       reproducing layer (poc_gen / pov_gate / oracle) recorded
 *                       a `pass`.
 *   `source-only`    ⇔ everything else (no runnable PoC, `poc:none`, or only
 *                       static signals).
 */
export function evidenceKindForFinding(finding: Finding): VerifyEvidenceKind {
  const hasPocSteps = Array.isArray(finding.pocSteps) && finding.pocSteps.length > 0;
  const reproduced =
    hasPocSteps &&
    (finding.layerVerdicts ?? []).some(
      (v) => v.verdict === "pass" && REPRODUCING_LAYERS.has(v.layer),
    );
  return reproduced ? "reproduced-poc" : "source-only";
}

/**
 * One piece of evidence behind a verdict — a structured-verify step, a
 * self-consistency vote tally, an oracle result, a blind-verify reproduction
 * attempt, etc. Kept deliberately loose so every verify path can map its own
 * native shape onto it without losing the human-readable trail.
 */
export interface VerifySignal {
  /** Stable identifier for the signal source (e.g. "reachability", "vote", "blind_verify"). */
  name: string;
  /** Whether this individual signal supported the finding being real. */
  passed?: boolean;
  /** Signal-local confidence in [0,1], when the source produces one. */
  confidence?: number;
  /** Short human-readable explanation for the audit trail. */
  reasoning?: string;
}

/**
 * The unified verify contract. Every verify path — structured, self-consistency,
 * agentic native, static blind — converges to this shape so downstream consumers
 * (disclosure gating, telemetry, the report) read one thing.
 */
export interface VerifyVerdict {
  verdict: VerifyOutcome;
  /** Aggregate confidence in the verdict, [0,1]. */
  confidence: number;
  /** Human-readable summary of why the verdict was reached. */
  reasoning: string;
  /** The individual signals that produced the verdict. May be empty. */
  signals: VerifySignal[];
  /**
   * Evidence basis behind the verdict (EPIC #674 / #666). Optional and
   * additive — undefined on verdicts emitted before this field existed, and on
   * paths where the producer has no finding in scope (the cloud side derives it
   * from the finding's `pocSteps` + layer verdicts in that case). When set, the
   * disclosure gate reads it directly. See {@link evidenceKindForFinding}.
   */
  evidenceKind?: VerifyEvidenceKind;
  /**
   * N-boot reproducibility flag (AIxCC / Shellphish T2: PoV-mandatory +
   * reproducibility gate). True when the kernel crash signature reproduced in
   * at least M of K fresh boots (each with a clean `snapshot=on` overlay) —
   * i.e. it is stable, not a one-off boot-luck splat. Produced by
   * {@link verifyAcrossBoots} in `kernel-vm-runner.ts`. Optional and additive:
   * undefined on every non-kernel verify path and on legacy single-boot kernel
   * verdicts. When the disclosure gate is run with `requireNbootStable`, a
   * kernel finding must carry `nbootStable === true` to be disclosure-eligible.
   *
   * SINGLE SOURCE / PARITY (#650): mirrored on the 0cloud side in
   * `@0cloud/cloud-contracts` (`DisclosureVerdictLike`). Keep the two in
   * lockstep.
   */
  nbootStable?: boolean;
}

/** Either the full verdict contract or just its outcome label. */
export type VerdictLike = VerifyVerdict | VerifyOutcome;

/**
 * Decision returned by {@link isDisclosureWorthy}: keep the finding (route it to
 * verification / human review) or allow the calling drop-layer to suppress it.
 */
export interface DisclosureDecision {
  /**
   * True when the finding must be KEPT — either because the verdict was not a
   * rejection, or because the severity/class guard protects it from a
   * heuristic/verdict drop. False only when a `rejected` verdict targets a
   * finding the guard deems eligible for auto-suppression.
   */
  keep: boolean;
  /** When `keep` is true *because* the guard fired, which guard. */
  guard?: AutoSuppressGuard;
  /** Stable reason string for the audit trail (`triageNote`, layer verdicts, logs). */
  reason: string;
}

function outcomeOf(verdict: VerdictLike): VerifyOutcome {
  return typeof verdict === "string" ? verdict : verdict.verdict;
}

/**
 * The single keep/drop predicate for the whole verify funnel.
 *
 * Every drop site — the heuristic triage layers (evidence_gate, learned/dynamic
 * router, publishability) and the verification-verdict layers (holding-it-wrong,
 * reachability, multi-modal, self-consistency, static blind verify) — routes its
 * suppression decision through here instead of dropping on its own. That makes
 * the severity/class guard ({@link canAutoSuppressDetailed}, PROTECTED_SEVERITIES
 * + high-impact classes) the one chokepoint it was always meant to be (#518).
 *
 * Rules:
 *   - A non-`rejected` verdict (`confirmed` / `inconclusive`) is ALWAYS kept.
 *     Inconclusive-on-error stays inconclusive — never an auto-drop.
 *   - A `rejected` verdict may drop the finding ONLY when the guard says it is
 *     eligible for auto-suppression. A disclosure-grade finding (high/critical
 *     severity, or a high-impact class) is held for verification/human review.
 */
export function isDisclosureWorthy(
  finding: Finding,
  verdict: VerdictLike,
): DisclosureDecision {
  if (outcomeOf(verdict) !== "rejected") {
    return {
      keep: true,
      reason: `verdict=${outcomeOf(verdict)}: not a rejection — finding kept`,
    };
  }
  const guard = canAutoSuppressDetailed(finding);
  if (guard.canSuppress) {
    return { keep: false, reason: guard.reason };
  }
  return { keep: true, guard: guard.guard, reason: guard.reason };
}
