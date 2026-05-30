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
