/**
 * Inline validation (validate-on-save) — issue #554.
 *
 * All verification used to run as a post-attack BATCH pass in agentic-scanner
 * (reachability gate, PoV gate, structured verify). During the attack, the
 * agent got NO real-time truth signal: it could burn 40–100 turns chasing a
 * lead that's actually unreachable or unprovable, and EGATS scored branches on
 * regex POSITIVE/NEGATIVE signals rather than confirmed exploitation.
 *
 * This module is the cheap end of that verification, pulled INTO the loop: when
 * the attack agent saves a high/critical finding, we re-run the same
 * deterministic category oracle (`verifyOracleByCategory` from triage/oracles —
 * the #553 PoV-gate→oracle delegation) against the finding's own evidence and
 * return a `{confirmed, inconclusive, reason}` verdict.
 *
 * Discipline (mirrors the PoV gate's `adjudicateWithOracle`):
 *   - oracle verifies                  → confirmed:true
 *   - oracle clean-fails (no reproduce)→ confirmed:false, inconclusive:false
 *   - oracle infra-error / throws      → confirmed:false, inconclusive:true
 *
 * An inline error is ALWAYS inconclusive, NEVER a false-positive: the finding
 * still flows through the full batch verification later. We never downgrade or
 * suppress a finding off this signal.
 */

import type { Finding } from "@pwnkit/shared";
import { verifyOracleByCategory, type OracleResult } from "../triage/oracles.js";

/** Signature of a category oracle (matches `verifyOracleByCategory`). */
export type InlineOracle = (
  finding: Finding,
  target: string,
) => Promise<OracleResult>;

/** Full outcome of one inline-validation run (telemetry + context note). */
export interface InlineValidationOutcome {
  findingId: string;
  category: string;
  severity: string;
  /** The deterministic oracle reproduced the exploit. */
  confirmed: boolean;
  /** Oracle could not run to a conclusion (infra error / threw). */
  inconclusive: boolean;
  /** Short reason for the verdict. */
  reason: string;
  /** Concrete artifact proving the exploit (when confirmed). */
  evidence: string;
  /** Oracle confidence (0–1). */
  confidence: number;
}

/**
 * Heuristic: does an `OracleResult.reason` describe an *infrastructure* error
 * (browser failed to launch, collector failed to bind, probe failed to send,
 * baseline request failed) rather than a clean "exploit did not reproduce"?
 *
 * Kept identical in spirit to pov-gate.ts `isOracleInfraError` so the inline
 * and batch paths agree on what "inconclusive" means. An infra error must
 * surface as INCONCLUSIVE so we never treat a broken harness as a refutation.
 */
function isOracleInfraError(reason: string): boolean {
  return /\b(failed|error|threw|exception|unavailable|timed? ?out)\b/i.test(
    reason,
  );
}

/** Should a saved finding be validated inline at all? */
export function shouldValidateInline(finding: Finding): boolean {
  return finding.severity === "high" || finding.severity === "critical";
}

/**
 * Run the deterministic category oracle against a freshly-saved finding and
 * map its result into an `InlineValidationOutcome`. Reuses the shared oracle
 * (does not reimplement it). Any throw is caught and reported as inconclusive.
 */
export async function validateFindingInline(
  finding: Finding,
  target: string,
  opts: { oracle?: InlineOracle } = {},
): Promise<InlineValidationOutcome> {
  const runOracle = opts.oracle ?? verifyOracleByCategory;
  const base = {
    findingId: finding.id,
    category: String(finding.category),
    severity: String(finding.severity),
  };

  let result: OracleResult;
  try {
    result = await runOracle(finding, target);
  } catch (err) {
    // Inline errors are INCONCLUSIVE, never a false-positive.
    return {
      ...base,
      confirmed: false,
      inconclusive: true,
      reason: `inline oracle errored: ${(err as Error).message}`,
      evidence: "",
      confidence: 0,
    };
  }

  if (result.verified) {
    return {
      ...base,
      confirmed: true,
      inconclusive: false,
      reason: result.evidence || result.reason || "oracle reproduced the exploit",
      evidence: result.evidence,
      confidence: result.confidence || 1,
    };
  }

  // Not verified. Distinguish an infra error (inconclusive) from a clean
  // "did not reproduce" negative.
  if (isOracleInfraError(result.reason)) {
    return {
      ...base,
      confirmed: false,
      inconclusive: true,
      reason: result.reason,
      evidence: result.evidence,
      confidence: 0,
    };
  }

  return {
    ...base,
    confirmed: false,
    inconclusive: false,
    reason: result.reason || "exploit did not reproduce",
    evidence: result.evidence,
    confidence: 0,
  };
}

/**
 * Build the note injected back into the loop's conversation after a
 * save_finding turn. The wording steers the agent the right way per verdict:
 *   - confirmed   → stop re-testing this lead, move on
 *   - unconfirmed → "do not assume success"
 *   - inconclusive→ not a refutation; batch verify will re-check
 */
export function buildInlineValidationNote(o: InlineValidationOutcome): string {
  const head = `[inline validation] Finding ${o.findingId} (${o.severity}/${o.category})`;
  if (o.confirmed) {
    return (
      `${head} was CONFIRMED by a deterministic oracle: ${o.reason}. ` +
      `This exploit is PROVEN — do not keep re-testing it. Move on to new ` +
      `attack surface or call done.`
    );
  }
  if (o.inconclusive) {
    return (
      `${head} is INCONCLUSIVE — the inline check could not run to a ` +
      `conclusion (${o.reason}). This is NOT a refutation; the full ` +
      `verification batch will re-check it later. Keep your evidence.`
    );
  }
  return (
    `${head} is UNCONFIRMED — the deterministic oracle did NOT reproduce ` +
    `the exploit (${o.reason}). Do NOT assume success: gather stronger proof ` +
    `(real exploit output, not a 200 OK) or move on to another vector.`
  );
}
