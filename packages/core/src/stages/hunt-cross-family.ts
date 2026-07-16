/**
 * Cross-family adversarial refuter — decorrelate finder and refuter errors
 * (issue #661).
 *
 * `makeSkepticVerifier` (hunt-scan.ts) re-reads a claimed finding and tries hard
 * to REFUTE it (assume-FP). By default that refute pass runs through the same
 * provider-agnostic loop — typically the same model FAMILY that produced the
 * finding. A model is worst at catching its own systematic errors: same blind
 * spots, same hallucinated sinks, so correlated errors survive.
 *
 * When enabled AND a distinct second family is available, this forces the refute
 * pass onto a model of a DIFFERENT family than the finder before a finding can
 * be promoted. The errors decorrelate — a hallucinated or non-reproducible
 * finding gets caught by the second family, and the ones that survive two
 * families are genuinely disclosure-grade.
 *
 * OFF by default — mirrors `huntNegativesEnabled()` / `huntFlywheelEnabled()`'s
 * opt-in discipline. This module is a PURE selector (no LLM calls, no I/O) so
 * the promotion gate stays unit-testable, and it returns the configured refuter
 * UNCHANGED whenever enforcement can't apply (disabled, no finder family known,
 * or no distinct-family candidate available) — the default path is
 * byte-identical to before this existed. Falling back to the same-family refuter
 * rather than dropping the finding is the assume-FP-safe choice: a finding is
 * never promoted on LESS scrutiny than today.
 */

import { modelProvider } from "@pwnkit/shared";

/** Default OFF — mirrors `huntNegativesEnabled()` / `huntFlywheelEnabled()`'s opt-in discipline. */
export function crossFamilyRefuteEnabled(): boolean {
  return !["", "0", "false", "no"].includes((process.env.PWNKIT_HUNT_CROSS_FAMILY ?? "").toLowerCase());
}

export interface CrossFamilyRefuteConfig {
  /**
   * Off → the configured refuter is returned unchanged (byte-identical to
   * today). Defaults to {@link crossFamilyRefuteEnabled} at the call site.
   */
  enabled: boolean;
  /** The finder model/family whose provider the refuter must decorrelate from. */
  finderModel?: string;
  /** The refuter model already configured (env `HUNT_SKEPTIC_MODEL` / `opts.model`). */
  refuterModel?: string;
  /** Alternate refuter models to pick a distinct family from, tried in order. */
  candidates?: readonly string[];
}

export interface CrossFamilyRefuteChoice {
  /** The model the refute pass should use (undefined = the provider default). */
  model?: string;
  /** True ONLY when a distinct-family refuter is actually being enforced. */
  crossFamily: boolean;
  /** The finder family avoided — set only when {@link crossFamily} is true. */
  finderFamily?: string;
  /** The refuter family used — set only when {@link crossFamily} is true. */
  refuterFamily?: string;
}

/**
 * Choose the refute pass's model so it decorrelates from the finder's family.
 *
 * Passthrough (crossFamily:false, model unchanged) whenever enforcement can't
 * apply: disabled, the finder family is unknown, or no distinct-family
 * candidate is available. Otherwise, if the already-configured refuter is
 * itself a different family, keep it (and just record the pairing); else pick
 * the first candidate from a DIFFERENT known family.
 */
export function selectCrossFamilyRefuter(cfg: CrossFamilyRefuteConfig): CrossFamilyRefuteChoice {
  const passthrough: CrossFamilyRefuteChoice = { model: cfg.refuterModel, crossFamily: false };
  if (!cfg.enabled) return passthrough;

  const finderFamily = cfg.finderModel ? modelProvider(cfg.finderModel) : "unknown";
  // Without a known finder family there is nothing to decorrelate FROM.
  if (finderFamily === "unknown") return passthrough;

  // Already cross-family? Keep the configured refuter — just record the pairing.
  const refuterFamily = cfg.refuterModel ? modelProvider(cfg.refuterModel) : "unknown";
  if (refuterFamily !== "unknown" && refuterFamily !== finderFamily) {
    return { model: cfg.refuterModel, crossFamily: true, finderFamily, refuterFamily };
  }

  // Otherwise pick the first candidate from a DIFFERENT known family.
  for (const candidate of cfg.candidates ?? []) {
    const family = modelProvider(candidate);
    if (family !== "unknown" && family !== finderFamily) {
      return { model: candidate, crossFamily: true, finderFamily, refuterFamily: family };
    }
  }

  // No distinct family available → byte-identical to today (assume-FP safe).
  return passthrough;
}
