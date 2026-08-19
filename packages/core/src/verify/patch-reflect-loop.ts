/**
 * Patch validate-and-reflect retry loop (0sec #1501 item 3).
 *
 * {@link validatePatchRemovesCrash} in `./patch-validate.ts` is a SINGLE-SHOT
 * patch-as-oracle: generate one candidate fix, apply it, rebuild the KASAN
 * kernel, re-run the reproducer, and report `root_cause_confirmed` only when
 * KASAN goes silent. That is the correct oracle — but one shot. A wrong or
 * incomplete fix (`not_root_cause`), a malformed diff (`patch_apply_failed`),
 * a declined generation (`patch_generation_failed`), or a transient/inconclusive
 * rebuild (`rebuild_failed`) all end the story with a single negative verdict.
 *
 * This module wraps that oracle in a bounded **validate → reflect → retry**
 * loop, the pattern AIxCC's Buttercup uses (design reference only — this is a
 * clean re-implementation, no code copied):
 *
 *   propose fix → rebuild → re-run PoV against the KASAN oracle
 *              → run regression checks → REFLECT (retry-same / try-different /
 *                stop) → loop, under a hard attempt budget so it never spins
 *                forever.
 *
 * It does NOT re-implement the oracle. It composes with it:
 *
 *   - The oracle itself (`validatePatchRemovesCrash`) is injected via
 *     {@link PatchReflectLoopOptions.validator} (defaults to the real one), so
 *     the whole loop unit-tests with a fake validator — no LLM, no QEMU boot.
 *   - The per-round {@link PatchGenerator} handed to the oracle is synthesised
 *     by the loop from the {@link ReflectivePatchGenerator}, threading the
 *     reflection `mode` and prior-attempt failure history into generation so a
 *     `try_different` round can steer the LLM away from the fix that just
 *     failed, and a `retry_same` round re-runs the exact previous diff (right
 *     for a transient `rebuild_failed`).
 *   - An optional {@link RegressionCheck} runs after the oracle confirms, so a
 *     fix that closes the bug but breaks something else is NOT accepted — it is
 *     reflected on like any other failure (the "verify-no-regression" leg).
 *
 * The reflection policy is injectable; {@link defaultReflect} encodes a
 * defensible default (see its doc comment).
 */

import type { Finding } from "@0sec/shared";
import {
  validatePatchRemovesCrash,
  type CandidatePatch,
  type PatchGenerator,
  type PatchValidateOptions,
  type PatchValidateResult,
  type PatchValidateStatus,
} from "./patch-validate.js";

/** Default attempt budget (1 build+run per attempt). Kept small — rebuilds are expensive. */
export const DEFAULT_MAX_ATTEMPTS = 3;

/** What the reflection step decides after a non-confirming validation. */
export type ReflectDecision = "retry_same" | "try_different" | "stop";

/** How the next round's patch should be produced, derived from the last decision. */
export type PatchGenMode = "initial" | "retry_same" | "try_different";

/** Outcome of an optional post-confirmation regression check. */
export interface RegressionOutcome {
  passed: boolean;
  reason: string;
}

/**
 * A patch generator aware of the reflection loop. Extends the base
 * {@link PatchGenerator} context with the current `mode`, 1-based `attempt`,
 * and the failure history so it can produce a genuinely DIFFERENT fix on a
 * `try_different` round instead of re-emitting the diff that just failed.
 * Returns `null` to decline (the oracle reports `patch_generation_failed`).
 */
export type ReflectivePatchGenerator = (ctx: {
  finding: Finding;
  reproducer: string;
  reproducerLang: "syz" | "c";
  crashDmesg: string;
  upstreamFixHint?: string;
  /** 1-based attempt index this generation is for. */
  attempt: number;
  /** Why this round is running. `initial` on the first attempt. */
  mode: PatchGenMode;
  /** Compact record of every prior attempt, oldest first — steer away from these. */
  priorAttempts: ReadonlyArray<PriorAttemptSummary>;
}) => Promise<CandidatePatch | null>;

/** Compact, generator-facing summary of an attempt that already failed. */
export interface PriorAttemptSummary {
  attempt: number;
  status: PatchValidateStatus;
  reason: string;
  patch?: CandidatePatch;
}

/** A post-confirmation regression gate: the fix closed the bug — did it break anything? */
export type RegressionCheck = (ctx: {
  patch: CandidatePatch;
  result: PatchValidateResult;
}) => Promise<RegressionOutcome>;

/** The patch-as-oracle itself. Defaults to {@link validatePatchRemovesCrash}; injected in tests. */
export type PatchValidator = (
  opts: PatchValidateOptions,
) => Promise<PatchValidateResult>;

/** The reflection decision function. Defaults to {@link defaultReflect}. */
export type ReflectFn = (ctx: {
  /** The validation verdict just produced (never a confirmed one). */
  result: PatchValidateResult;
  /** Present only when a regression check RAN and FAILED on an otherwise-confirmed patch. */
  regression?: RegressionOutcome;
  /** 1-based index of the attempt just completed. */
  attempt: number;
  maxAttempts: number;
  /** Every attempt so far, oldest first. */
  history: ReadonlyArray<PatchAttempt>;
}) => ReflectDecision;

/** One recorded pass through the loop. */
export interface PatchAttempt {
  attempt: number;
  mode: PatchGenMode;
  result: PatchValidateResult;
  /** Set when a regression check ran for this attempt (only on an oracle-confirmed patch). */
  regression?: RegressionOutcome;
  /** What reflection decided after this attempt. `stop` on the confirmed/accepted path. */
  decision: ReflectDecision;
}

export type PatchReflectLoopStatus =
  | "root_cause_confirmed"
  | "budget_exhausted"
  | "gave_up";

export interface PatchReflectLoopResult {
  status: PatchReflectLoopStatus;
  /** True ONLY when a patch closed the bug AND passed regression (if a check was supplied). */
  patchValidated: boolean;
  /** The accepted fix, set only on `root_cause_confirmed`. */
  confirmedPatch?: CandidatePatch;
  /** The last validation verdict the oracle returned. */
  finalResult: PatchValidateResult;
  /** Full audit trail, one entry per attempt. */
  attempts: PatchAttempt[];
  reason: string;
}

export interface PatchReflectLoopOptions {
  /**
   * Base options forwarded to the oracle each round. Everything
   * {@link validatePatchRemovesCrash} needs EXCEPT `patchGenerator`, which the
   * loop synthesises per round from {@link patchGenerator} + reflection state.
   */
  validate: Omit<PatchValidateOptions, "patchGenerator">;
  /** Reflection-aware patch generator (the LLM-backed fix proposer). */
  patchGenerator: ReflectivePatchGenerator;
  /** Hard cap on attempts (1 rebuild + re-run each). Default {@link DEFAULT_MAX_ATTEMPTS}. */
  maxAttempts?: number;
  /** Optional "no regression" gate run after the oracle confirms. */
  regressionCheck?: RegressionCheck;
  /** The patch-as-oracle. Defaults to the real {@link validatePatchRemovesCrash}. */
  validator?: PatchValidator;
  /** Reflection policy. Defaults to {@link defaultReflect}. */
  reflect?: ReflectFn;
  /** Custom logger; defaults to a no-op (the oracle has its own logger via `validate`). */
  logger?: (line: string) => void;
}

/** Count how many of the most-recent attempts ended in `decision`. */
function countTrailingDecision(
  history: ReadonlyArray<PatchAttempt>,
  decision: ReflectDecision,
): number {
  let n = 0;
  for (let i = history.length - 1; i >= 0; i--) {
    if (history[i].decision === decision) n++;
    else break;
  }
  return n;
}

/**
 * Default reflection policy — maps a non-confirming outcome to a next move:
 *
 *   - regression failed on a bug-closing patch → `try_different` (the fix shape
 *     is wrong even though it silenced KASAN).
 *   - `not_root_cause`    → `try_different` (wrong/incomplete fix; a re-run of
 *     the same diff is pointless — it deterministically fails again).
 *   - `patch_apply_failed`→ `try_different` (malformed/mis-contexted diff).
 *   - `patch_generation_failed` → `try_different` once; two declines in a row →
 *     `stop` (the generator has nothing).
 *   - `rebuild_failed`    → `retry_same` once (inconclusive/transient build or
 *     run); a second consecutive inconclusive → `stop`.
 *   - `error` / anything else → `stop`.
 */
export function defaultReflect(ctx: {
  result: PatchValidateResult;
  regression?: RegressionOutcome;
  attempt: number;
  maxAttempts: number;
  history: ReadonlyArray<PatchAttempt>;
}): ReflectDecision {
  if (ctx.regression && !ctx.regression.passed) return "try_different";

  switch (ctx.result.status) {
    case "root_cause_confirmed":
      // Reached only if a caller reflects on a confirmed result directly.
      return "stop";
    case "not_root_cause":
    case "patch_apply_failed":
      return "try_different";
    case "patch_generation_failed": {
      const prev = ctx.history[ctx.history.length - 1];
      if (prev && prev.result.status === "patch_generation_failed") return "stop";
      return "try_different";
    }
    case "rebuild_failed":
      // One same-patch retry for a transient/inconclusive build; then stop.
      return countTrailingDecision(ctx.history, "retry_same") >= 1
        ? "stop"
        : "retry_same";
    case "error":
    default:
      return "stop";
  }
}

/**
 * Run the bounded validate-and-reflect loop.
 *
 * Each attempt: synthesise the round's {@link PatchGenerator} from `mode` +
 * history, hand it to the oracle, and inspect the verdict.
 *
 *   - Oracle confirms + (no regression check OR regression passes) → accept,
 *     `root_cause_confirmed`, stop.
 *   - Oracle confirms but regression FAILS → reflect (default: `try_different`).
 *   - Oracle does not confirm → reflect. `stop` ⇒ `gave_up`; otherwise carry the
 *     decision into the next round's `mode`.
 *
 * Falls through to `budget_exhausted` when the attempt cap is hit while
 * reflection still wanted to continue. Always returns the full attempt trail.
 */
export async function runPatchReflectLoop(
  opts: PatchReflectLoopOptions,
): Promise<PatchReflectLoopResult> {
  const maxAttempts = Math.max(1, Math.floor(opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS));
  const validate = opts.validator ?? validatePatchRemovesCrash;
  const reflect = opts.reflect ?? defaultReflect;
  const log = opts.logger ?? (() => undefined);

  const attempts: PatchAttempt[] = [];
  let lastPatch: CandidatePatch | undefined;
  let mode: PatchGenMode = "initial";

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    log(`[patch-reflect] attempt ${attempt}/${maxAttempts} (mode=${mode})`);

    // Build the per-round generator. On `retry_same` with a known prior diff we
    // re-run that exact patch (the oracle re-applies + rebuilds it); otherwise
    // we ask the reflective generator for a (different) candidate.
    const priorAttempts: PriorAttemptSummary[] = attempts.map((a) => ({
      attempt: a.attempt,
      status: a.result.status,
      reason: a.result.reason,
      ...(a.result.patch ? { patch: a.result.patch } : {}),
    }));
    const roundGenerator: PatchGenerator =
      mode === "retry_same" && lastPatch
        ? async () => lastPatch ?? null
        : async (baseCtx) =>
            opts.patchGenerator({
              ...baseCtx,
              attempt,
              mode,
              priorAttempts,
            });

    const result = await validate({ ...opts.validate, patchGenerator: roundGenerator });
    if (result.patch) lastPatch = result.patch;

    if (result.patchValidated) {
      // The oracle says the bug is closed. Gate on regression if a check exists.
      let regression: RegressionOutcome | undefined;
      if (opts.regressionCheck && result.patch) {
        regression = await opts.regressionCheck({ patch: result.patch, result });
      }

      if (!regression || regression.passed) {
        const record: PatchAttempt = {
          attempt,
          mode,
          result,
          ...(regression ? { regression } : {}),
          decision: "stop",
        };
        attempts.push(record);
        return {
          status: "root_cause_confirmed",
          patchValidated: true,
          ...(result.patch ? { confirmedPatch: result.patch } : {}),
          finalResult: result,
          attempts,
          reason:
            `root cause confirmed on attempt ${attempt}/${maxAttempts}` +
            (regression ? " (regression checks passed)" : ""),
        };
      }

      // Bug closed but regression broke — reflect like any other failure.
      const decision = reflect({ result, regression, attempt, maxAttempts, history: attempts });
      attempts.push({ attempt, mode, result, regression, decision });
      log(`[patch-reflect] regression failed: ${regression.reason} → ${decision}`);
      if (decision === "stop") {
        return {
          status: "gave_up",
          patchValidated: false,
          finalResult: result,
          attempts,
          reason: `stopped after regression failure on attempt ${attempt}/${maxAttempts}: ${regression.reason}`,
        };
      }
      mode = decision;
      continue;
    }

    // Oracle did not confirm → reflect on the verdict.
    const decision = reflect({ result, attempt, maxAttempts, history: attempts });
    attempts.push({ attempt, mode, result, decision });
    log(`[patch-reflect] verdict=${result.status} → ${decision}`);

    if (decision === "stop") {
      return {
        status: "gave_up",
        patchValidated: false,
        finalResult: result,
        attempts,
        reason: `reflection stopped after attempt ${attempt}/${maxAttempts}: ${result.reason}`,
      };
    }
    mode = decision;
  }

  // Budget exhausted while reflection still wanted to keep going.
  const last = attempts[attempts.length - 1];
  return {
    status: "budget_exhausted",
    patchValidated: false,
    finalResult: last.result,
    attempts,
    reason: `patch not validated within ${maxAttempts} attempts (budget exhausted)`,
  };
}
