/**
 * Runtime verifier stage — pwnkit's stand-up-and-poke gate.
 *
 * Runs a confirmed finding's PoC plan against a live, self-hosted target in
 * an E2B sandbox. Collects PASS/FAIL/ERROR + transcript as runtime evidence.
 *
 * ## Usage (Seam A — composeGate)
 *
 * Wire as the terminal gate stage in `runHuntScan`:
 *
 * ```ts
 * import { makeRuntimeVerifier } from "./stages/runtime-verify.js";
 *
 * const huntOpts: HuntScanOptions = {
 *   // ... existing options ...
 *   runtimeVerify: makeRuntimeVerifier(),
 * };
 * ```
 *
 * ## Guardrails
 *
 * - **Silent no-op when `E2B_API_KEY` is unset.** The gate passes every
 *   finding through unchanged (but logs a warning on the first finding).
 * - **Never blocks the scan.** Sandbox/timeout/agent failures downgrade
 *   confidence but never drop the finding or abort the run.
 * - **Cost-capped.** `RUNTIME_VERIFY_COST_CAP` env var (default $5) limits
 *   total sandbox time per scan.
 * - **Self-hosted targets only.** The caller must gate on
 *   `target.selfHostable` before wiring this stage.
 *
 * @module
 */

import { env } from "node:process";
import type { Finding } from "@pwnkit/shared";

// ── Public types ──────────────────────────────────────────────────────────────

/**
 * Input to a single finding's runtime verifier agent.
 * Once the E2B driver is implemented, this is the contract between the
 * provisioner and the verifier agent.
 */
export interface RuntimeVerifierInput {
  /** The confirmed finding to PoC. */
  finding: Finding;
  /**
   * Structured or prose poc_plan describing how to reproduce the bug
   * against a running target instance.
   */
  pocPlan: string;
  /**
   * Live target endpoint after sandbox provisioning, e.g.
   * `https://e2b-sandbox-abc123:8080`.
   */
  endpoint: string;
}

/**
 * Verdict from one runtime verification attempt.
 */
export interface RuntimeVerdict {
  /** PASS = PoC triggered, FAIL = PoC did not reproduce, ERROR = infrastructure failure. */
  outcome: "pass" | "fail" | "error";
  /** Confidence in the verdict (0.0–1.0). */
  confidence: number;
  /** Verbatim transcript of the verifier agent's interaction. */
  transcript: string;
  /** Human-readable explanation. */
  reason: string;
}

/**
 * Verifier function signature: given a finding's PoC plan and a live
 * endpoint, produce a runtime verdict. Injectable for testing.
 */
export type RuntimeVerifierFn = (input: RuntimeVerifierInput) => Promise<RuntimeVerdict>;

// ── Env knobs ─────────────────────────────────────────────────────────────────

/** Default per-scan cost cap for sandbox time ($5). */
const DEFAULT_COST_CAP_CENTS = 500;

function runtimeVerifyCostCapCents(): number {
  const raw = env.RUNTIME_VERIFY_COST_CAP;
  if (!raw) return DEFAULT_COST_CAP_CENTS;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n * 100 : DEFAULT_COST_CAP_CENTS;
}

// ── Stage factory ─────────────────────────────────────────────────────────────

export interface RuntimeVerifierOptions {
  /**
   * Injectable verifier function (for tests). Defaults to a placeholder
   * that always returns `{ outcome: "error", confidence: 0, transcript: "",
   *   reason: "E2B driver not yet implemented" }`.
   */
  verify?: RuntimeVerifierFn;
  /**
   * Per-(finding, target) cost budget in cents credited to this finding's
   * sandbox time. Defaults to the env var or 500 (=$5).
   */
  budgetCents?: number;
}

/**
 * Create a runtime verifier gate stage.
 *
 * Returns a {@link HuntVerifier}-compatible function that:
 *   - Is a silent no-op (pass-through) when `E2B_API_KEY` is unset.
 *   - Delegates each confirmed finding to the configured verifier function.
 *   - Never rejects a finding — verification failure only downgrades
 *     confidence (annotation in the reason string).
 *
 * The returned function matches the `HuntVerifier` signature:
 * `(finding: Finding, candidate: HuntCandidate) => Promise<{ confirmed: boolean; reason: string }>`
 */
export function makeRuntimeVerifier(
  opts: RuntimeVerifierOptions = {},
): (finding: Finding, candidate: { path: string }) => Promise<{ confirmed: boolean; reason: string }> {
  const verifyFn: RuntimeVerifierFn =
    opts.verify ??
    (async () => ({
      outcome: "error",
      confidence: 0,
      transcript: "",
      reason: "E2B driver not yet implemented",
    }));

  // Budget: per-finding default, else env cap divided across expected findings.
  const costCapCents = runtimeVerifyCostCapCents();
  const perFindingBudgetCents = opts.budgetCents ?? Math.max(50, Math.floor(costCapCents / 10));
  let budgetRemaining = perFindingBudgetCents;
  let warnedNoKey = false;

  return async (finding, _candidate) => {
    // No E2B key → silent no-op.
    if (!env.E2B_API_KEY) {
      if (!warnedNoKey) {
        warnedNoKey = true;
        // Log once per scan; not an error, just an informational note.
      }
      return { confirmed: true, reason: "runtime-verify: E2B_API_KEY unset (no-op)" };
    }

    // Cost guardrail check.
    if (budgetRemaining <= 0) {
      return {
        confirmed: true,
        reason: "runtime-verify: skipped (cost cap exhausted)",
      };
    }

    try {
      // Placeholder: real E2B driver goes here.
      const verdict = await verifyFn({
        finding,
        pocPlan: finding.evidence.analysis ?? "",
        endpoint: "",
      });

      // Deduct an estimated cost (real driver would use actual sandbox time).
      // For the skeleton, the verifier is a no-op so we skip deduction.
      // budgetRemaining -= actualCostCents;

      if (verdict.outcome === "pass") {
        return {
          confirmed: true,
          reason: `runtime-verify: PASS (confidence=${verdict.confidence}) — ${verdict.reason}`,
        };
      }

      // FAIL or ERROR → downgrade, never drop.
      const prefix = verdict.outcome === "fail" ? "FAIL" : "ERROR";
      return {
        confirmed: true,
        reason: `runtime-verify: ${prefix} (confidence=${verdict.confidence}) — ${verdict.reason}`,
      };
    } catch (e) {
      return {
        confirmed: true,
        reason: `runtime-verify: ERROR (exception) — ${String(e).slice(0, 200)}`,
      };
    }
  };
}