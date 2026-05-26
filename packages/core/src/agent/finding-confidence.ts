/**
 * Hybrid confidence signal for findings.
 *
 * Background — the cloud-side `findings.confidence` column (numeric(4,3),
 * range 0.000–1.000) was 100% NULL because pwnkit-cli never emitted a
 * confidence value on findings: the OSS `Finding` type carried the field
 * but the `save_finding` agent tool didn't accept it, the JSON / structured
 * findings parser hard-coded `confidence: undefined`, and the
 * `finding_ingested` event payload didn't propagate it. This helper adds
 * the missing source-of-truth.
 *
 * We use strategy (c) — hybrid:
 *
 *   1. **LLM self-report.** `save_finding` now accepts an optional
 *      `confidence: number` (0..1). The agent reports its own calibration.
 *   2. **PoC-status floor.** LLMs are notoriously badly calibrated, so we
 *      clamp the LLM's value UP to a floor based on what the codebase
 *      actually has evidence for:
 *        - no PoC step graph attached         → no floor (LLM word alone)
 *        - pocSteps present                   → floor 0.6
 *        - pocSteps with at least one
 *          verifiable `expect` predicate      → floor 0.8
 *
 *      "Verifiable" here means the step graph asserts something concrete the
 *      behavioural re-verify executor will check (HTTP status, body match,
 *      file-exists, exit-zero), not just a `note`. A finding the agent
 *      bothered to encode as a structured PoC plan is, empirically, much
 *      more likely to be a true positive than one with prose-only evidence.
 *
 *   3. **Floor never exceeds 1.0.** Final value is clamped to [0,1].
 *
 * If neither signal is present (no LLM number, no PoC steps), we return
 * `undefined` — better an honest absence than a fabricated 0.5.
 *
 * The thresholds (0.6 / 0.8) are heuristic; the operator may want to
 * recalibrate them once we have ground-truth data from the cloud triage
 * pipeline. They're picked to match the existing convention in
 * `agentic-scanner.ts` where reachability/multi-modal layers already cap
 * confidence around 0.7 and the oracle layer hard-sets 1.0.
 */
import type { PocStep } from "@pwnkit/shared";

/**
 * The PoC step kinds whose `expect` predicates the behavioural re-verify
 * executor will actually run. A `note` step is informational and doesn't
 * count toward the verifiable floor — the agent could have written
 * anything in there.
 */
const VERIFIABLE_EXPECT_KINDS = new Set([
  "exit-zero",
  "http-status",
  "body-contains",
  "body-matches",
  "file-exists",
]);

/** Floor when pocSteps array is present but no `expect` predicate is set. */
export const POC_PRESENT_FLOOR = 0.6;

/** Floor when at least one pocStep has a verifiable `expect` predicate. */
export const POC_VERIFIABLE_FLOOR = 0.8;

/**
 * Coerce an arbitrary value to a finite number in [0,1], or `undefined` if
 * the input isn't a usable number.
 */
function clampToUnitOrUndefined(v: unknown): number | undefined {
  if (typeof v !== "number" || !Number.isFinite(v)) return undefined;
  if (v < 0) return 0;
  if (v > 1) return 1;
  return v;
}

/**
 * Compute the PoC-status floor for the given step graph.
 *
 * Returns 0 when there's no graph (i.e. no floor applies), `POC_PRESENT_FLOOR`
 * when there's a non-empty graph, and `POC_VERIFIABLE_FLOOR` when at least
 * one step has a verifiable `expect` predicate.
 */
export function pocStatusFloor(pocSteps: PocStep[] | undefined): number {
  if (!pocSteps || pocSteps.length === 0) return 0;
  const hasVerifiable = pocSteps.some(
    (s) => s.expect != null && VERIFIABLE_EXPECT_KINDS.has(s.expect.type),
  );
  return hasVerifiable ? POC_VERIFIABLE_FLOOR : POC_PRESENT_FLOOR;
}

/**
 * Compute the final per-finding confidence value to emit.
 *
 * @param rawConfidence  the LLM-reported confidence, if any (raw value from
 *   the `save_finding` tool call args — could be anything)
 * @param pocSteps       structured PoC step graph attached to the finding,
 *   if any
 * @returns a finite number in [0,1], or `undefined` when neither signal is
 *   present
 */
export function computeFindingConfidence(
  rawConfidence: unknown,
  pocSteps: PocStep[] | undefined,
): number | undefined {
  const llm = clampToUnitOrUndefined(rawConfidence);
  const floor = pocStatusFloor(pocSteps);

  if (llm === undefined && floor === 0) return undefined;

  // Take the max of the LLM number and the PoC floor, defaulting to the
  // floor alone when the LLM didn't report. Final clamp is redundant but
  // cheap insurance against future floor-constant typos.
  const fused = Math.max(llm ?? 0, floor);
  return Math.min(1, Math.max(0, fused));
}
