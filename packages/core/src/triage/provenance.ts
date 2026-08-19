/**
 * Triage provenance — "which FP-moat layers actually ran for this finding?"
 *
 * ## Why this module exists
 *
 * `finding.layerVerdicts` (pwnkit#112) is an append-only log that each triage
 * layer writes to as it executes. It is the only per-finding record of what
 * the triage stack did. But until now it had **no reader outside the router's
 * own feature extractor** — nothing rendered it, nothing summarized it, and
 * nothing reconciled it against the set of layers that are supposed to exist.
 *
 * That is a problem for a specific and load-bearing reason: we describe triage
 * as a multi-layer false-positive moat, but the shipped default enables only a
 * few of those layers (see `agent/features.ts`, which says so itself). Without
 * a reader, "the moat ran" is an assertion nobody can check — not in CI, not
 * in a report, not when a finding is questioned months later.
 *
 * This module makes the claim checkable. It answers, per finding:
 *   - which layers executed and what they decided,
 *   - which layers explicitly recorded that they were skipped, and why,
 *   - which layers left **no trace at all**.
 *
 * ## The honesty rule: read the record, not the environment
 *
 * A tempting shortcut is to report layer status from `features.*` — ask the
 * flags which layers are on and call those "ran". That would be wrong, and
 * dangerously so: findings are persisted and re-read later (`findings show`,
 * disclosure drafting, the benchmark data collector) under a *different*
 * environment than the scan ran in. Reading today's env would let a scan that
 * ran with the moat off be rendered, after the fact, as though the moat had
 * been on.
 *
 * So this module derives status **exclusively from the recorded verdicts**. If
 * a layer left no verdict, we say so plainly rather than inferring anything.
 * `features.*` is never consulted here — that is deliberate, not an oversight.
 *
 * ## The three statuses, and why `unrecorded` is not the same as `skipped`
 *
 * A layer that ran, and a layer that deliberately stood down, both leave a
 * verdict — the second with kind `"skip"` and a reason naming the flag or the
 * missing precondition. Those are `executed` and `skipped`.
 *
 * `unrecorded` is the third case and the one worth surfacing: no verdict of
 * any kind. It means we genuinely cannot say what happened. It has two causes
 * that a reader must be able to tell apart, so {@link LayerProvenance.reason}
 * distinguishes them:
 *
 *   1. **The layer has no instrumentation at all.** `structured_verify`,
 *      `consensus`, and `kernel_oracle` are declared in `TriageLayerName`,
 *      have registry entries, and are routable — but no code path in the
 *      engine emits a `LayerVerdict` for any of them. They are permanently
 *      invisible. See {@link UNINSTRUMENTED_LAYERS}.
 *   2. **The finding exited the pipeline early.** A finding rejected by
 *      `holding_it_wrong` never reaches `oracle`, so `oracle` has no verdict.
 *      That is correct behaviour and the absence is meaningful.
 *
 * Reporting both as a bare "skipped" would paper over (1), which is exactly
 * the kind of unfalsifiable moat claim this module exists to prevent.
 *
 * See `docs/src/content/docs/triage.md` for the operator-facing view, and
 * `agent/feature-presets.ts` for the preset that enables the full stack so an
 * A/B run becomes possible.
 */

import type { Finding, LayerVerdict, TriageLayerName } from "@pwnkit/shared";
import { LAYER_REGISTRY, LAYER_REGISTRY_BY_ID } from "./router/layer-registry.js";

/**
 * Whether a layer left evidence that it ran, evidence that it stood down, or
 * no evidence at all. Derived only from recorded verdicts — never from the
 * current environment (see the module header).
 */
export type LayerExecutionStatus =
  /** At least one non-`skip` verdict: the layer ran and reached a decision. */
  | "executed"
  /** Only `skip` verdicts: the layer explicitly recorded that it stood down. */
  | "skipped"
  /** No verdict of any kind. We cannot say whether this layer ran. */
  | "unrecorded";

/**
 * Layers that are declared, registered, and routable, but for which **no code
 * path anywhere in the engine emits a `LayerVerdict`**. Verified by exhaustive
 * search over every `layer:` literal in `packages/core` and `packages/cli`.
 *
 * They are listed here so provenance can say "this layer is uninstrumented"
 * instead of the misleading "this layer did not run" — the distinction between
 * a layer that stood down and a layer we simply cannot observe.
 *
 * Removing an entry from this list is the correct move the moment that layer
 * starts recording verdicts; `provenance.test.ts` pins the list so it cannot
 * drift silently.
 */
export const UNINSTRUMENTED_LAYERS: readonly TriageLayerName[] = [
  "structured_verify",
  "consensus",
  "kernel_oracle",
] as const;

/**
 * The opt-in false-positive moat layers — the ones gated behind a
 * `PWNKIT_FEATURE_*` flag that is **off** in the shipped default, and which
 * `agent/features.ts` says must be explicitly enabled before any FP-moat A/B
 * claim can be made.
 *
 * `holding_it_wrong`, `evidence_gate`, and `oracle` are excluded: the first
 * two default ON and the third is unconditional, so their execution is not
 * what a moat claim turns on. {@link TriageProvenance.moatEngaged} counts only
 * the layers in this set.
 */
export const OPT_IN_MOAT_LAYERS: readonly TriageLayerName[] = [
  "reachability",
  "multi_modal",
  "publishability",
  "structured_verify",
  "pov_gate",
  "poc_gen",
  "consensus",
] as const;

/** Per-layer provenance derived from a finding's recorded verdicts. */
export interface LayerProvenance {
  /** Stable layer id, matching `TriageLayerName`. */
  layer: TriageLayerName;
  /** Human-readable layer name from the registry. */
  name: string;
  /** The `PWNKIT_FEATURE_*` env var that gates this layer, per the registry. */
  envFlag: string;
  /** Whether the layer ran, stood down, or left no trace. */
  status: LayerExecutionStatus;
  /**
   * Every recorded verdict for this layer, in execution order. Usually zero or
   * one; a layer may record more than one when it re-evaluates a finding.
   */
  verdicts: readonly LayerVerdict[];
  /**
   * The last recorded reason when the layer left a verdict, or an explanation
   * of *why nothing was recorded* when `status` is `"unrecorded"`.
   */
  reason: string;
  /** Summed wall-clock across this layer's verdicts. 0 when unrecorded. */
  durationMs: number;
  /** Summed USD across this layer's verdicts. 0 when unrecorded. */
  costUsd: number;
  /** True when this layer is in {@link UNINSTRUMENTED_LAYERS}. */
  uninstrumented: boolean;
  /** True when this layer is in {@link OPT_IN_MOAT_LAYERS}. */
  optInMoatLayer: boolean;
}

/** Whole-finding triage provenance: what the moat actually did. */
export interface TriageProvenance {
  /** One entry per registry layer, in canonical execution order. */
  layers: readonly LayerProvenance[];
  /** Layers with at least one non-`skip` verdict. */
  executed: readonly TriageLayerName[];
  /** Layers whose only verdicts were `skip`. */
  skipped: readonly TriageLayerName[];
  /** Layers with no verdict at all. */
  unrecorded: readonly TriageLayerName[];
  /** The subset of {@link OPT_IN_MOAT_LAYERS} that actually executed. */
  moatLayersExecuted: readonly TriageLayerName[];
  /**
   * True when at least one opt-in moat layer executed. This is the single
   * value to check before describing a finding as having been through the FP
   * moat — if it is false, the finding saw only the always-on filters.
   */
  moatEngaged: boolean;
  /** Summed USD across every recorded verdict. */
  totalCostUsd: number;
  /** Summed wall-clock across every recorded verdict. */
  totalDurationMs: number;
}

/**
 * Explanation used when a layer left no verdict. Split by cause so a reader
 * can tell "we never built the recorder" apart from "the finding stopped
 * before this layer" — see the module header for why that matters.
 */
function unrecordedReason(layer: TriageLayerName): string {
  return UNINSTRUMENTED_LAYERS.includes(layer)
    ? "no instrumentation: this layer never emits a LayerVerdict, so its execution is unobservable"
    : "no verdict recorded: the layer did not run, or the finding exited triage before reaching it";
}

/**
 * Summarize what the triage stack recorded for a single finding.
 *
 * Pure and side-effect free. Safe on findings from any engine version: a
 * finding with no `layerVerdicts` at all yields every layer `unrecorded`,
 * which is the honest answer for pre-instrumentation data rather than a
 * silent "nothing was skipped".
 *
 * Verdicts naming a layer outside the registry are ignored rather than
 * throwing — `layerVerdicts` is persisted JSON that may outlive a rename.
 */
export function summarizeTriageProvenance(finding: Finding): TriageProvenance {
  const recorded = new Map<TriageLayerName, LayerVerdict[]>();
  for (const verdict of finding.layerVerdicts ?? []) {
    if (!(verdict.layer in LAYER_REGISTRY_BY_ID)) continue;
    const bucket = recorded.get(verdict.layer);
    if (bucket) bucket.push(verdict);
    else recorded.set(verdict.layer, [verdict]);
  }

  const layers: LayerProvenance[] = LAYER_REGISTRY.map((entry) => {
    const verdicts = recorded.get(entry.id) ?? [];
    const ran = verdicts.some((v) => v.verdict !== "skip");
    const status: LayerExecutionStatus =
      verdicts.length === 0 ? "unrecorded" : ran ? "executed" : "skipped";

    return {
      layer: entry.id,
      name: entry.name,
      envFlag: entry.env_flag,
      status,
      verdicts,
      reason:
        verdicts.length === 0
          ? unrecordedReason(entry.id)
          : (verdicts[verdicts.length - 1]?.reason ?? ""),
      durationMs: verdicts.reduce((sum, v) => sum + (v.durationMs || 0), 0),
      costUsd: verdicts.reduce((sum, v) => sum + (v.costUsd || 0), 0),
      uninstrumented: UNINSTRUMENTED_LAYERS.includes(entry.id),
      optInMoatLayer: OPT_IN_MOAT_LAYERS.includes(entry.id),
    };
  });

  const byStatus = (s: LayerExecutionStatus): TriageLayerName[] =>
    layers.filter((l) => l.status === s).map((l) => l.layer);

  const moatLayersExecuted = layers
    .filter((l) => l.optInMoatLayer && l.status === "executed")
    .map((l) => l.layer);

  return {
    layers,
    executed: byStatus("executed"),
    skipped: byStatus("skipped"),
    unrecorded: byStatus("unrecorded"),
    moatLayersExecuted,
    moatEngaged: moatLayersExecuted.length > 0,
    totalCostUsd: layers.reduce((sum, l) => sum + l.costUsd, 0),
    totalDurationMs: layers.reduce((sum, l) => sum + l.durationMs, 0),
  };
}

/**
 * Render provenance as plain text lines (no ANSI — the caller colorizes).
 *
 * The header states the moat conclusion first, because that is the question a
 * reader actually has. When no opt-in moat layer ran, it says so explicitly
 * rather than letting a long list of "skipped" lines imply coverage.
 */
export function formatTriageProvenance(provenance: TriageProvenance): string[] {
  const lines: string[] = [];

  lines.push(
    provenance.moatEngaged
      ? `FP moat engaged: ${provenance.moatLayersExecuted.length} opt-in layer(s) ran — ${provenance.moatLayersExecuted.join(", ")}`
      : "FP moat NOT engaged: no opt-in moat layer ran for this finding (always-on filters only)",
  );
  lines.push(
    `Layers: ${provenance.executed.length} executed, ${provenance.skipped.length} skipped, ${provenance.unrecorded.length} unrecorded` +
      ` | ${provenance.totalDurationMs}ms | $${provenance.totalCostUsd.toFixed(4)}`,
  );

  for (const layer of provenance.layers) {
    const marker =
      layer.status === "executed" ? "+" : layer.status === "skipped" ? "-" : "?";
    const verdictKinds = layer.verdicts.map((v) => v.verdict).join(",");
    const detail = verdictKinds ? `${layer.status}(${verdictKinds})` : layer.status;
    lines.push(`  ${marker} ${layer.layer.padEnd(18)} ${detail} — ${layer.reason}`);
  }

  return lines;
}
