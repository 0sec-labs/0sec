/**
 * Triage Layer Registry — catalog of the triage layers the router can
 * dispatch to. Each entry is **documentation in code**: the router uses the
 * `id` to refer to a layer, the runtime uses `env_flag` to read the existing
 * scan-level toggle, and the cost_factor is a normalized 0..1 estimate used
 * by the v0 rule-based router to prefer cheap layers over expensive ones.
 *
 * Cost factors are relative, not absolute USD: 0 = pure regex/grep (no LLM,
 * no network), 1 = full LLM-driven verify with tool use. The numbers come
 * from the per-layer telemetry shipped in pwnkit#112 and the per-layer
 * ablation in pwnkit#72's 2026-04-11 comment. They will be replaced by
 * measured medians once #112's telemetry has accumulated enough samples.
 *
 * See pwnkit#113 for the design doc, pwnkit#67 for the joint-paper plan.
 */

import type { TriageLayerName } from "@pwnkit/shared";

export type LayerId = TriageLayerName;

export interface LayerRegistryEntry {
  /** Stable layer identifier; matches the `TriageLayerName` union. */
  id: LayerId;
  /** Human-readable name (used in router reasoning strings). */
  name: string;
  /**
   * The PWNKIT_FEATURE_* env var that toggles this layer today. When the
   * router decides to skip a layer it does NOT mutate the env var; the
   * skip is per-finding, not per-scan. The env var remains the operator-
   * facing escape hatch.
   */
  env_flag: string;
  /**
   * Relative cost factor in [0, 1]:
   *   0.00 = pure regex/grep, no LLM, no network (`holding_it_wrong`)
   *   0.10 = feature-vector arithmetic, no LLM (`evidence_gate`)
   *   0.20 = static analysis pass, no LLM (`reachability`)
   *   0.25 = deterministic exploit replay against the target (`oracle`)
   *   0.30 = secondary scanner cross-check (`multi_modal`)
   *   0.40 = single-shot LLM verify (`structured_verify`)
   *   0.55 = LLM with tool use, single agent (`pov_gate`)
   *   0.60 = N-vote LLM consensus (`consensus`)
   *   0.50 = kernel reproducer compile + run (`kernel_oracle`)
   * The router uses cost_factor to break ties between rules and to compute
   * "cost saved" for the offline training dataset.
   */
  cost_factor: number;
  /** What this layer does, in one sentence. */
  description: string;
}

/**
 * The triage layers the v0 router can dispatch to.
 *
 * Order is the *canonical execution order* used by `agentic-scanner.ts`
 * today: free filters first (holding_it_wrong, evidence_gate), then static
 * analysis (reachability), then deterministic oracles (oracle, multi_modal,
 * publishability), then LLM-driven layers (structured_verify,
 * pov_gate, consensus), with kernel_oracle slotted in for kernel
 * findings.
 *
 * The router can choose ANY subset of these, but must respect the rule
 * that a downstream layer cannot run if an upstream layer rejected the
 * finding outright. That invariant is enforced by `agentic-scanner.ts`,
 * not by the registry.
 */
export const LAYER_REGISTRY: readonly LayerRegistryEntry[] = [
  {
    id: "holding_it_wrong",
    name: "Holding-It-Wrong Regex Blocklist",
    env_flag: "PWNKIT_FEATURE_HOLDING_IT_WRONG",
    cost_factor: 0.0,
    description:
      "Pure-regex blocklist that rejects findings whose evidence reads as 'the function did its job' (e.g. successful logout, normal 404).",
  },
  {
    id: "evidence_gate",
    name: "Evidence Completeness Gate",
    env_flag: "PWNKIT_FEATURE_EVIDENCE_GATE",
    cost_factor: 0.1,
    description:
      "Drops findings whose extracted feature vector reports evidence_completeness <= 0.5 (no request + response + analysis triad).",
  },
  {
    id: "reachability",
    name: "Reachability Gate",
    env_flag: "PWNKIT_FEATURE_REACHABILITY_GATE",
    cost_factor: 0.2,
    description:
      "Static-analysis check that the vulnerable sink is reachable from an application entry point. White-box only.",
  },
  {
    id: "oracle",
    name: "Per-Category Verification Oracle",
    env_flag: "(always on)",
    cost_factor: 0.25,
    description:
      "Deterministic per-class exploit replay (SQLi error-based, XSS reflection, SSRF callback, RCE, path traversal, IDOR). Free, fast, high precision.",
  },
  {
    id: "multi_modal",
    name: "Multi-Modal Agreement (Foxguard)",
    env_flag: "PWNKIT_FEATURE_MULTIMODAL",
    cost_factor: 0.3,
    description:
      "Cross-checks every finding against the foxguard Rust pattern scanner. Agreement boosts confidence; disagreement gates the verify pipeline.",
  },
  {
    id: "publishability",
    name: "Publishability / In-Scope Gate",
    env_flag: "PWNKIT_FEATURE_PUBLISHABILITY_GATE",
    cost_factor: 0.3,
    description:
      "Decides disclosure-worthiness (issue #539): SECURITY.md threat-model exclusion (by_design), global advisory dedup (duplicate) with the fix-bypass exception (advisory exists but reproduces on latest → fix_bypass), latest-version (fixed), and public-API reachability (unreachable). Never auto-drops high-severity/high-impact findings — routes them to needs_verify via canAutoSuppress.",
  },
  {
    id: "structured_verify",
    name: "Structured 4-Step Verify",
    env_flag: "PWNKIT_FEATURE_CONSENSUS_VERIFY",
    cost_factor: 0.4,
    description:
      "Single-shot LLM verification with a fixed 4-step rubric (reproduce, classify, impact, severity). Used for ambiguous mid-confidence findings.",
  },
  {
    id: "pov_gate",
    name: "Proof-of-Vulnerability Gate",
    env_flag: "PWNKIT_FEATURE_POV_GATE",
    cost_factor: 0.55,
    description:
      "Agentic loop (up to N turns) that tries to build a working PoC. No PoC → downgrade to info. Empirical FP discriminator per arXiv:2509.07225.",
  },
  {
    id: "consensus",
    name: "Self-Consistency Voting",
    env_flag: "PWNKIT_FEATURE_CONSENSUS_VERIFY",
    cost_factor: 0.6,
    description:
      "Runs the structured verify pipeline N times with sampling and takes the majority vote. Reduces single-call variance at N× the cost.",
  },
  {
    id: "kernel_oracle",
    name: "Kernel Crash Oracle",
    env_flag: "(always on for kernel)",
    cost_factor: 0.5,
    description:
      "Compile-and-run reproducer for kernel crashes. Runs only when the finding has crashType set; matches KASAN signatures and validates consistency.",
  },
] as const;

/**
 * Map from layer id to its registry entry. O(1) lookup.
 */
export const LAYER_REGISTRY_BY_ID: Readonly<Record<LayerId, LayerRegistryEntry>> =
  Object.freeze(
    LAYER_REGISTRY.reduce(
      (acc, entry) => {
        acc[entry.id] = entry;
        return acc;
      },
      {} as Record<LayerId, LayerRegistryEntry>,
    ),
  );

/**
 * The default static layer set used today by `agentic-scanner.ts`. When
 * `PWNKIT_FEATURE_DYNAMIC_TRIAGE` is unset, the router returns this set
 * verbatim so behavior is unchanged.
 *
 * Order matches `agentic-scanner.ts`'s dispatch order: free filters first,
 * then optional gates, then oracles. Kernel oracle is not in the default
 * set — it only fires for findings with `crashType` set.
 */
export const DEFAULT_STATIC_LAYER_SET: readonly LayerId[] = [
  "holding_it_wrong",
  "evidence_gate",
  "reachability",
  "multi_modal",
  "oracle",
  "pov_gate",
] as const;

/**
 * The "free" subset — layers with cost_factor <= 0.25. These layers run
 * even on findings the router has already decided to auto-accept, because
 * the marginal cost is negligible and the telemetry feeds the offline
 * training dataset for the eventual learned router.
 */
export const FREE_LAYER_SET: readonly LayerId[] = LAYER_REGISTRY.filter(
  (entry) => entry.cost_factor <= 0.25,
).map((entry) => entry.id);

/**
 * The "expensive" subset — layers with cost_factor > 0.4. The router
 * skips these on findings it has high confidence about (in either
 * direction) so the wallclock-and-USD savings show up in production.
 */
export const EXPENSIVE_LAYER_SET: readonly LayerId[] = LAYER_REGISTRY.filter(
  (entry) => entry.cost_factor > 0.4,
).map((entry) => entry.id);
