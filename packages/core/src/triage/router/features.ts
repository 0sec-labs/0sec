/**
 * Routing Feature Extractor
 *
 * Thin wrapper over `extractFeatures` from the existing
 * `triage/feature-extractor.ts`. The router consumes the same 45-feature
 * (well, 55 — 45 web + 10 kernel — but the issue and the paper refer to
 * it as "the 45-feature vector") handcrafted vector that the joint paper
 * (pwnkit#67) and the trained classifier (pwnkit#113) both train on.
 *
 * We deliberately DO NOT redesign or extend that vector inside the router
 * — it's the contract with the joint paper. Instead this module adds a
 * small set of **routing-specific scalars** (subsystem, prior layer
 * agreement) that the v0 rule-based router uses but the trained
 * classifier ignores. Those scalars live alongside the vector, not
 * inside it.
 *
 * See pwnkit#113 §"What the router sees".
 */

import type { Finding, LayerVerdict } from "@pwnkit/shared";
import { extractFeatures, FEATURE_NAMES } from "../feature-extractor.js";

// Re-export the existing handcrafted feature contract verbatim so callers
// can import everything routing-related from one place.
export { extractFeatures, FEATURE_NAMES };

/**
 * Coarse subsystem bucket the finding came from. Used by the v0 router
 * rules and by the offline training pipeline as a one-hot covariate.
 *
 * Derived purely from `finding.category` — no LLM, no network.
 */
export type RoutingSubsystem =
  | "web"
  | "kernel"
  | "supply_chain"
  | "agent_safety"
  | "source_audit"
  | "other";

/**
 * Aggregated verdict from upstream triage layers. Used by the router
 * when a layer ran before the routing decision (e.g. `holding_it_wrong`
 * and `evidence_gate` always run upstream of the router today).
 */
export interface PriorLayerSignals {
  /** Did any upstream layer reject the finding outright? */
  anyReject: boolean;
  /** Did any upstream layer downgrade severity? */
  anyDowngrade: boolean;
  /** Maximum confidence reported by any upstream layer. */
  maxUpstreamConfidence: number;
  /** Number of upstream layers that ran. */
  upstreamLayerCount: number;
}

/**
 * Routing-specific feature bundle. The 45-feature vector is the primary
 * input; everything else is auxiliary covariate used by the rule-based
 * v0 router but ignored by the to-be-trained learned classifier.
 */
export interface RoutingFeatures {
  /**
   * The 55-element handcrafted feature vector from
   * `triage/feature-extractor.ts`. Pre-existing — DO NOT mutate.
   *
   * (Length is 55 in practice: 45 web + 10 kernel. The 45-feature
   * naming convention in the paper-track refers to the web subset.)
   */
  vector: number[];
  /** Index-aligned names for `vector`. Useful for debugging. */
  vectorNames: readonly string[];
  /** Which subsystem produced the finding. */
  subsystem: RoutingSubsystem;
  /** Verdict signals from any layers that ran before the routing decision. */
  prior: PriorLayerSignals;
  /** Agent-assigned confidence (0..1), defaulted to 0.5 if absent. */
  agentConfidence: number;
}

const WEB_CATEGORIES = new Set<string>([
  "sql-injection",
  "xss",
  "ssrf",
  "cors",
  "command-injection",
  "code-injection",
  "path-traversal",
  "security-misconfiguration",
  "missing-validation",
  "information-disclosure",
  "unsafe-deserialization",
]);

const KERNEL_CATEGORIES = new Set<string>([
  "heap-overflow",
  "out-of-bounds-read",
  "out-of-bounds-write",
  "use-after-free",
  "stack-buffer-overflow",
  "null-pointer-deref",
  "null-deref",
  "integer-overflow",
  "integer-truncation",
  "race-condition",
  "toctou",
  "type-confusion",
  "double-free",
  "format-string",
  "uninitialized-memory",
]);

const AGENT_SAFETY_CATEGORIES = new Set<string>([
  "prompt-injection",
  "jailbreak",
  "system-prompt-extraction",
  "data-exfiltration",
  "tool-misuse",
  "output-manipulation",
  "encoding-bypass",
  "multi-turn",
]);

const SUPPLY_CHAIN_CATEGORIES = new Set<string>([
  "known-vulnerable-package",
  "supply-chain",
]);

const SOURCE_AUDIT_CATEGORIES = new Set<string>([
  "prototype-pollution",
  "regex-dos",
]);

/**
 * Bucket a finding into a coarse subsystem for routing.
 *
 * Pure function of `finding.category` — does not look at evidence or
 * any other field. Stable across runs for the same input.
 */
export function classifySubsystem(finding: Finding): RoutingSubsystem {
  const c = finding.category as string;
  if (WEB_CATEGORIES.has(c)) return "web";
  if (KERNEL_CATEGORIES.has(c)) return "kernel";
  if (AGENT_SAFETY_CATEGORIES.has(c)) return "agent_safety";
  if (SUPPLY_CHAIN_CATEGORIES.has(c)) return "supply_chain";
  if (SOURCE_AUDIT_CATEGORIES.has(c)) return "source_audit";
  return "other";
}

/**
 * Aggregate `finding.layerVerdicts` into a small signal bundle for the
 * router. Returns conservative zero values if the field is absent (no
 * upstream layers have run yet).
 */
export function summarizePriorVerdicts(verdicts: LayerVerdict[] | undefined): PriorLayerSignals {
  if (!verdicts || verdicts.length === 0) {
    return {
      anyReject: false,
      anyDowngrade: false,
      maxUpstreamConfidence: 0,
      upstreamLayerCount: 0,
    };
  }
  let anyReject = false;
  let anyDowngrade = false;
  let maxConfidence = 0;
  for (const v of verdicts) {
    if (v.verdict === "reject") anyReject = true;
    if (v.verdict === "downgrade") anyDowngrade = true;
    if (typeof v.confidence === "number" && v.confidence > maxConfidence) {
      maxConfidence = v.confidence;
    }
  }
  return {
    anyReject,
    anyDowngrade,
    maxUpstreamConfidence: maxConfidence,
    upstreamLayerCount: verdicts.length,
  };
}

/**
 * Extract routing features for a finding. Wraps the existing 55-dim
 * vector with a small router-specific extension (subsystem + prior
 * verdict summary).
 *
 * O(|description| + |evidence|) — the cost is dominated by the regex
 * scans inside `extractFeatures`. Sub-millisecond in practice on the
 * benchmark corpus.
 */
export function extractRoutingFeatures(finding: Finding): RoutingFeatures {
  return {
    vector: extractFeatures(finding),
    vectorNames: FEATURE_NAMES,
    subsystem: classifySubsystem(finding),
    prior: summarizePriorVerdicts(finding.layerVerdicts),
    agentConfidence: finding.confidence ?? 0.5,
  };
}
