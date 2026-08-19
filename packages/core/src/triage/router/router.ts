/**
 * Dynamic Triage Router — v0 rule-based, with a seam for a learned
 * classifier landing in a follow-up PR (0sec#113 phase 2).
 *
 * The router decides **per finding** which subset of the triage
 * layers to invoke. v0 ships explicit decision rules encoded from the
 * 0sec#72 (2026-04-11) per-profile ablation comment; a later PR will
 * swap in a learned classifier (XGBoost or VulnBERT-style hybrid head)
 * trained on the per-layer telemetry shipped in 0sec#112 and the
 * triage dataset described in 0sec#67.
 *
 * The dispatch site (`agentic-scanner.ts`) treats the router as a
 * black-box `RouterModel`. To swap in a learned model later, ship a
 * new class implementing `RouterModel` and pass it to
 * `setRouterModel()` — no changes needed at the call sites.
 *
 * NOTE on rule (3) — "auto-reject on FP-pattern match":
 *   The token-overlap heuristic that ships in `triage/memories.ts` is
 *   intentionally coarse. A single fuzzy match dropping a real finding
 *   is the regression mode we worry about. v0 only triggers the auto-
 *   reject branch when the match score is **strong** (>= 0.85) AND the
 *   category matches exactly AND the agent's confidence is low (< 0.6).
 *   The threshold is conservative on purpose; promote it down only after
 *   measured A/B testing on the npm-bench slice.
 *
 * See 0sec#113 design doc, 0sec#72 ablation, 0sec#67 paper plan.
 */

import type { Finding, LayerVerdict } from "@0sec/shared";
import {
  DEFAULT_STATIC_LAYER_SET,
  FREE_LAYER_SET,
  type LayerId,
} from "./layer-registry.js";
import {
  extractRoutingFeatures,
  type RoutingFeatures,
} from "./features.js";

// ────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────

export interface RoutingDecision {
  /** The subset of triage layers to actually invoke for this finding. */
  layers_to_invoke: LayerId[];
  /** 0..1 confidence in the routing decision (NOT in the finding itself). */
  confidence: number;
  /**
   * Human-readable explanation. Stable across runs for the same input;
   * used by the journal writer for offline training data.
   */
  reasoning?: string;
  /**
   * Identifier of the rule (or model) that produced this decision.
   * Lets the offline trainer slice the routing trace by rule.
   */
  matchedRule?: string;
}

/**
 * Pluggable router interface. v0 ships `RuleBasedRouter`; a learned
 * model lands as e.g. `XGBoostRouter` in a follow-up PR without
 * touching the dispatch site.
 */
export interface RouterModel {
  /**
   * Stable model identifier, recorded in the routing trace so the
   * offline trainer can correlate features → outputs by model version.
   */
  readonly id: string;
  /**
   * Decide which layers to invoke for this finding. The router may
   * inspect the full finding (not just the features) — the features
   * argument is provided as a cache so multiple routers can share the
   * vector extraction.
   */
  predict(finding: Finding, features: RoutingFeatures): RoutingDecision;
}

/**
 * A simple fuzzy-match interface for the triage memories layer. We
 * keep the interface minimal so tests can mock it without pulling in
 * the SQLite-backed `MemoryStore`.
 */
export interface FpPatternMatcher {
  /**
   * Returns the best-matching FP pattern + its score in [0, 1] (or null
   * if no pattern matches above the matcher's internal floor).
   */
  bestMatch(finding: Finding): { score: number; category: string } | null;
}

// ────────────────────────────────────────────────────────────────────
// Rule-based router (v0)
// ────────────────────────────────────────────────────────────────────

/**
 * Threshold for rule (1): high-confidence SQLi with error-based signal.
 * Both the agent confidence and the SQL-error regex must hit.
 */
const RULE_SQLI_HIGH_CONFIDENCE = 0.8;

/**
 * Threshold band for rule (2): ambiguous logic bug. Confidence in this
 * band gets the structured-verify + pov-gate combo, which the ablation
 * showed is the only combo that moves logic-bug findings.
 */
const RULE_LOGIC_AMBIGUOUS_LOW = 0.3;
const RULE_LOGIC_AMBIGUOUS_HIGH = 0.55;

/**
 * Threshold for rule (3): FP-pattern match. Conservative on purpose —
 * the token-overlap heuristic in `memories.ts` is coarse and a single
 * fuzzy match dropping a real finding is the regression mode.
 */
const RULE_FP_PATTERN_STRONG = 0.85;
const RULE_FP_PATTERN_AGENT_CONFIDENCE_CEILING = 0.6;

/**
 * Categories the v0 router treats as "logic bug" candidates for rule 2.
 * These are the categories where the per-profile ablation showed the
 * structured-verify + pov-gate combo carrying its weight.
 */
const LOGIC_BUG_CATEGORIES = new Set<string>([
  "missing-validation",
  "security-misconfiguration",
  "information-disclosure",
  "cors",
  "tool-misuse",
  "output-manipulation",
]);

/**
 * Heuristic: does the finding's response contain a SQL error string the
 * oracle would treat as deterministic evidence? Mirrors the regex bank
 * in `feature-extractor.ts` so the router and the oracle agree on what
 * "error-based SQLi" looks like.
 *
 * Implemented inline to avoid coupling the router to the (much larger)
 * feature-extractor regex banks — the router's rule fires on the *very
 * narrow* error-based signal, not on every potential SQLi marker.
 */
const SQL_ERROR_NEEDLES: readonly RegExp[] = [
  /you have an error in your sql syntax/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i,
  /ora-\d{5}/i, // Oracle
  /sqlite_error/i,
  /sqlite3\.(operational|programming)error/i,
  /pg::error/i,
  /postgresql.*error/i,
  /syntax error at or near/i,
  /microsoft.*odbc.*sql server/i,
];

function hasErrorBasedSqlSignal(finding: Finding): boolean {
  const response = finding.evidence?.response ?? "";
  if (!response) return false;
  return SQL_ERROR_NEEDLES.some((re) => re.test(response));
}

/**
 * The v0 rule-based router. Encodes the four rules from the 0sec#113
 * issue body, in priority order:
 *
 *   1. High-confidence SQLi with error-based signal → invoke the
 *      static layer set with high routing confidence.
 *
 *   2. Ambiguous logic bug (confidence in [0.3, 0.55]) → invoke
 *      `structured_verify` + `pov_gate`.
 *
 *   3. Finding matches a known FP pattern in `triageMemories` with
 *      a STRONG score (>= 0.85, exact category match, low agent
 *      confidence) → auto-reject (empty layer set).
 *
 *   4. Default → existing static layer set.
 */
export class RuleBasedRouter implements RouterModel {
  public readonly id = "rule-based-v0";

  constructor(private readonly fpMatcher?: FpPatternMatcher) {}

  predict(finding: Finding, features: RoutingFeatures): RoutingDecision {
    const conf = features.agentConfidence;

    // ── Rule 1: high-confidence SQLi with error-based signal ──
    if (
      finding.category === "sql-injection" &&
      conf >= RULE_SQLI_HIGH_CONFIDENCE &&
      hasErrorBasedSqlSignal(finding)
    ) {
      return {
        layers_to_invoke: [...DEFAULT_STATIC_LAYER_SET],
        confidence: 0.9,
        reasoning:
          "rule-1: high-confidence SQLi (conf>=0.8) with error-based signal — " +
          "invoke the static layer set with high routing confidence",
        matchedRule: "rule-1-sqli-error-based",
      };
    }

    // ── Rule 3 (checked before rule 2 so a strong FP match wins over the
    //          ambiguous-logic-bug heuristic): triage-memories match ──
    if (this.fpMatcher) {
      const match = this.fpMatcher.bestMatch(finding);
      if (
        match !== null &&
        match.score >= RULE_FP_PATTERN_STRONG &&
        match.category === finding.category &&
        conf < RULE_FP_PATTERN_AGENT_CONFIDENCE_CEILING
      ) {
        return {
          layers_to_invoke: [],
          confidence: match.score,
          reasoning:
            `rule-3: triageMemories FP-pattern match score=${match.score.toFixed(2)} ` +
            `(category=${match.category}, agent conf=${conf.toFixed(2)}) — auto-reject`,
          matchedRule: "rule-3-fp-pattern-auto-reject",
        };
      }
    }

    // ── Rule 2: ambiguous logic bug ──
    if (
      LOGIC_BUG_CATEGORIES.has(finding.category as string) &&
      conf >= RULE_LOGIC_AMBIGUOUS_LOW &&
      conf <= RULE_LOGIC_AMBIGUOUS_HIGH
    ) {
      // Run the free layers (free signal is always worth it) plus the two
      // layers the ablation showed carry their weight on logic bugs.
      const layers = Array.from(
        new Set<LayerId>([...FREE_LAYER_SET, "structured_verify", "pov_gate"]),
      );
      return {
        layers_to_invoke: layers,
        confidence: 0.6,
        reasoning:
          `rule-2: ambiguous logic bug (category=${finding.category}, ` +
          `conf=${conf.toFixed(2)} in [${RULE_LOGIC_AMBIGUOUS_LOW}, ${RULE_LOGIC_AMBIGUOUS_HIGH}]) — ` +
          `invoke structured_verify + pov_gate on top of free layers`,
        matchedRule: "rule-2-ambiguous-logic-bug",
      };
    }

    // ── Default ──
    return {
      layers_to_invoke: [...DEFAULT_STATIC_LAYER_SET],
      confidence: 0.5,
      reasoning: "default: no rule matched — invoke the static layer set",
      matchedRule: "default-static-set",
    };
  }
}

// ────────────────────────────────────────────────────────────────────
// Module-level router slot (lets follow-up PRs swap in a learned model
// without touching the dispatch site in agentic-scanner.ts)
// ────────────────────────────────────────────────────────────────────

let activeModel: RouterModel = new RuleBasedRouter();

export function setRouterModel(model: RouterModel): void {
  activeModel = model;
}

export function getRouterModel(): RouterModel {
  return activeModel;
}

/**
 * Resets the active router model to the v0 rule-based default. Used by
 * tests that swapped in a mock model.
 */
export function resetRouterModel(): void {
  activeModel = new RuleBasedRouter();
}

/**
 * Decide which triage layers to invoke for a finding. The primary entry
 * point for the dispatch site in `agentic-scanner.ts`.
 *
 * If `features` is omitted the router computes them from the finding.
 * Pass them in to share a cached vector across multiple routing
 * decisions or to support upcoming layered router stacks.
 */
export function decideLayers(
  finding: Finding,
  features?: RoutingFeatures,
): RoutingDecision {
  const f = features ?? extractRoutingFeatures(finding);
  return activeModel.predict(finding, f);
}

// ────────────────────────────────────────────────────────────────────
// Routing-trace records (training data for the eventual learned router)
// ────────────────────────────────────────────────────────────────────

/**
 * One row of the routing dataset. Emitted to `routing-trace.jsonl` under
 * the scan's journal sidecar dir at the end of each scan. The learned
 * router (phase 2 of 0sec#113) trains on the (features, decided_layers,
 * actual_verdict_per_layer, ground_truth) tuple.
 *
 * Schema is intentionally close to `LayerVerdict[]` so the offline
 * trainer can reuse the same JSONL reader that consumes the
 * triage-data-collector output.
 */
export interface RoutingTraceRecord {
  /** Globally-unique scan id; copied from the journal/database. */
  scan_id: string;
  /** Finding id within the scan. */
  finding_id: string;
  /** Finding category (denormalized for easy filtering). */
  category: string;
  /** Subsystem bucket from `classifySubsystem`. */
  subsystem: string;
  /** The 55-element feature vector. Same shape as `extractFeatures()`. */
  features: number[];
  /** Index-aligned names for `features`. */
  feature_names: readonly string[];
  /** Layers the router said to invoke. */
  decided_layers: LayerId[];
  /** Rule (or model id) that produced the decision. */
  matched_rule?: string;
  /** Confidence of the routing decision. */
  router_confidence: number;
  /**
   * Per-layer verdicts the layers actually returned. Populated once the
   * layers have run; null if the layer was skipped by the router.
   */
  actual_verdict_per_layer: Record<string, LayerVerdict | null>;
  /**
   * Final finding-level ground truth, if known. From flag extraction
   * (XBOW/Cybench), package verdict (npm-bench), or human triage. Left
   * undefined for in-flight scans; backfilled by the offline collector.
   */
  ground_truth?: "true_positive" | "false_positive";
  /** Wall-clock epoch millis at decision time. */
  decided_at: number;
}

/**
 * Build a routing-trace record for a single finding. Pure function —
 * does no I/O. The caller writes the result to disk.
 */
export function buildTraceRecord(args: {
  scanId: string;
  finding: Finding;
  features: RoutingFeatures;
  decision: RoutingDecision;
  groundTruth?: "true_positive" | "false_positive";
}): RoutingTraceRecord {
  const { scanId, finding, features, decision, groundTruth } = args;

  // Bucket actual layer verdicts by layer id; the router-decided layer
  // set tells us which slots should be present.
  const verdictByLayer: Record<string, LayerVerdict | null> = {};
  for (const layer of decision.layers_to_invoke) {
    const v = (finding.layerVerdicts ?? []).find((lv) => lv.layer === layer);
    verdictByLayer[layer] = v ?? null;
  }
  // Also record any verdict for layers the router said to skip — useful
  // for the offline ablation that asks "what would have happened if the
  // router had invoked this layer?"
  for (const lv of finding.layerVerdicts ?? []) {
    if (!(lv.layer in verdictByLayer)) {
      verdictByLayer[lv.layer] = lv;
    }
  }

  return {
    scan_id: scanId,
    finding_id: finding.id,
    category: finding.category as string,
    subsystem: features.subsystem,
    features: features.vector,
    feature_names: features.vectorNames,
    decided_layers: decision.layers_to_invoke,
    matched_rule: decision.matchedRule,
    router_confidence: decision.confidence,
    actual_verdict_per_layer: verdictByLayer,
    ground_truth: groundTruth,
    decided_at: Date.now(),
  };
}
