/**
 * Tests for the v0 rule-based router (pwnkit#113).
 *
 * Coverage:
 *   - Rule 1 (high-confidence SQLi with error-based signal → static set, high confidence)
 *   - Rule 2 (ambiguous logic bug → invoke structured_verify + pov_gate)
 *   - Rule 3 (strong FP-pattern match → empty layer set)
 *   - Default (unmatched → static layer set)
 *   - Router-model swap seam (mock model substitutes cleanly)
 *   - Trace record shape (one record per finding, correct fields)
 */

import { describe, expect, it, beforeEach } from "vitest";
import type { Finding } from "@pwnkit/shared";
import {
  RuleBasedRouter,
  decideLayers,
  setRouterModel,
  resetRouterModel,
  getRouterModel,
  buildTraceRecord,
  type RouterModel,
  type FpPatternMatcher,
  type RoutingDecision,
} from "./router.js";
import {
  DEFAULT_STATIC_LAYER_SET,
  FREE_LAYER_SET,
} from "./layer-registry.js";
import { extractRoutingFeatures } from "./features.js";

// ────────────────────────────────────────────────────────────────────
// Test helpers
// ────────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-test",
    templateId: "tpl-x",
    title: "Test finding",
    description: "A test finding for routing.",
    severity: "medium",
    category: "sql-injection",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" },
    confidence: 0.5,
    timestamp: Date.now(),
    ...overrides,
  } as Finding;
}

// ────────────────────────────────────────────────────────────────────
// Rule 1: high-confidence SQLi with error-based signal
// ────────────────────────────────────────────────────────────────────

describe("RuleBasedRouter — rule 1 (SQLi error-based)", () => {
  it("invokes the static layer set with high confidence for high-confidence SQLi with a SQL error in the response", () => {
    const router = new RuleBasedRouter();
    const finding = makeFinding({
      category: "sql-injection",
      confidence: 0.9,
      evidence: {
        request: "GET /q?id=1%27",
        response: "HTTP/1.1 500\nYou have an error in your SQL syntax near '1''",
        analysis: "Confirmed error-based SQLi (MySQL).",
      },
    });
    const features = extractRoutingFeatures(finding);
    const decision = router.predict(finding, features);

    expect(decision.matchedRule).toBe("rule-1-sqli-error-based");
    expect(decision.confidence).toBe(0.9);
    // Should include the full static set
    for (const layer of DEFAULT_STATIC_LAYER_SET) {
      expect(decision.layers_to_invoke).toContain(layer);
    }
  });

  it("does not fire for SQLi without an error-based signal", () => {
    const router = new RuleBasedRouter();
    const finding = makeFinding({
      category: "sql-injection",
      confidence: 0.9,
      evidence: {
        request: "GET /q?id=1",
        response: "HTTP/1.1 200\n<html><body>ok</body></html>",
        analysis: "Blind SQLi suspected.",
      },
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).not.toBe("rule-1-sqli-error-based");
  });

  it("does not fire for low-confidence SQLi even with an error-based signal", () => {
    const router = new RuleBasedRouter();
    const finding = makeFinding({
      category: "sql-injection",
      confidence: 0.3,
      evidence: {
        request: "GET /q?id=1",
        response: "You have an error in your SQL syntax",
        analysis: "Maybe.",
      },
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).not.toBe("rule-1-sqli-error-based");
  });
});

// ────────────────────────────────────────────────────────────────────
// Rule 2: ambiguous logic bug
// ────────────────────────────────────────────────────────────────────

describe("RuleBasedRouter — rule 2 (ambiguous logic bug)", () => {
  it("invokes structured_verify + pov_gate for ambiguous logic-bug findings", () => {
    const router = new RuleBasedRouter();
    const finding = makeFinding({
      category: "missing-validation",
      confidence: 0.4,
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).toBe("rule-2-ambiguous-logic-bug");
    expect(decision.layers_to_invoke).toContain("structured_verify");
    expect(decision.layers_to_invoke).toContain("pov_gate");
    // Free layers should also be present
    for (const layer of FREE_LAYER_SET) {
      expect(decision.layers_to_invoke).toContain(layer);
    }
  });

  it("does not fire for confidence outside the ambiguous band", () => {
    const router = new RuleBasedRouter();
    const high = makeFinding({ category: "missing-validation", confidence: 0.9 });
    const low = makeFinding({ category: "missing-validation", confidence: 0.1 });
    expect(router.predict(high, extractRoutingFeatures(high)).matchedRule).not.toBe(
      "rule-2-ambiguous-logic-bug",
    );
    expect(router.predict(low, extractRoutingFeatures(low)).matchedRule).not.toBe(
      "rule-2-ambiguous-logic-bug",
    );
  });

  it("does not fire for non-logic-bug categories", () => {
    const router = new RuleBasedRouter();
    const finding = makeFinding({ category: "sql-injection", confidence: 0.4 });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).not.toBe("rule-2-ambiguous-logic-bug");
  });
});

// ────────────────────────────────────────────────────────────────────
// Rule 3: FP-pattern match (auto-reject)
// ────────────────────────────────────────────────────────────────────

describe("RuleBasedRouter — rule 3 (FP-pattern auto-reject)", () => {
  function makeMatcher(score: number, category: string): FpPatternMatcher {
    return {
      bestMatch: () => ({ score, category }),
    };
  }

  it("returns empty layer set when a strong FP-pattern match is present", () => {
    const matcher = makeMatcher(0.9, "information-disclosure");
    const router = new RuleBasedRouter(matcher);
    const finding = makeFinding({
      category: "information-disclosure",
      confidence: 0.3,
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).toBe("rule-3-fp-pattern-auto-reject");
    expect(decision.layers_to_invoke).toHaveLength(0);
  });

  it("does NOT auto-reject when the agent confidence is high", () => {
    const matcher = makeMatcher(0.95, "sql-injection");
    const router = new RuleBasedRouter(matcher);
    const finding = makeFinding({
      category: "sql-injection",
      confidence: 0.9,
      evidence: { request: "", response: "ok", analysis: "" },
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).not.toBe("rule-3-fp-pattern-auto-reject");
  });

  it("does NOT auto-reject when the match score is weak", () => {
    const matcher = makeMatcher(0.5, "information-disclosure");
    const router = new RuleBasedRouter(matcher);
    const finding = makeFinding({
      category: "information-disclosure",
      confidence: 0.3,
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).not.toBe("rule-3-fp-pattern-auto-reject");
  });

  it("does NOT auto-reject when the matched category differs", () => {
    const matcher = makeMatcher(0.95, "xss");
    const router = new RuleBasedRouter(matcher);
    const finding = makeFinding({
      category: "information-disclosure",
      confidence: 0.3,
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).not.toBe("rule-3-fp-pattern-auto-reject");
  });

  it("does nothing when no matcher is provided (rule 3 unreachable)", () => {
    const router = new RuleBasedRouter(undefined);
    const finding = makeFinding({
      category: "information-disclosure",
      confidence: 0.3,
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).not.toBe("rule-3-fp-pattern-auto-reject");
  });
});

// ────────────────────────────────────────────────────────────────────
// Default
// ────────────────────────────────────────────────────────────────────

describe("RuleBasedRouter — default", () => {
  it("returns the static layer set when no rule matches", () => {
    const router = new RuleBasedRouter();
    const finding = makeFinding({
      category: "xss",
      confidence: 0.7,
      evidence: { request: "", response: "ok", analysis: "" },
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).toBe("default-static-set");
    expect(decision.layers_to_invoke).toEqual([...DEFAULT_STATIC_LAYER_SET]);
  });
});

// ────────────────────────────────────────────────────────────────────
// decideLayers + model swap seam
// ────────────────────────────────────────────────────────────────────

describe("decideLayers — module-level dispatch", () => {
  beforeEach(() => {
    resetRouterModel();
  });

  it("uses the rule-based router by default", () => {
    const finding = makeFinding({
      category: "sql-injection",
      confidence: 0.9,
      evidence: {
        request: "x",
        response: "You have an error in your SQL syntax",
        analysis: "",
      },
    });
    const decision = decideLayers(finding);
    expect(decision.matchedRule).toBe("rule-1-sqli-error-based");
    expect(getRouterModel().id).toBe("rule-based-v0");
  });

  it("honors a swapped-in mock RouterModel without touching the call site", () => {
    const mockDecision: RoutingDecision = {
      layers_to_invoke: ["oracle"],
      confidence: 0.99,
      reasoning: "mock router said so",
      matchedRule: "mock-rule",
    };
    const mock: RouterModel = {
      id: "mock-router-v0",
      predict: () => mockDecision,
    };
    setRouterModel(mock);
    const finding = makeFinding({});
    const decision = decideLayers(finding);
    expect(decision).toBe(mockDecision);
    expect(getRouterModel().id).toBe("mock-router-v0");
  });

  it("computes features on-the-fly when not passed in", () => {
    const finding = makeFinding({ category: "xss", confidence: 0.7 });
    const decision = decideLayers(finding);
    expect(decision.layers_to_invoke.length).toBeGreaterThan(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// buildTraceRecord shape
// ────────────────────────────────────────────────────────────────────

describe("buildTraceRecord", () => {
  it("returns a record with all required fields populated", () => {
    const finding = makeFinding({
      id: "f-trace-1",
      category: "xss",
      confidence: 0.65,
    });
    const features = extractRoutingFeatures(finding);
    const decision: RoutingDecision = {
      layers_to_invoke: ["oracle", "pov_gate"],
      confidence: 0.7,
      matchedRule: "default-static-set",
    };
    const record = buildTraceRecord({
      scanId: "scan-abc",
      finding,
      features,
      decision,
    });
    expect(record.scan_id).toBe("scan-abc");
    expect(record.finding_id).toBe("f-trace-1");
    expect(record.category).toBe("xss");
    expect(record.subsystem).toBe("web");
    expect(record.features).toEqual(features.vector);
    expect(record.decided_layers).toEqual(["oracle", "pov_gate"]);
    expect(record.matched_rule).toBe("default-static-set");
    expect(record.router_confidence).toBe(0.7);
    expect(record.actual_verdict_per_layer).toBeTypeOf("object");
    expect("oracle" in record.actual_verdict_per_layer).toBe(true);
    expect("pov_gate" in record.actual_verdict_per_layer).toBe(true);
    expect(record.ground_truth).toBeUndefined();
    expect(typeof record.decided_at).toBe("number");
  });

  it("captures layer verdicts even for layers the router said to skip", () => {
    const finding = makeFinding({
      id: "f-trace-2",
      layerVerdicts: [
        {
          layer: "holding_it_wrong",
          verdict: "pass",
          reason: "no match",
          durationMs: 1,
          costUsd: 0,
        },
      ],
    });
    const features = extractRoutingFeatures(finding);
    const decision: RoutingDecision = {
      layers_to_invoke: ["oracle"],
      confidence: 0.5,
      matchedRule: "default-static-set",
    };
    const record = buildTraceRecord({
      scanId: "scan-xyz",
      finding,
      features,
      decision,
    });
    // `oracle` was decided but no verdict yet → null slot
    expect(record.actual_verdict_per_layer.oracle).toBeNull();
    // `holding_it_wrong` ran upstream → captured even though router didn't decide it
    expect(record.actual_verdict_per_layer.holding_it_wrong).toMatchObject({
      verdict: "pass",
    });
  });
});
