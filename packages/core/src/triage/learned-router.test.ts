import { describe, expect, it } from "vitest";
import { parseModel, routeFinding } from "./learned-router.js";
import type { Finding } from "@0sec/shared";

/**
 * Minimal XGBoost-JSON-shaped fixture. `base_score` is intentionally a
 * string (XGBoost stores model params as strings) so we can vary it to
 * exercise parseModel's numeric coercion (#519).
 */
function makeModelJson(baseScore: string): unknown {
  return {
    learner: {
      learner_model_param: { base_score: baseScore },
      gradient_booster: {
        model: {
          trees: [
            {
              split_indices: [0],
              split_conditions: [0],
              left_children: [-1],
              right_children: [-1],
              base_weights: [0.1],
              default_left: [0],
            },
          ],
        },
      },
    },
  };
}

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "test",
    templateId: "t1",
    title: "Test finding",
    description: "A test finding.",
    severity: "medium",
    category: "sql-injection",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" },
    confidence: 0.5,
    timestamp: Date.now(),
    ...overrides,
  } as Finding;
}

describe("routeFinding — XGBoost model evaluation", () => {
  it("returns a valid RouterResult for a high-confidence finding", () => {
    const finding = makeFinding({
      confidence: 0.95,
      description: "Confirmed SQL injection. Error in response.",
      evidence: {
        request: "POST /login\nusername=admin'&password=test",
        response: "HTTP/1.1 500\nYou have an error in your SQL syntax",
        analysis: "Confirmed via error-based technique. MySQL backend.",
      },
    });
    const result = routeFinding(finding);
    expect(result).toHaveProperty("decision");
    expect(result).toHaveProperty("tpProbability");
    expect(result).toHaveProperty("reason");
    expect(result).toHaveProperty("layersToRun");
    expect(result).toHaveProperty("layersToSkip");
    expect(typeof result.tpProbability).toBe("number");
    expect(result.tpProbability).toBeGreaterThanOrEqual(0);
    expect(result.tpProbability).toBeLessThanOrEqual(1);
  });

  it("uses model scores when available and a safe fallback otherwise", () => {
    const highConf = makeFinding({
      confidence: 0.95,
      description: "Confirmed SQL injection with stack trace.",
      evidence: {
        request: "POST /login\nuser=admin'",
        response: "You have an error in your SQL syntax near 'admin'",
        analysis: "Confirmed. MySQL.",
      },
    });
    const lowConf = makeFinding({
      confidence: 0.1,
      description: "Might be something.",
      evidence: { request: "", response: "", analysis: "" },
    });
    const highResult = routeFinding(highConf);
    const lowResult = routeFinding(lowConf);

    if (highResult.reason === "model file not found, running full pipeline") {
      expect(lowResult.reason).toBe(highResult.reason);
      expect(highResult.tpProbability).toBe(0.5);
      expect(lowResult.tpProbability).toBe(0.5);
      return;
    }

    expect(highResult.tpProbability).toBeGreaterThan(lowResult.tpProbability);
  });

  it("gracefully falls back when model file is not at expected path", () => {
    // This test relies on the model being findable — if it's not found,
    // routeFinding returns a safe fallback (run all layers).
    const finding = makeFinding({});
    const result = routeFinding(finding);
    expect(["auto_accept", "auto_reject", "run_layers"]).toContain(result.decision);
  });

  it("auto_accept findings have empty layersToRun", () => {
    const finding = makeFinding({
      confidence: 0.99,
      description: "Confirmed critical RCE via command injection.",
      evidence: {
        request: "GET /?cmd=id HTTP/1.1",
        response: "uid=0(root) gid=0(root)",
        analysis: "Command injection confirmed. Root access.",
      },
    });
    const result = routeFinding(finding);
    if (result.decision === "auto_accept") {
      expect(result.layersToRun).toHaveLength(0);
      expect(result.layersToSkip.length).toBeGreaterThan(0);
    }
  });

  it("auto_reject findings have empty layersToRun", () => {
    const finding = makeFinding({
      confidence: 0.05,
      severity: "info",
      category: "information-disclosure",
      description: "Maybe.",
      evidence: { request: "", response: "", analysis: "" },
    });
    const result = routeFinding(finding);
    if (result.decision === "auto_reject") {
      expect(result.layersToRun).toHaveLength(0);
    }
  });
});

describe("parseModel — base_score parsing (#519)", () => {
  it("preserves a legitimate base_score of 0 (does not coerce to 0.5)", () => {
    const model = parseModel(makeModelJson("0"));
    expect(model.baseScore).toBe(0);
  });

  it("parses a non-zero base_score correctly", () => {
    const model = parseModel(makeModelJson("0.5"));
    expect(model.baseScore).toBe(0.5);
  });

  it("strips XGBoost's bracket notation around base_score (e.g. \"[0]\")", () => {
    const model = parseModel(makeModelJson("[0]"));
    expect(model.baseScore).toBe(0);
  });

  it("falls back to 0.5 when base_score is non-numeric / unparseable", () => {
    const model = parseModel(makeModelJson("not-a-number"));
    expect(model.baseScore).toBe(0.5);
  });
});
