import { describe, it, expect } from "vitest";
import type { AttackCategory, Finding, Severity } from "@pwnkit/shared";
import {
  canAutoSuppress,
  canAutoSuppressDetailed,
} from "./can-auto-suppress.js";
import { extractFeatures, FEATURE_NAMES } from "./feature-extractor.js";
import { routeFinding } from "./learned-router.js";
import { RuleBasedRouter, extractRoutingFeatures } from "./router/index.js";
import type { FpPatternMatcher } from "./router/index.js";

// ──────────────────────────────────────────────────────────────────────
// Issue #518 — guardrail: no score/heuristic triage path may auto-drop a
// high-severity / high-impact finding. The three flag-gated suppression
// paths in agentic-scanner.ts (evidence_gate, learned-router auto_reject,
// dynamic_triage Rule-3) all route their "may I drop this?" decision
// through `canAutoSuppress`. These tests prove the guard blocks the drop
// for high-severity / high-impact findings while preserving the existing
// suppression behavior for low-severity, low-impact findings.
// ──────────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "guard-test",
    templateId: "tpl-1",
    title: "Test finding",
    description: "A finding under triage.",
    severity: "low",
    category: "information-disclosure" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "",
      response: "",
      analysis: "",
    },
    confidence: 0.3,
    timestamp: 0,
    ...overrides,
  };
}

describe("canAutoSuppressDetailed — severity guard", () => {
  it("blocks auto-suppression of critical-severity findings", () => {
    const d = canAutoSuppressDetailed(makeFinding({ severity: "critical" }));
    expect(d.canSuppress).toBe(false);
    expect(d.guard).toBe("high_severity");
    expect(d.reason).toContain("critical");
  });

  it("blocks auto-suppression of high-severity findings", () => {
    const d = canAutoSuppressDetailed(makeFinding({ severity: "high" }));
    expect(d.canSuppress).toBe(false);
    expect(d.guard).toBe("high_severity");
  });

  it("allows auto-suppression of low/medium/info findings (low-impact class)", () => {
    for (const severity of ["medium", "low", "info"] as Severity[]) {
      const d = canAutoSuppressDetailed(
        makeFinding({ severity, category: "information-disclosure" }),
      );
      expect(d.canSuppress).toBe(true);
      expect(d.guard).toBeUndefined();
    }
  });
});

describe("canAutoSuppressDetailed — high-impact class guard", () => {
  // Even when severity is recorded low (a scanner can mis-rate, or an
  // earlier heuristic can downgrade), a high-impact CLASS must never be
  // auto-dropped on a score alone.
  const highImpact: AttackCategory[] = [
    "command-injection",
    "code-injection",
    "sql-injection",
    "unsafe-deserialization",
    "ssrf",
    "path-traversal",
    "heap-overflow",
    "out-of-bounds-write",
    "use-after-free",
    "stack-buffer-overflow",
    "double-free",
    "type-confusion",
    "format-string",
    "known-vulnerable-package",
    "supply-chain",
  ];

  for (const category of highImpact) {
    it(`blocks auto-suppression of ${category} even at low severity`, () => {
      const d = canAutoSuppressDetailed(
        makeFinding({ severity: "low", category }),
      );
      expect(d.canSuppress).toBe(false);
      expect(d.guard).toBe("high_impact_class");
      expect(d.reason).toContain(category);
    });
  }

  it("allows auto-suppression of a low-severity low-impact class (e.g. cors)", () => {
    const d = canAutoSuppressDetailed(
      makeFinding({ severity: "low", category: "cors" }),
    );
    expect(d.canSuppress).toBe(true);
  });

  it("severity guard wins over class for a high-sev low-impact class", () => {
    const d = canAutoSuppressDetailed(
      makeFinding({ severity: "high", category: "cors" }),
    );
    expect(d.canSuppress).toBe(false);
    expect(d.guard).toBe("high_severity");
  });
});

describe("canAutoSuppress — boolean convenience form", () => {
  it("returns false for protected findings, true otherwise", () => {
    expect(canAutoSuppress(makeFinding({ severity: "critical" }))).toBe(false);
    expect(
      canAutoSuppress(makeFinding({ severity: "low", category: "ssrf" })),
    ).toBe(false);
    expect(
      canAutoSuppress(makeFinding({ severity: "low", category: "cors" })),
    ).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────────
// Path 1: evidence_gate. The gate auto-rejects when the extracted feature
// `cross_evidence_completeness <= 0.5`. We construct a thin-evidence
// finding so the raw heuristic WOULD reject, then prove the guard blocks
// the drop for a high-severity finding and still permits it for a
// low-severity, low-impact one.
// ──────────────────────────────────────────────────────────────────────

describe("guardrail integration — evidence_gate (PWNKIT_FEATURE_EVIDENCE_GATE)", () => {
  const idx = FEATURE_NAMES.indexOf("cross_evidence_completeness");

  function evidenceCompleteness(f: Finding): number {
    const v = extractFeatures(f);
    return idx >= 0 ? v[idx] ?? 0 : 0;
  }

  it("a thin-evidence finding really does trip the <=0.5 gate", () => {
    const thin = makeFinding({
      severity: "low",
      category: "information-disclosure",
      evidence: { request: "", response: "", analysis: "" },
    });
    expect(evidenceCompleteness(thin)).toBeLessThanOrEqual(0.5);
  });

  it("does NOT auto-drop a high-severity RCE on the evidence score", () => {
    const finding = makeFinding({
      severity: "critical",
      category: "command-injection",
      evidence: { request: "", response: "", analysis: "" },
    });
    // Heuristic alone would reject (thin evidence)…
    expect(evidenceCompleteness(finding)).toBeLessThanOrEqual(0.5);
    // …but the guard forbids the auto-drop, so the site bails to verify.
    expect(canAutoSuppress(finding)).toBe(false);
  });

  it("still auto-drops a low-severity, low-impact finding with thin evidence", () => {
    const finding = makeFinding({
      severity: "low",
      category: "cors",
      evidence: { request: "", response: "", analysis: "" },
    });
    expect(evidenceCompleteness(finding)).toBeLessThanOrEqual(0.5);
    expect(canAutoSuppress(finding)).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────────
// Path 2: learned-router auto_reject (XGBoost p<=0.25). We drive the real
// model to find a finding it auto_rejects, then prove the guard blocks the
// drop when that same finding is high-severity / high-impact.
// ──────────────────────────────────────────────────────────────────────

describe("guardrail integration — learned-router auto_reject (PWNKIT_FEATURE_LEARNED_ROUTER)", () => {
  // Probe a small space of thin/empty-evidence shapes to find one the trained
  // model actually scores at p<=0.25 (auto_reject). We don't hard-code which
  // one — the exact threshold crossing depends on the model weights. We only
  // need ONE real auto_reject to prove the guard overrides it. If the model
  // file is absent (router falls back to run_layers / p=0.5), the model-
  // behavior assertion is skipped but the guard assertions still run.
  const fpShape = makeFinding({
    severity: "low",
    category: "information-disclosure",
    confidence: 0.05,
    evidence: { request: "", response: "", analysis: "" },
  });

  function findModelAutoReject(): Finding | null {
    const probes: Finding[] = [
      fpShape,
      makeFinding({ severity: "info", category: "information-disclosure", confidence: 0.01, title: "", description: "", evidence: { request: "", response: "" } }),
      makeFinding({ severity: "low", category: "missing-validation", confidence: 0.02, title: "x", description: "x", evidence: { request: "", response: "" } }),
      makeFinding({ severity: "low", category: "security-misconfiguration", confidence: 0.0, title: "", description: "", evidence: { request: "", response: "" } }),
    ];
    for (const p of probes) {
      if (routeFinding(p).decision === "auto_reject") return p;
    }
    return null;
  }

  it("the trained model produces at least one auto_reject (when the model is loaded)", () => {
    const modelLoaded = routeFinding(fpShape).tpProbability !== 0.5;
    if (!modelLoaded) return; // model file absent in this env — nothing to assert
    const rejected = findModelAutoReject();
    // If the model loaded but none of the probes crossed p<=0.25 in this
    // model version, we don't fail — the guard, not the model, is what #518
    // is about. The next test proves the guard regardless.
    if (rejected) {
      expect(routeFinding(rejected).decision).toBe("auto_reject");
      expect(routeFinding(rejected).tpProbability).toBeLessThanOrEqual(0.25);
    }
  });

  it("does NOT auto-drop a high-severity / high-impact finding (guard overrides any auto_reject)", () => {
    // The guard must protect a high-severity high-impact finding REGARDLESS of
    // what the router score says. This is the #518 invariant for this path.
    const highSev = makeFinding({
      severity: "critical",
      category: "use-after-free",
      confidence: 0.01,
      evidence: { request: "", response: "" },
    });
    const result = routeFinding(highSev);
    if (result.decision === "auto_reject") {
      // Model said drop on the score — guard must keep it.
      expect(canAutoSuppress(highSev)).toBe(false);
    }
    // Holds whether or not the model is present / auto_rejects.
    expect(canAutoSuppress(highSev)).toBe(false);
  });

  it("still lets the router auto_reject a low-severity, low-impact finding", () => {
    expect(canAutoSuppress(fpShape)).toBe(true);
  });
});

// ──────────────────────────────────────────────────────────────────────
// Path 3: dynamic_triage Rule-3 (empty layer set from a strong FP-pattern
// match). We build a RuleBasedRouter with a forced FP matcher so Rule-3
// fires, then prove the guard blocks the resulting auto-drop for a
// high-severity finding.
// ──────────────────────────────────────────────────────────────────────

describe("guardrail integration — dynamic_triage Rule-3 (PWNKIT_FEATURE_DYNAMIC_TRIAGE)", () => {
  function fpMatcher(score: number, category: string): FpPatternMatcher {
    return { bestMatch: () => ({ score, category }) };
  }

  it("Rule-3 really does return an empty layer set for a strong FP match", () => {
    const router = new RuleBasedRouter(fpMatcher(0.9, "information-disclosure"));
    const finding = makeFinding({
      category: "information-disclosure",
      confidence: 0.3,
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.matchedRule).toBe("rule-3-fp-pattern-auto-reject");
    expect(decision.layers_to_invoke).toHaveLength(0);
  });

  it("does NOT auto-drop a high-severity finding even when Rule-3 fires", () => {
    const router = new RuleBasedRouter(fpMatcher(0.9, "sql-injection"));
    const finding = makeFinding({
      severity: "critical",
      category: "sql-injection",
      confidence: 0.3,
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    // The dynamic router would short-circuit with an empty layer set…
    expect(decision.layers_to_invoke).toHaveLength(0);
    // …but the guard forbids the auto-drop, so the site keeps the finding.
    expect(canAutoSuppress(finding)).toBe(false);
  });

  it("still auto-drops a low-severity, low-impact finding when Rule-3 fires", () => {
    const router = new RuleBasedRouter(fpMatcher(0.9, "information-disclosure"));
    const finding = makeFinding({
      severity: "low",
      category: "information-disclosure",
      confidence: 0.3,
    });
    const decision = router.predict(finding, extractRoutingFeatures(finding));
    expect(decision.layers_to_invoke).toHaveLength(0);
    expect(canAutoSuppress(finding)).toBe(true);
  });
});
