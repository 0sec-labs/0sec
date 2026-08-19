/**
 * Tests for the routing feature extractor (`features.ts`).
 *
 * The 55-element handcrafted vector is exercised by
 * `feature-extractor.test.ts`; here we only test the routing-specific
 * extensions (subsystem classification, prior verdict summary).
 */

import { describe, it, expect } from "vitest";
import type { Finding, LayerVerdict } from "@pwnkit/shared";
import {
  classifySubsystem,
  extractRoutingFeatures,
  summarizePriorVerdicts,
  FEATURE_NAMES,
} from "./features.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f-1",
    templateId: "t",
    title: "x",
    description: "x",
    severity: "medium",
    category: "xss",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" },
    confidence: 0.5,
    timestamp: Date.now(),
    ...overrides,
  } as Finding;
}

describe("classifySubsystem", () => {
  it("buckets web categories", () => {
    expect(classifySubsystem(makeFinding({ category: "sql-injection" }))).toBe("web");
    expect(classifySubsystem(makeFinding({ category: "xss" }))).toBe("web");
    expect(classifySubsystem(makeFinding({ category: "ssrf" }))).toBe("web");
    expect(classifySubsystem(makeFinding({ category: "cors" }))).toBe("web");
  });

  it("buckets kernel categories", () => {
    expect(classifySubsystem(makeFinding({ category: "use-after-free" }))).toBe("kernel");
    expect(classifySubsystem(makeFinding({ category: "heap-overflow" }))).toBe("kernel");
    expect(classifySubsystem(makeFinding({ category: "race-condition" }))).toBe("kernel");
  });

  it("buckets agent-safety categories", () => {
    expect(classifySubsystem(makeFinding({ category: "prompt-injection" }))).toBe("agent_safety");
    expect(classifySubsystem(makeFinding({ category: "jailbreak" }))).toBe("agent_safety");
  });

  it("buckets supply-chain categories", () => {
    expect(classifySubsystem(makeFinding({ category: "supply-chain" }))).toBe("supply_chain");
    expect(classifySubsystem(makeFinding({ category: "known-vulnerable-package" }))).toBe(
      "supply_chain",
    );
  });

  it("falls back to other for unknown categories", () => {
    expect(classifySubsystem(makeFinding({ category: "other" as any }))).toBe("other");
  });
});

describe("summarizePriorVerdicts", () => {
  it("returns zeros for undefined / empty input", () => {
    expect(summarizePriorVerdicts(undefined)).toEqual({
      anyReject: false,
      anyDowngrade: false,
      maxUpstreamConfidence: 0,
      upstreamLayerCount: 0,
    });
    expect(summarizePriorVerdicts([])).toEqual({
      anyReject: false,
      anyDowngrade: false,
      maxUpstreamConfidence: 0,
      upstreamLayerCount: 0,
    });
  });

  it("aggregates verdict flags across layers", () => {
    const verdicts: LayerVerdict[] = [
      { layer: "holding_it_wrong", verdict: "pass", reason: "", durationMs: 0, costUsd: 0, confidence: 0.5 },
      { layer: "evidence_gate", verdict: "reject", reason: "", durationMs: 0, costUsd: 0, confidence: 0.9 },
      { layer: "oracle", verdict: "downgrade", reason: "", durationMs: 0, costUsd: 0, confidence: 0.3 },
    ];
    const summary = summarizePriorVerdicts(verdicts);
    expect(summary.anyReject).toBe(true);
    expect(summary.anyDowngrade).toBe(true);
    expect(summary.maxUpstreamConfidence).toBe(0.9);
    expect(summary.upstreamLayerCount).toBe(3);
  });
});

describe("extractRoutingFeatures", () => {
  it("returns the 55-element handcrafted vector plus routing extensions", () => {
    const finding = makeFinding({
      category: "sql-injection",
      confidence: 0.8,
      evidence: {
        request: "GET /q?id=1'",
        response: "You have an error in your SQL syntax",
        analysis: "Confirmed SQLi",
      },
    });
    const f = extractRoutingFeatures(finding);
    expect(f.vector).toHaveLength(FEATURE_NAMES.length);
    expect(f.vectorNames).toBe(FEATURE_NAMES);
    expect(f.subsystem).toBe("web");
    expect(f.agentConfidence).toBe(0.8);
    expect(f.prior).toEqual({
      anyReject: false,
      anyDowngrade: false,
      maxUpstreamConfidence: 0,
      upstreamLayerCount: 0,
    });
  });

  it("defaults agentConfidence to 0.5 when finding.confidence is absent", () => {
    const finding = makeFinding({ confidence: undefined as any });
    expect(extractRoutingFeatures(finding).agentConfidence).toBe(0.5);
  });
});
