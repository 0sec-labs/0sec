/**
 * Tests for `routing-trace.jsonl` emission.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "@0sec/shared";
import {
  emitRoutingTrace,
  appendRoutingTraceRecord,
} from "./trace.js";
import type { RoutingDecision } from "./router.js";

function makeFinding(id: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id,
    templateId: "tpl-1",
    title: `Finding ${id}`,
    description: "Test description",
    severity: "medium",
    category: "xss",
    status: "discovered",
    evidence: { request: "", response: "", analysis: "" },
    confidence: 0.5,
    timestamp: Date.now(),
    ...overrides,
  } as Finding;
}

function makeDecision(layers: string[]): RoutingDecision {
  return {
    layers_to_invoke: layers as any,
    confidence: 0.7,
    matchedRule: "test-rule",
  };
}

describe("emitRoutingTrace", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "routing-trace-test-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("writes one JSONL record per finding", () => {
    const decisions = [
      { finding: makeFinding("f1"), decision: makeDecision(["oracle"]) },
      { finding: makeFinding("f2"), decision: makeDecision(["pov_gate", "oracle"]) },
      { finding: makeFinding("f3"), decision: makeDecision([]) },
    ];
    const path = emitRoutingTrace("scan-1", decisions, { outputDir: tmpDir });
    const lines = readFileSync(path, "utf8").trim().split("\n");
    expect(lines).toHaveLength(3);

    const records = lines.map((l) => JSON.parse(l));
    expect(records[0].finding_id).toBe("f1");
    expect(records[0].decided_layers).toEqual(["oracle"]);
    expect(records[1].finding_id).toBe("f2");
    expect(records[1].decided_layers).toEqual(["pov_gate", "oracle"]);
    expect(records[2].finding_id).toBe("f3");
    expect(records[2].decided_layers).toEqual([]);
    // Required fields present on every record
    for (const r of records) {
      expect(r.scan_id).toBe("scan-1");
      expect(Array.isArray(r.features)).toBe(true);
      expect(r.features.length).toBeGreaterThan(0);
      expect(typeof r.router_confidence).toBe("number");
      expect(typeof r.decided_at).toBe("number");
      expect(typeof r.subsystem).toBe("string");
      expect(r.matched_rule).toBe("test-rule");
    }
  });

  it("writes an empty file when given zero decisions", () => {
    const path = emitRoutingTrace("scan-empty", [], { outputDir: tmpDir });
    expect(existsSync(path)).toBe(true);
    expect(readFileSync(path, "utf8")).toBe("");
  });

  it("uses the custom filename when provided", () => {
    const path = emitRoutingTrace(
      "scan-custom",
      [{ finding: makeFinding("fa"), decision: makeDecision(["oracle"]) }],
      { outputDir: tmpDir, fileName: "custom-trace.jsonl" },
    );
    expect(path.endsWith("custom-trace.jsonl")).toBe(true);
    expect(existsSync(path)).toBe(true);
  });
});

describe("appendRoutingTraceRecord", () => {
  let tmpDir: string;
  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "routing-trace-append-"));
  });
  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("appends one record per call and creates the file on first call", () => {
    const path = appendRoutingTraceRecord(
      "scan-1",
      { finding: makeFinding("f1"), decision: makeDecision(["oracle"]) },
      { outputDir: tmpDir },
    );
    expect(existsSync(path)).toBe(true);
    appendRoutingTraceRecord(
      "scan-1",
      { finding: makeFinding("f2"), decision: makeDecision(["pov_gate"]) },
      { outputDir: tmpDir },
    );
    appendRoutingTraceRecord(
      "scan-1",
      { finding: makeFinding("f3"), decision: makeDecision([]) },
      { outputDir: tmpDir },
    );
    const lines = readFileSync(path, "utf8").trim().split("\n");
    expect(lines).toHaveLength(3);
    const records = lines.map((l) => JSON.parse(l));
    expect(records.map((r) => r.finding_id)).toEqual(["f1", "f2", "f3"]);
  });

  it("captures ground_truth when provided", () => {
    const path = appendRoutingTraceRecord(
      "scan-gt",
      {
        finding: makeFinding("f1"),
        decision: makeDecision(["oracle"]),
        groundTruth: "true_positive",
      },
      { outputDir: tmpDir },
    );
    const record = JSON.parse(readFileSync(path, "utf8").trim());
    expect(record.ground_truth).toBe("true_positive");
  });
});
