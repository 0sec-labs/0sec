/**
 * Tests for triage-data-collector.ts
 *
 * Covers the v0.6.0+ patch that added:
 *   - npm-bench source (collectFromNpmBench, labels by package_verdict)
 *   - handcrafted feature vector emission (safeExtractFeatures)
 *   - JSONL serializer with features + label_source + source provenance
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  collectFromNpmBench,
  collectFromXbowResults,
  safeExtractFeatures,
  TRIAGE_FEATURE_COUNT,
  toTrainingFormat,
  type TriageSample,
} from "./triage-data-collector.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "triage-collector-test-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

// ────────────────────────────────────────────────────────────────────
// safeExtractFeatures
// ────────────────────────────────────────────────────────────────────

describe("safeExtractFeatures", () => {
  it("returns a feature vector for a fully-populated finding", () => {
    const finding = {
      id: "f1",
      templateId: "sqli-error-based",
      title: "SQL injection",
      description: "Error-based SQLi in /api/search",
      severity: "high",
      category: "sqli",
      confidence: 0.9,
      evidence: {
        request: "GET /api/search?q=' OR 1=1--",
        response: "ERROR: syntax error at or near \"OR\" in PostgreSQL",
        analysis: "Server returned a SQL stack trace",
      },
    };

    const features = safeExtractFeatures(finding);

    expect(features).toHaveLength(TRIAGE_FEATURE_COUNT);
    expect(features.every((f) => typeof f === "number")).toBe(true);
    // The PostgreSQL error pattern should fire SQL_ERROR_PATTERN (feature index 1)
    expect(features[1]).toBe(1);
  });

  it("returns a feature vector for an empty finding without throwing", () => {
    const features = safeExtractFeatures({});
    expect(features).toHaveLength(TRIAGE_FEATURE_COUNT);
    // The vector should be mostly zero on an empty input — features come from
    // regex matches against empty strings — but a handful of default/derived
    // features (e.g. confidence default, severity ordinal) may be non-zero.
    const nonZero = features.filter((f) => f !== 0).length;
    expect(nonZero).toBeLessThanOrEqual(8);
  });

  it("tolerates a totally malformed input", () => {
    expect(() => safeExtractFeatures(null)).not.toThrow();
    expect(() => safeExtractFeatures(undefined)).not.toThrow();
    expect(() => safeExtractFeatures("not an object")).not.toThrow();
    expect(safeExtractFeatures(null)).toHaveLength(TRIAGE_FEATURE_COUNT);
  });

  it("supports both nested evidence shape and flat shape from DB rows", () => {
    const flat = {
      id: "f2",
      title: "Reflected XSS",
      severity: "medium",
      category: "xss",
      request: "GET /q=<script>alert(1)</script>",
      response: "<html>...<script>alert(1)</script>...</html>",
      analysis: "Payload reflected unencoded",
    };
    const nested = {
      id: "f2",
      title: "Reflected XSS",
      severity: "medium",
      category: "xss",
      evidence: {
        request: flat.request,
        response: flat.response,
        analysis: flat.analysis,
      },
    };

    const flatFeatures = safeExtractFeatures(flat);
    const nestedFeatures = safeExtractFeatures(nested);

    expect(flatFeatures).toEqual(nestedFeatures);
  });
});

// ────────────────────────────────────────────────────────────────────
// collectFromNpmBench
// ────────────────────────────────────────────────────────────────────

describe("collectFromNpmBench", () => {
  function writeFakeNpmBench(results: any[]): string {
    const path = join(tmp, "npm-bench-latest.json");
    writeFileSync(
      path,
      JSON.stringify({
        timestamp: "2026-04-06T12:00:00Z",
        results,
      }),
    );
    return path;
  }

  it("labels findings on malicious packages as true_positive", () => {
    const path = writeFakeNpmBench([
      {
        pkg: "event-stream",
        verdict: "malicious",
        findings: [
          {
            id: "f1",
            title: "Malicious package",
            description: "supply-chain attack",
            severity: "critical",
            category: "supply_chain",
            evidence: { request: "", response: "", analysis: "" },
          },
        ],
      },
    ]);

    const samples = collectFromNpmBench(path);

    expect(samples).toHaveLength(1);
    expect(samples[0].label).toBe("true_positive");
    expect(samples[0].label_source).toBe("package_verdict");
    expect(samples[0].source).toBe("npm-bench:event-stream:malicious");
  });

  it("labels findings on vulnerable (CVE) packages as true_positive", () => {
    const path = writeFakeNpmBench([
      {
        pkg: "lodash@4.17.20",
        verdict: "vulnerable",
        findings: [
          {
            id: "f1",
            title: "Prototype pollution",
            severity: "high",
            category: "prototype_pollution",
            evidence: { request: "", response: "", analysis: "" },
          },
        ],
      },
    ]);

    const samples = collectFromNpmBench(path);
    expect(samples[0].label).toBe("true_positive");
  });

  it("labels findings on safe packages as false_positive", () => {
    const path = writeFakeNpmBench([
      {
        pkg: "rxjs",
        verdict: "safe",
        findings: [
          {
            id: "f1",
            title: "Suspicious eval",
            severity: "low",
            category: "code_quality",
            evidence: { request: "", response: "", analysis: "" },
          },
        ],
      },
    ]);

    const samples = collectFromNpmBench(path);
    expect(samples[0].label).toBe("false_positive");
    expect(samples[0].source).toBe("npm-bench:rxjs:safe");
  });

  it("emits a feature vector for every sample", () => {
    const path = writeFakeNpmBench([
      {
        pkg: "event-stream",
        verdict: "malicious",
        findings: [
          { id: "f1", title: "x", severity: "high", category: "supply_chain", evidence: {} },
          { id: "f2", title: "y", severity: "high", category: "supply_chain", evidence: {} },
        ],
      },
    ]);

    const samples = collectFromNpmBench(path);
    expect(samples).toHaveLength(2);
    for (const s of samples) {
      expect(s.features).toHaveLength(TRIAGE_FEATURE_COUNT);
      expect(s.features.every((f) => typeof f === "number")).toBe(true);
    }
  });

  it("returns zero rows for results that pre-date the findings field", () => {
    // Old npm-bench results (before the v0.6.0+ patch) lack the findings array
    const path = writeFakeNpmBench([
      { pkg: "event-stream", verdict: "malicious", findingsCount: 1, hasFindings: true },
      { pkg: "rxjs", verdict: "safe", findingsCount: 0, hasFindings: false },
    ]);

    const samples = collectFromNpmBench(path);
    expect(samples).toHaveLength(0);
  });

  it("produces a balanced TP/FP set across mixed verdicts", () => {
    const path = writeFakeNpmBench([
      {
        pkg: "event-stream",
        verdict: "malicious",
        findings: [{ id: "a", title: "x", severity: "high", category: "x", evidence: {} }],
      },
      {
        pkg: "lodash@4.17.20",
        verdict: "vulnerable",
        findings: [{ id: "b", title: "y", severity: "high", category: "y", evidence: {} }],
      },
      {
        pkg: "rxjs",
        verdict: "safe",
        findings: [
          { id: "c", title: "z", severity: "low", category: "z", evidence: {} },
          { id: "d", title: "w", severity: "low", category: "w", evidence: {} },
        ],
      },
    ]);

    const samples = collectFromNpmBench(path);
    const tp = samples.filter((s) => s.label === "true_positive").length;
    const fp = samples.filter((s) => s.label === "false_positive").length;
    expect(tp).toBe(2);
    expect(fp).toBe(2);
  });
});

// ────────────────────────────────────────────────────────────────────
// collectFromXbowResults — backwards compatibility
// ────────────────────────────────────────────────────────────────────

describe("collectFromXbowResults", () => {
  function writeFakeXbow(results: any[]): string {
    const path = join(tmp, "xbow-latest.json");
    writeFileSync(path, JSON.stringify({ results }));
    return path;
  }

  it("labels findings as TP when flagFound is true", () => {
    const path = writeFakeXbow([
      {
        id: "XBEN-001",
        flagFound: true,
        findings: [
          { id: "f1", title: "SQLi", severity: "high", category: "sqli", evidence: {} },
        ],
      },
    ]);
    const samples = collectFromXbowResults(path);
    expect(samples[0].label).toBe("true_positive");
    expect(samples[0].label_source).toBe("flag_extraction");
    expect(samples[0].features).toHaveLength(TRIAGE_FEATURE_COUNT);
  });

  it("labels findings as FP when flagFound is false", () => {
    const path = writeFakeXbow([
      {
        id: "XBEN-002",
        flagFound: false,
        findings: [
          { id: "f1", title: "SQLi", severity: "high", category: "sqli", evidence: {} },
        ],
      },
    ]);
    const samples = collectFromXbowResults(path);
    expect(samples[0].label).toBe("false_positive");
  });
});

// ────────────────────────────────────────────────────────────────────
// toTrainingFormat (JSONL serializer)
// ────────────────────────────────────────────────────────────────────

describe("toTrainingFormat", () => {
  const sample: TriageSample = {
    id: "test-1",
    title: "SQL injection",
    description: "Error-based SQLi",
    severity: "high",
    category: "sqli",
    request: "GET /search?q='",
    response: "ERROR: syntax error",
    analysis: "Confirmed via stack trace",
    confidence: 0.9,
    label: "true_positive",
    source: "npm-bench:event-stream:malicious",
    label_source: "package_verdict",
    features: new Array(TRIAGE_FEATURE_COUNT).fill(0).map((_, i) => i),
    layer_verdicts: [],
  };

  it("emits valid JSON on a single line", () => {
    const line = toTrainingFormat(sample);
    expect(() => JSON.parse(line)).not.toThrow();
    expect(line.includes("\n")).toBe(false);
  });

  it("includes the feature vector in the output", () => {
    const parsed = JSON.parse(toTrainingFormat(sample));
    expect(parsed.features).toHaveLength(TRIAGE_FEATURE_COUNT);
    expect(parsed.features[0]).toBe(0);
    expect(parsed.features[TRIAGE_FEATURE_COUNT - 1]).toBe(TRIAGE_FEATURE_COUNT - 1);
  });

  it("includes label as int, label_text as string, and label_source", () => {
    const parsed = JSON.parse(toTrainingFormat(sample));
    expect(parsed.label).toBe(1);
    expect(parsed.label_text).toBe("true_positive");
    expect(parsed.label_source).toBe("package_verdict");
  });

  it("emits label=0 for false_positive samples", () => {
    const parsed = JSON.parse(
      toTrainingFormat({ ...sample, label: "false_positive" }),
    );
    expect(parsed.label).toBe(0);
    expect(parsed.label_text).toBe("false_positive");
  });

  it("preserves source provenance for downstream filtering", () => {
    const parsed = JSON.parse(toTrainingFormat(sample));
    expect(parsed.source).toBe("npm-bench:event-stream:malicious");
  });

  it("renders the text field with all the structured fields", () => {
    const parsed = JSON.parse(toTrainingFormat(sample));
    expect(parsed.text).toContain("Title: SQL injection");
    expect(parsed.text).toContain("Category: sqli");
    expect(parsed.text).toContain("Severity: high");
    expect(parsed.text).toContain("Description: Error-based SQLi");
    expect(parsed.text).toContain("Request: GET /search?q='");
    expect(parsed.text).toContain("Response: ERROR: syntax error");
  });
});
