/**
 * Tests for the LayerVerdict pass-through (pwnkit#112).
 *
 * The collector has to extract `layerVerdicts` from three different shapes:
 *   1. XBOW result JSON — finding objects may carry `layerVerdicts` inline
 *      after the v0.7.5 instrumentation lands
 *   2. npm-bench result JSON — same as above
 *   3. SQLite DB rows — column is JSON-stringified text
 *
 * For all three, an absent or NULL field must produce an empty array, not
 * a crash. A present field must round-trip through `toTrainingFormat` so the
 * downstream JSONL preserves the exact verdicts.
 */
import { describe, expect, it } from "vitest";
import { writeFileSync, mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { LayerVerdict } from "@pwnkit/shared";
import {
  collectFromXbowResults,
  collectFromNpmBench,
  safeExtractLayerVerdicts,
  TRIAGE_FEATURE_COUNT,
  toTrainingFormat,
  type TriageSample,
} from "./triage-data-collector.js";

const SAMPLE_VERDICTS: LayerVerdict[] = [
  {
    layer: "holding_it_wrong",
    verdict: "pass",
    reason: "no holding-it-wrong pattern matched",
    durationMs: 1,
    costUsd: 0,
  },
  {
    layer: "evidence_gate",
    verdict: "pass",
    confidence: 0.83,
    reason: "evidence_completeness=0.83 > 0.5",
    durationMs: 0,
    costUsd: 0,
  },
  {
    layer: "oracle",
    verdict: "downgrade",
    confidence: 0.4,
    reason: "only 1/3 sqli signals fired: boolean_diff",
    durationMs: 4231,
    costUsd: 0,
    changedSeverity: { from: "high", to: "low" },
  },
];

function tmpFile(name: string, content: string): string {
  const dir = mkdtempSync(join(tmpdir(), "pwnkit-triage-test-"));
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
}

describe("safeExtractLayerVerdicts", () => {
  it("returns empty array when field is absent", () => {
    expect(safeExtractLayerVerdicts({})).toEqual([]);
    expect(safeExtractLayerVerdicts({ layerVerdicts: null })).toEqual([]);
    expect(safeExtractLayerVerdicts({ layerVerdicts: undefined })).toEqual([]);
  });

  it("returns the array verbatim when already-parsed", () => {
    expect(
      safeExtractLayerVerdicts({ layerVerdicts: SAMPLE_VERDICTS }),
    ).toEqual(SAMPLE_VERDICTS);
  });

  it("parses a JSON-stringified blob (the SQLite shape)", () => {
    expect(
      safeExtractLayerVerdicts({ layerVerdicts: JSON.stringify(SAMPLE_VERDICTS) }),
    ).toEqual(SAMPLE_VERDICTS);
  });

  it("accepts the snake_case alias from the JSONL output schema", () => {
    expect(
      safeExtractLayerVerdicts({ layer_verdicts: SAMPLE_VERDICTS }),
    ).toEqual(SAMPLE_VERDICTS);
  });

  it("returns empty array on corrupt JSON instead of crashing", () => {
    expect(safeExtractLayerVerdicts({ layerVerdicts: "{not json" })).toEqual([]);
  });

  it("returns empty array on a non-array JSON value", () => {
    expect(
      safeExtractLayerVerdicts({ layerVerdicts: '{"not": "an array"}' }),
    ).toEqual([]);
  });
});

describe("collectFromXbowResults — layer verdicts pass-through", () => {
  it("propagates layerVerdicts when present on the XBOW finding", () => {
    const path = tmpFile(
      "xbow-with-verdicts.json",
      JSON.stringify({
        results: [
          {
            id: "XBEN-042",
            flagFound: true,
            findings: [
              {
                id: "f1",
                title: "SQLi",
                severity: "high",
                category: "sql-injection",
                evidence: { request: "GET /?q='", response: "ERROR" },
                layerVerdicts: SAMPLE_VERDICTS,
              },
            ],
          },
        ],
      }),
    );
    const samples = collectFromXbowResults(path);
    expect(samples).toHaveLength(1);
    expect(samples[0].layer_verdicts).toEqual(SAMPLE_VERDICTS);
  });

  it("emits empty array for legacy XBOW findings without verdicts", () => {
    const path = tmpFile(
      "xbow-legacy.json",
      JSON.stringify({
        results: [
          {
            id: "XBEN-001",
            flagFound: false,
            findings: [
              { id: "f1", title: "SQLi", severity: "high", category: "sqli", evidence: {} },
            ],
          },
        ],
      }),
    );
    const samples = collectFromXbowResults(path);
    expect(samples[0].layer_verdicts).toEqual([]);
  });
});

describe("collectFromNpmBench — layer verdicts pass-through", () => {
  it("propagates layerVerdicts when present on an npm-bench finding", () => {
    const path = tmpFile(
      "npm-bench-with-verdicts.json",
      JSON.stringify({
        results: [
          {
            pkg: "event-stream",
            verdict: "malicious",
            findings: [
              {
                id: "f2",
                title: "Suspicious dep",
                severity: "high",
                category: "supply-chain",
                evidence: {},
                layerVerdicts: SAMPLE_VERDICTS,
              },
            ],
          },
        ],
      }),
    );
    const samples = collectFromNpmBench(path);
    expect(samples[0].layer_verdicts).toEqual(SAMPLE_VERDICTS);
  });

  it("emits empty array for safe-package findings without verdicts", () => {
    const path = tmpFile(
      "npm-bench-safe.json",
      JSON.stringify({
        results: [
          {
            pkg: "react",
            verdict: "safe",
            findings: [
              { id: "f3", title: "noise", severity: "info", category: "info", evidence: {} },
            ],
          },
        ],
      }),
    );
    const samples = collectFromNpmBench(path);
    expect(samples[0].layer_verdicts).toEqual([]);
  });
});

describe("toTrainingFormat — JSONL round-trip", () => {
  it("includes layer_verdicts in the emitted JSONL row", () => {
    const sample: TriageSample = {
      id: "test-1",
      title: "SQLi",
      description: "Error-based SQLi",
      severity: "high",
      category: "sqli",
      request: "GET /?q='",
      response: "ERROR",
      analysis: "",
      confidence: 0.9,
      label: "true_positive",
      source: "XBEN-042",
      label_source: "flag_extraction",
      features: new Array(TRIAGE_FEATURE_COUNT).fill(0),
      layer_verdicts: SAMPLE_VERDICTS,
    };
    const line = toTrainingFormat(sample);
    const parsed = JSON.parse(line);
    expect(parsed.layer_verdicts).toEqual(SAMPLE_VERDICTS);
  });

  it("emits an empty array (not undefined) for findings without verdicts", () => {
    const sample: TriageSample = {
      id: "test-2",
      title: "noise",
      description: "",
      severity: "info",
      category: "info",
      request: "",
      response: "",
      analysis: "",
      confidence: 0.1,
      label: "false_positive",
      source: "test",
      label_source: "manual",
      features: new Array(TRIAGE_FEATURE_COUNT).fill(0),
      layer_verdicts: [],
    };
    const parsed = JSON.parse(toTrainingFormat(sample));
    expect(parsed.layer_verdicts).toEqual([]);
  });
});
