import { describe, it, expect } from "vitest";
import { extractFencedJson, parseInvestigateResults, parseRefusalReport, REFUSAL_FOLLOWUP_PROMPT } from "./parse.js";
import type { ReviewFinding } from "./types.js";

// ── extractFencedJson ──────────────────────────────────────────────────────

describe("extractFencedJson", () => {
  it("extracts the last fenced json block", () => {
    const text = [
      "Some text",
      '```json\n{"a": 1}\n```',
      "more text",
      '```json\n{"b": 2}\n```',
    ].join("\n");
    expect(extractFencedJson(text)).toEqual({ b: 2 });
  });

  it("falls back to bare JSON array", () => {
    const text = 'Here is the result: [{"x": 1}]';
    expect(extractFencedJson(text)).toEqual([{ x: 1 }]);
  });

  it("falls back to bare JSON object when no fence", () => {
    const text = "The answer is {\"ok\": true} indeed";
    expect(extractFencedJson(text)).toEqual({ ok: true });
  });

  it("throws when nothing parseable", () => {
    expect(() => extractFencedJson("just some text")).toThrow("No parseable JSON");
    expect(() => extractFencedJson("")).toThrow("No parseable JSON");
  });

  it("prefers last fence over bare JSON", () => {
    const text = [
      'bare: {"a": 1}',
      '```json\n{"b": 2}\n```',
    ].join("\n");
    expect(extractFencedJson(text)).toEqual({ b: 2 });
  });
});

// ── parseInvestigateResults ────────────────────────────────────────────────

const BATCH = [
  { filePath: "src/auth/login.ts" },
  { filePath: "src/db/query.ts" },
];

const VALID_FINDING: ReviewFinding = {
  severity: "high",
  vulnSlug: "sql-injection",
  title: "SQL injection in login handler",
  description: "User input flows into raw query",
  lineNumbers: [15, 18],
  recommendation: "Use parameterized queries",
  confidence: "high",
};

describe("parseInvestigateResults", () => {
  it("parses valid fenced JSON array from LLM output", () => {
    const text = [
      "Here are the results:",
      "```json",
      JSON.stringify([
        { filePath: "src/auth/login.ts", findings: [VALID_FINDING] },
        { filePath: "src/db/query.ts", findings: [] },
      ]),
      "```",
      "End.",
    ].join("\n");

    const { results, invalid } = parseInvestigateResults(text, BATCH);
    expect(invalid).toHaveLength(0);
    expect(results).toHaveLength(2);

    const authResult = results.find((r) => r.filePath === "src/auth/login.ts");
    expect(authResult?.findings).toHaveLength(1);
    expect(authResult?.findings[0].title).toBe("SQL injection in login handler");
  });

  it("handles wrapped { results: [...] } format", () => {
    const text = JSON.stringify({
      results: [
        { filePath: "src/auth/login.ts", findings: [VALID_FINDING] },
      ],
    });

    const { results, invalid } = parseInvestigateResults(text, BATCH);
    expect(invalid).toHaveLength(0);
    expect(results).toHaveLength(1);
  });

  it("reports invalid findings by file", () => {
    const badFinding = {
      severity: "bogus",
      vulnSlug: "",
      title: "",
      description: "",
      lineNumbers: [-1, "bad"],
      confidence: "unknown",
    };

    const text = JSON.stringify([
      { filePath: "src/auth/login.ts", findings: [VALID_FINDING, badFinding] },
    ]);

    const { results, invalid } = parseInvestigateResults(text, BATCH);
    // VALID_FINDING is still accepted
    expect(results).toHaveLength(1);
    expect(results[0].findings).toHaveLength(1);
    // bad finding goes to invalid
    expect(invalid).toHaveLength(1);
    expect(invalid[0].filePath).toBe("src/auth/login.ts");
    expect(invalid[0].issues.length).toBeGreaterThanOrEqual(4);
  });

  it("rejects filePath not in batch", () => {
    const text = JSON.stringify([
      { filePath: "src/other/unknown.ts", findings: [VALID_FINDING] },
    ]);

    const { results, invalid } = parseInvestigateResults(text, BATCH);
    expect(results).toHaveLength(0);
    expect(invalid).toHaveLength(1);
    expect(invalid[0].issues[0]).toContain("not in batch");
  });

  it("throws when parsed JSON is not expected structure", () => {
    // Fenced JSON string literal: parses but is not an object or array
    const text = '```json\n"a plain string"\n```';
    expect(() => parseInvestigateResults(text, BATCH)).toThrow(
      "neither an array nor an object",
    );
  });

  it("throws when no JSON at all", () => {
    expect(() => parseInvestigateResults("just text", BATCH)).toThrow(
      "No parseable JSON",
    );
  });
});

// ── parseRefusalReport ─────────────────────────────────────────────────────

describe("parseRefusalReport", () => {
  it("parses a JSON refusal from fenced block", () => {
    const text = '```json\n{"refused": true, "reason": "Too complex"}\n```';
    const report = parseRefusalReport(text);
    expect(report).toBeDefined();
    expect(report!.refused).toBe(true);
    expect(report!.reason).toBe("Too complex");
  });

  it("parses a non-refusal JSON report", () => {
    const text = '{"refused": false}';
    const report = parseRefusalReport(text);
    expect(report).toBeDefined();
    expect(report!.refused).toBe(false);
  });

  it("heuristic fallback for refusal text", () => {
    const text = "I'm sorry, I cannot analyze that code. It's against policy.";
    const report = parseRefusalReport(text);
    expect(report).toBeDefined();
    expect(report!.refused).toBe(true);
    expect(report!.reason).toContain("heuristic:");
  });

  it("returns undefined for empty input", () => {
    expect(parseRefusalReport("")).toBeUndefined();
    expect(parseRefusalReport("  ")).toBeUndefined();
  });

  it("returns undefined for non-refusing plain text", () => {
    expect(parseRefusalReport("Everything looks fine here.")).toBeUndefined();
  });
});

// ── REFUSAL_FOLLOWUP_PROMPT ────────────────────────────────────────────────

describe("REFUSAL_FOLLOWUP_PROMPT", () => {
  it("is a non-empty string containing JSON structure", () => {
    expect(typeof REFUSAL_FOLLOWUP_PROMPT).toBe("string");
    expect(REFUSAL_FOLLOWUP_PROMPT.length).toBeGreaterThan(50);
    expect(REFUSAL_FOLLOWUP_PROMPT).toContain("refused");
    expect(REFUSAL_FOLLOWUP_PROMPT).toContain("skipped");
  });
});