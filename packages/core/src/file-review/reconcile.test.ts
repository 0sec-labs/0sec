import { describe, it, expect } from "vitest";
import {
  normalizeTitle,
  expectedFindingsForBatch,
  parseRevalidateVerdicts,
  reconcileVerdicts,
} from "./reconcile.js";
import type { ReviewFileRecord } from "./types.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeRecord(overrides: Partial<ReviewFileRecord> = {}): ReviewFileRecord {
  return {
    filePath: "src/auth.ts",
    projectId: "test",
    candidates: [],
    findings: [],
    analysisHistory: [],
    status: "pending",
    ...overrides,
  };
}

// ── normalizeTitle ──────────────────────────────────────────────────────────

describe("normalizeTitle", () => {
  it("lowercases the input", () => {
    expect(normalizeTitle("SQL Injection")).toBe("sql injection");
  });

  it("applies NFKC normalization", () => {
    expect(normalizeTitle("\uFF34TP\uFF11")) // FULLWIDTH LATIN
      .toBe("ttp1");
  });

  it("strips markdown backticks", () => {
    expect(normalizeTitle("`eval()` in user input")).toBe("eval in user input");
  });

  it("strips quotes", () => {
    expect(normalizeTitle("'dangerous' call")).toBe("dangerous call");
    expect(normalizeTitle('"double" quoted')).toBe("double quoted");
  });

  it("collapses internal whitespace", () => {
    expect(normalizeTitle("SQL   Injection\nis  bad")).toBe("sql injection is bad");
  });

  it("drops trailing punctuation", () => {
    expect(normalizeTitle("XSS vulnerability!")).toBe("xss vulnerability");
    expect(normalizeTitle("Path traversal?")).toBe("path traversal");
  });

  it("combines all normalizations", () => {
    expect(normalizeTitle("`RCE` in 'unsafe'  deserialize!!"))
      .toBe("rce in unsafe deserialize");
  });
});

// ── expectedFindingsForBatch ────────────────────────────────────────────────

describe("expectedFindingsForBatch", () => {
  it("assigns aliases F1..Fn in prompt order across records", () => {
    const records = [
      makeRecord({
        filePath: "a.ts",
        findings: [
          { severity: "high", vulnSlug: "xss", title: "XSS", description: "", lineNumbers: [1], recommendation: "", confidence: "high" },
          { severity: "high", vulnSlug: "rce", title: "RCE", description: "", lineNumbers: [5], recommendation: "", confidence: "medium" },
        ],
      }),
      makeRecord({
        filePath: "b.ts",
        findings: [
          { severity: "medium", vulnSlug: "sqli", title: "SQLi", description: "", lineNumbers: [10], recommendation: "", confidence: "high" },
        ],
      }),
    ];
    const result = expectedFindingsForBatch(records);
    expect(result).toHaveLength(3);
    expect(result[0].alias).toBe("F1");
    expect(result[0].title).toBe("XSS");
    expect(result[1].alias).toBe("F2");
    expect(result[1].title).toBe("RCE");
    expect(result[2].alias).toBe("F3");
    expect(result[2].title).toBe("SQLi");
  });

  it("skips findings that already have revalidation unless force", () => {
    const records = [
      makeRecord({
        findings: [
          { severity: "high", vulnSlug: "xss", title: "XSS", description: "", lineNumbers: [1], recommendation: "", confidence: "high", revalidation: { verdict: "true-positive", reasoning: "real", revalidatedAt: "2024-01-01", runId: "r1" } },
          { severity: "high", vulnSlug: "rce", title: "RCE", description: "", lineNumbers: [5], recommendation: "", confidence: "medium" },
        ],
      }),
    ];
    const result = expectedFindingsForBatch(records);
    expect(result).toHaveLength(1);
    expect(result[0].title).toBe("RCE");
  });

  it("includes already-revalidated findings when force is true", () => {
    const records = [
      makeRecord({
        findings: [
          { severity: "high", vulnSlug: "xss", title: "XSS", description: "", lineNumbers: [1], recommendation: "", confidence: "high", revalidation: { verdict: "true-positive", reasoning: "real", revalidatedAt: "2024-01-01", runId: "r1" } },
        ],
      }),
    ];
    const result = expectedFindingsForBatch(records, { force: true });
    expect(result).toHaveLength(1);
    expect(result[0].title).toBe("XSS");
  });

  it("returns empty array for empty records", () => {
    expect(expectedFindingsForBatch([])).toEqual([]);
  });

  it("uses empty string for findings without findingId", () => {
    const records = [
      makeRecord({
        findings: [
          { severity: "high", vulnSlug: "xss", title: "XSS", description: "", lineNumbers: [1], recommendation: "", confidence: "high" },
        ],
      }),
    ];
    const result = expectedFindingsForBatch(records);
    expect(result[0].findingId).toBe("");
  });
});

// ── parseRevalidateVerdicts ─────────────────────────────────────────────────

describe("parseRevalidateVerdicts", () => {
  it("extracts verdicts from a fenced JSON code block", () => {
    const text = [
      "Here are my findings:",
      "```json",
      '[{"findingId":"F1","verdict":"true-positive","reasoning":"Clear exploit path"}]',
      "```",
    ].join("\n");
    const result = parseRevalidateVerdicts(text);
    expect(result).toHaveLength(1);
    expect(result[0].verdict).toBe("true-positive");
    expect(result[0].reasoning).toBe("Clear exploit path");
  });

  it("extracts from a bare JSON array when no fence exists", () => {
    const text = '[{"findingId":"F1","verdict":"false-positive","reasoning":"Not exploitable"}]';
    const result = parseRevalidateVerdicts(text);
    expect(result).toHaveLength(1);
    expect(result[0].verdict).toBe("false-positive");
  });

  it("returns empty array for non-JSON text", () => {
    expect(parseRevalidateVerdicts("No findings here")).toEqual([]);
  });

  it("validates verdict values and drops invalid ones", () => {
    const text = JSON.stringify([
      { findingId: "F1", verdict: "true-positive", reasoning: "good" },
      { findingId: "F2", verdict: "not-a-real-verdict", reasoning: "bad" },
    ]);
    const result = parseRevalidateVerdicts(text);
    expect(result).toHaveLength(1);
    expect(result[0].findingId).toBe("F1");
  });

  it("parses verdicts with adjustedSeverity and duplicateOf", () => {
    const text = JSON.stringify([
      { findingId: "F1", verdict: "duplicate", duplicateOf: "abc-123", reasoning: "Same as abc-123" },
      { findingId: "F2", verdict: "true-positive", adjustedSeverity: "critical", reasoning: "Critical impact" },
    ]);
    const result = parseRevalidateVerdicts(text);
    expect(result).toHaveLength(2);
    expect(result[0].duplicateOf).toBe("abc-123");
    expect(result[1].adjustedSeverity).toBe("critical");
  });

  it("drops items missing required fields", () => {
    const text = JSON.stringify([
      { findingId: "F1", verdict: "true-positive", reasoning: "good" },
      { verdict: "true-positive", reasoning: "no-id" },
      { findingId: "F2", reasoning: "no-verdict" },
    ]);
    const result = parseRevalidateVerdicts(text);
    expect(result).toHaveLength(1);
  });
});

// ── reconcileVerdicts ───────────────────────────────────────────────────────

describe("reconcileVerdicts", () => {
  it("pass 1: matches by findingId", () => {
    const expected = [
      { findingId: "id-001", filePath: "a.ts", title: "XSS", alias: "F1" },
    ];
    const verdicts = [
      { findingId: "id-001", verdict: "true-positive" as const, reasoning: "real" },
    ];
    const result = reconcileVerdicts(expected, verdicts);
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0].matchedBy).toBe("finding-id");
  });

  it("pass 1: matches by alias case-insensitively", () => {
    const expected = [
      { findingId: "", filePath: "a.ts", title: "XSS", alias: "F1" },
    ];
    const verdicts = [
      { findingId: "f1", verdict: "true-positive" as const, reasoning: "real" },
    ];
    const result = reconcileVerdicts(expected, verdicts);
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0].matchedBy).toBe("finding-id");
  });

  it("pass 2: matches by exact title", () => {
    const expected = [
      { findingId: "id-001", filePath: "a.ts", title: "Cross-Site Scripting", alias: "F1" },
    ];
    const verdicts = [
      { findingId: "Cross-Site Scripting", verdict: "false-positive" as const, reasoning: "not exploitable" },
    ];
    const result = reconcileVerdicts(expected, verdicts);
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0].matchedBy).toBe("exact-title");
  });

  it("pass 3: matches by normalized title", () => {
    const expected = [
      { findingId: "id-001", filePath: "a.ts", title: "`RCE` in 'user input'!!", alias: "F1" },
    ];
    const verdicts = [
      { findingId: "RCE in user input!", verdict: "fixed" as const, reasoning: "patched in 2.3.1" },
    ];
    const result = reconcileVerdicts(expected, verdicts);
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0].matchedBy).toBe("normalized-title");
  });

  it("pass 4: unique remainder pairing", () => {
    const expected = [
      { findingId: "id-001", filePath: "a.ts", title: "Something", alias: "F1" },
    ];
    const verdicts = [
      { findingId: "TotallyUnrelatedTitle", verdict: "uncertain" as const, reasoning: "cannot determine" },
    ];
    const result = reconcileVerdicts(expected, verdicts);
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0].matchedBy).toBe("unique-remainder");
  });

  it("pass 1 beats pass 2 (findingId match takes priority over title)", () => {
    const expected = [
      { findingId: "id-001", filePath: "a.ts", title: "XSS", alias: "F1" },
    ];
    const verdicts = [
      { findingId: "id-001", verdict: "true-positive" as const, reasoning: "real" },
      { findingId: "XSS", verdict: "false-positive" as const, reasoning: "not real" },
    ];
    const result = reconcileVerdicts(expected, verdicts);
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0].matchedBy).toBe("finding-id");
    expect(result.matched[0].verdict.verdict).toBe("true-positive");
    expect(result.unmatched).toHaveLength(1);
    expect(result.missing).toHaveLength(0);
  });

  it("each expected matched at most once (first match wins)", () => {
    const expected = [
      { findingId: "id-001", filePath: "a.ts", title: "XSS", alias: "F1" },
      { findingId: "id-002", filePath: "a.ts", title: "RCE", alias: "F2" },
    ];
    // Two verdicts both ID-matching F1 — after first wins, second is unmatched
    const verdicts = [
      { findingId: "F1", verdict: "true-positive" as const, reasoning: "real" },
      { findingId: "F1", verdict: "false-positive" as const, reasoning: "wait no" },
    ];
    const result = reconcileVerdicts(expected, verdicts);
    expect(result.matched).toHaveLength(1);
    expect(result.matched[0].matchedBy).toBe("finding-id");
    expect(result.unmatched).toHaveLength(1);
    expect(result.missing).toHaveLength(1);
  });

  it("returns unmatched verdicts and missing expected", () => {
    const expected = [
      { findingId: "id-001", filePath: "a.ts", title: "XSS", alias: "F1" },
    ];
    const verdicts = [
      { findingId: "id-002", verdict: "true-positive" as const, reasoning: "orphan verdict" },
    ];
    const result = reconcileVerdicts(expected, verdicts);
    expect(result.matched).toHaveLength(0);
    expect(result.unmatched).toHaveLength(1);
    expect(result.unmatched[0].findingId).toBe("id-002");
    expect(result.missing).toHaveLength(1);
    expect(result.missing[0].findingId).toBe("id-001");
  });
});