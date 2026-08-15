import { describe, expect, it } from "vitest";
import { computeReviewFindingId, ensureReviewFindingIds } from "./finding-id.js";
import type { ReviewFileRecord, ReviewFinding } from "./types.js";

function finding(title: string, vulnSlug = "sql-injection"): ReviewFinding {
  return {
    severity: "high",
    vulnSlug,
    title,
    description: "User-controlled value reaches a query.",
    lineNumbers: [12],
    recommendation: "Use bound parameters.",
    confidence: "high",
  };
}

function record(findings: ReviewFinding[]): ReviewFileRecord {
  return {
    projectId: "demo",
    filePath: "src/api/users.ts",
    candidates: [],
    findings,
    analysisHistory: [],
    status: "analyzed",
  };
}

describe("review finding IDs", () => {
  it("derives one stable ID from immutable finding identity", () => {
    const id = computeReviewFindingId("demo", "src\\api\\users.ts", "SQL injection");
    expect(id).toMatch(/^finding_[0-9a-f]{16}$/);
    expect(computeReviewFindingId("demo", "./src/api/users.ts", "SQL injection")).toBe(id);
    expect(computeReviewFindingId("demo", "src/api/users.ts", "SQL injection")).not.toBe(
      computeReviewFindingId("demo", "src/api/users.ts", "SSRF"),
    );
  });

  it("backfills missing IDs deterministically and disambiguates title collisions", () => {
    const first = record([finding("Same title"), finding("Same title", "xss")]);
    const second = record([finding("Same title"), finding("Same title", "xss")]);

    expect(ensureReviewFindingIds(first)).toBe(true);
    expect(ensureReviewFindingIds(second)).toBe(true);
    expect(ensureReviewFindingIds(first)).toBe(false);
    expect(first.findings.map((item) => item.findingId)).toEqual(
      second.findings.map((item) => item.findingId),
    );
    expect(first.findings[0].findingId).not.toBe(first.findings[1].findingId);
  });
});
