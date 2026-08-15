import { describe, expect, it } from "vitest";
import { DEFAULT_REVIEW_COVERAGE_POLICY, evaluateReviewCoverage } from "./coverage.js";
import type { ReviewFileRecord, ReviewSurfaceInventory } from "./types.js";

function inventory(over: Partial<ReviewSurfaceInventory> = {}): ReviewSurfaceInventory {
  return {
    items: [
      {
        id: "public-http-api",
        kind: "http",
        description: "REST API",
        fileGlobs: ["src/api/**/*.ts"],
        representativeFiles: ["src/api/users.ts", "src/api/orders.ts"],
        exposure: "public",
      },
    ],
    sourceFiles: ["src/api/users.ts", "src/api/orders.ts", "src/lib/util.ts"],
    issues: [],
    expanded: {
      "public-http-api": ["src/api/users.ts", "src/api/orders.ts"],
    },
    ...over,
  };
}

const record = (filePath: string, candidates: number): ReviewFileRecord => ({
  filePath,
  projectId: "p",
  candidates:
    candidates > 0
      ? [{ vulnSlug: "rce", lineNumbers: [1], snippet: "s", matchedPattern: "m" }]
      : [],
  findings: [],
  analysisHistory: [],
  status: "pending",
  lastScannedRunId: "run-1",
});

describe("evaluateReviewCoverage", () => {
  it("passes when representatives and file ratios are covered", () => {
    const report = evaluateReviewCoverage({
      inventory: inventory(),
      records: [record("src/api/users.ts", 2), record("src/api/orders.ts", 1)],
      runId: "run-1",
    });
    expect(report.passed).toBe(true);
    expect(report.candidateFileCount).toBe(2);
  });

  it("fails when a public http surface has zero covered files", () => {
    const report = evaluateReviewCoverage({
      inventory: inventory(),
      records: [record("src/lib/util.ts", 1)],
      runId: "run-1",
    });
    expect(report.passed).toBe(false);
    expect(report.reasons.join(" ")).toMatch(/zero covered files/);
  });

  it("fails when a representative is uncovered on a small surface", () => {
    const report = evaluateReviewCoverage({
      inventory: inventory(),
      records: [record("src/api/users.ts", 1)],
      runId: "run-1",
    });
    expect(report.passed).toBe(false);
    expect(report.surfaces[0].reasons.join(" ")).toMatch(/representative file/);
  });

  it("large surfaces need both ratios", () => {
    const files = Array.from({ length: 20 }, (_, i) => `src/big/f${i}.ts`);
    const inv = inventory({
      items: [
        {
          id: "big-surface",
          kind: "http",
          description: "big",
          fileGlobs: ["src/big/**/*.ts"],
          representativeFiles: ["src/big/f0.ts", "src/big/f1.ts"],
          exposure: "authenticated",
        },
      ],
      sourceFiles: files,
      expanded: { "big-surface": files },
    });
    // Only 3/20 files covered → file ratio 15% < 50%.
    const records = [record("src/big/f0.ts", 1), record("src/big/f1.ts", 1), record("src/big/f2.ts", 1)];
    const report = evaluateReviewCoverage({ inventory: inv, records, runId: "run-1" });
    expect(report.passed).toBe(false);
    expect(report.surfaces[0].reasons.join(" ")).toMatch(/surface file coverage/);
  });

  it("flags dominant-language blind spots", () => {
    const report = evaluateReviewCoverage({
      inventory: inventory(),
      records: [record("src/api/users.ts", 1), record("src/api/orders.ts", 1)],
      runId: "run-1",
      languageStats: [
        { language: "go", scannedFiles: 100, candidates: 0 },
        { language: "typescript", scannedFiles: 100, candidates: 40 },
      ],
    });
    expect(report.languageWarnings).toHaveLength(1);
    expect(report.languageWarnings[0].language).toBe("go");
    // Warnings don't fail the gate on their own.
    expect(report.passed).toBe(true);
  });

  it("flags matcher explosions from new matchers", () => {
    const report = evaluateReviewCoverage({
      inventory: inventory(),
      records: [record("src/api/users.ts", 1), record("src/api/orders.ts", 1)],
      runId: "run-1",
      newMatcherHits: { "too-broad": ["src/api/users.ts", "src/api/orders.ts", "src/lib/util.ts"] },
      policy: { ...DEFAULT_REVIEW_COVERAGE_POLICY, matcherMaximumFiles: 2 },
    });
    expect(report.passed).toBe(false);
    expect(report.explosionWarnings[0].matcherSlug).toBe("too-broad");
  });

  it("only counts candidates stamped by the evaluated run", () => {
    const stale = record("src/api/users.ts", 1);
    stale.lastScannedRunId = "old-run";
    const report = evaluateReviewCoverage({
      inventory: inventory(),
      records: [stale],
      runId: "run-1",
    });
    expect(report.candidateFileCount).toBe(0);
    expect(report.passed).toBe(false);
  });
});
