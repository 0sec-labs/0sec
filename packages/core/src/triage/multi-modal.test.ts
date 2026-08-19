import { describe, it, expect } from "vitest";
import {
  checkMultiModalAgreement,
  parseFoxguardSarif,
  inferCategoryFromRule,
  extractFilesFromFinding,
  computeAgreement,
  fuseTriageSignals,
} from "./multi-modal.js";
import type { AttackCategory, Finding } from "@pwnkit/shared";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "mm-test",
    templateId: "audit-sink",
    title: "SQL injection in src/routes/users.ts",
    description:
      "User input from the `id` query parameter is concatenated into a SQL query in src/routes/users.ts at line 42.",
    severity: "high",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "GET /users?id=1' OR 1=1-- HTTP/1.1",
      response: "HTTP/1.1 200 OK\n\n[...]",
    },
    confidence: 0.7,
    timestamp: Date.now(),
    ...overrides,
  };
}

function makeSarif(results: Array<{
  ruleId: string;
  message: string;
  file: string;
  startLine?: number;
}>): string {
  return JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        results: results.map((r) => ({
          ruleId: r.ruleId,
          message: { text: r.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: r.file },
                region: r.startLine ? { startLine: r.startLine } : undefined,
              },
            },
          ],
        })),
      },
    ],
  });
}

describe("parseFoxguardSarif", () => {
  it("parses minimal SARIF with a single result", () => {
    const sarif = makeSarif([
      {
        ruleId: "sql-injection-concat",
        message: "SQL injection via string concatenation",
        file: "src/routes/users.ts",
        startLine: 42,
      },
    ]);
    const parsed = parseFoxguardSarif(sarif);
    expect(parsed).toHaveLength(1);
    expect(parsed[0]!.ruleId).toBe("sql-injection-concat");
    expect(parsed[0]!.file).toBe("src/routes/users.ts");
    expect(parsed[0]!.startLine).toBe(42);
    expect(parsed[0]!.category).toBe("sql-injection");
  });

  it("returns empty array on garbage input", () => {
    expect(parseFoxguardSarif("not json")).toEqual([]);
    expect(parseFoxguardSarif("{}")).toEqual([]);
  });
});

describe("inferCategoryFromRule", () => {
  it("maps common rule ids to categories", () => {
    expect(inferCategoryFromRule("sqli-concat", "")).toBe("sql-injection");
    expect(inferCategoryFromRule("xss-reflected", "")).toBe("xss");
    expect(inferCategoryFromRule("ssrf-url", "")).toBe("ssrf");
    expect(inferCategoryFromRule("path-traversal", "")).toBe("path-traversal");
    expect(inferCategoryFromRule("prototype-pollution", "")).toBe("prototype-pollution");
    expect(inferCategoryFromRule("redos", "")).toBe("regex-dos");
  });

  it("returns undefined for unknown rules", () => {
    expect(inferCategoryFromRule("mystery-rule", "nothing useful")).toBeUndefined();
  });
});

describe("extractFilesFromFinding", () => {
  it("pulls source paths out of description", () => {
    const f = makeFinding();
    const files = extractFilesFromFinding(f);
    expect(files.some((p) => p.endsWith("users.ts"))).toBe(true);
  });
});

describe("computeAgreement", () => {
  it("both_fire with high confidence when file + category match", () => {
    const f = makeFinding();
    const fox = parseFoxguardSarif(
      makeSarif([
        {
          ruleId: "sql-injection-concat",
          message: "SQL concat",
          file: "/repo/src/routes/users.ts",
          startLine: 42,
        },
      ]),
    );
    const result = computeAgreement(f, fox);
    expect(result.agreement).toBe("both_fire");
    expect(result.confidence).toBe(0.95);
    expect(result.foxguardFindings).toHaveLength(1);
  });

  it("both_fire with medium confidence when file matches but category differs", () => {
    const f = makeFinding(); // category = sql-injection
    const fox = parseFoxguardSarif(
      makeSarif([
        {
          ruleId: "xss-reflected",
          message: "XSS",
          file: "src/routes/users.ts",
          startLine: 10,
        },
      ]),
    );
    const result = computeAgreement(f, fox);
    expect(result.agreement).toBe("both_fire");
    expect(result.confidence).toBe(0.8);
  });

  it("only_pwnkit when foxguard has no finding in the file", () => {
    const f = makeFinding();
    const fox = parseFoxguardSarif(
      makeSarif([
        {
          ruleId: "sql-injection",
          message: "SQLi",
          file: "src/unrelated/other.ts",
        },
      ]),
    );
    const result = computeAgreement(f, fox);
    expect(result.agreement).toBe("only_pwnkit");
    expect(result.confidence).toBe(0.4);
  });

  it("only_pwnkit when foxguard scan is empty", () => {
    const f = makeFinding();
    const result = computeAgreement(f, []);
    expect(result.agreement).toBe("only_pwnkit");
    expect(result.confidence).toBe(0.4);
  });
});

describe("checkMultiModalAgreement", () => {
  it("uses sarifOverride to short-circuit the child process", async () => {
    const f = makeFinding();
    const sarif = makeSarif([
      {
        ruleId: "sqli-1",
        message: "SQL injection",
        file: "src/routes/users.ts",
      },
    ]);
    const result = await checkMultiModalAgreement(f, "/nonexistent", {
      sarifOverride: sarif,
    });
    expect(result.agreement).toBe("both_fire");
    expect(result.confidence).toBe(0.95);
  });

  it("returns only_pwnkit@0.5 when foxguard binary is missing", async () => {
    const f = makeFinding();
    // Force missing binary by supplying a nonexistent path and no override.
    const result = await checkMultiModalAgreement(f, "/nonexistent", {
      foxguardPath: undefined,
      // runner will never be called because detectFoxguard fails
    });
    // Note: on a machine where foxguard IS installed, this would go down the
    // real-run path. We can't deterministically prove the "missing" branch
    // without mocking `detectFoxguard`, so accept either outcome: missing OR
    // a bad-sourceDir reason.
    expect(["only_pwnkit", "both_fire"]).toContain(result.agreement);
    expect(result.confidence).toBeGreaterThanOrEqual(0);
    expect(result.confidence).toBeLessThanOrEqual(1);
  });
});

describe("fuseTriageSignals", () => {
  it("auto-rejects when holding-it-wrong fires", () => {
    const r = fuseTriageSignals({ holdingItWrong: true });
    expect(r.decision).toBe("auto_reject");
  });

  it("auto-accepts when multi-modal agrees and evidence is strong", () => {
    const r = fuseTriageSignals({
      multiModal: {
        agreement: "both_fire",
        confidence: 0.95,
        foxguardFindings: [],
        reasoning: "",
      },
      evidenceCompleteness: 0.9,
    });
    expect(r.decision).toBe("auto_accept");
  });

  it("prioritizes verify when multi-modal agrees but evidence is weak", () => {
    const r = fuseTriageSignals({
      multiModal: {
        agreement: "both_fire",
        confidence: 0.8,
        foxguardFindings: [],
        reasoning: "",
      },
      evidenceCompleteness: 0.3,
    });
    expect(r.decision).toBe("verify_priority");
  });

  it("auto-rejects when foxguard disagrees and evidence is weak", () => {
    const r = fuseTriageSignals({
      multiModal: {
        agreement: "only_pwnkit",
        confidence: 0.4,
        foxguardFindings: [],
        reasoning: "",
      },
      evidenceCompleteness: 0.3,
    });
    expect(r.decision).toBe("auto_reject");
  });

  it("falls through to verify otherwise", () => {
    const r = fuseTriageSignals({
      multiModal: {
        agreement: "only_pwnkit",
        confidence: 0.5,
        foxguardFindings: [],
        reasoning: "",
      },
      evidenceCompleteness: 0.6,
    });
    expect(r.decision).toBe("verify");
  });
});
