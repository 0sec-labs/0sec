/**
 * Unit tests for `runFoxguardScan` and the Foxguard-JSON → `SemgrepFinding`
 * translator. The companion `__tests__/shared-analysis.foxguard.test.ts`
 * runs a fixture-driven parity check between `runSemgrepScan` and
 * `runFoxguardScan`; this file targets translator edge cases and the
 * silent-fallback path.
 *
 * Both files mock the subprocess seam — no real `npx foxguard` or
 * `semgrep` binary is invoked in CI.
 */
import type { execFileSync as ExecFileSync } from "node:child_process";
import { describe, expect, it, vi } from "vitest";
import {
  FOXGUARD_PINNED_TAG,
  runFoxguardScan,
  translateFoxguardJson,
} from "./shared-analysis.js";

const SAMPLE_FOXGUARD_JSON = JSON.stringify([
  {
    rule_id: "js/no-eval",
    severity: "critical",
    cwe: "CWE-94",
    description: "Use of eval() allows arbitrary code execution",
    file: "src/index.js",
    line: 7,
    column: 4,
    end_line: 7,
    end_column: 20,
    snippet: "eval(req.body.code);",
    taint_hops: 1,
    source_line: 4,
    source_description: "user input from req.body",
    sink_line: 7,
    sink_description: "eval(...)",
    confidence: 0.95,
    fix_suggestion: "Avoid eval; use JSON.parse for data or a sandboxed VM.",
    tags: ["taint", "javascript"],
  },
]);

describe("runFoxguardScan", () => {
  it("retains findings when Foxguard exits with its findings status", () => {
    // Foxguard returns exit code 1 whenever it finds at least one issue. The
    // runner throws but the stdout still carries the JSON array.
    const runner = vi.fn(() => {
      const err: NodeJS.ErrnoException & { stdout?: string; status?: number } = new Error(
        "Command failed with exit code 1",
      );
      err.stdout = SAMPLE_FOXGUARD_JSON;
      err.status = 1;
      throw err;
    }) as unknown as typeof ExecFileSync;

    const findings = runFoxguardScan("/repo", () => {}, { runner });

    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("js/no-eval");
  });

  it("uses the npm release when the local binary is absent", () => {
    const runner = vi.fn((command: string) => {
      if (command === "foxguard") throw Object.assign(new Error("missing binary"), { code: "ENOENT" });
      return SAMPLE_FOXGUARD_JSON;
    }) as unknown as typeof ExecFileSync;
    const findings = runFoxguardScan("/repo", () => {}, {
      runner,
      semgrepFallback: () => { throw new Error("unexpected fallback"); },
    });
    expect(findings[0]?.ruleId).toBe("js/no-eval");
  });

  it.each([
    { output: "truncated JSON", status: 0 },
    { output: SAMPLE_FOXGUARD_JSON, status: 2 },
    { output: '{"schema_version":"2.0.0","findings":[]}', status: 0 },
  ])("does not report scanner failure as a clean scan ($status, $output)", ({ output, status }) => {
    const runner = vi.fn(() => {
      if (status !== 0) throw Object.assign(new Error("scan failed"), { status, stdout: output });
      return output;
    }) as unknown as typeof ExecFileSync;
    expect(() => runFoxguardScan("/repo", () => {}, {
      runner,
      logger: () => {},
      semgrepFallback: () => { throw new Error("fallback unavailable"); },
    })).toThrow("fallback unavailable");
  });

  it("falls back to semgrep silently with a warning log when foxguard cannot be launched", () => {
    const runner = vi.fn(() => {
      // No stdout — simulates `npx` itself missing or the package failing to download.
      throw new Error("ENOENT: no such file or directory, open '/usr/local/bin/npx'");
    }) as unknown as typeof ExecFileSync;

    const semgrepFallback = vi.fn().mockReturnValue([
      {
        ruleId: "semgrep.js.no-eval",
        message: "eval call",
        severity: "high",
        path: "src/index.js",
        startLine: 7,
        endLine: 7,
        snippet: "eval(req.body)",
      },
    ]);

    const logs: string[] = [];
    const findings = runFoxguardScan("/repo", () => {}, {
      runner,
      semgrepFallback,
      logger: (m) => logs.push(m),
    });

    expect(semgrepFallback).toHaveBeenCalledTimes(1);
    expect(semgrepFallback).toHaveBeenCalledWith("/repo", expect.any(Function), {});
    expect(findings).toEqual([
      expect.objectContaining({ ruleId: "semgrep.js.no-eval" }),
    ]);
    expect(logs).toHaveLength(1);
    expect(logs[0]).toMatch(/foxguard unavailable/);
    expect(logs[0]).toMatch(/falling back to semgrep/);
    expect(logs[0]).toContain(FOXGUARD_PINNED_TAG);
  });

});

describe("translateFoxguardJson", () => {
  it("maps the documented Foxguard JSON shape to SemgrepFinding fields", () => {
    const findings = translateFoxguardJson(SAMPLE_FOXGUARD_JSON);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toEqual({
      ruleId: "js/no-eval",
      message: "Use of eval() allows arbitrary code execution",
      severity: "critical",
      path: "src/index.js",
      startLine: 7,
      endLine: 7,
      snippet: "eval(req.body.code);",
      metadata: expect.objectContaining({
        scanner: "foxguard",
        cwe: "CWE-94",
        confidence: 0.95,
        taintHops: 1,
        fixSuggestion: expect.stringContaining("Avoid eval"),
        tags: ["taint", "javascript"],
        dataflow: expect.objectContaining({
          sourceLine: 4,
          sinkLine: 7,
        }),
      }),
    });
  });

  it("retains findings from the versioned native report", () => {
    const report = JSON.stringify({
      schema_version: "1.0.0",
      finding_schema_version: "1.0.0",
      scanner: { name: "foxguard", version: "0.12.0", command: "scan" },
      findings: JSON.parse(SAMPLE_FOXGUARD_JSON),
    });
    expect(translateFoxguardJson(report)).toEqual(translateFoxguardJson(SAMPLE_FOXGUARD_JSON));
    expect(translateFoxguardJson(report)[0]?.ruleId).toBe("js/no-eval");
  });

  it("defaults endLine to startLine when foxguard omits end_line", () => {
    const json = JSON.stringify([
      {
        rule_id: "py/no-yaml-load",
        severity: "high",
        description: "Use of yaml.load is unsafe",
        file: "app.py",
        line: 3,
        snippet: "yaml.load(req.data)",
      },
    ]);
    const findings = translateFoxguardJson(json);
    expect(findings[0]).toMatchObject({
      ruleId: "py/no-yaml-load",
      startLine: 3,
      endLine: 3,
      severity: "high",
    });
  });

  it("skips entries missing required fields (rule_id, file, line)", () => {
    const json = JSON.stringify([
      { rule_id: "good", severity: "low", description: "ok", file: "a.js", line: 1 },
      { severity: "low", description: "missing rule_id", file: "a.js", line: 1 },
      { rule_id: "no-file", severity: "low", description: "x", line: 1 },
      { rule_id: "no-line", severity: "low", description: "x", file: "a.js" },
      null,
      "not-an-object",
    ]);
    const findings = translateFoxguardJson(json);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("good");
  });

  it("normalizes severity values into 0sec's vocabulary (low/medium/high/critical/info)", () => {
    const json = JSON.stringify([
      { rule_id: "a", severity: "low", description: "", file: "a", line: 1 },
      { rule_id: "b", severity: "medium", description: "", file: "a", line: 1 },
      { rule_id: "c", severity: "high", description: "", file: "a", line: 1 },
      { rule_id: "d", severity: "critical", description: "", file: "a", line: 1 },
      { rule_id: "e", severity: "WeIrD-sEvErItY", description: "", file: "a", line: 1 },
      { rule_id: "f", description: "", file: "a", line: 1 }, // missing severity
    ]);
    const findings = translateFoxguardJson(json);
    expect(findings.map((f) => f.severity)).toEqual([
      "low",
      "medium",
      "high",
      "critical",
      "info",
      "info",
    ]);
  });

  it("returns [] for empty / non-JSON / non-array input", () => {
    expect(translateFoxguardJson("")).toEqual([]);
    expect(translateFoxguardJson("   ")).toEqual([]);
    expect(translateFoxguardJson("not json")).toEqual([]);
    expect(translateFoxguardJson("{}")).toEqual([]); // object, not array
    expect(translateFoxguardJson("null")).toEqual([]);
  });
});
