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
import type { ScanEvent } from "./scanner.js";

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
  it("invokes `npx --yes foxguard@<pinned-tag> --format json <path>`", () => {
    const events: ScanEvent[] = [];
    const runner = vi.fn().mockReturnValue(SAMPLE_FOXGUARD_JSON) as unknown as typeof ExecFileSync;

    const findings = runFoxguardScan("/repo", (event) => events.push(event), {
      runner,
    });

    expect(runner).toHaveBeenCalledTimes(1);
    expect(runner).toHaveBeenCalledWith(
      "npx",
      ["--yes", `foxguard@${FOXGUARD_PINNED_TAG}`, "--format", "json", "/repo"],
      expect.objectContaining({ timeout: 300_000, stdio: "pipe", encoding: "utf-8" }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "js/no-eval",
      severity: "critical",
      path: "src/index.js",
      startLine: 7,
      endLine: 7,
    });
    expect(events.map((e) => e.message)).toContain(`Foxguard: 1 findings`);
  });

  it("passes narrowed paths to foxguard for diff-aware reviews", () => {
    const runner = vi.fn().mockReturnValue(SAMPLE_FOXGUARD_JSON) as unknown as typeof ExecFileSync;

    runFoxguardScan("/repo", () => {}, {
      runner,
      paths: ["/repo/src/changed.ts"],
    });

    expect(runner).toHaveBeenCalledWith(
      "npx",
      ["--yes", `foxguard@${FOXGUARD_PINNED_TAG}`, "--format", "json", "/repo/src/changed.ts"],
      expect.objectContaining({ timeout: 300_000, stdio: "pipe", encoding: "utf-8" }),
    );
  });

  it("uses Foxguard's diff command for multi-file changed-only reviews", () => {
    const runner = vi.fn().mockReturnValue(SAMPLE_FOXGUARD_JSON) as unknown as typeof ExecFileSync;

    runFoxguardScan("/repo", () => {}, {
      runner,
      diffBase: "HEAD^",
      paths: ["/repo/src/first.ts", "/repo/src/second.ts"],
    });

    expect(runner).toHaveBeenCalledWith(
      "npx",
      ["--yes", `foxguard@${FOXGUARD_PINNED_TAG}`, "diff", "HEAD^", "/repo", "--format", "json"],
      expect.objectContaining({ timeout: 300_000, stdio: "pipe", encoding: "utf-8" }),
    );
  });

  it("treats non-zero exit + populated stdout as a successful scan with findings", () => {
    // Foxguard returns exit code 1 whenever it finds at least one issue. The
    // runner throws but the stdout still carries the JSON array.
    const runner = vi.fn(() => {
      const err: NodeJS.ErrnoException & { stdout?: string } = new Error(
        "Command failed with exit code 1",
      );
      err.stdout = SAMPLE_FOXGUARD_JSON;
      throw err;
    }) as unknown as typeof ExecFileSync;

    const findings = runFoxguardScan("/repo", () => {}, { runner });

    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("js/no-eval");
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

  it("preserves narrowed paths when falling back to semgrep", () => {
    const runner = vi.fn(() => {
      throw new Error("npx failed");
    }) as unknown as typeof ExecFileSync;
    const semgrepFallback = vi.fn().mockReturnValue([]);

    runFoxguardScan("/repo", () => {}, {
      runner,
      semgrepFallback,
      logger: () => {},
      paths: ["/repo/src/changed.ts"],
    });

    expect(semgrepFallback).toHaveBeenCalledWith(
      "/repo",
      expect.any(Function),
      { paths: ["/repo/src/changed.ts"] },
    );
  });

  it("preserves noGitIgnore when falling back to semgrep for package scans", () => {
    const runner = vi.fn(() => {
      throw new Error("npx failed");
    }) as unknown as typeof ExecFileSync;
    const semgrepFallback = vi.fn().mockReturnValue([]);

    runFoxguardScan("/repo", () => {}, {
      runner,
      semgrepFallback,
      logger: () => {},
      noGitIgnore: true,
    });

    expect(semgrepFallback).toHaveBeenCalledWith(
      "/repo",
      expect.any(Function),
      { noGitIgnore: true },
    );
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
