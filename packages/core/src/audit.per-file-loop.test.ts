import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding } from "@pwnkit/shared";
import {
  runPerFileAudit,
  buildDirectApiAuditPromptForFile,
  type PerFileAuditOptions,
} from "./audit.js";
import type { InstalledPackage } from "./package-ecosystems.js";

// ── Helpers ──

function makeFinding(seed: string): Finding {
  return {
    id: `f-${seed}`,
    templateId: "tpl",
    title: `Finding ${seed}`,
    description: "desc",
    severity: "medium",
    category: "code-injection",
    status: "discovered",
    evidence: { request: seed, response: "200", analysis: "" },
    timestamp: 0,
  };
}

function makePkg(path: string): InstalledPackage {
  return {
    ecosystem: "npm",
    name: "test-pkg",
    version: "1.2.3",
    path,
    tempDir: path,
  };
}

function baseOpts(overrides: Partial<PerFileAuditOptions> & { pkg: InstalledPackage }): PerFileAuditOptions {
  return {
    pkg: overrides.pkg,
    files: [],
    semgrepFindings: [],
    npmAuditFindings: [],
    targetLabel: "npm package",
    advisoryLabel: "npm audit",
    invoke: async () => ({ findings: [] }),
    ...overrides,
  };
}

// ── Tests ──

describe("runPerFileAudit — per-file audit loop (#285)", () => {
  let tempDir: string;
  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), "pwnkit-audit-loop-test-"));
    // Make 8 source files so the test can drive an 8-file audit
    for (let i = 1; i <= 8; i++) {
      writeFileSync(join(tempDir, `src${i}.js`), `module.exports = function(x) { return x; };\n`);
    }
  });
  afterAll(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it("invokes the agent exactly once per file (8 files → 8 calls)", async () => {
    const calls: string[] = [];
    const files = Array.from({ length: 8 }, (_, i) => join(tempDir, `src${i + 1}.js`));

    const result = await runPerFileAudit(baseOpts({
      pkg: makePkg(tempDir),
      files,
      invoke: async ({ fileRel }) => {
        calls.push(fileRel);
        return { findings: [] };
      },
    }));

    expect(calls).toHaveLength(8);
    expect(calls).toEqual([
      "src1.js", "src2.js", "src3.js", "src4.js",
      "src5.js", "src6.js", "src7.js", "src8.js",
    ]);
    expect(result.findings).toEqual([]);
  });

  it("aggregates findings across all per-file sessions", async () => {
    const files = Array.from({ length: 3 }, (_, i) => join(tempDir, `src${i + 1}.js`));
    let i = 0;
    const result = await runPerFileAudit(baseOpts({
      pkg: makePkg(tempDir),
      files,
      invoke: async () => {
        i++;
        if (i === 1) return { findings: [makeFinding("a"), makeFinding("b")] };
        if (i === 2) return { findings: [] };
        return { findings: [makeFinding("c"), makeFinding("d"), makeFinding("e")] };
      },
    }));

    expect(result.findings.map((f) => f.id)).toEqual([
      "f-a", "f-b", "f-c", "f-d", "f-e",
    ]);
  });

  it("sums usage and cost across per-file sessions", async () => {
    const files = Array.from({ length: 3 }, (_, i) => join(tempDir, `src${i + 1}.js`));
    let i = 0;
    const result = await runPerFileAudit(baseOpts({
      pkg: makePkg(tempDir),
      files,
      invoke: async () => {
        i++;
        return {
          findings: [],
          usage: { inputTokens: 100 * i, outputTokens: 50 * i },
          estimatedCostUsd: 0.01 * i,
        };
      },
    }));

    // 100 + 200 + 300 = 600 input, 50 + 100 + 150 = 300 output
    expect(result.usage).toEqual({ inputTokens: 600, outputTokens: 300 });
    expect(result.estimatedCostUsd).toBeCloseTo(0.06, 5);
  });

  it("isolates per-file errors — one bad file does not abort the pass", async () => {
    const files = Array.from({ length: 3 }, (_, i) => join(tempDir, `src${i + 1}.js`));
    const errors: string[] = [];

    const result = await runPerFileAudit(baseOpts({
      pkg: makePkg(tempDir),
      files,
      invoke: async ({ fileRel }) => {
        if (fileRel === "src2.js") throw new Error("simulated runtime crash");
        return { findings: [makeFinding(fileRel)] };
      },
      onFileError: (rel, err) => errors.push(`${rel}: ${err.message}`),
    }));

    expect(result.findings.map((f) => f.id)).toEqual(["f-src1.js", "f-src3.js"]);
    expect(errors).toEqual(["src2.js: simulated runtime crash"]);
  });

  it("each per-file system prompt only mentions that file's relative path", async () => {
    const files = [
      join(tempDir, "src1.js"),
      join(tempDir, "src2.js"),
    ];
    const prompts: string[] = [];

    await runPerFileAudit(baseOpts({
      pkg: makePkg(tempDir),
      files,
      invoke: async ({ systemPrompt }) => {
        prompts.push(systemPrompt);
        return { findings: [] };
      },
    }));

    expect(prompts[0]).toContain("src1.js");
    expect(prompts[0]).not.toContain("src2.js");
    expect(prompts[1]).toContain("src2.js");
    expect(prompts[1]).not.toContain("src1.js");
  });

  it("zero files → zero invocations", async () => {
    let calls = 0;
    const result = await runPerFileAudit(baseOpts({
      pkg: makePkg(tempDir),
      files: [],
      invoke: async () => { calls++; return { findings: [] }; },
    }));
    expect(calls).toBe(0);
    expect(result.findings).toEqual([]);
    expect(result.usage).toBeUndefined();
    expect(result.estimatedCostUsd).toBeUndefined();
  });
});

describe("buildDirectApiAuditPromptForFile — single-file dump prompt (#285)", () => {
  let tempDir: string;
  beforeAll(() => {
    tempDir = mkdtempSync(join(tmpdir(), "pwnkit-audit-prompt-test-"));
    writeFileSync(join(tempDir, "vulnerable.js"), "eval(req.query.code);\n");
    writeFileSync(join(tempDir, "safe.js"), "const x = 1;\n");
  });
  afterAll(() => {
    try { rmSync(tempDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it("embeds only the requested file's source verbatim", () => {
    const prompt = buildDirectApiAuditPromptForFile(
      makePkg(tempDir),
      join(tempDir, "vulnerable.js"),
      [],
      [],
    );
    expect(prompt).toContain("vulnerable.js");
    expect(prompt).toContain("eval(req.query.code);");
    expect(prompt).not.toContain("const x = 1;"); // other file's content not included
  });

  it("filters semgrep findings to only the file under review", () => {
    const prompt = buildDirectApiAuditPromptForFile(
      makePkg(tempDir),
      join(tempDir, "vulnerable.js"),
      [
        { ruleId: "javascript.eval", message: "eval call", path: "vulnerable.js", startLine: 1, severity: "high", snippet: "" } as any,
        { ruleId: "javascript.note", message: "irrelevant", path: "safe.js", startLine: 1, severity: "info", snippet: "" } as any,
      ],
      [],
    );
    expect(prompt).toContain("vulnerable.js:1");
    expect(prompt).toContain("eval call");
    expect(prompt).not.toContain("irrelevant");
  });
});
