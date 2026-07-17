import { describe, it, expect } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { runPerFileResearch, type PerFileResearchOptions } from "./unified-pipeline.js";

// ── Helpers ──

function makeFinding(seed: string): Finding {
  return {
    id: `f-${seed}`,
    templateId: "tpl",
    title: `Finding for ${seed}`,
    description: `desc ${seed}`,
    severity: "medium",
    category: "code-injection",
    status: "discovered",
    evidence: { request: seed, response: "200 OK", analysis: "found" },
    timestamp: 0,
  };
}

function baseOpts(overrides: Partial<PerFileResearchOptions> = {}): PerFileResearchOptions {
  return {
    scopePath: "/scope",
    target: "/scope",
    scanId: "scan-test",
    files: [],
    semgrepFindings: [],
    npmAuditFindings: [],
    targetLabel: "test package",
    advisoryLabel: "npm audit",
    invoke: async () => ({ findings: [] }),
    ...overrides,
  };
}

// ── Tests ──

describe("runPerFileResearch — per-file research loop (#285)", () => {
  it("invokes the per-file agent exactly once per file (5 files → 5 calls)", async () => {
    const calls: string[] = [];
    const files = [
      "/scope/src/a.ts",
      "/scope/src/b.ts",
      "/scope/src/c.ts",
      "/scope/lib/d.ts",
      "/scope/index.js",
    ];

    await runPerFileResearch(baseOpts({
      files,
      invoke: async ({ fileRel }) => {
        calls.push(fileRel);
        return { findings: [] };
      },
    }));

    expect(calls).toHaveLength(5);
    // fileRel is path-relative to scopePath.
    expect(calls).toEqual([
      "src/a.ts",
      "src/b.ts",
      "src/c.ts",
      "lib/d.ts",
      "index.js",
    ]);
  });

  it("aggregates findings emitted by each per-file session into the final list", async () => {
    const files = ["/scope/a.ts", "/scope/b.ts", "/scope/c.ts"];
    let i = 0;
    const findings = await runPerFileResearch(baseOpts({
      files,
      invoke: async () => {
        i++;
        // File 1 finds 2, file 2 finds 0, file 3 finds 1 → 3 total
        if (i === 1) return { findings: [makeFinding("a-1"), makeFinding("a-2")] };
        if (i === 2) return { findings: [] };
        return { findings: [makeFinding("c-1")] };
      },
    }));

    expect(findings).toHaveLength(3);
    expect(findings.map((f) => f.id)).toEqual(["f-a-1", "f-a-2", "f-c-1"]);
  });

  it("each per-file system prompt only mentions that file's relative path", async () => {
    const files = ["/scope/src/foo.ts", "/scope/src/bar.ts"];
    const prompts: string[] = [];

    await runPerFileResearch(baseOpts({
      files,
      invoke: async ({ systemPrompt }) => {
        prompts.push(systemPrompt);
        return { findings: [] };
      },
    }));

    expect(prompts).toHaveLength(2);
    expect(prompts[0]).toContain("src/foo.ts");
    expect(prompts[0]).not.toContain("src/bar.ts");
    expect(prompts[1]).toContain("src/bar.ts");
    expect(prompts[1]).not.toContain("src/foo.ts");
  });

  it("invokes onFileStart in order with index/total metadata", async () => {
    const files = ["/scope/a", "/scope/b", "/scope/c"];
    const lifecycle: Array<{ rel: string; i: number; total: number }> = [];

    await runPerFileResearch(baseOpts({
      files,
      invoke: async () => ({ findings: [] }),
      onFileStart: (rel, i, total) => lifecycle.push({ rel, i, total }),
    }));

    expect(lifecycle).toEqual([
      { rel: "a", i: 0, total: 3 },
      { rel: "b", i: 1, total: 3 },
      { rel: "c", i: 2, total: 3 },
    ]);
  });

  it("does not abort the overall pass when one per-file invocation throws — collects errors via onFileError", async () => {
    const files = ["/scope/a", "/scope/b", "/scope/c"];
    const errors: string[] = [];

    const findings = await runPerFileResearch(baseOpts({
      files,
      invoke: async ({ fileRel }) => {
        if (fileRel === "b") throw new Error("transient runtime failure");
        return { findings: [makeFinding(fileRel)] };
      },
      onFileError: (rel, err) => errors.push(`${rel}: ${err.message}`),
    }));

    // file a + c succeeded, b errored → 2 findings, 1 error captured
    expect(findings).toHaveLength(2);
    expect(findings.map((f) => f.id)).toEqual(["f-a", "f-c"]);
    expect(errors).toEqual(["b: transient runtime failure"]);
  });

  it("zero files → zero invocations, empty findings", async () => {
    let calls = 0;
    const findings = await runPerFileResearch(baseOpts({
      files: [],
      invoke: async () => { calls++; return { findings: [] }; },
    }));
    expect(calls).toBe(0);
    expect(findings).toEqual([]);
  });

  it("filters semgrep findings to only the file under review (per-file prompt scoping)", async () => {
    const files = ["/scope/safe.ts", "/scope/vuln.ts"];
    const prompts: string[] = [];

    await runPerFileResearch(baseOpts({
      files,
      semgrepFindings: [
        { ruleId: "javascript.eval", message: "eval call", path: "vuln.ts", startLine: 42, severity: "high", snippet: "" } as any,
        { ruleId: "javascript.exec", message: "child_process.exec", path: "vuln.ts", startLine: 99, severity: "medium", snippet: "" } as any,
        { ruleId: "javascript.note", message: "informational", path: "safe.ts", startLine: 7, severity: "info", snippet: "" } as any,
      ],
      invoke: async ({ systemPrompt }) => {
        prompts.push(systemPrompt);
        return { findings: [] };
      },
    }));

    // safe.ts session: only the safe.ts hit
    expect(prompts[0]).toContain("safe.ts:7");
    expect(prompts[0]).not.toContain("vuln.ts:42");
    // vuln.ts session: only the vuln.ts hits
    expect(prompts[1]).toContain("vuln.ts:42");
    expect(prompts[1]).toContain("vuln.ts:99");
    expect(prompts[1]).not.toContain("safe.ts:7");
  });
});

// ── consecutive-failure circuit breaker (auth/endpoint-global failures) ──

describe("runPerFileResearch — consecutive-failure circuit breaker", () => {
  const tenFiles = Array.from({ length: 10 }, (_, i) => `/scope/src/f${i}.ts`);

  it("trips after 3 consecutive identical-signature failures (10 files → 3 invokes)", async () => {
    let invokes = 0;
    const errors: string[] = [];
    await runPerFileResearch(baseOpts({
      files: tenFiles,
      invoke: async () => {
        invokes++;
        throw new Error("ChatGPT (Codex backend) API error 401: could not parse token");
      },
      onFileError: (fileRel) => errors.push(fileRel),
    }));
    expect(invokes).toBe(3);
    // 3 per-file errors + 1 aggregated circuit-breaker error
    expect(errors).toHaveLength(4);
    expect(errors[3]).toBe("(circuit-breaker)");
  });

  it("a success resets the consecutive counter", async () => {
    let invokes = 0;
    await runPerFileResearch(baseOpts({
      files: ["/scope/a.ts", "/scope/b.ts", "/scope/c.ts", "/scope/d.ts", "/scope/e.ts"],
      invoke: async ({ fileRel }) => {
        invokes++;
        if (fileRel === "c.ts") return { findings: [] };
        throw new Error("same error everywhere");
      },
    }));
    // fail, fail, OK (reset), fail, fail — never 3 consecutive
    expect(invokes).toBe(5);
  });

  it("non-consecutive identical errors never trip the breaker", async () => {
    let invokes = 0;
    await runPerFileResearch(baseOpts({
      files: ["/scope/a.ts", "/scope/b.ts", "/scope/c.ts", "/scope/d.ts", "/scope/e.ts"],
      invoke: async ({ fileRel }) => {
        invokes++;
        if (fileRel === "b.ts" || fileRel === "d.ts") return { findings: [] };
        throw new Error("same error everywhere");
      },
    }));
    expect(invokes).toBe(5);
  });

  it("varying error signatures never trip the breaker", async () => {
    let invokes = 0;
    await runPerFileResearch(baseOpts({
      files: ["/scope/a.ts", "/scope/b.ts", "/scope/c.ts", "/scope/d.ts"],
      invoke: async ({ fileRel }) => {
        invokes++;
        throw new Error(`file-specific parse error in ${fileRel}`);
      },
    }));
    expect(invokes).toBe(4);
  });
});
