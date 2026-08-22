import { describe, expect, it } from "vitest";

import {
  formatToolArgs,
  formatToolResult,
  toolResultDetail,
  MAX_SUMMARY_CHARS,
  type ToolCallLike,
  type ToolResultLike,
} from "./tool-format.js";

/** Assert a value is a single, control-free line within the summary cap. */
function assertBounded(value: string): void {
  expect(typeof value).toBe("string");
  expect(value.length).toBeLessThanOrEqual(MAX_SUMMARY_CHARS);
  expect(value).not.toMatch(/[\r\n\t\x00-\x08\x0b-\x1f\x7f]/);
}

describe("formatToolArgs — covered tools", () => {
  it("search_files matches the transcript sample", () => {
    const out = formatToolArgs({
      name: "search_files",
      arguments: { query: "child_process", path: "packages/core/src", max_results: 100 },
    });
    expect(out).toBe('"child_process" in packages/core/src');
  });

  it("search_files without a path shows only the query", () => {
    expect(formatToolArgs({ name: "search_files", arguments: { query: "eval" } })).toBe('"eval"');
  });

  it("list_files shows the path or scope root", () => {
    expect(formatToolArgs({ name: "list_files", arguments: { path: "src/agent" } })).toBe("src/agent");
    expect(formatToolArgs({ name: "list_files", arguments: {} })).toBe("(scope root)");
  });

  it("read_file shows path and offset", () => {
    expect(formatToolArgs({ name: "read_file", arguments: { path: "a/b.ts" } })).toBe("a/b.ts");
    expect(formatToolArgs({ name: "read_file", arguments: { path: "a/b.ts", offset: 120 } })).toBe(
      "a/b.ts @120",
    );
  });

  it("run_command shows the command", () => {
    expect(
      formatToolArgs({ name: "run_command", arguments: { command: "rg --files ." } }),
    ).toBe("rg --files .");
  });

  it("http_request shows method and url, defaulting to POST", () => {
    expect(
      formatToolArgs({ name: "http_request", arguments: { url: "https://x.test/login", method: "GET" } }),
    ).toBe("GET https://x.test/login");
    expect(formatToolArgs({ name: "http_request", arguments: { url: "https://x.test/a" } })).toBe(
      "POST https://x.test/a",
    );
  });

  it("apply_patch counts file operations in the envelope", () => {
    const patch = [
      "*** Begin Patch",
      "*** Update File: src/a.ts",
      "*** Add File: src/b.ts",
      "*** End Patch",
    ].join("\n");
    expect(formatToolArgs({ name: "apply_patch", arguments: { patch } })).toBe("2 files");
  });

  it("save_finding leads with severity, category and title", () => {
    expect(
      formatToolArgs({
        name: "save_finding",
        arguments: { severity: "high", category: "sql-injection", title: "Login bypass" },
      }),
    ).toBe("high sql-injection: Login bypass");
  });

  it("spawn_agent shows the task", () => {
    expect(formatToolArgs({ name: "spawn_agent", arguments: { task: "enumerate tables" } })).toBe(
      "enumerate tables",
    );
  });

  it("spawn_agents counts the batch", () => {
    const out = formatToolArgs({
      name: "spawn_agents",
      arguments: { tasks: [{ task: "probe /a" }, { task: "probe /b" }] },
    });
    expect(out).toBe("2 agents: probe /a");
  });

  it("analyze_binary shows the binary path and bug class", () => {
    expect(
      formatToolArgs({
        name: "analyze_binary",
        arguments: { binary_path: "bin/target", bug_class: "memory-safety" },
      }),
    ).toBe("bin/target (memory-safety)");
  });
});

describe("formatToolResult — count summaries", () => {
  it("search_files → N matches in M files", () => {
    const result: ToolResultLike = {
      success: true,
      output: {
        matches: [
          { path: "a.ts", line: 1, content: "x" },
          { path: "a.ts", line: 9, content: "y" },
          { path: "b.ts", line: 2, content: "z" },
          { path: "c.ts", line: 3, content: "w" },
        ],
        truncated: false,
      },
    };
    expect(formatToolResult({ name: "search_files", arguments: {} }, result)).toBe(
      "4 matches in 3 files",
    );
  });

  it("search_files marks a truncated result", () => {
    const result: ToolResultLike = {
      success: true,
      output: { matches: [{ path: "a.ts", line: 1, content: "x" }], truncated: true },
    };
    expect(formatToolResult({ name: "search_files", arguments: {} }, result)).toBe(
      "1 match in 1 file (truncated)",
    );
  });

  it("list_files → N files", () => {
    expect(
      formatToolResult(
        { name: "list_files", arguments: {} },
        { success: true, output: { files: new Array(128).fill("x"), truncated: false } },
      ),
    ).toBe("128 files");
  });

  it("read_file → N lines", () => {
    expect(
      formatToolResult(
        { name: "read_file", arguments: {} },
        { success: true, output: { content: "…", totalLines: 312, truncated: false } },
      ),
    ).toBe("312 lines");
  });

  it("read_file marks a windowed read", () => {
    expect(
      formatToolResult(
        { name: "read_file", arguments: {} },
        { success: true, output: { content: "…", totalLines: 5000, truncated: true } },
      ),
    ).toBe("5000 lines (windowed)");
  });

  it("run_command → lines · size", () => {
    const out = formatToolResult(
      { name: "run_command", arguments: {} },
      { success: true, output: "line1\nline2\nline3" },
    );
    expect(out).toBe("3 lines · 17 B");
  });

  it("http_request → status · size", () => {
    const out = formatToolResult(
      { name: "http_request", arguments: {} },
      { success: true, output: { status: 200, headers: {}, body: "a".repeat(4300) } },
    );
    expect(out).toBe("200 · 4.2 kB");
  });

  it("http_request flags a WAF block", () => {
    const out = formatToolResult(
      { name: "http_request", arguments: {} },
      { success: true, output: { status: 403, body: "blocked", waf: { blocked: true } } },
    );
    expect(out).toBe("403 · 7 B · WAF blocked");
  });

  it("apply_patch → N files patched", () => {
    expect(
      formatToolResult(
        { name: "apply_patch", arguments: {} },
        {
          success: true,
          output: { applied: [{ kind: "update", path: "a.ts" }, { kind: "add", path: "b.ts" }] },
        },
      ),
    ).toBe("2 files patched");
  });

  it("save_finding → saved <id>", () => {
    expect(
      formatToolResult(
        { name: "save_finding", arguments: {} },
        { success: true, output: { findingId: "F-42", message: "Finding saved" } },
      ),
    ).toBe("saved F-42");
  });

  it("spawn_agent → findings in turns", () => {
    expect(
      formatToolResult(
        { name: "spawn_agent", arguments: {} },
        { success: true, output: { turns: 8, findings: 2, summary: "…", done: true } },
      ),
    ).toBe("2 findings in 8 turns");
  });

  it("spawn_agents → batch outcome", () => {
    expect(
      formatToolResult(
        { name: "spawn_agents", arguments: {} },
        { success: true, output: { spawned: 3, succeeded: 2, failed: 1, agents: [] } },
      ),
    ).toBe("3 agents: 2 ok, 1 failed");
  });

  it("analyze_binary → confirmed and hypotheses", () => {
    expect(
      formatToolResult(
        { name: "analyze_binary", arguments: {} },
        { success: true, output: { confirmed: [{ title: "UAF" }], hypotheses: [{}, {}] } },
      ),
    ).toBe("1 confirmed, 2 hypotheses");
  });
});

describe("failures are first-class", () => {
  it("leads with the error text", () => {
    const out = formatToolResult(
      { name: "search_files", arguments: {} },
      { success: false, output: null, error: "search_files requires a scoped local directory" },
    );
    expect(out).toBe("failed: search_files requires a scoped local directory");
  });

  it("collapses a multi-line error to one line", () => {
    const out = formatToolResult(
      { name: "run_command", arguments: {} },
      { success: false, output: null, error: "boom\n  at line 1\n  at line 2" },
    );
    assertBounded(out);
    expect(out.startsWith("failed: boom")).toBe(true);
  });

  it("handles a failure with no error text", () => {
    expect(
      formatToolResult({ name: "read_file", arguments: {} }, { success: false, output: null }),
    ).toBe("failed");
  });
});

describe("generic fallback for unknown tools", () => {
  it("summarizes arguments as key=value, salient first", () => {
    const out = formatToolArgs({
      name: "some_unknown_tool",
      arguments: { extra: "z", url: "https://x.test", note: "hello" },
    });
    expect(out.startsWith("url=https://x.test")).toBe(true);
  });

  it("collapses nested containers instead of dumping them", () => {
    const out = formatToolArgs({
      name: "mystery",
      arguments: { items: [1, 2, 3], meta: { a: 1, b: 2 } },
    });
    expect(out).toContain("items=[3]");
    expect(out).toContain("meta={2}");
  });

  it("counts array results", () => {
    expect(
      formatToolResult({ name: "mystery", arguments: {} }, { success: true, output: [1, 2, 3, 4] }),
    ).toBe("4 items");
  });

  it("counts object keys", () => {
    expect(
      formatToolResult({ name: "mystery", arguments: {} }, { success: true, output: { a: 1, b: 2 } }),
    ).toBe("2 fields");
  });
});

describe("secrets discipline — credential-bearing keys are redacted", () => {
  const spellings = [
    "authorization",
    "Authorization",
    "AUTH_TOKEN",
    "api_key",
    "apiKey",
    "x-api-key",
    "access_key",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "Cookie",
    "session_token",
    "bearer",
    "private_key",
    "passphrase",
  ];

  for (const key of spellings) {
    it(`redacts "${key}" in generic args`, () => {
      const out = formatToolArgs({ name: "mystery", arguments: { [key]: "s3cr3t-value-123" } });
      expect(out).toContain("[redacted]");
      expect(out).not.toContain("s3cr3t-value-123");
    });
  }

  it("redacts credentials in generic result objects too", () => {
    const out = formatToolArgs({
      name: "mystery",
      arguments: { token: "abcdef123456", path: "src/a.ts" },
    });
    expect(out).toContain("token=[redacted]");
    expect(out).toContain("path=src/a.ts");
  });

  it("does not redact ordinary keys", () => {
    const out = formatToolArgs({ name: "mystery", arguments: { path: "src/a.ts" } });
    expect(out).not.toContain("[redacted]");
  });
});

describe("totality — malformed input never throws and stays bounded", () => {
  const BIG = "x".repeat(50_000);

  // Build a deeply nested + cyclic object; JSON.stringify would throw on it.
  const cyclic: Record<string, unknown> = { a: 1 };
  cyclic.self = cyclic;
  let deep: Record<string, unknown> = {};
  const root = deep;
  for (let i = 0; i < 2000; i++) {
    const next: Record<string, unknown> = {};
    deep.child = next;
    deep = next;
  }

  const adversarialCalls: ToolCallLike[] = [
    { name: "search_files", arguments: undefined },
    { name: "search_files", arguments: null as unknown },
    { name: "search_files", arguments: "not json {" },
    { name: "search_files", arguments: '{"query":"ok"}' },
    { name: "read_file", arguments: [1, 2, 3] as unknown },
    { name: "http_request", arguments: { url: BIG, headers: { authorization: BIG } } },
    { name: "run_command", arguments: { command: BIG } },
    { name: "mystery", arguments: cyclic },
    { name: "mystery", arguments: root },
    { name: "mystery", arguments: BIG },
    { name: "", arguments: {} },
    { name: undefined as unknown as string, arguments: {} },
  ];

  const adversarialResults: ToolResultLike[] = [
    { success: true, output: undefined },
    { success: true, output: null },
    { success: true, output: BIG },
    { success: true, output: cyclic },
    { success: true, output: root },
    { success: true, output: [BIG, BIG, BIG] },
    { success: false, output: null, error: BIG },
    { success: false, output: null, error: null },
    { success: undefined as unknown as boolean, output: {} },
  ];

  it("formatToolArgs is total and bounded", () => {
    for (const call of adversarialCalls) {
      expect(() => formatToolArgs(call)).not.toThrow();
      assertBounded(formatToolArgs(call));
    }
    // A completely malformed call object.
    expect(() => formatToolArgs({} as ToolCallLike)).not.toThrow();
    assertBounded(formatToolArgs({} as ToolCallLike));
  });

  it("formatToolResult is total and bounded across the call×result matrix", () => {
    for (const call of adversarialCalls) {
      for (const result of adversarialResults) {
        expect(() => formatToolResult(call, result)).not.toThrow();
        assertBounded(formatToolResult(call, result));
      }
    }
  });

  it("credentials survive redaction even inside a 50 kB value", () => {
    const out = formatToolArgs({
      name: "http_request",
      arguments: { url: "https://x.test", headers: { authorization: BIG } },
    });
    // headers is a nested object → collapses to a count; the raw secret never leaks.
    expect(out).not.toContain(BIG.slice(0, 200));
    assertBounded(out);
  });
});

describe("toolResultDetail", () => {
  it("lists first search matches as path:line", () => {
    const detail = toolResultDetail(
      { name: "search_files", arguments: {} },
      {
        success: true,
        output: {
          matches: [
            { path: "a.ts", line: 3, content: "x" },
            { path: "b.ts", line: 9, content: "y" },
          ],
          truncated: false,
        },
      },
    );
    expect(detail).toEqual(["a.ts:3", "b.ts:9"]);
  });

  it("respects the maxLines cap", () => {
    const matches = new Array(10).fill(0).map((_, i) => ({ path: `f${i}.ts`, line: i, content: "x" }));
    const detail = toolResultDetail(
      { name: "search_files", arguments: {} },
      { success: true, output: { matches, truncated: true } },
      2,
    );
    expect(detail).toHaveLength(2);
  });

  it("surfaces failed children of a fan-out", () => {
    const detail = toolResultDetail(
      { name: "spawn_agents", arguments: {} },
      {
        success: true,
        output: {
          spawned: 2,
          succeeded: 1,
          failed: 1,
          agents: [
            { index: 0, ok: true, findings: 1, turns: 3 },
            { index: 1, ok: false, error: "timed out" },
          ],
        },
      },
    );
    expect(detail).toEqual(["agent 1 failed: timed out"]);
  });

  it("returns [] for failures, unknown tools, and maxLines=0", () => {
    expect(
      toolResultDetail({ name: "search_files", arguments: {} }, { success: false, output: null }),
    ).toEqual([]);
    expect(
      toolResultDetail({ name: "mystery", arguments: {} }, { success: true, output: {} }),
    ).toEqual([]);
    expect(
      toolResultDetail(
        { name: "search_files", arguments: {} },
        { success: true, output: { matches: [{ path: "a", line: 1 }] } },
        0,
      ),
    ).toEqual([]);
  });

  it("every detail line is single-line and bounded", () => {
    const detail = toolResultDetail(
      { name: "list_files", arguments: {} },
      { success: true, output: { files: ["x/".repeat(500), "y\nz", "ok.ts"], truncated: false } },
    );
    for (const l of detail) assertBounded(l);
  });
});
