import { describe, it, expect, afterEach } from "vitest";
import {
  parseXmlDispatch,
  formatXmlOutput,
  formatXmlOutputBatch,
  buildXmlDispatchPrompt,
  resolveDispatchMode,
} from "./xml-dispatch.js";

describe("parseXmlDispatch", () => {
  it("extracts a single <command>", () => {
    // Spec test #1: given a model response containing <command>echo hi</command>,
    // the parser extracts `echo hi`.
    const parse = parseXmlDispatch("<note>thinking...</note>\n<command>echo hi</command>");
    expect(parse.calls).toEqual([{ name: "bash", arguments: { command: "echo hi" } }]);
    expect(parse.notes).toEqual(["thinking..."]);
    expect(parse.error).toBeUndefined();
  });

  it("flag-first: <flag> wins over <command> in the same response", () => {
    // Spec test #2: a model that finds the flag mid-thought sometimes
    // also leaves a stray <command>. The flag is the answer; it must
    // dispatch `done` and not the bash command.
    const parse = parseXmlDispatch(
      "<command>curl -s http://target/probe</command>\n<flag>FLAG{1d0r-w0rks}</flag>",
    );
    expect(parse.calls).toHaveLength(1);
    expect(parse.calls[0].name).toBe("done");
    expect(parse.calls[0].arguments.flag).toBe("FLAG{1d0r-w0rks}");
    expect((parse.calls[0].arguments.summary as string)).toContain("FLAG{1d0r-w0rks}");
  });

  it("dispatches multiple <command> tags in source order", () => {
    // Spec test #3: BoxPwnr executes multiple commands in a single
    // response sequentially. We do the same — order matters because
    // the second command often depends on environment from the first.
    const parse = parseXmlDispatch("<command>a</command><command>b</command><command>c</command>");
    expect(parse.calls.map((c) => c.arguments.command)).toEqual(["a", "b", "c"]);
  });

  it("flag-first: a single <flag> with no commands still dispatches done", () => {
    const parse = parseXmlDispatch("<flag>FLAG{abc}</flag>");
    expect(parse.calls).toHaveLength(1);
    expect(parse.calls[0].name).toBe("done");
    expect(parse.calls[0].arguments.flag).toBe("FLAG{abc}");
  });

  it("rejects an unclosed <command> with a clear error", () => {
    // Spec test #4: malformed tags must NOT silently corrupt state.
    const parse = parseXmlDispatch("<command>echo hi");
    expect(parse.calls).toEqual([]);
    expect(parse.error).toBeDefined();
    expect(parse.error).toMatch(/Unclosed <command>/i);
  });

  it("rejects an unclosed <flag> with a clear error", () => {
    const parse = parseXmlDispatch("<flag>FLAG{partial");
    expect(parse.error).toMatch(/Unclosed <flag>/i);
    expect(parse.calls).toEqual([]);
  });

  it("ignores empty command bodies", () => {
    const parse = parseXmlDispatch("<command></command><command>ls</command>");
    expect(parse.calls).toHaveLength(1);
    expect(parse.calls[0].arguments.command).toBe("ls");
  });

  it("parses <finding> bodies into save_finding args", () => {
    const parse = parseXmlDispatch(
      "<finding>title: Reflected XSS; severity: high; category: xss; evidence: <script>alert(1)</script></finding>",
    );
    expect(parse.calls).toHaveLength(1);
    expect(parse.calls[0].name).toBe("save_finding");
    expect(parse.calls[0].arguments.title).toBe("Reflected XSS");
    expect(parse.calls[0].arguments.severity).toBe("high");
    // Bare `evidence` is normalised onto evidence_response so cheap models
    // don't have to remember both field names.
    expect(parse.calls[0].arguments.evidence_response).toContain("alert(1)");
  });

  it("drops <finding> bodies that lack title and evidence", () => {
    const parse = parseXmlDispatch("<finding>severity: low</finding>");
    expect(parse.calls).toEqual([]);
  });

  it("collects <note> tags without dispatching them", () => {
    const parse = parseXmlDispatch(
      "<note>step 1: enumerate</note><command>nmap -p 80 target</command><note>step 2: probe</note>",
    );
    expect(parse.notes).toEqual(["step 1: enumerate", "step 2: probe"]);
    expect(parse.calls).toHaveLength(1);
    expect(parse.calls[0].name).toBe("bash");
  });

  it("handles multi-line <command> bodies", () => {
    const parse = parseXmlDispatch("<command>for i in 1 2 3; do\n  curl -s http://t/$i\ndone</command>");
    expect(parse.calls).toHaveLength(1);
    expect(parse.calls[0].arguments.command).toContain("for i in 1 2 3");
    expect(parse.calls[0].arguments.command).toContain("done");
  });
});

describe("formatXmlOutput", () => {
  it("wraps results with status and tool name", () => {
    // Spec test #5: results are wrapped in <output>...</output> and fed back.
    const out = formatXmlOutput("bash", { success: true, output: "hello\nworld" });
    expect(out).toContain('<output tool="bash" status="OK">');
    expect(out).toContain("hello\nworld");
    expect(out).toContain("</output>");
  });

  it("marks errors with status=ERROR", () => {
    const out = formatXmlOutput("bash", { success: false, output: null, error: "command timed out" });
    expect(out).toContain('status="ERROR"');
    expect(out).toContain("command timed out");
  });

  it("truncates oversized output to protect the context window", () => {
    const huge = "a".repeat(20000);
    const out = formatXmlOutput("bash", { success: true, output: huge });
    expect(out.length).toBeLessThan(huge.length);
    expect(out).toMatch(/truncated \d+ bytes/);
  });

  it("serializes object output as JSON", () => {
    const out = formatXmlOutput("save_finding", {
      success: true,
      output: { id: "f1", title: "Test" },
    });
    expect(out).toContain('"id": "f1"');
    expect(out).toContain('"title": "Test"');
  });
});

describe("formatXmlOutputBatch", () => {
  it("joins multiple results with blank-line separators", () => {
    const text = formatXmlOutputBatch([
      { name: "bash", result: { success: true, output: "ls output" } },
      { name: "bash", result: { success: false, output: null, error: "timeout" } },
    ]);
    expect(text.match(/<output /g)).toHaveLength(2);
    expect(text).toContain("ls output");
    expect(text).toContain("timeout");
  });
});

describe("resolveDispatchMode", () => {
  const origEnv = process.env["0SEC_DISPATCH"];
  afterEach(() => {
    if (origEnv === undefined) {
      delete process.env["0SEC_DISPATCH"];
    } else {
      process.env["0SEC_DISPATCH"] = origEnv;
    }
  });

  it("returns the explicit mode when set", () => {
    expect(resolveDispatchMode("xml", "claude-3-5-sonnet")).toBe("xml");
    expect(resolveDispatchMode("json", "deepseek-chat")).toBe("json");
  });

  it("auto-picks XML for cheap providers", () => {
    delete process.env["0SEC_DISPATCH"];
    expect(resolveDispatchMode("auto", "deepseek/deepseek-chat")).toBe("xml");
    expect(resolveDispatchMode("auto", "google/gemini-flash-1.5")).toBe("xml");
    expect(resolveDispatchMode("auto", "openrouter/auto")).toBe("xml");
    expect(resolveDispatchMode("auto", "qwen-2.5-72b")).toBe("xml");
    expect(resolveDispatchMode("auto", "mistral-large")).toBe("xml");
    expect(resolveDispatchMode("auto", "meta-llama/llama-3.1-405b")).toBe("xml");
  });

  it("auto-picks JSON for premium providers", () => {
    delete process.env["0SEC_DISPATCH"];
    expect(resolveDispatchMode("auto", "claude-3-5-sonnet-20240620")).toBe("json");
    expect(resolveDispatchMode("auto", "gpt-4o")).toBe("json");
    expect(resolveDispatchMode("auto", undefined)).toBe("json");
  });

  it("0SEC_DISPATCH env var overrides auto", () => {
    process.env["0SEC_DISPATCH"] = "xml";
    expect(resolveDispatchMode("auto", "claude-3-5-sonnet")).toBe("xml");
    process.env["0SEC_DISPATCH"] = "json";
    expect(resolveDispatchMode("auto", "deepseek-chat")).toBe("json");
  });
});

describe("buildXmlDispatchPrompt", () => {
  it("includes the four protocol verbs and the target", () => {
    const prompt = buildXmlDispatchPrompt({
      role: "audit",
      target: "http://example.test",
      scanId: "scan-123",
      tools: [],
    });
    expect(prompt).toContain("http://example.test");
    expect(prompt).toContain("scan-123");
    expect(prompt).toContain("<command>");
    expect(prompt).toContain("<flag>");
    expect(prompt).toContain("<finding>");
    expect(prompt).toContain("<note>");
    expect(prompt).toContain("<output");
  });
});
