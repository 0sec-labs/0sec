import { describe, expect, it } from "vitest";
import { toolCallPreview, summariseTurnToolCalls } from "./tool-preview.js";
import type { ToolCall } from "./types.js";

function call(name: string, args: Record<string, unknown> = {}): ToolCall {
  return { name, arguments: args };
}

describe("toolCallPreview", () => {
  it("bash previews the command", () => {
    expect(toolCallPreview(call("bash", { command: "curl -sI https://doruk.ch" })))
      .toBe("bash: curl -sI https://doruk.ch");
  });

  it("bash without a command falls back to the tool name", () => {
    expect(toolCallPreview(call("bash", {}))).toBe("bash");
    expect(toolCallPreview(call("bash", { command: "" }))).toBe("bash");
  });

  it("bash preserves pipes, redirects, and multi-word commands", () => {
    expect(toolCallPreview(call("bash", {
      command: "curl -s https://t/ | grep -oE 'form[^>]+' | head -5",
    })))
      .toContain("grep -oE 'form[^>]+'");
  });

  it("bash collapses internal whitespace so the preview stays one-line", () => {
    const preview = toolCallPreview(call("bash", {
      command: "echo   'hello\nworld'",
    }));
    expect(preview).not.toContain("\n");
    expect(preview).toContain("echo");
  });

  it("http_request previews as METHOD url", () => {
    expect(toolCallPreview(call("http_request", {
      url: "https://example.com/login",
      method: "POST",
    })))
      .toBe("http_request: POST https://example.com/login");
  });

  it("http_request defaults to GET when method is missing", () => {
    expect(toolCallPreview(call("http_request", {
      url: "https://example.com/",
    })))
      .toBe("http_request: GET https://example.com/");
  });

  it("crawl previews the URL", () => {
    expect(toolCallPreview(call("crawl", { url: "https://doruk.ch" })))
      .toBe("crawl: https://doruk.ch");
  });

  it("submit_form previews the URL", () => {
    expect(toolCallPreview(call("submit_form", { url: "https://t/login" })))
      .toBe("submit_form: https://t/login");
  });

  it("browser includes action and URL when both are present", () => {
    expect(toolCallPreview(call("browser", { action: "navigate", url: "https://t/" })))
      .toBe("browser.navigate: https://t/");
  });

  it("browser handles action-only and URL-only cases", () => {
    expect(toolCallPreview(call("browser", { action: "screenshot" }))).toBe("browser.screenshot");
    expect(toolCallPreview(call("browser", { url: "https://t/" }))).toBe("browser: https://t/");
  });

  it("save_finding previews as [severity] title", () => {
    expect(toolCallPreview(call("save_finding", {
      severity: "high",
      title: "Reflected XSS in search param",
    })))
      .toBe("save_finding: [high] Reflected XSS in search param");
  });

  it("save_finding falls back gracefully when fields are missing", () => {
    // `clip()` trims trailing whitespace, so the blank title collapses the
    // "] " suffix down to "]".
    expect(toolCallPreview(call("save_finding", { severity: "info" })))
      .toBe("save_finding: [info]");
    expect(toolCallPreview(call("save_finding", {})))
      .toBe("save_finding: [?]");
  });

  it("unknown tools fall back to the first string argument", () => {
    expect(toolCallPreview(call("custom_tool", { target: "foo", count: 5 })))
      .toBe("custom_tool: foo");
  });

  it("unknown tools with no string args fall back to the bare name", () => {
    expect(toolCallPreview(call("mystery", { count: 42, enabled: true })))
      .toBe("mystery");
  });

  it("does not throw on null/undefined arguments", () => {
    expect(toolCallPreview({ name: "bash", arguments: null as any })).toBe("bash");
    expect(toolCallPreview({ name: "bash", arguments: undefined as any })).toBe("bash");
  });

  it("clips previews longer than MAX_PREVIEW_CHARS and appends an ellipsis", () => {
    const huge = "a".repeat(500);
    const preview = toolCallPreview(call("bash", { command: huge }));
    expect(preview.length).toBeLessThanOrEqual(243); // 240 + "..."
    expect(preview.endsWith("...")).toBe(true);
  });
});

describe("summariseTurnToolCalls", () => {
  it("returns null for an empty turn", () => {
    expect(summariseTurnToolCalls([])).toBeNull();
  });

  it("returns a single preview when the turn had exactly one tool call", () => {
    expect(summariseTurnToolCalls([call("crawl", { url: "https://t" })]))
      .toBe("crawl: https://t");
  });

  it("joins multiple tool calls with a pipe separator", () => {
    const s = summariseTurnToolCalls([
      call("bash", { command: "id" }),
      call("bash", { command: "whoami" }),
    ]);
    expect(s).toBe("bash: id | bash: whoami");
  });

  it("preserves order across heterogeneous tool calls in a single turn", () => {
    const s = summariseTurnToolCalls([
      call("http_request", { url: "https://t/", method: "GET" }),
      call("save_finding", { severity: "medium", title: "cors" }),
    ]);
    expect(s).toBe("http_request: GET https://t/ | save_finding: [medium] cors");
  });
});
