/**
 * Human-readable preview of a tool call for the scan TUI sub-action stream.
 *
 * The agent loop emits one sub-action per tool call so users can see what
 * the agent is actually *doing* turn-by-turn instead of a useless
 * `turn 3: bash, bash, bash`. This module turns a ToolCall into a short,
 * single-line string like `bash: curl -sI https://example.com/admin`.
 *
 * Each formatter is tolerant: the arguments field is `Record<string, unknown>`
 * and we never throw on unexpected shapes. If a formatter doesn't recognise
 * the arguments it falls back to the plain tool name.
 */

import type { ToolCall } from "./types.js";

/**
 * Hard cap on the preview length stored in the scan action history. The TUI
 * does its own per-row truncation (60 chars compact, 120 verbose) at render
 * time; this is just a sanity ceiling so we don't stuff multi-kilobyte bash
 * scripts into memory unbounded. 240 is roughly two terminal lines of 120
 * wrapped width, which is plenty for the verbose toolcall preview.
 */
const MAX_PREVIEW_CHARS = 240;

function clip(s: string): string {
  const cleaned = s.replace(/\s+/g, " ").trim();
  if (cleaned.length <= MAX_PREVIEW_CHARS) return cleaned;
  return cleaned.slice(0, MAX_PREVIEW_CHARS) + "...";
}

function stringArg(args: Record<string, unknown>, key: string): string | undefined {
  const v = args[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

/**
 * Build a one-line preview like `bash: curl -sI https://...` or
 * `http_request: POST https://target/login` for display in the scan TUI.
 * Always safe to call on any ToolCall shape; never throws.
 */
export function toolCallPreview(call: ToolCall): string {
  const name = call.name;
  const args = (call.arguments ?? {}) as Record<string, unknown>;

  switch (name) {
    case "bash": {
      const command = stringArg(args, "command");
      return command ? clip(`bash: ${command}`) : "bash";
    }
    case "http_request": {
      const url = stringArg(args, "url");
      if (!url) return "http_request";
      const method = stringArg(args, "method") ?? "GET";
      return clip(`http_request: ${method} ${url}`);
    }
    case "crawl": {
      const url = stringArg(args, "url");
      return url ? clip(`crawl: ${url}`) : "crawl";
    }
    case "submit_form": {
      const url = stringArg(args, "url");
      return url ? clip(`submit_form: ${url}`) : "submit_form";
    }
    case "browser": {
      const action = stringArg(args, "action");
      const url = stringArg(args, "url");
      if (action && url) return clip(`browser.${action}: ${url}`);
      if (action) return clip(`browser.${action}`);
      if (url) return clip(`browser: ${url}`);
      return "browser";
    }
    case "send_prompt": {
      const target = stringArg(args, "target");
      const prompt = stringArg(args, "prompt");
      if (target && prompt) return clip(`send_prompt: ${target} → ${prompt}`);
      if (prompt) return clip(`send_prompt: ${prompt}`);
      return "send_prompt";
    }
    case "save_finding": {
      const severity = stringArg(args, "severity") ?? "?";
      const title = stringArg(args, "title") ?? "";
      return clip(`save_finding: [${severity}] ${title}`);
    }
    case "save_target_info": {
      const type = stringArg(args, "type");
      return type ? `save_target_info: ${type}` : "save_target_info";
    }
    case "done": {
      const summary = stringArg(args, "summary");
      return summary ? clip(`done: ${summary}`) : "done";
    }
    default: {
      // Generic fallback: pick the first non-empty string argument, if any,
      // and append it to the tool name. This keeps future tools readable
      // without having to update this switch for every new tool added.
      for (const [, v] of Object.entries(args)) {
        if (typeof v === "string" && v.length > 0) {
          return clip(`${name}: ${v}`);
        }
      }
      return name;
    }
  }
}

/**
 * Format a whole turn's worth of tool calls as a single preview string
 * (when the caller wants one line per turn) or return null if the turn
 * had no tool calls at all. Callers that want one sub-action *per tool
 * call* (richer history) should map over the array themselves instead.
 */
export function summariseTurnToolCalls(calls: readonly ToolCall[]): string | null {
  if (calls.length === 0) return null;
  if (calls.length === 1) return toolCallPreview(calls[0]);
  return calls.map((c) => toolCallPreview(c)).join(" | ");
}
