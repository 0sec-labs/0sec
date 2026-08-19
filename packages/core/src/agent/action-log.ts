/**
 * Action-level durable action log for the agent loops.
 *
 * The `tool_calls` DB event used to be turn-level: a list of tool NAMES with
 * one timestamp for the whole turn. That is not enough for a SOC
 * cross-reference — an analyst comparing our log against their WAF/proxy logs
 * needs "at 14:32:07.412 UTC we sent GET https://target/x", per action, not
 * "turn 12 called http_request and bash".
 *
 * This module owns the per-action entry shape, the correlation id that joins a
 * `tool_calls` entry to its `tool_artifact` row, and the redacted argument
 * preview. Both agent loops (`native-loop.ts` and `loop.ts`) build their
 * `tool_calls` payload through here so the persisted shape stays identical.
 *
 * Redaction is NOT a second code path: it delegates to the same
 * `redactSensitiveHeaders` sweep the disclosure renderer uses, which is why
 * arguments are rendered as line-oriented `key: value` text (with nested
 * objects such as `headers` expanded one level) rather than JSON — the sweep
 * is line-oriented for header names and would miss `{"Cookie":"..."}`.
 */

import { randomUUID } from "node:crypto";
import { redactSensitiveHeaders } from "../disclose/template.js";
import type { ToolCall } from "./types.js";

/**
 * Per-argument cap on the rendered preview, matching the bash-command capture
 * cap in `tools.ts` (500). Applied AFTER redaction so a truncation can never
 * slice a secret in half and leak the surviving prefix.
 */
export const ACTION_LOG_ARG_VALUE_MAX = 500;

/**
 * Whole-preview cap, matching the request-body capture cap in `tools.ts`
 * (2000). Also applied after redaction.
 */
export const ACTION_LOG_ARGS_MAX = 2000;

/**
 * Bound on how much of a single raw argument is fed into the redaction sweep.
 * Purely a cost guard against multi-megabyte bodies; well above the caps above.
 */
const RAW_VALUE_SCAN_MAX = 20_000;

/** One tool invocation, with its own wall clock. */
export interface ToolCallLogEntry {
  name: string;
  /** Redacted, truncated `key: value` rendering of the call arguments. */
  args: string;
  /** Epoch ms at which the invocation started. */
  startedAt: number;
  durationMs: number;
  ok: boolean;
  error?: string;
  /** Joins this entry to the `tool_artifact` row emitted by the same call. */
  correlationId: string;
}

/**
 * Payload persisted under `eventType: "tool_calls"`.
 *
 * `calls` is the action-level truth. `tools` / `results` are kept for
 * backward compatibility: this is an append-only audit table, so historical
 * rows only have the old shape and every reader has to tolerate both anyway.
 */
export interface ToolCallsLogPayload extends Record<string, unknown> {
  turn: number;
  calls: ToolCallLogEntry[];
  /** Back-compat mirror of `calls[].name`. */
  tools: string[];
  /** Back-compat mirror of `calls[].ok` / `calls[].error`. */
  results: Array<{ success: boolean; error?: string }>;
}

/** Fresh correlation id for one tool invocation. */
export function newCorrelationId(): string {
  return randomUUID();
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max)}...`;
}

function scalarText(v: unknown): string {
  if (typeof v === "string") return v;
  if (v === null) return "null";
  if (v === undefined) return "undefined";
  if (typeof v === "object") {
    try {
      return JSON.stringify(v) ?? String(v);
    } catch {
      return "[unserializable]";
    }
  }
  return String(v);
}

/**
 * Render a tool call's arguments as a redacted, truncated preview.
 *
 * Never throws: an unexpected argument shape degrades to a best-effort string.
 * Order of operations matters — redact the full text first, truncate second,
 * so a cut can't strip the tail of a token and leave its prefix in the log.
 */
export function redactedArgsPreview(args: Record<string, unknown> | undefined): string {
  let block: string;
  try {
    const lines: string[] = [];
    for (const [key, value] of Object.entries(args ?? {})) {
      if (value !== null && typeof value === "object" && !Array.isArray(value)) {
        // Expand one level so header maps land as `Name: value` lines the
        // redaction sweep recognises.
        lines.push(`${key}:`);
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
          lines.push(`  ${k}: ${truncate(scalarText(v), RAW_VALUE_SCAN_MAX)}`);
        }
      } else {
        lines.push(`${key}: ${truncate(scalarText(value), RAW_VALUE_SCAN_MAX)}`);
      }
    }
    block = lines.join("\n");
  } catch {
    block = "";
  }
  if (!block) return "";
  const redacted = redactSensitiveHeaders(block);
  const capped = redacted
    .split("\n")
    .map((line) => truncate(line, ACTION_LOG_ARG_VALUE_MAX))
    .join("\n");
  return truncate(capped, ACTION_LOG_ARGS_MAX);
}

/** Build one action-level log entry for a completed tool invocation. */
export function buildToolCallLogEntry(input: {
  call: ToolCall;
  correlationId: string;
  startedAt: number;
  endedAt: number;
  result: { success: boolean; error?: string };
}): ToolCallLogEntry {
  const { call, correlationId, startedAt, endedAt, result } = input;
  return {
    name: call.name,
    args: redactedArgsPreview(call.arguments),
    startedAt,
    durationMs: Math.max(0, endedAt - startedAt),
    ok: result.success,
    ...(result.error !== undefined ? { error: result.error } : {}),
    correlationId,
  };
}

/**
 * Assemble the `tool_calls` event payload, emitting the action-level `calls`
 * array plus the legacy `tools` / `results` mirrors.
 */
export function buildToolCallsPayload(
  turn: number,
  entries: readonly ToolCallLogEntry[],
): ToolCallsLogPayload {
  return {
    turn,
    calls: [...entries],
    tools: entries.map((e) => e.name),
    results: entries.map((e) => ({ success: e.ok, error: e.error })),
  };
}

/**
 * Read tool names off a `tool_calls` payload of EITHER shape.
 *
 * New rows carry `calls[].name`; rows written before the action-level upgrade
 * only carry `tools: string[]`. Readers must not assume one or the other.
 * Never throws on a malformed payload — returns an empty array.
 */
export function readToolCallNames(payload: unknown): string[] {
  if (!payload || typeof payload !== "object") return [];
  const p = payload as Record<string, unknown>;
  if (Array.isArray(p.calls)) {
    const names = p.calls
      .map((c) =>
        c && typeof c === "object" && typeof (c as Record<string, unknown>).name === "string"
          ? ((c as Record<string, unknown>).name as string)
          : null,
      )
      .filter((n): n is string => n !== null);
    if (names.length > 0) return names;
  }
  if (Array.isArray(p.tools)) {
    return p.tools.filter((t): t is string => typeof t === "string");
  }
  return [];
}
