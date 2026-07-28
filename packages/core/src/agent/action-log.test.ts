/**
 * Action-level durable action log.
 *
 * Covers the three properties the SOC cross-reference deliverable depends on:
 * arguments are redacted before they are persisted, the payload keeps the
 * pre-upgrade `tools` mirror so old readers keep working, and a reader handed
 * a pre-upgrade row does not crash.
 */

import { describe, it, expect } from "vitest";
import {
  newCorrelationId,
  redactedArgsPreview,
  buildToolCallLogEntry,
  buildToolCallsPayload,
  readToolCallNames,
  ACTION_LOG_ARG_VALUE_MAX,
  ACTION_LOG_ARGS_MAX,
} from "./action-log.js";

describe("redactedArgsPreview — evidence retained", () => {
  it("keeps the method + URL a SOC analyst needs to cross-reference", () => {
    const out = redactedArgsPreview({ url: "https://target.example/x", method: "GET" });
    expect(out).toContain("url: https://target.example/x");
    expect(out).toContain("method: GET");
  });

  it("returns an empty string for missing / empty arguments", () => {
    expect(redactedArgsPreview(undefined)).toBe("");
    expect(redactedArgsPreview({})).toBe("");
  });

  it("renders non-string values without throwing", () => {
    const out = redactedArgsPreview({ depth: 3, follow: true, tags: ["a", "b"], nothing: null });
    expect(out).toContain("depth: 3");
    expect(out).toContain("follow: true");
    expect(out).toContain('tags: ["a","b"]');
    expect(out).toContain("nothing: null");
  });
});

describe("redactedArgsPreview — redaction", () => {
  it("masks an Authorization header nested in the headers object", () => {
    const out = redactedArgsPreview({
      url: "https://target.example/x",
      headers: { Authorization: "Bearer sup3rs3cr3t", "Content-Type": "application/json" },
    });
    expect(out).not.toContain("sup3rs3cr3t");
    expect(out).toContain("<REDACTED-Authorization>");
    // Non-sensitive headers survive — this is evidence, not a black box.
    expect(out).toContain("Content-Type: application/json");
  });

  it("masks Cookie and Set-Cookie header values", () => {
    const out = redactedArgsPreview({
      headers: { Cookie: "session=abc123", "Set-Cookie": "refresh=xyz789" },
    });
    expect(out).not.toContain("abc123");
    expect(out).not.toContain("xyz789");
  });

  it("masks a bearer token embedded in a bash command", () => {
    const out = redactedArgsPreview({
      command: `curl -H "Authorization: Bearer ***REMOVED***" https://target.example/x`,
    });
    expect(out).not.toContain("eyJhbGciOiJIUzI1NiJ9");
    expect(out).toContain("https://target.example/x");
  });

  it("masks an AWS access key anywhere in the args", () => {
    const out = redactedArgsPreview({ command: "export AWS_KEY=***REMOVED*** && aws s3 ls" });
    expect(out).not.toContain("***REMOVED***");
    expect(out).toContain("<REDACTED-AWS-KEY>");
  });

  it("masks a JWT in a request body", () => {
    const jwt = `${"a".repeat(40)}.${"b".repeat(40)}.${"c".repeat(40)}`;
    const out = redactedArgsPreview({ body: `{"token":"${jwt}"}` });
    expect(out).not.toContain(jwt);
    expect(out).toContain("<REDACTED-JWT>");
  });

  it("redacts before truncating so a cut can never leave a secret prefix", () => {
    // A cookie value far longer than the per-value cap: if truncation ran
    // first, the surviving prefix would be a usable session token.
    const cookie = "session=" + "S".repeat(ACTION_LOG_ARG_VALUE_MAX * 3);
    const out = redactedArgsPreview({ headers: { Cookie: cookie } });
    expect(out).not.toContain("SSSSSSSSSS");
    expect(out).toContain("<REDACTED-Cookie>");
  });
});

describe("redactedArgsPreview — truncation", () => {
  it("caps a single argument line at the per-value limit", () => {
    const out = redactedArgsPreview({ command: "A".repeat(5_000) });
    const line = out.split("\n")[0];
    expect(line.length).toBeLessThanOrEqual(ACTION_LOG_ARG_VALUE_MAX + "command: ".length + 3);
    expect(out.endsWith("...")).toBe(true);
  });

  it("caps the whole preview at the overall limit", () => {
    const args: Record<string, unknown> = {};
    for (let i = 0; i < 50; i++) args[`k${i}`] = "V".repeat(400);
    const out = redactedArgsPreview(args);
    expect(out.length).toBeLessThanOrEqual(ACTION_LOG_ARGS_MAX + 3);
  });
});

describe("buildToolCallLogEntry", () => {
  it("records per-action wall clock, duration, outcome, and correlation id", () => {
    const entry = buildToolCallLogEntry({
      call: { name: "http_request", arguments: { url: "https://target.example/x", method: "GET" } },
      correlationId: "corr-1",
      startedAt: 1_700_000_000_412,
      endedAt: 1_700_000_000_512,
      result: { success: true },
    });
    expect(entry).toMatchObject({
      name: "http_request",
      startedAt: 1_700_000_000_412,
      durationMs: 100,
      ok: true,
      correlationId: "corr-1",
    });
    expect(entry.error).toBeUndefined();
    expect(entry.args).toContain("GET");
  });

  it("carries the error message through on failure", () => {
    const entry = buildToolCallLogEntry({
      call: { name: "bash", arguments: { command: "false" } },
      correlationId: "corr-2",
      startedAt: 10,
      endedAt: 15,
      result: { success: false, error: "exit 1" },
    });
    expect(entry.ok).toBe(false);
    expect(entry.error).toBe("exit 1");
  });

  it("never reports a negative duration if the clock steps backwards", () => {
    const entry = buildToolCallLogEntry({
      call: { name: "done", arguments: {} },
      correlationId: "corr-3",
      startedAt: 100,
      endedAt: 90,
      result: { success: true },
    });
    expect(entry.durationMs).toBe(0);
  });
});

describe("buildToolCallsPayload", () => {
  const entries = [
    buildToolCallLogEntry({
      call: { name: "http_request", arguments: { url: "https://target.example/x" } },
      correlationId: "c1",
      startedAt: 1_000,
      endedAt: 1_100,
      result: { success: true },
    }),
    buildToolCallLogEntry({
      call: { name: "bash", arguments: { command: "id" } },
      correlationId: "c2",
      startedAt: 1_100,
      endedAt: 1_150,
      result: { success: false, error: "denied" },
    }),
  ];

  it("emits the action-level calls array", () => {
    const payload = buildToolCallsPayload(12, entries);
    expect(payload.turn).toBe(12);
    expect(payload.calls).toHaveLength(2);
    expect(payload.calls[0].correlationId).toBe("c1");
    expect(payload.calls[1].startedAt).toBe(1_100);
  });

  it("keeps the pre-upgrade tools + results mirrors for old readers", () => {
    const payload = buildToolCallsPayload(12, entries);
    expect(payload.tools).toEqual(["http_request", "bash"]);
    expect(payload.results).toEqual([
      { success: true, error: undefined },
      { success: false, error: "denied" },
    ]);
  });
});

describe("readToolCallNames — both shapes", () => {
  it("reads names off a new action-level row", () => {
    const payload = buildToolCallsPayload(1, [
      buildToolCallLogEntry({
        call: { name: "crawl", arguments: { url: "https://target.example" } },
        correlationId: "c1",
        startedAt: 1,
        endedAt: 2,
        result: { success: true },
      }),
    ]);
    expect(readToolCallNames(payload)).toEqual(["crawl"]);
  });

  it("reads names off a pre-upgrade turn-level row without crashing", () => {
    const oldRow = {
      turn: 12,
      tools: ["http_request", "bash"],
      results: [{ success: true }, { success: true }],
    };
    expect(readToolCallNames(oldRow)).toEqual(["http_request", "bash"]);
  });

  it("tolerates null, non-objects, and malformed entries", () => {
    expect(readToolCallNames(null)).toEqual([]);
    expect(readToolCallNames(undefined)).toEqual([]);
    expect(readToolCallNames("nope")).toEqual([]);
    expect(readToolCallNames({})).toEqual([]);
    expect(readToolCallNames({ calls: "nope" })).toEqual([]);
    expect(readToolCallNames({ calls: [null, 5, { name: "bash" }] })).toEqual(["bash"]);
    expect(readToolCallNames({ tools: [1, "bash", null] })).toEqual(["bash"]);
  });
});

describe("newCorrelationId", () => {
  it("is unique per invocation", () => {
    const ids = new Set(Array.from({ length: 100 }, () => newCorrelationId()));
    expect(ids.size).toBe(100);
  });
});
