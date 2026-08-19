import { describe, expect, it } from "vitest";

import { buildConsoleSystemPrompt, createConsoleSession } from "./turn-engine.js";
import type {
  NativeMessage,
  NativeRuntime,
  NativeRuntimeResult,
  NativeToolDef,
} from "../runtime/types.js";

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
    expect(p).toContain("pwnkit operator console");
    expect(p).toContain("https://example.com");
    expect(p).toContain("console-x");
  });

  it("notes when no target is set", () => {
    const p = buildConsoleSystemPrompt({ scanId: "console-y" });
    expect(p).toContain("No target is set yet");
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
