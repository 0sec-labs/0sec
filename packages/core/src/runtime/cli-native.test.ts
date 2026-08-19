import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { EventEmitter } from "node:events";

// Mock child_process.spawn before importing the module under test so the
// hoisted import inside cli-native.ts picks up the mock.
const spawnMock = vi.fn();
vi.mock("node:child_process", () => ({
  spawn: (...args: unknown[]) => spawnMock(...args),
}));

import {
  CliNativeRuntime,
  buildClaudePromptFromLastUser,
  mapClaudeStopReason,
} from "./cli-native.js";
import type { NativeMessage } from "./types.js";

/**
 * Build a fake `claude` subprocess that:
 *   - emits the canned stream-json lines on stdout
 *   - closes with the given exit code
 *
 * Returns a tuple of the fake child and a function to fire the events,
 * so tests can control the timing of the close event.
 */
function makeFakeChild(opts: {
  stdoutLines: string[];
  stderr?: string;
  exitCode?: number;
}) {
  const child = new EventEmitter() as EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: (sig?: string) => void;
  };
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = vi.fn();

  // Fire data + close on the next microtask so the runtime has time to
  // attach its listeners.
  Promise.resolve().then(() => {
    for (const line of opts.stdoutLines) {
      child.stdout.emit("data", Buffer.from(line + "\n", "utf-8"));
    }
    if (opts.stderr) {
      child.stderr.emit("data", Buffer.from(opts.stderr, "utf-8"));
    }
    child.emit("close", opts.exitCode ?? 0);
  });

  return child;
}

describe("buildClaudePromptFromLastUser", () => {
  it("returns empty string when no user message exists", () => {
    expect(buildClaudePromptFromLastUser([])).toBe("");
  });

  it("returns plain text when last user message is just text", () => {
    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "hello" }] },
    ];
    expect(buildClaudePromptFromLastUser(messages)).toBe("hello");
  });

  it("serializes tool_results as JSON with a marker", () => {
    const messages: NativeMessage[] = [
      {
        role: "assistant",
        content: [
          { type: "tool_use", id: "tu_1", name: "http_request", input: { url: "x" } },
        ],
      },
      {
        role: "user",
        content: [
          { type: "tool_result", tool_use_id: "tu_1", content: "200 OK" },
        ],
      },
    ];
    const prompt = buildClaudePromptFromLastUser(messages);
    expect(prompt).toContain("[0sec:tool_results]");
    expect(prompt).toContain('"tool_use_id": "tu_1"');
    expect(prompt).toContain('"content": "200 OK"');
  });

  it("uses the LAST user message, not the first", () => {
    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "first" }] },
      { role: "assistant", content: [{ type: "text", text: "ack" }] },
      { role: "user", content: [{ type: "text", text: "second" }] },
    ];
    expect(buildClaudePromptFromLastUser(messages)).toBe("second");
  });

  it("merges tool_result + free text in the same user turn", () => {
    const messages: NativeMessage[] = [
      {
        role: "user",
        content: [
          { type: "tool_result", tool_use_id: "tu_x", content: "ok", is_error: true },
          { type: "text", text: "Now what?" },
        ],
      },
    ];
    const prompt = buildClaudePromptFromLastUser(messages);
    expect(prompt).toContain("[0sec:tool_results]");
    expect(prompt).toContain('"is_error": true');
    expect(prompt).toContain("Now what?");
  });
});

describe("mapClaudeStopReason", () => {
  it("maps tool_use", () => {
    expect(mapClaudeStopReason("tool_use")).toBe("tool_use");
  });
  it("maps end_turn / success / stop_sequence", () => {
    expect(mapClaudeStopReason("end_turn")).toBe("end_turn");
    expect(mapClaudeStopReason("success")).toBe("end_turn");
    expect(mapClaudeStopReason("stop_sequence")).toBe("end_turn");
  });
  it("maps max_tokens variants", () => {
    expect(mapClaudeStopReason("max_tokens")).toBe("max_tokens");
    expect(mapClaudeStopReason("success_max_turns")).toBe("max_tokens");
  });
  it("maps error variants", () => {
    expect(mapClaudeStopReason("error")).toBe("error");
    expect(mapClaudeStopReason("error_max_turns")).toBe("error");
    expect(mapClaudeStopReason("error_during_execution")).toBe("error");
  });
  it("falls back to end_turn for unknown / undefined", () => {
    expect(mapClaudeStopReason(undefined)).toBe("end_turn");
    expect(mapClaudeStopReason("brand_new_reason")).toBe("end_turn");
  });
});

describe("CliNativeRuntime — claude subscription mode", () => {
  beforeEach(() => {
    spawnMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("rejects type=api at construction time", () => {
    expect(
      () =>
        new CliNativeRuntime({
          type: "api" as any,
          timeout: 1000,
        }),
    ).toThrow(/CliNativeRuntime/);
  });

  it("returns a clear error for codex / gemini (no native multi-turn yet)", async () => {
    const rt = new CliNativeRuntime({ type: "codex", timeout: 1000 });
    const result = await rt.executeNative(
      "system",
      [{ role: "user", content: [{ type: "text", text: "hi" }] }],
      [],
    );
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("only supported for the 'claude' CLI runtime");
    expect(spawnMock).not.toHaveBeenCalled();
  });

  it("turn 1: spawns claude with -p, --output-format stream-json, and --system-prompt", async () => {
    const sessionId = "session-abc-123";
    spawnMock.mockImplementationOnce(() =>
      makeFakeChild({
        stdoutLines: [
          JSON.stringify({
            type: "system",
            subtype: "init",
            session_id: sessionId,
          }),
          JSON.stringify({
            type: "assistant",
            session_id: sessionId,
            message: {
              content: [
                { type: "text", text: "I'll probe the target." },
                {
                  type: "tool_use",
                  id: "tu_1",
                  name: "http_request",
                  input: { url: "https://example.com" },
                },
              ],
              usage: { input_tokens: 100, output_tokens: 25 },
            },
          }),
          JSON.stringify({
            type: "result",
            stop_reason: "tool_use",
            usage: { input_tokens: 100, output_tokens: 25 },
          }),
        ],
        exitCode: 0,
      }),
    );

    const rt = new CliNativeRuntime({ type: "claude", timeout: 5000 });
    const result = await rt.executeNative(
      "you are 0sec attack agent",
      [{ role: "user", content: [{ type: "text", text: "scan https://x" }] }],
      [],
    );

    expect(spawnMock).toHaveBeenCalledTimes(1);
    const [cmd, args] = spawnMock.mock.calls[0]!;
    expect(cmd).toBe("claude");
    expect(args).toContain("-p");
    expect(args).toContain("--output-format");
    expect(args).toContain("stream-json");
    // Turn 1 must NOT have --resume
    expect(args).not.toContain("--resume");
    // Turn 1 SHOULD pass the system prompt
    const sysIdx = args.indexOf("--system-prompt");
    expect(sysIdx).toBeGreaterThan(-1);
    expect(args[sysIdx + 1]).toBe("you are 0sec attack agent");

    // Result blocks
    expect(result.stopReason).toBe("tool_use");
    expect(result.content).toEqual([
      { type: "text", text: "I'll probe the target." },
      {
        type: "tool_use",
        id: "tu_1",
        name: "http_request",
        input: { url: "https://example.com" },
      },
    ]);
    expect(result.usage).toEqual({ inputTokens: 100, outputTokens: 25 });
  });

  it("turn N: spawns claude with --resume <session_id> and JSON-encoded tool_results", async () => {
    const sessionId = "session-xyz-789";

    // Turn 1 — capture session id from system event.
    spawnMock.mockImplementationOnce(() =>
      makeFakeChild({
        stdoutLines: [
          JSON.stringify({
            type: "system",
            subtype: "init",
            session_id: sessionId,
          }),
          JSON.stringify({
            type: "assistant",
            session_id: sessionId,
            message: {
              content: [
                { type: "tool_use", id: "tu_a", name: "http_request", input: { url: "https://x" } },
              ],
              usage: { input_tokens: 50, output_tokens: 10 },
            },
          }),
          JSON.stringify({ type: "result", stop_reason: "tool_use" }),
        ],
        exitCode: 0,
      }),
    );

    // Turn 2 — should --resume.
    spawnMock.mockImplementationOnce(() =>
      makeFakeChild({
        stdoutLines: [
          JSON.stringify({
            type: "assistant",
            session_id: sessionId,
            message: {
              content: [{ type: "text", text: "Got the response, finishing up." }],
              usage: { input_tokens: 60, output_tokens: 8 },
            },
          }),
          JSON.stringify({ type: "result", stop_reason: "end_turn" }),
        ],
        exitCode: 0,
      }),
    );

    const rt = new CliNativeRuntime({ type: "claude", timeout: 5000 });

    // Turn 1
    await rt.executeNative(
      "system prompt",
      [{ role: "user", content: [{ type: "text", text: "go" }] }],
      [],
    );

    // Turn 2 — feed back the tool_result for tu_a.
    const result2 = await rt.executeNative(
      "system prompt",
      [
        { role: "user", content: [{ type: "text", text: "go" }] },
        {
          role: "assistant",
          content: [
            { type: "tool_use", id: "tu_a", name: "http_request", input: { url: "https://x" } },
          ],
        },
        {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: "tu_a", content: '{"status":200}' },
          ],
        },
      ],
      [],
    );

    expect(spawnMock).toHaveBeenCalledTimes(2);
    const [cmd2, args2] = spawnMock.mock.calls[1]!;
    expect(cmd2).toBe("claude");
    const resumeIdx = args2.indexOf("--resume");
    expect(resumeIdx).toBeGreaterThan(-1);
    expect(args2[resumeIdx + 1]).toBe(sessionId);
    // System prompt must NOT be re-sent on resume — Claude Code retains it
    // server-side, and re-passing it would re-prepend on every turn.
    expect(args2).not.toContain("--system-prompt");
    // The prompt argument should carry the JSON-encoded tool_result.
    const pIdx = args2.indexOf("-p");
    expect(pIdx).toBeGreaterThan(-1);
    const promptArg = args2[pIdx + 1] as string;
    expect(promptArg).toContain("[0sec:tool_results]");
    expect(promptArg).toContain('"tool_use_id": "tu_a"');
    expect(promptArg).toContain('"content": "{\\"status\\":200}"');

    expect(result2.stopReason).toBe("end_turn");
    expect(result2.content).toEqual([
      { type: "text", text: "Got the response, finishing up." },
    ]);
  });

  it("surfaces a helpful auth hint when claude exits non-zero with login error", async () => {
    spawnMock.mockImplementationOnce(() =>
      makeFakeChild({
        stdoutLines: [],
        stderr: "Error: Please run claude login\n",
        exitCode: 1,
      }),
    );

    const rt = new CliNativeRuntime({ type: "claude", timeout: 5000 });
    const result = await rt.executeNative(
      "sys",
      [{ role: "user", content: [{ type: "text", text: "hi" }] }],
      [],
    );
    expect(result.stopReason).toBe("error");
    expect(result.error).toMatch(/claude login/i);
  });

  it("forwards onThinking and onUsage callbacks", async () => {
    spawnMock.mockImplementationOnce(() =>
      makeFakeChild({
        stdoutLines: [
          JSON.stringify({ type: "system", subtype: "init", session_id: "s1" }),
          JSON.stringify({
            type: "assistant",
            session_id: "s1",
            message: {
              content: [{ type: "text", text: "thinking..." }],
              usage: { input_tokens: 7, output_tokens: 3 },
            },
          }),
          JSON.stringify({ type: "result", stop_reason: "end_turn" }),
        ],
        exitCode: 0,
      }),
    );

    const onThinking = vi.fn();
    const onUsage = vi.fn();
    const rt = new CliNativeRuntime({ type: "claude", timeout: 5000 });
    await rt.executeNative(
      "sys",
      [{ role: "user", content: [{ type: "text", text: "go" }] }],
      [],
      { onThinking, onUsage },
    );

    expect(onThinking).toHaveBeenCalledWith("thinking...");
    expect(onUsage).toHaveBeenCalledWith({ inputTokens: 7, outputTokens: 3 });
  });

  it("auto-clears cached session id when a resume turn exits non-zero (no infinite stale-resume loop)", async () => {
    // Turn 1 — establishes a session id.
    spawnMock.mockImplementationOnce(() =>
      makeFakeChild({
        stdoutLines: [
          JSON.stringify({ type: "system", subtype: "init", session_id: "stale-id" }),
          JSON.stringify({
            type: "assistant",
            session_id: "stale-id",
            message: {
              content: [{ type: "tool_use", id: "tu_a", name: "http_request", input: {} }],
            },
          }),
          JSON.stringify({ type: "result", stop_reason: "tool_use" }),
        ],
        exitCode: 0,
      }),
    );
    // Turn 2 — `--resume stale-id` fails because Claude Code lost the
    // session server-side. CliNativeRuntime must drop the cached id.
    spawnMock.mockImplementationOnce(() =>
      makeFakeChild({
        stdoutLines: [],
        stderr: "Error: session not found\n",
        exitCode: 1,
      }),
    );
    // Turn 3 — should NOT re-send `--resume stale-id`; it should start
    // a fresh session with `--system-prompt` instead.
    spawnMock.mockImplementationOnce(() =>
      makeFakeChild({
        stdoutLines: [
          JSON.stringify({ type: "system", subtype: "init", session_id: "fresh-id" }),
          JSON.stringify({ type: "result", stop_reason: "end_turn" }),
        ],
        exitCode: 0,
      }),
    );

    const rt = new CliNativeRuntime({ type: "claude", timeout: 5000 });
    await rt.executeNative(
      "sys",
      [{ role: "user", content: [{ type: "text", text: "go" }] }],
      [],
    );
    const r2 = await rt.executeNative(
      "sys",
      [
        { role: "user", content: [{ type: "text", text: "go" }] },
        {
          role: "assistant",
          content: [{ type: "tool_use", id: "tu_a", name: "http_request", input: {} }],
        },
        {
          role: "user",
          content: [{ type: "tool_result", tool_use_id: "tu_a", content: "200" }],
        },
      ],
      [],
    );
    expect(r2.stopReason).toBe("error");

    await rt.executeNative(
      "sys",
      [{ role: "user", content: [{ type: "text", text: "retry" }] }],
      [],
    );

    expect(spawnMock).toHaveBeenCalledTimes(3);
    const args3 = spawnMock.mock.calls[2]![1] as string[];
    // After the failed resume, the next call must start fresh, not
    // replay `--resume stale-id`.
    expect(args3).not.toContain("--resume");
    expect(args3).toContain("--system-prompt");
  });

  it("resetSession() clears the cached session id so the next turn starts fresh", async () => {
    spawnMock.mockImplementation(() =>
      makeFakeChild({
        stdoutLines: [
          JSON.stringify({ type: "system", subtype: "init", session_id: "fresh" }),
          JSON.stringify({ type: "result", stop_reason: "end_turn" }),
        ],
        exitCode: 0,
      }),
    );

    const rt = new CliNativeRuntime({ type: "claude", timeout: 5000 });
    await rt.executeNative(
      "sys",
      [{ role: "user", content: [{ type: "text", text: "first" }] }],
      [],
    );
    rt.resetSession();
    await rt.executeNative(
      "sys",
      [{ role: "user", content: [{ type: "text", text: "second" }] }],
      [],
    );

    expect(spawnMock).toHaveBeenCalledTimes(2);
    // After reset, the second call should NOT carry --resume.
    const args2 = spawnMock.mock.calls[1]![1] as string[];
    expect(args2).not.toContain("--resume");
  });
});
