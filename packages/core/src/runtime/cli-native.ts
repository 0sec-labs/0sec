import { spawn, type ChildProcess } from "node:child_process";
import type {
  NativeRuntime,
  NativeMessage,
  NativeContentBlock,
  NativeToolDef,
  NativeRuntimeResult,
  NativeStreamCallbacks,
  RuntimeConfig,
  RuntimeType,
} from "./types.js";

/**
 * CliNativeRuntime — wraps a CLI runtime (`claude`, `codex`, `gemini`) so
 * that it satisfies the {@link NativeRuntime} contract used by
 * `runNativeAgentLoop()`.
 *
 * The motivation is subscription auth: users who pay for Claude Max /
 * ChatGPT / Gemini already have working CLI auth on their machine, but
 * the legacy {@link Runtime} interface only supports a single
 * round-trip per call. The native loop drives a multi-turn conversation
 * through structured `tool_use` / `tool_result` blocks, which until now
 * required a raw API key.
 *
 * ## Strategy: session resume
 *
 * Claude Code emits a `session_id` in its `system` init event and on
 * every subsequent `assistant` event. We capture it on turn 1 and pass
 * `--resume <session_id>` on every later call. Claude Code holds the
 * conversation server-side, so we only need to feed the *latest* user
 * turn (a JSON-encoded array of `tool_result` blocks plus any free
 * text) on each invocation.
 *
 * Codex and Gemini are not currently supported for multi-turn — their
 * resume semantics are either undocumented or differ enough that this
 * PR keeps the surface area small. They fall through with a clear
 * error directing the user to `--runtime claude` or to set an API key.
 *
 * ## Known tradeoffs (called out in the bounty discussion)
 *
 * - **Dual context windows.** Claude Code manages its own context
 *   internally; pwnkit's native loop also manages context (compaction,
 *   message history). Both are running, side-by-side, on the same
 *   conversation. This is acceptable: Claude Code's own compaction
 *   prevents the subprocess from blowing up, and pwnkit's native-loop
 *   features (loop detection, early-stop, playbook injection) still
 *   fire on top of whatever Claude Code returns.
 * - **Token usage opacity.** stream-json reports the same token counts
 *   the Anthropic API returns to Claude Code itself, which is good
 *   enough for soft cost-ceiling enforcement.
 * - **Subprocess fragility.** If the spawn crashes, we surface
 *   `stopReason: "error"`. The native loop's existing retry path
 *   handles that the same way it handles an API 5xx.
 */
export class CliNativeRuntime implements NativeRuntime {
  readonly type: RuntimeType;
  private config: RuntimeConfig;
  private command: string;
  /** Populated from the first turn's stream-json `system` event. */
  private sessionId: string | undefined;

  constructor(config: RuntimeConfig) {
    if (config.type === "api") {
      throw new Error(
        "CliNativeRuntime does not support type=api. Use LlmApiRuntime instead.",
      );
    }
    this.type = config.type;
    this.config = config;
    this.command = config.type;
  }

  /**
   * Reset the cached session id so the next call starts a brand-new
   * Claude Code session. The native loop uses this between scans.
   */
  resetSession(): void {
    this.sessionId = undefined;
  }

  async isAvailable(): Promise<boolean> {
    return new Promise((resolve) => {
      const proc = spawn(this.command, ["--version"], {
        cwd: this.config.cwd ?? process.cwd(),
        env: { ...process.env, ...this.config.env },
        stdio: ["ignore", "pipe", "pipe"],
      });
      const timer = setTimeout(() => {
        proc.kill();
        resolve(false);
      }, 5_000);
      proc.on("close", (code) => {
        clearTimeout(timer);
        resolve(code === 0);
      });
      proc.on("error", () => {
        clearTimeout(timer);
        resolve(false);
      });
    });
  }

  async executeNative(
    system: string,
    messages: NativeMessage[],
    _tools: NativeToolDef[],
    callbacks?: NativeStreamCallbacks,
  ): Promise<NativeRuntimeResult> {
    const start = Date.now();

    if (this.type !== "claude") {
      return {
        content: [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: Date.now() - start,
        error:
          `Native multi-turn agent loop is only supported for the 'claude' CLI runtime. ` +
          `'${this.type}' does not yet expose a stable session-resume protocol — ` +
          `use --runtime claude (with 'claude login') for subscription auth, ` +
          `or set ANTHROPIC_API_KEY / OPENROUTER_API_KEY / OPENAI_API_KEY for --runtime api.`,
      };
    }

    // The native loop accumulates the entire conversation in `messages`.
    // Claude Code holds it server-side once we have a session id, so we
    // only need to push the latest user turn down the wire.
    const promptText = buildClaudePromptFromLastUser(messages);
    if (!promptText) {
      return {
        content: [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: Date.now() - start,
        error: "CliNativeRuntime: last message was not a user turn (cannot prompt Claude Code).",
      };
    }

    const args: string[] = ["-p", promptText, "--verbose", "--output-format", "stream-json"];
    if (this.sessionId) {
      args.push("--resume", this.sessionId);
    } else if (system && system.trim().length > 0) {
      // System prompt is only meaningful on the first turn — once a
      // session exists, Claude Code retains the original system prompt
      // and re-passing it via `--append-system-prompt` would silently
      // double-append on every turn.
      args.push("--system-prompt", system);
    }

    return new Promise((resolve) => {
      let stdoutBuf = "";
      let stderrBuf = "";
      let timedOut = false;
      const content: NativeContentBlock[] = [];
      let stopReason: NativeRuntimeResult["stopReason"] = "end_turn";
      let usage: { inputTokens: number; outputTokens: number } | undefined;
      let sawAssistantEnd = false;

      const proc: ChildProcess = spawn(this.command, args, {
        cwd: this.config.cwd ?? process.cwd(),
        env: { ...process.env, ...this.config.env },
        stdio: ["ignore", "pipe", "pipe"],
      });

      proc.stdout?.on("data", (chunk: Buffer) => {
        stdoutBuf += chunk.toString("utf-8");

        // Newline-delimited JSON. Drain complete lines; leave any
        // trailing partial in the buffer for the next chunk.
        let nl = stdoutBuf.indexOf("\n");
        while (nl >= 0) {
          const line = stdoutBuf.slice(0, nl).trim();
          stdoutBuf = stdoutBuf.slice(nl + 1);
          nl = stdoutBuf.indexOf("\n");
          if (!line) continue;
          const event = tryParseJson(line);
          if (!event) continue;

          // Capture session id from the first event that carries it —
          // both the `system` init event and every `assistant` event
          // include `session_id` at the top level.
          if (typeof event.session_id === "string" && !this.sessionId) {
            this.sessionId = event.session_id;
          }

          // ── Assistant message blocks ──
          if (
            event.type === "assistant"
            && event.message
            && Array.isArray(event.message.content)
          ) {
            for (const block of event.message.content) {
              if (block?.type === "text" && typeof block.text === "string") {
                content.push({ type: "text", text: block.text });
                if (block.text.trim()) callbacks?.onThinking?.(block.text);
              } else if (
                block?.type === "tool_use"
                && typeof block.id === "string"
                && typeof block.name === "string"
              ) {
                content.push({
                  type: "tool_use",
                  id: block.id,
                  name: block.name,
                  input:
                    block.input && typeof block.input === "object"
                      ? (block.input as Record<string, unknown>)
                      : {},
                });
              }
            }

            // Surface any per-turn usage Claude Code attaches to
            // assistant events so the cost ceiling has fresher data
            // than waiting for the terminal `result` event.
            const u = event.message?.usage as Record<string, unknown> | undefined;
            if (u) {
              const partial = readUsage(u);
              if (partial) callbacks?.onUsage?.(partial);
            }
          }

          // ── Final result event ──
          if (event.type === "result") {
            sawAssistantEnd = true;
            stopReason = mapClaudeStopReason(event.stop_reason ?? event.subtype);
            const u = event.usage as Record<string, unknown> | undefined;
            if (u) usage = readUsage(u) ?? usage;
          }
        }
      });

      proc.stderr?.on("data", (chunk: Buffer) => {
        stderrBuf += chunk.toString("utf-8");
      });

      const timer = setTimeout(() => {
        timedOut = true;
        proc.kill("SIGTERM");
        setTimeout(() => proc.kill("SIGKILL"), 5_000).unref();
      }, this.config.timeout || 600_000);

      proc.on("error", (err) => {
        clearTimeout(timer);
        // Spawn-level failure also invalidates any cached session id —
        // see the `close` handlers below for the same rationale.
        this.sessionId = undefined;
        resolve({
          content: [{ type: "text", text: "" }],
          stopReason: "error",
          durationMs: Date.now() - start,
          error: `claude CLI spawn failed: ${err.message}`,
        });
      });

      proc.on("close", (code) => {
        clearTimeout(timer);

        if (timedOut) {
          // A timed-out resume often means Claude Code lost the session
          // server-side (idle eviction, restart, expiry). Drop the cached
          // id so the next call falls back to a fresh `--system-prompt`
          // invocation instead of looping on `--resume <stale_id>`.
          this.sessionId = undefined;
          resolve({
            content: content.length > 0 ? content : [{ type: "text", text: "" }],
            stopReason: "error",
            usage,
            durationMs: Date.now() - start,
            error: `claude CLI timed out after ${this.config.timeout}ms`,
          });
          return;
        }

        if (code !== 0 && !sawAssistantEnd) {
          // Surface any auth / login hint Claude Code dumped to stderr.
          // Common modes: "Please run claude login", "session expired".
          const hint = extractAuthHint(stderrBuf);
          // Same rationale as the timeout path: a non-zero exit on a
          // resume usually means the server-side session is gone. Clear
          // the cached id so we don't wedge the native loop replaying
          // `--resume` against an id Claude Code no longer recognises.
          this.sessionId = undefined;
          resolve({
            content: [{ type: "text", text: "" }],
            stopReason: "error",
            usage,
            durationMs: Date.now() - start,
            error:
              `claude CLI exited ${code}` +
              (hint ? ` — ${hint}` : "") +
              (stderrBuf.trim() ? `\nstderr: ${stderrBuf.trim().slice(0, 500)}` : ""),
          });
          return;
        }

        resolve({
          content:
            content.length > 0 ? content : [{ type: "text", text: "" }],
          stopReason,
          usage,
          durationMs: Date.now() - start,
        });
      });
    });
  }
}

/**
 * Build the prompt string for a single `claude -p ...` invocation from
 * the last user turn in the native-loop conversation.
 *
 * Claude Code expects a flat string. `tool_result` blocks are
 * serialized as a JSON array prefixed with a marker so Claude Code
 * recognises them as previous-turn outputs. Any free-form text in the
 * same user turn is appended verbatim.
 *
 * Exported for unit testing.
 */
export function buildClaudePromptFromLastUser(messages: NativeMessage[]): string {
  // Walk backwards to find the most recent user message.
  let last: NativeMessage | undefined;
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i]!.role === "user") {
      last = messages[i];
      break;
    }
  }
  if (!last) return "";

  const toolResults: Array<{
    tool_use_id: string;
    content: string;
    is_error?: boolean;
  }> = [];
  const textParts: string[] = [];

  for (const block of last.content) {
    if (block.type === "tool_result") {
      toolResults.push({
        tool_use_id: block.tool_use_id,
        content: block.content,
        ...(block.is_error ? { is_error: true } : {}),
      });
    } else if (block.type === "text") {
      textParts.push(block.text);
    }
  }

  const parts: string[] = [];
  if (toolResults.length > 0) {
    parts.push(
      `[pwnkit:tool_results]\n${JSON.stringify(toolResults, null, 2)}`,
    );
  }
  if (textParts.length > 0) {
    parts.push(textParts.join("\n").trim());
  }
  return parts.filter((p) => p.length > 0).join("\n\n").trim();
}

/**
 * Map Claude Code's stop-reason vocabulary to the native runtime's
 * normalized set. Both the Anthropic Messages API and Claude Code
 * stream-json use the same string constants for the common cases, but
 * the `result` event sometimes only sets `subtype` (e.g.
 * "success_max_turns") so we accept either.
 *
 * Exported for unit testing.
 */
export function mapClaudeStopReason(
  raw: string | undefined,
): NativeRuntimeResult["stopReason"] {
  if (!raw) return "end_turn";
  switch (raw) {
    case "tool_use":
      return "tool_use";
    case "max_tokens":
    case "success_max_turns":
      return "max_tokens";
    case "end_turn":
    case "success":
    case "stop_sequence":
      return "end_turn";
    case "error":
    case "error_max_turns":
    case "error_during_execution":
      return "error";
    default:
      return "end_turn";
  }
}

function tryParseJson(line: string): Record<string, any> | null {
  try {
    const parsed = JSON.parse(line);
    if (parsed && typeof parsed === "object") {
      return parsed as Record<string, any>;
    }
  } catch {
    // not all stdout lines are stream-json events (e.g. log lines from
    // npm wrappers); ignore and move on.
  }
  return null;
}

function readUsage(
  u: Record<string, unknown>,
): { inputTokens: number; outputTokens: number } | undefined {
  const input = num(u.input_tokens) ?? num(u.prompt_tokens);
  const output = num(u.output_tokens) ?? num(u.completion_tokens);
  if (input === undefined && output === undefined) return undefined;
  return { inputTokens: input ?? 0, outputTokens: output ?? 0 };
}

function num(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return undefined;
}

function extractAuthHint(stderr: string): string | undefined {
  if (!stderr) return undefined;
  if (/please\s+run\s+claude\s+login/i.test(stderr)) {
    return "run `claude login` to authenticate the CLI with your subscription";
  }
  if (/not\s+(?:logged|authenticated)/i.test(stderr)) {
    return "Claude Code reports the user is not authenticated — run `claude login`";
  }
  if (/session\s+expired/i.test(stderr)) {
    return "Claude Code session expired — run `claude login` again";
  }
  return undefined;
}
