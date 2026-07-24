import { randomUUID } from "node:crypto";

import { LlmApiRuntime } from "../runtime/llm-api.js";
import type {
  NativeContentBlock,
  NativeMessage,
  NativeRuntime,
  NativeStreamCallbacks,
  NativeToolDef,
  RuntimeConfig,
} from "../runtime/types.js";
import { ToolExecutor, getToolsForRole } from "../agent/tools.js";
import type { AgentRole, ToolCall, ToolContext, ToolDefinition, ToolResult } from "../agent/types.js";

/**
 * Unified interactive chat console — engine-side turn driver.
 *
 * This is the conversational front-end for the pwnkit engine described in the
 * 0sec "operator cockpit" direction: one surface where an operator talks to the
 * engine and it can invoke every tool in the registry (recon, web pentest,
 * source-scan, variant-hunt, verify, patch-gen) in one place.
 *
 * It deliberately REUSES the engine's real components rather than re-building
 * them:
 *   - the real tool registry + dispatcher (`getToolsForRole` + `ToolExecutor`
 *     from `agent/tools.ts`),
 *   - the real LLM runtime (`LlmApiRuntime.executeNative` from
 *     `runtime/llm-api.ts`, the same native tool_use client the autonomous
 *     `runNativeAgentLoop` drives).
 *
 * What it adds is the thin turn-orchestration glue that `runNativeAgentLoop`
 * intentionally does NOT expose: a chat turn that runs the model + its tool
 * calls to a natural stop and then HANDS CONTROL BACK to the operator, keeping
 * the conversation history across operator turns. `runNativeAgentLoop` is a
 * one-shot autonomous scan (it terminates the whole run when the model calls
 * `done`), so its terminal semantics don't fit a "respond, then wait for me"
 * console. The inner turn cycle here mirrors that loop's cycle (executeNative →
 * dispatch tool_use via ToolExecutor → append tool_result → repeat) so the two
 * stay behaviourally aligned. See `console/repl.ts` for the CLI consumer.
 *
 * First-PR scope: a working single-operator REPL over the full tool registry.
 * Deliberately NOT wired here (tracked as follow-ups): SQLite session
 * persistence/resume, cost ledgers + ceilings, scope/rate-limit/WAF
 * enforcement, the loot ledger, and journaling — all of which
 * `runNativeAgentLoop` already implements and a later pass can thread through
 * `ToolContext` / a shared config.
 */

/** Streaming + activity callbacks a renderer (CLI REPL, product UI) hooks into. */
export interface ConsoleRenderCallbacks {
  /** Incremental visible assistant text (SSE delta fragments, not cumulative). */
  onAssistantDelta?: (text: string) => void;
  /** Incremental hidden reasoning-summary text. */
  onReasoningDelta?: (text: string) => void;
  /** Fired just before a tool call is dispatched to the executor. */
  onToolStart?: (call: ToolCall) => void;
  /** Fired after a tool call resolves, with its result. */
  onToolResult?: (call: ToolCall, result: ToolResult) => void;
  /** Per-turn token usage. */
  onUsage?: (usage: { inputTokens: number; outputTokens: number }) => void;
  /** Non-fatal operational notice (e.g. hit the tool-iteration cap). */
  onNotice?: (message: string) => void;
}

/** Why a single operator turn stopped. */
export type ConsoleStopReason = "end_turn" | "max_tool_iterations" | "error";

/** Outcome of one operator message (the model's reply + every tool it ran). */
export interface ConsoleTurnOutcome {
  assistantText: string;
  toolCalls: Array<{ call: ToolCall; result: ToolResult }>;
  usage: { inputTokens: number; outputTokens: number };
  stopReason: ConsoleStopReason;
  error?: string;
}

export interface ConsoleSessionConfig {
  /**
   * LLM client. Any `NativeRuntime` works (tests inject a stub); production
   * passes an `LlmApiRuntime`. Build one with {@link createConsoleRuntime}.
   */
  runtime: NativeRuntime;
  /**
   * Engagement target the tools operate against (same-origin checks, tool
   * context). Optional — a bare console can start target-less and the operator
   * can name targets in-conversation; target-scoped tools then return a
   * graceful error until a target is set.
   */
  target?: string;
  /**
   * Role whose tool set the console exposes. Defaults to `"audit"`, which maps
   * to the full "everything" registry (recon, web, source, patch, run_command,
   * …) — the cockpit wants every tool in one place.
   */
  role?: AgentRole;
  /** Explicit tool override; defaults to `getToolsForRole(role, …)`. */
  tools?: ToolDefinition[];
  /** Stable id for this console session (telemetry / future persistence). */
  scanId?: string;
  /** Safety cap on tool-call rounds within a single operator turn. */
  maxToolIterations?: number;
  /** Opt in to generic-scanner tool wrappers (sqlmap/nikto/…). Default off. */
  allowScanners?: boolean;
  /** System-prompt override. Defaults to {@link buildConsoleSystemPrompt}. */
  systemPrompt?: string;
}

/** A live console session: persistent history + a `send()` per operator line. */
export interface ConsoleSession {
  readonly scanId: string;
  readonly systemPrompt: string;
  readonly tools: ToolDefinition[];
  /** Full conversation so far (native content blocks). Grows with each turn. */
  readonly messages: NativeMessage[];
  /** Run one operator message to a natural stop, streaming via `callbacks`. */
  send(userText: string, callbacks?: ConsoleRenderCallbacks): Promise<ConsoleTurnOutcome>;
  /** Release tool resources (browser/PTY) held by the executor. */
  cleanup(): Promise<void>;
}

const DEFAULT_MAX_TOOL_ITERATIONS = 20;

/**
 * Build the console persona system prompt. Distinct from the scan-role prompts
 * (`discoveryPrompt`/`attackPrompt`/…): this frames an interactive operator
 * cockpit rather than an autonomous hunt, and tells the model to answer the
 * operator directly and stop for input instead of driving to a `done` verdict.
 */
export function buildConsoleSystemPrompt(opts: { target?: string; scanId: string }): string {
  return [
    "You are the pwnkit operator console — an interactive security assistant with",
    "direct access to the full pwnkit tool registry (reconnaissance, web pentest,",
    "source and package scanning, variant hunting, exploit verification, and",
    "patch generation).",
    "",
    "You are talking to a trusted operator on an authorized engagement. Work",
    "conversationally: use tools to investigate, report what you find in clear",
    "prose, and then STOP and wait for the operator's next instruction. Do not",
    "narrate a long autonomous plan — take the next concrete step, show the",
    "result, and hand control back.",
    "",
    "Call tools whenever they help; prefer real tool output over speculation.",
    "When a request is ambiguous or an action is destructive, ask before acting.",
    "",
    opts.target ? `Current target: ${opts.target}` : "No target is set yet; ask the operator for one when a tool needs it.",
    `Session id: ${opts.scanId}`,
  ].join("\n");
}

/**
 * Construct the production LLM client for the console and fail fast on a
 * misconfigured provider (missing API key, etc). Mirrors the pre-flight
 * `getConfigurationDiagnostics()` check `agent-runner.ts` runs before the
 * native loop.
 */
export function createConsoleRuntime(config?: Partial<RuntimeConfig>): LlmApiRuntime {
  const runtime = new LlmApiRuntime({
    type: "api",
    timeout: config?.timeout ?? 120_000,
    apiKey: config?.apiKey,
    model: config?.model,
    ...config,
  });
  const diagnostics = runtime.getConfigurationDiagnostics();
  if (!diagnostics.valid) {
    throw new Error(
      diagnostics.fatalError ?? `${diagnostics.providerLabel} runtime is not configured (no API key found).`,
    );
  }
  return runtime;
}

/** Convert a registry `ToolDefinition` to the runtime's native tool schema. */
function toNativeToolDef(tool: ToolDefinition): NativeToolDef {
  const properties: Record<string, unknown> = {};
  for (const [key, param] of Object.entries(tool.parameters)) {
    const prop: Record<string, unknown> = { type: param.type, description: param.description };
    if (param.enum) prop.enum = param.enum;
    properties[key] = prop;
  }
  return {
    name: tool.name,
    description: tool.description,
    input_schema: { type: "object", properties, required: tool.required ?? [] },
  };
}

/** Serialize a tool result into the string content of a `tool_result` block. */
function stringifyToolResult(result: ToolResult): string {
  if (!result.success) return result.error ?? "tool execution failed";
  return typeof result.output === "string" ? result.output : JSON.stringify(result.output);
}

/**
 * Create an interactive console session over the real tool registry + runtime.
 *
 * The returned session holds conversation history in memory; each `send()`
 * runs the model and its tool calls to a natural stop and returns control.
 */
export function createConsoleSession(config: ConsoleSessionConfig): ConsoleSession {
  const scanId = config.scanId ?? `console-${randomUUID()}`;
  const role: AgentRole = config.role ?? "audit";
  const target = config.target ?? "";

  const toolContext: ToolContext = {
    target,
    scanId,
    role,
    findings: [],
    attackResults: [],
    targetInfo: {},
    allowScanners: config.allowScanners,
  };

  // The real dispatcher over the real registry. `db = null` → no persistence
  // this pass (findings live in `toolContext.findings` for the session).
  const executor = new ToolExecutor(toolContext);

  const tools =
    config.tools ?? getToolsForRole(role, { allowScanners: config.allowScanners });
  const nativeTools = tools.map(toNativeToolDef);

  const systemPrompt =
    config.systemPrompt ?? buildConsoleSystemPrompt({ target: config.target, scanId });
  const maxToolIterations = config.maxToolIterations ?? DEFAULT_MAX_TOOL_ITERATIONS;

  const messages: NativeMessage[] = [];

  async function send(userText: string, callbacks?: ConsoleRenderCallbacks): Promise<ConsoleTurnOutcome> {
    messages.push({ role: "user", content: [{ type: "text", text: userText }] });

    const runCalls: Array<{ call: ToolCall; result: ToolResult }> = [];
    const usage = { inputTokens: 0, outputTokens: 0 };
    let assistantText = "";

    const streamCallbacks: NativeStreamCallbacks = {
      onDelta: (scope, text) => {
        if (scope === "assistant_response") callbacks?.onAssistantDelta?.(text);
        else callbacks?.onReasoningDelta?.(text);
      },
      // Live display only; the authoritative per-call total is accumulated from
      // `result.usage` below so we neither miss it nor double-count it.
      onUsage: (u) => callbacks?.onUsage?.(u),
    };

    let iterations = 0;
    // Turn cycle: plan → run tools → feed results back → repeat until the model
    // stops requesting tools (end_turn) or we hit the per-turn safety cap.
    for (;;) {
      const result = await config.runtime.executeNative(systemPrompt, messages, nativeTools, streamCallbacks);

      if (result.stopReason === "error") {
        return {
          assistantText,
          toolCalls: runCalls,
          usage,
          stopReason: "error",
          error: result.error ?? "LLM runtime error",
        };
      }

      if (result.usage) {
        usage.inputTokens += result.usage.inputTokens;
        usage.outputTokens += result.usage.outputTokens;
      }

      messages.push({ role: "assistant", content: result.content });

      // Surface any visible text the runtime didn't stream token-by-token.
      const turnText = result.content
        .filter((b): b is Extract<NativeContentBlock, { type: "text" }> => b.type === "text")
        .map((b) => b.text)
        .join("");
      if (turnText) assistantText += turnText;

      const toolUseBlocks = result.content.filter(
        (b): b is Extract<NativeContentBlock, { type: "tool_use" }> => b.type === "tool_use",
      );
      if (toolUseBlocks.length === 0) {
        return { assistantText, toolCalls: runCalls, usage, stopReason: "end_turn" };
      }

      const toolResultBlocks: NativeContentBlock[] = [];
      for (const block of toolUseBlocks) {
        const call: ToolCall = { name: block.name, arguments: block.input };
        callbacks?.onToolStart?.(call);
        const toolResult = await executor.execute(call);
        callbacks?.onToolResult?.(call, toolResult);
        runCalls.push({ call, result: toolResult });
        toolResultBlocks.push({
          type: "tool_result",
          tool_use_id: block.id,
          content: stringifyToolResult(toolResult),
          is_error: !toolResult.success,
        });
      }
      messages.push({ role: "user", content: toolResultBlocks });

      iterations += 1;
      if (iterations >= maxToolIterations) {
        callbacks?.onNotice?.(
          `Reached the ${maxToolIterations}-tool-call cap for this turn; pausing for operator input.`,
        );
        return { assistantText, toolCalls: runCalls, usage, stopReason: "max_tool_iterations" };
      }
    }
  }

  return {
    scanId,
    systemPrompt,
    tools,
    messages,
    send,
    cleanup: () => executor.cleanup(),
  };
}
