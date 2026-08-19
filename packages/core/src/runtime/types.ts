import type { AuthConfig } from "@0sec/shared";

export type RuntimeType = "api" | "claude" | "codex" | "gemini" | "ollama";

export interface RuntimeConfig {
  type: RuntimeType;
  timeout: number;
  cwd?: string;
  env?: Record<string, string>;
  model?: string;
  apiKey?: string;
  /** Called when the subprocess executes a tool (read file, run command, etc.) */
  onToolCall?: (name: string, detail: string) => void;
  /** Called when the model streams thinking/reasoning text */
  onThinking?: (text: string) => void;
  /** JSON Schema for structured output (Claude --json-schema, Codex --output-schema) */
  outputSchema?: Record<string, unknown>;
  /**
   * Opt in to SERVER-SIDE context compaction (Responses API only) at this
   * prompt-token threshold. Values below 1000 are clamped up to the API
   * minimum; omit to leave compaction off.
   *
   * Deliberately opt-in: the native agent loop runs its own structured
   * compaction (`native-loop.ts`, which preserves credential-bearing messages
   * verbatim) and must not be compacted twice. It is for the loops that have no
   * context strategy at all — `craft-scan` and `exploit-scan`.
   */
  serverCompactionTokens?: number;
}

export interface RuntimeResult {
  output: string;
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  usage?: { inputTokens: number; outputTokens: number };
  error?: string;
}

export interface Runtime {
  readonly type: RuntimeType;
  execute(prompt: string, context?: RuntimeContext): Promise<RuntimeResult>;
  isAvailable(): Promise<boolean>;
}

export interface RuntimeContext {
  target?: string;
  findings?: string;
  templateId?: string;
  systemPrompt?: string;
  scanId?: string;
  mcp?: {
    enableTargetTools?: boolean;
    dbPath?: string;
    scopeFile?: string;
    rateLimit?: string;
    allowScanners?: boolean;
    attributionHeaders?: string[];
    attributionUaToken?: string;
    auth?: AuthConfig;
  };
}

// ── Native Runtime (structured messages + tool_use) ──

/**
 * The provider's own response items, carried VERBATIM so they can be echoed
 * back on the next turn.
 *
 * This exists for retained reasoning on the Responses API. Reasoning items are
 * opaque (`encrypted_content`) and must be replayed exactly, in order, with the
 * item they produced immediately after them — a reconstructed twin trips
 * `400 Item 'rs_…' of type 'reasoning' was provided without its required
 * following item`. Keeping the raw array and splicing it back whole satisfies
 * the ordering rule by construction, and keeps `NativeContentBlock` free of
 * provider-specific shapes.
 *
 * `provider` / `model` / `wireApi` are the identity this array is bound to.
 * Encrypted reasoning is only valid for the model that produced it, so the
 * consumer MUST compare all three before replaying and fall back to
 * reconstruction on any mismatch. That comparison is also the model-switch
 * strip point (ensemble runs, mid-conversation re-detection).
 */
export interface ProviderRawOutput {
  provider: string;
  model: string;
  wireApi: string;
  /** The provider's `response.output` array, untouched. */
  output: unknown[];
}

export interface NativeMessage {
  role: "user" | "assistant";
  content: NativeContentBlock[];
  /**
   * Assistant turns only. Opaque provider items for this turn — see
   * {@link ProviderRawOutput}. Plain JSON, so it survives the session
   * persist/resume round-trip.
   */
  providerRaw?: ProviderRawOutput;
}

export type NativeContentBlock =
  | { type: "text"; text: string }
  | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
  | { type: "tool_result"; tool_use_id: string; content: string; is_error?: boolean };

export interface NativeToolDef {
  name: string;
  description: string;
  input_schema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
}

export interface NativeRuntimeResult {
  content: NativeContentBlock[];
  stopReason: "end_turn" | "tool_use" | "max_tokens" | "error";
  /**
   * `inputTokens` is always the TOTAL prompt size (uncached + cache reads +
   * cache writes), never the wire's post-cache remainder — see
   * `runtime/prompt-cache.ts` → `readCacheUsage` for why that normalisation is
   * load-bearing for cost accounting and compaction triggering.
   *
   * The two cache fields are populated only by providers that report them
   * (Anthropic), and are consumed by `estimateCost` / `ScanCostLedger` to price
   * cache reads at the cached-input rate.
   */
  usage?: {
    inputTokens: number;
    outputTokens: number;
    /** Prompt tokens served from cache this request (~0.1x input price). */
    cachedInputTokens?: number;
    /** Prompt tokens written to cache this request (~1.25x input price). */
    cacheWriteTokens?: number;
  };
  durationMs: number;
  error?: string;
  /**
   * The provider's raw response items for this turn, when the wire format has
   * items worth replaying (Responses API). Callers that maintain a message
   * history should carry this onto the assistant message they push — see
   * {@link ProviderRawOutput}.
   */
  providerRaw?: ProviderRawOutput;
}

export interface NativeStreamCallbacks {
  onThinking?: (text: string) => void;
  onUsage?: (usage: { inputTokens: number; outputTokens: number }) => void;
  /**
   * Token-level streaming hook. Fired for every SSE delta event while the
   * runtime is still streaming the response. `text` is just the incremental
   * fragment, NOT the full accumulated buffer — callers concatenate.
   *
   * `scope`:
   *   - `"assistant_response"` — visible text the model is producing
   *     (Responses API: `response.output_text.delta`).
   *   - `"reasoning"` — the hidden reasoning summary channel
   *     (Responses API: `response.reasoning_summary_text.delta`).
   *
   * Wired in the agent loop only when a cloud sink is active so non-cloud
   * runs pay zero per-token overhead.
   */
  onDelta?: (scope: "assistant_response" | "reasoning", text: string) => void;
}

export interface NativeRuntime {
  readonly type: RuntimeType;
  executeNative(
    system: string,
    messages: NativeMessage[],
    tools: NativeToolDef[],
    callbacks?: NativeStreamCallbacks,
  ): Promise<NativeRuntimeResult>;
  isAvailable(): Promise<boolean>;
}
