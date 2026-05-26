/**
 * Ollama runtime — drives the pwnkit agent loop against a locally-served
 * Gemma 4 (or any tool-calling-capable Ollama model) via Ollama's `/api/chat`
 * endpoint. Closes pwnkit#369.
 *
 * Why this runtime exists
 * -----------------------
 * GemmaForge's small probe (8B Gemma 4 E2B-it) generates ND-JSON leads via
 * `gemmaforge scan` and pwnkit consumes them with `--seed-findings` (#368).
 * The natural finishing move is to also run the *hunt* phase locally on a
 * bigger Gemma 4 (e.g. 27B) — no cloud spend, no key juggling, native
 * function-calling. That's what this runtime is.
 *
 * Wire format
 * -----------
 * POST `{OLLAMA_HOST}/api/chat`:
 *
 *   { model: "gemma4:27b", messages: [...], tools: [...], stream: true|false }
 *
 * Non-streaming: a single JSON body with `{message, done: true, ...}`.
 *
 * Streaming: ND-JSON over a chunked HTTP body. Each line is a JSON object
 *   `{message: {role, content, tool_calls?}, done: bool, done_reason?, ...}`.
 *   Most lines carry incremental `message.content` (delta-style — Ollama emits
 *   tokens, not cumulative buffers). The terminal frame has `done: true`,
 *   `prompt_eval_count`, `eval_count`, and (typically) the full `tool_calls`
 *   array. Tool-call arguments are not split across frames in current Ollama
 *   builds — they arrive whole on the final frame.
 *
 * Gemma 4 returns assistant turns with optional `tool_calls`, each carrying
 * `{ function: { name, arguments } }`. We translate that into pwnkit's
 * NativeContentBlock shape (`tool_use` blocks) so the existing agent loop
 * can dispatch tool calls without caring which runtime produced them.
 */
import type {
  NativeContentBlock,
  NativeMessage,
  NativeRuntime,
  NativeRuntimeResult,
  NativeStreamCallbacks,
  NativeToolDef,
  Runtime,
  RuntimeConfig,
  RuntimeContext,
  RuntimeResult,
} from "./types.js";

export interface OllamaRuntimeOptions {
  /** Base URL, default `http://localhost:11434`. Overridable via `OLLAMA_HOST`. */
  host?: string;
  /** Model id, e.g. `gemma4:27b` or `gemma3:27b`. Required. */
  model: string;
  /** Request timeout in ms. */
  timeout: number;
  /** Sampling temperature (Ollama `options.temperature`). */
  temperature?: number;
  /** Override fetch — primarily for tests. */
  fetchImpl?: typeof fetch;
  /**
   * Stream the `/api/chat` response as ND-JSON and fire per-token deltas via
   * `NativeStreamCallbacks.onDelta("assistant_response", ...)`. Default `true`
   * — turning it off only makes sense when the caller can't consume a stream
   * (e.g. mocked tests). Opt out per-process with `--runtime-stream=false`.
   */
  stream?: boolean;
}

interface OllamaToolCall {
  function: {
    name: string;
    // Ollama serialises this as an object, but old builds returned a JSON-string.
    // We accept both.
    arguments: Record<string, unknown> | string;
  };
}

interface OllamaChatResponse {
  model: string;
  created_at: string;
  message: {
    role: "assistant";
    content: string;
    tool_calls?: OllamaToolCall[];
  };
  done: boolean;
  done_reason?: string;
  total_duration?: number;
  prompt_eval_count?: number;
  eval_count?: number;
}

const DEFAULT_HOST = "http://localhost:11434";

function resolveHost(explicit?: string): string {
  const fromEnv = process.env.OLLAMA_HOST?.trim();
  return (explicit && explicit.length > 0 ? explicit : fromEnv) || DEFAULT_HOST;
}

/**
 * Translate a `NativeMessage` (pwnkit's structured turn) into the wire shape
 * Ollama expects on `/api/chat`. Tool results become `role: "tool"` turns;
 * everything else maps to `role: "user" | "assistant"` with a flat string body.
 */
function toOllamaMessages(
  system: string,
  messages: NativeMessage[],
): Array<{ role: string; content: string; tool_call_id?: string; name?: string }> {
  const out: Array<{ role: string; content: string; tool_call_id?: string; name?: string }> = [];
  if (system) out.push({ role: "system", content: system });
  for (const msg of messages) {
    // Collapse text blocks; tool_use / tool_result need special handling.
    const textParts: string[] = [];
    for (const block of msg.content) {
      if (block.type === "text") textParts.push(block.text);
      else if (block.type === "tool_use") {
        textParts.push(
          `[tool_call name=${block.name} input=${JSON.stringify(block.input)}]`,
        );
      } else if (block.type === "tool_result") {
        out.push({
          role: "tool",
          content: block.content,
          tool_call_id: block.tool_use_id,
        });
      }
    }
    if (textParts.length > 0) {
      out.push({ role: msg.role, content: textParts.join("\n") });
    }
  }
  return out;
}

/** Ollama tool format mirrors OpenAI's: { type: "function", function: { name, description, parameters } }. */
function toOllamaTools(tools: NativeToolDef[]): Array<{
  type: "function";
  function: { name: string; description: string; parameters: NativeToolDef["input_schema"] };
}> {
  return tools.map((t) => ({
    type: "function" as const,
    function: {
      name: t.name,
      description: t.description,
      parameters: t.input_schema,
    },
  }));
}

function parseToolCalls(calls: OllamaToolCall[] | undefined): NativeContentBlock[] {
  if (!calls || calls.length === 0) return [];
  const blocks: NativeContentBlock[] = [];
  for (let i = 0; i < calls.length; i++) {
    const c = calls[i]!;
    let input: Record<string, unknown>;
    if (typeof c.function.arguments === "string") {
      try {
        input = JSON.parse(c.function.arguments) as Record<string, unknown>;
      } catch {
        input = { _raw: c.function.arguments };
      }
    } else {
      input = c.function.arguments;
    }
    blocks.push({
      type: "tool_use",
      // Ollama doesn't return a per-call id, so synthesise one stable
      // within this turn. Agent dispatch only needs uniqueness per turn.
      id: `ollama_${Date.now()}_${i}`,
      name: c.function.name,
      input,
    });
  }
  return blocks;
}

export class OllamaRuntime implements Runtime, NativeRuntime {
  readonly type = "ollama" as const;
  private host: string;
  private model: string;
  private timeout: number;
  private temperature: number;
  private fetchImpl: typeof fetch;
  private stream: boolean;

  constructor(opts: OllamaRuntimeOptions) {
    if (!opts.model) {
      throw new Error("OllamaRuntime requires a model (e.g. 'gemma4:27b').");
    }
    this.host = resolveHost(opts.host);
    this.model = opts.model;
    this.timeout = opts.timeout;
    this.temperature = opts.temperature ?? 0.6;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.stream = opts.stream ?? true;
  }

  /** Cheap health probe — `/api/tags` is the canonical Ollama liveness check. */
  async isAvailable(): Promise<boolean> {
    try {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 2000);
      const res = await this.fetchImpl(`${this.host}/api/tags`, { signal: ctl.signal });
      clearTimeout(t);
      return res.ok;
    } catch {
      return false;
    }
  }

  /** Legacy text-in/text-out path. Used by stages that haven't migrated to NativeRuntime. */
  async execute(prompt: string, _context?: RuntimeContext): Promise<RuntimeResult> {
    const start = Date.now();
    try {
      const body = {
        model: this.model,
        messages: [{ role: "user", content: prompt }],
        stream: false,
        options: { temperature: this.temperature },
      };
      const res = await this.postChat(body);
      const usage = readUsage(res);
      return {
        output: res.message.content,
        exitCode: 0,
        timedOut: false,
        durationMs: Date.now() - start,
        usage,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        output: "",
        exitCode: 1,
        timedOut: msg.includes("AbortError"),
        durationMs: Date.now() - start,
        error: msg,
      };
    }
  }

  async executeNative(
    system: string,
    messages: NativeMessage[],
    tools: NativeToolDef[],
    callbacks?: NativeStreamCallbacks,
  ): Promise<NativeRuntimeResult> {
    const start = Date.now();
    const useStream = this.stream;
    try {
      const body = {
        model: this.model,
        messages: toOllamaMessages(system, messages),
        tools: tools.length > 0 ? toOllamaTools(tools) : undefined,
        stream: useStream,
        options: { temperature: this.temperature },
      };

      const aggregate = useStream
        ? await this.streamChat(body, callbacks)
        : await this.postChat(body);
      const usage = readUsage(aggregate);
      if (callbacks?.onUsage && usage) callbacks.onUsage(usage);

      const content: NativeContentBlock[] = [];
      if (aggregate.message.content && aggregate.message.content.trim()) {
        content.push({ type: "text", text: aggregate.message.content });
      }
      const toolBlocks = parseToolCalls(aggregate.message.tool_calls);
      content.push(...toolBlocks);

      // pwnkit's NativeRuntimeResult.stopReason taxonomy:
      //   - "tool_use" when the model emitted at least one tool call
      //   - "max_tokens" when Ollama signals length truncation
      //   - "end_turn" otherwise (clean completion)
      // Ollama exposes `done_reason: "stop" | "length"` from gemma3 onwards.
      let stopReason: NativeRuntimeResult["stopReason"];
      if (toolBlocks.length > 0) stopReason = "tool_use";
      else if (aggregate.done_reason === "length") stopReason = "max_tokens";
      else stopReason = "end_turn";

      return {
        content,
        stopReason,
        usage,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        content: [{ type: "text", text: "" }],
        stopReason: "error",
        durationMs: Date.now() - start,
        error: msg,
      };
    }
  }

  private async postChat(body: unknown): Promise<OllamaChatResponse> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.timeout);
    try {
      const res = await this.fetchImpl(`${this.host}/api/chat`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: ctl.signal,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Ollama /api/chat returned ${res.status}: ${text.slice(0, 200)}`);
      }
      return (await res.json()) as OllamaChatResponse;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Consume Ollama's ND-JSON stream from `/api/chat?stream=true`.
   *
   * Behaviour:
   *  - Each non-terminal frame's `message.content` is treated as a delta and
   *    forwarded to `callbacks.onDelta("assistant_response", delta)` exactly
   *    once (no accumulation passed to the callback — pwnkit's contract is
   *    "incremental fragment only", see types.ts:88).
   *  - The terminal frame (`done: true`) is taken as authoritative for
   *    `tool_calls`, `done_reason`, and usage stats. Tool-call shape across
   *    intermediate frames in current Ollama builds is empty/absent, so we
   *    don't try to stitch partials — we just trust the final frame.
   *  - The aggregated `message.content` (full assistant text) is returned in
   *    the synthetic `OllamaChatResponse` so the rest of `executeNative`
   *    can keep its non-streaming-shape codepath.
   */
  private async streamChat(
    body: unknown,
    callbacks?: NativeStreamCallbacks,
  ): Promise<OllamaChatResponse> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), this.timeout);
    try {
      const res = await this.fetchImpl(`${this.host}/api/chat`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: ctl.signal,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        throw new Error(`Ollama /api/chat returned ${res.status}: ${text.slice(0, 200)}`);
      }
      if (!res.body) {
        // Some intermediates buffer the stream into a single JSON body —
        // fall back to parsing the whole thing as JSON.
        return (await res.json()) as OllamaChatResponse;
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let aggregateContent = "";
      let lastModel = "";
      let lastCreatedAt = "";
      let finalToolCalls: OllamaToolCall[] | undefined;
      let doneReason: string | undefined;
      let promptEvalCount: number | undefined;
      let evalCount: number | undefined;
      let totalDuration: number | undefined;
      let sawDone = false;

      const processLine = (line: string): void => {
        const trimmed = line.trim();
        if (!trimmed) return;
        let frame: Partial<OllamaChatResponse>;
        try {
          frame = JSON.parse(trimmed) as Partial<OllamaChatResponse>;
        } catch {
          // Skip malformed lines — Ollama doesn't normally produce them, but
          // we'd rather drop a partial than abort the whole stream.
          return;
        }
        if (frame.model) lastModel = frame.model;
        if (frame.created_at) lastCreatedAt = frame.created_at;
        const msg = frame.message;
        if (msg) {
          if (typeof msg.content === "string" && msg.content.length > 0) {
            aggregateContent += msg.content;
            callbacks?.onDelta?.("assistant_response", msg.content);
          }
          if (msg.tool_calls && msg.tool_calls.length > 0) {
            // Ollama only emits these on the terminal frame today, but if a
            // future build sends them earlier we still pick up the latest set.
            finalToolCalls = msg.tool_calls;
          }
        }
        if (frame.done) {
          sawDone = true;
          if (frame.done_reason) doneReason = frame.done_reason;
          if (typeof frame.prompt_eval_count === "number") promptEvalCount = frame.prompt_eval_count;
          if (typeof frame.eval_count === "number") evalCount = frame.eval_count;
          if (typeof frame.total_duration === "number") totalDuration = frame.total_duration;
        }
      };

      // eslint-disable-next-line no-constant-condition
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        // ND-JSON: split on newlines, keep the trailing partial in `buffer`.
        let nl = buffer.indexOf("\n");
        while (nl !== -1) {
          const line = buffer.slice(0, nl);
          buffer = buffer.slice(nl + 1);
          processLine(line);
          nl = buffer.indexOf("\n");
        }
      }
      // Flush any trailing partial line (some HTTP layers omit the final \n).
      if (buffer.length > 0) processLine(buffer);

      return {
        model: lastModel,
        created_at: lastCreatedAt,
        message: {
          role: "assistant",
          content: aggregateContent,
          tool_calls: finalToolCalls,
        },
        done: sawDone,
        done_reason: doneReason,
        total_duration: totalDuration,
        prompt_eval_count: promptEvalCount,
        eval_count: evalCount,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

function readUsage(
  res: OllamaChatResponse,
): { inputTokens: number; outputTokens: number } | undefined {
  const inp = res.prompt_eval_count;
  const out = res.eval_count;
  if (typeof inp !== "number" || typeof out !== "number") return undefined;
  return { inputTokens: inp, outputTokens: out };
}
