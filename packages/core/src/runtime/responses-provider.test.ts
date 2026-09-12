import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LlmApiRuntime, __resetFallbackChainForTests } from "./llm-api.js";
import type { NativeMessage, RuntimeConfig } from "./types.js";

const providers = [
  { provider: "openai", prefix: "OPENAI", model: "gpt-4.1", base: "https://api.openai.com/v1" },
  { provider: "openrouter", prefix: "OPENROUTER", model: "openrouter/fixture", base: "https://openrouter.ai/api/v1" },
  { provider: "xai", prefix: "XAI", model: "grok-4", base: "https://api.x.ai/v1" },
  { provider: "azure", prefix: "AZURE_OPENAI", model: "DeepSeek-V4-Pro", base: "https://azure.example.test/openai/v1" },
] as const;

function responsesReply(): Response {
  return new Response(`data: ${JSON.stringify({
    type: "response.completed",
    response: {
      output: [{ type: "function_call", call_id: "call_fixture", name: "inspect", arguments: '{"path":"README.md"}' }],
      usage: { input_tokens: 7, output_tokens: 3 },
    },
  })}\n\n`, { headers: { "content-type": "text/event-stream" } });
}

function chatReply(): Response {
  return Response.json({
    choices: [{ message: { content: "chat answer" }, finish_reason: "stop" }],
    usage: { prompt_tokens: 2, completion_tokens: 1 },
  });
}

const messages: NativeMessage[] = [{ role: "user", content: [{ type: "text", text: "Inspect README.md" }] }];
async function request(config: Partial<RuntimeConfig> = {}) {
  const runtime = new LlmApiRuntime({ type: "api", timeout: 1000, ...config });
  return runtime.executeNative("Inspect the workspace.", structuredClone(messages), [
    { name: "inspect", description: "Inspect a path", input_schema: { type: "object", properties: { path: { type: "string" } } } },
  ]);
}

function expectToolResult(result: Awaited<ReturnType<typeof request>>) {
  expect(result.error).toBeUndefined();
  expect(result.stopReason).toBe("tool_use");
  expect(result.content).toEqual([{ type: "tool_use", id: "call_fixture", name: "inspect", input: { path: "README.md" } }]);
  expect(result.usage).toMatchObject({ inputTokens: 7, outputTokens: 3 });
}

describe("provider Responses selection", () => {
  let originalEnv: NodeJS.ProcessEnv;
  let home: string;
  let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

  beforeEach(() => {
    originalEnv = process.env;
    home = mkdtempSync(join(tmpdir(), "0sec-responses-provider-"));
    process.env = { HOME: home, "0SEC_SKIP_PROVIDER_BANNER": "1" };
    __resetFallbackChainForTests();
    // Every request is intercepted; no operator credentials or external network.
    fetchMock = vi.fn<typeof fetch>(async () => { throw new Error("Unexpected network request"); });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    process.env = originalEnv;
    __resetFallbackChainForTests();
    rmSync(home, { recursive: true, force: true });
  });

  it.each(providers)("honors $prefix selection for explicit, model-routed and credential-routed requests", async ({ provider, prefix, model, base }) => {
    process.env[`${prefix}_API_KEY`] = "fixture-key";
    process.env[`${prefix}_WIRE_API`] = "responses";
    if (provider === "azure") process.env.AZURE_OPENAI_BASE_URL = base;
    fetchMock.mockImplementation(async () => responsesReply());

    for (const config of [{ provider, model }, { model }, {}]) {
      expectToolResult(await request(config));
    }
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual(Array(3).fill(`${base}/responses`));
  });

  it.each([
    { apiKey: "sk-fixture", variable: "OPENAI_WIRE_API", base: "https://api.openai.com/v1" },
    { apiKey: "sk-or-fixture", variable: "OPENROUTER_WIRE_API", base: "https://openrouter.ai/api/v1" },
  ])("honors $variable with an explicit config API key", async ({ apiKey, variable, base }) => {
    process.env[variable] = "responses";
    fetchMock.mockImplementation(async () => responsesReply());
    expectToolResult(await request({ apiKey }));
    expect(String(fetchMock.mock.calls[0][0])).toBe(`${base}/responses`);
  });

  it.each(providers)("rejects an unsupported $prefix wire before dispatch", async ({ provider, prefix, model, base }) => {
    process.env[`${prefix}_API_KEY`] = "fixture-key";
    process.env[`${prefix}_WIRE_API`] = "anthropic_messages";
    if (provider === "azure") process.env.AZURE_OPENAI_BASE_URL = base;
    await expect(request({ provider, model })).rejects.toThrow(Error);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("preserves custom gateway chat behavior and the OpenRouter Qwen chat route", async () => {
    fetchMock.mockImplementation(async () => chatReply());
    const configs: Partial<RuntimeConfig>[] = [
      { provider: "openai", model: "custom-model", env: { OPENAI_API_KEY: "fixture", OPENAI_BASE_URL: "https://custom.example.test/compat/v1" } },
      { provider: "xai", model: "custom-model", env: { XAI_API_KEY: "fixture", XAI_BASE_URL: "https://custom.example.test/xai/v1" } },
      { provider: "openrouter", model: "qwen/qwen3-coder", env: { OPENROUTER_API_KEY: "fixture" } },
    ];
    for (const config of configs) {
      const result = await request(config);
      expect(result.error).toBeUndefined();
      expect(result.content).toEqual([{ type: "text", text: "chat answer" }]);
    }
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      "https://custom.example.test/compat/v1/chat/completions",
      "https://custom.example.test/xai/v1/chat/completions",
      "https://openrouter.ai/api/v1/chat/completions",
    ]);
  });

  it("retains a custom endpoint when its operator explicitly selects Responses", async () => {
    fetchMock.mockImplementation(async () => responsesReply());
    expectToolResult(await request({
      provider: "openai", model: "custom-model",
      env: { OPENAI_API_KEY: "fixture", OPENAI_BASE_URL: "https://custom.example.test/prefix/v1", OPENAI_WIRE_API: "responses" },
    }));
    expect(String(fetchMock.mock.calls[0][0])).toBe("https://custom.example.test/prefix/v1/responses");
  });

  it("preserves Azure config wire inheritance and an explicit chat override", async () => {
    mkdirSync(join(home, ".codex"));
    writeFileSync(join(home, ".codex", "config.toml"), '[model_providers.azure]\nbase_url = "https://azure.example.test/openai/v1"\nwire_api = "responses"\n');
    process.env.AZURE_OPENAI_API_KEY = "fixture";
    fetchMock.mockImplementation(async () => responsesReply());
    expectToolResult(await request());
    process.env.AZURE_OPENAI_WIRE_API = "chat_completions";
    fetchMock.mockImplementation(async () => chatReply());
    expect((await request()).content).toEqual([{ type: "text", text: "chat answer" }]);
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      "https://azure.example.test/openai/v1/responses",
      "https://azure.example.test/openai/v1/chat/completions",
    ]);
  });

  it("keeps the captured Responses wire and credentials across failover", async () => {
    Object.assign(process.env, {
      OPENAI_API_KEY: "fixture-primary", OPENROUTER_API_KEY: "fixture-fallback",
      OPENAI_WIRE_API: "chat_completions", OPENROUTER_WIRE_API: "responses",
      "0SEC_LLM_FALLBACK": "openrouter:openai/gpt-4.1", "0SEC_LLM_429_MAX_RETRIES": "0",
    });
    fetchMock.mockImplementation(async (url) => String(url).endsWith("/chat/completions")
      ? Response.json({ error: { message: "rate limited" } }, { status: 429 })
      : responsesReply());
    const runtime = new LlmApiRuntime({ type: "api", timeout: 1000, provider: "openai", model: "gpt-4.1" });
    process.env.OPENROUTER_WIRE_API = "chat_completions";
    process.env.OPENROUTER_API_KEY = "changed-after-construction";
    expectToolResult(await runtime.executeNative("Inspect.", structuredClone(messages), []));
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual([
      "https://api.openai.com/v1/chat/completions", "https://openrouter.ai/api/v1/responses",
    ]);
    expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get("authorization")).toBe("Bearer fixture-fallback");
    const finalBody = JSON.parse(String(fetchMock.mock.calls[1][1]?.body));
    expect(finalBody.model).toBe("openai/gpt-4.1");
    expect(finalBody.input).toContainEqual(expect.objectContaining({ role: "user" }));
    expect(finalBody.messages).toBeUndefined();
  });

  it("consumes documented OpenRouter deltas, output items and response.done usage", async () => {
    // https://openrouter.ai/docs/api_reference/responses/basic-usage.md
    const events = [
      { type: "response.created", response: { id: "resp_fixture", status: "in_progress" } },
      { type: "response.content_part.delta", output_index: 0, content_index: 0, delta: "Once" },
      { type: "response.content_part.delta", output_index: 0, content_index: 0, delta: " upon a time." },
      { type: "response.output_item.done", output_index: 0, item: { type: "message", role: "assistant", content: [{ type: "output_text", text: "Once upon a time." }] } },
      { type: "response.output_item.done", output_index: 1, item: { type: "function_call", call_id: "call_fixture", name: "inspect", arguments: '{"path":"README.md"}' } },
      { type: "response.done", response: { id: "resp_fixture", status: "completed", usage: { input_tokens: 12, output_tokens: 45, total_tokens: 57 } } },
    ];
    fetchMock.mockImplementation(async () => new Response(
      events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join("") + "data: [DONE]\n\n",
      { headers: { "content-type": "text/event-stream" } },
    ));
    const runtime = new LlmApiRuntime({
      type: "api", timeout: 1000, provider: "openrouter", model: "openai/gpt-4.1",
      env: { OPENROUTER_API_KEY: "fixture", OPENROUTER_WIRE_API: "responses" },
    });
    const deltas: string[] = [];
    const usage: Array<{ inputTokens: number; outputTokens: number }> = [];
    const result = await runtime.executeNative("Inspect.", structuredClone(messages), [], {
      onDelta: (kind, delta) => { if (kind === "assistant_response") deltas.push(delta); },
      onUsage: (value) => { usage.push(value); },
    });
    expect(result.error).toBeUndefined();
    expect(deltas).toEqual(["Once", " upon a time."]);
    expect(result.content).toEqual([
      { type: "text", text: "Once upon a time." },
      { type: "tool_use", id: "call_fixture", name: "inspect", input: { path: "README.md" } },
    ]);
    expect(result.stopReason).toBe("tool_use");
    expect(result.usage).toEqual({ inputTokens: 12, outputTokens: 45 });
    expect(usage).toEqual([{ inputTokens: 12, outputTokens: 45 }]);
  });

  it.each([
    { scenario: "truncated stream", terminal: [] },
    { scenario: "failed terminal", terminal: [{ type: "response.done", response: { status: "failed", error: { message: "fixture failure" } } }] },
    { scenario: "error followed by completion", terminal: [
      { type: "error", error: { message: "fixture failure" } },
      { type: "response.done", response: { status: "completed" } },
    ] },
    { scenario: "incomplete alias after completion", terminal: [
      { type: "response.completed", response: { status: "completed" } },
      { type: "response.incomplete" },
    ] },
  ])("does not promote tools from an OpenRouter $scenario", async ({ terminal }) => {
    const events = [
      { type: "response.output_item.done", item: { type: "function_call", call_id: "unsafe_to_run", name: "inspect", arguments: '{"path":"README.md"}' } },
      ...terminal,
    ];
    fetchMock.mockImplementation(async () => new Response(
      events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""),
      { headers: { "content-type": "text/event-stream" } },
    ));
    const result = await request({
      provider: "openrouter", model: "openai/gpt-4.1",
      env: { OPENROUTER_API_KEY: "fixture", OPENROUTER_WIRE_API: "responses" },
    });
    expect(result.stopReason).toBe("error");
    expect(result.error).toBeDefined();
    expect(result.content.some((block) => block.type === "tool_use")).toBe(false);
    expect(result.usage).toBeUndefined();
  });

  it.each([
    { type: "response.done", status: "failed" },
    { type: "response.incomplete", status: "completed" },
    { type: "response.completed", status: "failed" },
  ])("retains reported usage from OpenRouter $type/$status without promoting tools", async ({ type, status }) => {
    const events = [
      { type: "response.output_item.done", item: { type: "function_call", call_id: "unsafe_to_run", name: "inspect", arguments: '{"path":"README.md"}' } },
      { type, response: { status, usage: { input_tokens: 7, output_tokens: 3 } } },
    ];
    fetchMock.mockImplementation(async () => new Response(
      events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(""),
      { headers: { "content-type": "text/event-stream" } },
    ));
    const runtime = new LlmApiRuntime({
      type: "api", timeout: 1000, provider: "openrouter", model: "openai/gpt-4.1",
      env: { OPENROUTER_API_KEY: "fixture", OPENROUTER_WIRE_API: "responses" },
    });
    const usage: Array<{ inputTokens: number; outputTokens: number }> = [];
    const result = await runtime.executeNative("Inspect.", structuredClone(messages), [], {
      onUsage: (value) => { usage.push(value); },
    });
    expect(result.stopReason).toBe("error");
    expect(result.error).toBeDefined();
    expect(result.content.some((block) => block.type === "tool_use")).toBe(false);
    expect(result.usage).toEqual({ inputTokens: 7, outputTokens: 3 });
    expect(usage).toEqual([{ inputTokens: 7, outputTokens: 3 }]);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("does not accept OpenRouter-only terminal events on OpenAI", async () => {
    fetchMock.mockImplementation(async () => new Response(
      `data: ${JSON.stringify({ type: "response.done", response: { status: "completed", output: [] } })}\n\n`,
      { headers: { "content-type": "text/event-stream" } },
    ));
    const result = await request({
      provider: "openai", model: "gpt-4.1",
      env: { OPENAI_API_KEY: "fixture", OPENAI_WIRE_API: "responses" },
    });
    expect(result.stopReason).toBe("error");
  });

  it("cancels an OpenRouter stream during text delivery", async () => {
    const operator = new AbortController();
    const cancel = vi.fn();
    fetchMock.mockImplementation(async () => new Response(new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify({
          type: "response.content_part.delta", delta: "working",
        })}\n\n`));
      },
      cancel,
    }), { headers: { "content-type": "text/event-stream" } }));
    const runtime = new LlmApiRuntime({
      type: "api", timeout: 1000, provider: "openrouter", model: "openai/gpt-4.1",
      env: { OPENROUTER_API_KEY: "fixture", OPENROUTER_WIRE_API: "responses" },
    });
    const result = await runtime.executeNative("Inspect.", structuredClone(messages), [], {
      onDelta: () => operator.abort(),
    }, operator.signal);
    expect(result.stopReason).toBe("error");
    expect(result.cancelled).toBe(true);
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("returns measured Responses usage from legacy execute", async () => {
    fetchMock.mockImplementation(async () => Response.json({
      output_text: "legacy answer", usage: { input_tokens: 7, output_tokens: 3 },
    }));
    const runtime = new LlmApiRuntime({
      type: "api", timeout: 1000, provider: "openai", model: "gpt-4.1",
      env: { OPENAI_API_KEY: "fixture", OPENAI_WIRE_API: "responses" },
    });
    const result = await runtime.execute("Answer.");
    expect(result.error).toBeUndefined();
    expect(result.output).toBe("legacy answer");
    expect(result.usage).toEqual({ inputTokens: 7, outputTokens: 3 });
  });

  it("returns measured chat usage without treating missing usage as zero", async () => {
    fetchMock.mockImplementationOnce(async () => chatReply()).mockImplementationOnce(async () => Response.json({
      choices: [{ message: { content: "unmetered answer" } }],
    }));
    const runtime = new LlmApiRuntime({
      type: "api", timeout: 1000, provider: "openai", model: "gpt-4.1",
      env: { OPENAI_API_KEY: "fixture" },
    });
    const measured = await runtime.execute("Answer.");
    expect(measured.output).toBe("chat answer");
    expect(measured.usage).toEqual({ inputTokens: 2, outputTokens: 1 });
    const unknown = await runtime.execute("Answer again.");
    expect(unknown.output).toBe("unmetered answer");
    expect(unknown.usage).toBeUndefined();
  });

  it("normalizes cached Anthropic prompt usage in legacy execute", async () => {
    fetchMock.mockImplementation(async () => Response.json({
      content: [{ type: "text", text: "cached answer" }],
      usage: { input_tokens: 3, cache_read_input_tokens: 5, cache_creation_input_tokens: 2, output_tokens: 4 },
    }));
    const runtime = new LlmApiRuntime({
      type: "api", timeout: 1000, provider: "anthropic", model: "fixture-claude",
      env: { ANTHROPIC_API_KEY: "fixture" },
    });
    const result = await runtime.execute("Answer.");
    expect(result.output).toBe("cached answer");
    expect(result.usage).toMatchObject({ inputTokens: 10, outputTokens: 4 });
  });

  it("uses Google usageMetadata for legacy Zen Gemini requests", async () => {
    fetchMock.mockImplementation(async () => Response.json({
      candidates: [{ content: { parts: [{ text: "Gemini answer" }] } }],
      usageMetadata: { promptTokenCount: 8, candidatesTokenCount: 2 },
    }));
    const runtime = new LlmApiRuntime({
      type: "api", timeout: 1000, provider: "opencode", model: "gemini-3.8-flash",
      env: { OPENCODE_API_KEY: "fixture" },
    });
    const result = await runtime.execute("Answer.");
    expect(result.output).toBe("Gemini answer");
    expect(result.usage).toEqual({ inputTokens: 8, outputTokens: 2 });
  });
});
