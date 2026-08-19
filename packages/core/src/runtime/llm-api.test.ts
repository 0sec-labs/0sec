import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  LlmApiRuntime,
  probeAzureRegion,
  parseRetryAfterMs,
  isRetryableHttpStatus,
  retryBackoffMs,
  parseUsageLimitReached,
  QuotaExhaustedError,
  parseLlmFallbackChain,
  resolveFailoverProvider,
  __resetFallbackChainForTests,
  __resetAzureRegionCacheForTests,
  __resetProviderStartupLogForTests,
} from "./llm-api.js";
import type { NativeMessage, NativeContentBlock } from "./types.js";

// ── Provider Detection ──

describe("LlmApiRuntime provider detection", () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    delete process.env.OPENROUTER_API_KEY;
    delete process.env.DEEPSEEK_API_KEY;
    delete process.env.DEEPSEEK_BASE_URL;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.AZURE_OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.AZURE_OPENAI_BASE_URL;
    delete process.env.AZURE_OPENAI_MODEL;
    delete process.env.AZURE_OPENAI_WIRE_API;
    delete process.env.ANTHROPIC_BASE_URL;
    // kimi/z-ai are valid providers in the priority chain too — a shell that
    // exports them (e.g. an agent session routed through Moonshot/GLM) leaks
    // a credential into provider-detection tests otherwise.
    delete process.env.KIMI_API_KEY;
    delete process.env.KIMI_BASE_URL;
    delete process.env.QWEN_API_KEY;
    delete process.env.QWEN_BASE_URL;
    delete process.env.Z_AI_API_KEY;
    delete process.env.Z_AI_BASE_URL;
    delete process.env["0SEC_MODEL"];
    delete process.env["0SEC_SELECTED_PROVIDER"];
    delete process.env["0SEC_FORCE_PROVIDER"];
    delete process.env["0SEC_REGION_OVERRIDE"];
    delete process.env["0SEC_CHATGPT_ACCESS_TOKEN"];
    delete process.env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"];
    delete process.env["0SEC_CHATGPT_ACCOUNT_ID"];
    // Provider-selection tests must not inherit the operator's Codex login.
    process.env["0SEC_CHATGPT_AUTH_FILE"] = "/tmp/0sec-provider-test-no-auth.json";
    // Suppress the startup banner so provider-detection tests don't
    // spew log lines or attempt real network probes.
    process.env["0SEC_SKIP_PROVIDER_BANNER"] = "1";
  });
  afterEach(() => {
    for (const key of Object.keys(process.env)) {
      if (!(key in origEnv)) delete process.env[key];
    }
    Object.assign(process.env, origEnv);
  });

  it("selects OpenRouter when OPENROUTER_API_KEY is set", async () => {
    process.env.OPENROUTER_API_KEY = "sk-or-test123";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((rt as any).provider).toBe("openrouter");
    expect((rt as any).apiKey).toBe("sk-or-test123");
    expect(await rt.isAvailable()).toBe(true);
  });

  it("selects direct DeepSeek Flash 0731 before Azure for its exact API model", async () => {
    process.env.DEEPSEEK_API_KEY = "deepseek-key-123";
    process.env.AZURE_OPENAI_API_KEY = "azure-key-should-not-win";
    process.env["0SEC_MODEL"] = "deepseek-v4-flash";

    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });

    expect((rt as any).provider).toBe("deepseek");
    expect((rt as any).baseUrl).toBe("https://api.deepseek.com");
    expect((rt as any).model).toBe("deepseek-v4-flash");
    expect((rt as any).wireApi).toBe("responses");
    expect(await rt.isAvailable()).toBe(true);
  });

  it("selects Azure Foundry Pro before an injected direct DeepSeek failover", async () => {
    // Test fixtures, literal non-secret keys.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.DEEPSEEK_API_KEY = "deepseek-fallback-key";
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.AZURE_OPENAI_API_KEY = "azure-primary-key";
    process.env.AZURE_OPENAI_BASE_URL = "https://example-resource.openai.azure.com/openai/v1";
    process.env.AZURE_OPENAI_MODEL = "DeepSeek-V4-Pro";
    process.env["0SEC_MODEL"] = "DeepSeek-V4-Pro";

    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    const diagnostics = rt.getConfigurationDiagnostics();

    expect(diagnostics.valid).toBe(true);
    expect(diagnostics.provider).toBe("azure");
    expect(rt.resolvedModel()).toBe("DeepSeek-V4-Pro");
    expect(await rt.isAvailable()).toBe(true);
  });

  it("selects Azure Foundry gpt-5.4 before an injected direct DeepSeek failover", async () => {
    // Test fixtures, literal non-secret keys.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.DEEPSEEK_API_KEY = "deepseek-fallback-key";
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.AZURE_OPENAI_API_KEY = "azure-primary-key";
    process.env.AZURE_OPENAI_BASE_URL = "https://example-resource.openai.azure.com/openai/v1";
    process.env.AZURE_OPENAI_MODEL = "DeepSeek-V4-Pro";
    process.env["0SEC_MODEL"] = "gpt-5.4";

    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    const diagnostics = rt.getConfigurationDiagnostics();

    expect(diagnostics.valid).toBe(true);
    expect(diagnostics.provider).toBe("azure");
    expect(rt.resolvedModel()).toBe("gpt-5.4");
    expect(await rt.isAvailable()).toBe(true);
  });

  it("honors a cloud-selected Azure provider over ambient fallback credentials", async () => {
    // Test fixtures, literal non-secret keys.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.DEEPSEEK_API_KEY = "deepseek-fallback-key";
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.AZURE_OPENAI_API_KEY = "azure-primary-key";
    process.env.AZURE_OPENAI_BASE_URL = "https://example-resource.openai.azure.com/openai/v1";
    process.env.AZURE_OPENAI_MODEL = "DeepSeek-V4-Pro";
    process.env["0SEC_MODEL"] = "future-foundry-deployment";
    process.env["0SEC_SELECTED_PROVIDER"] = "azure";

    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });

    expect(rt.getConfigurationDiagnostics().provider).toBe("azure");
    expect(rt.resolvedModel()).toBe("future-foundry-deployment");
  });

  it("routes a cross-family refuter model past the primary provider pin", () => {
    // Test fixtures, literal non-secret keys.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.AZURE_OPENAI_API_KEY = "azure-primary-key";
    process.env.AZURE_OPENAI_BASE_URL = "https://azure.example/openai/v1";
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.ANTHROPIC_API_KEY = "sk-ant-refuter-key";
    process.env["0SEC_MODEL"] = "gpt-5.5";
    process.env["0SEC_SELECTED_PROVIDER"] = "azure";

    const rt = new LlmApiRuntime({
      type: "api",
      timeout: 5000,
      model: "claude-sonnet-4-6",
    });

    expect(rt.getConfigurationDiagnostics().provider).toBe("anthropic");
  });

  it("selects Anthropic when ANTHROPIC_API_KEY is set", async () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-test456";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((rt as any).provider).toBe("anthropic");
    // Anthropic uses its own Messages API, wireApi is just a default
    expect((rt as any).wireApi).toBe("chat_completions");
  });

  it("selects Azure when AZURE_OPENAI_API_KEY is set (before OPENAI_API_KEY)", async () => {
    process.env.AZURE_OPENAI_API_KEY = "azure-key-123";
    process.env.OPENAI_API_KEY = "sk-openai-should-not-win";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((rt as any).provider).toBe("azure");
    expect((rt as any).apiKey).toBe("azure-key-123");
  });

  it("selects OpenAI as last resort", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-test";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((rt as any).provider).toBe("openai");
  });

  it("reports unavailable when no key is set", async () => {
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect(await rt.isAvailable()).toBe(false);
  });

  it("reports Azure config as invalid when only the key is set", () => {
    process.env.HOME = "/tmp/0sec-no-codex-config";
    process.env.AZURE_OPENAI_API_KEY = "azure-key-123";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    const diagnostics = rt.getConfigurationDiagnostics();
    expect(diagnostics.valid).toBe(false);
    expect(diagnostics.reason).toBe("invalid_config");
    expect(diagnostics.fatalError).toContain("AZURE_OPENAI_BASE_URL");
    expect(diagnostics.fatalError).toContain("AZURE_OPENAI_MODEL");
  });

  it("accepts Azure config when base URL and model are provided via env", () => {
    process.env.AZURE_OPENAI_API_KEY = "azure-key-123";
    process.env.AZURE_OPENAI_BASE_URL = "https://example-resource.openai.azure.com/openai/v1";
    process.env.AZURE_OPENAI_MODEL = "gpt-5-deployment";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    const diagnostics = rt.getConfigurationDiagnostics();
    expect(diagnostics.valid).toBe(true);
    expect(diagnostics.reason).toBeUndefined();
  });

  it("uses Responses wire format for the exact Azure GPT-5.6 Sol deployment", () => {
    // Test fixture, literal non-secret key.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.AZURE_OPENAI_API_KEY = "azure-key-123";
    process.env.AZURE_OPENAI_BASE_URL = "https://example-resource.openai.azure.com/openai/v1";
    process.env.AZURE_OPENAI_WIRE_API = "chat_completions";

    process.env.AZURE_OPENAI_MODEL = "gpt-5.6-sol";
    const sol = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((sol as any).wireApi).toBe("responses");

    process.env.AZURE_OPENAI_MODEL = "gpt-5.6-luna";
    const luna = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((luna as any).wireApi).toBe("chat_completions");
  });

  it("detects provider from explicit config key prefix", () => {
    const rt1 = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "sk-or-cfg" });
    expect((rt1 as any).provider).toBe("openrouter");

    const rt2 = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "sk-ant-cfg" });
    expect((rt2 as any).provider).toBe("anthropic");

    const rt3 = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "some-other-key" });
    expect((rt3 as any).provider).toBe("openai");
  });

  it("respects 0SEC_MODEL env var", () => {
    process.env.OPENAI_API_KEY = "sk-test";
    process.env["0SEC_MODEL"] = "gpt-4-turbo";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((rt as any).model).toBe("gpt-4-turbo");
  });

  it("selects Qwen via QWEN_API_KEY with Token Plan defaults", () => {
    // Test fixture, literal non-secret key.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.QWEN_API_KEY = "sk-sp-test";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((rt as any).provider).toBe("qwen");
    expect((rt as any).model).toBe("qwen3.8-max");
    expect((rt as any).baseUrl).toBe(
      "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1",
    );
    // OpenAI-compatible wire: Bearer auth + /chat/completions, NOT the
    // Anthropic x-api-key + /v1/messages path z-ai/kimi ride.
    const headers = (rt as any).buildHeaders();
    expect(headers["Authorization"]).toBe("Bearer sk-sp-test");
    expect(headers["x-api-key"]).toBeUndefined();
    expect((rt as any).buildUrl()).toBe(
      "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1/chat/completions",
    );
  });

  it("routes qwen-prefixed model picks to the qwen provider, honoring QWEN_BASE_URL", () => {
    // Test fixture, literal non-secret key.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.QWEN_API_KEY = "sk-sp-test";
    process.env.QWEN_BASE_URL = "https://qwen.example/v1";
    process.env["0SEC_MODEL"] = "qwen3.7-max";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((rt as any).provider).toBe("qwen");
    expect((rt as any).model).toBe("qwen3.7-max");
    expect((rt as any).baseUrl).toBe("https://qwen.example/v1");
  });

  it("routes the Token Plan deepseek revision id to qwen, never direct deepseek", () => {
    // Test fixtures, literal non-secret keys.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.QWEN_API_KEY = "sk-sp-test";
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.DEEPSEEK_API_KEY = "sk-ds-test"; // present but must NOT win
    process.env["0SEC_MODEL"] = "deepseek-v4-flash-0731";
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000 });
    expect((rt as any).provider).toBe("qwen");
    expect((rt as any).model).toBe("deepseek-v4-flash-0731");
  });

  it("binds a controlled run to its declared API-key provider over ChatGPT OAuth", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-test";
    process.env["0SEC_CHATGPT_ACCESS_TOKEN"] = "oauth-test";
    process.env["0SEC_FORCE_PROVIDER"] = "openai";

    const rt = new LlmApiRuntime({ type: "api", timeout: 5000, model: "gpt-5.5" });

    expect(await rt.isAvailable()).toBe(true);
    expect(rt.outputTokenLimit).toBe(8192);
  });
});

// ── Azure Headers ──

describe("LlmApiRuntime Azure headers", () => {
  it("uses api-key header for Azure provider", () => {
    const rt = new LlmApiRuntime({
      type: "api",
      timeout: 5000,
      apiKey: "azure-key",
    });
    // Force Azure provider
    (rt as any).provider = "azure";
    (rt as any).apiKey = "azure-key-123";
    const headers = (rt as any).buildHeaders();
    expect(headers["api-key"]).toBe("azure-key-123");
    expect(headers["Authorization"]).toBeUndefined();
  });

  it("uses Bearer token for OpenAI provider", () => {
    const rt = new LlmApiRuntime({
      type: "api",
      timeout: 5000,
      apiKey: "sk-test",
    });
    (rt as any).provider = "openai";
    (rt as any).apiKey = "sk-test";
    const headers = (rt as any).buildHeaders();
    expect(headers["Authorization"]).toBe("Bearer sk-test");
    expect(headers["api-key"]).toBeUndefined();
  });
});

// ── Responses API Message Format ──

describe("LlmApiRuntime Responses API message format", () => {
  let rt: LlmApiRuntime;
  let capturedBody: any;

  beforeEach(() => {
    rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test-key" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "responses";
    (rt as any).apiKey = "test-key";

    // Mock fetch to capture the request body
    capturedBody = null;
    vi.stubGlobal("fetch", vi.fn(async (_url: string, opts: any) => {
      capturedBody = JSON.parse(opts.body);
      return {
        ok: true,
        text: async () => JSON.stringify({
          output: [
            { type: "message", content: [{ type: "output_text", text: "done" }] },
          ],
          usage: { input_tokens: 10, output_tokens: 5 },
        }),
      } as Response;
    }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("converts tool_use blocks to top-level function_call items", async () => {
    const messages: NativeMessage[] = [
      {
        role: "user",
        content: [{ type: "text", text: "test prompt" }],
      },
      {
        role: "assistant",
        content: [
          { type: "text", text: "I'll call a tool" },
          {
            type: "tool_use",
            id: "call_123",
            name: "http_request",
            input: { url: "https://example.com" },
          },
        ],
      },
      {
        role: "user",
        content: [
          {
            type: "tool_result",
            tool_use_id: "call_123",
            content: '{"status":200}',
          },
        ],
      },
    ];

    await rt.executeNative("system prompt", messages, []);

    // Verify the input structure
    const input = capturedBody.input;

    // System message
    expect(input[0].role).toBe("system");

    // User text
    expect(input[1].role).toBe("user");
    expect(input[1].content[0].type).toBe("input_text");

    // Assistant history must be serialized as `output_text` — the OpenAI
    // Responses API rejects `input_text` on an assistant message with a 400
    // ("Supported values are: 'output_text' and 'refusal'"), which used to
    // blow up every multi-turn Azure scan starting at turn 2.
    expect(input[2].role).toBe("assistant");
    expect(input[2].content[0].type).toBe("output_text");
    expect(input[2].content[0].text).toBe("I'll call a tool");

    // function_call should be a top-level item, NOT nested in content
    expect(input[3].type).toBe("function_call");
    expect(input[3].call_id).toBe("call_123");
    expect(input[3].name).toBe("http_request");
    expect(input[3].arguments).toBe('{"url":"https://example.com"}');

    // function_call_output should be a top-level item
    expect(input[4].type).toBe("function_call_output");
    expect(input[4].call_id).toBe("call_123");
    expect(input[4].output).toBe('{"status":200}');
  });

  it("handles multiple tool calls in one turn", async () => {
    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
      {
        role: "assistant",
        content: [
          { type: "tool_use", id: "c1", name: "http_request", input: { url: "https://a.com" } },
          { type: "tool_use", id: "c2", name: "send_prompt", input: { prompt: "hello" } },
        ],
      },
      {
        role: "user",
        content: [
          { type: "tool_result", tool_use_id: "c1", content: "result1" },
          { type: "tool_result", tool_use_id: "c2", content: "result2" },
        ],
      },
    ];

    await rt.executeNative("sys", messages, []);

    const input = capturedBody.input;
    // system(0), user(1), fn_call(2), fn_call(3), fn_output(4), fn_output(5)
    expect(input[2].type).toBe("function_call");
    expect(input[2].call_id).toBe("c1");
    expect(input[3].type).toBe("function_call");
    expect(input[3].call_id).toBe("c2");
    expect(input[4].type).toBe("function_call_output");
    expect(input[4].call_id).toBe("c1");
    expect(input[5].type).toBe("function_call_output");
    expect(input[5].call_id).toBe("c2");
  });

  it("regression: assistant text replies use output_text, not input_text (Azure 400 at turn 2+)", async () => {
    // This is the regression guard for the bug that made every multi-turn
    // Azure Responses API scan fail at turn 2 or later. The agent loop replays
    // the assistant's prior text reply on every turn to preserve context; if
    // we serialize that text with `input_text` the API 400s with:
    //   "Invalid value: 'input_text'. Supported values are: 'output_text' and 'refusal'."
    // The symptom in the TUI looked like a stuck attack stage that reached
    // max turns with 0 findings — the real cause was that every turn after
    // the first was getting rejected by Azure.
    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "initial user prompt" }] },
      {
        role: "assistant",
        content: [
          { type: "text", text: "I'll start by probing the target." },
          { type: "tool_use", id: "probe1", name: "http_request", input: { url: "https://t.invalid" } },
        ],
      },
      {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "probe1", content: '{"status":200}' }],
      },
      {
        role: "assistant",
        content: [{ type: "text", text: "The target is live. Let me try an SQL injection." }],
      },
      {
        role: "user",
        content: [{ type: "text", text: "follow-up from user" }],
      },
    ];

    await rt.executeNative("system", messages, []);

    const input = capturedBody.input;
    // Walk every item that carries a content array and assert role → type.
    // Assistant text MUST be `output_text`, everything else `input_text`.
    for (const item of input) {
      if (!Array.isArray(item.content)) continue;
      for (const block of item.content) {
        if (block.type === "input_text" || block.type === "output_text") {
          if (item.role === "assistant") {
            expect(block.type).toBe("output_text");
          } else {
            expect(block.type).toBe("input_text");
          }
        }
      }
    }

    // Sanity: at least one assistant-role item should exist in the serialized
    // input, and it should be carrying output_text. Otherwise the test above
    // would vacuously pass if the serializer ever dropped assistant messages
    // entirely.
    const assistantItems = input.filter((i: any) => i.role === "assistant" && Array.isArray(i.content));
    expect(assistantItems.length).toBeGreaterThan(0);
    expect(assistantItems[0].content[0].type).toBe("output_text");
  });

  it("does not nest function_call inside content arrays", async () => {
    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "start" }] },
      {
        role: "assistant",
        content: [
          { type: "tool_use", id: "tc1", name: "done", input: { summary: "ok" } },
        ],
      },
      {
        role: "user",
        content: [
          { type: "tool_result", tool_use_id: "tc1", content: '{"done":true}' },
        ],
      },
    ];

    await rt.executeNative("sys", messages, []);

    const input = capturedBody.input;
    // Verify no item has a nested function_call in its content array
    for (const item of input) {
      if (Array.isArray(item.content)) {
        for (const block of item.content) {
          expect(block.type).not.toBe("function_call");
          expect(block.type).not.toBe("function_call_output");
        }
      }
    }

    // The function_call should be at top level
    const fnCalls = input.filter((i: any) => i.type === "function_call");
    expect(fnCalls).toHaveLength(1);
    expect(fnCalls[0].call_id).toBe("tc1");
  });
});

// ── Chat Completions Message Format ──

describe("LlmApiRuntime chat completions format", () => {
  let rt: LlmApiRuntime;
  let capturedBody: any;

  beforeEach(() => {
    rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test-key" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";
    (rt as any).apiKey = "test-key";

    capturedBody = null;
    vi.stubGlobal("fetch", vi.fn(async (_url: string, opts: any) => {
      capturedBody = JSON.parse(opts.body);
      return {
        ok: true,
        text: async () => JSON.stringify({
          choices: [{ message: { content: "ok" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 10, completion_tokens: 5 },
        }),
      } as Response;
    }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("converts tool_use to OpenAI tool_calls format", async () => {
    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "hello" }] },
      {
        role: "assistant",
        content: [
          {
            type: "tool_use",
            id: "tc1",
            name: "http_request",
            input: { url: "https://x.com" },
          },
        ],
      },
      {
        role: "user",
        content: [
          { type: "tool_result", tool_use_id: "tc1", content: "result" },
        ],
      },
    ];

    await rt.executeNative("system", messages, []);

    const msgs = capturedBody.messages;
    // system(0), user(1), assistant with tool_calls(2), tool result(3)
    expect(msgs[0].role).toBe("system");
    expect(msgs[2].role).toBe("assistant");
    expect(msgs[2].tool_calls[0].id).toBe("tc1");
    expect(msgs[2].tool_calls[0].function.name).toBe("http_request");
    expect(msgs[3].role).toBe("tool");
    expect(msgs[3].tool_call_id).toBe("tc1");
  });

  it("attaches reasoning_effort on chat_completions only when explicitly set", async () => {
    // Regression: the field previously only went out on the Responses wire, so
    // every OpenAI-compatible provider (DeepSeek direct — where the knob is
    // measured to matter) ran at the server default. Endpoints that don't
    // know the field (Alibaba compatible-mode) silently ignore it, and the
    // default request shape must stay byte-identical.
    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "hi" }] },
    ];

    await rt.executeNative("system", messages, []);
    expect(capturedBody.reasoning_effort).toBeUndefined();

    (rt as any).reasoningEffort = "high";
    await rt.executeNative("system", messages, []);
    expect(capturedBody.reasoning_effort).toBe("high");
  });

  it("threads reasoning_effort through the legacy execute path too", async () => {
    (rt as any).reasoningEffort = "low";
    await rt.execute("prompt");
    expect(capturedBody.reasoning_effort).toBe("low");
  });
});

// ── Response Parsing ──

describe("LlmApiRuntime response parsing", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("parses function_call items from Responses API output", async () => {
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "responses";
    (rt as any).apiKey = "test";

    const sseEvent = `data: ${JSON.stringify({
      type: "response.completed",
      response: {
        output: [
          {
            type: "function_call",
            call_id: "fc_001",
            name: "http_request",
            arguments: '{"url":"https://target.com"}',
          },
        ],
        usage: { input_tokens: 50, output_tokens: 20 },
      },
    })}\n\n`;

    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(sseEvent));
          controller.close();
        },
      }),
    } as unknown as Response)));

    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], []);

    expect(result.stopReason).toBe("tool_use");
    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe("tool_use");
    const toolUse = result.content[0] as Extract<NativeContentBlock, { type: "tool_use" }>;
    expect(toolUse.id).toBe("fc_001");
    expect(toolUse.name).toBe("http_request");
    expect(toolUse.input).toEqual({ url: "https://target.com" });
  });

  it("parses tool_calls from chat completions response", async () => {
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";
    (rt as any).apiKey = "test";

    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      text: async () => JSON.stringify({
        choices: [{
          message: {
            content: null,
            tool_calls: [{
              id: "tc_abc",
              type: "function",
              function: {
                name: "send_prompt",
                arguments: '{"prompt":"test"}',
              },
            }],
          },
          finish_reason: "tool_calls",
        }],
        usage: { prompt_tokens: 30, completion_tokens: 10 },
      }),
    } as Response)));

    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], []);

    expect(result.stopReason).toBe("tool_use");
    expect(result.content).toHaveLength(1);
    const block = result.content[0] as Extract<NativeContentBlock, { type: "tool_use" }>;
    expect(block.name).toBe("send_prompt");
    expect(block.input).toEqual({ prompt: "test" });
  });

  it("emits onUsage for non-streaming wires (chat-completions AND anthropic)", async () => {
    // Regression: usage previously reached only `result.usage`, so callback-
    // only consumers (craft-scan) recorded 0 tokens on every non-streaming
    // provider (kimi/z-ai/anthropic/qwen/openai/azure-chat).
    const chatRt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test" });
    (chatRt as any).provider = "qwen";
    (chatRt as any).wireApi = "chat_completions";
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      text: async () => JSON.stringify({
        choices: [{ message: { content: "done" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 30, completion_tokens: 10 },
      }),
    } as Response)));
    const chatUsage: Array<{ inputTokens: number; outputTokens: number }> = [];
    await chatRt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], [], { onUsage: (u) => chatUsage.push(u) } as never);
    expect(chatUsage).toEqual([{ inputTokens: 30, outputTokens: 10 }]);

    const anthropicRt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test" });
    (anthropicRt as any).provider = "kimi";
    (anthropicRt as any).wireApi = "chat_completions";
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      text: async () => JSON.stringify({
        content: [{ type: "text", text: "done" }],
        stop_reason: "end_turn",
        usage: { input_tokens: 41, output_tokens: 9 },
      }),
    } as Response)));
    const anthropicUsage: Array<{ inputTokens: number; outputTokens: number }> = [];
    await anthropicRt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], [], { onUsage: (u) => anthropicUsage.push(u) } as never);
    expect(anthropicUsage).toHaveLength(1);
    expect(anthropicUsage[0]?.inputTokens).toBe(41);
    expect(anthropicUsage[0]?.outputTokens).toBe(9);
  });

  it("returns error result on API failure", async () => {
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";
    (rt as any).apiKey = "test";

    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: false,
      status: 400,
      text: async () => '{"error":"bad request"}',
    } as unknown as Response)));

    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], []);

    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("400");
  });
});

  it("retries a transient transport failure before failing the native turn", async () => {
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test" });
    // Test-only mutable view: force the OpenAI-compatible branch without env setup.
    const mutableRuntime = rt as unknown as {
      provider: string;
      wireApi: string;
      apiKey: string;
    };
    mutableRuntime.provider = "openai";
    mutableRuntime.wireApi = "chat_completions";
    mutableRuntime.apiKey = "test";
    const transportError = Object.assign(new TypeError("fetch failed"), {
      cause: Object.assign(new Error("connect timed out"), {
        code: "UND_ERR_CONNECT_TIMEOUT",
      }),
    });
    const fetchMock = vi.fn()
      .mockRejectedValueOnce(transportError)
      .mockResolvedValueOnce({
        ok: true,
        text: async () => JSON.stringify({
          choices: [{ message: { content: "ok" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 1, completion_tokens: 1 },
        }),
      } as Response);
    vi.stubGlobal("fetch", fetchMock);
    vi.stubEnv("0SEC_LLM_MAX_RETRIES", "1");
    vi.stubEnv("0SEC_LLM_MAX_RETRY_WAIT_MS", "500");
    vi.spyOn(Math, "random").mockReturnValue(0);

    try {
      const result = await rt.executeNative("sys", [
        { role: "user", content: [{ type: "text", text: "go" }] },
      ], []);
      expect(result.stopReason).toBe("end_turn");
      expect(fetchMock).toHaveBeenCalledTimes(2);
    } finally {
      vi.unstubAllEnvs();
      vi.restoreAllMocks();
    }
  });

// ── Live Azure Integration (only runs when AZURE_OPENAI_API_KEY is set) ──

const hasAzureKey = !!process.env.AZURE_OPENAI_API_KEY;
const shouldRunAzureLiveTest = hasAzureKey && process.env["0SEC_RUN_AZURE_LIVE_TEST"] === "1";

// Capture the real Azure key before any test mutates process.env.
const realAzureKey = process.env.AZURE_OPENAI_API_KEY;

function isTransientAzureLiveError(error: string | undefined): boolean {
  if (!error) return false;
  return (
    error.includes("DeploymentNotFound") ||
    error.includes("429") ||
    error.includes("500") ||
    error.includes("fetch failed") ||
    error.includes("timed out") ||
    error.includes("transient upstream failure")
  );
}

// ── Azure Region Probe (Task #85) ──

describe("probeAzureRegion", () => {
  beforeEach(() => {
    __resetAzureRegionCacheForTests();
    __resetProviderStartupLogForTests();
    delete process.env["0SEC_REGION_OVERRIDE"];
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    delete process.env["0SEC_REGION_OVERRIDE"];
  });

  it("parses x-ms-region header and pretty-prints the region", async () => {
    const mockFetch = vi.fn(async () => ({
      ok: false,
      status: 401,
      headers: new Headers({ "x-ms-region": "eastus2" }),
      text: async () => "",
    } as unknown as Response));
    const region = await probeAzureRegion(
      "https://rapidata-hackathon-resource.openai.azure.com/openai/v1",
      "fake-key",
      mockFetch as unknown as typeof fetch,
    );
    expect(region).toBe("East US 2");
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe(
      "https://rapidata-hackathon-resource.openai.azure.com/openai/v1/models",
    );
    expect((init as any).headers["api-key"]).toBe("fake-key");
  });

  it("returns 'unknown' when the x-ms-region header is absent", async () => {
    const mockFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      headers: new Headers({}),
      text: async () => "",
    } as unknown as Response));
    const region = await probeAzureRegion(
      "https://no-header-resource.openai.azure.com/openai/v1",
      "fake-key",
      mockFetch as unknown as typeof fetch,
    );
    expect(region).toBe("unknown");
  });

  it("returns 'unknown' on network failure without throwing", async () => {
    const mockFetch = vi.fn(async () => {
      throw new Error("network down");
    });
    const region = await probeAzureRegion(
      "https://broken.openai.azure.com/openai/v1",
      "fake-key",
      mockFetch as unknown as typeof fetch,
    );
    expect(region).toBe("unknown");
  });

  it("caches the result per base URL", async () => {
    const mockFetch = vi.fn(async () => ({
      ok: false,
      status: 401,
      headers: new Headers({ "x-ms-region": "westeurope" }),
      text: async () => "",
    } as unknown as Response));
    const url = "https://cached-resource.openai.azure.com/openai/v1";
    const r1 = await probeAzureRegion(url, "k", mockFetch as unknown as typeof fetch);
    const r2 = await probeAzureRegion(url, "k", mockFetch as unknown as typeof fetch);
    expect(r1).toBe("West Europe");
    expect(r2).toBe("West Europe");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("honors 0SEC_REGION_OVERRIDE without hitting the network", async () => {
    process.env["0SEC_REGION_OVERRIDE"] = "East US 2 (forced)";
    const mockFetch = vi.fn();
    const region = await probeAzureRegion(
      "https://any-resource.openai.azure.com/openai/v1",
      "fake-key",
      mockFetch as unknown as typeof fetch,
    );
    expect(region).toBe("East US 2 (forced)");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("passes through an unknown region code verbatim", async () => {
    const mockFetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      headers: new Headers({ "x-ms-region": "marscentral" }),
      text: async () => "",
    } as unknown as Response));
    const region = await probeAzureRegion(
      "https://mars.openai.azure.com/openai/v1",
      "k",
      mockFetch as unknown as typeof fetch,
    );
    expect(region).toBe("marscentral");
  });
});

describe.skipIf(!shouldRunAzureLiveTest)("Azure Responses API live integration", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    // Restore Azure key (provider detection tests delete it)
    process.env.AZURE_OPENAI_API_KEY = realAzureKey!;
    // Ensure Azure wins priority deterministically: clear every higher-
    // priority credential AND the operator's Codex login (auth file at
    // ~/.codex/auth.json), which otherwise pre-empts azure on dev hosts.
    delete process.env.OPENROUTER_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.DEEPSEEK_API_KEY;
    delete process.env.KIMI_API_KEY;
    delete process.env.QWEN_API_KEY;
    delete process.env.Z_AI_API_KEY;
    delete process.env["0SEC_CHATGPT_ACCESS_TOKEN"];
    delete process.env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"];
    process.env["0SEC_CHATGPT_AUTH_FILE"] = "/tmp/0sec-azure-live-test-no-auth.json";
  });

  it("completes a tool call and continuation round-trip", async () => {
    const rt = new LlmApiRuntime({ type: "api", timeout: 30_000 });

    // Turn 1: expect a tool call
    const turn1 = await rt.executeNative(
      "Use the ping tool when asked to check something.",
      [{ role: "user", content: [{ type: "text", text: "Please ping example.com" }] }],
      [{
        name: "ping",
        description: "Ping a host",
        input_schema: {
          type: "object",
          properties: { host: { type: "string", description: "Hostname" } },
          required: ["host"],
        },
      }],
    );

    // Skip if Azure deployment is temporarily unavailable (infra issue, not our code)
    if (isTransientAzureLiveError(turn1.error)) {
      console.warn("Skipping: Azure deployment unavailable —", turn1.error.slice(0, 100));
      return;
    }

    expect(turn1.error).toBeUndefined();
    expect(turn1.stopReason).toBe("tool_use");
    const toolUse = turn1.content.find((b): b is Extract<NativeContentBlock, { type: "tool_use" }> => b.type === "tool_use");
    expect(toolUse).toBeDefined();
    expect(toolUse!.name).toBe("ping");

    // Turn 2: send tool result back — this is the critical continuation
    const turn2 = await rt.executeNative(
      "Use the ping tool when asked to check something.",
      [
        { role: "user", content: [{ type: "text", text: "Please ping example.com" }] },
        { role: "assistant", content: turn1.content },
        { role: "user", content: [{
          type: "tool_result",
          tool_use_id: toolUse!.id,
          content: '{"alive":true,"latency_ms":12}',
        }] },
      ],
      [{
        name: "ping",
        description: "Ping a host",
        input_schema: {
          type: "object",
          properties: { host: { type: "string", description: "Hostname" } },
          required: ["host"],
        },
      }],
    );

    expect(turn2.error).toBeUndefined();
    expect(turn2.stopReason).toBe("end_turn");
    const text = turn2.content.find((b): b is Extract<NativeContentBlock, { type: "text" }> => b.type === "text");
    expect(text).toBeDefined();
    expect(text!.text.length).toBeGreaterThan(0);
  }, 60_000);
});

// ── 429 rate-limit backoff + retry (burst-scan resilience) ──
//
// The nightly sweep fires hundreds of scans at once; the shared ChatGPT/Codex
// subscription then returns HTTP 429. These tests pin the behaviour that keeps
// a rate-limited scan from failing as "no work": the wire layer backs off and
// retries retryable statuses, honours Retry-After, and only surfaces a real
// terminal error once retries are exhausted — while a non-retryable 4xx still
// fails fast.

describe("parseRetryAfterMs", () => {
  it("parses the delta-seconds form", () => {
    expect(parseRetryAfterMs("5")).toBe(5000);
    expect(parseRetryAfterMs("0")).toBe(0);
    expect(parseRetryAfterMs("  12 ")).toBe(12000);
  });

  it("parses the HTTP-date form as a future delta", () => {
    const future = new Date(Date.now() + 3000).toUTCString();
    const ms = parseRetryAfterMs(future);
    expect(ms).toBeGreaterThan(0);
    expect(ms).toBeLessThanOrEqual(3000);
  });

  it("clamps a past HTTP-date to 0", () => {
    const past = new Date(Date.now() - 10_000).toUTCString();
    expect(parseRetryAfterMs(past)).toBe(0);
  });

  it("returns undefined for absent or unparseable values", () => {
    expect(parseRetryAfterMs(null)).toBeUndefined();
    expect(parseRetryAfterMs(undefined)).toBeUndefined();
    expect(parseRetryAfterMs("")).toBeUndefined();
    expect(parseRetryAfterMs("soon")).toBeUndefined();
  });
});

describe("parseUsageLimitReached", () => {
  it("parses the nested ChatGPT/Codex error shape", () => {
    const resetsAtS = Math.floor(
      new Date("2026-07-19T00:00:00Z").getTime() / 1000,
    );
    const details = parseUsageLimitReached(
      JSON.stringify({
        error: {
          type: "usage_limit_reached",
          message: "You have reached your usage limit.",
          plan_type: "pro",
          resets_at: resetsAtS,
          resets_in_seconds: 172_800,
        },
      }),
    );
    expect(details).toBeDefined();
    expect(details?.planType).toBe("pro");
    expect(details?.resetsAtMs).toBe(resetsAtS * 1000);
    expect(details?.resetsInSeconds).toBe(172_800);
  });

  it("parses Alibaba Token Plan insufficient_quota", () => {
    const details = parseUsageLimitReached(
      JSON.stringify({
        error: {
          message:
            "Your token-plan 1-week quota has been exhausted. The quota will reset at 08-12 21:25:00 UTC.",
          type: "insufficient_quota",
          code: "insufficient_quota",
        },
      }),
    );
    // The reset arrives as message text (month-day, no year): current year,
    // rolling forward a year when that lands in the past.
    const y = new Date().getUTCFullYear();
    let resets = Date.UTC(y, 7, 12, 21, 25, 0);
    if (resets <= Date.now()) resets = Date.UTC(y + 1, 7, 12, 21, 25, 0);
    expect(details).toEqual({
      quotaKind: "insufficient_quota",
      planType: "token-plan",
      resetsAtMs: resets,
    });
  });

  it("parses the Alibaba text reset without a UTC suffix (5-hour form)", () => {
    const details = parseUsageLimitReached(
      JSON.stringify({
        error: {
          message:
            "Your token-plan 5-hour quota has been exhausted. The quota will reset at 12-31 15:24:00.",
          type: "insufficient_quota",
          code: "insufficient_quota",
        },
      }),
    );
    const y = new Date().getUTCFullYear();
    let resets = Date.UTC(y, 11, 31, 15, 24, 0);
    if (resets <= Date.now()) resets = Date.UTC(y + 1, 11, 31, 15, 24, 0);
    expect(details?.resetsAtMs).toBe(resets);
  });

  it("derives resetsAtMs from resets_in_seconds when resets_at is absent", () => {
    const before = Date.now();
    const details = parseUsageLimitReached(
      JSON.stringify({
        error: { type: "usage_limit_reached", resets_in_seconds: 3600 },
      }),
    );
    const after = Date.now();
    expect(details?.resetsInSeconds).toBe(3600);
    expect(details?.resetsAtMs).toBeGreaterThanOrEqual(before + 3_600_000);
    expect(details?.resetsAtMs).toBeLessThanOrEqual(after + 3_600_000);
  });

  it("accepts the un-nested (top-level) shape", () => {
    const details = parseUsageLimitReached(
      JSON.stringify({ type: "usage_limit_reached", plan_type: "plus" }),
    );
    expect(details?.planType).toBe("plus");
  });

  it("returns undefined for regular 429 bodies and non-JSON", () => {
    expect(
      parseUsageLimitReached('{"detail":"rate limit exceeded"}'),
    ).toBeUndefined();
    expect(
      parseUsageLimitReached('{"error":{"type":"rate_limit_exceeded"}}'),
    ).toBeUndefined();
    expect(parseUsageLimitReached("not json")).toBeUndefined();
    expect(parseUsageLimitReached("")).toBeUndefined();
  });
});

describe("QuotaExhaustedError", () => {
  it("carries the typed quota fields", () => {
    const err = new QuotaExhaustedError("msg", {
      quotaKind: "usage_limit_reached",
      planType: "pro",
      resetsAtMs: 1_784_428_800_000,
      resetsInSeconds: 172_800,
    });
    expect(err.name).toBe("QuotaExhaustedError");
    expect(err.quotaKind).toBe("usage_limit_reached");
    expect(err.planType).toBe("pro");
    expect(err.resetsAtMs).toBe(1_784_428_800_000);
    expect(err.resetsInSeconds).toBe(172_800);
    expect(err).toBeInstanceOf(Error);
  });
});

describe("isRetryableHttpStatus", () => {
  it("retries 429 and transient 5xx", () => {
    for (const s of [429, 500, 502, 503, 504]) {
      expect(isRetryableHttpStatus(s)).toBe(true);
    }
  });

  it("does not retry auth/bad-request 4xx or success 2xx", () => {
    for (const s of [200, 400, 401, 403, 404, 422]) {
      expect(isRetryableHttpStatus(s)).toBe(false);
    }
  });
});

describe("retryBackoffMs", () => {
  it("grows with attempt and stays within the jittered ceiling", () => {
    for (let attempt = 0; attempt < 8; attempt++) {
      const ms = retryBackoffMs(attempt);
      const ceiling = Math.min(20_000, 500 * 2 ** attempt);
      expect(ms).toBeGreaterThanOrEqual(250);
      expect(ms).toBeLessThanOrEqual(ceiling + 250);
    }
  });
});

describe("LlmApiRuntime 429 backoff + retry", () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    process.env["0SEC_SKIP_PROVIDER_BANNER"] = "1";
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    Object.assign(process.env, origEnv);
    for (const k of [
      "0SEC_LLM_MAX_RETRIES",
      "0SEC_LLM_MAX_RETRY_WAIT_MS",
      "0SEC_LLM_429_MAX_RETRIES",
      "0SEC_LLM_429_MAX_RETRY_WAIT_MS",
    ]) {
      if (!(k in origEnv)) delete process.env[k];
    }
  });

  function mkRuntime(): LlmApiRuntime {
    const rt = new LlmApiRuntime({ type: "api", timeout: 30_000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";
    // test fixture, literal non-secret "test" key
    // foxguard: ignore[js/no-hardcoded-secret]
    (rt as any).apiKey = "test";
    return rt;
  }

  function rateLimited(retryAfter?: string): Response {
    const headers = new Headers();
    if (retryAfter != null) headers.set("retry-after", retryAfter);
    return {
      ok: false,
      status: 429,
      headers,
      text: async () => '{"detail":"rate limit exceeded"}',
    } as unknown as Response;
  }

  function okChat(text: string): Response {
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          choices: [{ message: { content: text }, finish_reason: "stop" }],
          usage: { prompt_tokens: 10, completion_tokens: 5 },
        }),
    } as unknown as Response;
  }

  const userMsg: NativeMessage[] = [
    { role: "user", content: [{ type: "text", text: "go" }] },
  ];

  it("retries a 429 then succeeds (does not fail the scan)", async () => {
    const responses = [rateLimited("0"), okChat("done")];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal("fetch", fetchMock);

    const rt = mkRuntime();
    const result = await rt.executeNative("sys", userMsg, []);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.stopReason).toBe("end_turn");
    expect(result.error).toBeUndefined();
  });

  it("honors a Retry-After header and retries", async () => {
    const responses = [rateLimited("0"), rateLimited("0"), okChat("ok")];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal("fetch", fetchMock);

    const rt = mkRuntime();
    const start = Date.now();
    const result = await rt.executeNative("sys", userMsg, []);

    // Retry-After "0" → no backoff wait; both retries complete near-instantly.
    expect(Date.now() - start).toBeLessThan(2000);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(result.error).toBeUndefined();
  });

  it("surfaces a clear terminal error after retries are exhausted", async () => {
    process.env["0SEC_LLM_MAX_RETRIES"] = "2";
    const fetchMock = vi.fn(async () => rateLimited("0"));
    vi.stubGlobal("fetch", fetchMock);

    const rt = mkRuntime();
    const result = await rt.executeNative("sys", userMsg, []);

    // 1 initial + 2 retries = 3 calls, then a REAL error (not silent no-work).
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("429");
  });

  it("does NOT retry a non-retryable 400 (fails fast)", async () => {
    const fetchMock = vi.fn(
      async () =>
        ({
          ok: false,
          status: 400,
          headers: new Headers(),
          text: async () => '{"error":"bad request"}',
        }) as unknown as Response,
    );
    vi.stubGlobal("fetch", fetchMock);

    const rt = mkRuntime();
    const result = await rt.executeNative("sys", userMsg, []);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("400");
  });

  function quotaLimited(): Response {
    const resetsAtS = Math.floor(
      new Date("2026-07-19T00:00:00Z").getTime() / 1000,
    );
    return {
      ok: false,
      status: 429,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          error: {
            type: "usage_limit_reached",
            message: "You have reached your usage limit.",
            plan_type: "pro",
            resets_at: resetsAtS,
            resets_in_seconds: 172_800,
          },
        }),
    } as unknown as Response;
  }

  it("fails fast on usage_limit_reached (plan quota) — never retried", async () => {
    const fetchMock = vi.fn(async () => quotaLimited());
    vi.stubGlobal("fetch", fetchMock);

    const rt = mkRuntime();
    const result = await rt.executeNative("sys", userMsg, []);

    // ONE call only: plan quota resets in hours/days, so retrying is waste.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("usage_limit_reached");
    expect(result.error).toContain("plan=pro");
    expect(result.error).toContain("resets_at=2026-07-19T00:00:00.000Z");
    // Distinct from the per-minute exhaustion shape ("API error 429: ...").
    expect(result.error).not.toContain("API error 429");
  });

  it("detects plan quota even after per-minute 429 retries have started", async () => {
    const responses = [rateLimited("0"), quotaLimited()];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal("fetch", fetchMock);

    const rt = mkRuntime();
    const result = await rt.executeNative("sys", userMsg, []);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.error).toContain("usage_limit_reached");
  });

  it("honors retry-after-ms (millisecond form) over retry-after", async () => {
    const headers = new Headers();
    headers.set("retry-after", "60"); // must be ignored in favour of the ms form
    headers.set("retry-after-ms", "250");
    const responses = [
      {
        ok: false,
        status: 429,
        headers,
        text: async () => '{"detail":"rate limit exceeded"}',
      } as unknown as Response,
      okChat("ok"),
    ];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal("fetch", fetchMock);
    const stderrSpy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);

    const rt = mkRuntime();
    const result = await rt.executeNative("sys", userMsg, []);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.error).toBeUndefined();
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining("backoff 250ms"),
    );
  });

  it("caps a long Retry-After at 120s instead of honoring it verbatim", async () => {
    vi.useFakeTimers();
    const stderrSpy = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    const responses = [rateLimited("300"), rateLimited("300"), okChat("capped")];
    const fetchMock = vi.fn(async () => responses.shift()!);
    vi.stubGlobal("fetch", fetchMock);

    // Big call timeout so the per-call abort timer can't fire mid-test; only
    // the retry sleeps (capped 120s each) are on the clock.
    const rt = new LlmApiRuntime({ type: "api", timeout: 600_000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";
    // test fixture, literal non-secret "test" key
    // foxguard: ignore[js/no-hardcoded-secret]
    (rt as any).apiKey = "test";

    const promise = rt.executeNative("sys", userMsg, []);
    await vi.advanceTimersByTimeAsync(300_000);
    const result = await promise;

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(result.error).toBeUndefined();
    expect(result.stopReason).toBe("end_turn");
    // Uncapped, the server asked for 300000ms; the emitted wait must be 120000.
    expect(stderrSpy).toHaveBeenCalledWith(
      expect.stringContaining("backoff 120000ms"),
    );
    expect(stderrSpy).not.toHaveBeenCalledWith(
      expect.stringContaining("backoff 300000ms"),
    );
  });

  it("widens the default 429 budget to 12 retries and preserves the body on exhaustion", async () => {
    const fetchMock = vi.fn(async () => rateLimited("0"));
    vi.stubGlobal("fetch", fetchMock);

    const rt = mkRuntime();
    const result = await rt.executeNative("sys", userMsg, []);

    // 1 initial + 12 retries (default 0SEC_LLM_429_MAX_RETRIES).
    expect(fetchMock).toHaveBeenCalledTimes(13);
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("429");
    // The classified-and-re-wrapped response still carries the original body.
    expect(result.error).toContain("rate limit exceeded");
  });

  it("respects 0SEC_LLM_429_MAX_RETRIES when set", async () => {
    process.env["0SEC_LLM_429_MAX_RETRIES"] = "3";
    const fetchMock = vi.fn(async () => rateLimited("0"));
    vi.stubGlobal("fetch", fetchMock);

    const rt = mkRuntime();
    const result = await rt.executeNative("sys", userMsg, []);

    expect(fetchMock).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
    expect(result.error).toContain("429");
  });

  it("keeps the transient 5xx budget unchanged (6 retries by default)", async () => {
    const fetchMock = vi.fn(
      async () =>
        ({
          ok: false,
          status: 503,
          headers: new Headers({ "retry-after": "0" }),
          text: async () => '{"error":"service unavailable"}',
        }) as unknown as Response,
    );
    vi.stubGlobal("fetch", fetchMock);

    const rt = mkRuntime();
    const result = await rt.executeNative("sys", userMsg, []);

    // 1 initial + 6 retries — the generic budget, not the widened 429 one.
    expect(fetchMock).toHaveBeenCalledTimes(7);
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("503");
  });
});

// ── SSE stream idle watchdog (the silent-stall kill) ──

describe("LlmApiRuntime stream idle watchdog", () => {
  const IDLE_ENV = "0SEC_LLM_STREAM_IDLE_TIMEOUT_MS";

  afterEach(() => {
    delete process.env[IDLE_ENV];
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  const mkStreamingRt = (timeout = 5000) => {
    const rt = new LlmApiRuntime({ type: "api", timeout, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "responses";
    (rt as any).apiKey = "test";
    return rt;
  };
  const userMsg: NativeMessage[] = [
    { role: "user", content: [{ type: "text", text: "go" }] },
  ];

  it("fails a never-yielding SSE stream as a transient stall instead of hanging", async () => {
    process.env[IDLE_ENV] = "200";
    const rt = mkStreamingRt();
    // Server accepts (200) then holds the stream open without a single byte —
    // the exact ChatGPT-backend hold reproduced on E2B + microsandbox.
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      body: new ReadableStream<Uint8Array>({ start() { /* never enqueues */ } }),
    } as unknown as Response)));

    const t0 = Date.now();
    const result = await rt.executeNative("sys", userMsg, []);
    expect(Date.now() - t0).toBeLessThan(4000); // bounded — never a hang
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("stalled");
  });

  it("trips the watchdog when the stream yields once then goes silent", async () => {
    process.env[IDLE_ENV] = "200";
    const rt = mkStreamingRt();
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(
            `data: ${JSON.stringify({ type: "response.output_text.delta", delta: "hi" })}\n\n`,
          ));
          // then silence forever — never closes
        },
      }),
    } as unknown as Response)));

    const result = await rt.executeNative("sys", userMsg, []);
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("stalled");
  });

  it("applies the total request timeout even while an SSE stream keeps yielding", async () => {
    vi.useFakeTimers();
    process.env[IDLE_ENV] = "1000";
    const rt = mkStreamingRt(80);
    vi.stubGlobal("fetch", vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const signal = init?.signal;
      if (!signal) throw new Error("missing abort signal");
      let interval: ReturnType<typeof setInterval> | undefined;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          interval = setInterval(() => {
            controller.enqueue(new TextEncoder().encode(
              `data: ${JSON.stringify({ type: "response.output_text.delta", delta: "." })}\n\n`,
            ));
          }, 10);
          signal.addEventListener("abort", () => {
            clearInterval(interval);
            controller.error(signal.reason);
          }, { once: true });
        },
        cancel() {
          clearInterval(interval);
        },
      });
      return { ok: true, body };
    }));

    const pending = rt.executeNative("sys", userMsg, []);
    await vi.advanceTimersByTimeAsync(0);
    await vi.advanceTimersByTimeAsync(100);
    const result = await pending;
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("timed out");
  });

  it("healthy streams complete well inside the idle window", async () => {
    process.env[IDLE_ENV] = "5000";
    const rt = mkStreamingRt();
    const sseEvent = `data: ${JSON.stringify({
      type: "response.completed",
      response: { output: [], usage: { input_tokens: 5, output_tokens: 1 } },
    })}\n\n`;
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true,
      body: new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(sseEvent));
          controller.close();
        },
      }),
    } as unknown as Response)));

    const result = await rt.executeNative("sys", userMsg, []);
    expect(result.stopReason).not.toBe("error");
    expect(result.error ?? "").not.toContain("stalled");
  });

  it("pins 401/403 as NON-retryable at the wire layer (auth fails fast)", () => {
    expect(isRetryableHttpStatus(401)).toBe(false);
    expect(isRetryableHttpStatus(403)).toBe(false);
  });
});

// ── 0SEC_LLM_FALLBACK ──────────────────────────────────────────────────────

describe("parseLlmFallbackChain", () => {
  const origVal = process.env["0SEC_LLM_FALLBACK"];
  afterEach(() => {
    if (origVal === undefined) delete process.env["0SEC_LLM_FALLBACK"];
    else process.env["0SEC_LLM_FALLBACK"] = origVal;
  });

  it("returns empty when unset", () => {
    delete process.env["0SEC_LLM_FALLBACK"];
    expect(parseLlmFallbackChain()).toEqual([]);
  });

  it("returns empty for empty string", () => {
    process.env["0SEC_LLM_FALLBACK"] = "";
    expect(parseLlmFallbackChain()).toEqual([]);
  });

  it("parses a single entry", () => {
    process.env["0SEC_LLM_FALLBACK"] = "azure:gpt-5-deployment";
    expect(parseLlmFallbackChain()).toEqual([
      { provider: "azure", model: "gpt-5-deployment" },
    ]);
  });

  it("parses multiple entries in order", () => {
    process.env["0SEC_LLM_FALLBACK"] = "deepseek:deepseek-v4-flash,azure:gpt-5-deployment,openrouter:qwen/qwen-2.5-coder-32b-instruct";
    expect(parseLlmFallbackChain()).toEqual([
      { provider: "deepseek", model: "deepseek-v4-flash" },
      { provider: "azure", model: "gpt-5-deployment" },
      { provider: "openrouter", model: "qwen/qwen-2.5-coder-32b-instruct" },
    ]);
  });

  it("skips unknown providers with a warning", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    process.env["0SEC_LLM_FALLBACK"] = "unknown:foo,openai:gpt-4o";
    expect(parseLlmFallbackChain()).toEqual([
      { provider: "openai", model: "gpt-4o" },
    ]);
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining("unknown provider"));
    stderrSpy.mockRestore();
  });

  it("skips malformed entries with a warning", () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
    process.env["0SEC_LLM_FALLBACK"] = "justprovider,openai:gpt-4o";
    expect(parseLlmFallbackChain()).toEqual([
      { provider: "openai", model: "gpt-4o" },
    ]);
    expect(stderrSpy).toHaveBeenCalledWith(expect.stringContaining("malformed"));
    stderrSpy.mockRestore();
  });
});

describe("resolveFailoverProvider", () => {
  const origEnv = { ...process.env };
  afterEach(() => {
    for (const k of Object.keys(process.env)) {
      if (!(k in origEnv)) delete process.env[k];
    }
    Object.assign(process.env, origEnv);
  });

  it("returns undefined when the provider's auth env is absent", () => {
    delete process.env.DEEPSEEK_API_KEY;
    expect(resolveFailoverProvider("deepseek", "deepseek-v4-flash")).toBeUndefined();
  });

  it("resolves deepseek when key is present", () => {
    process.env.DEEPSEEK_API_KEY = "ds-key";
    const cfg = resolveFailoverProvider("deepseek", "deepseek-v4-flash");
    expect(cfg).not.toBeUndefined();
    expect(cfg!.apiKey).toBe("ds-key");
    expect(cfg!.wireApi).toBe("responses");
  });

  it("resolves openrouter when key is present", () => {
    process.env.OPENROUTER_API_KEY = "sk-or-fallback";
    const cfg = resolveFailoverProvider("openrouter", "qwen/qwen-2.5-coder-32b-instruct");
    expect(cfg).not.toBeUndefined();
    expect(cfg!.apiKey).toBe("sk-or-fallback");
    expect(cfg!.wireApi).toBe("chat_completions");
  });

  it("resolves azure when key and base URL are present", () => {
    process.env.AZURE_OPENAI_API_KEY = "az-key";
    process.env.AZURE_OPENAI_BASE_URL = "https://test.openai.azure.com";
    const cfg = resolveFailoverProvider("azure", "gpt-5-deployment");
    expect(cfg).not.toBeUndefined();
    expect(cfg!.apiKey).toBe("az-key");
    expect(cfg!.baseUrl).toContain("azure.com");
  });

  it("returns undefined for azure when base URL is missing", () => {
    process.env.AZURE_OPENAI_API_KEY = "az-key";
    delete process.env.AZURE_OPENAI_BASE_URL;
    // No base URL from the codex config either (no file present)
    expect(resolveFailoverProvider("azure", "gpt-5")).toBeUndefined();
  });

  it("resolves anthropic when key is present", () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-fallback";
    const cfg = resolveFailoverProvider("anthropic", "claude-sonnet-4-20250514");
    expect(cfg).not.toBeUndefined();
    expect(cfg!.apiKey).toBe("sk-ant-fallback");
  });
});

describe("LlmApiRuntime cross-provider failover (0SEC_LLM_FALLBACK)", () => {
  const origEnv = { ...process.env };

  function rateOnly429(): Response {
    return {
      ok: false,
      status: 429,
      headers: new Headers({ "retry-after": "0" }),
      text: async () => '{"detail":"rate limit exceeded"}',
    } as unknown as Response;
  }

  function quotaLimited(): Response {
    return {
      ok: false,
      status: 429,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          error: {
            type: "usage_limit_reached",
            message: "Token Plan weekly quota exhausted.",
            plan_type: "weekly",
          },
        }),
    } as unknown as Response;
  }

  function alibabaTokenPlanQuotaLimited(): Response {
    return {
      ok: false,
      status: 429,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          error: {
            message:
              "Your token-plan 1-week quota has been exhausted. The quota will reset at 08-12 21:25:00 UTC.",
            type: "insufficient_quota",
            code: "insufficient_quota",
          },
        }),
    } as unknown as Response;
  }

  function okChat(text: string): Response {
    return {
      ok: true,
      status: 200,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          choices: [{ message: { content: text }, finish_reason: "stop" }],
          usage: { prompt_tokens: 10, completion_tokens: 5 },
        }),
    } as unknown as Response;
  }

  beforeEach(() => {
    // Start with a clean env for the primary provider.
    for (const k of [
      "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY",
      "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_BASE_URL", "OPENAI_API_KEY",
      "KIMI_API_KEY", "QWEN_API_KEY", "Z_AI_API_KEY",
      "0SEC_CHATGPT_ACCESS_TOKEN", "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN",
      "0SEC_CHATGPT_ACCOUNT_ID", "0SEC_MODEL",
      "0SEC_LLM_MAX_RETRIES", "0SEC_LLM_MAX_RETRY_WAIT_MS",
      "0SEC_LLM_429_MAX_RETRIES", "0SEC_LLM_429_MAX_RETRY_WAIT_MS",
      "0SEC_LLM_FALLBACK",
    ]) {
      if (!(k in origEnv)) delete process.env[k];
    }
    process.env["0SEC_CHATGPT_AUTH_FILE"] = "/tmp/0sec-provider-test-no-auth.json";
    process.env["0SEC_SKIP_PROVIDER_BANNER"] = "1";
    __resetFallbackChainForTests();
  });

  afterEach(() => {
    for (const k of Object.keys(process.env)) {
      if (!(k in origEnv)) delete process.env[k];
    }
    Object.assign(process.env, origEnv);
    __resetFallbackChainForTests();
  });

  it("fails over to the next provider after exhausting the 429 budget", async () => {
    // Primary: OpenAI. Fallback: OpenRouter with a different model.
    process.env.OPENAI_API_KEY = "sk-openai-primary";
    process.env.OPENROUTER_API_KEY = "sk-or-fallback";
    // Urgent: 0SEC_LLM_FALLBACK entries and 12 429s for the primary.
    // Tune 429 budget so it exhausts quickly: 1 retry then failover.
    process.env["0SEC_LLM_429_MAX_RETRIES"] = "1";
    process.env["0SEC_LLM_FALLBACK"] = "openrouter:qwen/qwen-2.5-coder-32b-instruct";

    let fetchCalls = 0;
    const fetchMock = vi.fn(async () => {
      fetchCalls++;
      if (fetchCalls <= 2) {
        // Primary gets 1 initial + 1 retry = 2 calls, all 429.
        return rateOnly429();
      }
      // Fallback provider succeeds.
      return okChat("fallback worked");
    });
    vi.stubGlobal("fetch", fetchMock);

    const msg: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ];

    const rt = new LlmApiRuntime({ type: "api", timeout: 30_000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";

    const result = await rt.executeNative("sys", msg, []);

    expect(result.stopReason).not.toBe("error");
    expect(result.error).toBeUndefined();
    // 2 calls to primary (initial + 1 retry) + 1 call to fallback = 3 total.
    expect(fetchCalls).toBeGreaterThanOrEqual(3);
  });

  it("immediately advances the fallback chain on Alibaba Token Plan quota exhaustion", async () => {
    // Test fixtures, literal non-secret keys.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.OPENAI_API_KEY = "sk-openai-primary";
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.OPENROUTER_API_KEY = "sk-or-fallback";
    process.env["0SEC_LLM_FALLBACK"] =
      "openrouter:qwen/qwen-2.5-coder-32b-instruct";

    let fetchCalls = 0;
    const fetchMock = vi.fn(async () => {
      fetchCalls++;
      return fetchCalls === 1
        ? alibabaTokenPlanQuotaLimited()
        : okChat("fallback after quota");
    });
    vi.stubGlobal("fetch", fetchMock);

    const msg: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ];
    const rt = new LlmApiRuntime({ type: "api", timeout: 30_000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";

    const result = await rt.executeNative("sys", msg, []);

    expect(result.stopReason).not.toBe("error");
    expect(result.error).toBeUndefined();
    // Quota is never retried: primary quota response, then declared fallback.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(String(fetchMock.mock.calls[1]?.[0])).toContain("openrouter.ai");
  });

  it("takes the deployed Token Plan → Kimi → Azure chain in order", async () => {
    // Test fixtures, literal non-secret keys.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.QWEN_API_KEY = "sk-sp-qwen-primary";
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.KIMI_API_KEY = "kimi-fallback";
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.AZURE_OPENAI_API_KEY = "azure-fallback";
    process.env.AZURE_OPENAI_BASE_URL = "https://azure.example/openai/v1";
    process.env["0SEC_LLM_FALLBACK"] = "kimi:k3,azure:DeepSeek-V4-Pro";

    let fetchCalls = 0;
    const fetchMock = vi.fn(async () => {
      fetchCalls++;
      return fetchCalls < 3
        ? alibabaTokenPlanQuotaLimited()
        : okChat("Azure fallback worked");
    });
    vi.stubGlobal("fetch", fetchMock);

    const msg: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ];
    const rt = new LlmApiRuntime({
      type: "api",
      timeout: 30_000,
      model: "deepseek-v4-flash-0731",
    });
    const result = await rt.executeNative("sys", msg, []);

    expect(result.stopReason).not.toBe("error");
    expect(result.error).toBeUndefined();
    expect(fetchCalls).toBe(3);
    expect(String(fetchMock.mock.calls[0]?.[0])).toContain("token-plan.");
    expect(String(fetchMock.mock.calls[1]?.[0])).toContain("api.kimi.com");
    expect(String(fetchMock.mock.calls[2]?.[0])).toContain("azure.example");
  });

  it("surfaces the terminal error when the fallback chain is exhausted", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-primary";
    process.env.OPENROUTER_API_KEY = "sk-or-fallback";
    process.env["0SEC_LLM_429_MAX_RETRIES"] = "0";
    process.env["0SEC_LLM_FALLBACK"] = "openrouter:qwen/qwen-2.5-coder-32b-instruct";

    let callCount = 0;
    const fetchMock = vi.fn(async () => {
      callCount++;
      return rateOnly429();
    });
    vi.stubGlobal("fetch", fetchMock);

    const msg: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ];

    const rt = new LlmApiRuntime({ type: "api", timeout: 10_000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";

    const result = await rt.executeNative("sys", msg, []);

    // Both primary and fallback exhausted — terminal error.
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("429");
    // Initial (0 retries) to primary + initial (0 retries) to fallback = 2.
    expect(callCount).toBe(2);
  });

  it("surfaces quota exhaustion only after every configured fallback is exhausted", async () => {
    // Test fixtures, literal non-secret keys.
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.OPENAI_API_KEY = "sk-openai-primary";
    // foxguard: ignore[js/no-hardcoded-secret]
    process.env.OPENROUTER_API_KEY = "sk-or-fallback";
    process.env["0SEC_LLM_FALLBACK"] =
      "openrouter:qwen/qwen-2.5-coder-32b-instruct";
    const fetchMock = vi.fn(async () => alibabaTokenPlanQuotaLimited());
    vi.stubGlobal("fetch", fetchMock);

    const msg: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ];
    const rt = new LlmApiRuntime({ type: "api", timeout: 30_000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";

    const result = await rt.executeNative("sys", msg, []);

    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("insufficient_quota");
    // One immediate attempt per provider; neither weekly quota response retries.
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does NOT fail over for non-429 errors", async () => {
    process.env.OPENAI_API_KEY = "sk-openai-primary";
    process.env.OPENROUTER_API_KEY = "sk-or-fallback";
    process.env["0SEC_LLM_FALLBACK"] = "openrouter:qwen/qwen-2.5-coder-32b-instruct";

    const fetchMock = vi.fn(
      async () =>
        ({
          ok: false,
          status: 400,
          headers: new Headers(),
          text: async () => '{"error":"bad request"}',
        }) as unknown as Response,
    );
    vi.stubGlobal("fetch", fetchMock);

    const msg: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ];

    const rt = new LlmApiRuntime({ type: "api", timeout: 10_000, apiKey: "test" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "chat_completions";

    const result = await rt.executeNative("sys", msg, []);

    // 400 fails fast — no retry, no failover.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.stopReason).toBe("error");
  });
});
