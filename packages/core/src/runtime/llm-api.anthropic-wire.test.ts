import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { LlmApiRuntime } from "./llm-api.js";
import type { NativeMessage } from "./types.js";

/**
 * Routing guard for the Anthropic Messages wire shared by the real `anthropic`
 * provider and the two Anthropic-compatible endpoints, z-ai (GLM) and kimi
 * (Moonshot).
 *
 * These providers ride `/v1/messages` (x-api-key + anthropic-version) ONLY by
 * being absent from `isOpenAICompat` and matched by the positive
 * `isAnthropicWire` predicate. Their `wireApi` field is a dead
 * "chat_completions" default that must never route them. If someone ever adds
 * either provider to `isOpenAICompat` — or starts trusting `wireApi` — they get
 * silently mis-routed to `/chat/completions` with a Bearer header. The
 * assertions below lock that footgun shut.
 */

describe("Anthropic Messages wire routing and retained thinking", () => {
  const origEnv = { ...process.env };

  beforeEach(() => {
    // Clear every provider credential so detection is deterministic.
    delete process.env.OPENROUTER_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_BASE_URL;
    delete process.env.AZURE_OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.KIMI_API_KEY;
    delete process.env.KIMI_BASE_URL;
    delete process.env.Z_AI_API_KEY;
    delete process.env.Z_AI_BASE_URL;
    delete process.env.PWNKIT_MODEL;
    delete process.env.PWNKIT_ZAI_THINKING_BUDGET;
    delete process.env.PWNKIT_CHATGPT_ACCESS_TOKEN;
    delete process.env.PWNKIT_CHATGPT_OAUTH_REFRESH_TOKEN;
    process.env.PWNKIT_CHATGPT_AUTH_FILE = "/tmp/pwnkit-anthropic-wire-test-no-auth.json";
    process.env.PWNKIT_SKIP_PROVIDER_BANNER = "1";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    Object.assign(process.env, origEnv);
  });

  // ── (a) kimi wire round-trip ──

  describe("kimi (Moonshot) wire round-trip", () => {
    it("routes to /v1/messages with x-api-key + anthropic-version headers", () => {
      process.env.KIMI_API_KEY = "kimi-test-key";
      const rt = new LlmApiRuntime({ type: "api", timeout: 5000, model: "k3" });

      expect((rt as any).provider).toBe("kimi");
      const url = (rt as any).buildUrl() as string;
      expect(url.endsWith("/v1/messages")).toBe(true);

      const headers = (rt as any).buildHeaders() as Record<string, string>;
      expect(headers["x-api-key"]).toBe("kimi-test-key");
      expect(headers["anthropic-version"]).toBe("2023-06-01");
      // Never an OpenAI-style Bearer header on this wire.
      expect(headers["Authorization"]).toBeUndefined();
    });

    it("builds an Anthropic body and parses the Anthropic response", async () => {
      process.env.KIMI_API_KEY = "kimi-test-key";
      const rt = new LlmApiRuntime({ type: "api", timeout: 5000, model: "k3" });

      let capturedBody: Record<string, unknown> = {};
      vi.stubGlobal(
        "fetch",
        vi.fn(async (_url: string, opts: { body: string }) => {
          capturedBody = JSON.parse(opts.body) as Record<string, unknown>;
          return {
            ok: true,
            text: async () =>
              JSON.stringify({
                content: [
                  { type: "text", text: "probing" },
                  {
                    type: "tool_use",
                    id: "tu_1",
                    name: "http_request",
                    input: { url: "https://target.test/" },
                  },
                ],
                stop_reason: "tool_use",
                usage: { input_tokens: 100, output_tokens: 25 },
              }),
          } as unknown as Response;
        }),
      );

      const messages: NativeMessage[] = [
        { role: "user", content: [{ type: "text", text: "audit this target" }] },
      ];
      const result = await rt.executeNative("SYSTEM PROMPT", messages, [
        {
          name: "http_request",
          description: "send a request",
          input_schema: { type: "object", properties: { url: { type: "string" } } },
        },
      ]);

      // Anthropic-shaped request body: top-level `system` string, `messages`,
      // and `tools` carrying `input_schema` (NOT the OpenAI `functions` shape).
      expect(capturedBody.model).toBe("k3");
      expect(capturedBody.system).toBe("SYSTEM PROMPT");
      const wireMessages = capturedBody.messages as Array<{ role: string; content: unknown[] }>;
      expect(wireMessages[0]!.role).toBe("user");
      expect(wireMessages[0]!.content[0]).toEqual({ type: "text", text: "audit this target" });
      const wireTools = capturedBody.tools as Array<Record<string, unknown>>;
      expect(wireTools[0]!.name).toBe("http_request");
      expect(wireTools[0]!.input_schema).toEqual({
        type: "object",
        properties: { url: { type: "string" } },
      });

      // Anthropic-shaped response: text + tool_use blocks, stop_reason mapping,
      // and total input tokens surfaced on `usage`.
      expect(result.content).toEqual([
        { type: "text", text: "probing" },
        { type: "tool_use", id: "tu_1", name: "http_request", input: { url: "https://target.test/" } },
      ]);
      expect(result.stopReason).toBe("tool_use");
      expect(result.usage).toEqual({ inputTokens: 100, outputTokens: 25 });
    });
  });

  // ── (b) z-ai thinking-budget fragment ──

  describe("anthropicThinkingField()", () => {
    function runtimeForProvider(provider: string): LlmApiRuntime {
      const rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test-key" });
      (rt as unknown as { provider: string }).provider = provider;
      (rt as unknown as { apiKey: string }).apiKey = "test-key";
      return rt;
    }

    it("enables extended thinking with the default budget for z-ai", () => {
      const rt = runtimeForProvider("z-ai");
      expect((rt as any).anthropicThinkingField()).toEqual({
        thinking: { type: "enabled", budget_tokens: 2048 },
      });
    });

    it("honors PWNKIT_ZAI_THINKING_BUDGET for z-ai", () => {
      process.env.PWNKIT_ZAI_THINKING_BUDGET = "4096";
      const rt = runtimeForProvider("z-ai");
      expect((rt as any).anthropicThinkingField()).toEqual({
        thinking: { type: "enabled", budget_tokens: 4096 },
      });
    });

    it("returns an empty fragment when the z-ai budget is 0", () => {
      process.env.PWNKIT_ZAI_THINKING_BUDGET = "0";
      const rt = runtimeForProvider("z-ai");
      expect((rt as any).anthropicThinkingField()).toEqual({});
    });

    it("returns an empty fragment for kimi (K3 reasons natively, no body param)", () => {
      const rt = runtimeForProvider("kimi");
      expect((rt as any).anthropicThinkingField()).toEqual({});
    });

    it("enables adaptive thinking for real Anthropic while retained reasoning is on", () => {
      // Private helper observed through a narrow test-only shape.
      const rt = runtimeForProvider("anthropic") as unknown as {
        anthropicThinkingField(): Record<string, unknown>;
      };
      expect(rt.anthropicThinkingField()).toEqual({
        thinking: { type: "adaptive" },
      });
    });

    it("turns Claude adaptive thinking off for a retained-reasoning A/B run", () => {
      const previous = process.env.PWNKIT_FEATURE_RETAINED_REASONING;
      process.env.PWNKIT_FEATURE_RETAINED_REASONING = "0";
      try {
        // Private helper observed through a narrow test-only shape.
        const rt = runtimeForProvider("anthropic") as unknown as {
          anthropicThinkingField(): Record<string, unknown>;
        };
        expect(rt.anthropicThinkingField()).toEqual({});
      } finally {
        if (previous === undefined) delete process.env.PWNKIT_FEATURE_RETAINED_REASONING;
        else process.env.PWNKIT_FEATURE_RETAINED_REASONING = previous;
      }
    });
  });

  // ── (c) Claude thinking/signature round-trip ──

  describe("Claude retained thinking", () => {
    const rawAssistantContent = [
      { type: "thinking", thinking: "", signature: "opaque-thinking-signature" },
      { type: "redacted_thinking", data: "opaque-redacted-block" },
      {
        type: "tool_use",
        id: "toolu_1",
        name: "read_file",
        input: { path: "/workspace/target.c" },
      },
    ];

    function jsonResponse(body: Record<string, unknown>): Response {
      return {
        ok: true,
        text: async () => JSON.stringify(body),
      } as unknown as Response;
    }

    function anthropicRuntime(): LlmApiRuntime {
      process.env.ANTHROPIC_API_KEY = ["anthropic", "test", "key"].join("-");
      return new LlmApiRuntime({
        type: "api",
        timeout: 5000,
        model: "claude-opus-4-8",
      });
    }

    it("replays the complete raw assistant turn without mutating it for cache control", async () => {
      const rt = anthropicRuntime();
      const bodies: Array<Record<string, unknown>> = [];
      const responseBodies: Array<Record<string, unknown>> = [
        {
          content: rawAssistantContent,
          stop_reason: "tool_use",
          usage: { input_tokens: 10, output_tokens: 5 },
        },
        {
          content: [{ type: "text", text: "done" }],
          stop_reason: "end_turn",
          usage: { input_tokens: 12, output_tokens: 3 },
        },
      ];
      vi.stubGlobal(
        "fetch",
        vi.fn(async (_url: string, opts: { body: string }) => {
          bodies.push(JSON.parse(opts.body) as Record<string, unknown>);
          const response = responseBodies.shift();
          if (!response) throw new Error("unexpected Anthropic request");
          return jsonResponse(response);
        }),
      );

      const first = await rt.executeNative(
        "SYSTEM",
        [{ role: "user", content: [{ type: "text", text: "inspect the target" }] }],
        [],
      );
      expect(first.providerRaw?.output).toEqual(rawAssistantContent);
      expect(bodies[0]!.thinking).toEqual({ type: "adaptive" });

      await rt.executeNative(
        "SYSTEM",
        [
          { role: "user", content: [{ type: "text", text: "inspect the target" }] },
          {
            role: "assistant",
            content: first.content,
            providerRaw: first.providerRaw,
          },
          {
            role: "user",
            content: [{
              type: "tool_result",
              tool_use_id: "toolu_1",
              content: "int main(void) { return 0; }",
            }],
          },
        ],
        [],
      );

      const messages = bodies[1]!.messages as Array<{ role: string; content: unknown }>;
      // Exact means exact: preserve empty thinking + signature, redacted block,
      // tool_use ordering, and no cache_control decoration.
      expect(messages[1]).toEqual({ role: "assistant", content: rawAssistantContent });
    });

    it("strips raw Claude thinking on a model mismatch and reconstructs the visible turn", async () => {
      const rt = anthropicRuntime();
      const bodies: Array<Record<string, unknown>> = [];
      const responseBodies: Array<Record<string, unknown>> = [
        {
          content: rawAssistantContent,
          stop_reason: "tool_use",
          usage: { input_tokens: 10, output_tokens: 5 },
        },
        {
          content: [{ type: "text", text: "done" }],
          stop_reason: "end_turn",
          usage: { input_tokens: 10, output_tokens: 5 },
        },
      ];
      vi.stubGlobal(
        "fetch",
        vi.fn(async (_url: string, opts: { body: string }) => {
          bodies.push(JSON.parse(opts.body) as Record<string, unknown>);
          const response = responseBodies.shift();
          if (!response) throw new Error("unexpected Anthropic request");
          return jsonResponse(response);
        }),
      );

      const first = await rt.executeNative(
        "SYSTEM",
        [{ role: "user", content: [{ type: "text", text: "inspect the target" }] }],
        [],
      );
      expect(first.providerRaw).toBeDefined();

      await rt.executeNative(
        "SYSTEM",
        [
          { role: "user", content: [{ type: "text", text: "inspect the target" }] },
          {
            role: "assistant",
            content: first.content,
            providerRaw: { ...first.providerRaw!, model: "other-model" },
          },
        ],
        [],
      );

      const messages = bodies[1]!.messages as Array<{ role: string; content: unknown }>;
      expect(JSON.stringify(messages[1]!.content)).not.toContain("opaque-thinking-signature");
      expect(messages[1]).toMatchObject({
        role: "assistant",
        content: [{
          type: "tool_use",
          id: "toolu_1",
          name: "read_file",
          input: { path: "/workspace/target.c" },
        }],
      });
    });
  });

  // ── (c) routing-guard regression ──

  describe("routing guard: z-ai and kimi never fall onto the OpenAI wire", () => {
    function runtimeForEnv(envKey: "Z_AI_API_KEY" | "KIMI_API_KEY", model: string): LlmApiRuntime {
      process.env[envKey] = "wire-guard-key";
      return new LlmApiRuntime({ type: "api", timeout: 5000, model });
    }

    it("z-ai is NOT isOpenAICompat and routes to /v1/messages + x-api-key", () => {
      const rt = runtimeForEnv("Z_AI_API_KEY", "glm-5.2");
      expect((rt as any).provider).toBe("z-ai");
      expect((rt as any).isOpenAICompat).toBe(false);
      expect((rt as any).isAnthropicWire).toBe(true);
      expect(((rt as any).buildUrl() as string).endsWith("/v1/messages")).toBe(true);
      expect((rt as any).buildHeaders()["x-api-key"]).toBe("wire-guard-key");
    });

    it("kimi is NOT isOpenAICompat and routes to /v1/messages + x-api-key", () => {
      const rt = runtimeForEnv("KIMI_API_KEY", "k3");
      expect((rt as any).provider).toBe("kimi");
      expect((rt as any).isOpenAICompat).toBe(false);
      expect((rt as any).isAnthropicWire).toBe(true);
      expect(((rt as any).buildUrl() as string).endsWith("/v1/messages")).toBe(true);
      expect((rt as any).buildHeaders()["x-api-key"]).toBe("wire-guard-key");
    });
  });
});
