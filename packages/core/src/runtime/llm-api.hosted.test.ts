import { afterEach, describe, expect, it, vi } from "vitest";
import { LlmApiRuntime, __resetFallbackChainForTests } from "./llm-api.js";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  __resetFallbackChainForTests();
});

function hostedRuntime(model: string, provider = "hosted") {
  vi.stubEnv("0SEC_FORCE_PROVIDER", provider);
  vi.stubEnv("0SEC_SELECTED_PROVIDER", "");
  vi.stubEnv("0SEC_CLOUD_HOST", "http://127.0.0.1:12345");
  vi.stubEnv("0SEC_CLOUD_TOKEN", "fixture-token");
  vi.stubEnv("0SEC_SKIP_PROVIDER_BANNER", "1");
  return new LlmApiRuntime({ type: "api", model, timeout: 1000 });
}

describe("hosted catalog selection", () => {
  it("uses the catalog wire for an explicitly selected model and returns its tool call", async () => {
    const runtime = hostedRuntime("hosted-responses");
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/models")) return Response.json({ object: "list", data: [{ id: "hosted-responses", wire_api: "responses" }] });
      if (!url.endsWith("/responses")) throw new Error("The selected model only supports Responses");
      const request = JSON.parse(String(init?.body));
      expect(request.model).toBe("hosted-responses");
      const events = [
        { type: "response.output_item.done", item: { type: "function_call", call_id: "call_local", name: "read_file", arguments: '{"path":"sample.txt"}' } },
        { type: "response.completed", response: { output: [], usage: { input_tokens: 10, output_tokens: 5 } } },
      ];
      return new Response(events.map(event => `data: ${JSON.stringify(event)}\n\n`).join(""), { headers: { "content-type": "text/event-stream" } });
    }));
    const result = await runtime.executeNative("Use local tools", [{ role: "user", content: [{ type: "text", text: "Read sample.txt" }] }], [{ name: "read_file", description: "Read a local file", input_schema: { type: "object", properties: { path: { type: "string" } } } }]);
    expect(result.content).toContainEqual({ type: "tool_use", id: "call_local", name: "read_file", input: { path: "sample.txt" } });
  });

  it("rejects an unavailable selected model before submitting inference", async () => {
    const runtime = hostedRuntime("not-enabled");
    const inference = vi.fn();
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("/models")) return Response.json({ object: "list", data: [{ id: "available", wire_api: "chat_completions" }] });
      inference();
      return new Response(null, { status: 500 });
    }));
    await expect(runtime.executeNative("system", [], [])).rejects.toThrow(/unavailable/);
    expect(inference).not.toHaveBeenCalled();
  });

  it("rebuilds native tool requests across hosted fallback models and wire protocols", async () => {
    vi.stubEnv("OPENAI_API_KEY", "fixture-primary");
    vi.stubEnv("0SEC_LLM_FALLBACK", "hosted:hosted-chat,hosted:hosted-responses");
    vi.stubEnv("0SEC_LLM_429_MAX_RETRIES", "0");
    __resetFallbackChainForTests();
    const runtime = hostedRuntime("primary", "openai");
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/models")) return Response.json({ object: "list", data: [
        { id: "hosted-chat", wire_api: "chat_completions" },
        { id: "hosted-responses", wire_api: "responses" },
      ] });
      const request = JSON.parse(String(init?.body));
      if (request.model === "primary" || request.model === "hosted-chat") {
        return Response.json({ error: { message: "rate limit" } }, { status: 429 });
      }
      if (!url.endsWith("/responses") || !Array.isArray(request.input) || request.messages) {
        return Response.json({ error: "wrong model protocol" }, { status: 400 });
      }
      const events = [
        { type: "response.output_item.done", item: { type: "function_call", call_id: "fallback-call", name: "read_file", arguments: '{"path":"sample.txt"}' } },
        { type: "response.completed", response: { output: [], usage: { input_tokens: 10, output_tokens: 5 } } },
      ];
      return new Response(events.map(event => `data: ${JSON.stringify(event)}\n\n`).join(""), { headers: { "content-type": "text/event-stream" } });
    }));
    const result = await runtime.executeNative("Use local tools", [{ role: "user", content: [{ type: "text", text: "Read sample.txt" }] }], [{ name: "read_file", description: "Read a local file", input_schema: { type: "object", properties: { path: { type: "string" } } } }]);
    expect(result.content).toContainEqual({ type: "tool_use", id: "fallback-call", name: "read_file", input: { path: "sample.txt" } });
  });

  it("rebuilds a plain completion for a hosted Responses fallback", async () => {
    vi.stubEnv("OPENAI_API_KEY", "fixture-primary");
    vi.stubEnv("0SEC_LLM_FALLBACK", "hosted:hosted-responses");
    vi.stubEnv("0SEC_LLM_429_MAX_RETRIES", "0");
    __resetFallbackChainForTests();
    const runtime = hostedRuntime("primary", "openai");
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith("/models")) return Response.json({ object: "list", data: [{ id: "hosted-responses", wire_api: "responses" }] });
      const request = JSON.parse(String(init?.body));
      if (request.model === "primary") return Response.json({ error: { message: "rate limit" } }, { status: 429 });
      if (!url.endsWith("/responses") || !Array.isArray(request.input) || request.messages) {
        return Response.json({ error: "wrong model protocol" }, { status: 400 });
      }
      return Response.json({ output_text: "fallback answer" });
    }));
    const result = await runtime.execute("Reply to the fixture");
    expect(result).toMatchObject({ exitCode: 0, output: "fallback answer" });
  });
});
