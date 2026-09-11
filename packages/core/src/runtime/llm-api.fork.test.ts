import { afterEach, describe, expect, it, vi } from "vitest";
import { LlmApiRuntime } from "./llm-api.js";

const messages = [{ role: "user" as const, content: [{ type: "text" as const, text: "fixture" }] }];
const completion = (content: string) => Response.json({ choices: [{ message: { role: "assistant", content }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1 } });
const environment = () => ({ "0SEC_FORCE_PROVIDER": "", "0SEC_SELECTED_PROVIDER": "", "0SEC_SKIP_PROVIDER_BANNER": "1", "0SEC_LLM_FALLBACK": "" });

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("isolated child runtimes", () => {
  it("inherits each parent's resolved route and credentials despite caller and ambient mutation", async () => {
    const azureEnv = { ...environment(), AZURE_OPENAI_API_KEY: "azure-original", AZURE_OPENAI_BASE_URL: "https://azure.fixture/openai/v1", AZURE_OPENAI_WIRE_API: "chat_completions" };
    const openaiEnv = { ...environment(), OPENAI_API_KEY: "openai-original", OPENAI_BASE_URL: "https://openai.fixture/v1" };
    const azure = new LlmApiRuntime({ type: "api", provider: "azure", model: "azure-model", timeout: 1000, env: azureEnv });
    const openai = new LlmApiRuntime({ type: "api", provider: "openai", model: "openai-model", timeout: 1000, env: openaiEnv });
    azureEnv.AZURE_OPENAI_API_KEY = "changed";
    openaiEnv.OPENAI_BASE_URL = "https://unexpected.fixture";
    vi.stubEnv("0SEC_FORCE_PROVIDER", "hosted");
    vi.stubEnv("0SEC_CLOUD_TOKEN", "unrelated-account");
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      const headers = new Headers(init?.headers);
      const body = JSON.parse(String(init?.body));
      if (url === "https://azure.fixture/openai/v1/chat/completions" && headers.get("api-key") === "azure-original" && body.model === "azure-model") return completion("azure accepted");
      if (url === "https://openai.fixture/v1/chat/completions" && headers.get("authorization") === "Bearer openai-original" && body.model === "openai-model") return completion("openai accepted");
      return Response.json({ error: "wrong account or route" }, { status: 401 });
    });
    const children = await Promise.all([azure.forkForSubagent(1000), openai.forkForSubagent(1000)]);
    const results = await Promise.all(children.map(child => child.executeNative("system", messages, [])));
    expect(results.map(result => result.content)).toEqual([[{ type: "text", text: "azure accepted" }], [{ type: "text", text: "openai accepted" }]]);
  });

  it("resolves hosted identity before forking and retains the catalog ceiling without rediscovery", async () => {
    const parent = new LlmApiRuntime({ type: "api", provider: "hosted", timeout: 1000, env: { ...environment(), "0SEC_MODEL": "", "0SEC_CLOUD_HOST": "http://127.0.0.1:12345", "0SEC_CLOUD_TOKEN": "original-cloud", "0SEC_LLM_FALLBACK": "openai:unapproved", OPENAI_API_KEY: "unapproved" } });
    let catalogReads = 0;
    let requests = 0;
    vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (new Headers(init?.headers).get("authorization") !== "Bearer original-cloud") return new Response(null, { status: 401 });
      if (url.endsWith("/models")) {
        catalogReads++;
        if (catalogReads !== 1) throw new Error("Catalog must not be rediscovered by a fork");
        return Response.json({ data: [{ id: "hosted-pinned", wire_api: "chat_completions", max_output_tokens: 64 }] });
      }
      requests++;
      const body = JSON.parse(String(init?.body));
      if (!url.startsWith("http://127.0.0.1:12345/") || body.model !== "hosted-pinned" || body.max_tokens !== 64) return new Response(null, { status: 400 });
      return completion("hosted accepted");
    });
    const children = await Promise.all([parent.forkForSubagent(1000), parent.forkForSubagent(1000)]);
    vi.stubEnv("0SEC_CLOUD_TOKEN", "changed-cloud");
    expect(children.map(child => child.resolvedModel())).toEqual(["hosted-pinned", "hosted-pinned"]);
    const results = await Promise.all(children.map(child => child.executeNative("system", messages, [])));
    expect(results.map(result => result.content)).toEqual([[{ type: "text", text: "hosted accepted" }], [{ type: "text", text: "hosted accepted" }]]);
    expect(catalogReads).toBe(1);
    expect(requests).toBe(2);
    vi.stubGlobal("fetch", async () => new Response("quota", { status: 429 }));
    expect(await children[0]!.executeNative("system", messages, [])).toMatchObject({ stopReason: "error" });
    expect(children[0]!.resolvedModel()).toBe("hosted-pinned");
  });

  it("keeps a child's explicitly configured fallback cursor independent of its parent and sibling", async () => {
    vi.stubEnv("0SEC_LLM_429_MAX_RETRIES", "0");
    const parent = new LlmApiRuntime({ type: "api", provider: "openai", model: "primary", timeout: 1000, env: { ...environment(), OPENAI_API_KEY: "primary-key", OPENAI_BASE_URL: "https://primary.fixture/v1", "0SEC_LLM_FALLBACK": "deepseek:secondary", DEEPSEEK_API_KEY: "secondary-key", DEEPSEEK_BASE_URL: "https://secondary.fixture/v1" } });
    const [first, second] = await Promise.all([parent.forkForSubagent(1000), parent.forkForSubagent(1000)]);
    vi.stubGlobal("fetch", async (_input: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      return body.model === "primary" ? new Response("quota", { status: 429 }) : Response.json({ output_text: "fallback accepted" });
    });
    expect(await first!.execute("fixture")).toMatchObject({ exitCode: 0, output: "fallback accepted" });
    expect(first!.resolvedModel()).toBe("secondary");
    expect(second!.resolvedModel()).toBe("primary");
    expect(parent.resolvedModel()).toBe("primary");
  });

  it("cannot extend the parent request timeout", async () => {
    vi.useFakeTimers();
    const parent = new LlmApiRuntime({ type: "api", provider: "openai", model: "fixture", timeout: 25, env: { ...environment(), OPENAI_API_KEY: "fixture", OPENAI_BASE_URL: "https://timeout.fixture/v1" } });
    const child = await parent.forkForSubagent(60_000);
    vi.stubGlobal("fetch", (_input: string | URL | Request, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
    }));
    const pending = child.execute("fixture");
    await vi.advanceTimersByTimeAsync(26);
    expect(await pending).toMatchObject({ exitCode: 1, timedOut: true });
  });
});
