import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { LlmApiRuntime } from "./llm-api.js";
import type { NativeMessage } from "./types.js";

/**
 * Wire-level assertions for prompt caching: what actually lands in the request
 * body per provider, and what comes back out of `usage`.
 *
 * These complement `prompt-cache.test.ts` (which unit-tests the placement
 * planner in isolation) by proving the two ends are actually connected — a
 * correct planner wired into the wrong branch would still ship zero cache hits.
 */

/** Count `cache_control` markers anywhere in a request body. */
function countBreakpoints(value: unknown): number {
  if (Array.isArray(value)) {
    return value.reduce<number>((sum, entry) => sum + countBreakpoints(entry), 0);
  }
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    const own = "cache_control" in record ? 1 : 0;
    return Object.values(record).reduce<number>(
      (sum, entry) => sum + countBreakpoints(entry),
      own,
    );
  }
  return 0;
}

/** A conversation long enough to exercise bridge breakpoints. */
function longConversation(turns: number): NativeMessage[] {
  const messages: NativeMessage[] = [
    { role: "user", content: [{ type: "text", text: "audit this target" }] },
  ];
  for (let i = 0; i < turns; i++) {
    messages.push({
      role: "assistant",
      content: [{ type: "tool_use", id: `t${i}`, name: "http_request", input: { url: "/" } }],
    });
    messages.push({
      role: "user",
      content: [{ type: "tool_result", tool_use_id: `t${i}`, content: "200 OK" }],
    });
  }
  return messages;
}

describe("prompt caching on the wire", () => {
  const origEnv = { ...process.env };
  let capturedBody: Record<string, unknown>;

  function runtimeFor(provider: string): LlmApiRuntime {
    const rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test-key" });
    // Provider/wire are private detection results; overriding them directly is
    // the pattern the existing llm-api tests use to pin a provider.
    (rt as unknown as { provider: string }).provider = provider;
    (rt as unknown as { apiKey: string }).apiKey = "test-key";
    if (provider === "openai" || provider === "azure") {
      (rt as unknown as { wireApi: string }).wireApi = "chat_completions";
    }
    return rt;
  }

  beforeEach(() => {
    process.env.PWNKIT_SKIP_PROVIDER_BANNER = "1";
    delete process.env.PWNKIT_FEATURE_PROMPT_CACHE;
    delete process.env.PWNKIT_PROMPT_CACHE_EXTRA_PROVIDERS;

    capturedBody = {};
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, opts: { body: string }) => {
        capturedBody = JSON.parse(opts.body) as Record<string, unknown>;
        return {
          ok: true,
          text: async () =>
            JSON.stringify({
              content: [{ type: "text", text: "done" }],
              stop_reason: "end_turn",
              usage: {
                input_tokens: 120,
                output_tokens: 40,
                cache_read_input_tokens: 30_000,
                cache_creation_input_tokens: 900,
              },
            }),
        } as unknown as Response;
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    Object.assign(process.env, origEnv);
  });

  it("marks the system prompt for a supporting provider (covering tools too)", async () => {
    const rt = runtimeFor("anthropic");
    await rt.executeNative("SYSTEM PROMPT", longConversation(1), [
      {
        name: "http_request",
        description: "send a request",
        input_schema: { type: "object", properties: {} },
      },
    ]);

    // `system` becomes a block array — the only shape that accepts a marker.
    expect(capturedBody.system).toEqual([
      { type: "text", text: "SYSTEM PROMPT", cache_control: { type: "ephemeral" } },
    ]);

    // Render order is tools → system → messages, so the system breakpoint
    // already covers the tool schemas; they must NOT burn a second breakpoint.
    expect(countBreakpoints(capturedBody.tools)).toBe(0);
  });

  it("marks the newest message so the next turn reads the cache back", async () => {
    const rt = runtimeFor("anthropic");
    const messages = longConversation(2);
    await rt.executeNative("sys", messages, []);

    const wireMessages = capturedBody.messages as Array<{ content: unknown[] }>;
    const last = wireMessages[wireMessages.length - 1]!;
    const lastBlock = last.content[last.content.length - 1] as Record<string, unknown>;
    expect(lastBlock.cache_control).toEqual({ type: "ephemeral" });
  });

  it("never exceeds the 4-breakpoint API limit on a long conversation", async () => {
    const rt = runtimeFor("anthropic");
    await rt.executeNative("sys", longConversation(60), [
      { name: "a", description: "a", input_schema: { type: "object", properties: {} } },
      { name: "b", description: "b", input_schema: { type: "object", properties: {} } },
    ]);

    expect(countBreakpoints(capturedBody)).toBeLessThanOrEqual(4);
    // ...and it genuinely used more than the system breakpoint alone.
    expect(countBreakpoints(capturedBody.messages)).toBeGreaterThan(1);
  });

  it("emits NO cache_control for a non-supporting provider", async () => {
    const rt = runtimeFor("openai");
    await rt.executeNative("sys", longConversation(30), [
      { name: "a", description: "a", input_schema: { type: "object", properties: {} } },
    ]);

    expect(countBreakpoints(capturedBody)).toBe(0);
    // The OpenAI wire keeps its plain string system message.
    const wireMessages = capturedBody.messages as Array<{ role: string; content: unknown }>;
    expect(wireMessages[0]).toEqual({ role: "system", content: "sys" });
  });

  it("keeps unverified Anthropic-compatible providers uncached by default", async () => {
    const rt = runtimeFor("z-ai");
    await rt.executeNative("sys", longConversation(30), []);

    expect(countBreakpoints(capturedBody)).toBe(0);
    // Body stays byte-identical to the pre-caching shape: system as a string.
    expect(capturedBody.system).toBe("sys");
  });

  it("caches an Anthropic-compatible provider once explicitly opted in", async () => {
    process.env.PWNKIT_PROMPT_CACHE_EXTRA_PROVIDERS = "z-ai";
    const rt = runtimeFor("z-ai");
    await rt.executeNative("sys", longConversation(2), []);

    expect(countBreakpoints(capturedBody)).toBeGreaterThan(0);
  });

  it("emits nothing when the feature flag is off", async () => {
    process.env.PWNKIT_FEATURE_PROMPT_CACHE = "0";
    const rt = runtimeFor("anthropic");
    await rt.executeNative("sys", longConversation(30), []);

    expect(countBreakpoints(capturedBody)).toBe(0);
    expect(capturedBody.system).toBe("sys");
  });

  it("surfaces cache read/write counts and reports TOTAL prompt tokens", async () => {
    const rt = runtimeFor("anthropic");
    const result = await rt.executeNative("sys", longConversation(1), []);

    // 120 uncached + 30000 read + 900 written = 31020 total prompt tokens.
    expect(result.usage).toEqual({
      inputTokens: 31_020,
      outputTokens: 40,
      cachedInputTokens: 30_000,
      cacheWriteTokens: 900,
    });
  });

  it("re-plans breakpoints over rewritten history after compaction", async () => {
    const rt = runtimeFor("anthropic");

    // Pre-compaction: a long transcript.
    const grown = longConversation(40);
    await rt.executeNative("sys", grown, []);
    const beforeCount = countBreakpoints(capturedBody.messages);
    expect(beforeCount).toBeGreaterThan(1);

    // Post-compaction: history rewritten the way compactMessagesWithLLM does it
    // — message 0 verbatim, middle collapsed to a summary, recent tail kept.
    const compacted: NativeMessage[] = [
      grown[0]!,
      { role: "assistant", content: [{ type: "text", text: "summary of prior turns" }] },
      ...grown.slice(-4),
    ];
    await rt.executeNative("sys", compacted, []);

    // Markers land on the NEW array, not at stale pre-compaction positions.
    const wireMessages = capturedBody.messages as Array<{ content: unknown[] }>;
    expect(wireMessages.length).toBe(compacted.length);
    expect(countBreakpoints(wireMessages)).toBeGreaterThan(0);

    const last = wireMessages[wireMessages.length - 1]!;
    const lastBlock = last.content[last.content.length - 1] as Record<string, unknown>;
    expect(lastBlock.cache_control).toEqual({ type: "ephemeral" });

    // The system breakpoint is unaffected by compaction — it keeps hitting.
    expect(countBreakpoints(capturedBody.system)).toBe(1);
  });

  it("does not persist markers onto the caller's message objects", async () => {
    // A marker written into the loop's own NativeMessage state would be
    // replayed — and saved into the session blob — on every later turn.
    const rt = runtimeFor("anthropic");
    const messages = longConversation(2);
    await rt.executeNative("sys", messages, []);

    for (const message of messages) {
      for (const block of message.content) {
        expect(block).not.toHaveProperty("cache_control");
      }
    }
  });
});
