/**
 * Retained reasoning on the Responses path.
 *
 * The runtime asks for `reasoning.encrypted_content` and then has exactly one
 * way to give it back: echo the provider's own output items into the next
 * request's `input`. These tests pin the two halves of that contract —
 *
 *   1. a completed turn hands its raw item array back as `providerRaw`;
 *   2. an assistant message carrying `providerRaw` is spliced VERBATIM on the
 *      next request when provider+model+wireApi match, and falls back to the
 *      reconstructed representation on any mismatch.
 *   3. the reasoning SUMMARY — a lossy paraphrase of what (1) carries properly
 *      — stays out of `content` entirely and reaches the UI's thinking
 *      channel exactly once. A text block there would be replayed as
 *      `output_text` on every later turn and would also become the scan's
 *      reported summary on a clean end_turn.
 *
 * The mismatch case is what keeps the ensemble runtime (openrouter.ts, which
 * shares one messages array across N models) from 400-ing on a sibling's
 * encrypted items.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { LlmApiRuntime } from "./llm-api.js";
import type { NativeMessage } from "./types.js";

/** SSE `Response` whose events are emitted one chunk each. */
function sseResponse(events: Array<Record<string, unknown>>): Response {
  const encoder = new TextEncoder();
  const chunks = events.map((e) => encoder.encode(`data: ${JSON.stringify(e)}\n\n`));
  let i = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i < chunks.length) controller.enqueue(chunks[i++]);
      else controller.close();
    },
  });
  return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
}

/** A reasoning item immediately followed by the call it produced. */
const REASONING_ITEM = {
  type: "reasoning",
  id: "rs_abc123",
  encrypted_content: "gAAAAAB-opaque-blob",
  summary: [{ type: "summary_text", text: "I should list the directory." }],
};
const FUNCTION_CALL_ITEM = {
  type: "function_call",
  call_id: "call_1",
  name: "list_dir",
  arguments: JSON.stringify({ path: "." }),
};

function completedEvent(output: Array<Record<string, unknown>>): Record<string, unknown> {
  return {
    type: "response.completed",
    response: { output, usage: { input_tokens: 10, output_tokens: 5 } },
  };
}

/** Capture the JSON body of every POST the runtime makes. */
function stubFetchCapturing(bodies: Array<Record<string, unknown>>, events: Array<Record<string, unknown>>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init: RequestInit) => {
      bodies.push(JSON.parse(String(init.body)));
      return sseResponse(events);
    }),
  );
}

describe("Responses reasoning echo-back", () => {
  let rt: LlmApiRuntime;

  beforeEach(() => {
    rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test-key", model: "gpt-5.5" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "responses";
    (rt as any).model = "gpt-5.5";
    (rt as any).apiKey = "test-key";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("returns the provider's raw output array as providerRaw", async () => {
    stubFetchCapturing([], [
      { type: "response.output_item.done", item: REASONING_ITEM },
      { type: "response.output_item.done", item: FUNCTION_CALL_ITEM },
      completedEvent([]),
    ]);

    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], []);

    expect(result.providerRaw).toBeDefined();
    expect(result.providerRaw!.provider).toBe("openai");
    expect(result.providerRaw!.model).toBe("gpt-5.5");
    expect(result.providerRaw!.wireApi).toBe("responses");
    // Verbatim: the encrypted blob and the item ordering both survive.
    expect(result.providerRaw!.output).toEqual([REASONING_ITEM, FUNCTION_CALL_ITEM]);
    // …and the summary is NOT ALSO flattened into `content`: the raw item is
    // the real reasoning, the summary is a paraphrase, and a text block here
    // gets replayed as `output_text` on every later turn.
    expect(result.content).toEqual([
      { type: "tool_use", id: "call_1", name: "list_dir", input: { path: "." } },
    ]);
  });

  it("omits the sidecar for an empty Responses output array", async () => {
    stubFetchCapturing([], [completedEvent([])]);

    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], []);

    expect(result.providerRaw).toBeUndefined();
  });

  it("survives the session persist/resume JSON round-trip", async () => {
    stubFetchCapturing([], [
      { type: "response.output_item.done", item: REASONING_ITEM },
      completedEvent([]),
    ]);
    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], []);

    const message: NativeMessage = {
      role: "assistant",
      content: result.content,
      providerRaw: result.providerRaw,
    };
    const revived = JSON.parse(JSON.stringify(message)) as NativeMessage;
    expect(revived.providerRaw).toEqual(result.providerRaw);
  });

  it("splices the raw items verbatim and skips reconstruction when the identity matches", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    stubFetchCapturing(bodies, [completedEvent([])]);

    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
      {
        role: "assistant",
        content: [
          { type: "text", text: "I should list the directory." },
          { type: "tool_use", id: "call_1", name: "list_dir", input: { path: "." } },
        ],
        providerRaw: {
          provider: "openai",
          model: "gpt-5.5",
          wireApi: "responses",
          output: [REASONING_ITEM, FUNCTION_CALL_ITEM],
        },
      },
      { role: "user", content: [{ type: "tool_result", tool_use_id: "call_1", content: "." }] },
    ];

    await rt.executeNative("sys", messages, []);

    const input = bodies[0]!.input as Array<Record<string, unknown>>;
    // The raw reasoning item is present, with its blob, immediately followed by
    // the call it produced — the ordering rule the API enforces.
    const reasoningIdx = input.findIndex((item) => item.type === "reasoning");
    expect(reasoningIdx).toBeGreaterThanOrEqual(0);
    expect(input[reasoningIdx]).toEqual(REASONING_ITEM);
    expect(input[reasoningIdx + 1]).toEqual(FUNCTION_CALL_ITEM);
    // And NOT its reconstructed twin: no assistant output_text message, and
    // exactly one function_call for this turn.
    expect(input.filter((item) => item.role === "assistant")).toHaveLength(0);
    expect(input.filter((item) => item.type === "function_call")).toHaveLength(1);
    // The tool result still follows normally.
    expect(input.at(-1)).toEqual({
      type: "function_call_output",
      call_id: "call_1",
      output: ".",
    });
  });

  it("reconstructs matching items when retained reasoning is disabled for an A/B run", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    stubFetchCapturing(bodies, [completedEvent([])]);
    const previous = process.env.PWNKIT_FEATURE_RETAINED_REASONING;
    process.env.PWNKIT_FEATURE_RETAINED_REASONING = "0";
    try {
      await rt.executeNative("sys", [
        { role: "user", content: [{ type: "text", text: "go" }] },
        {
          role: "assistant",
          content: [
            { type: "text", text: "I should list the directory." },
            { type: "tool_use", id: "call_1", name: "list_dir", input: { path: "." } },
          ],
          providerRaw: {
            provider: "openai",
            model: "gpt-5.5",
            wireApi: "responses",
            output: [REASONING_ITEM, FUNCTION_CALL_ITEM],
          },
        },
      ], []);
    } finally {
      if (previous === undefined) delete process.env.PWNKIT_FEATURE_RETAINED_REASONING;
      else process.env.PWNKIT_FEATURE_RETAINED_REASONING = previous;
    }

    const input = bodies[0]!.input as Array<Record<string, unknown>>;
    expect(input.some((item) => item.type === "reasoning")).toBe(false);
    expect(input).toContainEqual({
      role: "assistant",
      content: [{ type: "output_text", text: "I should list the directory." }],
    });
    expect(input).toContainEqual(FUNCTION_CALL_ITEM);
  });

  it("falls back to reconstruction when the model differs (ensemble / model switch)", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    stubFetchCapturing(bodies, [completedEvent([])]);

    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
      {
        role: "assistant",
        content: [
          { type: "text", text: "I should list the directory." },
          { type: "tool_use", id: "call_1", name: "list_dir", input: { path: "." } },
        ],
        providerRaw: {
          provider: "openai",
          model: "some-other-model",
          wireApi: "responses",
          output: [REASONING_ITEM, FUNCTION_CALL_ITEM],
        },
      },
    ];

    await rt.executeNative("sys", messages, []);

    const input = bodies[0]!.input as Array<Record<string, unknown>>;
    // No encrypted item from a foreign model is ever replayed.
    expect(input.some((item) => item.type === "reasoning")).toBe(false);
    expect(JSON.stringify(input)).not.toContain("gAAAAAB-opaque-blob");
    // Today's exact behaviour instead: assistant text as output_text, then the
    // reconstructed function_call.
    expect(input).toContainEqual({
      role: "assistant",
      content: [{ type: "output_text", text: "I should list the directory." }],
    });
    expect(input).toContainEqual(FUNCTION_CALL_ITEM);
  });

  it("falls back when the provider differs", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    stubFetchCapturing(bodies, [completedEvent([])]);

    await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
      {
        role: "assistant",
        content: [{ type: "text", text: "hello" }],
        providerRaw: {
          provider: "azure",
          model: "gpt-5.5",
          wireApi: "responses",
          output: [REASONING_ITEM],
        },
      },
    ], []);

    const input = bodies[0]!.input as Array<Record<string, unknown>>;
    expect(input.some((item) => item.type === "reasoning")).toBe(false);
    expect(input).toContainEqual({
      role: "assistant",
      content: [{ type: "output_text", text: "hello" }],
    });
  });

  it("falls back when the wire API differs", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    stubFetchCapturing(bodies, [completedEvent([])]);

    await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
      {
        role: "assistant",
        content: [{ type: "text", text: "hello" }],
        providerRaw: {
          provider: "openai",
          model: "gpt-5.5",
          wireApi: "chat_completions",
          output: [REASONING_ITEM],
        },
      },
    ], []);

    const input = bodies[0]!.input as Array<Record<string, unknown>>;
    expect(input.some((item) => item.type === "reasoning")).toBe(false);
  });

  it("keeps the summary out of content when the turn ends with a message", async () => {
    stubFetchCapturing([], [
      { type: "response.output_item.done", item: REASONING_ITEM },
      {
        type: "response.output_item.done",
        item: { type: "message", role: "assistant", content: [{ type: "output_text", text: "the directory is empty" }] },
      },
      completedEvent([]),
    ]);

    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], []);

    // Only the model's actual answer — not its thinking. `native-loop` joins
    // every text block into `state.summary` on a clean end_turn, so a leaked
    // paraphrase here becomes the scan's reported conclusion.
    expect(result.content).toEqual([{ type: "text", text: "the directory is empty" }]);
    expect(JSON.stringify(result.content)).not.toContain("I should list the directory.");
  });

  it("still routes the summary to onThinking, exactly once, when the stream emits summary deltas", async () => {
    // Two summary PARTS. `response.reasoning_summary_text.done` overwrites
    // rather than appends, so the streamed thinking text ends up as part two
    // alone while the item's joined summary is both parts — different text and
    // different length, which is what defeats the emit throttle's
    // same-length guard. Anything but an explicit "already emitted?" check
    // shows the user a second, longer copy of the same thinking.
    const twoPartItem = {
      ...REASONING_ITEM,
      summary: [
        { type: "summary_text", text: "First I check the listing." },
        { type: "summary_text", text: "Then I read the files." },
      ],
    };
    stubFetchCapturing([], [
      { type: "response.reasoning_summary_text.done", text: "First I check the listing." },
      { type: "response.reasoning_summary_text.done", text: "Then I read the files." },
      { type: "response.output_item.done", item: twoPartItem },
      { type: "response.output_item.done", item: FUNCTION_CALL_ITEM },
      completedEvent([]),
    ]);

    const onThinking = vi.fn();
    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], [], { onThinking });

    // Only what the stream delivered. The item-array fallback must not fire.
    expect(onThinking.mock.calls.map((c) => c[0])).toEqual([
      "First I check the listing.",
      "Then I read the files.",
    ]);
    expect(result.content.some((b) => b.type === "text")).toBe(false);
  });

  it("falls back to the reasoning item for onThinking when no summary deltas were streamed", async () => {
    // The item array is the only carrier here — dropping it from `content`
    // without this fallback would black out the dashboard thinking channel.
    stubFetchCapturing([], [
      { type: "response.output_item.done", item: REASONING_ITEM },
      { type: "response.output_item.done", item: FUNCTION_CALL_ITEM },
      completedEvent([]),
    ]);

    const onThinking = vi.fn();
    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], [], { onThinking });

    expect(onThinking).toHaveBeenCalledTimes(1);
    expect(onThinking).toHaveBeenCalledWith("I should list the directory.");
    expect(result.content).toEqual([
      { type: "tool_use", id: "call_1", name: "list_dir", input: { path: "." } },
    ]);
  });

  it("reports cached_tokens from the Responses usage payload", async () => {
    stubFetchCapturing([], [
      {
        type: "response.completed",
        response: {
          output: [],
          usage: {
            input_tokens: 1000,
            output_tokens: 20,
            input_tokens_details: { cached_tokens: 768 },
          },
        },
      },
    ]);

    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], []);

    // `input_tokens` already includes the cached span on this API — it is not
    // re-added, only surfaced.
    expect(result.usage).toEqual({
      inputTokens: 1000,
      outputTokens: 20,
      cachedInputTokens: 768,
    });
  });

  it("omits cachedInputTokens when the provider does not report it", async () => {
    stubFetchCapturing([], [completedEvent([])]);
    const result = await rt.executeNative("sys", [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ], []);
    expect(result.usage).toEqual({ inputTokens: 10, outputTokens: 5 });
  });
});

describe("server-side compaction (opt-in)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  async function bodyFor(serverCompactionTokens?: number): Promise<Record<string, unknown>> {
    const rt = new LlmApiRuntime({
      type: "api",
      timeout: 5000,
      apiKey: "test-key",
      model: "gpt-5.5",
      ...(serverCompactionTokens !== undefined ? { serverCompactionTokens } : {}),
    });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "responses";
    (rt as any).apiKey = "test-key";
    const bodies: Array<Record<string, unknown>> = [];
    stubFetchCapturing(bodies, [completedEvent([])]);
    await rt.executeNative("sys", [{ role: "user", content: [{ type: "text", text: "go" }] }], []);
    return bodies[0]!;
  }

  // The key must be ABSENT when compaction is off: `context_management: []` is
  // a hard 400 (`empty array. Expected an array with minimum length 1`), and
  // this backend rejects unknown/mis-typed fields rather than ignoring them.
  it("is off unless asked for — the native loop compacts client-side", async () => {
    expect(await bodyFor()).not.toHaveProperty("context_management");
  });

  // Array-of-tagged-objects, verified live against the Codex backend. The
  // object form the public docs show returns
  // `400 Invalid type for 'context_management': expected an array of objects`.
  it("sends the array form with an explicit type and the requested threshold", async () => {
    expect((await bodyFor(150_000)).context_management).toEqual([
      { type: "compaction", compact_threshold: 150_000 },
    ]);
  });

  it("clamps up to the API minimum of 1000", async () => {
    expect((await bodyFor(10)).context_management).toEqual([
      { type: "compaction", compact_threshold: 1000 },
    ]);
  });

  it("never emits the object form the public docs describe", async () => {
    const sent = (await bodyFor(150_000)).context_management;
    expect(Array.isArray(sent)).toBe(true);
    expect(sent).not.toHaveProperty("compaction");
  });
});
