/**
 * Tests for the token-level delta forwarding inside `consumeResponsesStream`.
 *
 * The SSE wire format we mock here is the OpenAI Responses API's
 * `text/event-stream` response, so each event is a `data: {...}\n\n`
 * boundary-separated JSON object. We feed two delta types:
 *
 *   - `response.output_text.delta`        → onDelta("assistant_response", …)
 *   - `response.reasoning_summary_text.delta` → onDelta("reasoning", …)
 *
 * plus the terminal `response.completed` so the loop exits cleanly.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { LlmApiRuntime } from "./llm-api.js";
import type { NativeMessage } from "./types.js";

/**
 * Build a `Response` whose body is a `ReadableStream` that yields each
 * SSE chunk as a separate Uint8Array. The runtime's stream parser splits
 * on `\n\n` so each chunk is a complete event terminated by a blank line.
 */
function sseResponse(events: Array<Record<string, unknown>>): Response {
  const encoder = new TextEncoder();
  const chunks = events.map((e) => encoder.encode(`data: ${JSON.stringify(e)}\n\n`));
  let i = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (i < chunks.length) {
        controller.enqueue(chunks[i++]);
      } else {
        controller.close();
      }
    },
  });
  return new Response(body, {
    status: 200,
    headers: { "content-type": "text/event-stream" },
  });
}

describe("LlmApiRuntime onDelta forwarding (Responses API SSE)", () => {
  let rt: LlmApiRuntime;

  beforeEach(() => {
    rt = new LlmApiRuntime({ type: "api", timeout: 5000, apiKey: "test-key" });
    (rt as any).provider = "openai";
    (rt as any).wireApi = "responses";
    (rt as any).apiKey = "test-key";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("forwards response.output_text.delta to onDelta('assistant_response', …) and response.reasoning_summary_text.delta to onDelta('reasoning', …)", async () => {
    const completedResponse = {
      type: "response.completed",
      response: {
        output: [
          {
            type: "message",
            content: [{ type: "output_text", text: "Hello world" }],
          },
        ],
        usage: { input_tokens: 10, output_tokens: 5 },
      },
    };

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => sseResponse([
        { type: "response.reasoning_summary_text.delta", delta: "thinking " },
        { type: "response.reasoning_summary_text.delta", delta: "step one" },
        { type: "response.output_text.delta", delta: "Hello " },
        { type: "response.output_text.delta", delta: "world" },
        completedResponse,
      ])),
    );

    const deltas: Array<{ scope: string; text: string }> = [];
    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ];

    await rt.executeNative("system", messages, [], {
      onDelta: (scope, text) => {
        deltas.push({ scope, text });
      },
    });

    // Both channels forwarded as raw fragments — NOT the accumulated buffer.
    expect(deltas).toEqual([
      { scope: "reasoning", text: "thinking " },
      { scope: "reasoning", text: "step one" },
      { scope: "assistant_response", text: "Hello " },
      { scope: "assistant_response", text: "world" },
    ]);
  });

  it("does not call onDelta when the callback is not provided (back-compat with non-cloud runs)", async () => {
    const completedResponse = {
      type: "response.completed",
      response: {
        output: [{ type: "message", content: [{ type: "output_text", text: "ok" }] }],
        usage: { input_tokens: 1, output_tokens: 1 },
      },
    };

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => sseResponse([
        { type: "response.output_text.delta", delta: "ok" },
        completedResponse,
      ])),
    );

    const messages: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
    ];

    // No onDelta — this must not throw and the existing return shape must
    // still come through with the expected text content.
    const result = await rt.executeNative("system", messages, [], {});
    expect(result.stopReason).toBe("end_turn");
    expect(
      result.content.some((b) => b.type === "text" && (b as { text: string }).text === "ok"),
    ).toBe(true);
  });
});
