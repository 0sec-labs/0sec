import { describe, it, expect, vi } from "vitest";
import type { NativeMessage, NativeToolDef } from "./types.js";
import { OllamaRuntime } from "./ollama.js";

function mockFetch(handler: (url: string, init?: RequestInit) => Response): typeof fetch {
  return ((url: any, init?: any) => Promise.resolve(handler(String(url), init))) as typeof fetch;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Build a Response whose body is a ReadableStream of ND-JSON chunks — one
 * line per frame, terminated by `\n`. Mirrors Ollama's `/api/chat?stream=true`
 * wire format closely enough that the runtime's parser can't tell the
 * difference from the real server.
 */
function ndjsonStreamResponse(frames: unknown[], status = 200): Response {
  const encoder = new TextEncoder();
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const frame of frames) {
        controller.enqueue(encoder.encode(`${JSON.stringify(frame)}\n`));
      }
      controller.close();
    },
  });
  return new Response(stream, {
    status,
    headers: { "content-type": "application/x-ndjson" },
  });
}

const tools: NativeToolDef[] = [
  {
    name: "read_file",
    description: "Read a file from the target repo.",
    input_schema: { type: "object", properties: { path: { type: "string" } }, required: ["path"] },
  },
];

describe("OllamaRuntime.isAvailable", () => {
  it("returns true when /api/tags responds ok", async () => {
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 1000,
      fetchImpl: mockFetch(() => jsonResponse({ models: [] })),
    });
    expect(await rt.isAvailable()).toBe(true);
  });

  it("returns false on network error", async () => {
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 1000,
      fetchImpl: mockFetch(() => {
        throw new Error("ECONNREFUSED");
      }),
    });
    expect(await rt.isAvailable()).toBe(false);
  });
});

describe("OllamaRuntime.execute (legacy text path)", () => {
  it("returns the assistant message as output", async () => {
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch((url) => {
        expect(url).toContain("/api/chat");
        return jsonResponse({
          model: "gemma4:27b",
          created_at: "2026-05-18T00:00:00Z",
          message: { role: "assistant", content: "hello back" },
          done: true,
          prompt_eval_count: 4,
          eval_count: 3,
        });
      }),
    });
    const res = await rt.execute("hi");
    expect(res.output).toBe("hello back");
    expect(res.exitCode).toBe(0);
    expect(res.usage).toEqual({ inputTokens: 4, outputTokens: 3 });
  });

  it("surfaces error on non-2xx response", async () => {
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch(() => new Response("model not pulled", { status: 404 })),
    });
    const res = await rt.execute("hi");
    expect(res.exitCode).toBe(1);
    expect(res.error).toMatch(/404/);
  });
});

describe("OllamaRuntime.executeNative", () => {
  const messages: NativeMessage[] = [
    { role: "user", content: [{ type: "text", text: "Find SQL injection." }] },
  ];

  it("translates tool_calls into tool_use content blocks", async () => {
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch((_url, init) => {
        const body = JSON.parse(String(init!.body));
        expect(body.tools[0].function.name).toBe("read_file");
        expect(body.tools[0].function.parameters.required).toEqual(["path"]);
        return jsonResponse({
          model: "gemma4:27b",
          created_at: "2026-05-18T00:00:00Z",
          message: {
            role: "assistant",
            content: "Investigating.",
            tool_calls: [
              {
                function: {
                  name: "read_file",
                  arguments: { path: "src/router.js" },
                },
              },
            ],
          },
          done: true,
          done_reason: "stop",
        });
      }),
    });

    const res = await rt.executeNative("system", messages, tools);
    expect(res.stopReason).toBe("tool_use");
    expect(res.content).toHaveLength(2);
    expect(res.content[0]).toMatchObject({ type: "text", text: "Investigating." });
    expect(res.content[1]).toMatchObject({
      type: "tool_use",
      name: "read_file",
      input: { path: "src/router.js" },
    });
  });

  it("accepts tool_call.arguments as a JSON-encoded string (legacy gemma3 behaviour)", async () => {
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch(() =>
        jsonResponse({
          model: "gemma4:27b",
          created_at: "2026-05-18T00:00:00Z",
          message: {
            role: "assistant",
            content: "",
            tool_calls: [
              { function: { name: "read_file", arguments: '{"path":"x.py"}' } },
            ],
          },
          done: true,
        }),
      ),
    });
    const res = await rt.executeNative("", messages, tools);
    const toolUse = res.content.find((b) => b.type === "tool_use");
    expect(toolUse).toMatchObject({ name: "read_file", input: { path: "x.py" } });
  });

  it("maps done_reason='length' to stopReason='max_tokens'", async () => {
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch(() =>
        jsonResponse({
          model: "gemma4:27b",
          created_at: "2026-05-18T00:00:00Z",
          message: { role: "assistant", content: "truncated…" },
          done: true,
          done_reason: "length",
        }),
      ),
    });
    const res = await rt.executeNative("", messages, []);
    expect(res.stopReason).toBe("max_tokens");
  });

  it("returns stopReason='end_turn' on clean stop with no tool calls", async () => {
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch(() =>
        jsonResponse({
          model: "gemma4:27b",
          created_at: "2026-05-18T00:00:00Z",
          message: { role: "assistant", content: "done" },
          done: true,
          done_reason: "stop",
        }),
      ),
    });
    const res = await rt.executeNative("", messages, []);
    expect(res.stopReason).toBe("end_turn");
  });

  it("emits usage to the onUsage callback when prompt_eval_count + eval_count are present", async () => {
    const onUsage = vi.fn();
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch(() =>
        jsonResponse({
          model: "gemma4:27b",
          created_at: "2026-05-18T00:00:00Z",
          message: { role: "assistant", content: "ok" },
          done: true,
          prompt_eval_count: 100,
          eval_count: 25,
        }),
      ),
    });
    await rt.executeNative("", messages, [], { onUsage });
    expect(onUsage).toHaveBeenCalledWith({ inputTokens: 100, outputTokens: 25 });
  });

  it("threads tool_result blocks into role=tool turns on the wire", async () => {
    const seen: any[] = [];
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch((_url, init) => {
        seen.push(JSON.parse(String(init!.body)));
        return jsonResponse({
          model: "gemma4:27b",
          created_at: "2026-05-18T00:00:00Z",
          message: { role: "assistant", content: "thanks" },
          done: true,
        });
      }),
    });
    const msgs: NativeMessage[] = [
      { role: "user", content: [{ type: "text", text: "go" }] },
      {
        role: "assistant",
        content: [{ type: "tool_use", id: "abc", name: "read_file", input: { path: "x" } }],
      },
      {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "abc", content: "FILE CONTENTS" }],
      },
    ];
    await rt.executeNative("sys", msgs, tools);
    const wire = seen[0].messages;
    // Wire order: system, user (text), assistant (tool_use prose), tool result.
    expect(wire[0]).toMatchObject({ role: "system", content: "sys" });
    expect(wire.find((m: any) => m.role === "tool")).toMatchObject({
      role: "tool",
      content: "FILE CONTENTS",
      tool_call_id: "abc",
    });
  });
});

describe("OllamaRuntime.executeNative (streaming)", () => {
  const messages: NativeMessage[] = [
    { role: "user", content: [{ type: "text", text: "Stream me." }] },
  ];

  it("fires onDelta for each ND-JSON content chunk and aggregates to full text", async () => {
    const onDelta = vi.fn();
    const frames = [
      { model: "gemma4:27b", created_at: "t", message: { role: "assistant", content: "Hel" }, done: false },
      { model: "gemma4:27b", created_at: "t", message: { role: "assistant", content: "lo " }, done: false },
      { model: "gemma4:27b", created_at: "t", message: { role: "assistant", content: "world" }, done: false },
      {
        model: "gemma4:27b",
        created_at: "t",
        message: { role: "assistant", content: "" },
        done: true,
        done_reason: "stop",
        prompt_eval_count: 9,
        eval_count: 3,
      },
    ];
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch((_url, init) => {
        // Streaming on by default — wire body should reflect that.
        expect(JSON.parse(String(init!.body)).stream).toBe(true);
        return ndjsonStreamResponse(frames);
      }),
    });

    const res = await rt.executeNative("", messages, [], { onDelta });

    expect(onDelta).toHaveBeenCalledTimes(3);
    expect(onDelta).toHaveBeenNthCalledWith(1, "assistant_response", "Hel");
    expect(onDelta).toHaveBeenNthCalledWith(2, "assistant_response", "lo ");
    expect(onDelta).toHaveBeenNthCalledWith(3, "assistant_response", "world");
    expect(res.content[0]).toMatchObject({ type: "text", text: "Hello world" });
    expect(res.stopReason).toBe("end_turn");
  });

  it("fires onUsage exactly once when the terminal frame arrives", async () => {
    const onUsage = vi.fn();
    const onDelta = vi.fn();
    const frames = [
      { message: { role: "assistant", content: "a" }, done: false },
      { message: { role: "assistant", content: "b" }, done: false },
      {
        message: { role: "assistant", content: "" },
        done: true,
        done_reason: "stop",
        prompt_eval_count: 42,
        eval_count: 7,
      },
    ];
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch(() => ndjsonStreamResponse(frames)),
    });

    await rt.executeNative("", messages, [], { onDelta, onUsage });

    expect(onUsage).toHaveBeenCalledTimes(1);
    expect(onUsage).toHaveBeenCalledWith({ inputTokens: 42, outputTokens: 7 });
  });

  it("maps tool_calls arriving on the terminal frame into tool_use blocks", async () => {
    const onDelta = vi.fn();
    const frames = [
      { message: { role: "assistant", content: "Looking" }, done: false },
      { message: { role: "assistant", content: " up the file." }, done: false },
      {
        message: {
          role: "assistant",
          content: "",
          tool_calls: [
            { function: { name: "read_file", arguments: { path: "src/app.js" } } },
          ],
        },
        done: true,
        done_reason: "stop",
        prompt_eval_count: 20,
        eval_count: 8,
      },
    ];
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      fetchImpl: mockFetch(() => ndjsonStreamResponse(frames)),
    });

    const res = await rt.executeNative("", messages, tools, { onDelta });

    expect(res.stopReason).toBe("tool_use");
    expect(res.content).toHaveLength(2);
    expect(res.content[0]).toMatchObject({ type: "text", text: "Looking up the file." });
    expect(res.content[1]).toMatchObject({
      type: "tool_use",
      name: "read_file",
      input: { path: "src/app.js" },
    });
    // Pre-terminal deltas still fire; terminal frame's empty content does not.
    expect(onDelta).toHaveBeenCalledTimes(2);
  });

  it("honours stream:false to keep the legacy single-shot JSON path", async () => {
    const onDelta = vi.fn();
    const rt = new OllamaRuntime({
      model: "gemma4:27b",
      timeout: 5000,
      stream: false,
      fetchImpl: mockFetch((_url, init) => {
        expect(JSON.parse(String(init!.body)).stream).toBe(false);
        return jsonResponse({
          model: "gemma4:27b",
          created_at: "t",
          message: { role: "assistant", content: "no-stream" },
          done: true,
          done_reason: "stop",
        });
      }),
    });
    const res = await rt.executeNative("", messages, [], { onDelta });
    expect(onDelta).not.toHaveBeenCalled();
    expect(res.content[0]).toMatchObject({ type: "text", text: "no-stream" });
  });
});

describe("OllamaRuntime construction", () => {
  it("throws when model is missing", () => {
    expect(() => new OllamaRuntime({ model: "", timeout: 1000 } as any)).toThrow(/model/);
  });

  it("respects OLLAMA_HOST when host is not passed explicitly", () => {
    const original = process.env.OLLAMA_HOST;
    process.env.OLLAMA_HOST = "http://example.test:9999";
    try {
      const rt = new OllamaRuntime({
        model: "gemma4:27b",
        timeout: 1000,
        fetchImpl: mockFetch((url) => {
          expect(url).toContain("example.test:9999");
          return jsonResponse({ models: [] });
        }),
      });
      return rt.isAvailable().then((ok) => expect(ok).toBe(true));
    } finally {
      if (original === undefined) delete process.env.OLLAMA_HOST;
      else process.env.OLLAMA_HOST = original;
    }
  });
});
