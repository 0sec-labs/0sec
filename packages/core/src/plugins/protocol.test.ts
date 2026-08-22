import { describe, expect, it } from "vitest";

import type { PluginManifest } from "./manifest.js";
import {
  clampResultContent,
  decodeHostMessage,
  decodePluginMessage,
  encodeHostMessage,
  encodePluginMessage,
  FrameReader,
  MAX_RESULT_CHARS,
  MAX_TOOLS_IN_LIST,
  PROTOCOL_VERSION,
  RESULT_TRUNCATION_MARKER,
} from "./protocol.js";

// ── fixtures ─────────────────────────────────────────────────────────────────

const TOOL = {
  name: "acme_probe",
  description: "probe a host",
  parameters: { host: { type: "string", description: "target host" } },
  required: ["host"],
  capabilities: ["network"],
};

const MANIFEST: PluginManifest = {
  id: "acme.recon",
  name: "Acme Recon",
  version: "1.2.3",
  tools: [TOOL as never],
};

function handshakeFrame(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    v: PROTOCOL_VERSION,
    kind: "handshake",
    pluginId: "acme.recon",
    version: "1.2.3",
    manifest: MANIFEST,
    ...overrides,
  });
}

// ── envelope-level totality ──────────────────────────────────────────────────

describe("decodePluginMessage — totality", () => {
  const hostile: unknown[] = [
    "",
    "   ",
    "not json",
    "{",
    "[]",
    "null",
    "123",
    '"a string"',
    "{}",
    '{"v":2,"kind":"handshake"}',
    '{"v":"1","kind":"handshake"}',
    '{"v":1}',
    '{"v":1,"kind":"nope"}',
    '{"v":1,"kind":42}',
    '{"v":1,"kind":"handshake","manifest":null}',
    '{"v":1,"kind":"tool_result"}',
    '{"v":1,"kind":"tool_result","id":"a"}',
    '{"v":1,"kind":"error"}',
    '{"v":1,"kind":"list_tools"}',
    '{"__proto__":{"polluted":true},"v":1,"kind":"handshake"}',
  ];

  it("never throws on any malformed frame and always returns a typed failure", () => {
    for (const raw of hostile) {
      const decode = (): unknown => decodePluginMessage(raw as string);
      expect(decode).not.toThrow();
      const result = decodePluginMessage(raw as string);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(typeof result.reason).toBe("string");
        expect(typeof result.detail).toBe("string");
      }
    }
  });

  it("does not throw when handed non-string input", () => {
    for (const bad of [undefined, null, 12, {}, []]) {
      expect(() => decodePluginMessage(bad as unknown as string)).not.toThrow();
      expect(decodePluginMessage(bad as unknown as string).ok).toBe(false);
    }
  });

  it("classifies failures precisely", () => {
    expect(decodePluginMessage("")).toMatchObject({ reason: "empty-frame" });
    expect(decodePluginMessage("{oops")).toMatchObject({ reason: "invalid-json" });
    expect(decodePluginMessage("[1,2]")).toMatchObject({ reason: "not-an-object" });
    expect(decodePluginMessage('{"v":9,"kind":"error"}')).toMatchObject({
      reason: "unsupported-version",
    });
    expect(decodePluginMessage('{"v":1,"kind":"telepathy"}')).toMatchObject({
      reason: "unknown-kind",
    });
  });

  it("rejects a frame larger than the bound instead of decoding it", () => {
    const huge = JSON.stringify({ v: 1, kind: "error", id: null, code: "x", message: "y".repeat(2_000_000) });
    expect(decodePluginMessage(huge)).toMatchObject({ reason: "oversized-frame" });
  });

  it("a __proto__ key in a frame does not pollute Object.prototype", () => {
    decodePluginMessage('{"v":1,"kind":"error","id":null,"code":"c","message":"m","__proto__":{"pwned":1}}');
    expect(({} as Record<string, unknown>).pwned).toBeUndefined();
  });
});

// ── handshake ────────────────────────────────────────────────────────────────

describe("decodePluginMessage — handshake", () => {
  it("accepts a well-formed handshake and returns the validated manifest", () => {
    const result = decodePluginMessage(handshakeFrame());
    expect(result.ok).toBe(true);
    if (result.ok && result.message.kind === "handshake") {
      expect(result.message.pluginId).toBe("acme.recon");
      expect(result.message.manifest.tools).toHaveLength(1);
      expect(result.message.manifest.tools[0]?.capabilities).toEqual(["network"]);
    }
  });

  it("rejects a manifest that fails stage-1 validation and reports its errors", () => {
    const bad = handshakeFrame({
      manifest: { ...MANIFEST, tools: [{ ...TOOL, capabilities: [] }] },
    });
    const result = decodePluginMessage(bad);
    expect(result).toMatchObject({ ok: false, reason: "invalid-manifest" });
    if (!result.ok) expect(result.errors?.join(" ")).toContain("capabilities");
  });

  it("rejects a manifest whose tool shadows a reserved built-in name", () => {
    const shadow = handshakeFrame({
      manifest: { ...MANIFEST, tools: [{ ...TOOL, name: "run_command" }] },
    });
    const result = decodePluginMessage(shadow, { reservedToolNames: ["run_command"] });
    expect(result).toMatchObject({ ok: false, reason: "invalid-manifest" });
    if (!result.ok) expect(result.errors?.join(" ")).toContain("collides with a built-in");
  });

  it("rejects a handshake whose announced id disagrees with its manifest", () => {
    expect(decodePluginMessage(handshakeFrame({ pluginId: "evil.other" }))).toMatchObject({
      ok: false,
      reason: "malformed-field",
    });
  });

  it("rejects a handshake whose announced version disagrees with its manifest", () => {
    expect(decodePluginMessage(handshakeFrame({ version: "9.9.9" }))).toMatchObject({
      ok: false,
      reason: "malformed-field",
    });
  });

  it("rejects a plugin announcing an id other than the one it was installed as", () => {
    const result = decodePluginMessage(handshakeFrame(), { expectPluginId: "someone.else" });
    expect(result).toMatchObject({ ok: false, reason: "malformed-field" });
    if (!result.ok) expect(result.detail).toContain("installed as");
  });

  it("rejects missing pluginId / version", () => {
    expect(decodePluginMessage(handshakeFrame({ pluginId: 5 }))).toMatchObject({ ok: false });
    expect(decodePluginMessage(handshakeFrame({ version: "" }))).toMatchObject({ ok: false });
  });
});

// ── list_tools ───────────────────────────────────────────────────────────────

describe("decodePluginMessage — list_tools", () => {
  const frame = (tools: unknown, id: unknown = "r1"): string =>
    JSON.stringify({ v: 1, kind: "list_tools", id, tools });
  const frameNoId = (tools: unknown): string =>
    JSON.stringify({ v: 1, kind: "list_tools", tools });

  it("accepts a valid tool list", () => {
    const result = decodePluginMessage(frame([TOOL]));
    expect(result.ok).toBe(true);
    if (result.ok && result.message.kind === "list_tools") {
      expect(result.message.tools[0]?.name).toBe("acme_probe");
    }
  });

  it("requires a correlation id", () => {
    expect(decodePluginMessage(frameNoId([TOOL]))).toMatchObject({ ok: false });
    expect(decodePluginMessage(frame([TOOL], "has spaces"))).toMatchObject({ ok: false });
  });

  it("rejects non-array, empty, and oversized lists", () => {
    expect(decodePluginMessage(frame("nope"))).toMatchObject({ ok: false });
    expect(decodePluginMessage(frame([]))).toMatchObject({ ok: false });
    const many = Array.from({ length: MAX_TOOLS_IN_LIST + 1 }, (_, i) => ({
      ...TOOL,
      name: `t_${i}`,
    }));
    expect(decodePluginMessage(frame(many))).toMatchObject({ ok: false });
  });

  it("applies the SAME validator as the handshake (no second, laxer path)", () => {
    // capability-less tool must be rejected here exactly as in a handshake
    expect(decodePluginMessage(frame([{ ...TOOL, capabilities: [] }]))).toMatchObject({
      ok: false,
      reason: "invalid-manifest",
    });
    // built-in shadowing must be rejected here exactly as in a handshake
    expect(
      decodePluginMessage(frame([{ ...TOOL, name: "save_finding" }]), {
        reservedToolNames: ["save_finding"],
      }),
    ).toMatchObject({ ok: false, reason: "invalid-manifest" });
  });
});

// ── tool_result / error ──────────────────────────────────────────────────────

describe("decodePluginMessage — tool_result and error", () => {
  it("accepts a well-formed result", () => {
    const raw = JSON.stringify({
      v: 1,
      kind: "tool_result",
      id: "c1",
      ok: true,
      content: "hello",
      truncated: false,
    });
    const result = decodePluginMessage(raw);
    expect(result.ok).toBe(true);
    if (result.ok && result.message.kind === "tool_result") {
      expect(result.message.content).toBe("hello");
      expect(result.message.ok).toBe(true);
    }
  });

  it("rejects results with wrong field types", () => {
    const bad = [
      { v: 1, kind: "tool_result", id: "c1", ok: "yes", content: "x" },
      { v: 1, kind: "tool_result", id: "c1", ok: true, content: 5 },
      { v: 1, kind: "tool_result", id: 5, ok: true, content: "x" },
    ];
    for (const b of bad) expect(decodePluginMessage(JSON.stringify(b)).ok).toBe(false);
  });

  it("clamps oversized result content on receipt even if the child claims otherwise", () => {
    const raw = JSON.stringify({
      v: 1,
      kind: "tool_result",
      id: "c1",
      ok: true,
      content: "a".repeat(MAX_RESULT_CHARS + 500),
      truncated: false,
    });
    const result = decodePluginMessage(raw);
    expect(result.ok).toBe(true);
    if (result.ok && result.message.kind === "tool_result") {
      expect(result.message.truncated).toBe(true);
      expect(result.message.content.length).toBeLessThanOrEqual(
        MAX_RESULT_CHARS + RESULT_TRUNCATION_MARKER.length,
      );
    }
  });

  it("accepts an error with a null id and rejects a bad code", () => {
    expect(
      decodePluginMessage(JSON.stringify({ v: 1, kind: "error", id: null, code: "boom", message: "x" })).ok,
    ).toBe(true);
    expect(
      decodePluginMessage(JSON.stringify({ v: 1, kind: "error", id: null, code: "", message: "x" })).ok,
    ).toBe(false);
    expect(
      decodePluginMessage(JSON.stringify({ v: 1, kind: "error", id: "not ok!", code: "c", message: "x" })).ok,
    ).toBe(false);
  });
});

// ── clamping ─────────────────────────────────────────────────────────────────

describe("clampResultContent", () => {
  it("passes short content through untouched", () => {
    expect(clampResultContent("abc")).toEqual({ content: "abc", truncated: false });
  });

  it("truncates and marks long content", () => {
    const out = clampResultContent("z".repeat(MAX_RESULT_CHARS + 1));
    expect(out.truncated).toBe(true);
    expect(out.content.endsWith(RESULT_TRUNCATION_MARKER)).toBe(true);
  });

  it("is total for non-string input", () => {
    expect(clampResultContent(undefined as unknown as string)).toEqual({
      content: "",
      truncated: false,
    });
  });
});

// ── encoders ─────────────────────────────────────────────────────────────────

describe("encoders", () => {
  it("round-trips a call_tool through the host decoder", () => {
    const line = encodeHostMessage({
      v: 1,
      kind: "call_tool",
      id: "c7",
      tool: "acme_probe",
      args: { host: "example.test" },
    });
    expect(line.endsWith("\n")).toBe(true);
    const back = decodeHostMessage(line.trim());
    expect(back.ok).toBe(true);
    if (back.ok && back.message.kind === "call_tool") {
      expect(back.message.tool).toBe("acme_probe");
      expect(back.message.args).toEqual({ host: "example.test" });
    }
  });

  it("does not throw on unserializable args — it degrades to empty args", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    const line = encodeHostMessage({ v: 1, kind: "call_tool", id: "c8", tool: "t", args: cyclic });
    const back = decodeHostMessage(line.trim());
    expect(back.ok).toBe(true);
    if (back.ok && back.message.kind === "call_tool") expect(back.message.args).toEqual({});
  });

  it("round-trips a handshake through the plugin decoder", () => {
    const line = encodePluginMessage({
      v: 1,
      kind: "handshake",
      pluginId: "acme.recon",
      version: "1.2.3",
      manifest: MANIFEST,
    });
    expect(decodePluginMessage(line.trim()).ok).toBe(true);
  });
});

describe("decodeHostMessage", () => {
  it("is total for garbage", () => {
    for (const raw of ["", "{", "[]", '{"v":1,"kind":"call_tool"}', '{"v":1,"kind":"zzz","id":"a"}']) {
      expect(() => decodeHostMessage(raw)).not.toThrow();
      expect(decodeHostMessage(raw).ok).toBe(false);
    }
  });

  it("rejects call_tool with non-object args", () => {
    expect(
      decodeHostMessage(JSON.stringify({ v: 1, kind: "call_tool", id: "a", tool: "t", args: 5 })).ok,
    ).toBe(false);
  });
});

// ── framing ──────────────────────────────────────────────────────────────────

describe("FrameReader", () => {
  it("reassembles frames split across arbitrary chunk boundaries", () => {
    const reader = new FrameReader();
    const whole = '{"a":1}\n{"b":2}\n';
    const seen: string[] = [];
    for (const ch of whole) seen.push(...reader.push(ch).frames);
    expect(seen).toEqual(['{"a":1}', '{"b":2}']);
  });

  it("emits several frames from one chunk and tolerates blank lines", () => {
    const reader = new FrameReader();
    const batch = reader.push("one\n\n\ntwo\nthree");
    expect(batch.frames).toEqual(["one", "two"]);
    expect(reader.pending).toBe(5);
  });

  it("bounds memory: a child that never sends a newline cannot grow the buffer", () => {
    const reader = new FrameReader(64);
    let failures = 0;
    for (let i = 0; i < 200; i++) {
      failures += reader.push("x".repeat(32)).failures.length;
      expect(reader.pending).toBeLessThanOrEqual(64);
    }
    expect(failures).toBeGreaterThan(0);
  });

  it("resynchronizes on the next newline after an oversized frame", () => {
    const reader = new FrameReader(16);
    const first = reader.push("y".repeat(100));
    expect(first.failures[0]).toMatchObject({ reason: "oversized-frame" });
    expect(first.frames).toEqual([]);
    const second = reader.push("more-garbage\nGOOD\n");
    expect(second.frames).toEqual(["GOOD"]);
  });

  it("rejects a complete-but-oversized frame without emitting it", () => {
    const reader = new FrameReader(8);
    const batch = reader.push(`${"a".repeat(50)}\nok\n`);
    expect(batch.frames).toEqual(["ok"]);
    expect(batch.failures).toHaveLength(1);
  });

  it("never throws on any input", () => {
    const reader = new FrameReader();
    for (const bad of [undefined, null, 5, {}, ""]) {
      expect(() => reader.push(bad as unknown as string)).not.toThrow();
    }
  });

  it("reset() discards a partial frame so state cannot leak across a respawn", () => {
    const reader = new FrameReader();
    reader.push("half-a-fra");
    expect(reader.pending).toBeGreaterThan(0);
    reader.reset();
    expect(reader.pending).toBe(0);
    expect(reader.push("me\n").frames).toEqual(["me"]);
  });
});
