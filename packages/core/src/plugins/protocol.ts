/**
 * Plugin wire protocol — newline-delimited JSON over the child's stdio.
 *
 * Host → child:  `list_tools`, `call_tool`
 * Child → host:  `handshake`, `list_tools`, `tool_result`, `error`
 *
 * Broker direction (host-mediated calls from guest back to host):
 * Child → host:  `request_tool`, `request_skill`, `request_model`
 * Host → child:  `tool_delivery`, `skill_delivery`, `model_delivery`, `broker_error`
 *
 * Protocol version 1 covers all existing and broker message kinds. A child that
 * speaks v1 may send broker requests; a host that speaks v1 may answer them.
 * Extant (pre-broker) code never sends a broker request, so it is unaffected.
 * Unknown-kind rejection remains the correct handling.
 *
 * See DESIGN.md §3 for the wire contract, §5 for the broker path.
 */

import {
  gateFlagsFor,
  validatePluginManifest,
  type PluginManifest,
  type PluginToolManifest,
} from "./manifest.js";

// ── Bounds ───────────────────────────────────────────────────────────────────

/** Wire version. A frame that does not carry exactly this is rejected. */
export const PROTOCOL_VERSION = 1;

/**
 * Maximum characters in a single newline-delimited frame. A child that exceeds
 * it — whether by sending one enormous message or by never sending a newline —
 * has its pending buffer DISCARDED and gets a typed failure. The host never
 * grows a buffer beyond this, so "flood stdout" is a bounded-memory event.
 */
export const MAX_FRAME_CHARS = 1_048_576;

/**
 * Maximum characters of tool-result content the host will carry forward. A
 * plugin result eventually reaches a model context; an unbounded one is both a
 * token-budget and a display-corruption vector.
 */
export const MAX_RESULT_CHARS = 100_000;

/** Appended when {@link MAX_RESULT_CHARS} clamps a result. */
export const RESULT_TRUNCATION_MARKER = "\n[0sec-plugin: result truncated]";

/** Maximum tools a single `list_tools` response may enumerate. */
export const MAX_TOOLS_IN_LIST = 64;

/** Maximum characters in a correlation id / error code. */
const MAX_TOKEN_CHARS = 128;

/** Correlation ids are opaque but must stay printable and bounded. */
const TOKEN_RE = /^[A-Za-z0-9._:-]{1,128}$/;

// ── Host → child messages ────────────────────────────────────────────────────

/** Host asks the child to enumerate the tools it contributes. */
export interface HostListToolsMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "list_tools";
  id: string;
}

/**
 * Host invokes one contributed tool. `args` is a plain object; the host does
 * NOT forward scope, auth config, credentials, or any handle to host state —
 * the child receives only the model-supplied arguments.
 */
export interface HostCallToolMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "call_tool";
  id: string;
  tool: string;
  args: Record<string, unknown>;
}

/**
 * Host delivers a structured tool result in response to a guest's
 * `request_tool` broker call. `output` carries the structured result value,
 * NOT wrapped in the [[0SEC_UNTRUSTED_DATA]] marker — that marker is applied
 * only when content is forwarded to the model as raw text.
 */
export interface HostToolDeliveryMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "tool_delivery";
  id: string;
  ok: boolean;
  output: unknown;
  error?: string;
  truncated: boolean;
}

/**
 * Host delivers a skill execution result in response to a guest's
 * `request_skill` broker call.
 */
export interface HostSkillDeliveryMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "skill_delivery";
  id: string;
  ok: boolean;
  output: unknown;
  error?: string;
}

/**
 * Host delivers a model invocation result in response to a guest's
 * `request_model` broker call. `output` carries the NativeRuntimeResult
 * with `providerRaw` stripped (generated code gets no provider internals).
 */
export interface HostModelDeliveryMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "model_delivery";
  id: string;
  ok: boolean;
  output: unknown;
  error?: string;
}

/**
 * Host reports a broker call failure that did not reach the requested tool,
 * skill, or model — for example, budget exhaustion, an unknown tool name,
 * an unsupported brokered tool, or a signal-triggered cancellation.
 */
export interface HostBrokerErrorMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "broker_error";
  id: string;
  code: string;
  message: string;
}

export type HostMessage =
  | HostListToolsMessage
  | HostCallToolMessage
  | HostToolDeliveryMessage
  | HostSkillDeliveryMessage
  | HostModelDeliveryMessage
  | HostBrokerErrorMessage;

// ── Child → host messages ────────────────────────────────────────────────────

/**
 * First message a child must send. It announces who it claims to be and its
 * full manifest. The loader cross-checks `pluginId`/`version` against the
 * manifest AND against the id it discovered on disk, so a plugin cannot
 * announce itself as someone else.
 */
export interface PluginHandshakeMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "handshake";
  pluginId: string;
  version: string;
  manifest: PluginManifest;
}

/** Child's answer to {@link HostListToolsMessage}, correlated by `id`. */
export interface PluginListToolsMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "list_tools";
  id: string;
  tools: PluginToolManifest[];
}

/**
 * Child's answer to {@link HostCallToolMessage}, correlated by `id`.
 * `ok === false` means the tool failed and `content` carries the reason; there
 * is no separate error channel per call so a child cannot answer twice.
 */
export interface PluginToolResultMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "tool_result";
  id: string;
  ok: boolean;
  content: string;
  truncated: boolean;
}

/**
 * Out-of-band failure. `id` is the correlation id when the failure belongs to a
 * specific request, or `null` for a plugin-level problem.
 */
export interface PluginErrorMessage {
  v: typeof PROTOCOL_VERSION;
  kind: "error";
  id: string | null;
  code: string;
  message: string;
}

/**
 * Guest requests the host to call one of its own (host-side) tools via the
 * broker callback. The guest provides the tool name and args; the host
 * dispatches through normal authorization and returns a structured result.
 * This is the SDK's `sdk.callTool(name, args)` path.
 */
export interface PluginCallToolRequest {
  v: typeof PROTOCOL_VERSION;
  kind: "request_tool";
  id: string;
  name: string;
  args: Record<string, unknown>;
}

/**
 * Guest requests the host to execute another executable skill by name.
 * The host resolves the skill, spins up a guest if needed, and returns the
 * structured result. This is the SDK's `sdk.callSkill(name, args)` path.
 */
export interface PluginCallSkillRequest {
  v: typeof PROTOCOL_VERSION;
  kind: "request_skill";
  id: string;
  name: string;
  args: Record<string, unknown>;
}

/**
 * Guest requests the host to invoke the configured model provider.
 * `system`, `messages`, and `tools` are passed through; the host selects the
 * actual provider, accounts token usage, and strips `providerRaw` from the
 * result. This is the SDK's `sdk.callModel(request)` path.
 */
export interface PluginCallModelRequest {
  v: typeof PROTOCOL_VERSION;
  kind: "request_model";
  id: string;
  system?: string;
  messages: unknown[];
  tools?: unknown[];
}

export type PluginMessage =
  | PluginHandshakeMessage
  | PluginListToolsMessage
  | PluginToolResultMessage
  | PluginErrorMessage
  | PluginCallToolRequest
  | PluginCallSkillRequest
  | PluginCallModelRequest;

// ── Typed failures ───────────────────────────────────────────────────────────

/**
 * The closed set of reasons a frame can fail to decode. Closed (rather than a
 * free-form string) so the loader can react differently to "this child is
 * speaking gibberish" versus "this one message was malformed".
 */
export type ProtocolDecodeFailureReason =
  | "empty-frame"
  | "oversized-frame"
  | "invalid-json"
  | "not-an-object"
  | "unsupported-version"
  | "unknown-kind"
  | "malformed-field"
  | "invalid-manifest";

export interface ProtocolDecodeFailure {
  ok: false;
  reason: ProtocolDecodeFailureReason;
  /** Single-line, bounded, safe to log. Never echoes the offending frame. */
  detail: string;
  /** Populated only when `reason === "invalid-manifest"`. */
  errors?: string[];
}

export type DecodeResult<T> = { ok: true; message: T } | ProtocolDecodeFailure;

function fail(
  reason: ProtocolDecodeFailureReason,
  detail: string,
  errors?: string[],
): ProtocolDecodeFailure {
  const out: ProtocolDecodeFailure = { ok: false, reason, detail };
  if (errors) out.errors = errors;
  return out;
}

// ── Small pure helpers ───────────────────────────────────────────────────────

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function isToken(x: unknown): x is string {
  return typeof x === "string" && x.length <= MAX_TOKEN_CHARS && TOKEN_RE.test(x);
}

/**
 * Clamp result content. Exported because both sides want the same rule: a
 * well-behaved plugin SDK clamps before sending, and the host clamps again on
 * receipt because it must never trust that the child did.
 */
export function clampResultContent(raw: string): { content: string; truncated: boolean } {
  if (typeof raw !== "string") return { content: "", truncated: false };
  if (raw.length <= MAX_RESULT_CHARS) return { content: raw, truncated: false };
  return { content: raw.slice(0, MAX_RESULT_CHARS) + RESULT_TRUNCATION_MARKER, truncated: true };
}

// ── Encoders ─────────────────────────────────────────────────────────────────

/**
 * Serialize a host message to the exact bytes written to the child's stdin,
 * including the terminating newline. Pure.
 *
 * `JSON.stringify` on a message containing a cyclic or unserializable `args`
 * would throw, so this is total by construction: `args` is re-materialized
 * through a shallow copy of own enumerable string keys, and a stringify failure
 * degrades to an empty args object rather than propagating.
 */
export function encodeHostMessage(msg: HostMessage): string {
  const base: Record<string, unknown> = { v: PROTOCOL_VERSION, kind: msg.kind, id: msg.id };
  if (msg.kind === "call_tool") {
    base.tool = msg.tool;
    base.args = msg.args;
  } else if (msg.kind === "tool_delivery") {
    base.ok = msg.ok;
    base.output = msg.output;
    base.truncated = msg.truncated;
    if (msg.error !== undefined) base.error = msg.error;
  } else if (msg.kind === "skill_delivery") {
    base.ok = msg.ok;
    base.output = msg.output;
    if (msg.error !== undefined) base.error = msg.error;
  } else if (msg.kind === "model_delivery") {
    base.ok = msg.ok;
    base.output = msg.output;
    if (msg.error !== undefined) base.error = msg.error;
  } else if (msg.kind === "broker_error") {
    base.code = msg.code;
    base.message = msg.message;
  }
  try {
    return `${JSON.stringify(base)}\n`;
  } catch {
    // Unserializable payload. Emit a well-formed error frame.
    if (msg.kind === "tool_delivery" || msg.kind === "skill_delivery" || msg.kind === "model_delivery") {
      return `${JSON.stringify({
        v: PROTOCOL_VERSION, kind: "broker_error", id: msg.id,
        code: "encode_failed", message: "host delivery payload could not be serialized",
      })}\n`;
    }
    if (msg.kind === "call_tool") {
      return `${JSON.stringify({
        v: PROTOCOL_VERSION, kind: "call_tool", id: msg.id, tool: msg.tool, args: {},
      })}\n`;
    }
    return `${JSON.stringify({ v: PROTOCOL_VERSION, kind: msg.kind, id: msg.id })}\n`;
  }
}

/**
 * Serialize a child message. Used by the reference plugin SDK, the fake
 * transport in tests, and the one integration test that spawns a real child.
 * Pure and total for the same reasons as {@link encodeHostMessage}.
 */
export function encodePluginMessage(msg: PluginMessage): string {
  try {
    return `${JSON.stringify({ ...msg, v: PROTOCOL_VERSION })}\n`;
  } catch {
    return `${JSON.stringify({
      v: PROTOCOL_VERSION,
      kind: "error",
      id: null,
      code: "encode_failed",
      message: "plugin message could not be serialized",
    })}\n`;
  }
}

// ── Decoders ─────────────────────────────────────────────────────────────────

/** Shared prelude: JSON-object-ness and version. Total. */
function decodeEnvelope(raw: string): DecodeResult<Record<string, unknown>> {
  if (typeof raw !== "string") return fail("malformed-field", "frame was not a string");
  const trimmed = raw.trim();
  if (trimmed.length === 0) return fail("empty-frame", "frame was empty");
  if (trimmed.length > MAX_FRAME_CHARS) {
    return fail("oversized-frame", `frame exceeds ${MAX_FRAME_CHARS} characters`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return fail("invalid-json", "frame was not valid JSON");
  }
  if (!isPlainObject(parsed)) {
    return fail("not-an-object", "frame decoded to a non-object JSON value");
  }
  if (parsed.v !== PROTOCOL_VERSION) {
    return fail(
      "unsupported-version",
      `frame declares protocol version ${JSON.stringify(parsed.v)}; this host speaks ${PROTOCOL_VERSION}`,
    );
  }
  return { ok: true, message: parsed };
}

/**
 * Decode one frame received FROM a plugin child. Pure and TOTAL.
 *
 * `opts.reservedToolNames` is forwarded to {@link validatePluginManifest} so a
 * handshake whose manifest shadows a built-in tool name is rejected at the wire
 * boundary, before the loader ever sees it. `opts.expectPluginId`, when given,
 * additionally requires the announced identity to match the id the host
 * discovered on disk — a plugin installed as `acme.recon` cannot announce
 * itself as `vendor.trusted`.
 */
export function decodePluginMessage(
  raw: string,
  opts?: { reservedToolNames?: readonly string[]; expectPluginId?: string },
): DecodeResult<PluginMessage> {
  const envelope = decodeEnvelope(raw);
  if (!envelope.ok) return envelope;
  const rec = envelope.message;

  switch (rec.kind) {
    case "handshake":
      return decodeHandshake(rec, opts);
    case "list_tools":
      return decodeListToolsResponse(rec, opts);
    case "tool_result":
      return decodeToolResult(rec);
    case "error":
      return decodeError(rec);
    case "request_tool":
      return decodeRequestTool(rec);
    case "request_skill":
      return decodeRequestSkill(rec);
    case "request_model":
      return decodeRequestModel(rec);
    default:
      return fail(
        "unknown-kind",
        `unknown message kind ${JSON.stringify(rec.kind)} from plugin`,
      );
  }
}

function decodeHandshake(
  rec: Record<string, unknown>,
  opts?: { reservedToolNames?: readonly string[]; expectPluginId?: string },
): DecodeResult<PluginHandshakeMessage> {
  const pluginId = rec.pluginId;
  const version = rec.version;
  if (typeof pluginId !== "string" || pluginId.length === 0) {
    return fail("malformed-field", "handshake `pluginId` must be a non-empty string");
  }
  if (typeof version !== "string" || version.length === 0) {
    return fail("malformed-field", "handshake `version` must be a non-empty string");
  }

  // ONE validator. `manifest.ts` owns what a manifest is; this module never
  // second-guesses it, and in particular never accepts a manifest it rejects.
  const result = validatePluginManifest(rec.manifest, {
    reservedToolNames: opts?.reservedToolNames,
  });
  if (!result.ok) {
    return fail(
      "invalid-manifest",
      `plugin ${pluginId} handshake has an invalid manifest`,
      result.errors,
    );
  }

  const manifest = result.manifest;
  if (pluginId !== manifest.id || version !== manifest.version) {
    return fail("malformed-field", "handshake identity and version must match its manifest");
  }

  if (opts?.expectPluginId !== undefined && pluginId !== opts.expectPluginId) {
    return fail(
      "malformed-field",
      `plugin announced id ${JSON.stringify(pluginId)} but was installed as ${JSON.stringify(opts.expectPluginId)}`,
    );
  }

  return {
    ok: true,
    message: { v: PROTOCOL_VERSION, kind: "handshake", pluginId, version, manifest },
  };
}

function decodeListToolsResponse(
  rec: Record<string, unknown>,
  opts?: { reservedToolNames?: readonly string[] },
): DecodeResult<PluginListToolsMessage> {
  if (!isToken(rec.id)) return fail("malformed-field", "`list_tools` response has a missing or malformed `id`");

  if (!Array.isArray(rec.tools)) {
    return fail("malformed-field", "`list_tools` response `tools` must be an array");
  }
  if (rec.tools.length > MAX_TOOLS_IN_LIST) {
    return fail("malformed-field", `at most ${MAX_TOOLS_IN_LIST} tools per plugin`);
  }

  const result = validatePluginManifest({
    id: "protocol.list-tools",
    name: "Plugin tool list",
    version: "0.0.0",
    tools: rec.tools,
  }, opts);
  if (!result.ok) {
    return fail("invalid-manifest", "plugin tool list has an invalid manifest", result.errors);
  }
  return {
    ok: true,
    message: { v: PROTOCOL_VERSION, kind: "list_tools", id: rec.id, tools: result.manifest.tools },
  };
}

function decodeToolResult(rec: Record<string, unknown>): DecodeResult<PluginToolResultMessage> {
  if (!isToken(rec.id)) return fail("malformed-field", "`tool_result` has a missing or malformed `id`");
  if (typeof rec.ok !== "boolean") return fail("malformed-field", "`tool_result` must have a boolean `ok`");
  if (typeof rec.content !== "string") return fail("malformed-field", "`tool_result` must have a string `content`");
  const bounded = clampResultContent(rec.content);
  return {
    ok: true,
    message: {
      v: PROTOCOL_VERSION, kind: "tool_result",
      id: rec.id as string, ok: rec.ok as boolean,
      content: bounded.content,
      truncated: bounded.truncated || rec.truncated === true,
    },
  };
}

function decodeError(rec: Record<string, unknown>): DecodeResult<PluginErrorMessage> {
  if (rec.id !== null && !isToken(rec.id)) return fail("malformed-field", "`error` message has a malformed `id`");
  const id = rec.id;
  if (!isToken(rec.code)) {
    return fail("malformed-field", "`error` must have a valid token `code`");
  }
  if (typeof rec.message !== "string" || rec.message.length === 0) {
    return fail("malformed-field", "`error` must have a non-empty `message`");
  }
  return { ok: true, message: { v: PROTOCOL_VERSION, kind: "error", id, code: rec.code as string, message: rec.message as string } };
}

function decodeRequestTool(rec: Record<string, unknown>): DecodeResult<PluginCallToolRequest> {
  if (!isToken(rec.id)) return fail("malformed-field", "`request_tool` has a missing or malformed `id`");
  if (typeof rec.name !== "string" || rec.name.length === 0) {
    return fail("malformed-field", "`request_tool` must have a non-empty `name`");
  }
  if (!isPlainObject(rec.args)) {
    return fail("malformed-field", "`request_tool` `args` must be a plain object");
  }
  return {
    ok: true,
    message: {
      v: PROTOCOL_VERSION, kind: "request_tool", id: rec.id as string,
      name: rec.name as string, args: rec.args as Record<string, unknown>,
    },
  };
}

function decodeRequestSkill(rec: Record<string, unknown>): DecodeResult<PluginCallSkillRequest> {
  if (!isToken(rec.id)) return fail("malformed-field", "`request_skill` has a missing or malformed `id`");
  if (typeof rec.name !== "string" || rec.name.length === 0) {
    return fail("malformed-field", "`request_skill` must have a non-empty `name`");
  }
  if (!isPlainObject(rec.args)) {
    return fail("malformed-field", "`request_skill` `args` must be a plain object");
  }
  return {
    ok: true,
    message: {
      v: PROTOCOL_VERSION, kind: "request_skill", id: rec.id as string,
      name: rec.name as string, args: rec.args as Record<string, unknown>,
    },
  };
}

function decodeRequestModel(rec: Record<string, unknown>): DecodeResult<PluginCallModelRequest> {
  if (!isToken(rec.id)) return fail("malformed-field", "`request_model` has a missing or malformed `id`");
  if (rec.system !== undefined && (typeof rec.system !== "string")) {
    return fail("malformed-field", "`request_model` `system` must be a string when present");
  }
  if (!Array.isArray(rec.messages)) {
    return fail("malformed-field", "`request_model` `messages` must be an array");
  }
  if (rec.tools !== undefined && !Array.isArray(rec.tools)) {
    return fail("malformed-field", "`request_model` `tools` must be an array when present");
  }
  return {
    ok: true,
    message: {
      v: PROTOCOL_VERSION, kind: "request_model", id: rec.id as string,
      system: rec.system as string | undefined,
      messages: rec.messages as unknown[],
      tools: rec.tools as unknown[] | undefined,
    },
  };
}

/**
 * Decode a frame received FROM the host. Pure and total. The host is the
 * trusted side, so this exists for plugin SDK authors and for tests that assert
 * the exact bytes the loader writes — not as a host-side security boundary.
 */
export function decodeHostMessage(raw: string): DecodeResult<HostMessage> {
  const envelope = decodeEnvelope(raw);
  if (!envelope.ok) return envelope;
  const rec = envelope.message;

  const id = rec.id as string | undefined;
  if (typeof id !== "string" || !isToken(id)) {
    return fail("malformed-field", "host message has a missing or malformed `id`");
  }

  switch (rec.kind) {
    case "list_tools":
      return { ok: true, message: { v: PROTOCOL_VERSION, kind: "list_tools", id } };
    case "call_tool":
      if (typeof rec.tool !== "string" || rec.tool.length === 0) {
        return fail("malformed-field", "`call_tool` must have a non-empty `tool`");
      }
      if (!isPlainObject(rec.args)) {
        return fail("malformed-field", "`call_tool` `args` must be a plain object");
      }
      return {
        ok: true,
        message: {
          v: PROTOCOL_VERSION, kind: "call_tool", id,
          tool: rec.tool as string, args: rec.args as Record<string, unknown>,
        },
      };
    case "tool_delivery":
      if (typeof rec.ok !== "boolean") return fail("malformed-field", "`tool_delivery` must have a boolean `ok`");
      return {
        ok: true,
        message: {
          v: PROTOCOL_VERSION, kind: "tool_delivery", id, ok: rec.ok as boolean,
          output: rec.output, error: rec.error as string | undefined,
          truncated: rec.truncated === true,
        },
      };
    case "skill_delivery":
      if (typeof rec.ok !== "boolean") return fail("malformed-field", "`skill_delivery` must have a boolean `ok`");
      return {
        ok: true,
        message: {
          v: PROTOCOL_VERSION, kind: "skill_delivery", id, ok: rec.ok as boolean,
          output: rec.output, error: rec.error as string | undefined,
        },
      };
    case "model_delivery":
      if (typeof rec.ok !== "boolean") return fail("malformed-field", "`model_delivery` must have a boolean `ok`");
      return {
        ok: true,
        message: {
          v: PROTOCOL_VERSION, kind: "model_delivery", id, ok: rec.ok as boolean,
          output: rec.output, error: rec.error as string | undefined,
        },
      };
    case "broker_error":
      if (typeof rec.code !== "string" || rec.code.length === 0) {
        return fail("malformed-field", "`broker_error` must have a non-empty `code`");
      }
      if (typeof rec.message !== "string") {
        return fail("malformed-field", "`broker_error` must have a string `message`");
      }
      return {
        ok: true,
        message: {
          v: PROTOCOL_VERSION, kind: "broker_error", id,
          code: rec.code as string, message: rec.message as string,
        },
      };
    default:
      return fail("unknown-kind", `unknown message kind ${JSON.stringify(rec.kind)} from host`);
  }
}

// ── Framing ──────────────────────────────────────────────────────────────────

/** One `push` worth of complete frames plus any framing-level failures. */
export interface FrameBatch {
  frames: string[];
  failures: ProtocolDecodeFailure[];
}

/**
 * Bounded newline reassembler. Oversized fragments are discarded through the
 * next newline, then framing resumes. Complete frames remain raw so callers
 * can decode with their expected plugin identity and reserved tool names.
 */
export class FrameReader {
  private buffer = "";
  private skipping = false;

  constructor(private readonly maxFrameChars: number = MAX_FRAME_CHARS) {}

  /** Reassemble raw frames; protocol decoding belongs to the caller. */
  push(chunk: string): FrameBatch {
    const out: FrameBatch = { frames: [], failures: [] };
    if (typeof chunk !== "string" || chunk.length === 0) return out;
    let rest = chunk;
    while (rest.length > 0) {
      if (this.skipping) {
        const nl = rest.indexOf("\n");
        if (nl === -1) return out;
        this.skipping = false;
        rest = rest.slice(nl + 1);
        continue;
      }
      const nl = rest.indexOf("\n");
      if (nl === -1) {
        if (this.buffer.length + rest.length > this.maxFrameChars) {
          out.failures.push(fail("oversized-frame", `plugin frame exceeded ${this.maxFrameChars} characters before a newline; buffer discarded`));
          this.buffer = "";
          this.skipping = true;
        } else {
          this.buffer += rest;
        }
        return out;
      }
      const size = this.buffer.length + nl;
      if (size > this.maxFrameChars) {
        out.failures.push(fail("oversized-frame", `plugin frame exceeded ${this.maxFrameChars} characters`));
      } else {
        const frame = this.buffer + rest.slice(0, nl);
        if (frame.trim().length > 0) out.frames.push(frame);
      }
      this.buffer = "";
      rest = rest.slice(nl + 1);
    }
    return out;
  }

  reset(): void {
    this.buffer = "";
    this.skipping = false;
  }

  get pending(): number {
    return this.buffer.length;
  }
}

// Re-exported for convenience so a plugin SDK importing only `protocol.js` can
// still reason about gate flags without reaching past the wire contract.
export { gateFlagsFor };
export type { PluginManifest, PluginToolManifest };