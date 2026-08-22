/**
 * Plugin wire protocol — newline-delimited JSON over the child's stdio.
 *
 * This is stage 3 of DESIGN.md ("isolation + dispatch"), the PURE half: the
 * message shapes a host and an out-of-process plugin exchange, plus total
 * decoders. Nothing here touches `process`, the filesystem, the network, a
 * clock, or stdout/stderr — the loader (`loader.ts`) owns all I/O. Keeping the
 * contract pure means the exact same decoder can be exercised by a fake
 * transport in a unit test, by the real stdio path, or by a third-party plugin
 * SDK, with no way for the three to drift.
 *
 * ── Why a subprocess and not an `import()` ───────────────────────────────────
 *
 * DESIGN.md §3 settles this: an in-process plugin "contains nothing" — it can
 * read `process.env` (every provider key), monkey-patch the gate maps in
 * `console/turn-engine.ts`, and turn a capability *declaration* into a promise
 * rather than a boundary. A child process cannot reach any of that. The price
 * is a wire format, and this file is it. The framing deliberately mirrors
 * `hub/mailbox.ts`: one JSON object per line, decoded by a pure/total function
 * that returns a typed failure for every malformed input instead of throwing.
 *
 * ── The trust direction ──────────────────────────────────────────────────────
 *
 * The child is UNTRUSTED. Every byte it sends is attacker-shaped input as far
 * as this module is concerned:
 *
 *   - Frames are BOUNDED ({@link MAX_FRAME_CHARS}). A child that never emits a
 *     newline cannot make the host buffer without limit; the partial frame is
 *     dropped and reported as a typed failure. This is the flood defense.
 *   - Every decoder is TOTAL. Malformed JSON, a JSON array, a JSON scalar, a
 *     missing field, a field of the wrong type, an unknown `kind`, a future
 *     protocol version, a truncated frame — each yields a
 *     {@link ProtocolDecodeFailure}, never a throw.
 *   - The manifest inside a `handshake` is validated by the STAGE-1 validator
 *     ({@link validatePluginManifest}) — there is exactly one manifest
 *     validator in this codebase and this module does not write a second one.
 *   - Tool result CONTENT is clamped here but NOT sanitized here: sanitizing is
 *     the loader's job because `sanitizeUntrustedToolResult` is the codebase's
 *     single untrusted-input defense and lives outside this pure module. This
 *     file guarantees bytes are BOUNDED, not that the prose is trustworthy.
 *
 * ── What the protocol deliberately cannot express ────────────────────────────
 *
 * There is no message a plugin can send that registers a guard, a hook, an
 * interceptor, or an event listener; no message that mutates host state; and no
 * message that carries credentials, scope, or auth config in either direction.
 * A plugin contributes TOOLS and answers `call_tool`. That is the entire
 * vocabulary, and the omission is the security property — see the extended note
 * in `loader.ts`.
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

export type HostMessage = HostListToolsMessage | HostCallToolMessage;

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

export type PluginMessage =
  | PluginHandshakeMessage
  | PluginListToolsMessage
  | PluginToolResultMessage
  | PluginErrorMessage;

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
  }
  try {
    return `${JSON.stringify(base)}\n`;
  } catch {
    // Unserializable args (cycle, BigInt, …). Send a well-formed frame with no
    // args rather than throwing into the caller's turn.
    if (msg.kind === "call_tool") {
      return `${JSON.stringify({
        v: PROTOCOL_VERSION,
        kind: "call_tool",
        id: msg.id,
        tool: msg.tool,
        args: {},
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
    return fail("invalid-manifest", "handshake manifest failed validation", result.errors);
  }
  const manifest = result.manifest;

  if (manifest.id !== pluginId) {
    return fail(
      "malformed-field",
      "handshake `pluginId` does not match the manifest `id` it carries",
    );
  }
  if (manifest.version !== version) {
    return fail(
      "malformed-field",
      "handshake `version` does not match the manifest `version` it carries",
    );
  }
  if (opts?.expectPluginId !== undefined && opts.expectPluginId !== pluginId) {
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
  if (!isToken(rec.id)) {
    return fail("malformed-field", "`list_tools` response is missing a valid correlation id");
  }
  const tools = rec.tools;
  if (!Array.isArray(tools)) {
    return fail("malformed-field", "`list_tools` response `tools` must be an array");
  }
  if (tools.length === 0) {
    return fail("malformed-field", "`list_tools` response declared no tools");
  }
  if (tools.length > MAX_TOOLS_IN_LIST) {
    return fail(
      "malformed-field",
      `\`list_tools\` response declared more than ${MAX_TOOLS_IN_LIST} tools`,
    );
  }

  // Validate the tools by running them through the real manifest validator in a
  // synthetic envelope. Reusing `validatePluginManifest` here is deliberate:
  // the charset, capability-mandatory and built-in-collision rules must be
  // IDENTICAL for a handshake manifest and a `list_tools` response, and the
  // only way to guarantee that is to have one implementation.
  const probe = validatePluginManifest(
    { id: "wire.probe", name: "wire probe", version: "0.0.0", tools },
    { reservedToolNames: opts?.reservedToolNames },
  );
  if (!probe.ok) {
    return fail("invalid-manifest", "`list_tools` response contained invalid tools", probe.errors);
  }

  return {
    ok: true,
    message: { v: PROTOCOL_VERSION, kind: "list_tools", id: rec.id, tools: probe.manifest.tools },
  };
}

function decodeToolResult(rec: Record<string, unknown>): DecodeResult<PluginToolResultMessage> {
  if (!isToken(rec.id)) {
    return fail("malformed-field", "`tool_result` is missing a valid correlation id");
  }
  if (typeof rec.ok !== "boolean") {
    return fail("malformed-field", "`tool_result.ok` must be a boolean");
  }
  if (typeof rec.content !== "string") {
    return fail("malformed-field", "`tool_result.content` must be a string");
  }
  // Clamp on receipt: a well-behaved child clamps too, but the host must never
  // depend on that.
  const clamped = clampResultContent(rec.content);
  return {
    ok: true,
    message: {
      v: PROTOCOL_VERSION,
      kind: "tool_result",
      id: rec.id,
      ok: rec.ok,
      content: clamped.content,
      truncated: clamped.truncated || rec.truncated === true,
    },
  };
}

function decodeError(rec: Record<string, unknown>): DecodeResult<PluginErrorMessage> {
  const id = rec.id === null || rec.id === undefined ? null : rec.id;
  if (id !== null && !isToken(id)) {
    return fail("malformed-field", "`error.id` must be null or a valid correlation id");
  }
  if (typeof rec.code !== "string" || rec.code.length === 0 || rec.code.length > MAX_TOKEN_CHARS) {
    return fail("malformed-field", "`error.code` must be a short non-empty string");
  }
  if (typeof rec.message !== "string") {
    return fail("malformed-field", "`error.message` must be a string");
  }
  return {
    ok: true,
    message: {
      v: PROTOCOL_VERSION,
      kind: "error",
      id,
      code: rec.code,
      message: clampResultContent(rec.message).content,
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

  if (!isToken(rec.id)) {
    return fail("malformed-field", "host message is missing a valid correlation id");
  }
  if (rec.kind === "list_tools") {
    return { ok: true, message: { v: PROTOCOL_VERSION, kind: "list_tools", id: rec.id } };
  }
  if (rec.kind === "call_tool") {
    if (typeof rec.tool !== "string" || rec.tool.length === 0) {
      return fail("malformed-field", "`call_tool.tool` must be a non-empty string");
    }
    if (!isPlainObject(rec.args)) {
      return fail("malformed-field", "`call_tool.args` must be an object");
    }
    return {
      ok: true,
      message: {
        v: PROTOCOL_VERSION,
        kind: "call_tool",
        id: rec.id,
        tool: rec.tool,
        args: rec.args,
      },
    };
  }
  return fail("unknown-kind", `unknown message kind ${JSON.stringify(rec.kind)} from host`);
}

// ── Framing ──────────────────────────────────────────────────────────────────

/** One `push` worth of complete frames plus any framing-level failures. */
export interface FrameBatch {
  frames: string[];
  failures: ProtocolDecodeFailure[];
}

/**
 * Newline-delimited frame reassembler with a HARD memory bound.
 *
 * A child's stdout arrives in arbitrary chunks; frames straddle chunk
 * boundaries. The naive reassembler appends to a buffer until it sees `\n`,
 * which a hostile (or merely broken) child turns into unbounded host memory
 * growth by never sending one. This one refuses:
 *
 *   - once the pending buffer exceeds `maxFrameChars`, the buffer is DROPPED,
 *     an `oversized-frame` failure is emitted, and the reader enters SKIP mode;
 *   - in skip mode every byte is discarded until the next newline, at which
 *     point normal framing resumes. The oversized frame is lost — which is
 *     correct, since a frame we refused to buffer cannot be decoded anyway —
 *     but the stream RESYNCHRONIZES instead of the plugin being permanently
 *     wedged on one bad message.
 *
 * Pure in the sense that matters: no I/O, no clock, no globals. State is only
 * the pending buffer.
 */
export class FrameReader {
  private buffer = "";
  private skipping = false;

  constructor(private readonly maxFrameChars: number = MAX_FRAME_CHARS) {}

  /** Feed a raw chunk. Never throws. */
  push(chunk: string): FrameBatch {
    const out: FrameBatch = { frames: [], failures: [] };
    if (typeof chunk !== "string" || chunk.length === 0) return out;

    let rest = chunk;
    while (rest.length > 0) {
      if (this.skipping) {
        const nl = rest.indexOf("\n");
        if (nl === -1) return out; // still inside the oversized frame
        this.skipping = false;
        rest = rest.slice(nl + 1);
        continue;
      }

      const nl = rest.indexOf("\n");
      if (nl === -1) {
        this.buffer += rest;
        if (this.buffer.length > this.maxFrameChars) {
          out.failures.push(
            fail(
              "oversized-frame",
              `plugin frame exceeded ${this.maxFrameChars} characters before a newline; buffer discarded`,
            ),
          );
          this.buffer = "";
          this.skipping = true;
        }
        return out;
      }

      const frame = this.buffer + rest.slice(0, nl);
      this.buffer = "";
      rest = rest.slice(nl + 1);

      if (frame.length > this.maxFrameChars) {
        out.failures.push(
          fail("oversized-frame", `plugin frame exceeded ${this.maxFrameChars} characters`),
        );
        continue;
      }
      if (frame.trim().length === 0) continue; // tolerate blank lines
      out.frames.push(frame);
    }
    return out;
  }

  /** Discard any partial frame. Called on respawn so state cannot leak across. */
  reset(): void {
    this.buffer = "";
    this.skipping = false;
  }

  /** Characters currently buffered awaiting a newline. For tests/diagnostics. */
  get pending(): number {
    return this.buffer.length;
  }
}

// Re-exported for convenience so a plugin SDK importing only `protocol.js` can
// still reason about gate flags without reaching past the wire contract.
export { gateFlagsFor };
export type { PluginManifest, PluginToolManifest };
