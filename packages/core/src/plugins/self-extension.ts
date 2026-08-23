/**
 * Model-authored self-extension: a session-scoped, additive-only registry.
 *
 * WHAT THIS IS
 * ------------
 * The operator asked for the DeepSeek-harness capability where the model can
 * author a plugin and register it into the running session. This module is the
 * REGISTRATION, VALIDATION and POLICY half of that, behind a setting that is
 * OFF by default (`SELF_EXTENSION_SETTING_DEF` below).
 *
 * It deliberately does NOT reproduce the flaw in that harness. In `dsh`, a
 * plugin can install a `tools/pre-execute` listener, and a listener that returns
 * without calling `next()` short-circuits the chain — so one model-written
 * plugin can silently disable the ENTIRE authorization pipeline. Their own
 * README concedes the toolset is "not a security boundary… treat it like bash
 * access." 0sec's guard layer is deny-only, and that single type-level fact is
 * what lets us accept model-authored contributions without inheriting that
 * property.
 *
 * ── The contribution surface: exactly two things ─────────────────────────────
 *
 *   1. TOOL DEFINITIONS, via a `PluginManifest` with MANDATORY capabilities.
 *   2. GUARDS, as `ToolGuard` — the deny-only guard type from `guards.ts`.
 *
 * That is the whole surface. There are no hooks, no interceptors, no
 * middleware, no `next()`, no event listeners, no config mutation, no access to
 * the session, the event bus, settings, or the gate maps. Those are not
 * "discouraged" — there is no field in `ExtensionSubmission` that can carry
 * them, so they are not expressible.
 *
 * ── Why a contribution can never WIDEN access ────────────────────────────────
 *
 * A contributed guard is a `ToolGuard = (ctx) => string | null | undefined`.
 * Every string is a denial reason (`evaluateGuards` treats even the empty
 * string as a placeholder denial); `null`/`undefined` is abstention. There is
 * NO value in that codomain meaning "allow". Therefore:
 *
 *   - a contributed guard cannot vote to allow;
 *   - it cannot override, cancel or short-circuit another guard's denial,
 *     because `evaluateGuards` runs every guard and only ever APPENDS reasons;
 *   - registering a contribution can only ever add guards to the evaluated set,
 *     and `allowed === reasons.length === 0`, so the verdict after registration
 *     is at most as permissive as before it.
 *
 * THIS IS THE PROPERTY `dsh` LACKS. Its pre-execute waterfall gives a plugin a
 * value ("return without calling next()") that means "stop authorizing"; ours
 * has no such value to return.
 *
 * Two runtime hardenings close the gaps the type system alone cannot:
 *
 *   - Contributed guards are wrapped (`wrapContributedGuard`). The wrapper hands
 *     the guard a FROZEN SHALLOW COPY of the `GuardContext`, never the caller's
 *     object. Without this, a contributed guard running before a built-in could
 *     mutate `ctx` (e.g. set `capabilitiesResolved = true`) and turn a built-in
 *     denial into an abstention — a real widening path, since `GuardContext`'s
 *     `readonly` markers are compile-time only. Mutating the frozen copy throws
 *     in strict mode, and `evaluateGuards` treats a throwing guard as a DENIAL,
 *     so the attempt narrows rather than widens.
 *   - The wrapper coerces the return value: a string passes through, anything
 *     else becomes `null`. A hostile object with a poisoned `toString` cannot
 *     become an allowance either way (non-strings already abstain), and this
 *     keeps the contract exact.
 *
 * ── Existing policy is untouchable ───────────────────────────────────────────
 *
 * Registration is ADDITIVE ONLY. This registry exposes no method that removes,
 * replaces, reorders or disables an existing guard, an existing gate-map entry,
 * or a built-in tool — assert that by reading the class's public surface: the
 * only mutators are `register` and the disposer it returns, and the disposer
 * only ever drops the contributions of its own registration. Base guards are
 * held in a frozen array captured at construction and are re-emitted first on
 * every `guards()` snapshot; nothing in the public API can reach them. Ordering
 * never affects `allowed` anyway (the verdict is "did anyone deny"), so
 * "reordering" is not even a meaningful attack here — but there is no API for it
 * regardless.
 *
 * A contributed tool whose name collides with a built-in is REJECTED, never
 * allowed to shadow: `reservedToolNames` is supplied by the caller (the keys of
 * `TOOL_DISPATCH` ∪ the three gate maps) and passed straight into
 * `validatePluginManifest`. Cross-extension collisions are rejected too.
 *
 * ── Capabilities: mandatory, fail-closed, one validator ───────────────────────
 *
 * This module writes NO second validator. It calls `validatePluginManifest` and
 * `gateFlagsFor` from `manifest.ts` — the same pair the third-party plugin path
 * uses — so a tool with no declared capability is rejected outright and an
 * unknown/empty capability set yields the most restrictive gate flags, never
 * read-only.
 *
 * ── OUT OF SCOPE: executing model-authored code ──────────────────────────────
 *
 * This module governs registration, validation and policy. It never compiles,
 * `eval`s, imports or invokes a tool body, and registering a tool here does NOT
 * make it callable. Execution needs the subprocess-over-stdio dispatch from
 * DESIGN.md §3 option B / stage 3. See SELF-EXTENSION.md.
 *
 * (One honest caveat, stated in full in SELF-EXTENSION.md: a contributed GUARD
 * is a function, and calling it is running code. This registry only ever accepts
 * an already-constructed function; it never turns model-authored TEXT into one.
 * The wiring must not hand it `new Function(modelText)` in-process.)
 */

import {
  gateFlagsFor,
  validatePluginManifest,
  type PluginCapability,
  type PluginManifest,
  type PluginToolManifest,
} from "./manifest.js";
import { evaluateGuards, sanitizeReason, type GuardContext, type GuardVerdict, type ToolGuard } from "./guards.js";

// ── Bounds ───────────────────────────────────────────────────────────────────
//
// A model that loops registering plugins must hit a wall, not exhaust memory.
// Every limit is small enough that the entire session's model-authored surface
// stays reviewable by a human on one screen — the point is auditability, not
// capacity. All are overridable per-registry (downward or upward) by the
// operator-side wiring, never by a submission.

/** Maximum successful registrations that may be live at one time in a session. */
export const MAX_EXTENSIONS_PER_SESSION = 8;
/** Maximum tools a single submitted manifest may contribute. */
export const MAX_TOOLS_PER_EXTENSION = 8;
/** Maximum live contributed tools across all extensions in a session. */
export const MAX_TOOLS_PER_SESSION = 32;
/** Maximum guards a single submission may contribute. */
export const MAX_GUARDS_PER_EXTENSION = 16;
/** Maximum serialized size, in UTF-8 bytes, of a submitted manifest. */
export const MAX_MANIFEST_BYTES = 16 * 1024;
/**
 * Ring-buffer cap on the in-memory audit log. Rejections consume no live slot
 * (they never touch `live`), so a model submitting well-shaped-but-invalid
 * manifests could otherwise append events unbounded within a session. Keep the
 * most recent N so the registry is self-bounding independent of the caller's
 * per-turn loop cap.
 */
export const MAX_AUDIT_LOG_EVENTS = 1000;

// ── Public shapes ────────────────────────────────────────────────────────────

/** Who submitted a contribution. Recorded on every audit event. */
export type ExtensionOrigin = "model" | "operator";

/**
 * The COMPLETE contribution surface. Two fields, both optional-shaped only in
 * the sense that `guards` may be omitted; there is no third thing to send.
 * Unknown extra keys on this object are ignored, never interpreted.
 */
export interface ExtensionSubmission {
  /** Raw, untrusted manifest. Validated by `validatePluginManifest`. */
  readonly manifest: unknown;
  /** Deny-only guards. Cannot express "allow"; see the module header. */
  readonly guards?: readonly ToolGuard[];
  /** Defaults to "model". Audit metadata only — it grants nothing. */
  readonly origin?: ExtensionOrigin;
}

/** The gate flags `gateFlagsFor` produces, carried alongside each tool. */
export interface ExtensionGateFlags {
  readonly networkCapable: boolean;
  readonly localScope: boolean;
  readonly readOnly: boolean;
}

/** A live contributed tool: what it is, who contributed it, how it is gated. */
export interface RegisteredExtensionTool {
  readonly registrationId: string;
  readonly pluginId: string;
  readonly name: string;
  readonly description: string;
  readonly parameters: Record<string, unknown>;
  readonly required?: readonly string[];
  readonly capabilities: readonly PluginCapability[];
  readonly gateFlags: ExtensionGateFlags;
}

/** Per-tool audit detail, so the console can show declared capabilities. */
export interface ExtensionToolAudit {
  readonly name: string;
  readonly capabilities: readonly PluginCapability[];
  readonly gateFlags: ExtensionGateFlags;
}

/**
 * The auditable record of one live registration. A silent extension is
 * unacceptable: everything the operator needs to answer "what did the model add
 * to its own session, when, and with what authority" is here.
 */
export interface SelfExtensionRecord {
  readonly registrationId: string;
  readonly pluginId: string;
  readonly pluginName: string;
  readonly version: string;
  readonly origin: ExtensionOrigin;
  /** Epoch milliseconds. */
  readonly registeredAt: number;
  /** Epoch milliseconds, set once the disposer runs. */
  readonly revokedAt?: number;
  readonly tools: readonly ExtensionToolAudit[];
  readonly guardCount: number;
  readonly manifestBytes: number;
}

/**
 * An auditable event. EVERY registration attempt produces one — including
 * rejections, which are the interesting ones when a prompt-injected model is
 * probing the limits.
 */
export interface SelfExtensionEvent {
  readonly kind: "registered" | "rejected" | "revoked";
  /** Epoch milliseconds. */
  readonly at: number;
  readonly registrationId: string;
  readonly origin: ExtensionOrigin;
  /** Null when the manifest was too malformed to name itself. */
  readonly pluginId: string | null;
  readonly pluginName: string | null;
  readonly version: string | null;
  readonly tools: readonly ExtensionToolAudit[];
  readonly guardCount: number;
  readonly manifestBytes: number;
  /** Present (non-empty) only on `kind: "rejected"`. */
  readonly errors?: readonly string[];
}

/** Revokes one registration. Idempotent; returns true only on the first call. */
export type ExtensionDisposer = () => boolean;

export type RegistrationResult =
  | { readonly ok: true; readonly record: SelfExtensionRecord; readonly dispose: ExtensionDisposer }
  | { readonly ok: false; readonly errors: readonly string[] };

export interface SelfExtensionRegistryOptions {
  /**
   * Mirrors the operator setting. FALSE unless explicitly passed true — the
   * registry is inert by default, and there is intentionally no setter, so
   * nothing reachable from a tool call can flip it mid-session.
   */
  readonly enabled?: boolean;
  /**
   * Built-in tool names a contribution may not shadow: the keys of
   * `TOOL_DISPATCH` ∪ `NETWORK_CAPABLE_TOOLS` ∪ `READ_ONLY_TOOLS` ∪
   * `LOCAL_SCOPE_TOOLS`. Supplied by the caller so this module stays free of a
   * dependency on the tool registry.
   */
  readonly reservedToolNames?: readonly string[];
  /**
   * The existing guard floor (normally `BUILTIN_GUARDS`). Captured and frozen;
   * unreachable from the public API, and always evaluated first.
   */
  readonly baseGuards?: readonly ToolGuard[];
  /** Injectable clock (epoch ms) so audit timestamps are testable. */
  readonly now?: () => number;
  /** Operator-side observer for the audit stream. Not a plugin seam. */
  readonly onEvent?: (event: SelfExtensionEvent) => void;
  readonly maxExtensions?: number;
  readonly maxToolsPerExtension?: number;
  readonly maxToolsPerSession?: number;
  readonly maxGuardsPerExtension?: number;
  readonly maxManifestBytes?: number;
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/** UTF-8 byte length without allocating an encoded copy. */
function utf8ByteLength(s: string): number {
  let bytes = 0;
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code < 0x80) bytes += 1;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && i + 1 < s.length) {
      const next = s.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        bytes += 4;
        i++;
        continue;
      }
      bytes += 3;
    } else bytes += 3;
  }
  return bytes;
}

/**
 * Measure a submitted manifest. Returns `null` when it cannot be serialized at
 * all (circular, a throwing `toJSON`, a BigInt) — which is itself a rejection:
 * an unmeasurable manifest is an unbounded manifest.
 */
function measureManifest(raw: unknown): number | null {
  let json: string;
  try {
    json = JSON.stringify(raw) ?? "";
  } catch {
    return null;
  }
  return utf8ByteLength(json);
}

/**
 * Wrap a contributed guard so it can only ever narrow.
 *
 * - The guard sees a FROZEN SHALLOW COPY of the context, never the caller's
 *   object, so it cannot mutate facts that later guards (or the console's own
 *   gates) rely on. A write attempt throws under strict mode, and a throwing
 *   guard is a DENIAL in `evaluateGuards` — the attempt narrows.
 * - Any non-string return becomes `null` (abstention); a string passes through
 *   for `evaluateGuards` to sanitize and record as a denial.
 * - The wrapper does not catch: `evaluateGuards` already converts a throw into
 *   a denial, and swallowing it here would be the one transformation that could
 *   widen (throw → abstain).
 */
function wrapContributedGuard(guard: ToolGuard, pluginId: string, index: number): ToolGuard {
  const label = sanitizeReason(`${pluginId}#${index}`);
  const wrapped: ToolGuard = (ctx: GuardContext) => {
    if (typeof guard !== "function") {
      // Fail closed, matching `evaluateGuards`: junk is a denial, not an abstention.
      return `contributed guard ${label} is not callable`;
    }
    const frozen: GuardContext = Object.freeze({ ...ctx });
    const result = guard(frozen);
    return typeof result === "string" ? result : null;
  };
  // A stable, sanitized name so denial reasons attribute back to the extension.
  Object.defineProperty(wrapped, "name", { value: `contributed:${label}`, configurable: true });
  return wrapped;
}

interface LiveRegistration {
  record: SelfExtensionRecord;
  readonly tools: readonly RegisteredExtensionTool[];
  readonly guards: readonly ToolGuard[];
  revoked: boolean;
}

// ── The registry ─────────────────────────────────────────────────────────────

/**
 * Session-scoped registry of model-authored extensions.
 *
 * SESSION-SCOPED AND REVOCABLE: all state lives in this instance. Nothing is
 * written to disk, nothing is read from disk, and a new session constructs a new
 * (empty) registry. `register` returns a disposer that fully revokes the
 * contribution; after disposal the guard set and tool set are exactly what they
 * were before it.
 *
 * PUBLIC SURFACE (this list is the invariant — note what is absent):
 *   register(submission)   → additive only
 *   guards()               → snapshot: base guards first, then contributed
 *   evaluate(ctx)          → evaluateGuards(this.guards(), ctx)
 *   tools() / tool(name) / gateFlagsForTool(name)
 *   records() / events() / isEnabled() / limits()
 *
 * There is no removeGuard, no replaceGuard, no setGuards, no reorder, no
 * setGateFlags, no unregisterByName, no setEnabled, and no accessor that hands
 * out a mutable reference to internal state (every getter returns a frozen
 * copy).
 */
export class SelfExtensionRegistry {
  private readonly enabled: boolean;
  private readonly reserved: readonly string[];
  private readonly baseGuards: readonly ToolGuard[];
  private readonly clock: () => number;
  private readonly onEvent?: (event: SelfExtensionEvent) => void;

  private readonly maxExtensions: number;
  private readonly maxToolsPerExtension: number;
  private readonly maxToolsPerSession: number;
  private readonly maxGuardsPerExtension: number;
  private readonly maxManifestBytes: number;

  private readonly live: LiveRegistration[] = [];
  private readonly auditLog: SelfExtensionEvent[] = [];
  private seq = 0;

  constructor(options: SelfExtensionRegistryOptions = {}) {
    // Fail closed: only an explicit `true` enables. `undefined` (an untyped
    // caller that forgot the flag) leaves the registry inert.
    this.enabled = options.enabled === true;
    this.reserved = Object.freeze([...(options.reservedToolNames ?? [])]);
    this.baseGuards = Object.freeze([...(options.baseGuards ?? [])]);
    this.clock = typeof options.now === "function" ? options.now : Date.now;
    this.onEvent = typeof options.onEvent === "function" ? options.onEvent : undefined;

    this.maxExtensions = boundedLimit(options.maxExtensions, MAX_EXTENSIONS_PER_SESSION);
    this.maxToolsPerExtension = boundedLimit(options.maxToolsPerExtension, MAX_TOOLS_PER_EXTENSION);
    this.maxToolsPerSession = boundedLimit(options.maxToolsPerSession, MAX_TOOLS_PER_SESSION);
    this.maxGuardsPerExtension = boundedLimit(options.maxGuardsPerExtension, MAX_GUARDS_PER_EXTENSION);
    this.maxManifestBytes = boundedLimit(options.maxManifestBytes, MAX_MANIFEST_BYTES);
  }

  /** Whether self-extension is enabled for this session. Read-only by design. */
  isEnabled(): boolean {
    return this.enabled;
  }

  /** The effective bounds, for display and for tests. */
  limits(): Readonly<{
    maxExtensions: number;
    maxToolsPerExtension: number;
    maxToolsPerSession: number;
    maxGuardsPerExtension: number;
    maxManifestBytes: number;
  }> {
    return Object.freeze({
      maxExtensions: this.maxExtensions,
      maxToolsPerExtension: this.maxToolsPerExtension,
      maxToolsPerSession: this.maxToolsPerSession,
      maxGuardsPerExtension: this.maxGuardsPerExtension,
      maxManifestBytes: this.maxManifestBytes,
    });
  }

  /**
   * Validate and register one contribution. Additive only: on success the
   * session gains the contributed tools and guards and NOTHING else changes —
   * no existing guard, gate entry or built-in tool is touched.
   *
   * Every outcome, success or rejection, is recorded as an audit event.
   */
  register(submission: ExtensionSubmission): RegistrationResult {
    const origin: ExtensionOrigin = submission?.origin === "operator" ? "operator" : "model";
    const registrationId = `ext-${++this.seq}`;
    const errors: string[] = [];

    if (!isPlainObject(submission)) {
      return this.reject(registrationId, origin, 0, 0, ["submission must be an object"]);
    }

    // ── enablement (checked before anything else does work) ──
    if (!this.enabled) {
      return this.reject(registrationId, origin, 0, 0, [
        "self-extension is disabled; enable `allowModelSelfExtension` to permit model-authored tools",
      ]);
    }

    // ── bound: live extensions ──
    if (this.liveCount() >= this.maxExtensions) {
      return this.reject(registrationId, origin, 0, 0, [
        `extension limit reached: at most ${this.maxExtensions} extensions may be registered per session`,
      ]);
    }

    // ── bound: manifest size (before validation, so a huge blob is cheap to refuse) ──
    const manifestBytes = measureManifest(submission.manifest);
    if (manifestBytes === null) {
      return this.reject(registrationId, origin, 0, 0, [
        "manifest could not be serialized (circular or non-JSON value) — refusing an unmeasurable submission",
      ]);
    }
    if (manifestBytes > this.maxManifestBytes) {
      return this.reject(registrationId, origin, 0, manifestBytes, [
        `manifest is ${manifestBytes} bytes; the limit is ${this.maxManifestBytes}`,
      ]);
    }

    // ── bound: contributed guards ──
    const rawGuards = submission.guards;
    if (rawGuards !== undefined && !Array.isArray(rawGuards)) {
      errors.push("`guards`, when present, must be an array of ToolGuard functions");
    }
    const guardList: readonly ToolGuard[] = Array.isArray(rawGuards) ? rawGuards : [];
    if (guardList.length > this.maxGuardsPerExtension) {
      errors.push(
        `guard limit reached: at most ${this.maxGuardsPerExtension} guards may be contributed per extension`,
      );
    }

    // ── the ONE validator: capabilities mandatory, fail-closed, no shadowing ──
    // Reserved names are the caller's built-ins PLUS every currently live
    // contributed name, so a second extension cannot shadow the first either.
    const reserved = [...this.reserved, ...this.liveToolNames()];
    const validation = validatePluginManifest(submission.manifest, { reservedToolNames: reserved });
    if (!validation.ok) {
      errors.push(...validation.errors);
      return this.reject(registrationId, origin, guardList.length, manifestBytes, errors);
    }
    const manifest: PluginManifest = validation.manifest;

    // ── bounds that need the validated manifest ──
    if (manifest.tools.length > this.maxToolsPerExtension) {
      errors.push(
        `tool limit reached: at most ${this.maxToolsPerExtension} tools may be contributed per extension`,
      );
    }
    if (this.liveToolNames().length + manifest.tools.length > this.maxToolsPerSession) {
      errors.push(
        `session tool limit reached: at most ${this.maxToolsPerSession} contributed tools may be live per session`,
      );
    }
    // A duplicate plugin id would make the audit trail ambiguous.
    if (this.live.some((r) => !r.revoked && r.record.pluginId === manifest.id)) {
      errors.push(`plugin id "${manifest.id}" is already registered in this session`);
    }

    if (errors.length > 0) {
      return this.reject(registrationId, origin, guardList.length, manifestBytes, errors);
    }

    // ── build the live registration ──
    const tools: RegisteredExtensionTool[] = manifest.tools.map((t: PluginToolManifest) =>
      Object.freeze({
        registrationId,
        pluginId: manifest.id,
        name: t.name,
        description: t.description,
        parameters: Object.freeze({ ...t.parameters }),
        ...(t.required ? { required: Object.freeze([...t.required]) } : {}),
        capabilities: Object.freeze([...t.capabilities]),
        // The single capability → gate translation. Not re-derived here.
        gateFlags: Object.freeze(gateFlagsFor(t)),
      }),
    );

    const wrapped = Object.freeze(
      guardList.map((g, i) => wrapContributedGuard(g, manifest.id, i)),
    );

    const at = this.nowMs();
    const audit: readonly ExtensionToolAudit[] = Object.freeze(
      tools.map((t) =>
        Object.freeze({ name: t.name, capabilities: t.capabilities, gateFlags: t.gateFlags }),
      ),
    );

    const record: SelfExtensionRecord = Object.freeze({
      registrationId,
      pluginId: manifest.id,
      pluginName: manifest.name,
      version: manifest.version,
      origin,
      registeredAt: at,
      tools: audit,
      guardCount: wrapped.length,
      manifestBytes,
    });

    const entry: LiveRegistration = {
      record,
      tools: Object.freeze(tools),
      guards: wrapped,
      revoked: false,
    };
    this.live.push(entry);

    this.emit({
      kind: "registered",
      at,
      registrationId,
      origin,
      pluginId: manifest.id,
      pluginName: manifest.name,
      version: manifest.version,
      tools: audit,
      guardCount: wrapped.length,
      manifestBytes,
    });

    const dispose: ExtensionDisposer = () => this.revoke(entry);
    return { ok: true, record, dispose };
  }

  /**
   * The full guard set to evaluate: the base floor FIRST, then contributed
   * guards in registration order. Returns a fresh frozen array, so a caller
   * cannot mutate the registry through it, and iteration is unaffected by a
   * registration that happens mid-evaluation.
   *
   * Order is presentational only — `evaluateGuards` runs every guard and
   * `allowed` is "nobody denied", which is order-independent.
   */
  guards(): readonly ToolGuard[] {
    const out: ToolGuard[] = [...this.baseGuards];
    for (const reg of this.live) {
      if (reg.revoked) continue;
      out.push(...reg.guards);
    }
    return Object.freeze(out);
  }

  /** Evaluate the base floor plus every live contributed guard. */
  evaluate(ctx: GuardContext): GuardVerdict {
    return evaluateGuards(this.guards(), ctx);
  }

  /** Every live contributed tool, with its gate flags. */
  tools(): readonly RegisteredExtensionTool[] {
    const out: RegisteredExtensionTool[] = [];
    for (const reg of this.live) {
      if (reg.revoked) continue;
      out.push(...reg.tools);
    }
    return Object.freeze(out);
  }

  /** Look up one live contributed tool by name. */
  tool(name: string): RegisteredExtensionTool | undefined {
    return this.tools().find((t) => t.name === name);
  }

  /**
   * Gate flags for a live contributed tool, or `undefined` when the name is not
   * a contributed tool. `undefined` means "not ours" — the caller must not read
   * it as "ungated"; built-ins keep their own gate-map entries.
   */
  gateFlagsForTool(name: string): ExtensionGateFlags | undefined {
    return this.tool(name)?.gateFlags;
  }

  /** Audit records. `all: true` includes revoked registrations. */
  records(opts?: { all?: boolean }): readonly SelfExtensionRecord[] {
    const all = opts?.all === true;
    return Object.freeze(this.live.filter((r) => all || !r.revoked).map((r) => r.record));
  }

  /** The full audit event stream, oldest first. Includes rejections. */
  events(): readonly SelfExtensionEvent[] {
    return Object.freeze([...this.auditLog]);
  }

  // ── internals ──

  private liveCount(): number {
    return this.live.reduce((n, r) => n + (r.revoked ? 0 : 1), 0);
  }

  private liveToolNames(): string[] {
    const names: string[] = [];
    for (const reg of this.live) {
      if (reg.revoked) continue;
      for (const t of reg.tools) names.push(t.name);
    }
    return names;
  }

  private nowMs(): number {
    const t = this.clock();
    return typeof t === "number" && Number.isFinite(t) ? t : 0;
  }

  /**
   * Revoke one registration: drop its tools and its guards, nothing else. It
   * cannot reach the base guards or another registration's contributions — the
   * entry closed over is the only thing it touches.
   */
  private revoke(entry: LiveRegistration): boolean {
    if (entry.revoked) return false;
    entry.revoked = true;
    const at = this.nowMs();
    entry.record = Object.freeze({ ...entry.record, revokedAt: at });
    this.emit({
      kind: "revoked",
      at,
      registrationId: entry.record.registrationId,
      origin: entry.record.origin,
      pluginId: entry.record.pluginId,
      pluginName: entry.record.pluginName,
      version: entry.record.version,
      tools: entry.record.tools,
      guardCount: entry.record.guardCount,
      manifestBytes: entry.record.manifestBytes,
    });
    return true;
  }

  private reject(
    registrationId: string,
    origin: ExtensionOrigin,
    guardCount: number,
    manifestBytes: number,
    errors: readonly string[],
  ): RegistrationResult {
    const clean = Object.freeze(errors.map((e) => sanitizeReason(String(e))));
    this.emit({
      kind: "rejected",
      at: this.nowMs(),
      registrationId,
      origin,
      pluginId: null,
      pluginName: null,
      version: null,
      tools: Object.freeze([]),
      guardCount,
      manifestBytes,
      errors: clean,
    });
    return { ok: false, errors: clean };
  }

  /** Record an event and notify the operator-side observer, fail-soft. */
  private emit(event: SelfExtensionEvent): void {
    const frozen = Object.freeze(event);
    this.auditLog.push(frozen);
    if (this.auditLog.length > MAX_AUDIT_LOG_EVENTS) {
      this.auditLog.splice(0, this.auditLog.length - MAX_AUDIT_LOG_EVENTS);
    }
    if (!this.onEvent) return;
    try {
      this.onEvent(frozen);
    } catch {
      // A broken observer must never abort a registration decision or crash the
      // session; the event is already in the in-memory audit log regardless.
    }
  }
}

function boundedLimit(value: number | undefined, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const n = Math.floor(value);
  return n < 0 ? 0 : n;
}

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

// ── The operator setting (default OFF) ───────────────────────────────────────

/**
 * Drop-in for the `DEFS` table in `packages/cli/src/tui/settings.ts`. Shaped to
 * that module's `SettingDef` (key, label, description, kind, default, group) but
 * declared here so this module owns the wording of the risk, and so `settings.ts`
 * is not edited by this change.
 *
 * DEFAULT IS FALSE and that is load-bearing: an operator who never opens the
 * settings panel never has a model-authored tool in their session.
 */
export const SELF_EXTENSION_SETTING_DEF: {
  readonly key: string;
  readonly label: string;
  readonly description: string;
  readonly kind: "boolean";
  readonly default: boolean;
  readonly group: string;
} = Object.freeze({
  key: "allowModelSelfExtension",
  label: "Model self-extension",
  description:
    "Enabling this lets the model add tools to its own session, and a prompt-injected model can therefore author tools you did not write.",
  kind: "boolean",
  default: false,
  group: "Security",
});
