/**
 * Structured diagnostics channel for `@0sec/core`.
 *
 * ## Why this exists
 *
 * Library code inside core legitimately needs to tell the operator things:
 * "your plan quota is exhausted", "the retry budget is spent", "the fallback
 * chain entry was malformed". Historically it said them with
 * `process.stderr.write` / `console.error`. That works for a plain CLI run and
 * is actively destructive for the interactive console, which is a full-screen
 * OpenTUI app: the renderer owns every cell on screen and repaints
 * differentially, so any write it did not originate scrolls or overprints the
 * framebuffer and desynchronizes the renderer's model of the screen. The
 * visible result is ghost header rows, characters from one widget appearing
 * inside another, and a garbled status line.
 *
 * `packages/cli/src/tui/output-guard.ts` intercepts stray writes while the TUI
 * is mounted, but that is containment, not a cure: it cannot give library code
 * a *code* to react to, it cannot carry structured fields, and every new
 * `console.warn` anywhere in core or a dependency re-creates the hazard until
 * the guard happens to catch it. This module is the cure — one typed,
 * pluggable, fail-soft channel that core writes to instead of the terminal.
 *
 * It is deliberately shaped like the existing `EventBus` (`../events/bus.ts`):
 * pluggable sinks, fan-out, exceptions swallowed. It is a *separate* channel
 * rather than another `osecEvent` variant because the two have different
 * audiences and different failure semantics — bus events are scan telemetry
 * destined for the cloud relay and are load-bearing for the dashboard, while
 * diagnostics are operator-facing prose about the health of the run that no
 * consumer is required to persist.
 *
 * ## Delivery model
 *
 *     diag.warn(code, message, fields?)
 *            |
 *            +- sanitize (ANSI stripped, control chars stripped, length bounded)
 *            |
 *            +- claimed? --yes--> the claiming sink (e.g. the TUI)  [stderr silent]
 *            |                    + any additive observers
 *            |
 *            +---- no ---> built-in stderr sink + any additive observers
 *
 * ## The default-delivery decision: **stderr, not silent buffering**
 *
 * When nothing has claimed the channel, diagnostics go to `process.stderr`.
 *
 * The alternative — buffer silently until someone subscribes — optimizes for
 * the one consumer that is already able to defend itself and penalizes every
 * consumer that is not. The overwhelming majority of 0sec invocations are
 * *not* the TUI: `0sec scan` in a terminal, a CI job, the cloud worker, a
 * shell pipeline redirecting stderr to a log. For all of those, a diagnostic
 * that is buffered and never drained is a diagnostic that is *lost*. Losing
 * "plan quota exhausted" means the operator watches a scan produce nothing and
 * has no idea why. That is a strictly worse bug than a corrupted frame.
 *
 * Meanwhile the TUI is a known, enumerable, code-owning consumer. It already
 * installs an output guard at mount; claiming the diagnostics channel in the
 * same place is one more line in code we control. "Safe by default" here means
 * *the process that owns the terminal opts out of stderr*, not *everybody
 * silently loses data so that one consumer does not have to ask*.
 *
 * A third property settles it: stderr-by-default makes the migration of the
 * ~68 existing raw writes a pure refactor. Every migrated call site keeps its
 * observable behaviour for non-TUI users, which is what makes it safe to
 * migrate them incrementally instead of in one risky sweep.
 *
 * The bounded ring buffer is still kept (see `recentDiagnostics`) so a late
 * claimer can replay what it missed — but it is a *replay* buffer, not the
 * primary delivery path.
 *
 * ## Guarantees
 *
 *   1. **Never throws into a scan.** Sanitization, sink dispatch, and the
 *      stderr write are each wrapped; the public methods have no throwing path
 *      at all. A sink that throws is isolated (and, if it is the claiming
 *      sink, its failure falls back to stderr so the message is not lost).
 *   2. **Inert text.** Messages and string fields have ANSI escape sequences
 *      and every C0/C1 control character removed, whitespace collapsed to
 *      single spaces, and length bounded. Nothing crossing into a renderer can
 *      move a cursor, set a colour, or open a new row.
 *   3. **Structured, not interpolated.** `fields` is carried as data all the
 *      way to the sink. It is never spliced into `message`. Only the built-in
 *      stderr renderer flattens it, and only at the very last step.
 *   4. **Zero dependencies.**
 *
 * ## Env controls
 *
 *   `0SEC_DIAG_LEVEL` — `off` | `error` | `warn` | `info` (default `info`).
 *   Filters at the source, before any sink sees the event. `off` silences the
 *   channel entirely.
 */

// ── Types ───────────────────────────────────────────────────────────────────

/** Severity of a diagnostic. Ordered `info` < `warn` < `error`. */
export type DiagLevel = "info" | "warn" | "error";

/**
 * A value carried in a diagnostic's structured `fields`. Inputs of any type
 * are accepted by the emit helpers and coerced to one of these before
 * delivery, so a sink never has to defend against a surprise shape.
 */
export type DiagFieldValue = string | number | boolean | null;

/** A sanitized, ready-to-render diagnostic. This is what sinks receive. */
export interface DiagnosticEvent {
  level: DiagLevel;
  /**
   * Stable machine-readable slug — `quota_exhausted`, `retry_budget_spent`.
   * Consumers switch on this instead of string-matching prose, so the human
   * wording of `message` can change without breaking them.
   */
  code: string;
  /** One line of human-readable prose. No ANSI, no control chars, bounded. */
  message: string;
  /** Structured detail. Never interpolated into `message`. */
  fields: Readonly<Record<string, DiagFieldValue>>;
  /** Epoch milliseconds at emit time. */
  ts: number;
}

export interface DiagnosticSink {
  /**
   * Called once per diagnostic. Exceptions are caught by the channel; a sink
   * SHOULD still avoid throwing, because a throwing *claiming* sink causes the
   * event to fall back to stderr — which, in the TUI, is the corruption this
   * whole module exists to prevent.
   */
  emit(event: DiagnosticEvent): void;
}

export interface ClaimOptions {
  /**
   * Replay the buffered recent diagnostics into the claiming sink before live
   * delivery begins. Lets a TUI that mounts after core has already warned
   * about something render the backlog instead of the operator only seeing it
   * in scrollback the renderer is about to paint over. Default `false`.
   */
  replay?: boolean;
}

// ── Bounds ──────────────────────────────────────────────────────────────────

/** Longest message delivered to a sink. Longer messages are truncated. */
export const MAX_MESSAGE_LENGTH = 512;
/** Longest string field value delivered to a sink. */
export const MAX_FIELD_VALUE_LENGTH = 256;
/** Longest code slug. */
export const MAX_CODE_LENGTH = 64;
/** Most fields carried on a single diagnostic. Extras are dropped. */
export const MAX_FIELDS = 32;
/** Diagnostics retained for replay. Oldest are evicted first. */
export const MAX_BUFFERED = 200;

/** Slug used when a caller passes a code that sanitizes to nothing. */
const UNKNOWN_CODE = "unknown";

// ── Sanitization ────────────────────────────────────────────────────────────

/**
 * CSI / OSC / two-character escape sequences. Matches the well-known
 * `ansi-regex` pattern; inlined rather than depended upon (zero new deps).
 */
const ANSI_PATTERN =
  /[\u001B\u009B][[\]()#;?]*(?:(?:(?:[a-zA-Z\d]*(?:;[-a-zA-Z\d/#&.:=?%@~_]*)*)?\u0007)|(?:(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~]))/g;

/**
 * Every C0 control character (including CR, LF and TAB), DEL, and the C1
 * range. Anything left after the ANSI pass that could still move a cursor,
 * ring a bell, or open a new row in a renderer.
 */
const CONTROL_PATTERN = /[\u0000-\u001F\u007F-\u009F]/g;

/** Unicode line/paragraph separators — real line breaks to a terminal. */
const UNICODE_BREAK_PATTERN = /[\u2028\u2029]/g;

/**
 * Reduce arbitrary text to a single inert line.
 *
 * ANSI is stripped first: its payload bytes are printable, so removing control
 * characters first would leave `[31m` behind as literal visible text.
 * Remaining control characters and Unicode breaks become spaces rather than
 * being deleted, so `"a\nb"` reads as `"a b"` and not `"ab"`.
 */
function sanitizeText(input: string, maxLength: number): string {
  let out = input.replace(ANSI_PATTERN, "");
  out = out.replace(CONTROL_PATTERN, " ");
  out = out.replace(UNICODE_BREAK_PATTERN, " ");
  out = out.replace(/\s+/g, " ").trim();
  if (out.length > maxLength) {
    out = out.slice(0, Math.max(0, maxLength - 1)).trimEnd() + "…";
  }
  return out;
}

/**
 * Normalize a code to a stable slug: lowercase, `[a-z0-9_.-]` only, other runs
 * collapsed to `_`. Never empty — an unusable code degrades to `"unknown"`
 * rather than throwing, because a diagnostic with a bad slug is still worth
 * delivering.
 */
function sanitizeCode(input: unknown): string {
  const raw = typeof input === "string" ? input : String(input ?? "");
  const slug = raw
    .toLowerCase()
    .replace(ANSI_PATTERN, "")
    .replace(/[^a-z0-9_.-]+/g, "_")
    .replace(/^[_.-]+|[_.-]+$/g, "")
    .slice(0, MAX_CODE_LENGTH);
  return slug.length > 0 ? slug : UNKNOWN_CODE;
}

/** Coerce one arbitrary field value into a `DiagFieldValue`, or drop it. */
function sanitizeFieldValue(value: unknown): DiagFieldValue | undefined {
  if (value === null) return null;
  switch (typeof value) {
    case "undefined":
      return undefined;
    case "boolean":
      return value;
    case "number":
      // Non-finite numbers survive as their string form. JSON would have
      // turned them into `null`, which reads as "absent" and is a lie.
      return Number.isFinite(value) ? value : String(value);
    case "bigint":
      return `${value}n`;
    case "string":
      return sanitizeText(value, MAX_FIELD_VALUE_LENGTH);
    case "function":
      return "[function]";
    case "symbol":
      return sanitizeText(String(value), MAX_FIELD_VALUE_LENGTH);
    default:
      break;
  }
  if (value instanceof Error) {
    return sanitizeText(
      `${value.name}: ${value.message}`,
      MAX_FIELD_VALUE_LENGTH,
    );
  }
  if (value instanceof Date) {
    // A structured consumer wants a comparable instant, not a locale string.
    const t = value.getTime();
    return Number.isFinite(t) ? value.toISOString() : "[invalid date]";
  }
  try {
    const json = JSON.stringify(value);
    return json === undefined
      ? "[unserializable]"
      : sanitizeText(json, MAX_FIELD_VALUE_LENGTH);
  } catch {
    // Circular structure, or a throwing `toJSON`.
    return "[unserializable]";
  }
}

const EMPTY_FIELDS: Readonly<Record<string, DiagFieldValue>> = Object.freeze({});

/**
 * Sanitize keys and values, bound the count, and freeze. Keys go through the
 * same slug normalizer as codes so a field name can never smuggle an escape
 * sequence into a renderer either. First writer wins on a key collision.
 */
function sanitizeFields(
  input: Record<string, unknown> | undefined,
): Readonly<Record<string, DiagFieldValue>> {
  if (input == null || typeof input !== "object") return EMPTY_FIELDS;
  const out: Record<string, DiagFieldValue> = {};
  let count = 0;
  for (const key of Object.keys(input)) {
    if (count >= MAX_FIELDS) break;
    const safeKey = sanitizeCode(key);
    if (Object.prototype.hasOwnProperty.call(out, safeKey)) continue;
    const value = sanitizeFieldValue(input[key]);
    if (value === undefined) continue;
    out[safeKey] = value;
    count++;
  }
  return Object.freeze(out);
}

// ── Level filtering ─────────────────────────────────────────────────────────

const LEVEL_RANK: Record<DiagLevel, number> = { info: 10, warn: 20, error: 30 };
const OFF_RANK = Number.POSITIVE_INFINITY;

/**
 * Minimum rank an event must meet to be emitted. Read per-emit (these are
 * low-frequency calls) so tests and long-lived processes can change
 * `0SEC_DIAG_LEVEL` without a restart.
 */
function minimumRank(): number {
  const raw = process.env["0SEC_DIAG_LEVEL"];
  if (!raw) return LEVEL_RANK.info;
  switch (raw.trim().toLowerCase()) {
    case "off":
    case "none":
    case "silent":
      return OFF_RANK;
    case "error":
      return LEVEL_RANK.error;
    case "warn":
    case "warning":
      return LEVEL_RANK.warn;
    default:
      return LEVEL_RANK.info;
  }
}

// ── Built-in stderr sink ────────────────────────────────────────────────────

/**
 * Render one diagnostic the way core has always rendered these lines:
 * `[0sec] <message>`, with structured fields flattened into a trailing
 * `(k=v k=v)` group so nothing that used to be visible becomes invisible.
 *
 * Deliberately carries no level tag. Every call site this replaces printed
 * bare prose, and preserving that keeps the migration a pure refactor —
 * existing tests that assert on stderr substrings stay green, and operators'
 * greps and log parsers keep working. Level is available in full fidelity to
 * every structured sink; only this one legacy-shaped renderer omits it.
 */
export function formatDiagnosticLine(event: DiagnosticEvent): string {
  const keys = Object.keys(event.fields);
  if (keys.length === 0) return `[0sec] ${event.message}`;
  const rendered = keys.map((k) => `${k}=${event.fields[k]}`).join(" ");
  return `[0sec] ${event.message} (${rendered})`;
}

/**
 * The default destination. Writes one line to stderr and swallows everything —
 * a closed or EPIPE'd stderr must not take a scan down.
 */
export const stderrDiagnosticSink: DiagnosticSink = {
  emit(event) {
    try {
      process.stderr.write(formatDiagnosticLine(event) + "\n");
    } catch {
      /* stderr gone — there is nowhere left to report this */
    }
  },
};

// ── Channel ─────────────────────────────────────────────────────────────────

/** Invoke a sink, isolating any throw. Returns `false` if the sink threw. */
function tryEmit(sink: DiagnosticSink, event: DiagnosticEvent): boolean {
  try {
    sink.emit(event);
    return true;
  } catch {
    return false;
  }
}

class DiagnosticsChannel {
  /** Exclusive owner of delivery. When set, the stderr sink is bypassed. */
  private claimed: DiagnosticSink | null = null;
  /** Additive observers. Always receive, claimed or not. */
  private observers: DiagnosticSink[] = [];
  /** Bounded replay ring. */
  private buffer: DiagnosticEvent[] = [];
  private dropped = 0;

  // ── Emit ────────────────────────────────────────────────────────────────

  info(code: string, message: string, fields?: Record<string, unknown>): void {
    this.emit("info", code, message, fields);
  }

  warn(code: string, message: string, fields?: Record<string, unknown>): void {
    this.emit("warn", code, message, fields);
  }

  error(code: string, message: string, fields?: Record<string, unknown>): void {
    this.emit("error", code, message, fields);
  }

  /**
   * Build, sanitize and deliver one diagnostic.
   *
   * The entire body sits inside a `try` with an empty `catch`: this is called
   * from retry loops, stream readers and `catch` blocks deep inside a scan, and
   * no diagnostic is important enough to justify aborting the work it is
   * describing.
   */
  emit(
    level: DiagLevel,
    code: string,
    message: string,
    fields?: Record<string, unknown>,
  ): void {
    try {
      if (LEVEL_RANK[level] < minimumRank()) return;
      const event: DiagnosticEvent = Object.freeze({
        level,
        code: sanitizeCode(code),
        message: sanitizeText(
          typeof message === "string" ? message : String(message ?? ""),
          MAX_MESSAGE_LENGTH,
        ),
        fields: sanitizeFields(fields),
        ts: Date.now(),
      });

      this.remember(event);
      this.deliver(event);
    } catch {
      /* a diagnostic must never become the reason a scan failed */
    }
  }

  private remember(event: DiagnosticEvent): void {
    this.buffer.push(event);
    while (this.buffer.length > MAX_BUFFERED) {
      this.buffer.shift();
      this.dropped++;
    }
  }

  private deliver(event: DiagnosticEvent): void {
    const claimed = this.claimed;
    if (claimed) {
      // A claiming sink that throws would otherwise swallow the diagnostic
      // entirely, so fall back to stderr. In the TUI that risks one corrupted
      // frame — an acceptable trade against losing "quota exhausted" outright,
      // and it only happens when the TUI sink is already broken.
      if (!tryEmit(claimed, event)) stderrDiagnosticSink.emit(event);
    } else {
      stderrDiagnosticSink.emit(event);
    }
    // Snapshot so an unsubscribe during iteration cannot skip a sink.
    for (const observer of this.observers.slice()) tryEmit(observer, event);
  }

  // ── Subscription ────────────────────────────────────────────────────────

  /**
   * Take exclusive ownership of delivery. While claimed, the built-in stderr
   * sink is bypassed — this is how the TUI stops core from writing to the
   * terminal it is painting.
   *
   * Claims nest: a second claim supersedes the first, and releasing it restores
   * the previous owner. Release is idempotent and only un-claims while this
   * claim is still the live one, so an out-of-order teardown cannot resurrect a
   * dead sink.
   */
  claim(sink: DiagnosticSink, options: ClaimOptions = {}): () => void {
    const previous = this.claimed;
    this.claimed = sink;
    if (options.replay) {
      for (const event of this.buffer.slice()) tryEmit(sink, event);
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      if (this.claimed === sink) this.claimed = previous;
    };
  }

  /**
   * Add an observer that receives every diagnostic regardless of who holds the
   * claim. For tracing exporters, test spies, and audit logs — anything that
   * wants a copy but must not silence stderr.
   */
  subscribe(sink: DiagnosticSink): () => void {
    this.observers.push(sink);
    return () => {
      const idx = this.observers.indexOf(sink);
      if (idx >= 0) this.observers.splice(idx, 1);
    };
  }

  /** True when some sink holds the exclusive claim (stderr is bypassed). */
  get isClaimed(): boolean {
    return this.claimed !== null;
  }

  /** Number of additive observers. */
  get observerCount(): number {
    return this.observers.length;
  }

  /** Recent diagnostics, oldest first. Bounded by `MAX_BUFFERED`. */
  recent(): readonly DiagnosticEvent[] {
    return this.buffer.slice();
  }

  /** How many buffered diagnostics were evicted to stay within the bound. */
  droppedCount(): number {
    return this.dropped;
  }

  /** Test-only: drop all sinks, the replay buffer, and the drop counter. */
  resetForTests(): void {
    this.claimed = null;
    this.observers = [];
    this.buffer = [];
    this.dropped = 0;
  }
}

// ── Public singleton ────────────────────────────────────────────────────────

/**
 * The process-wide diagnostics channel.
 *
 * ```ts
 * import { diag } from "../diagnostics/channel.js";
 * diag.warn("retry_budget_spent", "OpenRouter HTTP 429 — backing off", {
 *   provider: "OpenRouter", status: 429, delay_ms: 250, attempt: 3,
 * });
 * ```
 */
export const diag = new DiagnosticsChannel();

/**
 * Take exclusive ownership of diagnostics delivery, silencing the built-in
 * stderr sink. Returns a release function.
 *
 * Intended caller: the TUI, alongside `installTuiOutputGuard`. The guard
 * catches writes from code that has not been migrated yet; this claim is how
 * migrated code reaches the transcript as structured lines instead:
 *
 * ```ts
 * const releaseDiag = claimDiagnostics(
 *   { emit: (e) => appendTranscriptLine({ level: e.level, code: e.code,
 *                                         text: e.message, fields: e.fields }) },
 *   { replay: true },
 * );
 * // on unmount: releaseDiag();
 * ```
 */
export function claimDiagnostics(
  sink: DiagnosticSink,
  options?: ClaimOptions,
): () => void {
  return diag.claim(sink, options);
}

/** Observe every diagnostic without silencing stderr. Returns unsubscribe. */
export function subscribeDiagnostics(sink: DiagnosticSink): () => void {
  return diag.subscribe(sink);
}

/** True when a sink holds the exclusive claim, i.e. stderr is bypassed. */
export function isDiagnosticsClaimed(): boolean {
  return diag.isClaimed;
}

/** Bounded replay buffer of recent diagnostics, oldest first. */
export function recentDiagnostics(): readonly DiagnosticEvent[] {
  return diag.recent();
}

/** Test-only: restore the channel to its pristine, unclaimed state. */
export function _resetDiagnosticsForTests(): void {
  diag.resetForTests();
}
