/**
 * herdr pane-state integration (protocol 19).
 *
 * `herdr` (https://herdr.dev) is a terminal workspace manager for AI coding
 * agents. When 0sec runs inside a herdr pane, herdr wants to know whether the
 * agent in that pane is `idle | working | blocked` — it drives the sidebar,
 * the completion sounds/toasts and `herdr agent wait` off exactly that signal.
 * Without a native reporter herdr falls back to screen-scraping our TUI and
 * essentially always shows `unknown`.
 *
 * This module implements a `HerdrEventSink` — a normal `EventSink` (see
 * `../events/bus.ts`) that translates the bus's event vocabulary into herdr
 * agent-state reports. It deliberately mirrors the shape, naming and
 * registration style of `CloudEventSink` in `bus.ts`: a passive sink object
 * plus an env-gated factory, OFF unless the environment says otherwise.
 *
 * ── Wire protocol ────────────────────────────────────────────────────────
 * Transport is a Unix domain socket at `$HERDR_SOCKET_PATH` (a named pipe
 * `\\.\pipe\<path>` on Windows). Framing is newline-delimited JSON, one
 * request per line:
 *
 *     {"id":"…","method":"pane.report_agent","params":{…}}\n
 *
 * and the daemon answers `{"id",…,"result":{…}}` or `{"id",…,"error":{…}}`.
 * We connect per report (herdr's own bundled `pi` reference integration does
 * the same), treat the first `data` frame as "delivered", and never parse the
 * response — there is nothing actionable in it for us.
 *
 * ── Non-negotiables ──────────────────────────────────────────────────────
 *
 *  1. FAIL-SOFT, ALWAYS. This is decoration for a pane title. A missing
 *     socket, a hung daemon, a malformed response or an EPIPE must never
 *     throw into, block, or slow down a security scan. Every path here
 *     swallows. One ~500 ms attempt plus one ~1500 ms retry, then we give up
 *     on that report — no backoff loop, no unbounded queue.
 *
 *  2. NO PRINTING. 0sec runs inside an Ink TUI that owns the terminal;
 *     a stray `console.log` or `process.stderr.write` corrupts the
 *     framebuffer. There is deliberately not a single write to stdout/stderr
 *     in this file, not even on error. Failures are silent by design.
 *
 *  3. PRIVACY IS A HARD REQUIREMENT. See the block above
 *     `SAFE_TOKEN_KEYS` — the herdr socket is readable by any local process
 *     running as this user, and `tokens` / `title` render in shared chrome
 *     (and in herdr's own logs). We therefore emit COUNTS and FIXED ENUMS
 *     only. Never a finding title, target host, URL, tool argument or path.
 */

import { createConnection } from "node:net";

import type { EventSink, EventType } from "../events/bus.js";

// ── Protocol constants ──────────────────────────────────────────────────────

/** herdr's four agent states. */
export type HerdrAgentState = "idle" | "working" | "blocked" | "unknown";

/** Identifies us as the reporter in herdr's sidebar / `herdr agent ls`. */
const HERDR_SOURCE = "0sec";
const HERDR_AGENT = "0sec";

/** Protocol 19: `tokens` is a map of at most 16 entries… */
const MAX_TOKENS = 16;
/** …whose keys must each match this. */
const TOKEN_KEY_RE = /^[A-Za-z0-9_-]{1,32}$/;
/** …and `ttl_ms` must be <= 24h. */
const MAX_TTL_MS = 86_400_000;

/**
 * How long herdr should keep showing our metadata if we stop reporting.
 * Five minutes: long enough to survive a slow LLM turn, short enough that a
 * crashed scan's stale counters disappear from the sidebar on their own.
 */
const DEFAULT_TTL_MS = 300_000;

/** herdr's reference integration timings: one short attempt, one longer retry. */
const DEFAULT_ATTEMPT_MS = 500;
const DEFAULT_RETRY_MS = 1500;

// ── Privacy allow-lists ─────────────────────────────────────────────────────

/**
 * WHY AN ALLOW-LIST AND NOT A DENY-LIST: the bus payloads are open-ended
 * (`[k: string]: unknown` on most of them) and grow over time. A deny-list of
 * "don't send `title`, don't send `target`" silently starts leaking the day
 * someone adds `payload.host`. So nothing reaches the wire unless its key is
 * literally enumerated here, and every one of these is a count, a fixed
 * engine-internal enum, or a number.
 *
 * Deliberately EXCLUDED, and why:
 *   - finding `title` / `description` / `category` — engagement content, and
 *     the single most sensitive string we hold.
 *   - `target`, any hostname or URL — identifies the customer/asset.
 *   - `args_preview`, `summary`, `reason`, `error`, subagent `task` — free
 *     text that routinely embeds URLs, payloads and paths.
 *   - `source_path` and any file path — leaks repo layout and often the
 *     customer name.
 *   - tool NAMES — they look like a safe internal enum, but MCP tools are
 *     user-named and an MCP server called `acme-prod-api` would name the
 *     customer in herdr's sidebar. Excluded out of caution; we report the
 *     tool-call COUNT instead.
 *   - `severity` — combined with a public disclosure timeline this is
 *     engagement-sensitive, and it buys the operator nothing a count doesn't.
 */
const SAFE_TOKEN_KEYS: ReadonlySet<string> = new Set([
  "findings",
  "turn",
  "max_turns",
  "tools",
  "cost_usd",
  "phase",
  "subagents",
]);

/**
 * The only strings we will ever put in an operator-visible field. These are
 * the canonical pipeline phase names documented on `PhaseStartedPayload` in
 * `bus.ts` — a closed enum with no engagement content in it. `phase_started`
 * carries `name: string`, so a caller *could* emit something else; anything
 * not in this set is dropped rather than passed through.
 */
const PHASE_NAMES: ReadonlySet<string> = new Set([
  "prepare",
  "analyze",
  "research",
  "verify",
  "report",
]);

/**
 * Second line of defence on token VALUES. Anything that is not a finite
 * number, a boolean, or a short identifier-shaped string is dropped.
 *
 * Note we DROP rather than truncate over-long strings: a truncated hostname
 * is still an identifying hostname, so silently shortening it would defeat
 * the point. And no space is allowed, which alone kills essentially every
 * finding title, URL-with-query and shell command.
 */
const TOKEN_VALUE_RE = /^[A-Za-z0-9_.:+-]{1,32}$/;

// ── Injection seams ─────────────────────────────────────────────────────────

/** Minimal env shape — injected so tests never mutate `process.env`. */
export type HerdrEnvLike = Record<string, string | undefined>;

/** The slice of `net.Socket` we actually use. Fakes implement just this. */
export interface HerdrSocketLike {
  on(event: string, listener: (arg?: unknown) => void): unknown;
  write(data: string): unknown;
  destroy(): unknown;
}

/** Opens a connection to the herdr socket. MAY throw; callers must swallow. */
export type HerdrSocketFactory = (path: string) => HerdrSocketLike;

export interface HerdrEventSinkOptions {
  /** Override the transport (tests). Defaults to a real `node:net` socket. */
  connect?: HerdrSocketFactory;
  /** First-attempt deadline in ms. */
  attemptTimeoutMs?: number;
  /** Single-retry deadline in ms. */
  retryTimeoutMs?: number;
  /** Metadata TTL; clamped to the protocol's 24h ceiling. */
  ttlMs?: number;
}

/**
 * Real transport. Note `createConnection` can throw synchronously (an empty
 * or absurd path), which is why every call site wraps the factory in a
 * try/catch rather than relying on the socket's `error` event.
 */
function defaultSocketFactory(path: string): HerdrSocketLike {
  const socket = createConnection(normalizeSocketPath(path));
  // Never let a pending telemetry socket keep the CLI process alive after a
  // scan finishes.
  socket.unref();
  return {
    on: (event, listener) => socket.on(event, listener),
    write: (data) => socket.write(data),
    destroy: () => socket.destroy(),
  };
}

/**
 * On Windows the daemon listens on a named pipe; herdr hands us the bare
 * path and expects clients to apply the `\\.\pipe\` prefix themselves.
 */
export function normalizeSocketPath(path: string): string {
  if (process.platform !== "win32") return path;
  if (path.startsWith("\\\\.\\pipe\\")) return path;
  return `\\\\.\\pipe\\${path}`;
}

// ── Sanitizers (exported for direct testing) ────────────────────────────────

/** Clamp `ttl_ms` into the protocol's `(0, 86_400_000]` window. */
export function clampTtlMs(ttlMs: number): number {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) return DEFAULT_TTL_MS;
  return Math.min(Math.floor(ttlMs), MAX_TTL_MS);
}

/**
 * Enforce every protocol AND privacy constraint on a token map: optional
 * key allow-list, the protocol key regex, value coercion, and the 16-entry
 * cap. Returns a brand new object — the caller's map is never mutated.
 */
export function sanitizeHerdrTokens(
  input: Record<string, unknown>,
  allow: ReadonlySet<string> | null = SAFE_TOKEN_KEYS,
): Record<string, string> {
  const out: Record<string, string> = {};
  let count = 0;
  for (const [rawKey, rawValue] of Object.entries(input)) {
    if (count >= MAX_TOKENS) break;
    if (allow && !allow.has(rawKey)) continue;
    if (!TOKEN_KEY_RE.test(rawKey)) continue;
    const value = coerceTokenValue(rawValue);
    if (value === null) continue;
    out[rawKey] = value;
    count++;
  }
  return out;
}

function coerceTokenValue(value: unknown): string | null {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return null;
    // Trim float noise so `$0.043200000000000005` doesn't reach a pane title.
    const rounded = Number.isInteger(value) ? String(value) : value.toFixed(4);
    return rounded.length <= 32 ? rounded : null;
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "string") return TOKEN_VALUE_RE.test(value) ? value : null;
  return null;
}

// ── Event → state mapping ───────────────────────────────────────────────────

/**
 * Derived from the real `osecEvent` union in `../events/bus.ts`:
 *
 *   working  ← step_started, phase_started, agent_turn_started,
 *              tool_call_started, llm_planner_invoked,
 *              subagent_lifecycle{queued,running},
 *              agent_turn_completed{reason:"continue"}
 *   idle     ← scan_completed,
 *              agent_turn_completed{reason: finished | max_turns | error |
 *                                   cost_ceiling | early_stop}
 *   blocked  ← (nothing on the bus — see below)
 *
 * WHY `step_completed` / `phase_completed` DO NOT MAP TO `idle`: a phase
 * completing is immediately followed by the next phase starting. Reporting
 * idle there would flap the pane between idle and working several times per
 * scan, and herdr fires a completion sound/toast on every working→idle edge.
 * Only genuinely terminal events (`scan_completed`, a turn that is not
 * continuing) settle us to idle.
 *
 * WHY `agent_turn_completed` IS CONDITIONAL: `reason:"continue"` means the
 * loop is going straight into the next turn, so the agent is still working.
 *
 * WHY THERE IS NO `blocked` MAPPING: the bus vocabulary in `bus.ts` has no
 * event that means "waiting on the operator". The two places 0sec actually
 * blocks on a human — the co-pilot `approveTool` gate and the
 * `requestScope` prompt in `console/turn-engine.ts` — resolve their promises
 * inline and emit nothing. Rather than invent a mapping from an event that
 * does not mean what herdr's `blocked` means, the state is exposed as an
 * explicit `reportBlocked()` / `reportWorking()` pair for those gates to call
 * once someone owns wiring them.
 */
function mapEventToState(
  type: EventType,
  payload: Record<string, unknown>,
): HerdrAgentState | null {
  switch (type) {
    case "step_started":
    case "phase_started":
    case "agent_turn_started":
    case "tool_call_started":
    case "llm_planner_invoked":
      return "working";

    case "subagent_lifecycle": {
      const status = payload["status"];
      return status === "queued" || status === "running" ? "working" : null;
    }

    case "agent_turn_completed":
      return payload["reason"] === "continue" ? "working" : "idle";

    case "scan_completed":
      return "idle";

    default:
      return null;
  }
}

// ── HerdrEventSink ──────────────────────────────────────────────────────────

interface HerdrRequest {
  id: string;
  method: string;
  params: Record<string, unknown>;
}

interface PendingReport {
  state: HerdrAgentState;
  message?: string;
}

export class HerdrEventSink implements EventSink {
  private readonly paneId: string;
  private readonly socketPath: string;
  private readonly connect: HerdrSocketFactory;
  private readonly attemptTimeoutMs: number;
  private readonly retryTimeoutMs: number;
  private readonly ttlMs: number;

  /**
   * Monotonic sequence number. Seeded from wall-clock micros exactly like
   * herdr's `pi` integration so that a restarted 0sec in the same pane still
   * produces seqs above the ones the daemon already saw — otherwise the
   * daemon drops our first reports as stale.
   */
  private seq = Date.now() * 1000;

  // Single-flight queue: at most ONE report in flight, and at most ONE
  // pending report behind it. A newer state simply overwrites the older
  // pending one — herdr only cares about the LATEST state, so queueing a
  // backlog would just replay history slowly and unboundedly.
  private pendingState: PendingReport | null = null;
  private pendingTokens = false;
  private flushPromise: Promise<void> | null = null;
  private lastReported: string | null = null;
  private released = false;

  // Non-identifying counters, mirrored into `tokens` on every metadata report.
  private findings = 0;
  private toolCalls = 0;
  private turn = 0;
  private maxTurns = 0;
  private costUsd = 0;
  private activeSubagents = 0;
  private phase: string | null = null;

  constructor(paneId: string, socketPath: string, options: HerdrEventSinkOptions = {}) {
    this.paneId = paneId;
    this.socketPath = socketPath;
    this.connect = options.connect ?? defaultSocketFactory;
    this.attemptTimeoutMs = options.attemptTimeoutMs ?? DEFAULT_ATTEMPT_MS;
    this.retryTimeoutMs = options.retryTimeoutMs ?? DEFAULT_RETRY_MS;
    this.ttlMs = clampTtlMs(options.ttlMs ?? DEFAULT_TTL_MS);
  }

  /**
   * `EventSink.emit`. Synchronous, allocation-light and total: the whole body
   * is wrapped so that a malformed payload can never propagate into the bus's
   * fan-out (which would print to stderr and corrupt the TUI).
   */
  emit(type: EventType, payload: Record<string, unknown>): void {
    try {
      const countersChanged = this.updateCounters(type, payload);
      const state = mapEventToState(type, payload);
      if (state) this.queueState(state);
      // Only re-report metadata when a counter actually moved. `delta` events
      // fire hundreds of times per turn; without this guard every token batch
      // would schedule a socket connection for identical numbers.
      if (countersChanged) this.queueTokens();
    } catch {
      /* fail-soft: telemetry must never break a scan */
    }
  }

  /** Explicit state hooks for the operator-gate call sites (see mapping note). */
  reportBlocked(): void {
    this.queueState("blocked");
  }

  reportWorking(): void {
    this.queueState("working");
  }

  /**
   * Tell herdr we are done owning this pane's agent slot. Best-effort and
   * awaited by the caller only if it wants to; like everything else it never
   * throws.
   */
  async release(): Promise<void> {
    if (this.released) return;
    this.released = true;
    this.pendingState = null;
    this.pendingTokens = false;
    await this.drain();
    await this.send({
      id: this.nextId(),
      method: "pane.release_agent",
      params: {
        pane_id: this.paneId,
        source: HERDR_SOURCE,
        agent: HERDR_AGENT,
        seq: this.nextSeq(),
      },
    });
  }

  /** Resolves once the single-flight queue has drained. Never rejects. */
  async drain(): Promise<void> {
    while (this.flushPromise) {
      await this.flushPromise;
    }
  }

  // ── counters ──────────────────────────────────────────────────────────

  /**
   * PRIVACY: this is the only place bus payloads are read, and it reads
   * exactly five numeric fields plus one enum. Nothing else from a payload
   * is ever retained, so no string from an event body can reach the wire
   * except a `phase` name that survives the `PHASE_NAMES` allow-list.
   *
   * Returns `true` when a reported counter actually changed, so the caller
   * can skip a metadata report for the (very frequent) events that move
   * nothing.
   */
  private updateCounters(type: EventType, payload: Record<string, unknown>): boolean {
    switch (type) {
      case "finding_ingested":
        this.findings++;
        return true;
      case "tool_call_completed":
        this.toolCalls++;
        return true;
      case "agent_turn_started": {
        const turn = numberOr(payload["turn"], this.turn);
        const maxTurns = numberOr(payload["max_turns"], this.maxTurns);
        const changed = turn !== this.turn || maxTurns !== this.maxTurns;
        this.turn = turn;
        this.maxTurns = maxTurns;
        return changed;
      }
      case "cost_update": {
        const cost = numberOr(payload["cost_usd"], this.costUsd);
        const changed = cost !== this.costUsd;
        this.costUsd = cost;
        return changed;
      }
      case "phase_started": {
        const name = payload["name"];
        // Only a name from the documented closed enum is operator-visible.
        const phase = typeof name === "string" && PHASE_NAMES.has(name) ? name : null;
        const changed = phase !== this.phase;
        this.phase = phase;
        return changed;
      }
      case "scan_completed": {
        const findings = numberOr(payload["findings"], this.findings);
        const cost = numberOr(payload["cost_usd"], this.costUsd);
        const changed = findings !== this.findings || cost !== this.costUsd;
        this.findings = findings;
        this.costUsd = cost;
        return changed;
      }
      case "subagent_lifecycle": {
        const status = payload["status"];
        if (status === "running") {
          this.activeSubagents++;
          return true;
        }
        if (status === "completed" || status === "failed") {
          this.activeSubagents = Math.max(0, this.activeSubagents - 1);
          return true;
        }
        return false;
      }
      default:
        return false;
    }
  }

  private buildTokens(): Record<string, string> {
    return sanitizeHerdrTokens({
      findings: this.findings,
      turn: this.turn,
      max_turns: this.maxTurns,
      tools: this.toolCalls,
      cost_usd: this.costUsd,
      subagents: this.activeSubagents,
      ...(this.phase ? { phase: this.phase } : {}),
    });
  }

  // ── single-flight queue ───────────────────────────────────────────────

  private queueState(state: HerdrAgentState): void {
    if (this.released) return;
    // Suppress no-op churn: dozens of `tool_call_started`s in one turn all map
    // to `working`, and re-reporting it would spam the daemon for nothing.
    const key = `${state}|${this.phase ?? ""}`;
    if (key === this.lastReported && this.pendingState === null) return;
    this.pendingState = {
      state,
      ...(this.phase ? { message: this.phase } : {}),
    };
    this.scheduleFlush();
  }

  private queueTokens(): void {
    if (this.released) return;
    this.pendingTokens = true;
    this.scheduleFlush();
  }

  private scheduleFlush(): void {
    if (this.flushPromise) return;
    // `flush()` is total (its body is fully guarded), but the extra `.catch`
    // guarantees we can never produce an unhandled rejection in a host that
    // treats those as fatal.
    this.flushPromise = this.flush().catch(() => undefined);
  }

  private async flush(): Promise<void> {
    try {
      while (this.pendingState !== null || this.pendingTokens) {
        const state = this.pendingState;
        this.pendingState = null;
        if (state) {
          this.lastReported = `${state.state}|${state.message ?? ""}`;
          await this.send({
            id: this.nextId(),
            method: "pane.report_agent",
            params: {
              pane_id: this.paneId,
              source: HERDR_SOURCE,
              agent: HERDR_AGENT,
              state: state.state,
              ...(state.message ? { message: state.message } : {}),
              seq: this.nextSeq(),
            },
          });
        }
        if (this.pendingTokens) {
          this.pendingTokens = false;
          await this.send({
            id: this.nextId(),
            method: "pane.report_metadata",
            params: {
              pane_id: this.paneId,
              source: HERDR_SOURCE,
              // No `title`: it is the most tempting place to put the target,
              // and herdr renders it in shared chrome. We never send one.
              tokens: this.buildTokens(),
              ttl_ms: this.ttlMs,
              seq: this.nextSeq(),
            },
          });
        }
      }
    } catch {
      /* fail-soft */
    } finally {
      this.flushPromise = null;
    }
  }

  // ── transport ─────────────────────────────────────────────────────────

  private nextSeq(): number {
    return ++this.seq;
  }

  private nextId(): string {
    return `0sec-${this.seq + 1}`;
  }

  /**
   * One attempt, then exactly one retry — matching herdr's own integration.
   * No further backoff: a daemon that ignored two writes is not going to be
   * helped by a third, and the scan is more important than the pane title.
   */
  private async send(request: HerdrRequest): Promise<void> {
    let line: string;
    try {
      line = `${JSON.stringify(request)}\n`;
    } catch {
      return; // unserializable — drop rather than throw
    }
    if (await this.deliver(line, this.attemptTimeoutMs)) return;
    await this.deliver(line, this.retryTimeoutMs);
  }

  /**
   * Connect, write one NDJSON frame, resolve `true` on the first `data` event.
   * NEVER rejects: connect throwing, `write` throwing, `error`, an early
   * `close`, and the timeout all resolve `false`.
   */
  private deliver(line: string, timeoutMs: number): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      let settled = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      let socket: HerdrSocketLike | undefined;

      const finish = (ok: boolean): void => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        try {
          socket?.destroy();
        } catch {
          /* already gone */
        }
        resolve(ok);
      };

      timer = setTimeout(() => finish(false), timeoutMs);
      // Don't hold the event loop open on a telemetry deadline.
      (timer as { unref?: () => void }).unref?.();

      try {
        socket = this.connect(this.socketPath);
        socket.on("error", () => finish(false));
        socket.on("close", () => finish(false));
        // We never parse the response. A `{"error":…}` body and a malformed
        // one are equally uninteresting: there is no recovery either way, and
        // parsing is one more thing that could throw on the hot path.
        socket.on("data", () => finish(true));
        socket.on("connect", () => {
          try {
            socket?.write(line);
          } catch {
            finish(false);
          }
        });
      } catch {
        finish(false);
      }
    });
  }
}

// ── Factory ─────────────────────────────────────────────────────────────────

/**
 * Build a `HerdrEventSink`, or `null` when we are not running under herdr.
 *
 * Gating mirrors herdr's reference integration exactly: all three of
 * `HERDR_ENV === "1"`, `HERDR_SOCKET_PATH` and `HERDR_PANE_ID` must be
 * present. `HERDR_ENV` is compared strictly against `"1"` — a truthy-ish
 * `"true"` or `"0"` is NOT herdr and must not open a socket.
 *
 * The env is injected (defaulting to `process.env`) so tests never have to
 * mutate the real process environment.
 */
export function createHerdrEventSink(
  env: HerdrEnvLike = process.env,
  options: HerdrEventSinkOptions = {},
): HerdrEventSink | null {
  if (env["HERDR_ENV"] !== "1") return null;
  const socketPath = env["HERDR_SOCKET_PATH"];
  const paneId = env["HERDR_PANE_ID"];
  if (!socketPath || !paneId) return null;
  return new HerdrEventSink(paneId, socketPath, options);
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}
