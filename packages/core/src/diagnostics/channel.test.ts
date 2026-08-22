/**
 * Tests for the structured diagnostics channel.
 *
 * The contract under test is narrow but load-bearing:
 *
 *   - structured fields reach a sink as *data* and are never interpolated
 *     into the human-readable message;
 *   - a sink that throws cannot break the caller;
 *   - ANSI escapes, control characters and over-long text are neutralized
 *     before anything crosses into a renderer;
 *   - the unsubscribed default really is stderr (see the module docstring for
 *     why buffering was rejected);
 *   - a claiming sink (the TUI) receives everything and stderr goes silent.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  diag,
  claimDiagnostics,
  subscribeDiagnostics,
  isDiagnosticsClaimed,
  recentDiagnostics,
  formatDiagnosticLine,
  _resetDiagnosticsForTests,
  MAX_MESSAGE_LENGTH,
  MAX_FIELD_VALUE_LENGTH,
  MAX_FIELDS,
  MAX_BUFFERED,
  type DiagnosticEvent,
  type DiagnosticSink,
} from "./channel.js";

/** Collecting sink plus the events it saw. */
function recorder(): { sink: DiagnosticSink; events: DiagnosticEvent[] } {
  const events: DiagnosticEvent[] = [];
  return { sink: { emit: (e) => void events.push(e) }, events };
}

/** Spy on stderr so "did this reach the terminal?" is directly assertable. */
function stderrSpy() {
  return vi.spyOn(process.stderr, "write").mockImplementation(() => true);
}

/** Concatenated text of every stderr write recorded by the spy. */
function stderrText(spy: ReturnType<typeof stderrSpy>): string {
  return spy.mock.calls.map((c) => String(c[0])).join("");
}

const ESC = "\u001B";
const origDiagLevel = process.env["0SEC_DIAG_LEVEL"];

beforeEach(() => {
  _resetDiagnosticsForTests();
  delete process.env["0SEC_DIAG_LEVEL"];
});

afterEach(() => {
  vi.restoreAllMocks();
  _resetDiagnosticsForTests();
  if (origDiagLevel === undefined) delete process.env["0SEC_DIAG_LEVEL"];
  else process.env["0SEC_DIAG_LEVEL"] = origDiagLevel;
});

// ── Structured fields ───────────────────────────────────────────────────────

describe("structured fields", () => {
  it("delivers fields to the sink as data, not interpolated into the message", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.warn("quota_exhausted", "Anthropic plan quota exhausted", {
      provider: "Anthropic",
      plan: "pro",
      resets_at: "2026-08-22T18:00:00.000Z",
      status: 429,
      retryable: false,
    });

    expect(events).toHaveLength(1);
    const event = events[0]!;

    // The whole point: a consumer reads `fields.plan`, it does not regex the
    // prose. So the prose must NOT contain the field values.
    expect(event.message).toBe("Anthropic plan quota exhausted");
    expect(event.message).not.toContain("pro");
    expect(event.message).not.toContain("429");
    expect(event.message).not.toContain("2026-08-22");

    expect(event.fields).toEqual({
      provider: "Anthropic",
      plan: "pro",
      resets_at: "2026-08-22T18:00:00.000Z",
      status: 429,
      retryable: false,
    });
    // Types survive: 429 is a number, not the string "429".
    expect(typeof event.fields["status"]).toBe("number");
    expect(typeof event.fields["retryable"]).toBe("boolean");
  });

  it("carries a stable code independent of the prose", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.error("quota_exhausted", "wording one", { a: 1 });
    diag.error("quota_exhausted", "totally different wording", { a: 2 });

    expect(events.map((e) => e.code)).toEqual([
      "quota_exhausted",
      "quota_exhausted",
    ]);
    expect(events[0]!.level).toBe("error");
  });

  it("normalizes an unruly code into a slug rather than rejecting it", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.warn("Retry Budget/Spent!", "m");
    diag.warn(`${ESC}[31m`, "m");

    expect(events[0]!.code).toBe("retry_budget_spent");
    // Pure-escape code has nothing left after sanitization.
    expect(events[1]!.code).toBe("unknown");
  });

  it("coerces awkward field values instead of throwing or dropping silently", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    const circular: Record<string, unknown> = { name: "loop" };
    circular["self"] = circular;

    diag.info("coercion", "m", {
      err: new Error("boom"),
      nil: null,
      gone: undefined,
      big: 10n,
      nan: Number.NaN,
      inf: Number.POSITIVE_INFINITY,
      nested: { a: 1, b: [2, 3] },
      circular,
    });

    const f = events[0]!.fields;
    expect(f["err"]).toBe("Error: boom");
    expect(f["nil"]).toBeNull();
    // `undefined` means "no value" — the key is omitted, not rendered.
    expect(f).not.toHaveProperty("gone");
    expect(f["big"]).toBe("10n");
    // JSON would turn these into `null`, which reads as "absent" and is a lie.
    expect(f["nan"]).toBe("NaN");
    expect(f["inf"]).toBe("Infinity");
    expect(f["nested"]).toBe('{"a":1,"b":[2,3]}');
    expect(f["circular"]).toBe("[unserializable]");
  });

  it("bounds the number of fields", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    const many: Record<string, unknown> = {};
    for (let i = 0; i < MAX_FIELDS + 25; i++) many[`k${i}`] = i;
    diag.info("many_fields", "m", many);

    expect(Object.keys(events[0]!.fields)).toHaveLength(MAX_FIELDS);
  });

  it("omits the fields group entirely when there are none", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);
    diag.info("bare", "just prose");
    expect(events[0]!.fields).toEqual({});
    expect(formatDiagnosticLine(events[0]!)).toBe("[0sec] just prose");
  });
});

// ── Fail-soft ───────────────────────────────────────────────────────────────

describe("fail-soft delivery", () => {
  it("a throwing claiming sink cannot break the caller", () => {
    const boom: DiagnosticSink = {
      emit() {
        throw new Error("sink exploded");
      },
    };
    claimDiagnostics(boom);
    const spy = stderrSpy();

    expect(() => diag.warn("code", "message")).not.toThrow();
    // Losing the diagnostic outright would be worse than one corrupted frame,
    // so a broken claimant falls back to stderr.
    expect(stderrText(spy)).toContain("message");
  });

  it("a throwing observer cannot break the caller or starve other sinks", () => {
    const boom: DiagnosticSink = {
      emit() {
        throw new Error("observer exploded");
      },
    };
    const { sink: good, events } = recorder();
    subscribeDiagnostics(boom);
    subscribeDiagnostics(good);
    stderrSpy();

    expect(() => diag.error("code", "message")).not.toThrow();
    expect(events).toHaveLength(1);
  });

  it("a sink that throws on the first call still receives later ones", () => {
    let calls = 0;
    const flaky: DiagnosticSink = {
      emit() {
        calls++;
        if (calls === 1) throw new Error("transient");
      },
    };
    claimDiagnostics(flaky);
    stderrSpy();

    expect(() => {
      diag.warn("a", "one");
      diag.warn("b", "two");
    }).not.toThrow();
    expect(calls).toBe(2);
  });

  it("survives a stderr that throws (EPIPE) with no sink registered", () => {
    vi.spyOn(process.stderr, "write").mockImplementation(() => {
      throw new Error("EPIPE");
    });
    expect(() => diag.error("code", "message")).not.toThrow();
  });

  it("survives a hostile fields object whose getter throws", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);
    const hostile = {
      get bad(): string {
        throw new Error("getter exploded");
      },
      ok: 1,
    };

    expect(() => diag.warn("hostile", "m", hostile)).not.toThrow();
    // The emit is abandoned rather than half-delivered — but crucially, the
    // caller is untouched.
    expect(events.length).toBeLessThanOrEqual(1);
  });
});

// ── Sanitization ────────────────────────────────────────────────────────────

describe("sanitization", () => {
  it("strips ANSI escape sequences from the message", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.warn("ansi", `${ESC}[31mred${ESC}[0m and ${ESC}[1mbold${ESC}[22m`);

    expect(events[0]!.message).toBe("red and bold");
    expect(events[0]!.message).not.toContain(ESC);
  });

  it("strips ANSI cursor-movement and screen-clear sequences", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    // These are precisely the sequences that desynchronize a differential
    // renderer: move the cursor home, clear the screen, scroll.
    diag.warn("ansi_move", `${ESC}[2J${ESC}[H${ESC}[10;20Hhijacked${ESC}[K`);

    const message = events[0]!.message;
    expect(message).toBe("hijacked");
    expect(message).not.toContain(ESC);
  });

  it("turns newlines, carriage returns and tabs into single spaces", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.warn("multiline", "line one\nline two\r\nline three\ttabbed");

    const message = events[0]!.message;
    expect(message).toBe("line one line two line three tabbed");
    expect(message).not.toContain("\n");
    expect(message).not.toContain("\r");
    expect(message).not.toContain("\t");
  });

  it("strips NUL, BEL, backspace and other C0/C1 control characters", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.warn("controls", "a\u0000b\u0007c\u0008d\u001Fe");

    const message = events[0]!.message;
    expect(message).toBe("a b c d e");
    expect(/[\u0000-\u001F\u007F-\u009F]/.test(message)).toBe(false);
  });

  it("strips Unicode line and paragraph separators", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.warn("u_breaks", "a\u2028b\u2029c");

    expect(events[0]!.message).toBe("a b c");
  });

  it("bounds an over-long message and marks the truncation", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.warn("long", "x".repeat(MAX_MESSAGE_LENGTH * 3));

    const message = events[0]!.message;
    expect(message.length).toBe(MAX_MESSAGE_LENGTH);
    expect(message.endsWith("…")).toBe(true);
  });

  it("sanitizes and bounds string field values too", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.warn("field_sanitize", "m", {
      injected: `${ESC}[2Jwiped\nnewline`,
      long: "y".repeat(MAX_FIELD_VALUE_LENGTH * 3),
    });

    const f = events[0]!.fields;
    expect(f["injected"]).toBe("wiped newline");
    expect(String(f["long"]).length).toBe(MAX_FIELD_VALUE_LENGTH);
  });

  it("sanitizes field keys so a key cannot smuggle an escape sequence", () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);

    diag.warn("key_sanitize", "m", { [`${ESC}[31mplan`]: "pro" });

    const keys = Object.keys(events[0]!.fields);
    expect(keys).toEqual(["plan"]);
    expect(keys[0]).not.toContain(ESC);
  });

  it("keeps the rendered stderr line free of control characters end to end", () => {
    const spy = stderrSpy();

    diag.error("render_inert", `${ESC}[31mbad\nnews${ESC}[0m`, {
      detail: `${ESC}[2Jalso bad\r\n`,
    });

    const written = stderrText(spy);
    // Exactly one line: the trailing newline the sink adds, and nothing else.
    expect(written.split("\n").filter((l) => l.length > 0)).toHaveLength(1);
    expect(written).toBe("[0sec] bad news (detail=also bad)\n");
    expect(written).not.toContain(ESC);
  });
});

// ── Default (unsubscribed) behaviour ────────────────────────────────────────

describe("default delivery when nothing has subscribed", () => {
  it("writes to stderr rather than buffering silently", () => {
    const spy = stderrSpy();
    expect(isDiagnosticsClaimed()).toBe(false);

    diag.error("quota_exhausted", "Anthropic plan quota exhausted", {
      plan: "pro",
    });

    // The decision under test: a plain-CLI operator MUST see this. Buffering
    // it would mean the scan produces nothing and they never learn why.
    expect(spy).toHaveBeenCalledTimes(1);
    expect(stderrText(spy)).toBe(
      "[0sec] Anthropic plan quota exhausted (plan=pro)\n",
    );
  });

  it("writes every level to stderr by default, matching the pre-migration behaviour", () => {
    const spy = stderrSpy();

    diag.info("i", "info line");
    diag.warn("w", "warn line");
    diag.error("e", "error line");

    const text = stderrText(spy);
    expect(spy).toHaveBeenCalledTimes(3);
    expect(text).toContain("info line");
    expect(text).toContain("warn line");
    expect(text).toContain("error line");
  });

  it("emits exactly one trailing newline per diagnostic — callers never manage it", () => {
    const spy = stderrSpy();
    diag.warn("nl", "no newline supplied by the caller");
    const written = String(spy.mock.calls[0]![0]);
    expect(written.endsWith("\n")).toBe(true);
    expect(written.slice(0, -1)).not.toContain("\n");
  });

  it("renders structured fields into the line so nothing visible is lost", () => {
    const spy = stderrSpy();
    diag.warn("retry_backoff", "OpenRouter HTTP 429 — backoff 250ms", {
      status: 429,
      delay_ms: 250,
      attempt: 3,
    });
    expect(stderrText(spy)).toBe(
      "[0sec] OpenRouter HTTP 429 — backoff 250ms (status=429 delay_ms=250 attempt=3)\n",
    );
  });

  it("still buffers for replay even though stderr is the primary path", () => {
    stderrSpy();
    diag.warn("a", "one");
    diag.warn("b", "two");

    const recent = recentDiagnostics();
    expect(recent.map((e) => e.code)).toEqual(["a", "b"]);
  });

  it("bounds the replay buffer", () => {
    stderrSpy();
    for (let i = 0; i < MAX_BUFFERED + 40; i++) diag.info("n", `m${i}`);
    const recent = recentDiagnostics();
    expect(recent).toHaveLength(MAX_BUFFERED);
    // Oldest evicted first.
    expect(recent[recent.length - 1]!.message).toBe(`m${MAX_BUFFERED + 39}`);
  });

  it("honours 0SEC_DIAG_LEVEL as an at-source filter", () => {
    const spy = stderrSpy();

    process.env["0SEC_DIAG_LEVEL"] = "error";
    diag.info("i", "info line");
    diag.warn("w", "warn line");
    diag.error("e", "error line");
    expect(stderrText(spy)).toBe("[0sec] error line\n");

    spy.mockClear();
    process.env["0SEC_DIAG_LEVEL"] = "off";
    diag.error("e", "error line");
    expect(spy).not.toHaveBeenCalled();
    // Filtered at the source: nothing was buffered either.
    expect(recentDiagnostics().some((e) => e.message === "info line")).toBe(
      false,
    );
  });
});

// ── Claimed channel (TUI) ───────────────────────────────────────────────────

describe("a claimed channel", () => {
  it("routes everything to the claiming sink and keeps stderr silent", () => {
    const { sink, events } = recorder();
    const spy = stderrSpy();

    const release = claimDiagnostics(sink);
    expect(isDiagnosticsClaimed()).toBe(true);

    diag.info("provider_initialized", "OpenRouter provider initialized", {
      model: "x",
    });
    diag.warn("retry_backoff", "backoff 250ms", { delay_ms: 250 });
    diag.error("quota_exhausted", "plan quota exhausted", { plan: "pro" });

    // The whole reason this module exists: the renderer's terminal is untouched.
    expect(spy).not.toHaveBeenCalled();

    expect(events).toHaveLength(3);
    expect(events.map((e) => e.code)).toEqual([
      "provider_initialized",
      "retry_backoff",
      "quota_exhausted",
    ]);
    expect(events.map((e) => e.level)).toEqual(["info", "warn", "error"]);
    expect(events[2]!.fields["plan"]).toBe("pro");

    release();
    expect(isDiagnosticsClaimed()).toBe(false);
  });

  it("restores stderr delivery on release", () => {
    const { sink, events } = recorder();
    const spy = stderrSpy();

    const release = claimDiagnostics(sink);
    diag.warn("a", "while claimed");
    release();
    diag.warn("b", "after release");

    expect(events.map((e) => e.message)).toEqual(["while claimed"]);
    expect(stderrText(spy)).toBe("[0sec] after release\n");
  });

  it("release is idempotent and does not resurrect a superseded claim", () => {
    const first = recorder();
    const second = recorder();
    const spy = stderrSpy();

    const releaseFirst = claimDiagnostics(first.sink);
    const releaseSecond = claimDiagnostics(second.sink);

    diag.warn("a", "to second");
    expect(second.events).toHaveLength(1);
    expect(first.events).toHaveLength(0);

    // Out-of-order teardown: the outer claim releases while the inner is live.
    releaseFirst();
    releaseFirst();
    diag.warn("b", "still to second");
    expect(second.events).toHaveLength(2);

    releaseSecond();
    diag.warn("c", "back to first");
    expect(first.events.map((e) => e.message)).toEqual(["back to first"]);
    expect(spy).not.toHaveBeenCalled();
  });

  it("replays the buffered backlog into a late claimer when asked", () => {
    stderrSpy();
    diag.warn("early", "happened before the TUI mounted");

    const { sink, events } = recorder();
    claimDiagnostics(sink, { replay: true });

    expect(events.map((e) => e.message)).toEqual([
      "happened before the TUI mounted",
    ]);
  });

  it("does not replay unless asked", () => {
    stderrSpy();
    diag.warn("early", "happened before the TUI mounted");

    const { sink, events } = recorder();
    claimDiagnostics(sink);
    expect(events).toHaveLength(0);
  });

  it("observers still receive a copy while the channel is claimed", () => {
    const claimant = recorder();
    const observer = recorder();
    const spy = stderrSpy();

    claimDiagnostics(claimant.sink);
    const unsubscribe = subscribeDiagnostics(observer.sink);

    diag.warn("a", "one");
    expect(claimant.events).toHaveLength(1);
    expect(observer.events).toHaveLength(1);
    expect(spy).not.toHaveBeenCalled();

    unsubscribe();
    diag.warn("b", "two");
    expect(observer.events).toHaveLength(1);
  });

  it("an observer subscribing without a claim does NOT silence stderr", () => {
    const { sink, events } = recorder();
    const spy = stderrSpy();

    subscribeDiagnostics(sink);
    diag.warn("a", "one");

    expect(events).toHaveLength(1);
    expect(stderrText(spy)).toContain("one");
  });

  it("unsubscribing mid-fanout cannot skip a sink", () => {
    const late = recorder();
    stderrSpy();

    let unsubscribeSelf: (() => void) | undefined;
    const selfRemoving: DiagnosticSink = {
      emit() {
        unsubscribeSelf?.();
      },
    };
    unsubscribeSelf = subscribeDiagnostics(selfRemoving);
    subscribeDiagnostics(late.sink);

    diag.warn("a", "one");
    expect(late.events).toHaveLength(1);
  });
});

// ── Migrated call sites ─────────────────────────────────────────────────────

/**
 * End-to-end proof that the migration did not quietly cost non-TUI operators
 * their most important diagnostic. `llm-api.ts` used to `process.stderr.write`
 * the quota notice directly; it now goes through this channel, and with nobody
 * claiming (the plain-CLI case) it must still land on stderr — and it must go
 * silent the moment the TUI claims.
 */
describe("migrated llm-api quota path", () => {
  const origEnv = { ...process.env };

  /** 429 carrying the plan-quota body `parseUsageLimitReached` recognises. */
  function quotaLimited(): Response {
    return {
      ok: false,
      status: 429,
      headers: new Headers(),
      text: async () =>
        JSON.stringify({
          error: {
            type: "usage_limit_reached",
            message: "You have reached your usage limit.",
            plan_type: "pro",
            resets_at: Math.floor(
              new Date("2026-07-19T00:00:00Z").getTime() / 1000,
            ),
          },
        }),
    } as unknown as Response;
  }

  async function runQuotaExhaustedCall() {
    const { LlmApiRuntime, __resetFallbackChainForTests } = await import(
      "../runtime/llm-api.js"
    );
    __resetFallbackChainForTests();
    vi.stubGlobal("fetch", vi.fn(async () => quotaLimited()));

    const rt = new LlmApiRuntime({ type: "api", timeout: 30_000, apiKey: "k" });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const anyRt = rt as any;
    anyRt.provider = "openai";
    anyRt.wireApi = "chat_completions";
    // test fixture, literal non-secret key
    // foxguard: ignore[js/no-hardcoded-secret]
    anyRt.apiKey = "test";
    return rt.executeNative(
      "sys",
      [{ role: "user", content: [{ type: "text", text: "go" }] }],
      [],
    );
  }

  beforeEach(() => {
    // A fallback chain in the ambient environment would turn the quota error
    // into a silent failover, which is a different code path.
    delete process.env["0SEC_LLM_FALLBACK"];
    process.env["0SEC_SKIP_PROVIDER_BANNER"] = "1";
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    for (const key of Object.keys(process.env)) {
      if (!(key in origEnv)) delete process.env[key];
    }
    Object.assign(process.env, origEnv);
  });

  it("still reports plan-quota exhaustion on stderr for a plain CLI run", async () => {
    const spy = stderrSpy();
    expect(isDiagnosticsClaimed()).toBe(false);

    const result = await runQuotaExhaustedCall();

    const written = stderrText(spy);
    expect(written).toContain("plan quota exhausted");
    expect(written).toContain("usage_limit_reached");
    expect(written).toContain("plan=pro");
    expect(written).toContain("resets_at=2026-07-19T00:00:00.000Z");

    // Reporting change only — control flow and error type are untouched.
    expect(result.stopReason).toBe("error");
    expect(result.error).toContain("usage_limit_reached");
  });

  it("routes the same quota notice to a claiming TUI sink with stderr silent", async () => {
    const { sink, events } = recorder();
    claimDiagnostics(sink);
    const spy = stderrSpy();

    await runQuotaExhaustedCall();

    expect(spy).not.toHaveBeenCalled();

    const quota = events.find((e) => e.code === "quota_exhausted");
    expect(quota).toBeDefined();
    expect(quota!.level).toBe("error");
    // Structured, so the TUI can render a "resets at" countdown instead of
    // regexing the prose.
    expect(quota!.fields).toMatchObject({
      provider: "OpenAI",
      quota_kind: "usage_limit_reached",
      plan: "pro",
      resets_at: "2026-07-19T00:00:00.000Z",
      status: 429,
    });
  });
});
