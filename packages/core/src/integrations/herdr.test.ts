import { describe, expect, it } from "vitest";

import {
  clampTtlMs,
  createHerdrEventSink,
  sanitizeHerdrTokens,
  type HerdrEnvLike,
  type HerdrEventSinkOptions,
  type HerdrSocketFactory,
  type HerdrSocketLike,
} from "./herdr.js";

// ── Fake transport ──────────────────────────────────────────────────────────
//
// Never touches a real socket. `mode` is mutable on the harness so a test can
// make the transport fail, assert fail-soft, then flip it back to "auto" and
// prove the sink is still usable.

type FakeMode = "auto" | "manual" | "throw-connect" | "throw-write" | "silent";

interface FakeHarness {
  mode: FakeMode;
  connect: HerdrSocketFactory;
  /** Raw NDJSON frames handed to `socket.write`. */
  writes: string[];
  paths: string[];
  sockets: FakeSocket[];
  requests(): Array<Record<string, any>>;
  /** manual mode: deliver a response for the Nth connection. */
  respond(index: number): void;
}

class FakeSocket implements HerdrSocketLike {
  destroyed = false;
  private listeners = new Map<string, Array<(arg?: unknown) => void>>();

  constructor(private readonly harness: FakeHarness) {}

  on(event: string, listener: (arg?: unknown) => void): this {
    const list = this.listeners.get(event) ?? [];
    list.push(listener);
    this.listeners.set(event, list);
    return this;
  }

  fire(event: string, arg?: unknown): void {
    for (const listener of this.listeners.get(event) ?? []) listener(arg);
  }

  write(data: string): boolean {
    if (this.harness.mode === "throw-write") throw new Error("EPIPE");
    this.harness.writes.push(data);
    if (this.harness.mode === "auto") {
      queueMicrotask(() => this.fire("data", '{"id":"x","result":{}}'));
    }
    return true;
  }

  destroy(): void {
    this.destroyed = true;
  }
}

function createFakeHerdr(mode: FakeMode = "auto"): FakeHarness {
  const harness: FakeHarness = {
    mode,
    writes: [],
    paths: [],
    sockets: [],
    connect: (path: string) => {
      harness.paths.push(path);
      if (harness.mode === "throw-connect") throw new Error("ENOENT");
      const socket = new FakeSocket(harness);
      harness.sockets.push(socket);
      // The real socket connects asynchronously, so all handlers are attached
      // before "connect" lands.
      queueMicrotask(() => socket.fire("connect"));
      return socket;
    },
    requests: () => harness.writes.map((line) => JSON.parse(line)),
    respond: (index: number) => {
      harness.sockets[index]?.fire("data", '{"id":"x","result":{}}');
    },
  };
  return harness;
}

const tick = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

const ENV: HerdrEnvLike = {
  HERDR_ENV: "1",
  HERDR_SOCKET_PATH: "/run/user/1000/herdr.sock",
  HERDR_PANE_ID: "pane-7",
};

function makeSink(harness: FakeHarness, options: HerdrEventSinkOptions = {}) {
  const sink = createHerdrEventSink(ENV, {
    connect: harness.connect,
    attemptTimeoutMs: 5,
    retryTimeoutMs: 5,
    ...options,
  });
  if (!sink) throw new Error("expected a sink for a complete herdr env");
  return sink;
}

// ── Gating ──────────────────────────────────────────────────────────────────

describe("createHerdrEventSink gating", () => {
  it("returns a sink when all three herdr vars are present", () => {
    expect(createHerdrEventSink(ENV, { connect: createFakeHerdr().connect })).not.toBeNull();
  });

  it("returns null when HERDR_ENV is missing", () => {
    const { HERDR_ENV: _omit, ...rest } = ENV;
    expect(createHerdrEventSink(rest)).toBeNull();
  });

  it("returns null when HERDR_SOCKET_PATH is missing", () => {
    const { HERDR_SOCKET_PATH: _omit, ...rest } = ENV;
    expect(createHerdrEventSink(rest)).toBeNull();
  });

  it("returns null when HERDR_PANE_ID is missing", () => {
    const { HERDR_PANE_ID: _omit, ...rest } = ENV;
    expect(createHerdrEventSink(rest)).toBeNull();
  });

  it("returns null when either required var is empty string", () => {
    expect(createHerdrEventSink({ ...ENV, HERDR_SOCKET_PATH: "" })).toBeNull();
    expect(createHerdrEventSink({ ...ENV, HERDR_PANE_ID: "" })).toBeNull();
  });

  it("requires HERDR_ENV to be exactly \"1\"", () => {
    for (const value of ["true", "yes", "0", "on", " 1", "1 ", "01"]) {
      expect(createHerdrEventSink({ ...ENV, HERDR_ENV: value })).toBeNull();
    }
  });

  it("never opens a socket when gating fails", () => {
    const harness = createFakeHerdr();
    expect(createHerdrEventSink({ HERDR_ENV: "1" }, { connect: harness.connect })).toBeNull();
    expect(harness.paths).toHaveLength(0);
    expect(harness.writes).toHaveLength(0);
  });

  it("does not read the real process.env when an env is injected", () => {
    // Sanity: a bare empty object must gate off regardless of the host env.
    expect(createHerdrEventSink({})).toBeNull();
  });
});

// ── Request shape / seq ─────────────────────────────────────────────────────

describe("report shape", () => {
  it("sends pane.report_agent with the documented params", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);

    sink.emit("agent_turn_started", { turn: 3, max_turns: 40 });
    await sink.drain();

    const agent = harness.requests().find((r) => r.method === "pane.report_agent");
    expect(agent).toBeDefined();
    expect(agent!.method).toBe("pane.report_agent");
    expect(typeof agent!.id).toBe("string");
    expect(agent!.params).toMatchObject({
      pane_id: "pane-7",
      source: "0sec",
      agent: "0sec",
      state: "working",
    });
    expect(typeof agent!.params.seq).toBe("number");
  });

  it("connects to the configured socket path and frames one JSON per line", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);

    sink.emit("finding_ingested", { severity: "high" });
    await sink.drain();

    expect(harness.paths[0]).toBe("/run/user/1000/herdr.sock");
    for (const line of harness.writes) {
      expect(line.endsWith("\n")).toBe(true);
      expect(line.slice(0, -1)).not.toContain("\n");
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  it("sends pane.report_metadata with sanitized tokens and a bounded ttl", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);

    sink.emit("phase_started", { name: "research", index: 2 });
    sink.emit("finding_ingested", { severity: "critical" });
    await sink.drain();

    const meta = harness.requests().filter((r) => r.method === "pane.report_metadata").pop();
    expect(meta).toBeDefined();
    expect(meta!.params.pane_id).toBe("pane-7");
    expect(meta!.params.source).toBe("0sec");
    expect(meta!.params.ttl_ms).toBeLessThanOrEqual(86_400_000);
    expect(meta!.params.tokens).toMatchObject({ findings: "1", phase: "research" });
    expect(Object.keys(meta!.params.tokens).length).toBeLessThanOrEqual(16);
    // We deliberately never send a pane title — it is where a target would go.
    expect(meta!.params.title).toBeUndefined();
  });

  it("clamps an over-long configured ttl_ms to the protocol ceiling", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness, { ttlMs: 999_999_999 });

    sink.emit("finding_ingested", {});
    await sink.drain();

    const meta = harness.requests().find((r) => r.method === "pane.report_metadata");
    expect(meta!.params.ttl_ms).toBe(86_400_000);
  });

  it("emits a strictly increasing seq across every report", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);

    sink.emit("agent_turn_started", { turn: 1, max_turns: 10 });
    await sink.drain();
    sink.emit("finding_ingested", {});
    await sink.drain();
    sink.emit("agent_turn_completed", { turn: 1, duration_ms: 5, reason: "finished" });
    await sink.drain();
    sink.emit("scan_completed", { findings: 4 });
    await sink.drain();

    const seqs = harness.requests().map((r) => r.params.seq as number);
    expect(seqs.length).toBeGreaterThan(3);
    for (let i = 1; i < seqs.length; i++) {
      expect(seqs[i]).toBeGreaterThan(seqs[i - 1]!);
    }
  });

  it("sends pane.release_agent on release()", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);

    sink.emit("scan_completed", { findings: 0 });
    await sink.drain();
    await sink.release();

    const release = harness.requests().pop();
    expect(release!.method).toBe("pane.release_agent");
    expect(release!.params).toMatchObject({ pane_id: "pane-7", source: "0sec", agent: "0sec" });
  });
});

// ── State mapping ───────────────────────────────────────────────────────────

describe("event -> state mapping", () => {
  async function stateFor(
    type: Parameters<ReturnType<typeof makeSink>["emit"]>[0],
    payload: Record<string, unknown>,
  ): Promise<string | undefined> {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);
    sink.emit(type, payload);
    await sink.drain();
    const agent = harness.requests().filter((r) => r.method === "pane.report_agent").pop();
    return agent?.params.state as string | undefined;
  }

  it("maps start-ish events to working", async () => {
    expect(await stateFor("step_started", { step: "recon", n: 1 })).toBe("working");
    expect(await stateFor("phase_started", { name: "verify", index: 3 })).toBe("working");
    expect(await stateFor("agent_turn_started", { turn: 1, max_turns: 9 })).toBe("working");
    expect(await stateFor("tool_call_started", { tool: "http_request", turn: 1, args_preview: "", ts: 1 })).toBe("working");
    expect(await stateFor("llm_planner_invoked", { turn: 1 })).toBe("working");
  });

  it("maps a continuing turn to working and a terminal turn to idle", async () => {
    expect(
      await stateFor("agent_turn_completed", { turn: 1, duration_ms: 2, reason: "continue" }),
    ).toBe("working");
    for (const reason of ["finished", "max_turns", "error", "cost_ceiling", "early_stop"]) {
      expect(
        await stateFor("agent_turn_completed", { turn: 1, duration_ms: 2, reason }),
      ).toBe("idle");
    }
  });

  it("maps scan_completed to idle", async () => {
    expect(await stateFor("scan_completed", { findings: 2, exit_reason: "done" })).toBe("idle");
  });

  it("maps subagent lifecycle starts to working and ignores its terminal states", async () => {
    const base = { agent_id: "a1", parent_scan_id: "s1", task: "x", max_turns: 5 };
    expect(await stateFor("subagent_lifecycle", { ...base, status: "queued" })).toBe("working");
    expect(await stateFor("subagent_lifecycle", { ...base, status: "running" })).toBe("working");
    // completed/failed are NOT idle: the parent scan is still working.
    expect(await stateFor("subagent_lifecycle", { ...base, status: "completed" })).toBeUndefined();
  });

  it("does not flap to idle on step/phase completion", async () => {
    expect(await stateFor("step_completed", { step: "recon" })).toBeUndefined();
    expect(
      await stateFor("phase_completed", {
        name: "analyze",
        index: 1,
        duration_ms: 5,
        input_tokens: 0,
        output_tokens: 0,
        turns: 0,
      }),
    ).toBeUndefined();
  });

  it("ignores hot-path events that carry no state or counter change", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);
    for (let i = 0; i < 50; i++) {
      sink.emit("delta", { turn: 1, scope: "assistant_response", text: "tok", seq: i });
    }
    sink.emit("reasoning_summary", { turn: 1, summary: "thinking" });
    await sink.drain();
    expect(harness.writes).toHaveLength(0);
  });

  it("exposes an explicit blocked report (no bus event maps to it)", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);
    sink.reportBlocked();
    await sink.drain();
    const agent = harness.requests().find((r) => r.method === "pane.report_agent");
    expect(agent!.params.state).toBe("blocked");

    sink.reportWorking();
    await sink.drain();
    expect(harness.requests().pop()!.params.state).toBe("working");
  });

  it("suppresses repeated identical states", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);
    for (let i = 0; i < 5; i++) {
      sink.emit("tool_call_started", { tool: "bash", turn: 1, args_preview: "", ts: i });
      await sink.drain();
    }
    const agentReports = harness.requests().filter((r) => r.method === "pane.report_agent");
    expect(agentReports).toHaveLength(1);
  });

  it("uses only closed-enum phase names as the operator-visible message", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);
    // A phase name outside the documented enum must never reach the wire.
    sink.emit("phase_started", { name: "scanning https://victim.example.com", index: 0 });
    await sink.drain();
    const serialized = harness.writes.join("");
    expect(serialized).not.toContain("victim.example.com");
    const agent = harness.requests().find((r) => r.method === "pane.report_agent");
    expect(agent!.params.message).toBeUndefined();
  });
});

// ── Single-flight ───────────────────────────────────────────────────────────

describe("single-flight queue", () => {
  it("collapses rapid state changes to the latest, never queueing a backlog", async () => {
    const harness = createFakeHerdr("manual");
    const sink = makeSink(harness, { attemptTimeoutMs: 1_000, retryTimeoutMs: 1_000 });

    // #1 goes on the wire immediately and stays in flight (manual mode).
    sink.emit("agent_turn_started", { turn: 1, max_turns: 10 });
    await tick();
    expect(harness.writes).toHaveLength(1);
    expect(harness.requests()[0]!.params.state).toBe("working");

    // Two more state changes arrive while #1 is unacknowledged.
    sink.emit("agent_turn_completed", { turn: 1, duration_ms: 1, reason: "continue" });
    sink.emit("scan_completed", { findings: 1 });
    await tick();
    expect(harness.writes).toHaveLength(1); // nothing queued behind the flight

    // Release the in-flight reports one at a time; only the LATEST pending
    // state follows the one already on the wire.
    for (let i = 0; i < 8; i++) {
      const idx = harness.sockets.findIndex((s) => !s.destroyed);
      if (idx < 0) break;
      harness.respond(idx);
      await tick();
    }
    const states = harness
      .requests()
      .filter((r) => r.method === "pane.report_agent")
      .map((r) => r.params.state);
    expect(states).toEqual(["working", "idle"]);
    await sink.drain();
  });

  it("keeps at most one connection open at a time", async () => {
    const harness = createFakeHerdr("manual");
    const sink = makeSink(harness, { attemptTimeoutMs: 1_000, retryTimeoutMs: 1_000 });

    sink.emit("agent_turn_started", { turn: 1, max_turns: 10 });
    sink.emit("finding_ingested", {});
    sink.emit("finding_ingested", {});
    await tick();

    expect(harness.sockets).toHaveLength(1);

    harness.mode = "auto";
    for (let i = 0; i < 8; i++) {
      const idx = harness.sockets.findIndex((s) => !s.destroyed);
      if (idx < 0) break;
      harness.respond(idx);
      await tick();
    }
    await sink.drain();
  });
});

// ── Fail-soft ───────────────────────────────────────────────────────────────

describe("fail-soft", () => {
  it("survives a transport that throws on connect", async () => {
    const harness = createFakeHerdr("throw-connect");
    const sink = makeSink(harness);

    expect(() => sink.emit("agent_turn_started", { turn: 1, max_turns: 4 })).not.toThrow();
    await expect(sink.drain()).resolves.toBeUndefined();
    expect(harness.writes).toHaveLength(0);

    // Still usable once the daemon comes back.
    harness.mode = "auto";
    sink.emit("scan_completed", { findings: 1 });
    await sink.drain();
    expect(harness.writes.length).toBeGreaterThan(0);
  });

  it("survives a transport that throws on write", async () => {
    const harness = createFakeHerdr("throw-write");
    const sink = makeSink(harness);

    expect(() => sink.emit("agent_turn_started", { turn: 1, max_turns: 4 })).not.toThrow();
    await expect(sink.drain()).resolves.toBeUndefined();
    expect(harness.writes).toHaveLength(0);

    harness.mode = "auto";
    sink.emit("scan_completed", { findings: 1 });
    await sink.drain();
    expect(harness.writes.length).toBeGreaterThan(0);
  });

  it("survives a daemon that never responds (single retry, then gives up)", async () => {
    const harness = createFakeHerdr("silent");
    const sink = makeSink(harness);

    sink.emit("agent_turn_started", { turn: 1, max_turns: 4 });
    await expect(sink.drain()).resolves.toBeUndefined();

    // Exactly one attempt plus one retry per report — no unbounded retry loop.
    const agentAttempts = harness.requests().filter((r) => r.method === "pane.report_agent");
    expect(agentAttempts).toHaveLength(2);
    for (const socket of harness.sockets) expect(socket.destroyed).toBe(true);

    harness.mode = "auto";
    sink.emit("scan_completed", { findings: 0 });
    await expect(sink.drain()).resolves.toBeUndefined();
  });

  it("swallows a malformed response body", async () => {
    const harness = createFakeHerdr("manual");
    const sink = makeSink(harness, { attemptTimeoutMs: 1_000, retryTimeoutMs: 1_000 });

    sink.emit("agent_turn_started", { turn: 1, max_turns: 4 });
    await tick();
    harness.sockets[0]!.fire("data", "not-json-at-all}}}");
    await tick();
    harness.mode = "auto";
    await expect(sink.drain()).resolves.toBeUndefined();
  });

  it("swallows a peer that closes without answering", async () => {
    const harness = createFakeHerdr("manual");
    const sink = makeSink(harness, { attemptTimeoutMs: 1_000, retryTimeoutMs: 1_000 });

    sink.emit("agent_turn_started", { turn: 1, max_turns: 4 });
    await tick();
    for (const socket of harness.sockets) socket.fire("close");
    await tick();
    harness.mode = "auto";
    await expect(sink.drain()).resolves.toBeUndefined();
  });

  it("does not throw on structurally unexpected payloads", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);
    const hostile: Record<string, unknown> = { turn: Number.NaN, max_turns: null, name: 42 };
    expect(() => sink.emit("agent_turn_started", hostile)).not.toThrow();
    expect(() => sink.emit("phase_started", hostile)).not.toThrow();
    expect(() => sink.emit("cost_update", { cost_usd: Number.POSITIVE_INFINITY })).not.toThrow();
    await expect(sink.drain()).resolves.toBeUndefined();
  });
});

// ── Privacy ─────────────────────────────────────────────────────────────────

describe("privacy", () => {
  const SECRETS = [
    "admin.internal.acme-corp.com",
    "https://admin.internal.acme-corp.com/login?next=/etc",
    "Blind SQL injection in the tenant login form",
    "The password reset endpoint leaks tokens",
    "/home/dev/engagements/acme/src/auth/login.ts",
    "curl -X POST --data 'id=1 OR 1=1'",
    "Enumerate subdomains of acme-corp.com and exploit the admin panel",
    "SuperSecretApiKey123",
  ];

  it("never puts engagement content on the wire", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);

    sink.emit("finding_ingested", {
      finding_id: "f-1",
      severity: "critical",
      title: "Blind SQL injection in the tenant login form",
      description: "The password reset endpoint leaks tokens",
      category: "sqli",
      source_path: "/home/dev/engagements/acme/src/auth/login.ts",
      evidence_request: "GET https://admin.internal.acme-corp.com/login?next=/etc",
      evidence_response: "SuperSecretApiKey123",
      poc_steps: "curl -X POST --data 'id=1 OR 1=1'",
    });
    sink.emit("tool_call_started", {
      tool: "http_request",
      turn: 4,
      args_preview: "https://admin.internal.acme-corp.com/login?next=/etc",
      ts: 1,
    });
    sink.emit("tool_call_completed", {
      tool: "http_request",
      turn: 4,
      duration_ms: 12,
      status: "error",
      error: "connect ETIMEDOUT admin.internal.acme-corp.com:443",
      ts: 2,
    });
    sink.emit("subagent_lifecycle", {
      agent_id: "sub-1",
      parent_scan_id: "scan-1",
      status: "running",
      task: "Enumerate subdomains of acme-corp.com and exploit the admin panel",
      max_turns: 10,
      scope_rules: ["*.acme-corp.com"],
    });
    sink.emit("step_started", { step: "attack admin.internal.acme-corp.com" });
    sink.emit("scan_completed", {
      findings: 1,
      summary: "Blind SQL injection in the tenant login form",
      exit_reason: "done",
    });
    await sink.drain();

    const serialized = harness.writes.join("");
    expect(serialized.length).toBeGreaterThan(0);
    for (const secret of SECRETS) {
      expect(serialized).not.toContain(secret);
    }
    // Not even a fragment of the target host survives.
    expect(serialized).not.toContain("acme");
    expect(serialized).not.toContain("http");
    expect(serialized).not.toContain("/home/dev");
  });

  it("still reports the useful non-identifying counters", async () => {
    const harness = createFakeHerdr();
    const sink = makeSink(harness);

    sink.emit("agent_turn_started", { turn: 6, max_turns: 40 });
    sink.emit("finding_ingested", { title: "leaky thing", severity: "high" });
    sink.emit("finding_ingested", { title: "other leaky thing", severity: "low" });
    sink.emit("tool_call_completed", { tool: "bash", turn: 6, duration_ms: 1, status: "ok", ts: 1 });
    sink.emit("cost_update", { cost_usd: 1.2345678 });
    await sink.drain();

    const meta = harness.requests().filter((r) => r.method === "pane.report_metadata").pop();
    expect(meta!.params.tokens).toEqual({
      findings: "2",
      turn: "6",
      max_turns: "40",
      tools: "1",
      cost_usd: "1.2346",
      subagents: "0",
    });
  });
});

// ── Token / ttl sanitizers ──────────────────────────────────────────────────

describe("sanitizeHerdrTokens", () => {
  it("trims to at most 16 entries", () => {
    const input: Record<string, unknown> = {};
    for (let i = 0; i < 40; i++) input[`k${i}`] = i;
    const out = sanitizeHerdrTokens(input, null);
    expect(Object.keys(out)).toHaveLength(16);
  });

  it("drops keys that violate the protocol key regex", () => {
    const out = sanitizeHerdrTokens(
      {
        good_key: 1,
        "bad key": 2,
        "bad.key": 3,
        "bad/key": 4,
        "": 5,
        ["x".repeat(33)]: 6,
        "GOOD-2": 7,
      },
      null,
    );
    expect(Object.keys(out).sort()).toEqual(["GOOD-2", "good_key"]);
  });

  it("drops keys outside the privacy allow-list by default", () => {
    const out = sanitizeHerdrTokens({ findings: 3, target: "acme.com", title: "sqli" });
    expect(out).toEqual({ findings: "3" });
  });

  it("coerces and rejects values", () => {
    const out = sanitizeHerdrTokens(
      {
        a: 7,
        b: 1.23456789,
        c: Number.NaN,
        d: Number.POSITIVE_INFINITY,
        e: true,
        f: "ok-value",
        g: "has spaces so it is dropped",
        h: "x".repeat(64),
        i: { nested: 1 },
        j: null,
        k: undefined,
        l: ["a"],
      },
      null,
    );
    expect(out).toEqual({ a: "7", b: "1.2346", e: "true", f: "ok-value" });
  });

  it("does not mutate its input", () => {
    const input = { findings: 1, target: "acme.com" };
    sanitizeHerdrTokens(input);
    expect(input).toEqual({ findings: 1, target: "acme.com" });
  });
});

describe("clampTtlMs", () => {
  it("clamps to the 24h protocol ceiling", () => {
    expect(clampTtlMs(86_400_001)).toBe(86_400_000);
    expect(clampTtlMs(Number.MAX_SAFE_INTEGER)).toBe(86_400_000);
  });

  it("passes through a sane value and falls back on nonsense", () => {
    expect(clampTtlMs(300_000)).toBe(300_000);
    expect(clampTtlMs(0)).toBe(300_000);
    expect(clampTtlMs(-1)).toBe(300_000);
    expect(clampTtlMs(Number.NaN)).toBe(300_000);
  });
});
