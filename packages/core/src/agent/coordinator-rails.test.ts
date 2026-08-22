import { describe, expect, it } from "vitest";
import {
  stallWatchdog,
  resolveStallAction,
  takeoverGate,
  reduceCoordinatorState,
  superviseCoordinator,
  formatFindingTailLine,
  detectCallRepetition,
  fingerprintCall,
  LOOP_NUDGE_REPEATS,
  LOOP_FORCE_REPEATS,
  LOOP_WINDOW_SIZE,
  LOOP_ACTION_RANK,
  type CallSignature,
  type LoopAction,
  STALL_WARN_IDLE_MS,
  STALL_ESCALATE_IDLE_MS,
  STALL_KILL_IDLE_MS,
  STALL_ACTION_FLOOR_MS,
  MAX_AGENT_RETRIES,
  MAX_SOLO_BUDGET_SHARE,
  STALL_LEVEL_RANK,
  type CoordinatorState,
  type StallLevel,
} from "./coordinator-rails.js";

const NOW = 1_000_000_000;

// ── 1. Stall watchdog ───────────────────────────────────────────────────────

describe("stallWatchdog", () => {
  it("gates on idle-since-last-output, NOT dispatch age", () => {
    // Dispatched an hour ago (very old startedAt) but emitted output 1s ago.
    const d = stallWatchdog({
      startedAt: NOW - 3_600_000,
      lastOutputAt: NOW - 1_000,
      now: NOW,
      iterations: 200,
    });
    expect(d.level).toBe("continue");
  });

  it("threshold boundaries fire at exactly >= the constant", () => {
    const at = (idle: number): StallLevel =>
      stallWatchdog({
        startedAt: NOW,
        lastOutputAt: NOW - idle,
        now: NOW,
        iterations: 1,
      }).level;

    expect(at(STALL_WARN_IDLE_MS - 1)).toBe("continue");
    expect(at(STALL_WARN_IDLE_MS)).toBe("warn");
    expect(at(STALL_ESCALATE_IDLE_MS - 1)).toBe("warn");
    expect(at(STALL_ESCALATE_IDLE_MS)).toBe("escalate");
    expect(at(STALL_KILL_IDLE_MS - 1)).toBe("escalate");
    expect(at(STALL_KILL_IDLE_MS)).toBe("kill");
  });

  it("clamps future lastOutputAt (clock skew) to continue", () => {
    const d = stallWatchdog({
      startedAt: NOW,
      lastOutputAt: NOW + 50_000,
      now: NOW,
      iterations: 1,
    });
    expect(d.idleMs).toBe(0);
    expect(d.level).toBe("continue");
  });

  it("MONOTONICITY: more idle never yields a less-severe level (sweep)", () => {
    let prevRank = -1;
    for (let idle = 0; idle <= STALL_KILL_IDLE_MS + 120_000; idle += 5_000) {
      const level = stallWatchdog({
        startedAt: NOW,
        lastOutputAt: NOW - idle,
        now: NOW,
        iterations: 1,
      }).level;
      const rank = STALL_LEVEL_RANK[level];
      expect(rank).toBeGreaterThanOrEqual(prevRank);
      prevRank = rank;
    }
    // The sweep reaches the most severe level.
    expect(prevRank).toBe(STALL_LEVEL_RANK.kill);
  });

  it("an agent still emitting output is NEVER killed (sweep dispatch age)", () => {
    // For any dispatch age, if last output is recent, it stays healthy.
    for (let age = 0; age <= 2 * STALL_KILL_IDLE_MS; age += 30_000) {
      const d = stallWatchdog({
        startedAt: NOW - age,
        lastOutputAt: NOW - 2_000, // 2s ago — fresh output
        now: NOW,
        iterations: age / 1000,
      });
      expect(d.level).toBe("continue");
    }
  });
});

// ── 2. Kill-vs-escalate policy ──────────────────────────────────────────────

describe("resolveStallAction", () => {
  it("below the action floor → continue (never kill on a hunch)", () => {
    expect(
      resolveStallAction({
        stalledMs: STALL_ACTION_FLOOR_MS - 1,
        retriesSpent: MAX_AGENT_RETRIES,
        hasPartialFindings: false,
      }).action,
    ).toBe("continue");
  });

  it("stalled + retries exhausted → kill (provably dead, reaped)", () => {
    expect(
      resolveStallAction({
        stalledMs: STALL_KILL_IDLE_MS,
        retriesSpent: MAX_AGENT_RETRIES,
        hasPartialFindings: false,
      }).action,
    ).toBe("kill");
  });

  it("kill wins even when the dead agent holds partial findings (findings persist independently)", () => {
    expect(
      resolveStallAction({
        stalledMs: STALL_KILL_IDLE_MS,
        retriesSpent: MAX_AGENT_RETRIES,
        hasPartialFindings: true,
      }).action,
    ).toBe("kill");
  });

  it("stalled + retries remain + partial findings → escalate (never blindly discard work)", () => {
    expect(
      resolveStallAction({
        stalledMs: STALL_ACTION_FLOOR_MS,
        retriesSpent: 0,
        hasPartialFindings: true,
      }).action,
    ).toBe("escalate-to-operator");
  });

  it("stalled + retries remain + no findings → restart (cheap recovery)", () => {
    expect(
      resolveStallAction({
        stalledMs: STALL_ACTION_FLOOR_MS,
        retriesSpent: 0,
        hasPartialFindings: false,
      }).action,
    ).toBe("restart");
  });

  it("MONOTONICITY: increasing idle never reverts a non-continue action back to continue (sweep)", () => {
    for (const retriesSpent of [0, 1, MAX_AGENT_RETRIES]) {
      for (const hasPartialFindings of [false, true]) {
        let sawNonContinue = false;
        for (let s = 0; s <= STALL_KILL_IDLE_MS + 60_000; s += 5_000) {
          const action = resolveStallAction({
            stalledMs: s,
            retriesSpent,
            hasPartialFindings,
          }).action;
          if (action !== "continue") sawNonContinue = true;
          if (sawNonContinue) expect(action).not.toBe("continue");
        }
      }
    }
  });
});

// ── 3. Anti-solo-takeover gate ──────────────────────────────────────────────

describe("takeoverGate", () => {
  it("trips at EXACTLY the cap, not one iteration before", () => {
    const total = 10;
    const capIters = Math.ceil(MAX_SOLO_BUDGET_SHARE * total); // 6 for 0.6*10
    const below = takeoverGate({
      agentId: "a",
      iterationsByAgent: { a: capIters - 1, b: 1 },
      totalBudget: total,
    });
    const at = takeoverGate({
      agentId: "a",
      iterationsByAgent: { a: capIters, b: 1 },
      totalBudget: total,
    });
    expect(below.action).toBe("continue");
    expect(at.action).toBe("checkpoint");
    expect(at.share).toBeGreaterThanOrEqual(MAX_SOLO_BUDGET_SHARE);
  });

  it("MONOTONICITY: once tripped, more iterations never un-trips (sweep)", () => {
    let tripped = false;
    for (let mine = 0; mine <= 20; mine++) {
      const action = takeoverGate({
        agentId: "a",
        iterationsByAgent: { a: mine, b: 2 },
        totalBudget: 20,
      }).action;
      if (action === "checkpoint") tripped = true;
      if (tripped) expect(action).toBe("checkpoint");
    }
    expect(tripped).toBe(true);
  });

  it("zero budget never divides by zero and never trips", () => {
    const d = takeoverGate({
      agentId: "a",
      iterationsByAgent: { a: 5 },
      totalBudget: 0,
    });
    expect(d.share).toBe(0);
    expect(d.action).toBe("continue");
  });

  it("emits a reason on every decision (no silent caps)", () => {
    const d = takeoverGate({
      agentId: "a",
      iterationsByAgent: { a: 9, b: 1 },
      totalBudget: 10,
    });
    expect(d.action).toBe("checkpoint");
    expect(d.reason).toContain("a");
    expect(d.reason.length).toBeGreaterThan(0);
  });
});

// ── 4. Loop / repetition detection ───────────────────────────────────────────

describe("detectCallRepetition", () => {
  const sig = (tool: string, fp = ""): CallSignature => ({ tool, fingerprint: fp });
  const repeat = (s: CallSignature, n: number): CallSignature[] =>
    Array.from({ length: n }, () => s);

  it("a varied call sequence never trips", () => {
    const window = [sig("a"), sig("b"), sig("c"), sig("d"), sig("e"), sig("f")];
    expect(detectCallRepetition(window).action).toBe("continue");
  });

  it("boundary at exactly NUDGE and FORCE", () => {
    const s = sig("http_request", "url=/x");
    expect(detectCallRepetition(repeat(s, LOOP_NUDGE_REPEATS - 1)).action).toBe("continue");
    expect(detectCallRepetition(repeat(s, LOOP_NUDGE_REPEATS)).action).toBe("nudge");
    expect(detectCallRepetition(repeat(s, LOOP_FORCE_REPEATS - 1)).action).toBe("nudge");
    expect(detectCallRepetition(repeat(s, LOOP_FORCE_REPEATS)).action).toBe("force-pivot");
  });

  it("only the TRAILING identical run counts (a break resets it)", () => {
    // 4 identical then one different call → trailing run of 1.
    const s = sig("x", "p=1");
    const window = [...repeat(s, 4), sig("y", "p=2")];
    expect(detectCallRepetition(window).action).toBe("continue");
    expect(detectCallRepetition(window).repeatCount).toBe(1);
  });

  it("MONOTONICITY: more repetition never yields a less-severe action (sweep)", () => {
    const s = sig("scan", "target=host");
    let prevRank = -1;
    for (let n = 1; n <= LOOP_WINDOW_SIZE; n++) {
      const action: LoopAction = detectCallRepetition(repeat(s, n)).action;
      const rank = LOOP_ACTION_RANK[action];
      expect(rank).toBeGreaterThanOrEqual(prevRank);
      prevRank = rank;
    }
    expect(prevRank).toBe(LOOP_ACTION_RANK["force-pivot"]);
  });

  it("empty window → continue", () => {
    expect(detectCallRepetition([]).action).toBe("continue");
  });
});

describe("fingerprintCall", () => {
  it("is order-insensitive over arg keys (near-identical collapse)", () => {
    const a = fingerprintCall("t", { b: 2, a: 1 });
    const b = fingerprintCall("t", { a: 1, b: 2 });
    expect(a).toEqual(b);
  });

  it("normalizes whitespace/case and never throws on odd input", () => {
    expect(fingerprintCall("t", "  Foo  Bar ").fingerprint).toBe("foo bar");
    expect(() => fingerprintCall("t", undefined)).not.toThrow();
  });
});

// ── Pure reducer ─────────────────────────────────────────────────────────────

describe("reduceCoordinatorState", () => {
  it("returns the SAME reference for irrelevant events", () => {
    const prev: CoordinatorState = {};
    const next = reduceCoordinatorState(
      prev,
      { type: "cost_update", payload: { cost_usd: 1 } },
      NOW,
    );
    expect(next).toBe(prev);
  });

  it("queued lifecycle seeds an agent; progress advances it and resets idle clock", () => {
    let s: CoordinatorState = {};
    s = reduceCoordinatorState(
      s,
      {
        type: "subagent_lifecycle",
        payload: { agent_id: "c1", status: "queued", max_turns: 20 },
      },
      NOW,
    );
    expect(s.c1.status).toBe("queued");
    expect(s.c1.maxTurns).toBe(20);
    expect(s.c1.startedAt).toBe(NOW);

    s = reduceCoordinatorState(
      s,
      { type: "subagent_progress", payload: { agent_id: "c1", turn: 3, max_turns: 20 } },
      NOW + 5_000,
    );
    expect(s.c1.status).toBe("running");
    expect(s.c1.iterations).toBe(3);
    expect(s.c1.lastOutputAt).toBe(NOW + 5_000); // progress IS output
    expect(s.c1.startedAt).toBe(NOW); // dispatch time unchanged
  });

  it("progress events accumulate a bounded recent-call window (tool + note)", () => {
    let s: CoordinatorState = {};
    for (let t = 1; t <= LOOP_WINDOW_SIZE + 3; t++) {
      s = reduceCoordinatorState(
        s,
        {
          type: "subagent_progress",
          payload: { agent_id: "c1", turn: t, max_turns: 40, tool: "http_request", note: "same" },
        },
        NOW + t * 1_000,
      );
    }
    expect(s.c1.recentCalls.length).toBe(LOOP_WINDOW_SIZE); // bounded
    // All identical → the loop rail sees a full-window spin.
    expect(detectCallRepetition(s.c1.recentCalls).action).toBe("force-pivot");
  });

  it("a turn with no tool contributes no call to the window", () => {
    let s: CoordinatorState = {};
    s = reduceCoordinatorState(
      s,
      { type: "subagent_progress", payload: { agent_id: "c1", turn: 1, max_turns: 20 } },
      NOW,
    );
    expect(s.c1.recentCalls).toEqual([]);
  });

  it("completed lifecycle records findings and turns", () => {
    let s: CoordinatorState = {};
    s = reduceCoordinatorState(
      s,
      {
        type: "subagent_lifecycle",
        payload: { agent_id: "c1", status: "running", max_turns: 20 },
      },
      NOW,
    );
    s = reduceCoordinatorState(
      s,
      {
        type: "subagent_lifecycle",
        payload: { agent_id: "c1", status: "completed", turns: 12, findings: 4, max_turns: 20 },
      },
      NOW + 10_000,
    );
    expect(s.c1.status).toBe("completed");
    expect(s.c1.iterations).toBe(12);
    expect(s.c1.findings).toBe(4);
  });

  it("ignores events without an agent_id", () => {
    const prev: CoordinatorState = {};
    const next = reduceCoordinatorState(
      prev,
      { type: "subagent_progress", payload: { turn: 1 } },
      NOW,
    );
    expect(next).toBe(prev);
  });
});

// ── Supervisor composition ───────────────────────────────────────────────────

describe("superviseCoordinator", () => {
  function running(
    id: string,
    over: Partial<CoordinatorState[string]> = {},
  ): CoordinatorState[string] {
    return {
      agentId: id,
      startedAt: NOW - 1_000_000,
      lastOutputAt: NOW,
      iterations: 1,
      maxTurns: 20,
      status: "running",
      findings: 0,
      retriesSpent: 0,
      recentCalls: [],
      ...over,
    };
  }

  it("healthy fleet → no interventions", () => {
    const state: CoordinatorState = {
      a: running("a", { lastOutputAt: NOW - 1_000 }),
      b: running("b", { lastOutputAt: NOW - 2_000 }),
    };
    expect(superviseCoordinator(state, { now: NOW })).toEqual([]);
  });

  it("silent child yields a watchdog + a resolved kill-escalate intervention", () => {
    const state: CoordinatorState = {
      a: running("a", {
        lastOutputAt: NOW - STALL_KILL_IDLE_MS,
        retriesSpent: MAX_AGENT_RETRIES,
        findings: 0,
      }),
    };
    const out = superviseCoordinator(state, { now: NOW });
    const watchdog = out.find((i) => i.kind === "stall-watchdog");
    const resolved = out.find((i) => i.kind === "kill-escalate");
    expect(watchdog?.level).toBe("kill");
    expect(resolved?.action).toBe("kill");
  });

  it("a warn-level silence does NOT produce a kill-escalate intervention", () => {
    const state: CoordinatorState = {
      a: running("a", { lastOutputAt: NOW - STALL_WARN_IDLE_MS }),
    };
    const out = superviseCoordinator(state, { now: NOW });
    expect(out.some((i) => i.kind === "stall-watchdog" && i.level === "warn")).toBe(true);
    expect(out.some((i) => i.kind === "kill-escalate")).toBe(false);
  });

  it("a spinning child produces a loop-detection intervention", () => {
    const spin = Array.from({ length: LOOP_FORCE_REPEATS }, () => ({
      tool: "http_request",
      fingerprint: "url=/same",
    }));
    const state: CoordinatorState = {
      a: running("a", { recentCalls: spin, lastOutputAt: NOW }),
    };
    const out = superviseCoordinator(state, { now: NOW });
    const loop = out.find((i) => i.kind === "loop-detection");
    expect(loop?.action).toBe("force-pivot");
    expect(loop?.repeatCount).toBe(LOOP_FORCE_REPEATS);
  });

  it("completed children are not intervened on but still count toward budget", () => {
    const state: CoordinatorState = {
      done: running("done", { status: "completed", iterations: 12 }),
      hog: running("hog", { iterations: 8, lastOutputAt: NOW }),
    };
    // totalBudget defaults to sum of maxTurns = 40; hog share = 8/40 = 0.2 → fine.
    // Override the budget so hog crosses the cap and confirm the completed
    // agent contributes its iterations but is itself never intervened on.
    const out = superviseCoordinator(state, { now: NOW, totalBudget: 10 });
    expect(out.some((i) => i.agentId === "done")).toBe(false);
    expect(out.some((i) => i.agentId === "hog" && i.kind === "anti-takeover")).toBe(true);
  });
});

// ── Findings tail ────────────────────────────────────────────────────────────

describe("formatFindingTailLine", () => {
  it("renders severity + title on one line", () => {
    expect(
      formatFindingTailLine({ severity: "high", title: "SQL injection in /login" }),
    ).toBe("[HIGH] SQL injection in /login");
  });

  it("strips control chars and collapses whitespace (single-line safe)", () => {
    const line = formatFindingTailLine({
      severity: "critical",
      title: "line1\nline2\ttab nul",
    });
    expect(line).not.toMatch(/[\n\t ]/);
    expect(line).toBe("[CRITICAL] line1 line2 tab nul");
  });

  it("falls back through message/category and defaults to info", () => {
    expect(formatFindingTailLine({ message: "just a message" })).toBe(
      "[INFO] just a message",
    );
    expect(formatFindingTailLine({})).toBe("[INFO] (untitled finding)");
  });
});
