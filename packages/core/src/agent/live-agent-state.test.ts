import { describe, it, expect } from "vitest";
import {
  hasLiveAgentState,
  reduceLiveAgentState,
  type LiveAgentState,
} from "./live-agent-state.js";

// ── reduceLiveAgentState ──────────────────────────────────────────
//
// Pure-function reducer over the eventBus's wire shape. The CLI's
// TUI live-agent panel relies on these invariants holding so the
// terminal stays readable on long scans (replace-in-place, not a
// firehose).

const empty: LiveAgentState = {};

describe("reduceLiveAgentState — agent_turn_started", () => {
  it("populates turn / maxTurns / role on first turn", () => {
    const next = reduceLiveAgentState(empty, "agent_turn_started", {
      turn: 1,
      max_turns: 20,
      role: "audit",
    });
    expect(next.turn).toBe(1);
    expect(next.maxTurns).toBe(20);
    expect(next.role).toBe("audit");
  });

  it("clears the previous turn's currentTool so stale badges don't linger", () => {
    const prev: LiveAgentState = {
      turn: 1,
      currentTool: { tool: "rg", status: "running" },
    };
    const next = reduceLiveAgentState(prev, "agent_turn_started", { turn: 2 });
    expect(next.currentTool).toBeUndefined();
    expect(next.turn).toBe(2);
  });

  it("keeps max_turns when the new turn payload omits it", () => {
    const prev: LiveAgentState = { turn: 1, maxTurns: 20 };
    const next = reduceLiveAgentState(prev, "agent_turn_started", { turn: 2 });
    expect(next.maxTurns).toBe(20);
  });
});

describe("reduceLiveAgentState — tool_call_*", () => {
  it("tool_call_started swaps in the new tool with running status", () => {
    const next = reduceLiveAgentState(empty, "tool_call_started", {
      tool: "rg",
      args_preview: "rg foo /tmp",
      turn: 1,
    });
    expect(next.currentTool).toEqual({
      tool: "rg",
      argsPreview: "rg foo /tmp",
      status: "running",
    });
  });

  it("tool_call_started ignores payloads with no tool name", () => {
    const next = reduceLiveAgentState(empty, "tool_call_started", {
      args_preview: "no tool here",
    });
    expect(next).toBe(empty);
  });

  it("tool_call_completed flips a matching tool to ok + records duration", () => {
    const prev: LiveAgentState = {
      currentTool: { tool: "rg", argsPreview: "rg foo", status: "running" },
    };
    const next = reduceLiveAgentState(prev, "tool_call_completed", {
      tool: "rg",
      duration_ms: 42,
      status: "ok",
    });
    expect(next.currentTool).toEqual({
      tool: "rg",
      argsPreview: "rg foo",
      status: "ok",
      durationMs: 42,
      error: undefined,
    });
  });

  it("tool_call_completed records error message when status=error", () => {
    const prev: LiveAgentState = {
      currentTool: { tool: "rg", status: "running" },
    };
    const next = reduceLiveAgentState(prev, "tool_call_completed", {
      tool: "rg",
      status: "error",
      error: "spawn rg ENOENT",
      duration_ms: 1,
    });
    expect(next.currentTool?.status).toBe("error");
    expect(next.currentTool?.error).toBe("spawn rg ENOENT");
  });

  it("tool_call_completed without a matching currentTool is a no-op", () => {
    const next = reduceLiveAgentState(empty, "tool_call_completed", {
      tool: "rg",
      status: "ok",
    });
    expect(next).toBe(empty);
  });

  it("tool_call_completed for a different tool than the in-flight one is a no-op", () => {
    // Sub-agent loops can interleave tool calls; we don't want a
    // late completion from a different tool blowing away the
    // currently-rendering one.
    const prev: LiveAgentState = {
      currentTool: { tool: "rg", argsPreview: "rg foo", status: "running" },
    };
    const next = reduceLiveAgentState(prev, "tool_call_completed", {
      tool: "find",
      status: "ok",
    });
    expect(next).toBe(prev);
  });

  it("tool_call_completed without a tool field updates the in-flight one (best-effort)", () => {
    // Some runtimes don't echo the tool name back on completion.
    // We treat that as "the in-flight one finished" rather than
    // dropping the update, so the badge actually flips.
    const prev: LiveAgentState = {
      currentTool: { tool: "rg", status: "running" },
    };
    const next = reduceLiveAgentState(prev, "tool_call_completed", {
      status: "ok",
      duration_ms: 5,
    });
    expect(next.currentTool?.status).toBe("ok");
    expect(next.currentTool?.durationMs).toBe(5);
  });
});

describe("reduceLiveAgentState — reasoning_summary", () => {
  it("trims and stores the summary", () => {
    const next = reduceLiveAgentState(empty, "reasoning_summary", {
      summary: "  Inspecting lodash exports for unsafe sinks.  ",
      turn: 3,
    });
    expect(next.reasoningSummary).toBe(
      "Inspecting lodash exports for unsafe sinks.",
    );
  });

  it("ignores empty / whitespace-only summaries", () => {
    const next = reduceLiveAgentState(empty, "reasoning_summary", {
      summary: "   ",
    });
    expect(next).toBe(empty);
  });

  it("ignores non-string summary fields", () => {
    const next = reduceLiveAgentState(empty, "reasoning_summary", {
      summary: 42,
    });
    expect(next).toBe(empty);
  });

  it("replaces in place — no history accumulated", () => {
    const a = reduceLiveAgentState(empty, "reasoning_summary", {
      summary: "first",
    });
    const b = reduceLiveAgentState(a, "reasoning_summary", {
      summary: "second",
    });
    expect(b.reasoningSummary).toBe("second");
  });
});

describe("reduceLiveAgentState — cost_update", () => {
  it("populates cost / token totals", () => {
    const next = reduceLiveAgentState(empty, "cost_update", {
      cost_usd: 0.0123,
      input_tokens: 1000,
      output_tokens: 250,
      turn: 1,
    });
    expect(next.costUsd).toBe(0.0123);
    expect(next.inputTokens).toBe(1000);
    expect(next.outputTokens).toBe(250);
  });

  it("returns the same reference when no field actually changed", () => {
    // Some runtimes echo cost_update unchanged across delta chunks;
    // skip the rerender hint when there's nothing new to render.
    const prev: LiveAgentState = {
      costUsd: 0.05,
      inputTokens: 100,
      outputTokens: 50,
    };
    const next = reduceLiveAgentState(prev, "cost_update", {
      cost_usd: 0.05,
      input_tokens: 100,
      output_tokens: 50,
    });
    expect(next).toBe(prev);
  });

  it("partial cost updates preserve the missing fields", () => {
    const prev: LiveAgentState = {
      costUsd: 0.05,
      inputTokens: 100,
      outputTokens: 50,
    };
    const next = reduceLiveAgentState(prev, "cost_update", {
      cost_usd: 0.07,
    });
    expect(next.costUsd).toBe(0.07);
    expect(next.inputTokens).toBe(100);
    expect(next.outputTokens).toBe(50);
  });
});

describe("reduceLiveAgentState — irrelevant events", () => {
  it("returns the input unchanged for delta events", () => {
    const next = reduceLiveAgentState(empty, "delta", {
      turn: 1,
      text: "hi",
      seq: 0,
    });
    expect(next).toBe(empty);
  });

  it.each([
    "agent_turn_completed",
    "llm_planner_invoked",
    "finding_ingested",
    "scan_completed",
    "totally_unknown_event",
  ])("returns input unchanged for %s", (eventType) => {
    const next = reduceLiveAgentState(empty, eventType, {});
    expect(next).toBe(empty);
  });
});

describe("hasLiveAgentState", () => {
  it("returns false for undefined / empty", () => {
    expect(hasLiveAgentState(undefined)).toBe(false);
    expect(hasLiveAgentState({})).toBe(false);
  });

  it("returns true once any meaningful field is populated", () => {
    expect(hasLiveAgentState({ turn: 1 })).toBe(true);
    expect(hasLiveAgentState({ reasoningSummary: "..." })).toBe(true);
    expect(hasLiveAgentState({ costUsd: 0.01 })).toBe(true);
    expect(hasLiveAgentState({ inputTokens: 123 })).toBe(true);
    expect(hasLiveAgentState({ outputTokens: 45 })).toBe(true);
    expect(
      hasLiveAgentState({
        currentTool: { tool: "rg", status: "running" },
      }),
    ).toBe(true);
  });

  it("returns false when only role is set (role alone isn't useful UI signal)", () => {
    expect(hasLiveAgentState({ role: "audit" })).toBe(false);
  });
});
