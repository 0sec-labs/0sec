import { describe, expect, it } from "vitest";
import { renderSeedMessages } from "./seed.js";
import { rehydrateContext } from "./rehydrate.js";
import type { ConversationState } from "./rehydrate.js";
import type { JournalEntry } from "./types.js";

function emptyState(): ConversationState {
  return {
    runId: null,
    lastSeq: -1,
    toolSteps: [],
    hypotheses: [],
    findings: [],
    notes: [],
    decisions: [],
    done: false,
    summary: "",
  };
}

describe("renderSeedMessages", () => {
  it("returns an empty array for an empty state (fresh run → fall through to initial prompt)", () => {
    expect(renderSeedMessages(emptyState())).toEqual([]);
  });

  it("returns an empty array for a state with only a runId / lastSeq but no progress", () => {
    const state = emptyState();
    state.runId = "run-1";
    state.lastSeq = 5;
    expect(renderSeedMessages(state)).toEqual([]);
  });

  it("renders a single user message when there is progress", () => {
    const state = emptyState();
    state.toolSteps = [
      { tool: "run_command", arguments: { cmd: "ls" }, turn: 1, result: { ok: true, output: "file.txt" } },
    ];
    const messages = renderSeedMessages(state);
    expect(messages).toHaveLength(1);
    expect(messages[0].role).toBe("user");
    expect(messages[0].content).toHaveLength(1);
    expect(messages[0].content[0]).toMatchObject({ type: "text" });
  });

  it("includes tool steps, hypotheses, findings, decisions, notes and summary sections", () => {
    const state = emptyState();
    state.toolSteps = [
      { tool: "fetch", arguments: { url: "/admin" }, turn: 2, result: { ok: false, error: "403 Forbidden" } },
    ];
    state.hypotheses = [
      { statement: "admin is IDOR-able", status: "open", confidence: 0.6, rationale: "weak id check" },
    ];
    state.findings = [{ title: "XSS in search", severity: "high" }];
    state.decisions = ["pivot to the API surface"];
    state.notes = ["cookie is httpOnly"];
    state.done = true;
    state.summary = "found one high-sev XSS";

    const text = (renderSeedMessages(state)[0].content[0] as { text: string }).text;
    expect(text).toContain("Tool steps so far");
    expect(text).toContain("fetch");
    expect(text).toContain("403 Forbidden");
    expect(text).toContain("Hypotheses");
    expect(text).toContain("admin is IDOR-able");
    expect(text).toContain("Findings recorded");
    expect(text).toContain("XSS in search");
    expect(text).toContain("Decisions");
    expect(text).toContain("pivot to the API surface");
    expect(text).toContain("Notes");
    expect(text).toContain("cookie is httpOnly");
    expect(text).toContain("Prior run closed");
    expect(text).toContain("found one high-sev XSS");
  });

  it("clips a huge tool output so the seed stays bounded", () => {
    const state = emptyState();
    const huge = "A".repeat(10_000);
    state.toolSteps = [{ tool: "run_command", result: { ok: true, output: huge } }];
    const text = (renderSeedMessages(state)[0].content[0] as { text: string }).text;
    expect(text).toContain("…");
    expect(text.length).toBeLessThan(huge.length);
  });

  it("is deterministic: same state → identical messages", () => {
    const state = emptyState();
    state.toolSteps = [{ tool: "fetch", arguments: { url: "/" }, turn: 1, result: { ok: true, output: "ok" } }];
    expect(renderSeedMessages(state)).toEqual(renderSeedMessages(state));
  });

  it("renders a faithful seed end-to-end from journal entries via rehydrateContext", () => {
    const entries: JournalEntry[] = [
      {
        schemaVersion: 1,
        id: "e0",
        runId: "run-x",
        seq: 0,
        timestamp: "2026-05-28T00:00:00.000Z",
        kind: "tool_call",
        tool: "fetch",
        arguments: { url: "/login" },
        turn: 1,
        callId: "c1",
      } as JournalEntry,
      {
        schemaVersion: 1,
        id: "e1",
        runId: "run-x",
        seq: 1,
        timestamp: "2026-05-28T00:00:01.000Z",
        kind: "tool_result",
        tool: "fetch",
        ok: true,
        output: "200 OK",
        turn: 1,
        callId: "c1",
      } as JournalEntry,
    ];
    const messages = renderSeedMessages(rehydrateContext(entries));
    expect(messages).toHaveLength(1);
    const text = (messages[0].content[0] as { text: string }).text;
    expect(text).toContain("fetch");
    expect(text).toContain("/login");
    expect(text).toContain("200 OK");
  });
});
