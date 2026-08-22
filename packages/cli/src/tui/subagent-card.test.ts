import { describe, expect, it } from "vitest";
import { parseSubagentCard, reduceActiveSubagents } from "./subagent-card.js";

describe("parseSubagentCard", () => {
  it("returns card data for a successful completed subagent", () => {
    const card = parseSubagentCard(true, {
      turns: 12,
      findings: 3,
      summary: "Found SQLi in /api/users",
      done: true,
    });
    expect(card).toEqual({
      outcome: "completed",
      turns: 12,
      findings: 3,
      summary: "Found SQLi in /api/users",
    });
  });

  it("returns card data for a successful but incomplete subagent", () => {
    const card = parseSubagentCard(true, {
      turns: 25,
      findings: 0,
      summary: "Max turns reached, partial progress",
      done: false,
    });
    expect(card).toEqual({
      outcome: "failed",
      turns: 25,
      findings: 0,
      summary: "Max turns reached, partial progress",
    });
  });

  it("returns card data for a failed subagent with error", () => {
    const card = parseSubagentCard(false, null, "No API key available");
    expect(card).toEqual({
      outcome: "failed",
      turns: 0,
      findings: 0,
      summary: "",
      error: "No API key available",
    });
  });

  it("returns null for a non-subagent successful tool result", () => {
    expect(parseSubagentCard(true, "some plain string result")).toBeNull();
    expect(parseSubagentCard(true, 42)).toBeNull();
    expect(parseSubagentCard(true, null)).toBeNull();
  });

  it("returns null when output shape is wrong (missing turns)", () => {
    expect(parseSubagentCard(true, { findings: 1, summary: "x", done: true })).toBeNull();
  });

  it("returns null when output shape is wrong (non-number turns)", () => {
    expect(parseSubagentCard(true, { turns: "eight", findings: 1, summary: "x", done: true })).toBeNull();
  });

  it("returns null when output shape is wrong (non-string summary)", () => {
    expect(parseSubagentCard(true, { turns: 8, findings: 1, summary: 123, done: true })).toBeNull();
  });

  it("rejects negative or non-integer counters", () => {
    expect(parseSubagentCard(true, { turns: -1, findings: 0, summary: "x", done: true })).toBeNull();
    expect(parseSubagentCard(true, { turns: 1.5, findings: 0, summary: "x", done: true })).toBeNull();
    expect(parseSubagentCard(true, { turns: 1, findings: -1, summary: "x", done: true })).toBeNull();
  });

  it("trims whitespace from summary", () => {
    const card = parseSubagentCard(true, {
      turns: 5,
      findings: 1,
      summary: "  found it  ",
      done: true,
    });
    expect(card?.summary).toBe("found it");
  });

  it("returns card with error from non-success with empty error string", () => {
    const card = parseSubagentCard(false, null, "");
    expect(card).toEqual({
      outcome: "failed",
      turns: 0,
      findings: 0,
      summary: "",
      error: "",
    });
  });

  it("falls back to unknown error when error is missing", () => {
    const card = parseSubagentCard(false, null, undefined);
    expect(card).toEqual({
      outcome: "failed",
      turns: 0,
      findings: 0,
      summary: "",
      error: "unknown error",
    });
  });
});

describe("reduceActiveSubagents", () => {
  const qEvent = {
    agent_id: "a1",
    parent_scan_id: "scan-x",
    status: "queued" as const,
    task: "SQLi table enumeration",
    max_turns: 8,
  };

  const rEvent = {
    agent_id: "a1",
    parent_scan_id: "scan-x",
    status: "running" as const,
    task: "SQLi table enumeration",
    max_turns: 8,
    turns: 2,
  };

  const cEvent = {
    agent_id: "a1",
    parent_scan_id: "scan-x",
    status: "completed" as const,
    task: "SQLi table enumeration",
    max_turns: 8,
    turns: 6,
    findings: 2,
    summary: "found tables",
  };

  const fEvent = {
    agent_id: "a1",
    parent_scan_id: "scan-x",
    status: "failed" as const,
    task: "SQLi table enumeration",
    max_turns: 8,
    turns: 4,
    error: "API key expired",
  };

  it("inserts a queued event into empty state", () => {
    const result = reduceActiveSubagents({}, qEvent);
    expect(Object.keys(result)).toHaveLength(1);
    expect(result.a1?.status).toBe("queued");
  });

  it("promotes queued to running", () => {
    const result = reduceActiveSubagents({ a1: qEvent }, rEvent);
    expect(Object.keys(result)).toHaveLength(1);
    expect(result.a1?.status).toBe("running");
    expect(result.a1?.turns).toBe(2);
  });

  it("removes agent on completed", () => {
    const state = { a1: rEvent, a2: { ...rEvent, agent_id: "a2", task: "XSS probe" } };
    const result = reduceActiveSubagents(state, cEvent);
    expect(Object.keys(result)).toHaveLength(1);
    expect(result.a1).toBeUndefined();
    expect(result.a2).toBeDefined();
  });

  it("removes agent on failed", () => {
    const state = { a1: rEvent };
    const result = reduceActiveSubagents(state, fEvent);
    expect(Object.keys(result)).toHaveLength(0);
  });

  it("upserts a second agent alongside the first", () => {
    const state = { a1: rEvent };
    const second = { ...qEvent, agent_id: "a2", task: "XSS probe" };
    const result = reduceActiveSubagents(state, second);
    expect(Object.keys(result)).toHaveLength(2);
    expect(result.a2?.status).toBe("queued");
  });

  it("returns a new object (not mutated)", () => {
    const state = { a1: qEvent };
    const result = reduceActiveSubagents(state, rEvent);
    expect(result).not.toBe(state);
    expect(state.a1?.status).toBe("queued");
  });
});