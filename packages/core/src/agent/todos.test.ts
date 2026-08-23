/**
 * Tests for the structured TODOS / full-state plan (TodoWrite shape).
 *
 * The invariants under test: schema validation (empty content, cap, status
 * enum), full-REPLACE semantics + idempotency, grouping into phases with
 * per-phase and overall progress, the "Todos · done/total" summary line,
 * emit-on-change (and NOT on idempotent re-writes), and fail-soft behaviour
 * (a throwing emit sink never breaks a write).
 */

import { describe, it, expect, vi } from "vitest";
import {
  TodoTracker,
  validateUpdateTodosArgs,
  buildTodosPayload,
  MAX_TODOS,
  MAX_CONTENT_LEN,
  type TodoSnapshot,
} from "./todos.js";

describe("validateUpdateTodosArgs (schema)", () => {
  it("accepts a well-formed plan and defaults status to pending", () => {
    const r = validateUpdateTodosArgs({ todos: [{ content: "map the target" }] });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.todos).toEqual([{ content: "map the target", status: "pending" }]);
    }
  });

  it("rejects empty content", () => {
    const r = validateUpdateTodosArgs({ todos: [{ content: "   " }] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/content/i);
  });

  it("rejects content over the length cap", () => {
    const r = validateUpdateTodosArgs({
      todos: [{ content: "x".repeat(MAX_CONTENT_LEN + 1) }],
    });
    expect(r.ok).toBe(false);
  });

  it("rejects an invalid status value", () => {
    const r = validateUpdateTodosArgs({
      todos: [{ content: "do it", status: "blocked" }],
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/status/i);
  });

  it("enforces the item cap", () => {
    const todos = Array.from({ length: MAX_TODOS + 1 }, (_, i) => ({ content: `t${i}` }));
    const r = validateUpdateTodosArgs({ todos });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(new RegExp(`${MAX_TODOS}`));
  });

  it("accepts exactly the cap, and an empty plan (clear)", () => {
    const todos = Array.from({ length: MAX_TODOS }, (_, i) => ({ content: `t${i}` }));
    expect(validateUpdateTodosArgs({ todos }).ok).toBe(true);
    expect(validateUpdateTodosArgs({ todos: [] }).ok).toBe(true);
  });

  it("rejects a missing todos field", () => {
    expect(validateUpdateTodosArgs({}).ok).toBe(false);
  });

  it("normalizes a blank group to undefined and trims a real one", () => {
    const r = validateUpdateTodosArgs({
      todos: [
        { content: "a", group: "  " },
        { content: "b", group: "  Recon  " },
      ],
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.todos[0].group).toBeUndefined();
      expect(r.todos[1].group).toBe("Recon");
    }
  });

  it("strips unknown adjacent keys (id/title/detail)", () => {
    const r = validateUpdateTodosArgs({
      todos: [{ content: "a", id: "todo-99", title: "x", detail: "y" }],
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.todos[0]).toEqual({ content: "a", status: "pending" });
  });
});

function setFromRaw(tracker: TodoTracker, raw: unknown): TodoSnapshot {
  const v = validateUpdateTodosArgs(raw);
  if (!v.ok) throw new Error(v.error);
  return tracker.set(v.todos);
}

describe("TodoTracker — full replace + progress", () => {
  it("assigns deterministic position ids", () => {
    const t = new TodoTracker();
    setFromRaw(t, { todos: [{ content: "a" }, { content: "b" }] });
    expect(t.list().map((x) => x.id)).toEqual(["todo-1", "todo-2"]);
  });

  it("REPLACES the plan wholesale on each write", () => {
    const t = new TodoTracker();
    setFromRaw(t, { todos: [{ content: "a" }, { content: "b" }, { content: "c" }] });
    setFromRaw(t, { todos: [{ content: "only-one" }] });
    expect(t.list().map((x) => x.content)).toEqual(["only-one"]);
    expect(t.progress()).toEqual({ done: 0, total: 1 });
  });

  it("counts overall progress from completed status", () => {
    const t = new TodoTracker();
    setFromRaw(t, {
      todos: [
        { content: "a", status: "completed" },
        { content: "b", status: "in_progress" },
        { content: "c" },
      ],
    });
    expect(t.progress()).toEqual({ done: 1, total: 3 });
  });

  it("summaryLine is 'Todos · done/total', empty when no plan", () => {
    const t = new TodoTracker();
    expect(t.summaryLine()).toBe("");
    setFromRaw(t, {
      todos: [{ content: "a", status: "completed" }, { content: "b" }, { content: "c" }],
    });
    expect(t.summaryLine()).toBe("Todos · 1/3");
  });
});

describe("TodoTracker — grouping into phases", () => {
  it("buckets by group in first-appearance order with per-phase counts", () => {
    const t = new TodoTracker();
    setFromRaw(t, {
      todos: [
        { content: "scan", group: "Inspection", status: "completed" },
        { content: "read", group: "Inspection" },
        { content: "exploit", group: "Attack" },
      ],
    });
    const g = t.groups();
    expect(g.map((x) => x.group)).toEqual(["Inspection", "Attack"]);
    expect(g[0]).toMatchObject({ done: 1, total: 2 });
    expect(g[1]).toMatchObject({ done: 0, total: 1 });
  });

  it("collects ungrouped items under the '' label", () => {
    const t = new TodoTracker();
    setFromRaw(t, { todos: [{ content: "a" }, { content: "b", group: "P" }] });
    const g = t.groups();
    expect(g.map((x) => x.group)).toEqual(["", "P"]);
    expect(g[0].total).toBe(1);
  });
});

describe("TodoTracker — emit on change / idempotency", () => {
  it("emits once per real change and bumps revision", () => {
    const emit = vi.fn();
    const t = new TodoTracker({ emit });
    setFromRaw(t, { todos: [{ content: "a" }] });
    expect(emit).toHaveBeenCalledTimes(1);
    expect(t.revision).toBe(1);
    setFromRaw(t, { todos: [{ content: "a", status: "completed" }] });
    expect(emit).toHaveBeenCalledTimes(2);
    expect(t.revision).toBe(2);
  });

  it("does NOT emit or bump revision on an idempotent re-write", () => {
    const emit = vi.fn();
    const t = new TodoTracker({ emit });
    setFromRaw(t, { todos: [{ content: "a", group: "P", status: "in_progress" }] });
    expect(emit).toHaveBeenCalledTimes(1);
    setFromRaw(t, { todos: [{ content: "a", group: "P", status: "in_progress" }] });
    expect(emit).toHaveBeenCalledTimes(1);
    expect(t.revision).toBe(1);
  });

  it("is fail-soft: a throwing emit sink never breaks the write", () => {
    const t = new TodoTracker({
      emit: () => {
        throw new Error("render boom");
      },
    });
    expect(() => setFromRaw(t, { todos: [{ content: "a" }] })).not.toThrow();
    expect(t.progress()).toEqual({ done: 0, total: 1 });
  });
});

describe("buildTodosPayload", () => {
  it("flattens a snapshot to the event/DB shape", () => {
    const t = new TodoTracker();
    const snap = setFromRaw(t, {
      todos: [{ content: "a", group: "P", status: "completed" }, { content: "b" }],
    });
    const p = buildTodosPayload(snap);
    expect(p.done).toBe(1);
    expect(p.total).toBe(2);
    expect(p.line).toBe("Todos · 1/2");
    expect(p.revision).toBe(1);
    expect(p.todos[0]).toEqual({ id: "todo-1", content: "a", status: "completed", group: "P" });
    expect(p.todos[1]).toEqual({ id: "todo-2", content: "b", status: "pending" });
  });
});
