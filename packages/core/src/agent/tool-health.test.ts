import { describe, it, expect, vi } from "vitest";
import { ToolHealthTracker } from "./tool-health.js";

describe("ToolHealthTracker", () => {
  it("records distinct events and exposes them most-recent-first", () => {
    let t = 0;
    const tracker = new ToolHealthTracker({ now: () => ++t });
    tracker.record({ tool: "semgrep", category: "missing-binary", message: "not installed" });
    tracker.record({ tool: "run_command", category: "buffer-limit", message: "too big" });

    const list = tracker.list();
    expect(list).toHaveLength(2);
    // most-recent (highest lastSeen) first
    expect(list[0].tool).toBe("run_command");
    expect(list[1].tool).toBe("semgrep");
    expect(tracker.size).toBe(2);
    expect(tracker.isEmpty()).toBe(false);
  });

  it("dedups by (tool, category, message) and bumps count + lastSeen", () => {
    let t = 0;
    const tracker = new ToolHealthTracker({ now: () => ++t });
    tracker.record({ tool: "semgrep", category: "missing-binary", message: "not installed" });
    tracker.record({ tool: "semgrep", category: "missing-binary", message: "not installed" });
    tracker.record({ tool: "semgrep", category: "missing-binary", message: "not installed" });

    expect(tracker.size).toBe(1);
    const [event] = tracker.list();
    expect(event.count).toBe(3);
    expect(event.firstSeen).toBe(1);
    expect(event.lastSeen).toBe(3);
  });

  it("treats a different message/category/tool as a distinct event", () => {
    const tracker = new ToolHealthTracker();
    tracker.record({ tool: "npm", category: "wrong-lockfile", message: "a" });
    tracker.record({ tool: "npm", category: "wrong-lockfile", message: "b" });
    tracker.record({ tool: "npm", category: "policy-denied", message: "a" });
    tracker.record({ tool: "pnpm", category: "wrong-lockfile", message: "a" });
    expect(tracker.size).toBe(4);
  });

  it("emits once per NEW distinct event (not on dedup bumps)", () => {
    const emit = vi.fn();
    const tracker = new ToolHealthTracker({ emit });
    tracker.record({ tool: "nuclei", category: "missing-binary", message: "x" });
    tracker.record({ tool: "nuclei", category: "missing-binary", message: "x" });
    tracker.record({ tool: "nmap", category: "missing-binary", message: "y" });
    expect(emit).toHaveBeenCalledTimes(2);
  });

  it("is fail-soft: a throwing emit sink never propagates", () => {
    const tracker = new ToolHealthTracker({
      emit: () => {
        throw new Error("sink boom");
      },
    });
    expect(() => tracker.record({ tool: "x", category: "error", message: "y" })).not.toThrow();
    expect(tracker.size).toBe(1);
  });

  it("fills in a remedy from a later record when the first lacked one", () => {
    const tracker = new ToolHealthTracker();
    tracker.record({ tool: "semgrep", category: "missing-binary", message: "gone" });
    tracker.record({ tool: "semgrep", category: "missing-binary", message: "gone", remedy: "pip install semgrep" });
    expect(tracker.list()[0].remedy).toBe("pip install semgrep");
  });

  it("summary() rolls up counts, categories, and missing binaries", () => {
    const tracker = new ToolHealthTracker();
    tracker.record({ tool: "semgrep", category: "missing-binary", message: "m1" });
    tracker.record({ tool: "nuclei", category: "missing-binary", message: "m2" });
    tracker.record({ tool: "run_command", category: "buffer-limit", message: "b1" });
    tracker.record({ tool: "run_command", category: "buffer-limit", message: "b1" }); // dedup bump

    const summary = tracker.summary();
    expect(summary.total).toBe(3);
    expect(summary.occurrences).toBe(4);
    expect(summary.byCategory["missing-binary"]).toBe(2);
    expect(summary.byCategory["buffer-limit"]).toBe(1);
    expect(summary.missing).toEqual(["nuclei", "semgrep"]);
  });

  it("summaryLine() groups tools per category in a stable order", () => {
    const tracker = new ToolHealthTracker();
    tracker.record({ tool: "run_command", category: "wrong-lockfile", message: "w" });
    tracker.record({ tool: "semgrep", category: "missing-binary", message: "m" });
    tracker.record({ tool: "nuclei", category: "missing-binary", message: "n" });

    const line = tracker.summaryLine();
    // missing-binary comes before wrong-lockfile in the canonical order.
    expect(line).toBe("3 tool issues (missing: nuclei, semgrep; wrong-lockfile: run_command)");
  });

  it("summaryLine() is empty and summary().total is 0 when nothing recorded", () => {
    const tracker = new ToolHealthTracker();
    expect(tracker.summaryLine()).toBe("");
    expect(tracker.summary().total).toBe(0);
    expect(tracker.isEmpty()).toBe(true);
  });

  it("uses the singular noun for a single issue", () => {
    const tracker = new ToolHealthTracker();
    tracker.record({ tool: "semgrep", category: "missing-binary", message: "m" });
    expect(tracker.summaryLine()).toBe("1 tool issue (missing: semgrep)");
  });

  it("reset() clears recorded events", () => {
    const tracker = new ToolHealthTracker();
    tracker.record({ tool: "x", category: "error", message: "y" });
    tracker.reset();
    expect(tracker.isEmpty()).toBe(true);
  });
});
