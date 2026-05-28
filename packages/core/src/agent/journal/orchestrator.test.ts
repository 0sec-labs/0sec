import { describe, expect, it } from "vitest";
import {
  buildSpecialistDispatch,
  selectNextDispatch,
  summarizeForOrchestrator,
  SPECIALIST_PIPELINE,
  type OrchestratorView,
} from "./orchestrator.js";
import type { JournalEntry } from "./types.js";

let seqCounter = 0;
function entry(partial: Partial<JournalEntry> & { kind: JournalEntry["kind"] }): JournalEntry {
  return {
    schemaVersion: 1,
    id: `e${seqCounter}`,
    runId: "run-1",
    seq: seqCounter++,
    timestamp: "2026-05-28T00:00:00.000Z",
    ...partial,
  } as JournalEntry;
}

function reset() {
  seqCounter = 0;
}

describe("summarizeForOrchestrator", () => {
  it("returns an empty view for an empty / non-array journal", () => {
    expect(summarizeForOrchestrator([])).toMatchObject({
      runId: null,
      lastSeq: -1,
      dispatched: [],
      findingCount: 0,
      done: false,
    });
    // total: never throws on garbage
    expect(summarizeForOrchestrator(null as unknown as JournalEntry[]).findingCount).toBe(0);
    expect(summarizeForOrchestrator([null, 42, { kind: 5 }] as unknown as JournalEntry[]).findingCount).toBe(0);
  });

  it("collapses dispatches in first-dispatch order and tracks the last", () => {
    reset();
    const view = summarizeForOrchestrator([
      entry({ kind: "dispatch", targetAgent: "recon", objective: "x" }),
      entry({ kind: "dispatch", targetAgent: "harness-builder", objective: "y" }),
      entry({ kind: "dispatch", targetAgent: "recon", objective: "again" }),
    ]);
    expect(view.dispatched).toEqual(["recon", "harness-builder"]);
    expect(view.lastDispatched).toBe("recon");
  });

  it("ignores dispatches to non-specialist targetAgents (e.g. legacy roles)", () => {
    reset();
    const view = summarizeForOrchestrator([
      entry({ kind: "dispatch", targetAgent: "discovery", objective: "legacy" }),
      entry({ kind: "dispatch", targetAgent: "recon", objective: "x" }),
    ]);
    expect(view.dispatched).toEqual(["recon"]);
  });

  it("counts findings and extracts bounded titles, never raw payloads", () => {
    reset();
    const view = summarizeForOrchestrator([
      entry({ kind: "finding", finding: { title: "SQLi in /search", exploit: "A".repeat(5000) } }),
      entry({ kind: "finding", finding: { name: "XSS" } }),
      entry({ kind: "finding", finding: { foo: 1, bar: 2 } }),
    ]);
    expect(view.findingCount).toBe(3);
    expect(view.findingTitles[0]).toBe("SQLi in /search");
    expect(view.findingTitles[1]).toBe("XSS");
    // No raw exploit payload leaks into the router's view.
    expect(view.findingTitles.join(" ")).not.toContain("AAAA");
    expect(view.findingTitles[2]).toContain("finding{");
  });

  it("collapses hypotheses by statement keeping the latest status", () => {
    reset();
    const view = summarizeForOrchestrator([
      entry({ kind: "hypothesis", statement: "idor on /user", status: "open" }),
      entry({ kind: "hypothesis", statement: "idor on /user", status: "confirmed" }),
      entry({ kind: "hypothesis", statement: "race in upload", status: "refuted" }),
    ]);
    expect(view.hypotheses).toEqual({ open: 0, confirmed: 1, refuted: 1, abandoned: 0 });
  });

  it("records decisions, errors, and a terminal done verdict", () => {
    reset();
    const view = summarizeForOrchestrator([
      entry({ kind: "decision", decision: "focus on the auth flow" }),
      entry({ kind: "error", message: "tool crashed" }),
      entry({ kind: "error", message: "again" }),
      entry({ kind: "done", status: "success", summary: "reproduced" }),
    ]);
    expect(view.decisions).toEqual(["focus on the auth flow"]);
    expect(view.errorCount).toBe(2);
    expect(view.done).toBe(true);
    expect(view.doneStatus).toBe("success");
    expect(view.summary).toBe("reproduced");
  });

  it("orders by seq, not file order, and excludes per-step kinds", () => {
    reset();
    // Deliberately out-of-order seqs + per-step noise the router must ignore.
    const view = summarizeForOrchestrator([
      entry({ kind: "tool_call", tool: "fetch", seq: 5 } as Partial<JournalEntry> & { kind: "tool_call" }),
      entry({ kind: "dispatch", targetAgent: "harness-builder", objective: "y", seq: 3 } as Partial<JournalEntry> & { kind: "dispatch" }),
      entry({ kind: "dispatch", targetAgent: "recon", objective: "x", seq: 1 } as Partial<JournalEntry> & { kind: "dispatch" }),
    ]);
    // recon (seq 1) before harness-builder (seq 3); tool_call contributes nothing.
    expect(view.dispatched).toEqual(["recon", "harness-builder"]);
    expect(view.lastSeq).toBe(5);
  });
});

function viewWith(partial: Partial<OrchestratorView>): OrchestratorView {
  return {
    runId: "run-1",
    lastSeq: 0,
    dispatched: [],
    lastDispatched: null,
    findingCount: 0,
    findingTitles: [],
    decisions: [],
    hypotheses: { open: 0, confirmed: 0, refuted: 0, abandoned: 0 },
    errorCount: 0,
    done: false,
    doneStatus: null,
    summary: "",
    ...partial,
  };
}

describe("selectNextDispatch — picks the correct specialist for canned journal states", () => {
  it("dispatches recon first on a fresh run", () => {
    const d = selectNextDispatch(viewWith({}));
    expect(d).toMatchObject({ action: "dispatch", role: "recon" });
  });

  it("advances to harness-builder after recon ran with no finding", () => {
    const d = selectNextDispatch(viewWith({ dispatched: ["recon"], lastDispatched: "recon" }));
    expect(d).toMatchObject({ action: "dispatch", role: "harness-builder" });
  });

  it("advances to exploit-writer after recon + harness-builder ran", () => {
    const d = selectNextDispatch(
      viewWith({ dispatched: ["recon", "harness-builder"], lastDispatched: "harness-builder" }),
    );
    expect(d).toMatchObject({ action: "dispatch", role: "exploit-writer" });
  });

  it("dispatches the validator the moment a finding exists, jumping the pipeline", () => {
    const d = selectNextDispatch(viewWith({ dispatched: ["recon"], findingCount: 1 }));
    expect(d).toMatchObject({ action: "dispatch", role: "validator" });
  });

  it("stops with reason 'validated' once the validator has run against findings", () => {
    const d = selectNextDispatch(
      viewWith({ dispatched: ["recon", "exploit-writer", "validator"], findingCount: 2, hypotheses: { open: 0, confirmed: 2, refuted: 0, abandoned: 0 } }),
    );
    expect(d).toMatchObject({ action: "stop", reason: "validated" });
    if (d.action === "stop") expect(d.rationale).toContain("confirmed");
  });

  it("stops with reason 'done' when a terminal entry already closed the run", () => {
    const d = selectNextDispatch(viewWith({ done: true, doneStatus: "failed", summary: "gave up" }));
    expect(d).toMatchObject({ action: "stop", reason: "done" });
  });

  it("stops with reason 'pipeline-exhausted' when every specialist ran with no finding", () => {
    const d = selectNextDispatch(
      viewWith({ dispatched: ["recon", "harness-builder", "exploit-writer"], findingCount: 0 }),
    );
    expect(d).toMatchObject({ action: "stop", reason: "pipeline-exhausted" });
  });

  it("does not re-dispatch a specialist that already ran (no infinite loop on errors)", () => {
    const d = selectNextDispatch(
      viewWith({ dispatched: ["recon"], lastDispatched: "recon", errorCount: 9 }),
    );
    // recon erred repeatedly but we advance rather than re-dispatch it.
    expect(d).toMatchObject({ action: "dispatch", role: "harness-builder" });
  });

  it("is deterministic: same view → same decision", () => {
    const v = viewWith({ dispatched: ["recon"], findingCount: 1 });
    expect(selectNextDispatch(v)).toEqual(selectNextDispatch(v));
  });
});

describe("end-to-end: summarize → select on a canned journal", () => {
  it("routes a real journal slice through to the validator after a finding", () => {
    reset();
    const journal: JournalEntry[] = [
      entry({ kind: "dispatch", targetAgent: "recon", objective: "enumerate" }),
      entry({ kind: "observation", source: "scan", summary: "found /admin" } as Partial<JournalEntry> & { kind: "observation" }),
      entry({ kind: "hypothesis", statement: "idor on /admin", status: "open" }),
      entry({ kind: "dispatch", targetAgent: "exploit-writer", objective: "exploit" }),
      entry({ kind: "finding", finding: { title: "IDOR on /admin" } }),
    ];
    const view = summarizeForOrchestrator(journal);
    const decision = selectNextDispatch(view);
    expect(decision).toMatchObject({ action: "dispatch", role: "validator" });

    const dispatch = buildSpecialistDispatch(decision, journal, { rolePrompt: "validate findings" });
    expect(dispatch).not.toBeNull();
    expect(dispatch?.role).toBe("validator");
    expect(dispatch?.rolePrompt).toBe("validate findings");
    // The specialist gets the whole run to rehydrate from by default.
    expect(dispatch?.journalSlice).toHaveLength(journal.length);
  });

  it("buildSpecialistDispatch returns null for a stop decision", () => {
    const stop = selectNextDispatch(viewWith({ done: true }));
    expect(buildSpecialistDispatch(stop, [])).toBeNull();
  });
});

describe("SPECIALIST_PIPELINE", () => {
  it("is the canonical four-stage order", () => {
    expect(SPECIALIST_PIPELINE).toEqual(["recon", "harness-builder", "exploit-writer", "validator"]);
  });
});
