import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createJournalWriter,
  loadJournal,
  rehydrateContext,
  type JournalEntry,
} from "./index.js";
import { createShadowJournal } from "./shadow.js";

let tmpRoot: string;
let id = 0;

function nextId(): string {
  id += 1;
  return `entry-${id}`;
}

function fixedNow(): Date {
  return new Date("2026-05-28T12:00:00.000Z");
}

beforeEach(() => {
  tmpRoot = mkdtempSync(join(tmpdir(), "0sec-journal-rehydrate-"));
  id = 0;
});

afterEach(() => {
  rmSync(tmpRoot, { recursive: true, force: true });
});

// ── Monotonic seq ──

describe("journal seq assignment", () => {
  it("assigns monotonic zero-based seq across appends", () => {
    const writer = createJournalWriter({ runId: "run-seq", rootDir: tmpRoot, now: fixedNow, idFactory: nextId });
    const a = writer.append({ kind: "note", text: "first" });
    const b = writer.append({ kind: "note", text: "second" });
    const c = writer.append({ kind: "note", text: "third" });
    expect(a.seq).toBe(0);
    expect(b.seq).toBe(1);
    expect(c.seq).toBe(2);
  });

  it("continues seq numbering when a second writer reopens an existing run", () => {
    const w1 = createJournalWriter({ runId: "run-resume", rootDir: tmpRoot, idFactory: nextId });
    w1.append({ kind: "note", text: "a" });
    w1.append({ kind: "note", text: "b" });

    // A fresh writer (simulating resume) must not collide with existing seqs.
    const w2 = createJournalWriter({ runId: "run-resume", rootDir: tmpRoot, idFactory: nextId });
    const resumed = w2.append({ kind: "note", text: "c" });
    expect(resumed.seq).toBe(2);

    const entries = w2.load();
    expect(entries.map((e) => e.seq)).toEqual([0, 1, 2]);
  });

  it("honours a caller-supplied seq without moving the counter backwards", () => {
    const writer = createJournalWriter({ runId: "run-explicit", rootDir: tmpRoot, idFactory: nextId });
    writer.append({ kind: "note", text: "auto-0" }); // seq 0
    const pinned = writer.append({ kind: "note", text: "pinned", seq: 10 });
    const next = writer.append({ kind: "note", text: "after" });
    expect(pinned.seq).toBe(10);
    expect(next.seq).toBe(11);
  });
});

// ── New per-step entry kinds round-trip ──

describe("per-step entry kinds round-trip (#494)", () => {
  it("writes and reads tool_call / tool_result / hypothesis / note entries", () => {
    const writer = createJournalWriter({ runId: "run-kinds", rootDir: tmpRoot, now: fixedNow, idFactory: nextId });
    writer.append({ kind: "tool_call", tool: "read_file", arguments: { path: "/etc/passwd" }, turn: 1, callId: "c1" });
    writer.append({ kind: "tool_result", tool: "read_file", ok: true, output: "root:x:0:0", turn: 1, callId: "c1" });
    writer.append({ kind: "hypothesis", statement: "SQLi in /login", confidence: 0.6, status: "open", turn: 2 });
    writer.append({ kind: "note", text: "remember the demo creds", turn: 2 });

    const entries = loadJournal({ runId: "run-kinds", rootDir: tmpRoot });
    expect(entries.map((e) => e.kind)).toEqual(["tool_call", "tool_result", "hypothesis", "note"]);
    const [call, result, hyp, note] = entries;
    expect(call).toMatchObject({ kind: "tool_call", tool: "read_file", callId: "c1" });
    expect(result).toMatchObject({ kind: "tool_result", tool: "read_file", ok: true, callId: "c1" });
    expect(hyp).toMatchObject({ kind: "hypothesis", statement: "SQLi in /login", confidence: 0.6, status: "open" });
    expect(note).toMatchObject({ kind: "note", text: "remember the demo creds" });
  });
});

// ── rehydrateContext ──

function makeEntry(partial: Partial<JournalEntry> & { kind: string }): JournalEntry {
  return {
    schemaVersion: 1,
    id: nextId(),
    runId: "run-x",
    timestamp: "2026-05-28T12:00:00.000Z",
    ...partial,
  } as JournalEntry;
}

describe("rehydrateContext", () => {
  it("returns an empty state for no entries", () => {
    const state = rehydrateContext([]);
    expect(state).toMatchObject({
      runId: null,
      lastSeq: -1,
      toolSteps: [],
      hypotheses: [],
      findings: [],
      notes: [],
      decisions: [],
      done: false,
      summary: "",
    });
  });

  it("joins tool_result entries to their tool_call by callId", () => {
    const entries: JournalEntry[] = [
      makeEntry({ kind: "tool_call", tool: "run_command", arguments: { cmd: "ls" }, callId: "c1", seq: 0 } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "tool_result", tool: "run_command", ok: true, output: "a\nb", callId: "c1", seq: 1 } as Partial<JournalEntry> & { kind: string }),
    ];
    const state = rehydrateContext(entries);
    expect(state.runId).toBe("run-x");
    expect(state.lastSeq).toBe(1);
    expect(state.toolSteps).toHaveLength(1);
    expect(state.toolSteps[0]).toMatchObject({
      tool: "run_command",
      arguments: { cmd: "ls" },
      result: { ok: true, output: "a\nb" },
    });
  });

  it("falls back to latest unresolved same-tool call when callId is absent", () => {
    const entries: JournalEntry[] = [
      makeEntry({ kind: "tool_call", tool: "http_request", arguments: { url: "/a" }, seq: 0 } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "tool_result", tool: "http_request", ok: false, error: "404", seq: 1 } as Partial<JournalEntry> & { kind: string }),
    ];
    const state = rehydrateContext(entries);
    expect(state.toolSteps).toHaveLength(1);
    expect(state.toolSteps[0].result).toMatchObject({ ok: false, error: "404" });
  });

  it("orders by seq even when entries arrive out of order", () => {
    const entries: JournalEntry[] = [
      makeEntry({ kind: "note", text: "third", seq: 2 } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "note", text: "first", seq: 0 } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "note", text: "second", seq: 1 } as Partial<JournalEntry> & { kind: string }),
    ];
    const state = rehydrateContext(entries);
    expect(state.notes).toEqual(["first", "second", "third"]);
  });

  it("uses array order when seq is absent (legacy journals)", () => {
    const entries: JournalEntry[] = [
      makeEntry({ kind: "note", text: "one" } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "note", text: "two" } as Partial<JournalEntry> & { kind: string }),
    ];
    const state = rehydrateContext(entries);
    expect(state.notes).toEqual(["one", "two"]);
    expect(state.lastSeq).toBe(-1);
  });

  it("collapses repeated hypotheses keeping latest status, first-seen order", () => {
    const entries: JournalEntry[] = [
      makeEntry({ kind: "hypothesis", statement: "IDOR on /users", status: "open", seq: 0 } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "hypothesis", statement: "XSS on /search", status: "open", seq: 1 } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "hypothesis", statement: "IDOR on /users", status: "confirmed", confidence: 0.9, seq: 2 } as Partial<JournalEntry> & { kind: string }),
    ];
    const state = rehydrateContext(entries);
    expect(state.hypotheses).toHaveLength(2);
    expect(state.hypotheses[0]).toMatchObject({ statement: "IDOR on /users", status: "confirmed", confidence: 0.9 });
    expect(state.hypotheses[1]).toMatchObject({ statement: "XSS on /search", status: "open" });
  });

  it("collects findings, decisions, observations, and a terminal done", () => {
    const entries: JournalEntry[] = [
      makeEntry({ kind: "finding", finding: { title: "RCE", severity: "critical" }, seq: 0 } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "decision", decision: "pivot to source review", seq: 1 } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "observation", source: "recon", summary: "found /admin", seq: 2 } as Partial<JournalEntry> & { kind: string }),
      makeEntry({ kind: "done", status: "success", summary: "exploited", seq: 3 } as Partial<JournalEntry> & { kind: string }),
    ];
    const state = rehydrateContext(entries);
    expect(state.findings).toEqual([{ title: "RCE", severity: "critical" }]);
    expect(state.decisions).toEqual(["pivot to source review"]);
    expect(state.notes).toEqual(["found /admin"]);
    expect(state.done).toBe(true);
    expect(state.summary).toBe("exploited");
  });

  it("tolerates malformed / unknown entries without throwing", () => {
    const entries = [
      null,
      undefined,
      {},
      { kind: 123 },
      { kind: "tool_call" }, // missing tool
      { kind: "totally_unknown_kind", seq: 5 },
      makeEntry({ kind: "note", text: "survivor", seq: 6 } as Partial<JournalEntry> & { kind: string }),
    ] as unknown as JournalEntry[];
    const state = rehydrateContext(entries);
    expect(state.notes).toEqual(["survivor"]);
    expect(state.lastSeq).toBe(6);
  });

  it("round-trips through the on-disk writer then rehydrates", () => {
    const writer = createJournalWriter({ runId: "run-rt", rootDir: tmpRoot, now: fixedNow, idFactory: nextId });
    writer.append({ kind: "tool_call", tool: "read_file", arguments: { path: "app.js" }, callId: "k1" });
    writer.append({ kind: "tool_result", tool: "read_file", ok: true, output: "console.log(1)", callId: "k1" });
    writer.append({ kind: "hypothesis", statement: "prototype pollution", status: "open" });
    writer.append({ kind: "finding", finding: { title: "proto pollution", severity: "high" } });
    writer.append({ kind: "done", status: "success", summary: "confirmed" });

    const entries = loadJournal({ runId: "run-rt", rootDir: tmpRoot });
    const state = rehydrateContext(entries);
    expect(state.toolSteps[0].result).toMatchObject({ ok: true, output: "console.log(1)" });
    expect(state.hypotheses[0].statement).toBe("prototype pollution");
    expect(state.findings).toEqual([{ title: "proto pollution", severity: "high" }]);
    expect(state.done).toBe(true);
    expect(state.summary).toBe("confirmed");
    expect(state.lastSeq).toBe(4);
  });
});

// ── Shadow journal ──

describe("createShadowJournal", () => {
  it("is a no-op (no I/O) when the feature flag is off", () => {
    const shadow = createShadowJournal({ runId: "run-off", rootDir: tmpRoot, enabled: false });
    expect(shadow.enabled).toBe(false);
    expect(() => shadow.append({ kind: "note", text: "should not write" })).not.toThrow();
    // No journal file should have been created.
    const entries = loadJournal({ runId: "run-off", rootDir: tmpRoot });
    expect(entries).toEqual([]);
  });

  it("writes entries when explicitly enabled", () => {
    const shadow = createShadowJournal({ runId: "run-on", rootDir: tmpRoot, enabled: true });
    expect(shadow.enabled).toBe(true);
    shadow.append({ kind: "tool_call", tool: "read_file", arguments: { path: "x" }, callId: "c1" });
    shadow.append({ kind: "tool_result", tool: "read_file", ok: true, output: "y", callId: "c1" });
    shadow.append({ kind: "done", status: "success", summary: "ok" });

    const entries = loadJournal({ runId: "run-on", rootDir: tmpRoot });
    expect(entries.map((e) => e.kind)).toEqual(["tool_call", "tool_result", "done"]);
    expect(entries.map((e) => e.seq)).toEqual([0, 1, 2]);
  });

  it("never throws even when the underlying writer would fail", () => {
    const shadow = createShadowJournal({
      runId: "run-fail",
      enabled: true,
      writerFactory: () => ({
        paths: { runDir: "/x", journalPath: "/x/journal.jsonl", artifactsDir: "/x/artifacts" },
        append() {
          throw new Error("disk full");
        },
        load() {
          return [];
        },
      }),
    });
    expect(shadow.enabled).toBe(true);
    expect(() => shadow.append({ kind: "note", text: "boom" })).not.toThrow();
  });

  it("degrades to a no-op when writer construction itself throws", () => {
    const shadow = createShadowJournal({
      runId: "run-ctor-fail",
      enabled: true,
      writerFactory: () => {
        throw new Error("cannot open run dir");
      },
    });
    expect(shadow.enabled).toBe(false);
    expect(() => shadow.append({ kind: "note", text: "noop" })).not.toThrow();
  });

  it("does not create a journal file path on disk when disabled", () => {
    createShadowJournal({ runId: "run-nofile", rootDir: tmpRoot, enabled: false });
    expect(() => readFileSync(join(tmpRoot, "run-nofile", "journal.jsonl"), "utf8")).toThrow();
  });
});
