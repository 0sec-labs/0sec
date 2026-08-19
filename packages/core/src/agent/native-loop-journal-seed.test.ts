import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runNativeAgentLoop } from "./native-loop.js";
import { createJournalWriter } from "./journal/index.js";
import type {
  NativeRuntime,
  NativeRuntimeResult,
  NativeMessage,
  NativeToolDef,
} from "../runtime/types.js";

// ── Test scaffolding ──
//
// `runNativeAgentLoop` calls `loadJournal({ runId: config.scanId })` with no
// rootDir override, so the journal it reads resolves to
// `~/.pwnkit/runs/<scanId>/journal.jsonl`. We point HOME at a temp dir for the
// duration of each test so the loop reads OUR journal, not the real one, and
// nothing leaks between tests.

const REHYDRATE_ENV = "PWNKIT_FEATURE_JOURNAL_REHYDRATE";

let tmpHome: string;
let savedHome: string | undefined;
let savedRehydrate: string | undefined;

beforeEach(() => {
  tmpHome = mkdtempSync(join(tmpdir(), "pwnkit-seed-home-"));
  savedHome = process.env.HOME;
  savedRehydrate = process.env[REHYDRATE_ENV];
  process.env.HOME = tmpHome;
  // Default the flag OFF for every test; tests that exercise ON set it.
  delete process.env[REHYDRATE_ENV];
});

afterEach(() => {
  rmSync(tmpHome, { recursive: true, force: true });
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  if (savedRehydrate === undefined) delete process.env[REHYDRATE_ENV];
  else process.env[REHYDRATE_ENV] = savedRehydrate;
});

/** Journal root that matches what `defaultJournalRootDir()` will resolve to. */
function journalRoot(): string {
  // Sanity: HOME really is our temp dir for this test.
  expect(homedir()).toBe(tmpHome);
  return join(tmpHome, ".pwnkit", "runs");
}

/**
 * A mock runtime that records every `messages` array it is handed and returns
 * a single `done` tool call so the loop terminates on turn 1.
 */
function recordingRuntime(): { runtime: NativeRuntime; seenMessages: NativeMessage[][] } {
  const seenMessages: NativeMessage[][] = [];
  const runtime: NativeRuntime = {
    type: "api" as const,
    async executeNative(
      _system: string,
      messages: NativeMessage[],
      _tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      // Snapshot the messages the loop seeded itself with on the first call.
      seenMessages.push(JSON.parse(JSON.stringify(messages)) as NativeMessage[]);
      return {
        content: [{ type: "tool_use", id: "tc-done", name: "done", input: { summary: "ok" } }],
        stopReason: "tool_use",
        durationMs: 1,
      };
    },
    async isAvailable() {
      return true;
    },
  };
  return { runtime, seenMessages };
}

function baseConfig(scanId: string) {
  return {
    role: "discovery" as const,
    systemPrompt: "test",
    tools: [],
    maxTurns: 5,
    target: "https://example.com",
    scanId,
  };
}

/** Write a small, valid journal with a tool_call/tool_result and a finding. */
function writeJournal(scanId: string): void {
  const writer = createJournalWriter({ runId: scanId, rootDir: journalRoot() });
  writer.append({ kind: "tool_call", tool: "fetch", arguments: { url: "/admin" }, turn: 2, callId: "c1" });
  writer.append({ kind: "tool_result", tool: "fetch", ok: true, output: "200 OK admin panel", turn: 2, callId: "c1" });
  writer.append({ kind: "finding", finding: { id: "f1", title: "Exposed admin", severity: "high" } });
}

describe("native-loop journal-rehydrate seeding (#494 slice 2)", () => {
  it("flag OFF: fresh run is seeded with the initial prompt (byte-equivalent to today)", async () => {
    const { runtime, seenMessages } = recordingRuntime();
    await runNativeAgentLoop({ config: baseConfig("scan-off-fresh"), runtime, db: null });

    expect(seenMessages.length).toBeGreaterThan(0);
    const first = seenMessages[0];
    expect(first).toHaveLength(1);
    expect(first[0].role).toBe("user");
    const text = (first[0].content[0] as { text: string }).text;
    expect(text).toContain("You are a discovery agent for pwnkit");
    expect(text).toContain("Scan ID: scan-off-fresh");
    // No journal section leaked in.
    expect(text).not.toContain("Execution journal");
  });

  it("flag OFF: an existing journal is IGNORED — seeding is identical to no journal", async () => {
    writeJournal("scan-off-with-journal");

    const { runtime, seenMessages } = recordingRuntime();
    await runNativeAgentLoop({ config: baseConfig("scan-off-with-journal"), runtime, db: null });

    const text = (seenMessages[0][0].content[0] as { text: string }).text;
    expect(text).toContain("You are a discovery agent for pwnkit");
    expect(text).not.toContain("Execution journal");
    expect(text).not.toContain("Exposed admin");
  });

  it("flag OFF seeding is byte-equivalent regardless of whether a journal exists", async () => {
    // Fresh, no journal.
    const a = recordingRuntime();
    await runNativeAgentLoop({ config: baseConfig("scan-eq"), runtime: a.runtime, db: null });

    // Same scanId-shaped config, but with a journal on disk. OFF must ignore it.
    writeJournal("scan-eq");
    const b = recordingRuntime();
    await runNativeAgentLoop({ config: baseConfig("scan-eq"), runtime: b.runtime, db: null });

    expect(b.seenMessages[0]).toEqual(a.seenMessages[0]);
  });

  it("flag ON with a written journal: context is seeded from rehydrateContext", async () => {
    process.env[REHYDRATE_ENV] = "1";
    writeJournal("scan-on-journal");

    const { runtime, seenMessages } = recordingRuntime();
    const onEvent = vi.fn();
    const state = await runNativeAgentLoop({
      config: baseConfig("scan-on-journal"),
      runtime,
      db: null,
      onEvent,
    });

    const text = (seenMessages[0][0].content[0] as { text: string }).text;
    expect(text).toContain("Execution journal");
    expect(text).toContain("fetch");
    expect(text).toContain("/admin");
    expect(text).toContain("200 OK admin panel");
    expect(text).toContain("Exposed admin");
    // It must NOT also push the fresh initial prompt.
    expect(text).not.toContain("You are a discovery agent for pwnkit");

    // turnCount continues from the journal's highest tool-step turn (2).
    expect(state.turnCount).toBeGreaterThanOrEqual(2);
    // Findings recovered from the journal land on the loop state.
    expect(state.findings.some((f) => (f as { title?: string }).title === "Exposed admin")).toBe(true);

    // A rehydration event was emitted, no fallback event.
    const types = onEvent.mock.calls.map((c) => c[0]);
    expect(types).toContain("journal_rehydrated");
    expect(types).not.toContain("journal_rehydrate_fallback");
  });

  it("flag ON with NO journal (fresh run): falls through to the normal initial prompt", async () => {
    process.env[REHYDRATE_ENV] = "1";

    const { runtime, seenMessages } = recordingRuntime();
    const onEvent = vi.fn();
    await runNativeAgentLoop({
      config: baseConfig("scan-on-missing"),
      runtime,
      db: null,
      onEvent,
    });

    const text = (seenMessages[0][0].content[0] as { text: string }).text;
    expect(text).toContain("You are a discovery agent for pwnkit");
    expect(text).not.toContain("Execution journal");

    // Missing journal is the fresh-run case, not a corruption — no fallback event.
    const types = onEvent.mock.calls.map((c) => c[0]);
    expect(types).not.toContain("journal_rehydrate_fallback");
    expect(types).not.toContain("journal_rehydrated");
  });

  it("flag ON with a CORRUPT journal: falls back gracefully and logs the fallback", async () => {
    process.env[REHYDRATE_ENV] = "1";

    // Hand-write a journal with a complete-but-invalid JSON line so loadJournal
    // throws (a trailing partial line would be tolerated; a complete bad line
    // is not).
    const runDir = join(journalRoot(), "scan-on-corrupt");
    mkdirSync(runDir, { recursive: true, mode: 0o700 });
    writeFileSync(join(runDir, "journal.jsonl"), "{ this is not valid json }\n{}\n", "utf8");

    const { runtime, seenMessages } = recordingRuntime();
    const onEvent = vi.fn();
    const state = await runNativeAgentLoop({
      config: baseConfig("scan-on-corrupt"),
      runtime,
      db: null,
      onEvent,
    });

    // The loop did not crash and fell back to the fresh initial prompt.
    expect(state.done).toBe(true);
    const text = (seenMessages[0][0].content[0] as { text: string }).text;
    expect(text).toContain("You are a discovery agent for pwnkit");
    expect(text).not.toContain("Execution journal");

    // The fallback was logged.
    const fallback = onEvent.mock.calls.find((c) => c[0] === "journal_rehydrate_fallback");
    expect(fallback).toBeDefined();
    expect((fallback?.[1] as { reason?: string }).reason).toBe("journal_load_failed");
  });

  it("flag ON with an EMPTY journal file: treated as a fresh run, no fallback", async () => {
    process.env[REHYDRATE_ENV] = "1";

    const runDir = join(journalRoot(), "scan-on-empty");
    mkdirSync(runDir, { recursive: true, mode: 0o700 });
    writeFileSync(join(runDir, "journal.jsonl"), "", "utf8");

    const { runtime, seenMessages } = recordingRuntime();
    const onEvent = vi.fn();
    await runNativeAgentLoop({ config: baseConfig("scan-on-empty"), runtime, db: null, onEvent });

    const text = (seenMessages[0][0].content[0] as { text: string }).text;
    expect(text).toContain("You are a discovery agent for pwnkit");
    const types = onEvent.mock.calls.map((c) => c[0]);
    expect(types).not.toContain("journal_rehydrate_fallback");
    expect(types).not.toContain("journal_rehydrated");
  });
});
