import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { runAgentLoop } from "./loop.js";
import {
  BUDGET_WARNING_SOFT,
  BUDGET_WARNING_HARD,
} from "./native-loop.js";
import type { Runtime, RuntimeResult } from "../runtime/types.js";
import type { Finding } from "@pwnkit/shared";

// The XML-dispatch loop tests use synthetic short flags like `FLAG{xml-mode}`
// so they don't bind to any real benchmark answer. The default decoy validator
// would reject those as suspicious sentences/taunts, which is the correct
// product behavior but irrelevant to what these tests cover (the dispatch
// layer, not the validator).
const origDecoy = process.env.PWNKIT_FEATURE_DECOY_DETECTION;
beforeAll(() => {
  process.env.PWNKIT_FEATURE_DECOY_DETECTION = "0";
});
afterAll(() => {
  if (origDecoy === undefined) {
    delete process.env.PWNKIT_FEATURE_DECOY_DETECTION;
  } else {
    process.env.PWNKIT_FEATURE_DECOY_DETECTION = origDecoy;
  }
});

/**
 * Build a Runtime mock that returns a scripted response per turn.
 * Each invocation returns the next response in `outputs`; once exhausted,
 * the last response is repeated (so a stuck test fails on max-turns
 * rather than `undefined.output`).
 */
function scriptedRuntime(outputs: string[], model?: string): Runtime & { promptHistory: string[]; model?: string } {
  let i = 0;
  const promptHistory: string[] = [];
  const rt: Runtime & { promptHistory: string[]; model?: string } = {
    type: "api",
    model,
    promptHistory,
    async execute(prompt: string): Promise<RuntimeResult> {
      promptHistory.push(prompt);
      const out = outputs[i] ?? outputs[outputs.length - 1];
      i++;
      return {
        output: out,
        exitCode: 0,
        timedOut: false,
        durationMs: 1,
      };
    },
    async isAvailable() { return true; },
  };
  return rt;
}

describe("runAgentLoop with XML dispatch", () => {
  it("emits the XML protocol prompt when dispatchMode === 'xml'", async () => {
    const runtime = scriptedRuntime([
      // Turn 1: model emits a flag immediately so the loop completes fast.
      "<flag>FLAG{xml-mode}</flag>",
    ]);

    const state = await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 5,
        target: "http://example.test",
        scanId: "scan-xml-1",
        dispatchMode: "xml",
      },
      runtime,
      db: null,
    });

    // Initial prompt must include the XML protocol verbs.
    expect(runtime.promptHistory[0]).toContain("<command>");
    expect(runtime.promptHistory[0]).toContain("<flag>");
    expect(runtime.promptHistory[0]).not.toMatch(/^TOOL_CALL:/m);

    // The flag fires `done` and ends the loop.
    expect(state.done).toBe(true);
    expect(state.summary).toContain("FLAG{xml-mode}");
    expect(state.turnCount).toBe(1);
  });

  it("dispatches a <command>, formats result as <output>, then accepts <flag>", async () => {
    // 5-turn fixture: simulates a small XML conversation.
    //  T1: model emits <command> to probe.
    //  T2: model emits another <command> following up on the result.
    //  T3: model emits <flag>, terminating the loop.
    const runtime = scriptedRuntime([
      "<note>step 1</note><command>echo first</command>",
      "<command>echo second</command>",
      "<flag>FLAG{multi-turn}</flag>",
    ]);

    const state = await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 10,
        target: "http://example.test",
        scanId: "scan-xml-2",
        dispatchMode: "xml",
      },
      runtime,
      db: null,
    });

    expect(state.done).toBe(true);
    expect(state.turnCount).toBe(3);

    // Turn 2's prompt must contain the <output> wrapping for turn 1's bash result.
    // (Bash will likely fail in test env since shellExec needs setup, but the
    // result is still wrapped — success or error.)
    const turn2Prompt = runtime.promptHistory[1];
    expect(turn2Prompt).toContain("<output");
    expect(turn2Prompt).toContain('tool="bash"');
    expect(turn2Prompt).toContain("</output>");

    // Turn 3's prompt also has the wrapping for turn 2.
    const turn3Prompt = runtime.promptHistory[2];
    expect(turn3Prompt).toContain("<output");
    expect(turn3Prompt).toContain('tool="bash"');
  });

  it("surfaces an unclosed-tag error back to the model as a protocol nudge", async () => {
    // Model emits malformed XML on T1, then recovers with a flag on T2.
    const runtime = scriptedRuntime([
      "<command>echo unclosed",      // unclosed → parse error, no dispatch
      "<flag>FLAG{recovered}</flag>", // valid → done
    ]);

    const state = await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 5,
        target: "http://example.test",
        scanId: "scan-xml-err",
        dispatchMode: "xml",
      },
      runtime,
      db: null,
    });

    // T2's prompt should carry the protocol-error nudge from T1.
    const turn2Prompt = runtime.promptHistory[1];
    expect(turn2Prompt.toLowerCase()).toContain("unclosed <command>");
    expect(state.done).toBe(true);
    expect(state.summary).toContain("FLAG{recovered}");
  });

  it("auto-detects XML dispatch from a deepseek model hint", async () => {
    const runtime = scriptedRuntime(["<flag>FLAG{auto}</flag>"]);

    const state = await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 3,
        target: "http://example.test",
        scanId: "scan-auto",
        dispatchMode: "auto",
        modelHint: "deepseek/deepseek-chat",
      },
      runtime,
      db: null,
    });

    // Initial prompt must be XML-shaped (auto picked xml because the
    // model hint matches the cheap-provider list).
    expect(runtime.promptHistory[0]).toContain("<command>");
    expect(runtime.promptHistory[0]).not.toMatch(/^TOOL_CALL:/m);
    expect(state.done).toBe(true);
  });

  it("default dispatch is JSON for premium models (regression)", async () => {
    // Without dispatchMode set (or set to "auto") + a non-cheap model,
    // the loop must keep using the legacy TOOL_CALL JSON path.
    const runtime = scriptedRuntime(['TOOL_CALL: done {"summary":"json path"}']);

    const state = await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 3,
        target: "http://example.test",
        scanId: "scan-json",
        dispatchMode: "auto",
        modelHint: "claude-3-5-sonnet-20240620",
      },
      runtime,
      db: null,
    });

    expect(runtime.promptHistory[0]).toContain("TOOL_CALL:");
    expect(runtime.promptHistory[0]).not.toContain("<command>");
    expect(state.done).toBe(true);
    expect(state.summary).toBe("json path");
  });
});

// ── Two-stage budget warnings (pwnkit#408) ──
//
// The legacy `runAgentLoop` shares the same Strix-borrow helper with
// `runNativeAgentLoop`. These tests verify the helper is wired into the
// legacy path too — we count occurrences of each warning string in the
// scripted runtime's promptHistory (every serialized prompt that follows
// the injection turn contains the warning verbatim, so we de-dupe by
// looking at the FIRST prompt that mentions each warning).

describe("runAgentLoop budget warnings (#408)", () => {
  const ENV_KEY = "PWNKIT_FEATURE_BUDGET_WARNINGS";
  const originalEnv = process.env[ENV_KEY];

  afterEach(() => {
    if (originalEnv === undefined) delete process.env[ENV_KEY];
    else process.env[ENV_KEY] = originalEnv;
  });

  /** Build a runtime that never calls done — drives the loop to maxTurns. */
  function neverDoneJsonRuntime(): Runtime & { promptHistory: string[] } {
    const promptHistory: string[] = [];
    return {
      type: "api",
      promptHistory,
      async execute(prompt: string): Promise<RuntimeResult> {
        promptHistory.push(prompt);
        return {
          // A benign no-op tool call that the loop accepts. We use an
          // unknown tool name so the executor returns success=false; the
          // loop still treats this as a valid tool-call turn (so
          // consecutive-no-tool-calls doesn't trip) and keeps going until
          // maxTurns.
          output: 'TOOL_CALL: nonexistent_tool {"x":1}',
          exitCode: 0,
          timedOut: false,
          durationMs: 1,
        };
      },
      async isAvailable() { return true; },
    };
  }

  it("injects soft+hard exactly once on a 20-turn run (collision case)", async () => {
    process.env[ENV_KEY] = "1";
    const runtime = neverDoneJsonRuntime();

    const state = await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 20,
        target: "http://example.test",
        scanId: "loop-budget-20",
      },
      runtime,
      db: null,
    });

    expect(state.turnCount).toBe(20);

    // Find first prompt that mentions each warning. Both warnings are
    // injected before turn 17's prompt is serialized, so promptHistory[16]
    // (zero-indexed = turn 17) is the first one carrying them.
    const firstSoftIdx = runtime.promptHistory.findIndex((p) => p.includes(BUDGET_WARNING_SOFT));
    const firstHardIdx = runtime.promptHistory.findIndex((p) => p.includes(BUDGET_WARNING_HARD));
    expect(firstSoftIdx).toBe(16);
    expect(firstHardIdx).toBe(16);

    // Each warning string appears EXACTLY ONCE in the final serialized
    // prompt (the last one captures the entire conversation history).
    const finalPrompt = runtime.promptHistory[runtime.promptHistory.length - 1];
    const countSubstr = (hay: string, needle: string): number =>
      hay.split(needle).length - 1;
    expect(countSubstr(finalPrompt, BUDGET_WARNING_SOFT)).toBe(1);
    expect(countSubstr(finalPrompt, BUDGET_WARNING_HARD)).toBe(1);
  });

  it("respects the disable flag — zero warnings on a 20-turn run", async () => {
    process.env[ENV_KEY] = "0";
    const runtime = neverDoneJsonRuntime();

    const state = await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 20,
        target: "http://example.test",
        scanId: "loop-budget-off",
      },
      runtime,
      db: null,
    });

    expect(state.turnCount).toBe(20);
    const finalPrompt = runtime.promptHistory[runtime.promptHistory.length - 1];
    expect(finalPrompt).not.toContain(BUDGET_WARNING_SOFT);
    expect(finalPrompt).not.toContain(BUDGET_WARNING_HARD);
  });
});

// ── Action-level durable action log (loop.ts call site) ──────────────────
//
// Same contract as the native loop: the persisted `tool_calls` event is
// action-level, with a per-invocation wall clock, redacted arguments, and a
// correlation id that joins to the `tool_artifact` row.

describe("runAgentLoop — action-level tool_calls log", () => {
  it("logs one entry per action with its own wall clock and correlation id", async () => {
    const runtime = scriptedRuntime([
      "<command>echo first</command><command>echo second</command>",
      "<flag>FLAG{action-log}</flag>",
    ]);

    const events: any[] = [];
    const db = {
      logEvent: (event: any) => { events.push(event); },
      saveSession: () => {},
    } as any;

    const before = Date.now();
    await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 5,
        target: "http://example.test",
        scanId: "loop-action-log",
        dispatchMode: "xml",
      },
      runtime,
      db,
    });
    const after = Date.now();

    const toolCallEvents = events.filter((e) => e.eventType === "tool_calls");
    expect(toolCallEvents.length).toBeGreaterThanOrEqual(1);

    const payload = toolCallEvents[0].payload;
    expect(payload.calls).toHaveLength(2);
    const [a, b] = payload.calls;

    expect(a.name).toBe("bash");
    expect(a.args).toContain("echo first");
    expect(b.args).toContain("echo second");
    expect(a.startedAt).toBeGreaterThanOrEqual(before);
    expect(b.startedAt).toBeLessThanOrEqual(after);
    expect(b.startedAt).toBeGreaterThanOrEqual(a.startedAt);
    expect(b.startedAt).toBeGreaterThanOrEqual(a.startedAt + a.durationMs);
    expect(typeof a.durationMs).toBe("number");
    expect(a.correlationId).toBeTruthy();
    expect(a.correlationId).not.toBe(b.correlationId);

    // sessionId + the pre-upgrade mirrors are still on the payload.
    expect(typeof payload.sessionId).toBe("string");
    expect(payload.tools).toEqual(["bash", "bash"]);
    expect(payload.results).toHaveLength(2);
  });

  it("redacts credentials out of the logged arguments", async () => {
    const runtime = scriptedRuntime([
      `<command>curl -H "Authorization: Bearer sup3rs3cr3t" http://example.test/admin</command>`,
      "<flag>FLAG{action-log-redact}</flag>",
    ]);

    const events: any[] = [];
    const db = {
      logEvent: (event: any) => { events.push(event); },
      saveSession: () => {},
    } as any;

    await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 5,
        target: "http://example.test",
        scanId: "loop-action-log-redact",
        dispatchMode: "xml",
      },
      runtime,
      db,
    });

    const entry = events
      .filter((e) => e.eventType === "tool_calls")
      .flatMap((e) => e.payload.calls as any[])
      .find((c) => c.name === "bash");
    expect(entry).toBeDefined();
    expect(entry.args).not.toContain("sup3rs3cr3t");
    expect(entry.args).toContain("http://example.test/admin");
  });
});


describe("runAgentLoop — finding persistence callback", () => {
  it("emits only the finding that save_finding accepted", async () => {
    const delivered: Finding[] = [];
    const runtime = scriptedRuntime([
      [
        'TOOL_CALL: save_finding {"title":"Verified SSRF","severity":"high","category":"ssrf","evidence_request":"GET /fetch?url=http://probe","evidence_response":"202 Accepted"}',
        'TOOL_CALL: done {"summary":"saved"}',
      ].join("\n"),
    ]);

    const state = await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 3,
        target: "http://example.test",
        scanId: "loop-finding-callback",
      },
      runtime,
      db: null,
      onFindingSaved: (finding) => {
        delivered.push(finding);
      },
    });

    expect(state.done).toBe(true);
    expect(state.findings).toHaveLength(1);
    expect(delivered).toEqual(state.findings);
  });

  it("does not emit a rejected save_finding call", async () => {
    const delivered: Finding[] = [];
    const runtime = scriptedRuntime([
      [
        'TOOL_CALL: save_finding {"title":"Unproven SSRF","severity":"high","category":"ssrf","evidence_request":"","evidence_response":""}',
        'TOOL_CALL: done {"summary":"nothing saved"}',
      ].join("\n"),
    ]);

    const state = await runAgentLoop({
      config: {
        role: "audit",
        systemPrompt: "test",
        tools: [],
        maxTurns: 3,
        target: "http://example.test",
        scanId: "loop-rejected-finding",
      },
      runtime,
      db: null,
      onFindingSaved: (finding) => {
        delivered.push(finding);
      },
    });

    expect(state.findings).toEqual([]);
    expect(delivered).toEqual([]);
  });
});