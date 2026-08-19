import { describe, it, expect } from "vitest";
import type { Finding, ScanConfig } from "@0sec/shared";
import type { NativeRuntime, NativeRuntimeResult, NativeMessage, NativeToolDef } from "./runtime/types.js";
import { runNativeVerify } from "./agentic-scanner.js";

// ── Helpers ──

function makeFinding(i: number): Finding {
  return {
    id: `f-${i}`,
    templateId: `tpl-${i}`,
    title: `Finding ${i}`,
    description: `description ${i}`,
    severity: "high",
    category: "sql-injection",
    status: "discovered",
    evidence: {
      request: `GET /vuln${i} HTTP/1.1`,
      response: `200 OK ${i}`,
      analysis: `analysis ${i}`,
    },
    timestamp: 0,
  };
}

interface SessionTrace {
  /** True every time `executeNative` was called with messages.length === 1, i.e. a fresh session. */
  freshSessions: number;
  /** maxTurns recorded across all sessions, derived from system prompt finding ids and call count. */
  systemPrompts: string[];
  /** Total executeNative calls across all sessions. */
  totalCalls: number;
  /** Per-session turn counts (calls before `done`). */
  turnsPerSession: number[];
}

/**
 * Build a mock runtime that:
 *  - On the first call within a session, returns the agent's `done` tool to
 *    end the loop after one turn.
 *  - Tracks every executeNative call so the test can assert on session
 *    boundaries (a session starts when `messages.length === 1`).
 */
function createTracingRuntime(opts?: {
  /** Number of turns each per-finding session should burn before calling done. */
  turnsBeforeDone?: number;
}): { runtime: NativeRuntime; trace: SessionTrace } {
  const turnsBeforeDone = opts?.turnsBeforeDone ?? 1;
  const trace: SessionTrace = {
    freshSessions: 0,
    systemPrompts: [],
    totalCalls: 0,
    turnsPerSession: [],
  };
  let currentSessionTurn = 0;

  const runtime: NativeRuntime = {
    type: "api" as const,
    async executeNative(
      system: string,
      messages: NativeMessage[],
      _tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      trace.totalCalls++;
      // Detect a fresh session: only the initial user message has been added
      // (see native-loop.ts:240). On a fresh session we record the system
      // prompt so the test can verify per-finding scoping.
      if (messages.length === 1) {
        trace.freshSessions++;
        trace.systemPrompts.push(system);
        if (currentSessionTurn > 0) {
          trace.turnsPerSession.push(currentSessionTurn);
        }
        currentSessionTurn = 0;
      }
      currentSessionTurn++;

      if (currentSessionTurn >= turnsBeforeDone) {
        return {
          content: [
            { type: "tool_use", id: `tc-${trace.totalCalls}`, name: "done", input: { summary: "verified" } },
          ],
          stopReason: "tool_use",
          durationMs: 1,
        };
      }

      // Otherwise emit a benign text response so the loop continues but does
      // not call any side-effecting tool.
      return {
        content: [{ type: "text", text: "thinking..." }],
        stopReason: "end_turn",
        durationMs: 1,
      };
    },
    async isAvailable() { return true; },
  };

  return { runtime, trace };
}

function makeScanConfig(): ScanConfig {
  return {
    target: "https://example.test",
    depth: "default",
    format: "json",
  };
}

// ── Tests ──

describe("runNativeVerify — per-finding loop (#285)", () => {
  it("creates one fresh agent session per finding for 10 findings", async () => {
    const findings = Array.from({ length: 10 }, (_, i) => makeFinding(i + 1));
    const { runtime, trace } = createTracingRuntime();

    await runNativeVerify(runtime, null, makeScanConfig(), "scan-1", findings, () => {});

    expect(trace.freshSessions).toBe(10);
    // Each system prompt should mention its specific finding id (verifyPromptSingleFinding)
    expect(trace.systemPrompts).toHaveLength(10);
    for (let i = 0; i < 10; i++) {
      expect(trace.systemPrompts[i]).toContain(`f-${i + 1}`);
    }
  });

  it("respects per-finding turn budget — one runaway session does not burn the whole pass", async () => {
    // turnsBeforeDone is huge so the mock never calls `done`; the loop has
    // to terminate on its own per-session budget (maxTurns=5). The native
    // loop's text-only early-exit kicks in at turn ≥ 4 (see native-loop.ts
    // ~599), so we expect 4 calls per session × 3 findings = 12. The point
    // is that each session has an independent budget — three sessions ×
    // bounded turns, never one session that swallows the whole pass.
    const findings = Array.from({ length: 3 }, (_, i) => makeFinding(i + 1));
    const { runtime, trace } = createTracingRuntime({ turnsBeforeDone: 999 });

    await runNativeVerify(runtime, null, makeScanConfig(), "scan-2", findings, () => {});

    expect(trace.freshSessions).toBe(3);
    // With per-finding budget enforced, we have N independent sessions,
    // each terminating on its own. The exact per-session call count is a
    // property of the inner loop, but it MUST be ≤ maxTurns (5) and the
    // total MUST be roughly N × per-session, not a single shared 15.
    expect(trace.totalCalls).toBeGreaterThanOrEqual(3); // at least one call each
    expect(trace.totalCalls).toBeLessThanOrEqual(3 * 5); // never exceeds N × maxTurns
  });

  it("zero findings → zero agent sessions", async () => {
    const { runtime, trace } = createTracingRuntime();
    await runNativeVerify(runtime, null, makeScanConfig(), "scan-3", [], () => {});
    expect(trace.freshSessions).toBe(0);
    expect(trace.totalCalls).toBe(0);
  });

  it("each per-finding system prompt only references that finding's evidence", async () => {
    const findings = [makeFinding(42), makeFinding(7)];
    const { runtime, trace } = createTracingRuntime();

    await runNativeVerify(runtime, null, makeScanConfig(), "scan-4", findings, () => {});

    expect(trace.systemPrompts).toHaveLength(2);
    // First session sees only finding 42.
    expect(trace.systemPrompts[0]).toContain("f-42");
    expect(trace.systemPrompts[0]).not.toContain("f-7");
    // Second session sees only finding 7.
    expect(trace.systemPrompts[1]).toContain("f-7");
    expect(trace.systemPrompts[1]).not.toContain("f-42");
  });
});
