/**
 * End-to-end test for playbook re-injection through a REAL in-loop compaction.
 *
 * The defect: playbook injection was one-shot (`playbookInjected` latch, single
 * message push). The methodology lived only in the transcript, so a
 * `compactMessagesWithLLM` pass could erase it and nothing ever put it back.
 * Beyond losing the guidance, this contaminated evaluation — whether the
 * feature's own content was present at the end of a run depended on whether a
 * compaction happened to land after the injection turn, so an A/B of
 * `dynamicPlaybooks` would partly have been measuring compaction timing.
 *
 * This drives `runNativeAgentLoop` for real: the agent runs `bash` (local, no
 * network) emitting text that trips the SQLi indicators, the playbook is
 * injected at the 30% checkpoint, token usage is scripted high enough to force
 * a genuine compaction, and the loop is expected to notice the block is gone
 * and restore it from structured state.
 *
 * `dynamicPlaybooks` stays OFF by default — this only makes the mechanism
 * sound. The flag is enabled explicitly here and cleaned up after.
 */

import { describe, it, expect, afterEach } from "vitest";
import { runNativeAgentLoop, PLAYBOOK_MARKER } from "./native-loop.js";
import type {
  NativeRuntime,
  NativeRuntimeResult,
  NativeMessage,
  NativeToolDef,
} from "../runtime/types.js";

/** Text that trips >= 2 SQLi indicators in `detectPlaybooks`. */
const SQLI_ECHO =
  "echo \"You have an error in your SQL syntax\"; " +
  "echo \"mysql_fetch_array() expects parameter 1\"; " +
  "echo \"SELECT * FROM users WHERE id=1\"";

/**
 * Mock runtime that always issues the same `bash` call and reports a large
 * input-token count so the loop's compaction threshold (77k total, and >30k
 * regrowth since the last compaction) is crossed mid-run.
 */
function createRuntime(perTurnInputTokens: number): NativeRuntime {
  let n = 0;
  return {
    type: "api" as const,
    async executeNative(
      _system: string,
      _messages: NativeMessage[],
      _tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      n += 1;
      return {
        content: [
          { type: "tool_use", id: `tc-${n}`, name: "bash", input: { command: SQLI_ECHO } },
        ],
        stopReason: "tool_use",
        durationMs: 1,
        usage: { inputTokens: perTurnInputTokens, outputTokens: 10 },
      };
    },
    async isAvailable() {
      return true;
    },
  };
}

afterEach(() => {
  delete process.env.PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS;
  delete process.env.PWNKIT_FEATURE_PRESERVE_CRITICAL_MESSAGES;
});

describe("dynamic playbook injection survives compaction", () => {
  it("injects once, then restores the block after a real compaction erases it", async () => {
    process.env.PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS = "1";
    // Playbook text is full of "password" / "admin" / "token", so the #229
    // verbatim-preservation path would fold it into the compaction summary and
    // mask the very defect under test. Disable it so the block is genuinely
    // lost — that is the case the restore exists for.
    process.env.PWNKIT_FEATURE_PRESERVE_CRITICAL_MESSAGES = "0";

    const events: Array<{ type: string; payload: Record<string, unknown> }> = [];

    const state = await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt: "You are an attack agent testing a web application.",
        tools: [],
        maxTurns: 24,
        target: "https://example.com",
        scanId: "playbook-reinject-test",
        // Early-stop would end the run at 50% before compaction can happen.
        retryCount: 1,
      },
      runtime: createRuntime(20_000),
      db: null,
      onEvent: (type, payload) => {
        events.push({ type, payload: payload as Record<string, unknown> });
      },
    });

    const injections = events.filter((e) => e.type === "playbook_injected");
    const compactions = events.filter((e) => e.type === "context_compacted");

    // Preconditions: the run really did inject a playbook AND really did
    // compact. Without both, the test proves nothing.
    expect(injections.length).toBeGreaterThan(0);
    expect(compactions.length).toBeGreaterThan(0);
    expect(injections[0]?.payload.reason).toBe("initial");

    // The point of the fix: at least one injection is a post-compaction
    // restore, and the methodology is present in the final message window.
    const restored = injections.filter((e) => e.payload.reason === "restored");
    expect(restored.length).toBeGreaterThan(0);

    expect(JSON.stringify(state.messages)).toContain(PLAYBOOK_MARKER);
  }, 120_000);

  it("does not re-inject while the block is still in the window", async () => {
    process.env.PWNKIT_FEATURE_DYNAMIC_PLAYBOOKS = "1";

    const events: Array<{ type: string; payload: Record<string, unknown> }> = [];

    await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt: "You are an attack agent testing a web application.",
        tools: [],
        maxTurns: 20,
        target: "https://example.com",
        scanId: "playbook-no-spam-test",
        retryCount: 1,
      },
      // Low per-turn usage → never crosses the compaction threshold.
      runtime: createRuntime(10),
      db: null,
      onEvent: (type, payload) => {
        events.push({ type, payload: payload as Record<string, unknown> });
      },
    });

    const injections = events.filter((e) => e.type === "playbook_injected");
    // The regression this guards: a presence check that is always false would
    // push ~3.6k tokens of methodology EVERY turn for the rest of the run.
    // With no compaction, exactly one injection should ever happen.
    expect(injections).toHaveLength(1);
    expect(injections[0]?.payload.reason).toBe("initial");
  }, 120_000);
});
