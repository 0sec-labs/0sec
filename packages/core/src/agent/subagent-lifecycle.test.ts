import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const execution = vi.hoisted(() => ({ calls: 0 }));
vi.mock("./native-loop.js", () => ({
  runNativeAgentLoop: async () => {
    execution.calls++;
    return { findings: [], turnCount: 1, summary: "Ambient child ran", done: true };
  },
}));

import { eventBus } from "../events/bus.js";
import type { SubagentLifecyclePayload } from "../events/bus.js";
import { ToolExecutor } from "./tools.js";
import type { ToolContext } from "./types.js";
import type { NativeRuntime } from "../runtime/types.js";

/** Factory returning an unavailable runtime — the test verifies the fail-closed path. */
async function unavailableFactory(_timeoutMs?: number): Promise<NativeRuntime> {
  return {
    type: "api",
    isAvailable: async () => false,
    executeNative: async () => ({ content: [], stopReason: "end_turn" as const, durationMs: 0 }),
  };
}

function toolContext(): ToolContext {
  return {
    target: "https://target.test",
    scanId: "parent-scan",
    findings: [],
    attackResults: [],
    targetInfo: {},
  };
}

describe("spawn_agent lifecycle events", () => {
  beforeEach(() => {
    eventBus.clear();
    execution.calls = 0;
  });

  afterEach(() => {
    eventBus.clear();
    vi.unstubAllEnvs();
  });

  it("emits queued then failed when the child runtime is unavailable", async () => {
    const events: SubagentLifecyclePayload[] = [];
    const unsubscribe = eventBus.subscribe({
      emit: (type, payload) => {
        if (type === "subagent_lifecycle") {
          events.push(payload as SubagentLifecyclePayload);
        }
      },
    });

    try {
      const executor = new ToolExecutor(toolContext(), undefined, undefined, unavailableFactory);
      const result = await executor.execute({
        name: "spawn_agent",
        arguments: { task: "inspect the target", max_turns: 3 },
      });

      expect(result.success).toBe(false);
      expect(events).toHaveLength(2);
      expect(events.map((event) => event.status)).toEqual(["queued", "failed"]);
      expect(events[0]).toMatchObject({
        agent_id: expect.stringMatching(/^parent-scan-sub-/),
        parent_scan_id: "parent-scan",
        task: "inspect the target",
        max_turns: 3,
      });
      expect(events[1]).toMatchObject({
        agent_id: events[0]!.agent_id,
        error: result.error,
      });
    } finally {
      unsubscribe();
    }
  });

  it("fails closed when no child runtime factory is provided", async () => {
    vi.stubEnv("0SEC_FORCE_PROVIDER", "openai");
    vi.stubEnv("0SEC_SELECTED_PROVIDER", "");
    vi.stubEnv("OPENAI_API_KEY", "ambient-fixture-key");
    const events: SubagentLifecyclePayload[] = [];
    const unsubscribe = eventBus.subscribe({
      emit: (type, payload) => {
        if (type === "subagent_lifecycle") {
          events.push(payload as SubagentLifecyclePayload);
        }
      },
    });

    try {
      // No fourth argument → no factory → fail closed with a clear error.
      const executor = new ToolExecutor(toolContext());
      const result = await executor.execute({
        name: "spawn_agent",
        arguments: { task: "inspect the target", max_turns: 3 },
      });

      expect(result.success).toBe(false);
      expect(result.error).toBeTruthy();
      expect(execution.calls).toBe(0);
      expect(events).toHaveLength(2);
      expect(events.map((event) => event.status)).toEqual(["queued", "failed"]);
    } finally {
      unsubscribe();
    }
  });
});
