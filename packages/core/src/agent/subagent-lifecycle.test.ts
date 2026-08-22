import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    async isAvailable(): Promise<boolean> {
      return false;
    }
  },
}));

import { eventBus } from "../events/bus.js";
import type { SubagentLifecyclePayload } from "../events/bus.js";
import { ToolExecutor } from "./tools.js";
import type { ToolContext } from "./types.js";

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
  });

  afterEach(() => {
    eventBus.clear();
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
      const executor = new ToolExecutor(toolContext());
      const result = await executor.execute({
        name: "spawn_agent",
        arguments: { task: "inspect the target", max_turns: 3 },
      });

      expect(result).toMatchObject({ success: false, error: "No API key available for sub-agent" });
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
        error: "No API key available for sub-agent",
      });
    } finally {
      unsubscribe();
    }
  });
});
