import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Shared controller for the mocked native loop. `vi.hoisted` runs before the
// `vi.mock` factory below, so the factory can close over it. Each test installs
// an `impl` that stands in for one subagent's `runNativeAgentLoop` call.
const h = vi.hoisted(() => ({
  impl: null as null | ((opts: any) => Promise<any>),
  inFlight: 0,
  peak: 0,
  configs: [] as any[],
}));

vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    async isAvailable(): Promise<boolean> {
      return true;
    }
  },
}));

vi.mock("./native-loop.js", () => ({
  runNativeAgentLoop: async (opts: any) => {
    h.configs.push(opts.config);
    if (!h.impl) throw new Error("test did not install a native-loop impl");
    return h.impl(opts);
  },
}));

import { eventBus } from "../events/bus.js";
import type { SubagentLifecyclePayload } from "../events/bus.js";
import { ToolExecutor } from "./tools.js";
import type { ToolContext } from "./types.js";
import { ScanCostLedger } from "./cost-ledger.js";

function toolContext(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    target: "https://target.test",
    scanId: "parent-scan",
    findings: [],
    attackResults: [],
    targetInfo: {},
    ...overrides,
  };
}

/** Minimal fake NativeAgentState — the handler only reads these fields. */
function fakeState(findings: unknown[], done = true) {
  return { findings, turnCount: 1, summary: "did the thing", done } as any;
}

function collectLifecycle(): {
  events: SubagentLifecyclePayload[];
  unsubscribe: () => void;
} {
  const events: SubagentLifecyclePayload[] = [];
  const unsubscribe = eventBus.subscribe({
    emit: (type, payload) => {
      if (type === "subagent_lifecycle") {
        events.push(payload as SubagentLifecyclePayload);
      }
    },
  });
  return { events, unsubscribe };
}

describe("spawn_agents — concurrent subagent dispatch", () => {
  beforeEach(() => {
    eventBus.clear();
    h.impl = null;
    h.inFlight = 0;
    h.peak = 0;
    h.configs = [];
  });

  afterEach(() => {
    eventBus.clear();
    delete process.env["0SEC_SUBAGENT_CONCURRENCY"];
  });

  it("(1) runs two children to completion, merges findings, distinct agent_ids", async () => {
    const { events, unsubscribe } = collectLifecycle();
    // One finding per child, tagged with the task so we can assert the merge.
    h.impl = async (opts) => {
      const task = opts.config.systemPrompt as string;
      const tag = task.includes("alpha") ? "A" : "B";
      return fakeState([{ id: `finding-${tag}` }]);
    };

    try {
      const ctx = toolContext();
      const executor = new ToolExecutor(ctx);
      const result = await executor.execute({
        name: "spawn_agents",
        arguments: {
          tasks: [{ task: "probe alpha" }, { task: "probe beta" }],
        },
      });

      expect(result.success).toBe(true);
      expect(result.output).toMatchObject({ spawned: 2, succeeded: 2, failed: 0 });
      // Findings merged into the PARENT context, in index order.
      expect(ctx.findings.map((f: any) => f.id)).toEqual(["finding-A", "finding-B"]);

      const queued = events.filter((e) => e.status === "queued");
      const ids = new Set(queued.map((e) => e.agent_id));
      expect(ids.size).toBe(2);
      for (const id of ids) expect(id).toMatch(/^parent-scan-sub-/);
    } finally {
      unsubscribe();
    }
  });

  it("(2) isolates failure: one child throws, the other still returns its finding", async () => {
    h.impl = async (opts) => {
      if ((opts.config.systemPrompt as string).includes("BOOM")) {
        throw new Error("child exploded");
      }
      return fakeState([{ id: "good-finding" }]);
    };

    const ctx = toolContext();
    const executor = new ToolExecutor(ctx);
    const result = await executor.execute({
      name: "spawn_agents",
      arguments: {
        tasks: [{ task: "do BOOM" }, { task: "do fine" }],
      },
    });

    expect(result.success).toBe(true);
    expect(result.output).toMatchObject({ spawned: 2, succeeded: 1, failed: 1 });
    // Only the surviving child's finding lands in the parent.
    expect(ctx.findings.map((f: any) => f.id)).toEqual(["good-finding"]);

    const agents = (result.output as any).agents as any[];
    expect(agents[0]).toMatchObject({ index: 0, ok: false });
    expect(agents[0].error).toContain("child exploded");
    expect(agents[1]).toMatchObject({ index: 1, ok: true, findings: 1 });
  });

  it("(3) shared cost ceiling caps the whole batch across concurrent children", async () => {
    // Pre-load the shared ledger ABOVE the ceiling, standing in for spend by
    // other sessions in the same scan. Because every child shares this one
    // ledger + ceiling, none should be allowed to produce findings.
    const ledger = new ScanCostLedger();
    ledger.add({ inputTokens: 50_000_000, outputTokens: 50_000_000 });
    const ceiling = 0.01;
    expect(ledger.totalCostUsd()).toBeGreaterThan(ceiling);

    const seenLedgers: unknown[] = [];
    h.impl = async (opts) => {
      seenLedgers.push(opts.config.costLedger);
      const running = opts.config.costLedger
        ? opts.config.costLedger.totalCostUsd()
        : 0;
      if (
        opts.config.costCeilingUsd !== undefined &&
        running >= opts.config.costCeilingUsd
      ) {
        // Ceiling already tripped — return a partial (no new findings), which
        // is exactly what the real native loop does on costCeilingExceeded.
        return fakeState([], false);
      }
      opts.config.costLedger?.add({ inputTokens: 1_000, outputTokens: 1_000 });
      return fakeState([{ id: "should-not-happen" }]);
    };

    const ctx = toolContext({
      costLedger: ledger,
      costCeilingUsd: ceiling,
      costModel: "claude-sonnet-4",
    });
    const executor = new ToolExecutor(ctx);
    const result = await executor.execute({
      name: "spawn_agents",
      arguments: {
        tasks: [
          { task: "child 1" },
          { task: "child 2" },
          { task: "child 3" },
          { task: "child 4" },
        ],
      },
    });

    expect(result.success).toBe(true);
    // Batch capped: no findings produced despite four children.
    expect(ctx.findings).toHaveLength(0);
    // Every child received the SAME shared ledger instance.
    expect(seenLedgers).toHaveLength(4);
    for (const l of seenLedgers) expect(l).toBe(ledger);
  });

  it("(4) concurrency cap bounds the peak number of in-flight children", async () => {
    // 6 children, default cap of 4. Instrument entry/exit to record the peak.
    h.impl = async () => {
      h.inFlight += 1;
      h.peak = Math.max(h.peak, h.inFlight);
      await new Promise((r) => setTimeout(r, 10));
      h.inFlight -= 1;
      return fakeState([]);
    };

    const ctx = toolContext();
    const executor = new ToolExecutor(ctx);
    const result = await executor.execute({
      name: "spawn_agents",
      arguments: {
        tasks: Array.from({ length: 6 }, (_, i) => ({ task: `child ${i}` })),
      },
    });

    expect(result.success).toBe(true);
    expect(result.output).toMatchObject({ spawned: 6, succeeded: 6, failed: 0 });
    // Peak never exceeds SUBAGENT_CONCURRENCY (default 4)...
    expect(h.peak).toBeLessThanOrEqual(4);
    // ...and children genuinely overlapped (not serialized).
    expect(h.peak).toBeGreaterThan(1);
  });

  it("(5) emits queued -> running -> terminal exactly once per child, no cross-bleed", async () => {
    const { events, unsubscribe } = collectLifecycle();
    h.impl = async () => fakeState([]);

    try {
      const ctx = toolContext();
      const executor = new ToolExecutor(ctx);
      await executor.execute({
        name: "spawn_agents",
        arguments: { tasks: [{ task: "a" }, { task: "b" }] },
      });

      // Group events by child.
      const byAgent = new Map<string, string[]>();
      for (const e of events) {
        const seq = byAgent.get(e.agent_id) ?? [];
        seq.push(e.status);
        byAgent.set(e.agent_id, seq);
      }

      expect(byAgent.size).toBe(2);
      for (const seq of byAgent.values()) {
        expect(seq).toEqual(["queued", "running", "completed"]);
      }
    } finally {
      unsubscribe();
    }
  });

  it("(6) nesting guard: child tool set excludes spawn_agent/spawn_agents", async () => {
    h.impl = async () => fakeState([]);

    const ctx = toolContext();
    const executor = new ToolExecutor(ctx);
    await executor.execute({
      name: "spawn_agents",
      arguments: { tasks: [{ task: "solo" }] },
    });

    expect(h.configs).toHaveLength(1);
    const toolNames = (h.configs[0].tools as Array<{ name: string }>).map((t) => t.name);
    // Base three plus the child-only, non-privileged coordination channels:
    // `report_status` (progress), and `send_message` / `check_messages` (peer
    // messaging). The nesting guard is unchanged: the spawn tools remain
    // excluded, so a child still cannot spawn children.
    expect(toolNames).toEqual([
      "bash",
      "save_finding",
      "done",
      "report_status",
      "send_message",
      "check_messages",
    ]);
    expect(toolNames).not.toContain("spawn_agent");
    expect(toolNames).not.toContain("spawn_agents");
  });

  it("(7) rejects empty, oversized, and malformed task lists with a structured error", async () => {
    const executor = new ToolExecutor(toolContext());

    const empty = await executor.execute({
      name: "spawn_agents",
      arguments: { tasks: [] },
    });
    expect(empty).toMatchObject({ success: false });
    expect(empty.error).toContain("non-empty array");

    const notArray = await executor.execute({
      name: "spawn_agents",
      arguments: { tasks: "nope" },
    });
    expect(notArray).toMatchObject({ success: false });

    const oversized = await executor.execute({
      name: "spawn_agents",
      arguments: {
        tasks: Array.from({ length: 9 }, (_, i) => ({ task: `child ${i}` })),
      },
    });
    expect(oversized).toMatchObject({ success: false });
    expect(oversized.error).toContain("max 8");

    const malformed = await executor.execute({
      name: "spawn_agents",
      arguments: { tasks: [{ task: "ok" }, { max_turns: 3 }] },
    });
    expect(malformed).toMatchObject({ success: false });
    expect(malformed.error).toContain("tasks[1].task");
  });
});
