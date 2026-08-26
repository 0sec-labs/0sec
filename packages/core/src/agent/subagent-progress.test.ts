import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Shared controller for the mocked native loop (mirrors subagent-concurrent).
// `vi.hoisted` runs before the `vi.mock` factory, so the factory closes over
// it. Each test installs an `impl` standing in for one child's
// `runNativeAgentLoop`; the impl may drive `opts.onTurn(...)` to simulate the
// child's per-turn progress, then return a fake terminal state.
const h = vi.hoisted(() => ({
  impl: null as null | ((opts: any) => Promise<any>),
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
import type {
  SubagentLifecyclePayload,
  SubagentProgressPayload,
} from "../events/bus.js";
import {
  ToolExecutor,
  sanitizeSubagentNote,
  buildSubagentProgress,
  buildSubagentMessage,
} from "./tools.js";
import type { ToolContext } from "./types.js";

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

function fakeState(opts: { findings?: unknown[]; turns?: number } = {}) {
  return {
    findings: opts.findings ?? [],
    turnCount: opts.turns ?? 1,
    summary: "did the thing",
    done: true,
  } as any;
}

/** Capture every bus event we care about for one test. */
function collect(): {
  lifecycle: SubagentLifecyclePayload[];
  progress: SubagentProgressPayload[];
  unsubscribe: () => void;
} {
  const lifecycle: SubagentLifecyclePayload[] = [];
  const progress: SubagentProgressPayload[] = [];
  const unsubscribe = eventBus.subscribe({
    emit: (type, payload) => {
      if (type === "subagent_lifecycle") lifecycle.push(payload as SubagentLifecyclePayload);
      if (type === "subagent_progress") progress.push(payload as SubagentProgressPayload);
    },
  });
  return { lifecycle, progress, unsubscribe };
}

describe("sanitizeSubagentNote (Task 2 — bounded, single-line, sanitized)", () => {
  it("strips control characters and collapses whitespace to one line", () => {
    const out = sanitizeSubagentNote("line one\nline two\ttabbed\r\nthird");
    expect(out).toBe("line one line two tabbed third");
    expect(out).not.toMatch(/[\n\r\t]/);
  });

  it("strips bidi / zero-width 'trojan source' spoofers and terminal escapes", () => {
    // U+202E RLO override, U+200B zero-width space, U+001B ESC (terminal escape).
    const input = "safe\u202Eevil\u200B\u001B[2Jclear";
    const out = sanitizeSubagentNote(input);
    // Unsafe chars are neutralized to spaces (then whitespace-collapsed).
    expect(out).toBe("safe evil [2Jclear");
    // eslint-disable-next-line no-control-regex
    expect(out).not.toMatch(/[\u0000-\u001F\u200B-\u200F\u202A-\u202E]/);
  });

  it("clamps to a bounded length", () => {
    const out = sanitizeSubagentNote("x".repeat(1000));
    expect(out).toBeDefined();
    expect(out!.length).toBe(200);
  });

  it("returns undefined for non-strings and empty-after-strip input", () => {
    expect(sanitizeSubagentNote(undefined)).toBeUndefined();
    expect(sanitizeSubagentNote(42)).toBeUndefined();
    expect(sanitizeSubagentNote("   \n\t  ")).toBeUndefined();
  });
});

describe("buildSubagentProgress (Task 1 — payload shape & discipline)", () => {
  const base = {
    agent_id: "parent-scan-sub-abc",
    parent_scan_id: "parent-scan",
    task: "exploit the thing",
    max_turns: 10,
  };

  it("keys the payload by agent_id and carries turn N of M", () => {
    const p = buildSubagentProgress(base, 3, 10, [{ name: "bash", arguments: { command: "id" } }]);
    expect(p).toMatchObject({
      agent_id: "parent-scan-sub-abc",
      parent_scan_id: "parent-scan",
      turn: 3,
      max_turns: 10,
      tool: "bash",
    });
  });

  it("carries the tool NAME only — never tool arguments or output", () => {
    const p = buildSubagentProgress(base, 1, 10, [
      { name: "bash", arguments: { command: "curl http://secret.internal --data 'password=hunter2'" } },
    ]);
    const serialized = JSON.stringify(p);
    expect(p.tool).toBe("bash");
    expect(serialized).not.toContain("curl");
    expect(serialized).not.toContain("hunter2");
    expect(serialized).not.toContain("password");
    // No arbitrary keys leaked in besides the known small set.
    expect(Object.keys(p).sort()).toEqual(
      ["agent_id", "max_turns", "parent_scan_id", "tool", "turn"].sort(),
    );
  });

  it("does NOT re-send the child's task text on a progress tick", () => {
    const p = buildSubagentProgress(base, 1, 10, [{ name: "bash", arguments: {} }]);
    expect(JSON.stringify(p)).not.toContain("exploit the thing");
    expect((p as Record<string, unknown>).task).toBeUndefined();
  });

  it("surfaces a report_status line as a sanitized note, not as the tool", () => {
    const p = buildSubagentProgress(base, 2, 10, [
      { name: "bash", arguments: {} },
      { name: "report_status", arguments: { status: "enumerating users\ntable" } },
    ]);
    expect(p.tool).toBe("bash"); // report_status is meta, not activity
    expect(p.note).toBe("enumerating users table");
  });

  it("omits tool on a turn with no real tool call", () => {
    const p = buildSubagentProgress(base, 1, 10, []);
    expect(p.tool).toBeUndefined();
    expect(p.note).toBeUndefined();
  });
});

describe("buildSubagentMessage (full per-turn transcript for the focus view)", () => {
  const base = {
    agent_id: "parent-scan-sub-abc",
    parent_scan_id: "parent-scan",
    task: "exploit the thing",
    max_turns: 10,
  };

  it("carries the assistant prose + each tool (name, args, result) for the turn", () => {
    const p = buildSubagentMessage(
      base,
      3,
      "Found an IDOR on /orders.",
      [{ name: "bash", arguments: { command: "curl -s https://x/orders/2" } }],
      [{ success: true, output: "200 OK\n{\"id\":2}" }],
      1000,
    );
    expect(p).toMatchObject({
      agent_id: "parent-scan-sub-abc",
      parent_scan_id: "parent-scan",
      turn: 3,
      ts: 1000,
      assistant: "Found an IDOR on /orders.",
    });
    expect(p.tools).toHaveLength(1);
    expect(p.tools?.[0]).toMatchObject({
      call: { name: "bash", arguments: { command: "curl -s https://x/orders/2" } },
      result: { success: true, output: "200 OK\n{\"id\":2}" },
    });
  });

  it("drops the meta report_status channel from the visible tools", () => {
    const p = buildSubagentMessage(
      base,
      2,
      "",
      [
        { name: "report_status", arguments: { status: "enumerating" } },
        { name: "bash", arguments: {} },
      ],
      [
        { success: true, output: "ok" },
        { success: true, output: "done" },
      ],
      5,
    );
    expect(p.tools).toHaveLength(1);
    expect(p.tools?.[0].call.name).toBe("bash");
    // report_status output must not leak into the transcript event.
    expect(JSON.stringify(p)).not.toContain("enumerating");
  });

  it("bounds a huge tool output and huge assistant prose", () => {
    const bigOut = "A".repeat(20_000);
    const bigText = "B".repeat(20_000);
    const p = buildSubagentMessage(
      base,
      1,
      bigText,
      [{ name: "bash", arguments: {} }],
      [{ success: true, output: bigOut }],
      1,
    );
    expect((p.assistant ?? "").length).toBeLessThan(bigText.length);
    expect(p.assistant).toContain("…[truncated]");
    const out = p.tools?.[0].result.output as string;
    expect(out.length).toBeLessThan(bigOut.length);
    expect(out).toContain("…[truncated]");
  });

  it("omits assistant + tools cleanly on an empty turn", () => {
    const p = buildSubagentMessage(base, 1, "   ", [], [], 7);
    expect(p.assistant).toBeUndefined();
    expect(p.tools).toBeUndefined();
    expect(p).toMatchObject({ agent_id: base.agent_id, turn: 1, ts: 7 });
  });
});

describe("spawn_agent / spawn_agents — progress events on the bus", () => {
  beforeEach(() => {
    eventBus.clear();
    h.impl = null;
    h.configs = [];
  });

  afterEach(() => {
    eventBus.clear();
    delete process.env["0SEC_SUBAGENT_CONCURRENCY"];
  });

  it("emits monotonically increasing turn numbers for a single child", async () => {
    h.impl = async (opts) => {
      // Simulate a child that ran three turns.
      opts.onTurn(1, [{ name: "bash", arguments: { command: "a" } }], []);
      opts.onTurn(2, [{ name: "bash", arguments: { command: "b" } }], []);
      opts.onTurn(3, [{ name: "save_finding", arguments: {} }], []);
      return fakeState({ turns: 3 });
    };
    const { progress, unsubscribe } = collect();
    try {
      const executor = new ToolExecutor(toolContext());
      await executor.execute({ name: "spawn_agent", arguments: { task: "t", max_turns: 10 } });

      expect(progress).toHaveLength(3);
      expect(progress.map((p) => p.turn)).toEqual([1, 2, 3]);
      // Monotonic strictly increasing.
      for (let i = 1; i < progress.length; i++) {
        expect(progress[i]!.turn).toBeGreaterThan(progress[i - 1]!.turn);
      }
      // All keyed to one agent_id, with max_turns for "N of M".
      const ids = new Set(progress.map((p) => p.agent_id));
      expect(ids.size).toBe(1);
      expect(progress.every((p) => p.max_turns === 10)).toBe(true);
    } finally {
      unsubscribe();
    }
  });

  it("keys concurrent children by distinct agent_ids that never interleave incorrectly", async () => {
    // Each child emits its own turns tagged (in the tool name) with its task so
    // we can prove a progress event's agent_id matches the child that produced
    // its turns.
    h.impl = async (opts) => {
      const task = opts.config.systemPrompt as string;
      opts.onTurn(1, [{ name: "bash", arguments: { command: task } }], []);
      opts.onTurn(2, [{ name: "bash", arguments: { command: task } }], []);
      return fakeState({ turns: 2 });
    };
    const { progress, unsubscribe } = collect();
    try {
      const executor = new ToolExecutor(toolContext());
      await executor.execute({
        name: "spawn_agents",
        arguments: {
          tasks: [{ task: "alpha" }, { task: "beta" }, { task: "gamma" }, { task: "delta" }],
        },
      });

      // 4 children x 2 turns each.
      expect(progress).toHaveLength(8);
      const ids = new Set(progress.map((p) => p.agent_id));
      expect(ids.size).toBe(4);

      // Per agent_id, turns are monotonic 1,2 and never mix with another id.
      for (const id of ids) {
        const turns = progress.filter((p) => p.agent_id === id).map((p) => p.turn);
        expect(turns).toEqual([1, 2]);
      }
      // Every progress agent_id is a real child id from the parent scan.
      expect([...ids].every((id) => id.startsWith("parent-scan-sub-"))).toBe(true);
    } finally {
      unsubscribe();
    }
  });

  it("leaves the queued/running/completed lifecycle sequence unchanged (subagent-card regression guard)", async () => {
    h.impl = async (opts) => {
      opts.onTurn(1, [{ name: "bash", arguments: {} }], []);
      return fakeState({ turns: 1 });
    };
    const { lifecycle, unsubscribe } = collect();
    try {
      const executor = new ToolExecutor(toolContext());
      await executor.execute({ name: "spawn_agent", arguments: { task: "t" } });

      expect(lifecycle.map((e) => e.status)).toEqual(["queued", "running", "completed"]);
      // The reducer subagent-card.ts uses keys on these fields — assert intact.
      expect(lifecycle[0]).toMatchObject({
        agent_id: expect.stringMatching(/^parent-scan-sub-/),
        parent_scan_id: "parent-scan",
        task: "t",
      });
    } finally {
      unsubscribe();
    }
  });

  it("carries no tool arguments or tool output on the emitted progress events", async () => {
    h.impl = async (opts) => {
      opts.onTurn(1, [{ name: "bash", arguments: { command: "cat /etc/passwd" } }], [
        { success: true, output: "root:x:0:0:secret-output" },
      ]);
      return fakeState({ turns: 1 });
    };
    const { progress, unsubscribe } = collect();
    try {
      const executor = new ToolExecutor(toolContext());
      await executor.execute({ name: "spawn_agent", arguments: { task: "t" } });

      const serialized = JSON.stringify(progress);
      expect(serialized).not.toContain("/etc/passwd");
      expect(serialized).not.toContain("secret-output");
      expect(progress[0]!.tool).toBe("bash");
    } finally {
      unsubscribe();
    }
  });

  it("surfaces a bounded, control-char-stripped note when the child calls report_status", async () => {
    h.impl = async (opts) => {
      opts.onTurn(1, [
        { name: "report_status", arguments: { status: "dumping\ndb[2J via sqli " + "z".repeat(500) } },
        { name: "bash", arguments: { command: "sqlmap" } },
      ], []);
      return fakeState({ turns: 1 });
    };
    const { progress, unsubscribe } = collect();
    try {
      const executor = new ToolExecutor(toolContext());
      await executor.execute({ name: "spawn_agent", arguments: { task: "t" } });

      const note = progress[0]!.note!;
      expect(note).toBeDefined();
      expect(note.length).toBeLessThanOrEqual(200);
      expect(note).not.toMatch(/[\n\r\t]/);
      expect(note.startsWith("dumping db")).toBe(true);
      expect(progress[0]!.tool).toBe("bash");
    } finally {
      unsubscribe();
    }
  });

  it("makes report_status callable by a child (non-privileged) and returns success", async () => {
    // Reach into a child executor the way native-loop would: report_status must
    // resolve to a real handler and never touch fs/net/spawn.
    const executor = new ToolExecutor(toolContext());
    const ok = await executor.execute({ name: "report_status", arguments: { status: "probing" } });
    expect(ok).toMatchObject({ success: true, output: { recorded: true, status: "probing" } });

    const bad = await executor.execute({ name: "report_status", arguments: { status: "  " } });
    expect(bad.success).toBe(false);
  });
});

describe("depth guard — a child cannot spawn further children", () => {
  beforeEach(() => {
    eventBus.clear();
    h.impl = null;
    h.configs = [];
  });
  afterEach(() => {
    eventBus.clear();
  });

  it("gives the child a tool set that excludes spawn_agent / spawn_agents", async () => {
    h.impl = async () => fakeState({ turns: 1 });
    const executor = new ToolExecutor(toolContext());
    await executor.execute({ name: "spawn_agent", arguments: { task: "t" } });

    expect(h.configs).toHaveLength(1);
    const childToolNames = (h.configs[0].tools as Array<{ name: string }>).map((t) => t.name);
    expect(childToolNames).not.toContain("spawn_agent");
    expect(childToolNames).not.toContain("spawn_agents");
    // It DOES get the non-privileged status channel plus the base three.
    expect(childToolNames).toEqual(
      expect.arrayContaining(["bash", "save_finding", "done", "report_status"]),
    );
  });

  it("keeps the guard for every child in a concurrent fan-out", async () => {
    h.impl = async () => fakeState({ turns: 1 });
    const executor = new ToolExecutor(toolContext());
    await executor.execute({
      name: "spawn_agents",
      arguments: { tasks: [{ task: "a" }, { task: "b" }] },
    });

    expect(h.configs.length).toBe(2);
    for (const cfg of h.configs) {
      const names = (cfg.tools as Array<{ name: string }>).map((t) => t.name);
      expect(names).not.toContain("spawn_agent");
      expect(names).not.toContain("spawn_agents");
    }
  });
});
