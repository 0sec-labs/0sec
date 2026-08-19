import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { classifyHypothesis, runEGATS } from "./egats.js";
import { runNativeAgentLoop } from "./native-loop.js";
import type {
  NativeRuntime,
  NativeRuntimeResult,
  NativeMessage,
  NativeToolDef,
} from "../runtime/types.js";

// ── Mock runtime that records every executeNative call ──
//
// It records the system prompt and tool names of each call so tests can assert
// how a branch mini-loop was configured, and always returns a single `done`
// tool_use so the loop terminates in one turn.

interface RecordedCall {
  system: string;
  toolNames: string[];
}

function createRecordingRuntime(): {
  runtime: NativeRuntime;
  calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const runtime: NativeRuntime = {
    type: "api" as const,
    async executeNative(
      system: string,
      _messages: NativeMessage[],
      tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      calls.push({ system, toolNames: tools.map((t) => t.name) });
      return {
        content: [
          {
            type: "tool_use",
            id: `tc${calls.length}`,
            name: "done",
            input: { summary: "done" },
          },
        ],
        stopReason: "tool_use",
        durationMs: 1,
      };
    },
    async isAvailable() {
      return true;
    },
  };
  return { runtime, calls };
}

// ── classifyHypothesis (pure routing decision) ──

describe("classifyHypothesis", () => {
  it("routes a SQLi-named hypothesis to the sqli specialist", () => {
    expect(
      classifyHypothesis("SQLi via username param on POST /login (time-based blind)"),
    ).toBe("sqli");
  });

  it("routes an auth-bypass / JWT hypothesis to auth-bypass", () => {
    expect(
      classifyHypothesis("Auth bypass via JWT 'none' algorithm on /api/me"),
    ).toBe("auth-bypass");
  });

  it("routes IDOR, SSTI, XSS, and SSRF hypotheses to their classes", () => {
    expect(classifyHypothesis("IDOR via user_id param on GET /api/users/:id")).toBe("idor");
    expect(classifyHypothesis("SSTI in name field — {{7*7}} reflects as 49 (Jinja2)")).toBe("ssti");
    expect(classifyHypothesis("Reflected XSS via search param, <script>alert(1)</script>")).toBe("xss");
    expect(classifyHypothesis("SSRF via webhook URL to http://169.254.169.254/latest/meta-data/")).toBe("ssrf");
  });

  it("falls back to generic (null) for a hypothesis that names no class", () => {
    expect(
      classifyHypothesis(
        "The target has at least one exploitable web vulnerability reachable from the root endpoint.",
      ),
    ).toBeNull();
  });

  it("falls back to generic (null) when the hypothesis is genuinely ambiguous (multiple classes)", () => {
    expect(classifyHypothesis("Either SQLi or XSS in the search parameter")).toBeNull();
  });
});

// ── EGATS specialist routing (end-to-end through exploreNode) ──

describe("EGATS specialist routing", () => {
  const FLAG = "PWNKIT_FEATURE_SPECIALIST_ROUTING";
  let prev: string | undefined;

  beforeEach(() => {
    prev = process.env[FLAG];
  });
  afterEach(() => {
    if (prev === undefined) delete process.env[FLAG];
    else process.env[FLAG] = prev;
  });

  async function runRoot(rootHypothesis: string) {
    const { runtime, calls } = createRecordingRuntime();
    const events: Array<{ type: string; payload: Record<string, unknown> }> = [];
    const result = await runEGATS(
      {
        rootHypothesis,
        maxDepth: 0, // explore root only — no child expansion, no planner calls
        maxBranches: 1,
        evidenceThreshold: 0.25,
        turnsPerNode: 1,
        beamWidth: 1,
        target: "http://target.test",
        scanId: "test-scan",
      },
      runtime,
      null,
      (type, payload) => events.push({ type, payload }),
    );
    return { calls, events, result };
  }

  it("fires specialist routing for a named class: prompt, skill, tools, and event", async () => {
    process.env[FLAG] = "1";
    const { calls, events } = await runRoot("SQLi via username param on POST /login");

    // egats_specialist event emitted with the resolved class + skill id.
    const specialist = events.find((e) => e.type === "egats_specialist");
    expect(specialist).toBeDefined();
    expect(specialist!.payload.vulnClass).toBe("sqli");
    expect(specialist!.payload.skillId).toBe("sqli-advanced");

    // The branch loop ran with the SQLi specialist system prompt + auto-loaded
    // SQLi skill content + SQLi-tuned tools.
    expect(calls).toHaveLength(1);
    const { system, toolNames } = calls[0]!;
    expect(system).toContain("EGATS Specialist Branch — SQL Injection");
    expect(system).toContain("### SQL Injection"); // class technique section
    expect(system).toContain("## Loaded Skill: Advanced SQL Injection"); // auto-loaded skill
    expect(toolNames).toContain("http_request"); // class-tuned extra tool
    expect(toolNames).toContain("save_finding");
  });

  it("falls back to the generic branch agent for an ambiguous hypothesis", async () => {
    process.env[FLAG] = "1";
    const { calls, events } = await runRoot(
      "The target has at least one exploitable web vulnerability.",
    );

    expect(events.find((e) => e.type === "egats_specialist")).toBeUndefined();
    const { system, toolNames } = calls[0]!;
    expect(system).toContain("## EGATS Branch Focus"); // generic branch header
    expect(system).not.toContain("EGATS Specialist Branch");
    // Generic branch keeps the minimal tool set — no http_request injected.
    expect(toolNames).not.toContain("http_request");
  });

  it("respects the feature flag — no specialist routing when disabled", async () => {
    delete process.env[FLAG]; // default OFF
    const { calls, events } = await runRoot("SQLi via username param on POST /login");

    expect(events.find((e) => e.type === "egats_specialist")).toBeUndefined();
    expect(calls[0]!.system).toContain("## EGATS Branch Focus");
    expect(calls[0]!.system).not.toContain("EGATS Specialist Branch");
  });
});

// ── Skill auto-load idempotency (native-loop preload seam) ──

describe("native-loop specialist skill preload", () => {
  function createCapturingRuntime(): {
    runtime: NativeRuntime;
    systems: string[];
  } {
    const systems: string[] = [];
    const runtime: NativeRuntime = {
      type: "api" as const,
      async executeNative(system: string): Promise<NativeRuntimeResult> {
        systems.push(system);
        return {
          content: [{ type: "tool_use", id: "tc1", name: "done", input: { summary: "ok" } }],
          stopReason: "tool_use",
          durationMs: 1,
        };
      },
      async isAvailable() {
        return true;
      },
    };
    return { runtime, systems };
  }

  it("auto-loads a class skill once, even when the id is passed multiple times (idempotent)", async () => {
    const { runtime, systems } = createCapturingRuntime();
    const events: string[] = [];
    await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt: "BASE PROMPT",
        tools: [],
        maxTurns: 1,
        target: "http://target.test",
        scanId: "preload-scan",
        // duplicate id — the preload must dedupe to a single injection.
        preloadedSkillIds: ["sqli-advanced", "sqli-advanced"],
      },
      runtime,
      db: null,
      onEvent: (type) => events.push(type),
    });

    const system = systems[0]!;
    const occurrences = system.split("## Loaded Skill: Advanced SQL Injection").length - 1;
    expect(occurrences).toBe(1);
    // Exactly one skill_preloaded event for the deduped skill.
    expect(events.filter((e) => e === "skill_preloaded")).toHaveLength(1);
  });

  it("skips unknown skill ids without throwing", async () => {
    const { runtime, systems } = createCapturingRuntime();
    await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt: "BASE PROMPT",
        tools: [],
        maxTurns: 1,
        target: "http://target.test",
        scanId: "preload-unknown",
        preloadedSkillIds: ["does-not-exist"],
      },
      runtime,
      db: null,
    });
    expect(systems[0]).toBe("BASE PROMPT");
  });
});
