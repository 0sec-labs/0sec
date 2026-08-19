import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  cliConfigs: [] as Array<Record<string, unknown>>,
}));

vi.mock("./runtime/registry.js", () => ({
  detectAvailableRuntimes: vi.fn(async () => new Set(["codex"])),
  pickRuntimeForStage: vi.fn(() => "codex"),
}));

vi.mock("./runtime/process.js", () => ({
  ProcessRuntime: class {
    constructor(config: Record<string, unknown>) {
      state.cliConfigs.push(config);
    }
  },
}));

vi.mock("./agent/native-loop.js", () => ({
  runNativeAgentLoop: vi.fn(),
}));

vi.mock("../events/bus.js", () => ({
  eventBus: { emit: () => {}, on: () => () => {} },
}));

import { runNativeAgentLoop } from "./agent/native-loop.js";
import { runAnalysisAgent } from "./agent-runner.js";

const mockedLoop = vi.mocked(runNativeAgentLoop);

function opts(): Parameters<typeof runAnalysisAgent>[0] {
  return {
    role: "audit",
    scopePath: "/scope",
    target: "lodash",
    scanId: "scan-test",
    config: { runtime: "codex", timeout: 10_000 },
    db: null,
    emit: () => {},
    cliPrompt: "audit",
    agentSystemPrompt: "sys",
    cliSystemPrompt: "cli sys",
  };
}

describe("runAnalysisAgent — scoped source runtime boundary", () => {
  beforeEach(() => {
    state.cliConfigs.length = 0;
    process.env.OPENAI_API_KEY = "sk-test-dummy";
    mockedLoop.mockResolvedValue({
      findings: [],
      summary: "done",
      turnCount: 1,
      done: true,
      messages: [],
      totalUsage: { inputTokens: 0, outputTokens: 0 },
      estimatedCostUsd: 0,
      costCeilingExceeded: false,
    } as never);
  });

  afterEach(() => {
    delete process.env.OPENAI_API_KEY;
    vi.clearAllMocks();
  });

  it("never spawns an available CLI in an attacker-controlled source scope", async () => {
    await runAnalysisAgent(opts());

    expect(state.cliConfigs).toEqual([]);
    expect(mockedLoop).toHaveBeenCalledOnce();
    const config = mockedLoop.mock.calls[0]![0].config;
    expect(config.scopePath).toBe("/scope");
    expect(config.tools.map((tool) => tool.name)).toEqual([
      "read_file",
      "list_files",
      "search_files",
      "intel_search_advisories",
      "intel_lookup_cve",
      "intel_search_similar",
      "intel_build_dossier",
      "intel_search_target_history",
      "query_findings",
      "save_finding",
      "update_finding",
      "done",
    ]);
  });
});
