// agent-runner errorExit propagation — a hard agent-loop exit (auth 401,
// exhausted transient retries) must reach the caller's error path instead of
// reading as a clean "0 findings" return (the false-clean hole measured
// 2026-07-17: codex 401 → clean report with empty warnings).

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("./agent/native-loop.js", () => ({
  runNativeAgentLoop: vi.fn(),
}));

// No CLI runtimes available — routes deterministically to the API branch
// (and skips the real `--version` subprocess probes, which take seconds on a
// dev machine with claude/codex installed).
vi.mock("./runtime/registry.js", () => ({
  detectAvailableRuntimes: vi.fn(async () => new Set()),
  pickRuntimeForStage: vi.fn(() => "api"),
}));

vi.mock("../events/bus.js", () => ({
  eventBus: { emit: () => {}, on: () => () => {} },
}));

import { runNativeAgentLoop } from "./agent/native-loop.js";
import { runAnalysisAgent } from "./agent-runner.js";

const mockedLoop = vi.mocked(runNativeAgentLoop);

function baseOpts(): Parameters<typeof runAnalysisAgent>[0] {
  return {
    role: "audit",
    scopePath: "/scope",
    target: "lodash",
    scanId: "scan-test",
    config: { runtime: "api", model: "gpt-5.4", timeout: 10_000 },
    db: null,
    emit: () => {},
    cliPrompt: "audit",
    agentSystemPrompt: "sys",
    cliSystemPrompt: "cli sys",
  };
}

describe("runAnalysisAgent — errorExit propagation", () => {
  beforeEach(() => {
    process.env.OPENAI_API_KEY = "sk-test-dummy";
  });
  afterEach(() => {
    delete process.env.OPENAI_API_KEY;
    vi.clearAllMocks();
  });

  it("throws when the agent loop exits via errorExit (never a fake clean)", async () => {
    mockedLoop.mockResolvedValue({
      findings: [],
      summary: "Error: OpenAI API error 401: bad key",
      errorExit: { error: "OpenAI API error 401: bad key", turn: 1 },
      turnCount: 1,
      done: true,
      messages: [],
      totalUsage: { inputTokens: 0, outputTokens: 0 },
      estimatedCostUsd: 0,
      costCeilingExceeded: false,
    } as never);

    await expect(runAnalysisAgent(baseOpts())).rejects.toThrow("401");
  });

  it("returns findings normally when there is no errorExit", async () => {
    const finding = { title: "x", severity: "high", category: "c", file: "a.js", description: "d", poc: "p" };
    mockedLoop.mockResolvedValue({
      findings: [finding],
      summary: "done",
      turnCount: 3,
      done: true,
      messages: [],
      totalUsage: { inputTokens: 10, outputTokens: 5 },
      estimatedCostUsd: 0.01,
      costCeilingExceeded: false,
    } as never);

    const res = await runAnalysisAgent(baseOpts());
    expect(res.findings).toHaveLength(1);
    expect(res.turns).toBe(3);
  });
});
