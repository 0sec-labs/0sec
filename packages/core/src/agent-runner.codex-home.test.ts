// Source audits operate on attacker-controlled code. They must never reach a
// CLI runtime because its own project configuration, hooks, and trust mechanics
// sit outside ToolExecutor's scope boundary. The native tool loop is the only
// allowed path, so the operator's CODEX_HOME remains untouched.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

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

const OPERATOR_CONFIG = [
  'model = "gpt-5.6-terra"',
  "",
  '[projects."/private/var/folders/2b/T/pwnkit-audit-8103b3c8/node_modules/lodash"]',
  'trust_level = "trusted"',
  "",
].join("\n");

function opts(scopePath: string): Parameters<typeof runAnalysisAgent>[0] {
  return {
    role: "audit",
    scopePath,
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

describe("runAnalysisAgent — source scope runtime boundary", () => {
  const dirs: string[] = [];
  let operatorHome: string;

  beforeEach(() => {
    state.cliConfigs.length = 0;
    operatorHome = mkdtempSync(join(tmpdir(), "pwnkit-fake-codex-home-"));
    dirs.push(operatorHome);
    writeFileSync(join(operatorHome, "config.toml"), OPERATOR_CONFIG);
    vi.stubEnv("CODEX_HOME", operatorHome);
    vi.stubEnv("OPENAI_API_KEY", "sk-test-dummy");
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
    vi.unstubAllEnvs();
    vi.clearAllMocks();
    for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
  });

  it("never launches Codex against a downloaded source scope", async () => {
    const scope = mkdtempSync(join(tmpdir(), "pwnkit-audit-"));
    dirs.push(scope);

    await runAnalysisAgent(opts(scope));

    expect(state.cliConfigs).toEqual([]);
    expect(mockedLoop).toHaveBeenCalledOnce();
    expect(mockedLoop.mock.calls[0]?.[0].config).toMatchObject({ scopePath: scope });
    expect(readFileSync(join(operatorHome, "config.toml"), "utf8")).toBe(OPERATOR_CONFIG);
  });

  it("keeps the same boundary for an owned source checkout", async () => {
    await runAnalysisAgent(opts(process.cwd()));

    expect(state.cliConfigs).toEqual([]);
    expect(mockedLoop).toHaveBeenCalledOnce();
    expect(mockedLoop.mock.calls[0]?.[0].config).toMatchObject({ scopePath: process.cwd() });
    expect(readFileSync(join(operatorHome, "config.toml"), "utf8")).toBe(OPERATOR_CONFIG);
  });
});
