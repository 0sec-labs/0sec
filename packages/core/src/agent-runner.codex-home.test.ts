// The audit pipeline runs `codex exec` with cwd inside a package tree it just
// downloaded. Codex writes a trust entry for its cwd into the OPERATOR's
// ~/.codex/config.toml, and trust gates project-local config, hooks, exec
// policies and MCP servers — so the subprocess must get a throwaway CODEX_HOME.
// These pin the wiring: set for a temp-dir scope, absent for a real checkout,
// and gone from disk when the run ends.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const state = vi.hoisted(() => ({
  configs: [] as Array<Record<string, unknown>>,
  /** CODEX_HOME contents observed WHILE the subprocess was notionally running. */
  seenDuringRun: undefined as { exists: boolean; config: string } | undefined,
}));

vi.mock("./runtime/registry.js", () => ({
  detectAvailableRuntimes: vi.fn(async () => new Set(["codex"])),
  pickRuntimeForStage: vi.fn(() => "codex"),
}));

vi.mock("./runtime/process.js", () => ({
  ProcessRuntime: class {
    constructor(config: Record<string, unknown>) {
      state.configs.push(config);
    }
    async execute() {
      const env = state.configs.at(-1)?.env as Record<string, string> | undefined;
      const home = env?.CODEX_HOME;
      if (home) {
        state.seenDuringRun = {
          exists: existsSync(home),
          config: existsSync(join(home, "config.toml"))
            ? readFileSync(join(home, "config.toml"), "utf8")
            : "",
        };
      }
      return { output: "No vulnerabilities found.", exitCode: 0, timedOut: false, durationMs: 1 };
    }
  },
}));

import { runAnalysisAgent } from "./agent-runner.js";

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

describe("runAnalysisAgent — CODEX_HOME isolation for downloaded code", () => {
  const dirs: string[] = [];
  let operatorHome: string;

  beforeEach(() => {
    state.configs.length = 0;
    state.seenDuringRun = undefined;
    operatorHome = mkdtempSync(join(tmpdir(), "pwnkit-fake-codex-home-"));
    dirs.push(operatorHome);
    writeFileSync(join(operatorHome, "config.toml"), OPERATOR_CONFIG);
    vi.stubEnv("CODEX_HOME", operatorHome);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.clearAllMocks();
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("gives the subprocess its own trust-free CODEX_HOME when the scope is a temp tree", async () => {
    const scope = mkdtempSync(join(tmpdir(), "pwnkit-audit-"));
    dirs.push(scope);

    await runAnalysisAgent(opts(scope));

    const env = state.configs[0]!.env as Record<string, string>;
    expect(env.CODEX_HOME).toBeDefined();
    expect(env.CODEX_HOME).not.toBe(operatorHome);

    // It existed and carried the operator's provider config MINUS any trust.
    expect(state.seenDuringRun?.exists).toBe(true);
    expect(state.seenDuringRun?.config).toContain('model = "gpt-5.6-terra"');
    expect(state.seenDuringRun?.config).not.toContain("[projects.");
    expect(state.seenDuringRun?.config).not.toContain("trust_level");

    // …and it is gone once the run ends, taking any trust entry with it.
    expect(existsSync(env.CODEX_HOME)).toBe(false);
    // The operator's own config was never written to.
    expect(readFileSync(join(operatorHome, "config.toml"), "utf8")).toBe(OPERATOR_CONFIG);
  });

  it("leaves a real checkout alone — trusting your own repo is the point", async () => {
    await runAnalysisAgent(opts(process.cwd()));

    const env = state.configs[0]!.env as Record<string, string> | undefined;
    expect(env?.CODEX_HOME).toBeUndefined();
  });
});
