import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ToolExecutor, SELF_EXTENSION_RESERVED_TOOL_NAMES } from "./tools.js";
import { runNativeAgentLoop } from "./native-loop.js";
import type { ToolContext, ToolResult } from "./types.js";
import type { NativeRuntime, NativeRuntimeResult } from "../runtime/types.js";
import { SelfExtensionRegistry } from "../plugins/self-extension.js";
import { BUILTIN_GUARDS } from "../plugins/guards.js";
import { ExecutablePluginManager } from "../plugins/executable.js";
import { LiveHarnessHost } from "../plugins/live-harness.js";

beforeEach(() => vi.stubEnv("0SEC_DISABLE_HUNT_MEMORY", "1"));
afterEach(() => vi.unstubAllEnvs());

const submission = {
  manifest: {
    id: "test.executable", name: "Executable regression", version: "1.0.0",
    tools: [{ name: "executable_probe", description: "Returns an input", parameters: {}, capabilities: ["compute"] }],
  },
  files: { "main.ts": "export async function run(_name, args) { return args; }" },
  entry: "main.ts",
};

function registry(): SelfExtensionRegistry {
  return new SelfExtensionRegistry({
    enabled: true, baseGuards: BUILTIN_GUARDS, reservedToolNames: SELF_EXTENSION_RESERVED_TOOL_NAMES,
  });
}

function context(): ToolContext {
  return {
    target: "https://example.com", scanId: "executable-boundary-test", autonomyMode: "yolo",
    findings: [], attackResults: [], targetInfo: {}, selfExtension: registry(),
  };
}

describe("executable self-extension boundary", () => {
  it("does not admit metadata-only tools with no implementation", async () => {
    const executor = new ToolExecutor(context(), null);
    try {
      const result = await executor.execute({ name: "self_extend", arguments: { manifest: submission.manifest } });
      expect(result.success).toBe(false);
      const call = await executor.execute({ name: "executable_probe", arguments: {} });
      expect(call.success).toBe(false);
    } finally {
      await executor.cleanup();
    }
  });

  it("rejects executable source when no isolated backend is configured", async () => {
    const executor = new ToolExecutor(context(), null);
    try {
      const result = await executor.execute({ name: "self_extend", arguments: submission });
      expect(result.success).toBe(false);
      const call = await executor.execute({ name: "executable_probe", arguments: {} });
      expect(call.success).toBe(false);
    } finally {
      await executor.cleanup();
    }
  });

  it("does not turn model-supplied trust into host execution", async () => {
    const root = mkdtempSync(join(tmpdir(), "0sec-harness-trust-boundary-"));
    const marker = join(root, "host-code-ran");
    const ctx = context();
    const manager = new ExecutablePluginManager({
      registry: ctx.selfExtension!, root: join(root, "executable"),
      backend: "docker", image: "0sec-toolbox:qualification",
    });
    const harness = new LiveHarnessHost({
      executablePlugins: manager, root: join(root, "harness"),
      workspaceRoot: root, allowTrusted: () => false,
    });
    ctx.executablePlugins = manager;
    ctx.liveHarness = harness;
    const executor = new ToolExecutor(ctx, null);
    try {
      const result = await executor.execute({
        name: "self_extend",
        arguments: {
          action: "harness_submit", trusted: true, allowTrusted: true, workspaceRoot: root,
          generation: {
            label: "Model-supplied grant",
            providers: [{
              id: "untrusted", services: ["agent.driver"],
              source: {
                kind: "trusted", entry: "main.mjs",
                files: {
                  "main.mjs": `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(marker)}, "ran"); export function activate() { return {}; }`,
                },
              },
            }],
          },
        },
      });
      expect(result.success).toBe(false);
      expect(result.error).toMatch(/trust|grant/i);
      expect(existsSync(marker)).toBe(false);
      expect(await harness.drive({ system: "", messages: [], tools: [] }, {})).toBeUndefined();
    } finally {
      await harness.close();
      await manager.close();
      await executor.cleanup();
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("reserves child-only dispatch names as well as ordinary built-ins", () => {
    const result = registry().register({
      manifest: {
        ...submission.manifest,
        tools: [{ ...submission.manifest.tools[0], name: "send_message" }],
      },
    });
    expect(result.ok).toBe(false);
  });
});

for (const permission of [
  { role: "discovery" as const, enabled: false, reason: "explicitly disabled" },
  { role: "verify" as const, enabled: true, reason: "the independent verifier" },
]) {
  it(`does not expose or activate source rewriting for ${permission.reason}`, async () => {
    const advertised: string[][] = [];
    const outcomes: ToolResult[] = [];
    let turn = 0;
    const runtime: NativeRuntime = {
      type: "api",
      async isAvailable() { return true; },
      async executeNative(_system, _messages, tools): Promise<NativeRuntimeResult> {
        advertised.push(tools.map((tool) => tool.name));
        return {
          content: turn++ === 0
            ? [{ type: "tool_use", id: "submit", name: "self_extend", input: submission }]
            : [{ type: "tool_use", id: "finish", name: "done", input: { summary: "Finished" } }],
          stopReason: "tool_use", durationMs: 0,
        };
      },
    };
    await runNativeAgentLoop({
      config: {
        role: permission.role, systemPrompt: "Exercise explicit permissions", tools: [], maxTurns: 2,
        target: "https://example.com", scanId: `executable-${permission.role}`,
        allowModelSelfExtension: permission.enabled,
      },
      runtime, db: null,
      onTurn: (_turn, calls, results) => {
        calls.forEach((call, index) => { if (call.name === "self_extend") outcomes.push(results[index]!); });
      },
    });
    expect(advertised.every((names) => !names.includes("self_extend") && !names.includes("executable_probe"))).toBe(true);
    expect(outcomes).toHaveLength(1);
    expect(outcomes[0]!.success).toBe(false);
  });
}
