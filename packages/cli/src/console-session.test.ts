import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { osecDB } from "@0sec/db";
import type { NativeRuntime, NativeRuntimeResult } from "@0sec/core";
import { createLocalConsoleSession } from "./console-session.js";
import { createConversationHistory } from "./conversation-history.js";
import { saveSession } from "./tui/session-store.js";

function toolRuntime(name: string, input: Record<string, unknown>): NativeRuntime {
  const script: NativeRuntimeResult[] = [
    { content: [{ type: "tool_use", id: "history-call", name, input }], stopReason: "tool_use", durationMs: 0 },
    { content: [{ type: "text", text: "Done." }], stopReason: "end_turn", durationMs: 0 },
  ];
  return {
    type: "api",
    isAvailable: async () => true,
    executeNative: async () => {
      const result = script.shift();
      if (!result) throw new Error("Unexpected model call");
      return result;
    },
  };
}

const directories: string[] = [];
function databasePath(): string {
  const directory = mkdtempSync(join(tmpdir(), "0sec-console-history-"));
  directories.push(directory);
  return join(directory, "findings.db");
}

afterEach(() => {
  vi.unstubAllEnvs();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("local console persistent history", () => {
  it("reads prior findings through the real cross-session tool using the configured store", async () => {
    const path = databasePath();
    const seed = new osecDB(path);
    const priorId = seed.createScan({ target: "https://history.example.test", depth: "default", format: "terminal" });
    seed.saveFinding(priorId, {
      id: "prior-finding",
      templateId: "history-fixture",
      title: "Stored finding from an older run",
      description: "Stored before this console existed",
      severity: "high",
      category: "xss",
      status: "discovered",
      evidence: { request: "fixture", response: "fixture" },
      timestamp: 1,
    });
    seed.completeScan(priorId, {});
    seed.close();
    vi.stubEnv("0SEC_DB_PATH", path);

    const session = createLocalConsoleSession({ runtime: toolRuntime("query_findings", { all_sessions: true, limit: 50 }) });
    try {
      const outcome = await session.send("Show the findings from old runs");
      expect(outcome.toolCalls[0].result).toMatchObject({
        success: true,
        output: [expect.objectContaining({ id: "prior-finding", scanId: priorId })],
      });
    } finally {
      await session.cleanup();
    }
  });

  it("persists new console findings for a later session and closes idempotently", async () => {
    const path = databasePath();
    const writer = createLocalConsoleSession({
      target: "https://history.example.test",
      approveTool: async () => true,
      runtime: toolRuntime("save_finding", {
        title: "Persistent console finding",
        description: "Evidence survives closing the console",
        severity: "high",
        category: "xss",
        template_id: "history-fixture",
        evidence_request: "fixture request",
        evidence_response: "fixture response",
      }),
    }, path);
    try {
      const outcome = await writer.send("Record the finding");
      expect(outcome.toolCalls[0].result.success, JSON.stringify(outcome.toolCalls[0].result)).toBe(true);
    } finally {
      await writer.cleanup();
      await writer.cleanup();
    }
    const reader = createLocalConsoleSession({ runtime: toolRuntime("query_findings", { scan_id: writer.scanId }) }, path);
    try {
      const outcome = await reader.send("Read that prior session");
      expect(outcome.toolCalls[0].result).toMatchObject({
        success: true,
        output: [expect.objectContaining({ title: "Persistent console finding", scanId: writer.scanId })],
      });
    } finally {
      await reader.cleanup();
    }
  });
  it.each(["recon", "standard", "copilot"] as const)("reads saved conversations without approval in %s mode", async (autonomyMode) => {
    const path = databasePath();
    const home = dirname(path);
    expect(saveSession({
      id: "prior-conversation",
      cwd: "/history-project",
      savedAt: 1,
      preview: "",
      messageCount: 1,
      messages: [{ role: "assistant", content: "Earlier investigation result" }],
    }, home)).toBe(true);
    const session = createLocalConsoleSession({
      autonomyMode,
      runtime: toolRuntime("read_conversation", { session_id: "prior-conversation" }),
      conversationHistory: createConversationHistory({ homeDir: home, cwd: "/history-project" }),
    }, path);
    try {
      const outcome = await session.send("Read the earlier conversation");
      expect(outcome.toolCalls[0].result).toMatchObject({
        success: true,
        output: { messages: [{ text: "Earlier investigation result" }] },
      });
    } finally {
      await session.cleanup();
    }
  });
});
