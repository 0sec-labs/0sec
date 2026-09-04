import { describe, expect, it, vi } from "vitest";
import type {
  ConsoleRenderCallbacks,
  ConsoleScopeRequest,
  ConsoleSession,
  ConsoleTurnOutcome,
  ScopePolicy,
  ToolCall,
} from "@0sec/core";
import { DesktopConsoleGateway, DesktopConsoleGatewayError } from "./console-gateway.js";

type GatewayFactoryInput = {
  scanId: string;
  target: string;
  autonomyMode: "standard" | "recon" | "copilot" | "yolo";
  approveTool: (call: ToolCall) => Promise<boolean>;
};

function outcome(): ConsoleTurnOutcome {
  return {
    assistantText: "I inspected the requested file.",
    toolCalls: [],
    usage: { inputTokens: 10, outputTokens: 5 },
    budget: { tokensUsed: 15, tokenBudget: 1000, iterations: 1, maxToolIterations: 100 },
    stopReason: "end_turn",
  };
}

function makeSession(input: GatewayFactoryInput): ConsoleSession {
  const call: ToolCall = { name: "read_file", arguments: { path: "/tmp/target.ts" } };
  const session: ConsoleSession = {
    scanId: input.scanId,
    systemPrompt: "test",
    tools: [],
    messages: [],
    autonomyMode: input.autonomyMode,
    target: input.target,
    scope: undefined,
    localScopePath: undefined,
    setAutonomyMode: () => undefined,
    clearConversation: () => undefined,
    async send(_text, callbacks?, _options?): Promise<ConsoleTurnOutcome> {
      callbacks?.onAssistantDelta?.("I inspected ");
      callbacks?.onToolStart?.(call);
      const approved = await input.approveTool(call);
      callbacks?.onToolResult?.(
        call,
        approved
          ? { success: true, output: "export const safe = true;" }
          : { success: false, output: null, error: "Denied by operator" },
      );
      callbacks?.onAssistantDelta?.("the requested file.");
      callbacks?.onUsage?.({
        inputTokens: 10,
        outputTokens: 5,
        turnTokensUsed: 15,
        turnTokenBudget: 1000,
        iterations: 1,
        maxToolIterations: 100,
      });
      return outcome();
    },
    cleanup: async () => undefined,
  };
  return session;
}

function createGateway(): DesktopConsoleGateway {
  let sequence = 0;
  return new DesktopConsoleGateway({
    createId: () => `id-${++sequence}`,
    now: () => new Date("2026-08-31T00:00:00.000Z"),
    createSession: (input) => makeSession(input),
  });
}

describe("DesktopConsoleGateway", () => {
  it("creates a renderer-safe session and emits a session event", () => {
    const gateway = createGateway();

    const session = gateway.create({ target: "https://app.example.test", role: "audit", autonomyMode: "standard" });

    expect(session).toMatchObject({
      id: "id-1",
      target: "https://app.example.test",
      role: "audit",
      autonomyMode: "standard",
      status: "ready",
    });
    expect(gateway.eventsAfter(session.id)).toMatchObject([{ type: "session", session: { id: session.id } }]);
  });

  it("holds a standard-mode tool call until the operator resolves its decision", async () => {
    const gateway = createGateway();
    const session = gateway.create();

    gateway.send(session.id, "Inspect the target file");

    await vi.waitFor(() => {
      expect(gateway.eventsAfter(session.id).some((event) => event.type === "decision" && event.decision.kind === "tool")).toBe(true);
    });
    const decision = gateway.eventsAfter(session.id).find((event) => event.type === "decision");
    if (!decision || decision.type !== "decision") throw new Error("Expected a pending tool decision.");
    expect(gateway.list()[0]?.status).toBe("waiting");

    gateway.resolveDecision(session.id, decision.decision.id, { approve: true });

    await vi.waitFor(() => {
      expect(gateway.eventsAfter(session.id).some((event) => event.type === "turn-complete")).toBe(true);
    });
    const types = gateway.eventsAfter(session.id).map((event) => event.type);
    expect(types).toContain("user");
    expect(types).toContain("assistant-delta");
    expect(types).toContain("tool-result");
    expect(types).toContain("usage");
    expect(gateway.list()[0]?.status).toBe("ready");
  });

  it("extends network scope only after the matching approval resolves", async () => {
    let sequence = 0;
    let approvedScope: { target: string; scope: ScopePolicy } | null | undefined;
    const gateway = new DesktopConsoleGateway({
      createId: () => `scope-${++sequence}`,
      now: () => new Date("2026-08-31T00:00:00.000Z"),
      createSession: (input) => {
        const session = makeSession(input);
        const call: ToolCall = { name: "http_request", arguments: { url: "https://api.example.test/v1" } };
        session.send = async (_text, _callbacks, _options) => {
          const request: ConsoleScopeRequest = {
            call,
            requestedUrls: ["https://api.example.test/v1"],
            target: input.target,
          };
          approvedScope = await input.requestScope(request);
          return outcome();
        };
        return session;
      },
    });
    const session = gateway.create({ target: "https://app.example.test" });

    gateway.send(session.id, "Inspect the API");
    await vi.waitFor(() => {
      expect(gateway.eventsAfter(session.id).some((event) => event.type === "decision" && event.decision.kind === "scope")).toBe(true);
    });
    const decision = gateway.eventsAfter(session.id).find((event) => event.type === "decision" && event.decision.kind === "scope");
    if (!decision || decision.type !== "decision") throw new Error("Expected a scope approval.");

    gateway.resolveDecision(session.id, decision.decision.id, { approve: true });
    await vi.waitFor(() => expect(approvedScope).toBeDefined());

    expect(approvedScope?.scope.match("https://api.example.test/v1").allowed).toBe(true);
    expect(approvedScope?.scope.match("https://outside.example.test/").allowed).toBe(false);
  });

  it("rejects malformed session and decision input before it reaches the engine", () => {
    const gateway = createGateway();

    expect(() => gateway.create({ autonomyMode: "unsafe" as never })).toThrow(DesktopConsoleGatewayError);
    const session = gateway.create();
    expect(() => gateway.send(session.id, "   ")).toThrow(/cannot be empty/i);
    expect(() => gateway.resolveDecision(session.id, "missing", { approve: true })).toThrow(/no longer pending/i);
  });
});
