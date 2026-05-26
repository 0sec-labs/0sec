/**
 * Coverage seed for `pwnkit-cli`'s `mcp-server` command. This is the
 * stdio MCP server entry point — the one PR #295 made load-bearing
 * (gated Codex live scans now talk to pwnkit tools through here),
 * and the one verified end-to-end on dev. Prior to this seed it had
 * zero tests, so any regression in scope validation, auth-env parsing,
 * or wiring of tool executor / rate-limiter / attribution would have
 * shipped silently.
 *
 * Strategy: mock the heavy boundaries at the module level so we never
 *
 *   1. spawn a real MCP stdio transport,
 *   2. open the WASM SQLite DB, or
 *   3. construct a real ToolExecutor.
 *
 * Then register the command on a fresh Commander program and assert
 * on the inputs threaded into each mocked collaborator.
 *
 * Test areas covered:
 *   • parseAuthEnv() validation — the PR #295 CodeRabbit nit. Each
 *     auth-type (bearer/cookie/basic/header) is tested for missing
 *     and empty required fields, and the invalid-type sentinel.
 *   • parseJsonEnv() — malformed JSON rejected with a typed error
 *     mentioning the env-var name; empty/whitespace env-var → undefined.
 *   • Scope ordering nit — out-of-scope --target rejection MUST happen
 *     before pwnkitDB construction (else we leak a DB handle on the
 *     rejection path; per #295 review).
 *   • Argument plumbing — --scope, --rate-limit, --allow-scanners,
 *     --timeout flow through to the right collaborators with the
 *     right shapes.
 *   • Tool registration — only tools in MCP_LIVE_TOOL_NAMES are
 *     registered on the McpServer (the gate the live-scan path
 *     depends on; registering verify/discovery tools here would
 *     break role isolation).
 *
 * Out of scope (server-spawn-required):
 *   • The real stdio transport handshake — needs a peer over stdin,
 *     covered by integration tests in the cloud repo.
 *   • SIGINT/SIGTERM shutdown — calls process.exit(0) inline; exercising
 *     it cleanly requires a child-process harness, not a unit-test seed.
 *   • The withToolTimeout race — covered indirectly by the executor
 *     mock returning immediately; the timer path is pure JS and tested
 *     by inspection.
 *
 * Refactor notes (for follow-up PRs):
 *   • parseAuthEnv / parseJsonEnv are file-internal. Promoting them to
 *     named exports would let us drop the action wrapper and assert
 *     directly. Without that, we drive them through the action with
 *     env-var fixtures and a passing scope/target.
 *
 * Precedent: packages/cli/src/commands/__tests__/disclose.test.ts (#307),
 *            packages/cli/src/commands/__tests__/run.test.ts (#301),
 *            packages/cli/src/commands/__tests__/scan.test.ts (#301).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

// ── Module-level mocks ──────────────────────────────────────────────────────
//
// vi.mock is hoisted; the static imports below pick up our stubs. We
// mock four boundaries:
//
//   • @pwnkit/core   — loadScope, ToolExecutor, getToolsForRole,
//                       RateLimiter, parseRateLimitFlag, attribution
//   • @pwnkit/db      — pwnkitDB (no WASM SQLite open!)
//   • @modelcontextprotocol/sdk/server/mcp.js
//                     — McpServer (we capture .connect / .registerTool)
//   • @modelcontextprotocol/sdk/server/stdio.js
//                     — StdioServerTransport (no real stdio handshake)

interface ScopeMatchVerdict {
  allowed: boolean;
  reason?: string;
}

interface ScopeShim {
  match: (target: string) => ScopeMatchVerdict;
  raw: unknown;
}

const loadScopeMock = vi.fn<(path: string) => ScopeShim>();
const extractAttributionFromScopeJsonMock = vi.fn();
const resolveAttributionMock = vi.fn();
const parseRateLimitFlagMock = vi.fn();

// Capture the args ToolExecutor was constructed with so we can assert
// authConfig / scope / rateLimiter / allowScanners get threaded right.
const toolExecutorCtorCalls: Array<{
  ctx: Record<string, unknown>;
  db: unknown;
}> = [];
const toolExecutorInstances: Array<{
  execute: ReturnType<typeof vi.fn>;
  cleanup: ReturnType<typeof vi.fn>;
}> = [];

class FakeToolExecutor {
  execute = vi.fn().mockResolvedValue({ success: true, output: "ok" });
  cleanup = vi.fn().mockResolvedValue(undefined);
  constructor(ctx: Record<string, unknown>, db: unknown) {
    toolExecutorCtorCalls.push({ ctx, db });
    toolExecutorInstances.push(this);
  }
}

const rateLimiterCtorCalls: unknown[] = [];
class FakeRateLimiter {
  constructor(spec: unknown) {
    rateLimiterCtorCalls.push(spec);
  }
}

// The tool fixture covers the type/enum branches of zodForParam so we
// can assert registration without depending on the real tool registry.
const fakeTools = [
  {
    name: "http_request",
    description: "send an HTTP request",
    parameters: {
      url: { type: "string" as const, description: "target URL" },
      method: {
        type: "string" as const,
        description: "HTTP method",
        enum: ["GET", "POST"],
      },
      timeout_ms: { type: "number" as const, description: "timeout in ms" },
      follow_redirects: { type: "boolean" as const, description: "follow 3xx" },
      headers: { type: "object" as const, description: "header map" },
    },
    required: ["url", "method"],
  },
  {
    name: "save_finding",
    description: "persist a finding",
    parameters: {
      title: { type: "string" as const, description: "title" },
    },
    required: ["title"],
  },
  {
    // Not in MCP_LIVE_TOOL_NAMES — must be filtered out.
    name: "browser_navigate",
    description: "headless browser nav",
    parameters: {
      url: { type: "string" as const, description: "URL" },
    },
    required: ["url"],
  },
];
const getToolsForRoleMock = vi.fn(() => fakeTools);

vi.mock("@pwnkit/core", () => ({
  ToolExecutor: FakeToolExecutor,
  getToolsForRole: getToolsForRoleMock,
  loadScope: loadScopeMock,
  extractAttributionFromScopeJson: extractAttributionFromScopeJsonMock,
  resolveAttribution: resolveAttributionMock,
  RateLimiter: FakeRateLimiter,
  parseRateLimitFlag: parseRateLimitFlagMock,
}));

// Capture pwnkitDB construction order vs scope validation. PR #295's
// CodeRabbit nit was that scope-rejection happened AFTER the DB was
// opened; we assert the call-order is now scope-first.
const dbCtorCalls: Array<string | undefined> = [];
const dbInstances: Array<{ close: ReturnType<typeof vi.fn> }> = [];
class FakePwnkitDB {
  close = vi.fn();
  constructor(dbPath?: string) {
    dbCtorCalls.push(dbPath);
    dbInstances.push(this);
  }
}
vi.mock("@pwnkit/db", () => ({ pwnkitDB: FakePwnkitDB }));

// The MCP SDK: we replace McpServer with a recording shim. .connect
// resolves immediately so the action returns; .registerTool just
// captures (name, def, handler) for later inspection.
const registerToolCalls: Array<{
  name: string;
  def: { title: string; description: string; inputSchema: unknown };
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}> = [];
const serverConnectMock = vi.fn().mockResolvedValue(undefined);
const serverCloseMock = vi.fn().mockResolvedValue(undefined);

class FakeMcpServer {
  constructor(_info: unknown, _opts: unknown) {}
  registerTool(
    name: string,
    def: { title: string; description: string; inputSchema: unknown },
    handler: (args: Record<string, unknown>) => Promise<unknown>,
  ) {
    registerToolCalls.push({ name, def, handler });
  }
  connect(_transport: unknown): Promise<void> {
    return serverConnectMock();
  }
  close(): Promise<void> {
    return serverCloseMock();
  }
}
vi.mock("@modelcontextprotocol/sdk/server/mcp.js", () => ({
  McpServer: FakeMcpServer,
}));

class FakeStdioServerTransport {}
vi.mock("@modelcontextprotocol/sdk/server/stdio.js", () => ({
  StdioServerTransport: FakeStdioServerTransport,
}));

const { registerMcpServerCommand } = await import("../mcp-server.js");

// The action registers SIGINT/SIGTERM handlers per invocation. Since we
// fire the action many times in this file, raise the default 10-listener
// ceiling so Node doesn't spam MaxListenersExceededWarning. The handlers
// would call process.exit(0) if ever triggered — they aren't here.
process.setMaxListeners(64);

// ── Test harness ────────────────────────────────────────────────────────────

async function runCli(argv: string[]): Promise<unknown> {
  const program = new Command();
  program.exitOverride();
  program.configureOutput({
    writeOut: () => undefined,
    writeErr: () => undefined,
  });
  registerMcpServerCommand(program);
  try {
    await program.parseAsync(["node", "pwnkit-cli", ...argv]);
    return undefined;
  } catch (err) {
    // Commander throws on usage error; our action throws on validation
    // failures (out-of-scope target, bad auth env, malformed JSON env).
    // Return the error so tests can assert the message.
    return err;
  }
}

function allowingScope(): ScopeShim {
  return {
    raw: { scope: "fake" },
    match: () => ({ allowed: true }),
  };
}

let errSpy: ReturnType<typeof vi.spyOn>;
let logSpy: ReturnType<typeof vi.spyOn>;
const envSnapshot: Record<string, string | undefined> = {};

const ENV_KEYS = [
  "PWNKIT_MCP_AUTH_JSON",
  "PWNKIT_MCP_ATTRIBUTION_HEADERS_JSON",
  "PWNKIT_MCP_ATTRIBUTION_UA_TOKEN",
];

beforeEach(() => {
  loadScopeMock.mockReset();
  extractAttributionFromScopeJsonMock.mockReset().mockReturnValue(undefined);
  resolveAttributionMock.mockReset().mockReturnValue({
    headers: [],
    uaToken: undefined,
  });
  parseRateLimitFlagMock.mockReset().mockReturnValue({ default: 5, perHost: {} });
  getToolsForRoleMock.mockClear();
  toolExecutorCtorCalls.length = 0;
  toolExecutorInstances.length = 0;
  rateLimiterCtorCalls.length = 0;
  dbCtorCalls.length = 0;
  dbInstances.length = 0;
  registerToolCalls.length = 0;
  serverConnectMock.mockClear().mockResolvedValue(undefined);
  serverCloseMock.mockClear().mockResolvedValue(undefined);

  errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);

  for (const k of ENV_KEYS) {
    envSnapshot[k] = process.env[k];
    delete process.env[k];
  }
});

afterEach(() => {
  errSpy.mockRestore();
  logSpy.mockRestore();
  for (const k of ENV_KEYS) {
    const v = envSnapshot[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  // The action attaches SIGINT/SIGTERM handlers and never detaches them
  // (it expects the process to die). Strip them so they don't accumulate
  // across the ~30 invocations in this file.
  process.removeAllListeners("SIGINT");
  process.removeAllListeners("SIGTERM");
});

// ── Tests ───────────────────────────────────────────────────────────────────

describe("mcp-server — happy path wiring", () => {
  it("registers only MCP_LIVE_TOOL_NAMES tools (filters role tools)", async () => {
    const result = await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
    ]);
    expect(result).toBeUndefined();
    // fakeTools has http_request + save_finding (in the live set) and
    // browser_navigate (not in the live set). Only the first two should
    // reach registerTool.
    const names = registerToolCalls.map((c) => c.name).sort();
    expect(names).toEqual(["http_request", "save_finding"]);
  });

  it("constructs pwnkitDB and ToolExecutor when target/scan-id are valid", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
      "--db-path",
      "/tmp/pwnkit-test.db",
    ]);
    expect(dbCtorCalls).toEqual(["/tmp/pwnkit-test.db"]);
    expect(toolExecutorCtorCalls).toHaveLength(1);
    const ctx = toolExecutorCtorCalls[0]!.ctx;
    expect(ctx.target).toBe("https://example.com");
    expect(ctx.scanId).toBe("scan-abc");
    expect(ctx.persistFindings).toBe(true);
  });

  it("threads --allow-scanners=false (default) into ToolExecutor context", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
    ]);
    const ctx = toolExecutorCtorCalls[0]!.ctx;
    expect(ctx.allowScanners).toBe(false);
  });

  it("threads --allow-scanners=true into ToolExecutor context", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
      "--allow-scanners",
    ]);
    const ctx = toolExecutorCtorCalls[0]!.ctx;
    expect(ctx.allowScanners).toBe(true);
  });

  it("forwards --rate-limit spec to parseRateLimitFlag with default 5 rps", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
      "--rate-limit",
      "2",
    ]);
    expect(parseRateLimitFlagMock).toHaveBeenCalledWith("2", 5);
    // RateLimiter is constructed with whatever parseRateLimitFlag returns.
    expect(rateLimiterCtorCalls).toHaveLength(1);
  });

  it("uses '' + default 5 when --rate-limit is omitted", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
    ]);
    expect(parseRateLimitFlagMock).toHaveBeenCalledWith("", 5);
  });

  it("connects the MCP server (server.connect called exactly once)", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
    ]);
    expect(serverConnectMock).toHaveBeenCalledOnce();
  });
});

// ── parseAuthEnv: the PR #295 CodeRabbit-nit area ───────────────────────────

describe("mcp-server — PWNKIT_MCP_AUTH_JSON validation (PR #295)", () => {
  const baseArgs = [
    "mcp-server",
    "--target",
    "https://example.com",
    "--scan-id",
    "scan-abc",
  ];

  it("undefined env → authConfig undefined on ToolExecutor ctx", async () => {
    await runCli(baseArgs);
    const ctx = toolExecutorCtorCalls[0]!.ctx;
    expect(ctx.authConfig).toBeUndefined();
  });

  it("empty/whitespace env → authConfig undefined (not a parse error)", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = "   ";
    await runCli(baseArgs);
    const ctx = toolExecutorCtorCalls[0]!.ctx;
    expect(ctx.authConfig).toBeUndefined();
  });

  it("malformed JSON → typed error mentioning the env-var name", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = "{not json";
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/PWNKIT_MCP_AUTH_JSON.*valid JSON/);
  });

  it("invalid type → 'invalid auth type' error", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "oauth", token: "x" });
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/invalid auth type/i);
  });

  it("bearer w/ missing token → typed validation error", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "bearer" });
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/bearer auth requires.*'token'/);
  });

  it("bearer w/ empty-string token → rejected (CodeRabbit nit)", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "bearer", token: "" });
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/bearer auth requires/);
  });

  it("bearer w/ whitespace-only token → rejected", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "bearer", token: "   " });
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/bearer auth requires/);
  });

  it("bearer w/ valid token → threaded onto ToolExecutor ctx.authConfig", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "bearer", token: "sk-abc" });
    await runCli(baseArgs);
    const ctx = toolExecutorCtorCalls[0]!.ctx;
    expect(ctx.authConfig).toEqual({ type: "bearer", token: "sk-abc" });
  });

  it("cookie w/ missing 'value' → rejected (uses 'value' field, not 'cookie')", async () => {
    // AuthConfigCookie stores the full Cookie header value under `value`.
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "cookie" });
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/cookie auth requires.*'value'/);
  });

  it("cookie w/ valid value → threaded through", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "cookie", value: "sid=abc" });
    await runCli(baseArgs);
    const ctx = toolExecutorCtorCalls[0]!.ctx;
    expect(ctx.authConfig).toEqual({ type: "cookie", value: "sid=abc" });
  });

  it("basic w/ missing password → rejected (validates both fields)", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "basic", username: "u" });
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/basic auth requires.*'password'/);
  });

  it("basic w/ missing username → rejected", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "basic", password: "p" });
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/basic auth requires.*'username'/);
  });

  it("basic w/ both fields → threaded through", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({
      type: "basic",
      username: "u",
      password: "p",
    });
    await runCli(baseArgs);
    const ctx = toolExecutorCtorCalls[0]!.ctx;
    expect(ctx.authConfig).toEqual({ type: "basic", username: "u", password: "p" });
  });

  it("header w/ missing name → rejected", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({ type: "header", value: "v" });
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/header auth requires.*'name'/);
  });

  it("header w/ valid name + value → threaded through", async () => {
    process.env.PWNKIT_MCP_AUTH_JSON = JSON.stringify({
      type: "header",
      name: "X-Api-Key",
      value: "tok",
    });
    await runCli(baseArgs);
    const ctx = toolExecutorCtorCalls[0]!.ctx;
    expect(ctx.authConfig).toEqual({
      type: "header",
      name: "X-Api-Key",
      value: "tok",
    });
  });
});

// ── Scope plumbing + ordering (the second PR #295 nit) ──────────────────────

describe("mcp-server — scope validation ordering", () => {
  it("out-of-scope --target rejects BEFORE pwnkitDB is constructed", async () => {
    // The CodeRabbit nit on #295 was that scope validation must happen
    // before opening the DB, otherwise we leak a DB handle on the
    // rejection path. We assert that dbCtorCalls stays empty.
    loadScopeMock.mockReturnValueOnce({
      raw: {},
      match: () => ({ allowed: false, reason: "host not in scope" }),
    });
    const err = await runCli([
      "mcp-server",
      "--target",
      "https://evil.example.org",
      "--scan-id",
      "scan-abc",
      "--scope",
      "/tmp/scope.json",
    ]);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/out of scope/);
    expect((err as Error).message).toMatch(/host not in scope/);
    expect(dbCtorCalls).toHaveLength(0); // <- the load-bearing invariant
    expect(toolExecutorCtorCalls).toHaveLength(0);
  });

  it("in-scope --target lets the action proceed (scope.match called once)", async () => {
    const matchSpy = vi.fn(() => ({ allowed: true as const }));
    loadScopeMock.mockReturnValueOnce({ raw: { ok: true }, match: matchSpy });
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
      "--scope",
      "/tmp/scope.json",
    ]);
    expect(matchSpy).toHaveBeenCalledWith("https://example.com");
    expect(dbCtorCalls).toHaveLength(1);
    expect(toolExecutorCtorCalls).toHaveLength(1);
  });

  it("no --scope → loadScope is never called and scope is undefined on ctx", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
    ]);
    expect(loadScopeMock).not.toHaveBeenCalled();
    expect(toolExecutorCtorCalls[0]!.ctx.scope).toBeUndefined();
  });

  it("--scope present → resolveAttribution gets the scope-file attribution block", async () => {
    const scope: ScopeShim = allowingScope();
    loadScopeMock.mockReturnValueOnce(scope);
    extractAttributionFromScopeJsonMock.mockReturnValueOnce({
      headers: ["X-HackerOne: pwnkit"],
    });
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
      "--scope",
      "/tmp/scope.json",
    ]);
    expect(extractAttributionFromScopeJsonMock).toHaveBeenCalledWith(scope.raw);
    const resolveArgs = resolveAttributionMock.mock.calls[0]![0];
    expect(resolveArgs.scopeFileBlock).toEqual({
      headers: ["X-HackerOne: pwnkit"],
    });
  });
});

// ── parseJsonEnv plumbing via PWNKIT_MCP_ATTRIBUTION_HEADERS_JSON ───────────

describe("mcp-server — parseJsonEnv (via attribution headers env)", () => {
  const baseArgs = [
    "mcp-server",
    "--target",
    "https://example.com",
    "--scan-id",
    "scan-abc",
  ];

  it("valid JSON array → forwarded to resolveAttribution.cliHeaders", async () => {
    process.env.PWNKIT_MCP_ATTRIBUTION_HEADERS_JSON = JSON.stringify([
      "X-Trace: 1",
      "X-Audit: 2",
    ]);
    await runCli(baseArgs);
    const resolveArgs = resolveAttributionMock.mock.calls[0]![0];
    expect(resolveArgs.cliHeaders).toEqual(["X-Trace: 1", "X-Audit: 2"]);
  });

  it("malformed JSON → typed error mentioning the env-var name", async () => {
    process.env.PWNKIT_MCP_ATTRIBUTION_HEADERS_JSON = "[oops";
    const err = await runCli(baseArgs);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(
      /PWNKIT_MCP_ATTRIBUTION_HEADERS_JSON.*valid JSON/,
    );
  });

  it("PWNKIT_MCP_ATTRIBUTION_UA_TOKEN → forwarded to resolveAttribution.cliUaToken", async () => {
    process.env.PWNKIT_MCP_ATTRIBUTION_UA_TOKEN = "pwnkit-mcp/0.1";
    await runCli(baseArgs);
    const resolveArgs = resolveAttributionMock.mock.calls[0]![0];
    expect(resolveArgs.cliUaToken).toBe("pwnkit-mcp/0.1");
  });
});

// ── Tool registration — invariants for the live-scan gate ───────────────────

describe("mcp-server — tool registration", () => {
  it("calls getToolsForRole('attack', { webMode: true })", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
    ]);
    expect(getToolsForRoleMock).toHaveBeenCalledWith("attack", { webMode: true });
  });

  it("registers each kept tool with its description and an inputSchema object", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
    ]);
    const http = registerToolCalls.find((c) => c.name === "http_request");
    expect(http).toBeTruthy();
    expect(http!.def.description).toBe("send an HTTP request");
    expect(http!.def.inputSchema).toBeTruthy();
  });

  it("invokes the executor when a tool handler is called and maps success", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
    ]);
    const http = registerToolCalls.find((c) => c.name === "http_request");
    const result = (await http!.handler({
      url: "https://example.com",
      method: "GET",
    })) as { content: Array<{ text: string }>; structuredContent?: { success: boolean } };
    expect(toolExecutorInstances[0]!.execute).toHaveBeenCalledWith({
      name: "http_request",
      arguments: { url: "https://example.com", method: "GET" },
    });
    expect(result.content[0]!.text).toBe("ok");
    expect(result.structuredContent?.success).toBe(true);
  });

  it("maps an executor failure to an ERROR: text result", async () => {
    await runCli([
      "mcp-server",
      "--target",
      "https://example.com",
      "--scan-id",
      "scan-abc",
    ]);
    toolExecutorInstances[0]!.execute.mockResolvedValueOnce({
      success: false,
      output: null,
      error: "denied by scope",
    });
    const http = registerToolCalls.find((c) => c.name === "http_request");
    const result = (await http!.handler({
      url: "https://example.com",
      method: "GET",
    })) as { content: Array<{ text: string }>; structuredContent?: { success: boolean; error?: string } };
    expect(result.content[0]!.text).toMatch(/^ERROR: denied by scope/);
    expect(result.structuredContent?.success).toBe(false);
  });
});
