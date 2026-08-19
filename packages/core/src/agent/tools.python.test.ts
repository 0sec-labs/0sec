import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { ToolExecutor } from "./tools.js";
import type { ToolContext } from "./types.js";
import type { ScopePolicy } from "../scope/scope.js";

const T = 20_000;

const FLAG = "PWNKIT_FEATURE_PYTHON_EXEC";

function baseCtx(overrides: Partial<ToolContext> = {}): ToolContext {
  return {
    target: "http://localhost",
    scanId: "test-scan",
    findings: [],
    attackResults: [],
    targetInfo: {},
    ...overrides,
  };
}

describe("python_exec tool handler", () => {
  const prev = process.env[FLAG];

  beforeEach(() => {
    delete process.env[FLAG];
  });

  afterEach(() => {
    if (prev === undefined) delete process.env[FLAG];
    else process.env[FLAG] = prev;
  });

  it("returns the disabled message when the feature flag is off", async () => {
    const ex = new ToolExecutor(baseCtx(), null);
    const res = await ex.execute({ name: "python_exec", arguments: { code: "1 + 1" } });
    await ex.cleanup();
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/disabled/);
    expect(res.error).toMatch(/PWNKIT_FEATURE_PYTHON_EXEC/);
  });

  it("runs code and echoes a trailing expression when enabled", async () => {
    process.env[FLAG] = "1";
    const ex = new ToolExecutor(baseCtx(), null);
    const res = await ex.execute({ name: "python_exec", arguments: { code: "a = 20\nprint('hi')\na + 22" } });
    await ex.cleanup();
    expect(res.success).toBe(true);
    const out = res.output as { stdout: string; value?: string };
    expect(out.stdout).toContain("hi");
    expect(out.value).toBe("42");
  }, T);

  it("maps a Python traceback to success:false with the traceback tail", async () => {
    process.env[FLAG] = "1";
    const ex = new ToolExecutor(baseCtx(), null);
    const res = await ex.execute({ name: "python_exec", arguments: { code: "raise ValueError('boom')" } });
    await ex.cleanup();
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/ValueError: boom/);
    // stdout is still surfaced in the output payload for context.
    expect((res.output as { stdout: string }).stdout).toBe("");
  }, T);

  it("EGRESS: blocks raw sockets when an engagement scope is set", async () => {
    process.env[FLAG] = "1";
    const ex = new ToolExecutor(baseCtx({ scope: {} as unknown as ScopePolicy }), null);
    const res = await ex.execute({ name: "python_exec", arguments: { code: "import socket\nsocket.socket()" } });
    await ex.cleanup();
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/networking is disabled/i);
  }, T);

  it("EGRESS: urllib.urlopen fails closed when an engagement scope is set", async () => {
    process.env[FLAG] = "1";
    const ex = new ToolExecutor(baseCtx({ scope: {} as unknown as ScopePolicy }), null);
    const res = await ex.execute({
      name: "python_exec",
      arguments: { code: "import urllib.request\nurllib.request.urlopen('http://example.com')" },
    });
    await ex.cleanup();
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/networking is disabled/i);
  }, T);

  it("allows networking primitives when NO engagement scope is configured", async () => {
    process.env[FLAG] = "1";
    // No scope / enforcement → compute kernel is not egress-locked. We only
    // assert the socket object is constructible (no actual connection made).
    const ex = new ToolExecutor(baseCtx(), null);
    const res = await ex.execute({
      name: "python_exec",
      arguments: { code: "import socket\ns = socket.socket()\ns.close()\n'built'" },
    });
    await ex.cleanup();
    expect(res.success).toBe(true);
    expect((res.output as { value?: string }).value).toBe("'built'");
  }, T);
});
