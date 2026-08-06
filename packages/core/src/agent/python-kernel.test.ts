import { describe, it, expect, afterEach } from "vitest";
import { PythonKernelManager } from "./python-kernel.js";
import { MAX_CONCURRENT_SESSIONS, IDLE_TIMEOUT_MS } from "./pty-session.js";

// Each test drives a real python3 child, so give the spawns headroom.
const T = 20_000;

describe("PythonKernelManager", () => {
  let mgr: PythonKernelManager | null = null;

  afterEach(() => {
    mgr?.cleanup();
    mgr = null;
  });

  it("persists globals state across sends into one kernel", async () => {
    mgr = new PythonKernelManager();
    const s = mgr.createSession();
    const set = await mgr.send(s.id, "x = 40");
    expect(set.error).toBeNull();

    const use = await mgr.send(s.id, "x + 2");
    expect(use.error).toBeNull();
    expect(use.value).toBe("42");
  }, T);

  it("captures stdout and a trailing-expression repr separately", async () => {
    mgr = new PythonKernelManager();
    const s = mgr.createSession();
    const frame = await mgr.send(s.id, "print('hello')\n7 * 6");
    expect(frame.stdout).toContain("hello");
    expect(frame.value).toBe("42");
    expect(frame.error).toBeNull();
  }, T);

  it("reset() respawns a fresh interpreter and clears persistent state", async () => {
    mgr = new PythonKernelManager();
    const s = mgr.createSession();
    await mgr.send(s.id, "y = 5");
    expect((await mgr.send(s.id, "y")).value).toBe("5");

    mgr.reset(s.id);

    const afterReset = await mgr.send(s.id, "y");
    expect(afterReset.error).not.toBeNull();
    expect(afterReset.traceback ?? "").toMatch(/NameError/);
  }, T);

  it("surfaces a Python exception as an error frame with a traceback", async () => {
    mgr = new PythonKernelManager();
    const s = mgr.createSession();
    const frame = await mgr.send(s.id, "raise ValueError('boom')");
    expect(frame.error).not.toBeNull();
    expect(frame.traceback ?? "").toMatch(/ValueError: boom/);
  }, T);

  it("enforces the concurrent-session cap", async () => {
    mgr = new PythonKernelManager();
    for (let i = 0; i < MAX_CONCURRENT_SESSIONS; i++) {
      mgr.createSession(`k${i}`);
    }
    expect(() => mgr!.createSession("one-too-many")).toThrow(/Maximum concurrent kernels/);
  }, T);

  it("reaps idle sessions past IDLE_TIMEOUT_MS", async () => {
    mgr = new PythonKernelManager();
    const s = mgr.createSession();
    // Backdate last use beyond the idle window without waiting.
    s.lastUsedAt = Date.now() - IDLE_TIMEOUT_MS - 1_000;
    const reaped = mgr.reapIdleSessions();
    expect(reaped).toBe(1);
    expect(mgr.findByName(s.name)).toBeUndefined();
  }, T);

  it("cleanup() kills the child process", async () => {
    mgr = new PythonKernelManager();
    const s = mgr.createSession();
    await mgr.send(s.id, "1 + 1");
    mgr.cleanup();
    expect(mgr.listSessions()).toHaveLength(0);
    expect(s.process.killed).toBe(true);
    mgr = null;
  }, T);

  it("does not wedge when user code writes raw bytes to fd 1", async () => {
    // The kernel dups fd 1 for framing and points the real fd 1 at /dev/null,
    // so `os.write(1, ...)` from user code cannot corrupt the frame protocol.
    mgr = new PythonKernelManager();
    const s = mgr.createSession();
    const frame = await mgr.send(s.id, "import os\nos.write(1, b'garbage-not-a-frame')\n42");
    expect(frame.value).toBe("42");
    // And the kernel keeps working for the next call.
    const next = await mgr.send(s.id, "'ok'");
    expect(next.value).toBe("'ok'");
  }, T);
});
