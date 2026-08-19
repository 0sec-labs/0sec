/**
 * Python Kernel Manager — persistent, framed Python REPL sessions for the
 * native agent loop (Phase-0 `python_exec`). Mirrors `PtySessionManager`'s
 * lifecycle (Map of sessions, concurrent cap, idle reaping, cleanup) but the
 * transport is a length-prefixed JSON frame protocol rather than prompt
 * scraping.
 *
 * Each session spawns `python3 -u -c "<repl server>"`. The embedded server:
 *   - reads length-prefixed UTF-8 code frames on stdin,
 *   - `exec()`s each frame into ONE persistent globals dict (state persists
 *     across calls),
 *   - captures stdout/stderr via `contextlib.redirect_*`,
 *   - evaluates a trailing expression for its `repr()` (REPL-style value),
 *   - writes exactly ONE length-prefixed JSON frame
 *     `{stdout, stderr, value, error, traceback}` back per call.
 *
 * EGRESS SAFETY (the whole point of the Phase-0 cut): when `blockNetworking`
 * is set, the repl-server preamble installs a socket guard that raises on
 * `socket.socket` / `socket.create_connection`, so `urllib` / `requests` /
 * `http.client` all fail CLOSED — the kernel is compute-only during an active
 * engagement.
 *
 * The server also dups fd 1 to a private handle and redirects the real fd 1 to
 * /dev/null before running any user code, so user code that writes raw bytes
 * to stdout (`os.write(1, ...)`) can't corrupt the frame protocol.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { MAX_CONCURRENT_SESSIONS, IDLE_TIMEOUT_MS } from "./pty-session.js";

/** One length-prefixed JSON response frame from the kernel. */
export interface KernelFrame {
  /** Captured stdout produced while executing the code frame. */
  stdout: string;
  /** Captured stderr produced while executing the code frame. */
  stderr: string;
  /** `repr()` of a trailing expression, or null when there was none / it was None. */
  value: string | null;
  /** `repr()` of a raised exception, or null on success. */
  error: string | null;
  /** Full formatted traceback when an exception was raised, else null. */
  traceback: string | null;
}

interface PendingCall {
  resolve: (frame: KernelFrame) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export interface PythonKernelSession {
  id: string;
  name: string;
  process: ChildProcess;
  createdAt: number;
  lastUsedAt: number;
  alive: boolean;
}

/** Internal shape — carries the frame-decoder buffer + pending-call queue. */
interface InternalSession extends PythonKernelSession {
  buffer: Buffer;
  pending: PendingCall[];
  stderrBuf: string;
}

const DEFAULT_SESSION_NAME = "default";

// The embedded Python REPL server. Passed to `python3 -u -c`. Kept free of
// f-strings and backticks so it survives both the JS template literal and
// Python parsing untouched.
const REPL_SERVER = `
import sys, os, io, json, struct, ast, contextlib
import traceback as _tb

# Dup the real stdout to a private handle for the frame protocol, then send the
# original fd 1 to /dev/null so user code writing raw bytes to stdout cannot
# corrupt the length-prefixed stream.
_frame_out = os.fdopen(os.dup(1), "wb", buffering=0)
_devnull = os.open(os.devnull, os.O_WRONLY)
os.dup2(_devnull, 1)
_stdin = sys.stdin.buffer

# EGRESS GUARD: fail networking CLOSED when the host asks for a compute-only
# kernel. socket.socket stays a SUBCLASSABLE class (ssl.py does
# 'class SSLSocket(socket)' at import time) but raises on instantiation, and
# socket.create_connection raises directly. Together this makes raw sockets,
# urllib, requests, and http.client all fail closed.
if os.environ.get("0SEC_KERNEL_BLOCK_NET") == "1":
    import socket as _socket
    _NET_MSG = "networking is disabled in this compute-only kernel (engagement active)"
    _RealSocket = _socket.socket
    class _BlockedSocket(_RealSocket):
        def __init__(self, *a, **k):
            raise OSError(_NET_MSG)
    _socket.socket = _BlockedSocket
    def _blocked_conn(*a, **k):
        raise OSError(_NET_MSG)
    _socket.create_connection = _blocked_conn
    try:
        _socket.socketpair = _blocked_conn
    except Exception:
        pass

_G = {"__name__": "__kernel__", "__builtins__": __builtins__}

def _read_exact(n):
    buf = b""
    while len(buf) < n:
        chunk = _stdin.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def _read_frame():
    hdr = _read_exact(4)
    if hdr is None:
        return None
    (n,) = struct.unpack(">I", hdr)
    if n == 0:
        return ""
    body = _read_exact(n)
    if body is None:
        return None
    return body.decode("utf-8", "replace")

def _write_frame(obj):
    payload = json.dumps(obj).encode("utf-8")
    _frame_out.write(struct.pack(">I", len(payload)))
    _frame_out.write(payload)
    _frame_out.flush()

def _run(code):
    out = io.StringIO()
    err = io.StringIO()
    value = None
    error = None
    trace = None
    try:
        parsed = ast.parse(code, "<kernel>", "exec")
        last_expr = None
        if parsed.body and isinstance(parsed.body[-1], ast.Expr):
            last_expr = parsed.body.pop()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            if parsed.body:
                exec(compile(parsed, "<kernel>", "exec"), _G)
            if last_expr is not None:
                val = eval(compile(ast.Expression(last_expr.value), "<kernel>", "eval"), _G)
                if val is not None:
                    value = repr(val)
    except BaseException as e:
        error = repr(e)
        trace = _tb.format_exc()
    return {"stdout": out.getvalue(), "stderr": err.getvalue(), "value": value, "error": error, "traceback": trace}

while True:
    try:
        code = _read_frame()
    except Exception:
        break
    if code is None:
        break
    _write_frame(_run(code))
`;

export class PythonKernelManager {
  private sessions = new Map<string, InternalSession>();

  /**
   * When true, newly spawned (and respawned) kernels block all networking at
   * the socket source. Set by the tool executor to the truthiness of an active
   * engagement (scope / enforcement) BEFORE the first `createSession`.
   */
  blockNetworking = false;

  /**
   * Create a new persistent Python kernel session. Mirrors
   * `PtySessionManager.createSession` (reap-first, concurrent cap, name dedupe).
   */
  createSession(name: string = DEFAULT_SESSION_NAME): PythonKernelSession {
    this.reapIdleSessions();

    const aliveSessions = Array.from(this.sessions.values()).filter((s) => s.alive);
    if (aliveSessions.length >= MAX_CONCURRENT_SESSIONS) {
      throw new Error(
        `Maximum concurrent kernels (${MAX_CONCURRENT_SESSIONS}) reached. Close an existing kernel first.`,
      );
    }
    for (const s of this.sessions.values()) {
      if (s.name === name && s.alive) {
        throw new Error(`Kernel "${name}" already exists and is alive. Close it first or use a different name.`);
      }
    }

    const id = randomUUID().slice(0, 8);
    const now = Date.now();
    const session: InternalSession = {
      id,
      name,
      process: this.spawnKernel(),
      createdAt: now,
      lastUsedAt: now,
      alive: true,
      buffer: Buffer.alloc(0),
      pending: [],
      stderrBuf: "",
    };
    this.wire(session);
    this.sessions.set(id, session);
    return session;
  }

  /**
   * Ensure the singleton "default" kernel exists and is alive, creating it on
   * demand. The Phase-0 `python_exec` tool drives ONE persistent kernel per
   * executor, so this is the common entry point.
   */
  ensureDefaultSession(): PythonKernelSession {
    const existing = this.findByName(DEFAULT_SESSION_NAME);
    if (existing && existing.alive) return existing;
    if (existing) this.close(existing.id);
    return this.createSession(DEFAULT_SESSION_NAME);
  }

  /**
   * Send one code frame to a kernel and await its single response frame.
   * Rejects (and RESPAWNS the kernel so it stays usable) if no frame arrives
   * within `timeoutMs`.
   */
  send(sessionId: string, code: string, timeoutMs = 30_000): Promise<KernelFrame> {
    const session = this.getSession(sessionId);
    if (!session.alive) {
      return Promise.reject(new Error(`Kernel "${session.name}" (${sessionId}) is no longer alive.`));
    }
    if (!session.process.stdin?.writable) {
      return Promise.reject(new Error(`Kernel "${session.name}" (${sessionId}) stdin is not writable.`));
    }
    session.lastUsedAt = Date.now();

    return new Promise<KernelFrame>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = session.pending.findIndex((p) => p.timer === timer);
        if (idx >= 0) session.pending.splice(idx, 1);
        // Unwedge: a hung kernel (infinite loop) never returns a frame, so
        // respawn it with a fresh globals dict rather than leaving it stuck.
        try {
          this.respawn(session);
        } catch {
          // Best-effort — respawn failure surfaces on the next call.
        }
        reject(new Error(`python_exec timed out after ${timeoutMs}ms; kernel was reset.`));
      }, timeoutMs);

      session.pending.push({ resolve, reject, timer });

      const codeBuf = Buffer.from(code, "utf-8");
      const header = Buffer.alloc(4);
      header.writeUInt32BE(codeBuf.length, 0);
      try {
        session.process.stdin!.write(header);
        session.process.stdin!.write(codeBuf);
      } catch (err) {
        clearTimeout(timer);
        const idx = session.pending.findIndex((p) => p.timer === timer);
        if (idx >= 0) session.pending.splice(idx, 1);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  /**
   * Reset a kernel: kill the child and respawn a fresh interpreter, discarding
   * all persistent state. Any in-flight call is rejected.
   */
  reset(sessionId: string): void {
    const session = this.getSession(sessionId);
    this.respawn(session);
  }

  /** Close / terminate a kernel. */
  close(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.rejectPending(session, new Error(`Kernel "${session.name}" (${sessionId}) closed.`));
    if (session.alive) {
      session.process.kill("SIGTERM");
      setTimeout(() => {
        if (session.process.killed === false) {
          try {
            session.process.kill("SIGKILL");
          } catch {
            // Best-effort
          }
        }
      }, 2000);
    }
    session.alive = false;
    this.sessions.delete(sessionId);
  }

  /** List all kernels (active and dead). */
  listSessions(): Array<{ id: string; name: string; alive: boolean; createdAt: number }> {
    return Array.from(this.sessions.values()).map((s) => ({
      id: s.id,
      name: s.name,
      alive: s.alive,
      createdAt: s.createdAt,
    }));
  }

  /** Clean up all kernels. Call when the agent loop ends. */
  cleanup(): void {
    for (const [id] of this.sessions) {
      try {
        this.close(id);
      } catch {
        // Best-effort
      }
    }
    this.sessions.clear();
  }

  /** Find a kernel by name (first alive match, then any match). */
  findByName(name: string): PythonKernelSession | undefined {
    for (const s of this.sessions.values()) {
      if (s.name === name && s.alive) return s;
    }
    for (const s of this.sessions.values()) {
      if (s.name === name) return s;
    }
    return undefined;
  }

  /** Close kernels idle (no `send`) longer than IDLE_TIMEOUT_MS. */
  reapIdleSessions(): number {
    const now = Date.now();
    let reaped = 0;
    for (const [id, session] of this.sessions) {
      if (session.alive && now - session.lastUsedAt >= IDLE_TIMEOUT_MS) {
        try {
          this.close(id);
          reaped++;
        } catch {
          // Best-effort
        }
      }
    }
    return reaped;
  }

  // ── internals ──

  private spawnKernel(): ChildProcess {
    return spawn("python3", ["-u", "-c", REPL_SERVER], {
      env: {
        ...process.env,
        "0SEC_KERNEL_BLOCK_NET": this.blockNetworking ? "1" : "0",
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
  }

  /**
   * Attach stdout frame-decoder + stderr accumulator + exit handlers. Each
   * listener is bound to the SPECIFIC child it was wired for and no-ops if the
   * session has since been respawned onto a new child — otherwise a killed
   * old process's late `exit` event would reject the NEW child's in-flight call.
   */
  private wire(session: InternalSession): void {
    const proc = session.process;
    proc.stdout?.on("data", (chunk: Buffer) => {
      if (session.process !== proc) return;
      session.buffer = Buffer.concat([session.buffer, chunk]);
      this.drainFrames(session);
    });
    proc.stderr?.on("data", (chunk: Buffer) => {
      if (session.process !== proc) return;
      session.stderrBuf += chunk.toString("utf-8");
      if (session.stderrBuf.length > 100_000) {
        session.stderrBuf = session.stderrBuf.slice(-50_000);
      }
    });
    proc.on("exit", () => {
      if (session.process !== proc) return;
      session.alive = false;
      this.rejectPending(session, new Error(`Kernel "${session.name}" exited unexpectedly.`));
    });
    proc.on("error", () => {
      if (session.process !== proc) return;
      session.alive = false;
      this.rejectPending(session, new Error(`Kernel "${session.name}" process error.`));
    });
  }

  /** Kill + respawn the child, resetting decoder state and rejecting pending. */
  private respawn(session: InternalSession): void {
    this.rejectPending(session, new Error(`Kernel "${session.name}" was reset.`));
    try {
      session.process.kill("SIGKILL");
    } catch {
      // Best-effort
    }
    session.process = this.spawnKernel();
    session.buffer = Buffer.alloc(0);
    session.stderrBuf = "";
    session.alive = true;
    session.lastUsedAt = Date.now();
    this.wire(session);
  }

  /** Pull every complete length-prefixed frame out of the session buffer. */
  private drainFrames(session: InternalSession): void {
    for (;;) {
      if (session.buffer.length < 4) return;
      const n = session.buffer.readUInt32BE(0);
      if (session.buffer.length < 4 + n) return;
      const frameBytes = session.buffer.subarray(4, 4 + n);
      session.buffer = session.buffer.subarray(4 + n);
      this.deliverFrame(session, frameBytes);
    }
  }

  private deliverFrame(session: InternalSession, bytes: Buffer): void {
    const pending = session.pending.shift();
    if (!pending) return; // Unsolicited frame — ignore rather than wedge.
    clearTimeout(pending.timer);
    let frame: KernelFrame;
    try {
      const obj = JSON.parse(bytes.toString("utf-8")) as Partial<KernelFrame>;
      frame = {
        stdout: typeof obj.stdout === "string" ? obj.stdout : "",
        stderr: typeof obj.stderr === "string" ? obj.stderr : "",
        value: typeof obj.value === "string" ? obj.value : null,
        error: typeof obj.error === "string" ? obj.error : null,
        traceback: typeof obj.traceback === "string" ? obj.traceback : null,
      };
    } catch {
      // A malformed JSON body (correct length, bad content) must not wedge the
      // kernel: the frame was consumed cleanly, so resync is intact — surface
      // an error frame and keep going.
      frame = {
        stdout: "",
        stderr: "",
        value: null,
        error: "malformed kernel frame",
        traceback: bytes.toString("utf-8").slice(0, 200),
      };
    }
    pending.resolve(frame);
  }

  private rejectPending(session: InternalSession, err: Error): void {
    const pending = session.pending;
    session.pending = [];
    for (const p of pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
  }

  private getSession(sessionId: string): InternalSession {
    const session = this.sessions.get(sessionId);
    if (!session) {
      throw new Error(`Kernel "${sessionId}" not found.`);
    }
    return session;
  }
}
