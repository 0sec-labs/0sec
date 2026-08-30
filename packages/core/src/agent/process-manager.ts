/**
 * Background process supervision for the agent — the `monitor` tool's engine.
 *
 * The agent constantly needs to launch something and KEEP it running while it
 * does other work: a target dev server to test against, a reverse-shell / OAST
 * listener, a payload-hosting HTTP server, a long scanner (nuclei/ffuf/nmap) or
 * fuzzer, a build. `bash` can't do this — it is one-shot with a 120s cap and no
 * backgrounding. This module supervises detached processes across turns: start
 * (with a ready-gate), tail logs by cursor, wait on a condition, signal/stop.
 *
 * Design mirrors Oh My Pi's `hub` process family (start/logs/wait/stop with a
 * log+port ready-gate and cursor-based reads) — see the `monitor-tool-design`
 * research note. Two testable pure-ish pieces (`RingLog`, `matchReady`) are kept
 * free of real I/O so they can be unit-tested without spawning processes; the
 * `ProcessManager` is the thin child_process glue over them.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createConnection } from "node:net";

/** A captured output line with the byte offset AFTER it (its read cursor). */
export interface LogLine {
  readonly text: string;
  /** Monotonic cursor: pass back to `read` to resume after this line. */
  readonly cursor: number;
}

/**
 * A bounded, cursor-addressable log buffer. Appends never grow without limit
 * (oldest lines drop past `maxLines`), and a reader resumes from a cursor so a
 * long-running process's megabytes of output are never re-sent. Pure and
 * synchronous — the unit-tested core of `logs`.
 */
export class RingLog {
  private lines: LogLine[] = [];
  /** Total lines ever appended — the cursor space (monotonic, survives eviction). */
  private appended = 0;
  constructor(private readonly maxLines = 5_000) {}

  /** Append one line; splits on newlines, drops blanks-at-end. */
  append(chunk: string): void {
    for (const raw of String(chunk).split(/\r?\n/)) {
      // Keep a trailing empty line out (a chunk ending in \n yields one).
      if (raw === "" ) continue;
      this.appended += 1;
      this.lines.push({ text: raw, cursor: this.appended });
      if (this.lines.length > this.maxLines) this.lines.shift();
    }
  }

  /** The cursor at the tail (what a fresh reader should start "following" from). */
  get head(): number {
    return this.appended;
  }

  /**
   * Read lines after `cursor` (0 = from the oldest retained), optionally filtered
   * by a regex, capped at `limit`. Returns the lines and the new cursor to resume
   * from. If lines were evicted past `cursor`, reading resumes at the oldest
   * retained line (never silently skips backward).
   */
  read(cursor: number, opts: { grep?: RegExp; limit?: number } = {}): { lines: LogLine[]; cursor: number } {
    const limit = opts.limit && opts.limit > 0 ? Math.floor(opts.limit) : 1_000;
    let out = this.lines.filter((l) => l.cursor > cursor);
    if (opts.grep) out = out.filter((l) => opts.grep!.test(l.text));
    const clipped = out.slice(0, limit);
    const next = clipped.length > 0 ? clipped[clipped.length - 1]!.cursor : Math.max(cursor, this.oldestCursor());
    return { lines: clipped, cursor: next };
  }

  private oldestCursor(): number {
    return this.lines.length > 0 ? this.lines[0]!.cursor - 1 : this.appended;
  }
}

/** A ready condition: a log-line regex and/or a TCP port that must open. */
export interface ReadyGate {
  readonly log?: RegExp;
  readonly port?: number;
  readonly host?: string;
}

export type ReadyReason = "log" | "port" | "both" | "timeout" | "exited";

/**
 * Decide whether a ready-gate is satisfied by the current log + a port-open
 * result. AND semantics: if both `log` and `port` are given, BOTH must hold.
 * Pure — the port probe result is injected so this is unit-testable. Returns the
 * matched line (verbatim) when the log condition fires, since for a security tool
 * that line is often the signal itself.
 */
export function matchReady(
  gate: ReadyGate,
  recentLines: readonly string[],
  portOpen: boolean | undefined,
): { ready: boolean; reason: ReadyReason; matchedLine?: string } {
  const wantLog = gate.log !== undefined;
  const wantPort = gate.port !== undefined;
  if (!wantLog && !wantPort) return { ready: true, reason: "both" };

  const matchedLine = wantLog ? recentLines.find((l) => gate.log!.test(l)) : undefined;
  const logOk = wantLog ? matchedLine !== undefined : true;
  const portOk = wantPort ? portOpen === true : true;

  if (logOk && portOk) {
    const reason: ReadyReason = wantLog && wantPort ? "both" : wantLog ? "log" : "port";
    return { ready: true, reason, ...(matchedLine ? { matchedLine } : {}) };
  }
  return { ready: false, reason: "timeout" };
}

/** Probe a TCP port once; resolves true if a connection opens within `timeoutMs`. */
export function probePort(port: number, host = "127.0.0.1", timeoutMs = 1_000): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = createConnection({ port, host });
    let done = false;
    const finish = (ok: boolean): void => {
      if (done) return;
      done = true;
      sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => finish(true));
    sock.once("timeout", () => finish(false));
    sock.once("error", () => finish(false));
  });
}

export type ProcStatus = "running" | "exited" | "killed";

/** One supervised process. */
export interface ManagedProc {
  readonly name: string;
  readonly pid: number | undefined;
  status: ProcStatus;
  exitCode: number | null;
  readonly startedAt: number;
  readonly log: RingLog;
  readonly child: ChildProcess;
}

export interface StartSpec {
  readonly name: string;
  readonly command: string;
  readonly args?: readonly string[];
  readonly cwd?: string;
  readonly env?: Record<string, string>;
}

const SIGNALS: Record<string, NodeJS.Signals> = {
  TERM: "SIGTERM",
  KILL: "SIGKILL",
  INT: "SIGINT",
  HUP: "SIGHUP",
};

/**
 * Supervises detached background processes for one session. Names are unique
 * handles; a finished process stays listed (with its exit status + logs) until
 * the session ends, so the agent can read a dead process's output post-mortem.
 * `killAll` (called from the executor's cleanup) terminates everything so no
 * child outlives the session.
 */
export class ProcessManager {
  private readonly procs = new Map<string, ManagedProc>();
  constructor(private readonly now: () => number = () => Date.now()) {}

  /** True if `name` is a live (running) process. */
  isRunning(name: string): boolean {
    return this.procs.get(name)?.status === "running";
  }

  list(): ManagedProc[] {
    return [...this.procs.values()];
  }

  get(name: string): ManagedProc | undefined {
    return this.procs.get(name);
  }

  /**
   * Start a detached process. Args are passed as an ARRAY (no shell), so an
   * attacker-influenced value can't inject a second command. Throws if the name
   * is already a running process.
   */
  start(spec: StartSpec): ManagedProc {
    const existing = this.procs.get(spec.name);
    if (existing?.status === "running") {
      throw new Error(`a process named "${spec.name}" is already running`);
    }
    const log = new RingLog();
    const child = spawn(spec.command, [...(spec.args ?? [])], {
      cwd: spec.cwd,
      env: spec.env ? { ...process.env, ...spec.env } : process.env,
      stdio: ["ignore", "pipe", "pipe"],
      detached: false,
    });
    const proc: ManagedProc = {
      name: spec.name,
      pid: child.pid,
      status: "running",
      exitCode: null,
      startedAt: this.now(),
      log,
      child,
    };
    child.stdout?.on("data", (d) => log.append(d.toString()));
    child.stderr?.on("data", (d) => log.append(d.toString()));
    child.on("exit", (code, signal) => {
      proc.status = signal ? "killed" : "exited";
      proc.exitCode = code;
    });
    child.on("error", (err) => {
      log.append(`[process error] ${err instanceof Error ? err.message : String(err)}`);
      proc.status = "exited";
      proc.exitCode = proc.exitCode ?? -1;
    });
    this.procs.set(spec.name, proc);
    return proc;
  }

  /** Send a signal to a process. Returns false if unknown/not running. */
  stop(name: string, signal: keyof typeof SIGNALS = "TERM"): boolean {
    const proc = this.procs.get(name);
    if (!proc || proc.status !== "running") return false;
    try {
      proc.child.kill(SIGNALS[signal] ?? "SIGTERM");
      return true;
    } catch {
      return false;
    }
  }

  /** Write text to a process's stdin (if still open). */
  send(name: string, text: string): boolean {
    const proc = this.procs.get(name);
    if (!proc || proc.status !== "running" || !proc.child.stdin?.writable) return false;
    try {
      proc.child.stdin.write(text);
      return true;
    } catch {
      return false;
    }
  }

  /** Terminate every live process (session teardown). */
  killAll(): void {
    for (const proc of this.procs.values()) {
      if (proc.status === "running") {
        try {
          proc.child.kill("SIGKILL");
        } catch {
          /* best effort */
        }
      }
    }
  }
}
