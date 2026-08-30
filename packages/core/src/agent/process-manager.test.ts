import { describe, expect, it } from "vitest";

import { RingLog, matchReady, ProcessManager } from "./process-manager.js";

describe("RingLog", () => {
  it("appends, splits on newlines, and reads from a cursor", () => {
    const log = new RingLog();
    log.append("line one\nline two\n");
    log.append("line three");
    const all = log.read(0);
    expect(all.lines.map((l) => l.text)).toEqual(["line one", "line two", "line three"]);
    // Resume after the returned cursor → nothing new.
    expect(log.read(all.cursor).lines).toHaveLength(0);
  });

  it("returns only lines after the cursor (incremental follow)", () => {
    const log = new RingLog();
    log.append("a\nb\n");
    const first = log.read(0);
    log.append("c\n");
    const next = log.read(first.cursor);
    expect(next.lines.map((l) => l.text)).toEqual(["c"]);
  });

  it("filters by grep and caps at limit", () => {
    const log = new RingLog();
    log.append("error: boom\ninfo: ok\nerror: again\n");
    const errs = log.read(0, { grep: /^error:/ });
    expect(errs.lines.map((l) => l.text)).toEqual(["error: boom", "error: again"]);
    expect(log.read(0, { limit: 1 }).lines).toHaveLength(1);
  });

  it("evicts oldest lines past maxLines but keeps cursors monotonic", () => {
    const log = new RingLog(3);
    for (const c of ["1", "2", "3", "4", "5"]) log.append(c);
    const out = log.read(0);
    // Only the last 3 retained.
    expect(out.lines.map((l) => l.text)).toEqual(["3", "4", "5"]);
    // Cursor space still reflects all 5 appended.
    expect(log.head).toBe(5);
  });
});

describe("matchReady", () => {
  it("is ready immediately when no gate is set", () => {
    expect(matchReady({}, [], undefined).ready).toBe(true);
  });

  it("matches a log regex and returns the matched line", () => {
    const r = matchReady({ log: /Listening on/ }, ["boot...", "Listening on :8080"], undefined);
    expect(r.ready).toBe(true);
    expect(r.reason).toBe("log");
    expect(r.matchedLine).toBe("Listening on :8080");
  });

  it("waits for a port when only a port gate is set", () => {
    expect(matchReady({ port: 8080 }, [], false).ready).toBe(false);
    expect(matchReady({ port: 8080 }, [], true).ready).toBe(true);
  });

  it("requires BOTH when log and port are given (AND semantics)", () => {
    expect(matchReady({ log: /ready/, port: 80 }, ["ready"], false).ready).toBe(false);
    expect(matchReady({ log: /ready/, port: 80 }, ["nope"], true).ready).toBe(false);
    const both = matchReady({ log: /ready/, port: 80 }, ["ready"], true);
    expect(both.ready).toBe(true);
    expect(both.reason).toBe("both");
  });
});

describe("ProcessManager", () => {
  it("starts, captures output, lists with pid+status, and stops", async () => {
    const pm = new ProcessManager();
    const proc = pm.start({
      name: "echoer",
      command: process.execPath, // node
      args: ["-e", "console.log('hello from child'); setInterval(()=>{}, 1000)"],
    });
    expect(proc.status).toBe("running");
    expect(typeof proc.pid).toBe("number");
    expect(pm.isRunning("echoer")).toBe(true);
    expect(pm.list().map((p) => p.name)).toContain("echoer");

    // Give the child a moment to emit stdout.
    await new Promise((r) => setTimeout(r, 300));
    const out = proc.log.read(0);
    expect(out.lines.some((l) => l.text.includes("hello from child"))).toBe(true);

    expect(pm.stop("echoer", "KILL")).toBe(true);
    await new Promise((r) => setTimeout(r, 200));
    expect(pm.isRunning("echoer")).toBe(false);
  });

  it("refuses a duplicate running name and keeps a dead process listed", async () => {
    const pm = new ProcessManager();
    pm.start({ name: "quick", command: process.execPath, args: ["-e", "process.exit(0)"] });
    await new Promise((r) => setTimeout(r, 200));
    // Exited process stays listed for post-mortem.
    expect(pm.get("quick")?.status).toBe("exited");
    // Reusing the name is allowed once it's not running.
    expect(() => pm.start({ name: "quick", command: process.execPath, args: ["-e", "setInterval(()=>{},1000)"] })).not.toThrow();
    expect(pm.isRunning("quick")).toBe(true);
    pm.killAll();
  });
});
