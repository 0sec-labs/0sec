import { describe, expect, it, vi } from "vitest";

import {
  DetachedAgentSupervisor,
  runPersistentAgent,
  type PersistentRunDeps,
  type PersistentRunResult,
} from "./supervisor.js";
import type { HubMessage } from "./mailbox.js";

const PARK = { pollMs: 100, idleTtlMs: 500, maxRevives: 3 } as const;

function msg(from: string, body: string): HubMessage {
  return { id: `${from}-${body}`, from, to: "self", body, ts: 0 };
}

function baseDeps(over: Partial<PersistentRunDeps> = {}): {
  deps: PersistentRunDeps;
  emitted: string[];
  ran: Array<{ task?: string; messages?: readonly HubMessage[] }>;
} {
  let clock = 0;
  const emitted: string[] = [];
  const ran: Array<{ task?: string; messages?: readonly HubMessage[] }> = [];
  const deps: PersistentRunDeps = {
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    drain: () => [],
    runLoop: async (input) => {
      ran.push(input);
    },
    emit: (s) => emitted.push(s),
    park: PARK,
    ...over,
  };
  return { deps, emitted, ran };
}

describe("runPersistentAgent", () => {
  it("runs the task, parks, then completes when idle", async () => {
    const { deps, emitted, ran } = baseDeps();
    const out = await runPersistentAgent("audit the login flow", deps);
    expect(ran[0]).toEqual({ task: "audit the login flow" });
    expect(emitted).toEqual(["running", "parked", "completed"]);
    expect(out.status).toBe("completed");
    expect(out.revives).toBe(0);
  });

  it("revives on a message and re-parks", async () => {
    let i = 0;
    const drains = [[msg("Explorer", "take a look")], []];
    const { deps, emitted, ran } = baseDeps({
      drain: () => drains[i++] ?? [],
    });
    const out = await runPersistentAgent("watch", deps);
    // task, then one revive handling the message.
    expect(ran).toHaveLength(2);
    expect(ran[1]).toEqual({ messages: [msg("Explorer", "take a look")] });
    expect(emitted).toEqual(["running", "parked", "running", "parked", "completed"]);
    expect(out.revives).toBe(1);
  });

  it("ends failed if the initial task loop throws", async () => {
    const boom = new Error("loop crashed");
    const { deps, emitted } = baseDeps({
      runLoop: async () => {
        throw boom;
      },
    });
    const out = await runPersistentAgent("x", deps);
    expect(emitted).toEqual(["running", "failed"]);
    expect(out.status).toBe("failed");
    expect(out.error).toBe(boom);
  });

  it("ends failed if a revive loop throws", async () => {
    let drained = false;
    const { deps, emitted } = baseDeps({
      drain: () => {
        if (!drained) {
          drained = true;
          return [msg("A", "1")];
        }
        return [];
      },
      runLoop: async (input) => {
        if (input.messages) throw new Error("revive crashed");
      },
    });
    const out = await runPersistentAgent("x", deps);
    expect(out.status).toBe("failed");
    // running(task) → parked → running(revive) → parked(finally) → failed
    expect(emitted).toContain("failed");
  });
});

describe("DetachedAgentSupervisor", () => {
  const settled = (v: PersistentRunResult): Promise<PersistentRunResult> => Promise.resolve(v);

  it("tracks a live run and drops it when it settles", async () => {
    const sup = new DetachedAgentSupervisor();
    let resolve!: (v: PersistentRunResult) => void;
    const p = new Promise<PersistentRunResult>((r) => (resolve = r));
    sup.register("a1", "Explorer", p, () => undefined);
    expect(sup.size).toBe(1);
    expect(sup.liveIds()).toEqual(["a1"]);
    resolve({ reason: "idle", revives: 0, status: "completed" });
    await p;
    await Promise.resolve(); // let the .finally run
    expect(sup.size).toBe(0);
  });

  it("aborts one run by id", () => {
    const sup = new DetachedAgentSupervisor();
    const abort = vi.fn();
    sup.register("a1", "Explorer", settled({ reason: "idle", revives: 0, status: "completed" }), abort);
    expect(sup.abort("a1")).toBe(true);
    expect(abort).toHaveBeenCalledOnce();
    expect(sup.abort("nope")).toBe(false);
  });

  it("aborts all runs and awaits them", async () => {
    const sup = new DetachedAgentSupervisor();
    const aborts = [vi.fn(), vi.fn()];
    sup.register("a1", "A", settled({ reason: "idle", revives: 0, status: "completed" }), aborts[0]!);
    sup.register("a2", "B", settled({ reason: "idle", revives: 0, status: "completed" }), aborts[1]!);
    await sup.abortAll();
    expect(aborts[0]).toHaveBeenCalledOnce();
    expect(aborts[1]).toHaveBeenCalledOnce();
    expect(sup.size).toBe(0);
  });

  it("swallows a rejected detached run (no unhandled rejection)", async () => {
    const sup = new DetachedAgentSupervisor();
    const p = Promise.reject(new Error("boom")) as Promise<PersistentRunResult>;
    sup.register("a1", "A", p, () => undefined);
    await sup.abortAll(); // must not throw
    expect(sup.size).toBe(0);
  });
});
