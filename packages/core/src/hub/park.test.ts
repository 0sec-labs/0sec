import { describe, expect, it, vi } from "vitest";

import { parkAgent, type ParkDeps, type ParkOptions } from "./park.js";
import type { HubMessage } from "./mailbox.js";

const OPTS: ParkOptions = { pollMs: 100, idleTtlMs: 500, maxRevives: 3 };

function msg(from: string, body: string): HubMessage {
  return { id: `${from}-${body}`, from, to: "self", body, ts: 0 };
}

/**
 * A deterministic test harness: a virtual clock advanced by `sleep`, a scripted
 * sequence of drains, and a resume that records what it was handed.
 */
function harness(drains: HubMessage[][], over: Partial<ParkDeps> = {}) {
  let clock = 0;
  let i = 0;
  const resumed: HubMessage[][] = [];
  const deps: ParkDeps = {
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    drain: () => {
      const batch = drains[i] ?? [];
      i += 1;
      return batch;
    },
    resume: async (messages) => {
      resumed.push([...messages]);
    },
    ...over,
  };
  return { deps, resumed, clockRef: () => clock };
}

describe("parkAgent", () => {
  it("ends idle when no message ever arrives", async () => {
    // Every drain empty → after idleTtlMs of sleeping it gives up.
    const { deps, resumed } = harness([]);
    const out = await parkAgent(OPTS, deps);
    expect(out.reason).toBe("idle");
    expect(out.revives).toBe(0);
    expect(resumed).toHaveLength(0);
  });

  it("revives on a delivered message then parks again", async () => {
    const { deps, resumed } = harness([[msg("Explorer", "hi")], []]);
    const out = await parkAgent(OPTS, deps);
    expect(resumed).toEqual([[msg("Explorer", "hi")]]);
    // After the one revive, subsequent drains are empty → idle exit.
    expect(out.reason).toBe("idle");
    expect(out.revives).toBe(1);
  });

  it("stops at maxRevives even if messages keep coming", async () => {
    // A peer that messages on every poll must not keep the agent alive forever.
    const { deps, resumed } = harness([], {
      drain: () => [msg("Chatty", "again")],
    });
    const out = await parkAgent({ ...OPTS, maxRevives: 2 }, deps);
    expect(out.reason).toBe("max-revives");
    expect(out.revives).toBe(2);
    expect(resumed).toHaveLength(2);
  });

  it("exits promptly when aborted", async () => {
    const { deps } = harness([], { aborted: () => true });
    const out = await parkAgent(OPTS, deps);
    expect(out.reason).toBe("aborted");
    expect(out.revives).toBe(0);
  });

  it("reports an error from resume without throwing", async () => {
    const boom = new Error("resume failed");
    const { deps } = harness([[msg("X", "y")]], {
      resume: async () => {
        throw boom;
      },
    });
    const out = await parkAgent(OPTS, deps);
    expect(out.reason).toBe("error");
    expect(out.error).toBe(boom);
    expect(out.revives).toBe(1);
  });

  it("reports an error from drain without throwing", async () => {
    const boom = new Error("drain failed");
    const { deps } = harness([], {
      drain: () => {
        throw boom;
      },
    });
    const out = await parkAgent(OPTS, deps);
    expect(out.reason).toBe("error");
    expect(out.error).toBe(boom);
  });

  it("handles a message that arrived during the task (drains before idle)", async () => {
    // First drain has a message (no sleep yet) → resume immediately.
    const drainSpy = vi.fn().mockReturnValueOnce([msg("A", "1")]).mockReturnValue([]);
    const { deps, resumed } = harness([], { drain: drainSpy });
    const out = await parkAgent(OPTS, deps);
    expect(resumed[0]).toEqual([msg("A", "1")]);
    expect(out.revives).toBe(1);
  });

  it("clamps degenerate options instead of busy-spinning or living forever", async () => {
    const { deps } = harness([]);
    const out = await parkAgent({ pollMs: 0, idleTtlMs: -1, maxRevives: Number.NaN }, deps);
    // idleTtlMs clamps to a positive default, so it still terminates idle.
    expect(out.reason).toBe("idle");
  });
});
