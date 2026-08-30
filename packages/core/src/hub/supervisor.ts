/**
 * Detached long-lived ("persistent") agents.
 *
 * The synchronous `spawn_agents` fan-out runs children to completion and merges
 * their findings — perfect for a scan, wrong for a teammate you want to keep
 * around. This module adds the OTHER model, entirely alongside it: an agent that
 * runs its task, then PARKS (stays alive and addressable) and is REVIVED by an
 * incoming message, exactly like Oh My Pi. Nothing here touches the fan-out; a
 * persistent agent is a separate, opt-in path.
 *
 * Two pieces:
 *   - `runPersistentAgent` composes the lifecycle: emit `running`, run the task,
 *     emit `parked`, then loop on the mailbox (via `hub/park.ts`) reviving on
 *     each message until an idle TTL / revive cap / abort ends it — emitting a
 *     terminal `completed`/`failed`. It is pure of I/O: the loop runner, mailbox
 *     drain, clock and lifecycle sink are all injected, so it is unit-testable
 *     without a model.
 *   - `DetachedAgentSupervisor` owns the detached run Promises for a session so
 *     they are tracked (not fire-and-forget-and-lost), can be listed, and are
 *     aborted together on shutdown. A rejected detached run can never surface as
 *     an unhandled rejection — the supervisor attaches a catch.
 */

import { parkAgent, type ParkOptions, type ParkOutcome } from "./park.js";
import type { HubMessage } from "./mailbox.js";

/** Lifecycle status a persistent agent reports as it runs, parks and revives. */
export type PersistentStatus = "running" | "parked" | "completed" | "failed";

export interface PersistentRunDeps {
  /** Monotonic-ish clock (ms), injected — never reads ambient time. */
  now: () => number;
  /** Await `ms`; injected so tests advance time deterministically. */
  sleep: (ms: number) => Promise<void>;
  /** Drain (consume) this agent's pending mailbox messages. */
  drain: () => HubMessage[] | Promise<HubMessage[]>;
  /**
   * Run the agent's loop once — for the initial `task`, or to handle a revive's
   * `messages`. Resolves when the loop settles; a `false`/throw ends the agent
   * `failed`. Injected: the real impl calls `runNativeAgentLoop`.
   */
  runLoop: (input: { task?: string; messages?: readonly HubMessage[] }) => Promise<void>;
  /** Report a status transition (drives `subagent_lifecycle` in the real impl). */
  emit: (status: PersistentStatus) => void;
  /** True once the session is shutting down — the park loop exits promptly. */
  aborted?: () => boolean;
  /** Park bounds (poll cadence, idle TTL, revive cap). */
  park: ParkOptions;
}

export interface PersistentRunResult extends ParkOutcome {
  /** The terminal status emitted (`completed` unless a run threw → `failed`). */
  status: "completed" | "failed";
}

/**
 * Run one persistent agent through its whole life: task → park → (revive → park)*
 * → terminal. Never throws; a loop failure is reported as a `failed` terminal
 * status and returned, so a supervisor tracking many of these is never taken
 * down by one agent.
 */
export async function runPersistentAgent(
  task: string,
  deps: PersistentRunDeps,
): Promise<PersistentRunResult> {
  // Initial task.
  deps.emit("running");
  try {
    await deps.runLoop({ task });
  } catch (err) {
    deps.emit("failed");
    return { reason: "error", revives: 0, error: err, status: "failed" };
  }

  // Park, reviving on each delivered batch. The resume wraps the loop run in a
  // running→parked transition so the roster reflects an agent waking and settling.
  deps.emit("parked");
  const outcome = await parkAgent(deps.park, {
    now: deps.now,
    sleep: deps.sleep,
    drain: deps.drain,
    aborted: deps.aborted,
    resume: async (messages) => {
      deps.emit("running");
      try {
        await deps.runLoop({ messages });
      } finally {
        deps.emit("parked");
      }
    },
  });

  const status: "completed" | "failed" = outcome.reason === "error" ? "failed" : "completed";
  deps.emit(status);
  return { ...outcome, status };
}

/** A tracked detached agent run. */
interface TrackedRun {
  readonly id: string;
  readonly name: string;
  readonly promise: Promise<PersistentRunResult>;
  readonly abort: () => void;
}

/**
 * Owns the detached persistent-agent runs for one session. A detached run would
 * otherwise be an untracked Promise (lost, and a rejection would be unhandled);
 * registering it here keeps it live, listable, and abortable, and swallows a
 * late rejection so the session is never crashed by a parked agent.
 */
export class DetachedAgentSupervisor {
  private readonly runs = new Map<string, TrackedRun>();

  /**
   * Track a detached run. `abort` is the caller's cancel hook (typically flips
   * the `aborted` flag the run's park loop polls). The run is removed from the
   * live set when it settles; a rejection is caught so it never goes unhandled.
   */
  register(id: string, name: string, promise: Promise<PersistentRunResult>, abort: () => void): void {
    this.runs.set(id, { id, name, promise, abort });
    promise
      .catch(() => undefined)
      .finally(() => {
        this.runs.delete(id);
      });
  }

  /** Ids of the currently live detached runs. */
  liveIds(): string[] {
    return [...this.runs.keys()];
  }

  /** Number of live detached runs. */
  get size(): number {
    return this.runs.size;
  }

  /** Abort ONE run by id; returns whether it was live. */
  abort(id: string): boolean {
    const run = this.runs.get(id);
    if (!run) return false;
    run.abort();
    return true;
  }

  /**
   * Abort every live run and await them all settling. Safe to call on shutdown;
   * resolves once no run is still parked. Never rejects.
   */
  async abortAll(): Promise<void> {
    const pending = [...this.runs.values()];
    for (const run of pending) run.abort();
    await Promise.allSettled(pending.map((r) => r.promise));
  }
}
