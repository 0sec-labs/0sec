/**
 * Park-and-revive loop for a long-lived agent.
 *
 * Oh My Pi's model: an agent that finishes its task does not DIE — it PARKS,
 * staying addressable, and an incoming message REVIVES it to keep working. This
 * module is the pure core of that behaviour, deliberately isolated from the
 * agent runtime so it can be unit-tested without a real model, mailbox, or
 * clock: everything it touches (time, sleep, message drain, the resume itself,
 * an abort check) is injected. The existing synchronous `spawn_agents` fan-out
 * does not use this — it is opt-in, so the tested fan-out core is untouched.
 *
 * The loop is HARD-BOUNDED in three independent ways so a parked agent can never
 * run away: it ends after `idleTtlMs` with no message, after `maxRevives`
 * resumes, or the moment `aborted()` goes true (session shutdown). Every exit is
 * reported, never thrown.
 */

import type { HubMessage } from "./mailbox.js";

export interface ParkOptions {
  /** How often to check the mailbox while parked, in ms. */
  readonly pollMs: number;
  /**
   * End the agent after this long with no delivered message, in ms. This is what
   * lets a parked fleet wind down instead of lingering forever.
   */
  readonly idleTtlMs: number;
  /**
   * Maximum number of times the agent may be revived before it must end — a
   * runaway guard independent of the idle TTL (a peer that messages on every
   * poll can't keep an agent alive indefinitely).
   */
  readonly maxRevives: number;
}

export interface ParkDeps {
  /** Monotonic-ish clock in ms (injected; the loop never reads ambient time). */
  now: () => number;
  /** Await `ms`. Injected so tests advance time deterministically. */
  sleep: (ms: number) => Promise<void>;
  /**
   * Drain the messages addressed to this agent since the last call (consuming).
   * Empty array means nothing waiting.
   */
  drain: () => HubMessage[] | Promise<HubMessage[]>;
  /**
   * Resume the agent's loop with the delivered messages; resolves once the agent
   * has finished handling them and is ready to park again. A throw here ends the
   * park loop with reason `error` rather than propagating.
   */
  resume: (messages: readonly HubMessage[]) => Promise<void>;
  /** True once the session is shutting down — the loop exits promptly. */
  aborted?: () => boolean;
}

export type ParkEndReason = "idle" | "max-revives" | "aborted" | "error";

export interface ParkOutcome {
  readonly reason: ParkEndReason;
  /** How many times the agent was revived before ending. */
  readonly revives: number;
  /** The error, when `reason === "error"`. */
  readonly error?: unknown;
}

/**
 * Validate + clamp options into a safe range. A non-finite or non-positive value
 * would turn the loop into a busy-spin or an immortal agent, so each is coerced
 * to a sane floor/default.
 */
function normalizeOptions(opts: ParkOptions): ParkOptions {
  const posInt = (v: number, fallback: number): number =>
    Number.isFinite(v) && v > 0 ? Math.floor(v) : fallback;
  return {
    pollMs: posInt(opts.pollMs, 500),
    idleTtlMs: posInt(opts.idleTtlMs, 60_000),
    maxRevives: Number.isFinite(opts.maxRevives) && opts.maxRevives >= 0 ? Math.floor(opts.maxRevives) : 8,
  };
}

/**
 * Park an agent until it should end. Returns the reason and revive count.
 *
 * Contract: drain first (a message that arrived during the task is handled
 * before any idle accounting), resume on any delivery, and only start the idle
 * clock once there is nothing to do. `maxRevives` is checked BEFORE a resume, so
 * the cap is a hard ceiling on how many times `resume` runs.
 */
export async function parkAgent(options: ParkOptions, deps: ParkDeps): Promise<ParkOutcome> {
  const opts = normalizeOptions(options);
  let revives = 0;
  let lastActive = deps.now();

  for (;;) {
    if (deps.aborted?.()) return { reason: "aborted", revives };

    let messages: HubMessage[];
    try {
      messages = [...(await deps.drain())];
    } catch (err) {
      return { reason: "error", revives, error: err };
    }

    if (messages.length > 0) {
      if (revives >= opts.maxRevives) return { reason: "max-revives", revives };
      revives += 1;
      try {
        await deps.resume(messages);
      } catch (err) {
        return { reason: "error", revives, error: err };
      }
      lastActive = deps.now();
      continue;
    }

    if (deps.now() - lastActive >= opts.idleTtlMs) return { reason: "idle", revives };

    await deps.sleep(opts.pollMs);
  }
}
