/**
 * The mid-turn composer queue.
 *
 * The console accepts typed input at any moment, but a turn is single-flight:
 * `send()` refuses to start one while another is running. Before this module
 * that refusal was a bare `return` in the Enter handler, which dropped the
 * message AND left it sitting in the composer — from the operator's side
 * indistinguishable from a dead keyboard. On a tool whose turns routinely run
 * for minutes (a scan, a long tool chain), that is the single most common
 * moment someone wants to type.
 *
 * So input typed mid-turn is PARKED rather than refused, and delivered FIFO as
 * the console returns to idle. The rules live here, as pure functions, because
 * the console component itself is not under test (this package tests `.ts`
 * modules, not `.tsx`); keeping the decision out of the component is what makes
 * it verifiable.
 */

/** What the console should do with one submitted composer line. */
export type ComposerDisposition =
  /** Deliver it now. */
  | "send"
  /** Park it; a later idle transition delivers it. */
  | "queue"
  /** Nothing to do (blank input). */
  | "discard";

/**
 * Upper bound on parked messages.
 *
 * Unbounded growth is a real hazard here: a long scan plus an impatient
 * operator is exactly the shape that fills a queue. The cap is generous enough
 * that no realistic session reaches it, and reaching it REFUSES the newest
 * message rather than evicting an older one — silently discarding an operator
 * instruction is the bug this module exists to remove, so the failure is
 * surfaced instead of hidden.
 */
export const COMPOSER_QUEUE_LIMIT = 50;

/**
 * Decide what to do with one submitted line.
 *
 * Slash commands are deliberately exempt from queueing: they are console-local
 * control verbs (`/stop`, `/model`, `/help`) whose entire purpose is to act
 * WHILE a turn runs. Parking `/stop` until the turn ends would invert its
 * meaning.
 *
 * @param params.input - the raw composer text.
 * @param params.isSlash - whether it parses as a slash command.
 * @param params.busy - whether a turn is currently in flight.
 * @param params.hasSession - whether a session exists to send against.
 * @returns the disposition the caller should apply.
 */
export function classifyComposerInput(params: {
  input: string;
  isSlash: boolean;
  busy: boolean;
  hasSession: boolean;
}): ComposerDisposition {
  const { input, isSlash, busy, hasSession } = params;
  if (!input.trim()) return "discard";
  // Control verbs run against the console, not the model, so neither a running
  // turn nor a missing session blocks them.
  if (isSlash) return "send";
  if (!busy && hasSession) return "send";
  // Busy, or still connecting. Either way the text is worth keeping: a session
  // that never arrives leaves it visibly parked rather than vanished.
  return "queue";
}

/** The result of parking one message. */
export interface EnqueueResult {
  /** The queue after the attempt. Unchanged when `accepted` is false. */
  queue: string[];
  /** False only when the queue was already at {@link COMPOSER_QUEUE_LIMIT}. */
  accepted: boolean;
}

/**
 * Park one message at the back of the queue.
 *
 * @param queue - the current queue; never mutated.
 * @param input - the message to park.
 * @param limit - the cap, injectable for tests.
 * @returns the new queue and whether the message was accepted.
 */
export function enqueueComposerInput(
  queue: readonly string[],
  input: string,
  limit: number = COMPOSER_QUEUE_LIMIT,
): EnqueueResult {
  if (queue.length >= limit) return { queue: [...queue], accepted: false };
  return { queue: [...queue, input], accepted: true };
}


export interface FlushQueuedInputParams {
  /** Raw composer input submitted with Enter. */
  input: string;
  /** Whether a turn is currently in flight. */
  busy: boolean;
  /** Whether a session exists to send against. */
  hasSession: boolean;
  /** Number of parked messages. */
  queuedCount: number;
}

/**
 * Decide whether an empty Enter should flush the next queued message now.
 *
 * This is the manual escape hatch for the operator-visible queue: if a message
 * is parked and the console is idle, pressing Enter on an empty composer sends
 * the front queued message immediately instead of doing nothing. Busy turns stay
 * single-flight; while busy, Enter still cannot race a second model call.
 */
export function shouldFlushQueuedInput(params: FlushQueuedInputParams): boolean {
  return !params.input.trim() && !params.busy && params.hasSession && params.queuedCount > 0;
}

/** The result of taking the next parked message. */
export interface DequeueResult {
  /** The front message, or undefined when the queue was empty. */
  next: string | undefined;
  /** The queue after the take. */
  rest: string[];
}

/**
 * Take the next parked message.
 *
 * Callers drain ONE per idle transition rather than looping: delivering a
 * message makes the console busy again, so the following idle drains the next.
 * That keeps FIFO order without the drain re-entering itself.
 *
 * @param queue - the current queue; never mutated.
 * @returns the front message (if any) and the remaining queue.
 */
export function dequeueComposerInput(queue: readonly string[]): DequeueResult {
  if (queue.length === 0) return { next: undefined, rest: [] };
  const [next, ...rest] = queue;
  return { next, rest };
}

/**
 * The operator-facing label for parked messages.
 *
 * Returns undefined when there is nothing parked, so the caller can render
 * nothing at all rather than an empty slot.
 *
 * @param count - how many messages are parked.
 * @returns the label, or undefined when the queue is empty.
 */
export function composerQueueLabel(count: number): string | undefined {
  if (count <= 0) return undefined;
  return count === 1 ? "1 queued" : `${count} queued`;
}
