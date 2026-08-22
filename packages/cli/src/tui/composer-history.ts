/**
 * Readline-style recall of previously submitted operator messages.
 *
 * The console composer is append-only and has no caret, so its history is the
 * one place arrow keys earn their keep: Up walks back through what the operator
 * already sent, Down walks forward toward the live draft. This module owns the
 * pure cursor arithmetic — an array of submissions plus a position — so the
 * transitions are unit-tested here rather than reasoned about inside the
 * keyboard handler.
 *
 * The model, borrowed straight from shells: `index` points into `entries`,
 * and `index >= entries.length` is the sentinel for "not browsing, editing the
 * live draft". The first Up saves whatever is in the buffer as `draft` and
 * jumps to the newest entry; each further Up moves toward older; Down moves
 * toward newer and, on stepping past the newest entry, restores the saved
 * draft. Every out-of-range move is a no-op the caller can ignore, so an empty
 * history and an already-at-either-end cursor cost nothing.
 */

/** How many submissions to remember. Old entries fall off the front. */
export const HISTORY_LIMIT = 100;

/**
 * Append a submitted message to the history, oldest-first. Empty and
 * whitespace-only inputs are dropped, a submission identical to the most recent
 * one is de-duplicated (so holding Enter on the same command does not bloat the
 * ring), and the list is capped at `limit` by evicting from the front.
 */
export function pushHistory(
  entries: readonly string[],
  text: string,
  limit: number = HISTORY_LIMIT,
): string[] {
  if (text.trim().length === 0) return [...entries];
  if (entries.length > 0 && entries[entries.length - 1] === text) return [...entries];
  const next = [...entries, text];
  if (next.length > limit) next.splice(0, next.length - limit);
  return next;
}

/**
 * The outcome of a recall step. `value` is the text to place in the composer,
 * `index` the new cursor position, `draft` the buffer to remember for a later
 * restore, and `changed` whether anything moved — a `false` result is a no-op
 * the caller must not act on (leave the composer and cursor untouched).
 */
export interface Recall {
  readonly value: string;
  readonly index: number;
  readonly draft: string;
  readonly changed: boolean;
}

/**
 * Step one entry older (the Up arrow). From the live draft this saves `buffer`
 * as the draft and jumps to the newest entry; from within history it moves one
 * step back. An empty history, or a cursor already at the oldest entry, is a
 * no-op.
 */
export function recallPrev(
  entries: readonly string[],
  index: number,
  draft: string,
  buffer: string,
): Recall {
  if (entries.length === 0) return { value: buffer, index, draft, changed: false };
  // Leaving the live draft: remember it, land on the newest entry.
  if (index >= entries.length) {
    const newIndex = entries.length - 1;
    return { value: entries[newIndex]!, index: newIndex, draft: buffer, changed: true };
  }
  // Already at the oldest entry: nothing older to show.
  if (index <= 0) return { value: entries[0]!, index: 0, draft, changed: false };
  const newIndex = index - 1;
  return { value: entries[newIndex]!, index: newIndex, draft, changed: true };
}

/**
 * Step one entry newer (the Down arrow). Moves toward the live draft and, on
 * stepping past the newest entry, restores the saved draft and returns to the
 * not-browsing sentinel. A cursor already at the draft is a no-op.
 */
export function recallNext(
  entries: readonly string[],
  index: number,
  draft: string,
): Recall {
  // Not browsing: there is nothing newer than the live draft.
  if (index >= entries.length) return { value: draft, index, draft, changed: false };
  const newIndex = index + 1;
  if (newIndex >= entries.length) {
    // Walked past the newest entry — back to the draft the operator was typing.
    return { value: draft, index: entries.length, draft, changed: true };
  }
  return { value: entries[newIndex]!, index: newIndex, draft, changed: true };
}
