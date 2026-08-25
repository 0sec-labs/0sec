export type StreamEntryKind = "assistant" | "reasoning";

/**
 * A latest-state update for one streamed transcript row. `at` is captured when
 * the row first appears so coalescing does not make its timestamp drift while
 * tokens continue to arrive.
 */
export interface StreamPatch {
  kind: StreamEntryKind;
  text: string;
  turn: number;
  at: number;
}

/** The transcript fields the coalescer owns. Real entries may carry more data. */
export interface StreamEntryLike {
  kind: string;
  text: string;
  turn: number;
}

/**
 * Add a streamed update without retaining every intermediate token state.
 * Adjacent updates for the same row collapse to its newest text; updates of a
 * different kind or turn deliberately keep their order.
 */
export function enqueueStreamPatch(
  pending: readonly StreamPatch[],
  patch: StreamPatch,
): StreamPatch[] {
  const previous = pending.at(-1);
  if (previous?.kind === patch.kind && previous.turn === patch.turn) {
    if (previous.text === patch.text) return pending as StreamPatch[];
    return [
      ...pending.slice(0, -1),
      { ...previous, text: patch.text },
    ];
  }
  return [...pending, patch];
}

/**
 * Apply an ordered batch of stream updates to a transcript. The behavior is
 * intentionally the same as updating the live tail once per delta, except
 * unseen intermediate text is skipped. A patch only replaces the current tail;
 * a tool, notice, or another stream kind between two patches starts a new row.
 */
export function applyStreamPatches<T extends StreamEntryLike>(
  entries: readonly T[],
  patches: readonly StreamPatch[],
  createEntry: (patch: StreamPatch) => T,
): T[] {
  let next: T[] | undefined;

  for (const patch of patches) {
    const current = next ?? entries;
    const tail = current.at(-1);

    if (tail?.kind === patch.kind && tail.turn === patch.turn) {
      if (tail.text === patch.text) continue;
      if (!next) next = [...entries];
      next[next.length - 1] = { ...tail, text: patch.text } as T;
      continue;
    }

    const created = createEntry(patch);
    next = next ? [...next, created] : [...entries, created];
  }

  return next ?? (entries as T[]);
}
