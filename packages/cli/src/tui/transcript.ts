/**
 * Pure transcript logic for the chat screen.
 *
 * {@link appendTranscriptEntry} collapses *consecutive* identical entries, so
 * a refusal fired eight times by a key repeat renders once with a count
 * instead of eight times verbatim. It used to be impossible to test because
 * it was tangled into a 2 000-line React component.
 */

/** The transcript voices. Mirrors `ChatEntry["kind"]` in chat-screen.tsx. */
export type TranscriptEntryKind =
  | "user"
  | "assistant"
  | "reasoning"
  | "tool"
  | "subagent"
  | "notice"
  | "panel"
  | "error"
  | "peer";

/**
 * The subset of a chat entry these functions reason about. The renderer's
 * `ChatEntry` is a superset (it adds an id, a timestamp and the subagent
 * card fields), so anything produced here is assignable to it.
 */
export interface TranscriptEntry {
  kind: TranscriptEntryKind;
  text: string;
  detail?: string;
  success?: boolean;
  turn: number;
  /**
   * How many consecutive identical entries this row stands for. Absent or 1
   * means "just this one". The count is carried as a FIELD rather than being
   * baked into `text`, so the next duplicate still compares equal and the
   * collapse keeps working past the second repeat.
   */
  repeat?: number;
}

// ---------------------------------------------------------------------------
// Consecutive-duplicate collapse
// ---------------------------------------------------------------------------

/**
 * Kinds that must never collapse.
 *
 * `user` — an operator who deliberately sends the same line twice has to see
 * it twice; the transcript is evidence of what was actually submitted.
 * `panel` — a panel's payload lives in `panel`, not in `text`, so two panels
 * that happen to share a title are not necessarily the same output, and a
 * command the operator ran twice must produce two answers.
 */
const NEVER_COLLAPSE: ReadonlySet<TranscriptEntryKind> = new Set<TranscriptEntryKind>([
  "user",
  "panel",
]);

/**
 * True when `next` is a repeat of `previous` for collapse purposes.
 *
 * `detail` participates in the comparison as well as `kind`/`text`: two
 * notices sharing a headline but carrying different explanations are two
 * different pieces of information, and merging them would hide one.
 */
export function isConsecutiveDuplicate(
  previous: TranscriptEntry | undefined,
  next: TranscriptEntry,
): boolean {
  if (!previous) return false;
  if (NEVER_COLLAPSE.has(next.kind)) return false;
  return (
    previous.kind === next.kind
    && previous.text === next.text
    && (previous.detail ?? "") === (next.detail ?? "")
    && previous.success === next.success
  );
}

/**
 * Append `next`, collapsing it into the last entry when it is an immediate
 * repeat. Only the IMMEDIATELY preceding entry is considered: the same
 * notice appearing again later in the conversation is real information about
 * a later moment, and squashing it would be a lie about the timeline.
 *
 * The array is never mutated — the caller is a React state updater.
 */
export function appendTranscriptEntry<T extends TranscriptEntry>(
  entries: readonly T[],
  next: T,
): T[] {
  const previous = entries[entries.length - 1];
  if (isConsecutiveDuplicate(previous, next)) {
    const collapsed = { ...previous, repeat: (previous.repeat ?? 1) + 1 };
    return [...entries.slice(0, -1), collapsed];
  }
  return [...entries, next];
}

/** Display suffix for a collapsed row: `" (x3)"`, or "" when it stands alone. */
export function repeatSuffix(repeat: number | undefined): string {
  return repeat && repeat > 1 ? ` (x${repeat})` : "";
}
