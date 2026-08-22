/**
 * Pure state model for the interactive selector overlay.
 *
 * `/model` used to answer with a single line of text. The overlay that
 * replaces it is a keyboard-driven list — filter as you type, arrow to
 * navigate, enter to commit — and the same widget has to serve `/mode`,
 * `/agents` and `/targets` without being rewritten each time. So the
 * *behaviour* lives here as a reducer over a plain object and the React /
 * OpenTUI component becomes a dumb projection of it.
 *
 * Nothing in this file imports React, OpenTUI, or touches I/O: every rule
 * that is easy to get subtly wrong (wrap-around past disabled rows, index
 * clamping when the filter shrinks the list, viewport scrolling) is a unit
 * test rather than something you have to drive a terminal to observe.
 */

export interface SelectorItem {
  /** Stable identifier returned on commit. */
  id: string;
  /** Primary text, e.g. "gpt-5.5". */
  label: string;
  /** Right-aligned metadata, e.g. "openai · $5/30 per M". */
  meta?: string;
  /** Second-line detail shown for the highlighted item only. */
  detail?: string;
  /** Rendered dimmed and skipped by navigation when true. */
  disabled?: boolean;
  /** Marks the item that is currently in effect (e.g. the active model). */
  current?: boolean;
}

export interface SelectorState {
  title: string;
  items: SelectorItem[];
  /** Live filter text, exactly as typed. */
  query: string;
  /** Highlighted position WITHIN the filtered list, never the full list. */
  index: number;
}

export type SelectorAction =
  | { type: "up" }
  | { type: "down" }
  | { type: "home" }
  | { type: "end" }
  | { type: "append"; char: string }
  | { type: "backspace" }
  | { type: "setQuery"; query: string };

/** Ranks are ordered: lower sorts first. */
const RANK_SUBSTRING = 0;
const RANK_SUBSEQUENCE = 1;
const RANK_NO_MATCH = -1;

/** Everything the filter searches, as one lowercased haystack. */
function haystack(item: SelectorItem): string {
  return item.meta ? `${item.label} ${item.meta}`.toLowerCase() : item.label.toLowerCase();
}

function isSubsequence(needle: string, hay: string): boolean {
  let at = 0;
  for (let i = 0; i < hay.length && at < needle.length; i += 1) {
    if (hay[i] === needle[at]) at += 1;
  }
  return at === needle.length;
}

/**
 * Two-tier match. Typing "g55" should still find "gpt-5.5" (subsequence),
 * but when a query IS a literal substring of something, that something is
 * almost always what the operator meant — so "gpt-5" must not be buried
 * under a dozen incidental subsequence hits.
 */
function rankOf(item: SelectorItem, needle: string): number {
  if (needle.length === 0) return RANK_SUBSTRING;
  const hay = haystack(item);
  if (hay.includes(needle)) return RANK_SUBSTRING;
  return isSubsequence(needle, hay) ? RANK_SUBSEQUENCE : RANK_NO_MATCH;
}

export function visibleItems(state: SelectorState): SelectorItem[] {
  const needle = state.query.toLowerCase();
  if (needle.length === 0) return state.items.slice();

  // Decorate/sort/undecorate with the original position as the final key:
  // Array.prototype.sort is only guaranteed stable per spec, and carrying
  // the position explicitly makes "ties keep input order" a property of
  // the code rather than of the engine.
  const ranked: Array<{ item: SelectorItem; rank: number; position: number }> = [];
  state.items.forEach((item, position) => {
    const rank = rankOf(item, needle);
    if (rank !== RANK_NO_MATCH) ranked.push({ item, rank, position });
  });
  ranked.sort((a, b) => (a.rank === b.rank ? a.position - b.position : a.rank - b.rank));
  return ranked.map((entry) => entry.item);
}

export function highlighted(state: SelectorState): SelectorItem | undefined {
  return visibleItems(state)[state.index];
}

function hasEnabled(list: SelectorItem[]): boolean {
  return list.some((item) => !item.disabled);
}

/**
 * First enabled position at or after `from`, walking in `step` direction and
 * wrapping once. The loop is bounded by the list length rather than by
 * "until we find one": a list whose rows are ALL disabled would otherwise
 * spin forever, and such a list is reachable (e.g. a provider whose models
 * are all gated behind a missing API key).
 */
function seekEnabled(list: SelectorItem[], from: number, step: 1 | -1): number {
  if (list.length === 0) return 0;
  const origin = ((from % list.length) + list.length) % list.length;
  let at = origin;
  for (let hops = 0; hops < list.length; hops += 1) {
    if (!list[at].disabled) return at;
    at = (at + step + list.length) % list.length;
  }
  return origin;
}

/** Step exactly one row, then skip over any disabled rows in that direction. */
function move(list: SelectorItem[], index: number, step: 1 | -1): number {
  if (list.length === 0) return 0;
  // Nothing to land on: stay exactly where we are instead of drifting.
  if (!hasEnabled(list)) return index;
  const next = (index + step + list.length) % list.length;
  return seekEnabled(list, next, step);
}

export function createSelectorState(
  title: string,
  items: SelectorItem[],
  initialId?: string,
): SelectorState {
  const start = items.findIndex((item) => item.id === initialId && !item.disabled);
  const index = start >= 0 ? start : seekEnabled(items, 0, 1);
  return { title, items: items.slice(), query: "", index };
}

/**
 * Re-anchor the highlight after the filter changed. Keeping the operator on
 * the row they were already looking at is the least surprising behaviour;
 * only when that row is filtered away do we fall back to clamping the raw
 * position into the new range.
 */
function reanchor(previous: SelectorItem | undefined, next: SelectorItem[], oldIndex: number): number {
  if (next.length === 0) return 0;
  if (previous) {
    const kept = next.findIndex((item) => item.id === previous.id);
    if (kept >= 0) return kept;
  }
  const clamped = Math.min(Math.max(oldIndex, 0), next.length - 1);
  return next[clamped]?.disabled ? seekEnabled(next, clamped, 1) : clamped;
}

function withQuery(state: SelectorState, query: string): SelectorState {
  const previous = highlighted(state);
  const next: SelectorState = { ...state, query, index: 0 };
  next.index = reanchor(previous, visibleItems(next), state.index);
  return next;
}

export function reduceSelector(state: SelectorState, action: SelectorAction): SelectorState {
  switch (action.type) {
    case "up":
    case "down": {
      const list = visibleItems(state);
      return { ...state, index: move(list, state.index, action.type === "up" ? -1 : 1) };
    }
    case "home": {
      const list = visibleItems(state);
      if (!hasEnabled(list)) return { ...state };
      return { ...state, index: seekEnabled(list, 0, 1) };
    }
    case "end": {
      const list = visibleItems(state);
      if (!hasEnabled(list)) return { ...state };
      return { ...state, index: seekEnabled(list, Math.max(0, list.length - 1), -1) };
    }
    case "append":
      return withQuery(state, state.query + action.char);
    case "backspace":
      return withQuery(state, state.query.slice(0, -1));
    case "setQuery":
      return withQuery(state, action.query);
    default:
      return { ...state };
  }
}

/**
 * Slice bounds for a scrolling viewport of `maxRows`.
 *
 * The highlight is centred rather than pinned to an edge so the operator can
 * always see what is above and below the cursor; the clamp then pulls the
 * window flush against the ends of the list so the last page is never padded
 * with blank rows.
 */
export function windowFor(state: SelectorState, maxRows: number): { start: number; end: number } {
  const total = visibleItems(state).length;
  if (maxRows <= 0 || total === 0) return { start: 0, end: 0 };
  if (maxRows >= total) return { start: 0, end: total };

  const index = Math.min(Math.max(state.index, 0), total - 1);
  const centred = index - Math.floor((maxRows - 1) / 2);
  const start = Math.min(Math.max(centred, 0), total - maxRows);
  return { start, end: start + maxRows };
}
