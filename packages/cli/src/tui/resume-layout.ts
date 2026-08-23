/**
 * Layout, grouping and detail-pane arithmetic for the full-screen "resume a
 * session" browser.
 *
 * This is `model-layout.ts` / `settings-layout.ts` for the resume screen, and it
 * exists for the same reason spelled out in `PRIMITIVES.md`: OpenTUI lays rows
 * out with Yoga, and Yoga *shrinks* siblings rather than clipping them. Two
 * `<text>` nodes that together want more cells than their row has are both
 * painted in full into boxes now too small, and the terminal shows the two
 * strings interleaved character by character; the same failure on the vertical
 * axis makes a bordered box paint its own border through its last content row.
 * So the component reads widths and row counts off this module and never
 * computes one, and a sweep hammers every number in here across widths and
 * heights.
 *
 * What is domain-specific and lives here:
 *
 *   - the category split, "This project" before "Other projects", so the
 *     operator sees at a glance which stored engagements ran in the directory
 *     they are standing in;
 *   - the list projection (`resumeItems`) — label, compact meta, category and
 *     current-session dot — plus the AND-over-terms filter, scoped to the
 *     `summary` and `preview` because those are the two lines that say what a
 *     session was *about*;
 *   - the detail pane (`resumeDetailLines`): the objective/preview in full,
 *     then a metadata block, as flat tone-tagged lines the component only has
 *     to colour.
 *
 * `shellChromeRows` and `wrapCells` are imported from `settings-layout.ts`
 * rather than copied — the honest long-term home for both is a shared
 * `shell-geometry.ts`, and this import is the marker for that move. Nothing here
 * imports React, OpenTUI, or touches I/O.
 */

import { relativeAge, type StoredSessionMeta } from "./session-store.js";
import { shellChromeRows, wrapCells } from "./settings-layout.js";
import { sanitizeTuiText } from "./text.js";
import type { DialogItem } from "./dialog-select-layout.js";

export { shellChromeRows, wrapCells };

// ---------------------------------------------------------------------------
// Numeric hygiene
// ---------------------------------------------------------------------------

/**
 * Cell and row counts are non-negative integers.
 *
 * Terminal geometry arrives from `useTerminalDimensions`, which reports 0 on a
 * detached tty and can report a fractional or `NaN` size mid-resize. Yoga
 * accepts all of those and lays out sub-cell boxes that round inconsistently
 * between siblings, which is itself an overlap.
 */
function cells(value: unknown, fallback = 0): number {
  const raw = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  const truncated = Math.trunc(raw);
  return truncated > 0 ? truncated : 0;
}

// ---------------------------------------------------------------------------
// Category split
// ---------------------------------------------------------------------------

/** Heading for sessions saved in the directory the console is running in. */
export const CATEGORY_THIS = "This project";
/** Heading for sessions saved in any other working directory. */
export const CATEGORY_OTHER = "Other projects";

/**
 * The group heading a session sits under, or `undefined` when the list should
 * not be split at all.
 *
 * The split is only meaningful when the caller knows its own working directory:
 * with no `currentCwd` there is no "here" to contrast against, so every session
 * is uncategorised and the list renders flat (no headings). With a `currentCwd`
 * the sessions that ran there sort under "This project" and the rest under
 * "Other projects", which is the one distinction an operator resuming work
 * actually cares about.
 */
export function sessionCategory(
  session: StoredSessionMeta,
  currentCwd?: string,
): string | undefined {
  if (currentCwd === undefined || currentCwd.length === 0) return undefined;
  return session.cwd === currentCwd ? CATEGORY_THIS : CATEGORY_OTHER;
}

// ---------------------------------------------------------------------------
// List projection
// ---------------------------------------------------------------------------

/**
 * The row label: the objective if the caller recorded one, else the opening
 * prompt, else an explicit placeholder so a session with neither is still a
 * selectable, named row rather than a blank line.
 */
export function sessionLabel(session: StoredSessionMeta): string {
  const summary = sanitizeTuiText(session.summary ?? "");
  if (summary.length > 0) return summary;
  const preview = sanitizeTuiText(session.preview ?? "");
  if (preview.length > 0) return preview;
  return "(no prompt)";
}

/**
 * The compact right-aligned meta: `age · N msgs · model`.
 *
 * A blank age (an unorderable or future `savedAt`, per `relativeAge`) is
 * dropped rather than printed as a dangling separator, and the model is dropped
 * when the session never recorded one. The full, unabbreviated facts live in
 * the detail pane; this line is only the glance.
 */
export function sessionMeta(session: StoredSessionMeta, now: number): string {
  const parts: string[] = [];
  const age = relativeAge(session.savedAt, now);
  if (age.length > 0) parts.push(age);
  const count = cells(session.messageCount);
  parts.push(`${count} msg${count === 1 ? "" : "s"}`);
  const model = sanitizeTuiText(session.model ?? "");
  if (model.length > 0) parts.push(model);
  return parts.join(" · ");
}

export interface ResumeItemsInput {
  /** Sessions to project, newest-first as the caller supplies them. */
  sessions: readonly StoredSessionMeta[];
  /** The session currently on screen, marked with the gutter dot. */
  currentId?: string;
  /** The console's working directory; drives the "This project" split. */
  currentCwd?: string;
  /** Injected clock for `relativeAge`. Never an ambient `Date.now()`. */
  now: number;
  /** AND-over-terms filter, matched against `summary` + `preview` only. */
  filter?: string;
}

/**
 * Projects sessions onto `DialogItem`s, filtered and grouped.
 *
 * The filter is AND-over-terms across the objective and the opening prompt —
 * the two fields that say what a session was for — so typing a target host or a
 * bug class reaches the right engagement without matching an incidental model
 * id or timestamp. Surviving sessions keep their newest-first order within each
 * category, and "This project" is emitted before "Other projects" so
 * `buildDialogRows` draws that heading first.
 */
export function resumeItems({
  sessions,
  currentId,
  currentCwd,
  now,
  filter = "",
}: ResumeItemsInput): DialogItem[] {
  const terms = sanitizeTuiText(filter).toLowerCase().split(" ").filter(Boolean);
  const matched = sessions.filter((session) => {
    if (terms.length === 0) return true;
    const haystack = `${session.summary ?? ""} ${session.preview ?? ""}`.toLowerCase();
    return terms.every((term) => haystack.includes(term));
  });

  // Partition stably so "This project" leads. With no `currentCwd` every
  // category is undefined and the input order is preserved untouched.
  const here: StoredSessionMeta[] = [];
  const elsewhere: StoredSessionMeta[] = [];
  for (const session of matched) {
    if (sessionCategory(session, currentCwd) === CATEGORY_THIS) here.push(session);
    else elsewhere.push(session);
  }
  const ordered = currentCwd ? [...here, ...elsewhere] : matched;

  return ordered.map((session) => ({
    id: session.id,
    label: sessionLabel(session),
    meta: sessionMeta(session, now),
    category: sessionCategory(session, currentCwd),
    current: currentId !== undefined && session.id === currentId,
  }));
}

// ---------------------------------------------------------------------------
// Absolute timestamp
// ---------------------------------------------------------------------------

function pad2(value: number): string {
  return String(value).padStart(2, "0");
}

/**
 * The absolute save time as `YYYY-MM-DD HH:MM UTC`, or "" for an unorderable
 * timestamp.
 *
 * UTC on purpose: the whole store is deterministic (its ordering and its
 * `relativeAge` take an injected clock), and a local-time render would make the
 * detail pane depend on the machine's timezone, which no test could pin. The
 * relative age beside it in the pane carries the "how long ago" the operator
 * reads at a glance; this is the stable anchor.
 */
export function formatSavedAt(savedAt: number): string {
  if (!Number.isFinite(savedAt) || savedAt <= 0) return "";
  const date = new Date(savedAt);
  const day = `${date.getUTCFullYear()}-${pad2(date.getUTCMonth() + 1)}-${pad2(date.getUTCDate())}`;
  const time = `${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}`;
  return `${day} ${time} UTC`;
}

// ---------------------------------------------------------------------------
// Detail pane
// ---------------------------------------------------------------------------

export type ResumeDetailTone = "title" | "text" | "muted" | "accent" | "blank";

export interface ResumeDetailLine {
  readonly text: string;
  readonly tone: ResumeDetailTone;
}

export interface ResumeDetailInput {
  session?: StoredSessionMeta;
  /** Injected clock for the relative-age line. */
  now: number;
  /** Omit the blank separator rows. Set when the pane is short of rows. */
  compact?: boolean;
}

/**
 * The detail pane's body, as flat tone-tagged lines: the objective/preview in
 * full, then a metadata block.
 *
 * Content is decided here and colour is decided by the component, so the pane
 * can be asserted on without a renderer. Every value is wrapped to `width` by
 * `wrapCells`, so no line can overhang the pane; optional fields (target, mode,
 * model) are simply absent when the session never recorded them rather than
 * printed as "none". `": "` separators, never alignment columns:
 * `sanitizeTuiText` collapses whitespace, so a padded literal would be trimmed
 * away and the label would fuse to its value.
 */
export function resumeDetailLines(
  { session, now, compact = false }: ResumeDetailInput,
  width: number,
): ResumeDetailLine[] {
  const limit = cells(width);
  if (!session || limit <= 0) return [];

  const lines: ResumeDetailLine[] = [];
  const push = (value: string, tone: ResumeDetailTone) => {
    for (const text of wrapCells(value, limit)) lines.push({ text, tone });
  };
  const separate = () => {
    if (!compact) lines.push({ text: "", tone: "blank" });
  };

  // What the session was about / did. When the objective and the opening
  // prompt differ, show both — the objective as the headline, the prompt as the
  // muted "how it opened" beneath — since together they are the "what's what"
  // the operator opened this screen to read.
  const summary = sanitizeTuiText(session.summary ?? "");
  const preview = sanitizeTuiText(session.preview ?? "");
  if (summary.length > 0) {
    push(summary, "text");
    if (preview.length > 0 && preview !== summary) {
      separate();
      push(`Opened with: ${preview}`, "muted");
    }
  } else if (preview.length > 0) {
    push(preview, "text");
  } else {
    push("(no prompt recorded)", "muted");
  }

  separate();

  const count = cells(session.messageCount);
  push(`Messages: ${count}`, "muted");
  const model = sanitizeTuiText(session.model ?? "");
  if (model.length > 0) push(`Model: ${model}`, "muted");
  const mode = sanitizeTuiText(session.mode ?? "");
  if (mode.length > 0) push(`Mode: ${mode}`, "muted");
  const target = sanitizeTuiText(session.target ?? "");
  if (target.length > 0) push(`Target: ${target}`, "muted");
  const cwd = sanitizeTuiText(session.cwd ?? "");
  if (cwd.length > 0) push(`Cwd: ${cwd}`, "muted");

  const absolute = formatSavedAt(session.savedAt);
  const age = relativeAge(session.savedAt, now);
  if (absolute.length > 0 && age.length > 0) push(`Saved: ${absolute} (${age} ago)`, "muted");
  else if (absolute.length > 0) push(`Saved: ${absolute}`, "muted");
  else if (age.length > 0) push(`Saved: ${age} ago`, "muted");

  return lines;
}

/**
 * Trims detail lines to the rows the pane actually has, marking the cut.
 *
 * Rendering more rows than the box holds is what pushes a border through the
 * content, so the overflow has to be cut — but it is marked rather than cut
 * silently. Given a width, the marker is appended to the last surviving line
 * instead of taking a row of its own, because on the terminals where clipping
 * happens the pane has only a few rows and a lone `...` throws away real text to
 * say text was thrown away. Mirrors `clipModelDetailLines`; kept local because
 * this module's tone union is its own.
 */
export function clipResumeDetailLines(
  lines: readonly ResumeDetailLine[],
  rows: number,
  width = 0,
): ResumeDetailLine[] {
  const limit = cells(rows);
  if (limit <= 0) return [];
  if (lines.length <= limit) return [...lines];

  const kept = lines.slice(0, limit);
  const last = kept[limit - 1];
  const room = cells(width);
  if (room >= 8 && last && last.text.length > 0) {
    const head = last.text.slice(0, Math.max(0, room - 4)).trimEnd();
    kept[limit - 1] = { text: `${head} ...`, tone: last.tone };
  } else {
    kept[limit - 1] = { text: "...", tone: "muted" };
  }
  return kept;
}

// ---------------------------------------------------------------------------
// Hints and keys
// ---------------------------------------------------------------------------

export type ResumeMode = "browse" | "filter" | "confirm-delete";

/**
 * The footer hint, per mode.
 *
 * `d` is named as the delete key in browse mode and, once armed, the confirm
 * key — a second press is what actually deletes, so the destructive action is
 * never one tap. Esc unwinds one step at a time, which the hint reflects: it
 * cancels an armed delete, then clears a filter, then leaves.
 */
export function resumeFooterHint(
  mode: ResumeMode,
  hasFilter = false,
  hasSessions = true,
): string {
  switch (mode) {
    case "filter":
      return "type to filter · enter/esc done · backspace delete";
    case "confirm-delete":
      return "d or del confirm delete · esc cancel";
    default:
      return [
        "up/down move",
        hasSessions ? "enter resume" : undefined,
        hasSessions ? "d delete" : undefined,
        "/ filter",
        hasFilter ? "esc clear filter" : "esc back",
        "ctrl+c exit",
      ]
        .filter((part): part is string => part !== undefined)
        .join(" · ");
  }
}

/**
 * Every printable character can start a filter — except the keys browse mode
 * reserves, which the caller checks first (`d` for delete). This only decides
 * "is this a character that types", exactly as the model and settings screens'
 * own `isFilterKey` does; kept local so this module has no cross-screen import.
 */
export function isFilterKey(sequence: unknown): boolean {
  if (typeof sequence !== "string" || sequence.length !== 1) return false;
  const code = sequence.charCodeAt(0);
  return code >= 0x20 && code !== 0x7f;
}
