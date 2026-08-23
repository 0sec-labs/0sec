/** @jsxImportSource @opentui/react */
/**
 * The full-screen "resume a session" browser.
 *
 * Resuming a stored engagement used to happen through a compact picker floating
 * above the composer: a flat list of previews, one line each, and nowhere to
 * say what any of them was actually *about*. That shape competed with the
 * transcript for the only scarce resource a TUI has — rows — and it left the
 * operator scanning truncated first-prompts to guess which engagement they were
 * about to drop back into.
 *
 * This screen is the replacement, and — like `/model` and `/settings` — it is a
 * projection of the one shared picker body, `DialogSelectBody`: the grouped,
 * windowed list of sessions on the left and, on the right, a detail pane that
 * says what the highlighted session was for and everything recorded about it.
 * This file supplies only the domain (which sessions exist, how they group,
 * what their detail says) and its own keyboard; `resume-layout.ts` supplies
 * every width, height and row count, swept by a test.
 *
 * Two properties are load-bearing:
 *
 * 1. **This component does no arithmetic.** Every width, height, row count and
 *    window boundary comes off `resume-layout.ts` / `dialog-select-layout.ts`.
 *    The reason is in `PRIMITIVES.md`: Yoga shrinks siblings rather than
 *    clipping them, so a row that claims one cell too many paints two strings
 *    on top of each other, and a bordered box one row short of its content
 *    paints its own border through that content.
 *
 * 2. **Deletion is never one tap.** `d` (or Delete) arms a confirm on the
 *    highlighted row; only a second press actually removes it. A transcript is
 *    plaintext engagement content — the destructive key must not fire on a
 *    fat-fingered keystroke, so anything other than the confirm cancels.
 */

import React, { useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { TextAttributes } from "@opentui/core";

import { type Theme } from "./theme-context.js";
import { Cells } from "./primitives.js";
import { DialogSelectBody, type DialogItem } from "./dialog-select.js";
import {
  clampDialogSelection,
  computeDialogPanel,
  moveDialogSelection,
} from "./dialog-select-layout.js";
import type { StoredSessionMeta } from "./session-store.js";
import {
  clipResumeDetailLines,
  isFilterKey,
  resumeDetailLines,
  resumeFooterHint,
  resumeItems,
  shellChromeRows,
  type ResumeDetailTone,
  type ResumeMode,
} from "./resume-layout.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;

export interface ResumeScreenProps {
  /** Stored sessions, newest-first as the caller supplies them. */
  sessions: StoredSessionMeta[];
  /** The session currently on screen, drawn with the gutter dot. */
  currentId?: string;
  /** Injected clock for the age strings. Never an ambient `Date.now()`. */
  now: number;
  /** Enter on a row — hand the id back so the router rebuilds the chat. */
  onResume: (id: string) => void;
  /** Confirmed delete of one transcript. Called only after a second `d`. */
  onDelete: (id: string) => void;
  /** Leave the screen — Esc, once any filter or armed delete is cleared. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
  /** The active palette, injected so the screen needs no theme context. */
  theme: Theme;
}

function toneColor(theme: Theme, tone: ResumeDetailTone): string | undefined {
  switch (tone) {
    case "title":
      return theme.PRIMARY;
    case "accent":
      return theme.ACCENT;
    case "muted":
    case "blank":
      return theme.MUTED;
    default:
      return theme.TEXT;
  }
}

export function ResumeScreen({
  sessions,
  currentId,
  now,
  onResume,
  onDelete,
  onBack,
  onExit,
  theme,
}: ResumeScreenProps) {
  const { width, height } = useTerminalDimensions();

  const [filter, setFilter] = useState("");
  const [filtering, setFiltering] = useState(false);
  // The id armed for deletion, or null. A second `d` on this id deletes.
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  // Rows deleted this session are hidden immediately, so the list updates
  // without waiting on the parent to re-list from disk.
  const [deleted, setDeleted] = useState<ReadonlySet<string>>(() => new Set());

  // The working directory the console is standing in — read from the sessions'
  // own metadata by matching the current session, so the "This project" split
  // needs no extra prop. Falls back to the first session's cwd when there is no
  // current session, which is the directory a fresh console saved into.
  const currentCwd = useMemo(() => {
    if (currentId !== undefined) {
      const active = sessions.find((session) => session.id === currentId);
      if (active) return active.cwd;
    }
    return sessions[0]?.cwd;
  }, [sessions, currentId]);

  const visibleSessions = useMemo(
    () => sessions.filter((session) => !deleted.has(session.id)),
    [sessions, deleted],
  );

  const items = useMemo<DialogItem[]>(
    () => resumeItems({ sessions: visibleSessions, currentId, currentCwd, now, filter }),
    [visibleSessions, currentId, currentCwd, now, filter],
  );
  const byId = useMemo(() => {
    const map = new Map<string, StoredSessionMeta>();
    for (const session of visibleSessions) map.set(session.id, session);
    return map;
  }, [visibleSessions]);

  // Display rows (headings interleaved) drive the panel's scroll/height math.
  const totalRows = useMemo(() => {
    let count = 0;
    let group: string | undefined;
    for (const item of items) {
      if (item.category && item.category !== group) {
        group = item.category;
        count += 1;
      }
      count += 1;
    }
    return count;
  }, [items]);

  const [selected, setSelected] = useState(0);
  // The highlighted row can vanish from under the cursor as the filter narrows
  // or a row is deleted, so the rendered cursor is always the clamped one.
  const cursor = clampDialogSelection(items, selected);
  const activeItem = items.length > 0 && cursor >= 0 ? items[cursor] : undefined;

  const mode: ResumeMode = pendingDelete ? "confirm-delete" : filtering ? "filter" : "browse";

  // The status line under the list carries the delete confirm. It costs a row
  // only when armed, and it names the row it will remove so a mistaken arm is
  // obvious before the second press.
  const pendingLabel = pendingDelete
    ? (items.find((item) => item.id === pendingDelete)?.label ?? "this session")
    : "";
  const statusText = pendingDelete ? `Delete "${pendingLabel}"? press d again to confirm · esc cancel` : "";

  const contentWidth = Math.max(0, width - 4);
  const bodyRows = Math.max(0, height - shellChromeRows(width) - (statusText ? 1 : 0));
  const panel = computeDialogPanel({
    width: contentWidth,
    height,
    size: "large",
    totalRows,
    withDetail: true,
    bodyRows,
  });

  const move = (delta: number) => {
    if (items.length === 0) return;
    setPendingDelete(null);
    const dir: 1 | -1 = delta >= 0 ? 1 : -1;
    let next = cursor < 0 ? 0 : cursor;
    for (let i = 0; i < Math.abs(delta); i += 1) next = moveDialogSelection(items, next, dir);
    setSelected(next);
  };

  const setQuery = (next: string) => {
    setPendingDelete(null);
    setFilter(next);
    setSelected(0);
  };

  const armOrDelete = () => {
    if (!activeItem) return;
    if (pendingDelete === activeItem.id) {
      // Confirmed: hide it now and tell the router to remove it from disk.
      const id = activeItem.id;
      setPendingDelete(null);
      setDeleted((prev) => {
        const next = new Set(prev);
        next.add(id);
        return next;
      });
      onDelete(id);
      return;
    }
    setPendingDelete(activeItem.id);
  };

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";

    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }

    if (key.name === "up") return move(-1);
    if (key.name === "down") return move(1);
    if (key.name === "pageup") return move(-PAGE_STEP);
    if (key.name === "pagedown") return move(PAGE_STEP);

    // The Delete key is a delete request in either mode — it is not a filter
    // character, so it never fights type-to-filter.
    if (key.name === "delete") {
      armOrDelete();
      return;
    }

    if (key.name === "return") {
      // Enter resumes from either mode: while filtering, the whole point of
      // typing is to reach one row and take it.
      if (activeItem) onResume(activeItem.id);
      return;
    }

    // ── filter mode ──
    if (filtering) {
      if (key.name === "escape") {
        setFiltering(false);
        return;
      }
      if (key.name === "backspace") {
        setQuery(filter.slice(0, -1));
        return;
      }
      if (isFilterKey(seq)) setQuery(filter + seq);
      return;
    }

    // ── browse mode ──
    if (key.name === "escape") {
      // Esc unwinds one step at a time: cancel an armed delete, then clear the
      // filter, then leave.
      if (pendingDelete) {
        setPendingDelete(null);
        return;
      }
      if (filter) {
        setQuery("");
        return;
      }
      onBack();
      return;
    }
    if (key.name === "backspace") {
      if (filter) setQuery(filter.slice(0, -1));
      return;
    }
    // `d` is reserved for delete/confirm, exactly as `/settings` reserves `r`
    // for reset; to type a `d` into the filter, open it with `/` first.
    if (seq === "d" || seq === "D") {
      armOrDelete();
      return;
    }
    if (seq === "/") {
      setFiltering(true);
      setQuery("");
      return;
    }
    if (isFilterKey(seq)) {
      setFiltering(true);
      setQuery(seq);
    }
  });

  // The detail pane: what the highlighted session was about, then its metadata,
  // fitted to the exact box the shared body hands it.
  const renderDetail = (item: DialogItem, pane: { width: number; height: number }) => {
    const session = byId.get(item.id);
    const compact = pane.height < 12;
    const lines = clipResumeDetailLines(
      resumeDetailLines({ session, now, compact }, pane.width),
      pane.height,
      pane.width,
    );
    return (
      <>
        {lines.map((line, index) => (
          <Cells
            key={`detail-${index}`}
            width={pane.width}
            fg={toneColor(theme, line.tone)}
            attributes={line.tone === "title" ? TextAttributes.BOLD : undefined}
          >
            {line.text}
          </Cells>
        ))}
      </>
    );
  };

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <DialogSelectBody
        items={items}
        cursor={cursor}
        panel={panel}
        query={filter}
        placeholder="type to filter sessions"
        gutter={items.some((item) => item.current === true)}
        isCurrent={(item) => item.current === true}
        renderDetail={renderDetail}
        emptyText={filter ? "no sessions match this filter" : "no saved sessions to resume"}
      />
      {statusText ? (
        <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
          <Cells width={contentWidth} fg={theme.WARNING}>
            {statusText}
          </Cells>
        </box>
      ) : null}
      <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
        <Cells width={contentWidth} fg={theme.MUTED}>
          {resumeFooterHint(mode, filter.length > 0, items.length > 0)}
        </Cells>
      </box>
    </box>
  );

  return <>{body}</>;
}
