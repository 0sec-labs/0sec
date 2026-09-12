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

import React, { useMemo, useRef, useState } from "react";
import { useKeyboard, usePaste, useTerminalDimensions } from "@opentui/react";
import { decodePasteBytes, TextAttributes } from "@opentui/core";

import { type Theme } from "./theme-context.js";
import { Cells } from "./primitives.js";
import { DialogSelectBody, type DialogItem } from "./dialog-select.js";
import {
  clampDialogSelection,
  computeDialogPanel,
  moveDialogSelection,
} from "./dialog-select-layout.js";
import type { StoredSessionMeta } from "./session-store.js";
import { sanitizeTuiText } from "./text.js";
import {
  clipResumeDetailLines,
  isFilterKey,
  resumeDetailLines,
  resumeFooterHint,
  resumeItems,
  sessionCategory,
  CATEGORY_THIS,
  CATEGORY_OTHER,
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
  /**
   * The console's actual working directory for "This project" scope.
   * Passed from the route using `process.cwd()` rather than guessed from
   * session metadata, so the category split is accurate even when there are
   * no sessions from the current directory yet.
   */
  currentCwd?: string;
  /** Enter on a row — hand the id back so the router rebuilds the chat. */
  onResume: (id: string) => boolean;
  /**
   * Confirmed delete of one transcript. Called only after a confirm key on an
   * armed row. Returns whether the deletion succeeded so the screen only hides
   * the row locally on success.
   */
  onDelete: (id: string) => boolean;
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
  currentCwd: propCwd,
  onResume,
  onDelete,
  onBack,
  onExit,
  theme,
}: ResumeScreenProps) {
  const { width, height } = useTerminalDimensions();

  const [filter, setFilter] = useState("");
  const [filtering, setFilteringState] = useState(false);
  // "project" = only current-cwd sessions; "all" = every session.
  const [scope, setScope] = useState<"project" | "all">("project");
  // The id armed for deletion, or null. A second Delete on this id deletes.
  const [pendingDelete, setPendingDeleteState] = useState<string | null>(null);
  // Action failures remain visible without closing the session browser.
  const [deleteError, setDeleteError] = useState<string | null>(null);
  // Rows deleted successfully this session are hidden immediately.
  const [deleted, setDeleted] = useState<ReadonlySet<string>>(() => new Set());
  // Track the selected session id across filter/list changes.
  const selectedIdRef = useRef<string | null>(null);
  // Mutable ref to avoid stale closures in event handlers (usePaste).
  const pendingDeleteRef = useRef<string | null>(null);
  const filterRef = useRef("");
  const filteringRef = useRef(false);
  const scopeRef = useRef(scope);
  const deletedRef = useRef(deleted);
  const baseSelectedRef = useRef(0);
  const setFiltering = (value: boolean) => {
    filteringRef.current = value;
    setFilteringState(value);
  };
  const setPendingDelete = (id: string | null) => {
    pendingDeleteRef.current = id;
    setPendingDeleteState(id);
  };

  // The console's real working directory. The prop comes from the route
  // via `process.cwd()`, so it is accurate even when no session exists for
  // the current directory yet.
  const currentCwd = propCwd;

  const visibleSessions = useMemo(
    () => sessions.filter((session) => !deleted.has(session.id)),
    [sessions, deleted],
  );

  // Filter to current-cwd sessions when scope is "project".
  const scopedSessions = useMemo(() => {
    if (scope === "project" && currentCwd !== undefined) {
      return visibleSessions.filter(
        (session) => sessionCategory(session, currentCwd) === CATEGORY_THIS,
      );
    }
    return visibleSessions;
  }, [visibleSessions, scope, currentCwd]);

  const items = useMemo<DialogItem[]>(
    () =>
      resumeItems({
        sessions: scopedSessions,
        currentId,
        currentCwd,
        now,
        filter,
      }),
    [scopedSessions, currentId, currentCwd, now, filter],
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

  // Preserve the selected session by identity when items change.
  const [baseSelected, setBaseSelected] = useState(0);
  const selected = useMemo(() => {
    const id = selectedIdRef.current;
    if (id !== null && items.length > 0) {
      const idx = items.findIndex((item) => item.id === id);
      if (idx >= 0) return idx;
    }
    if (baseSelected < items.length) return baseSelected;
    return Math.max(0, items.length - 1);
  }, [items, baseSelected]);
  // The highlighted row can vanish from under the cursor as the filter narrows
  // or a row is deleted, so the rendered cursor is always the clamped one.
  const cursor = clampDialogSelection(items, selected);
  const activeItem = items.length > 0 && cursor >= 0 ? items[cursor] : undefined;

  // Track the active id for identity preservation.
  if (activeItem) selectedIdRef.current = activeItem.id;


  const mode: ResumeMode = pendingDelete ? "confirm-delete" : filtering ? "filter" : "browse";

  // Status/error lines under the list.
  const pendingLabel = pendingDelete
    ? (items.find((item) => item.id === pendingDelete)?.label ?? "this session")
    : "";
  const statusText = pendingDelete
    ? `\uf071 Delete "${pendingLabel}"? press del again to confirm · esc cancel`
    : deleteError
      ? deleteError
      : "";

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

  // Whether other-project sessions exist (for empty-state guidance).
  const hasOtherSessions = useMemo(() => {
    if (!currentCwd) return false;
    return visibleSessions.some(
      (session) => sessionCategory(session, currentCwd) === CATEGORY_OTHER,
    );
  }, [visibleSessions, currentCwd]);

  const currentItems = () => filterRef.current === filter && scopeRef.current === scope && deletedRef.current === deleted
    ? items
    : resumeItems({
      sessions: sessions.filter((session) => !deletedRef.current.has(session.id) &&
        (scopeRef.current === "all" || currentCwd === undefined || sessionCategory(session, currentCwd) === CATEGORY_THIS)),
      currentId,
      currentCwd,
      now,
      filter: filterRef.current,
    });
  const selectedIndex = (visible: DialogItem[]) => {
    const index = visible.findIndex((item) => item.id === selectedIdRef.current);
    return clampDialogSelection(visible, index >= 0 ? index : baseSelectedRef.current);
  };
  const highlight = (visible: DialogItem[], index: number) => {
    const next = clampDialogSelection(visible, index);
    selectedIdRef.current = visible[next]?.id ?? null;
    baseSelectedRef.current = next;
    setBaseSelected(next);
    setPendingDelete(null);
    setDeleteError(null);
  };
  const move = (delta: number) => {
    const visible = currentItems();
    if (visible.length === 0) return;
    const direction = delta >= 0 ? 1 : -1;
    let next = selectedIndex(visible);
    for (let i = 0; i < Math.abs(delta); i++) next = moveDialogSelection(visible, next, direction);
    highlight(visible, next);
  };
  const setQuery = (query: string) => {
    filterRef.current = query;
    setFilter(query);
    selectedIdRef.current = null;
    baseSelectedRef.current = 0;
    setBaseSelected(0);
    setPendingDelete(null);
    setDeleteError(null);
  };
  const armOrDelete = () => {
    const visible = currentItems();
    const item = visible[selectedIndex(visible)];
    if (!item) return;
    setDeleteError(null);
    if (pendingDeleteRef.current !== item.id) {
      setPendingDelete(item.id);
      return;
    }
    setPendingDelete(null);
    if (!onDelete(item.id)) {
      setDeleteError("Failed to delete session — check file permissions");
      return;
    }
    deletedRef.current = new Set(deletedRef.current).add(item.id);
    setDeleted(deletedRef.current);
    selectedIdRef.current = null;
  };

  useKeyboard((key) => {
    const sequence = typeof key.sequence === "string" ? key.sequence : "";
    if (key.ctrl && key.name === "c") return onExit();
    if (key.ctrl && key.name === "u") {
      setQuery("");
      setFiltering(false);
      return;
    }
    if (key.ctrl || key.meta || key.option) return;
    if (key.name === "escape") {
      if (pendingDeleteRef.current) setPendingDelete(null);
      else if (filteringRef.current || filterRef.current) {
        setFiltering(false);
        setQuery("");
      } else onBack();
      return;
    }
    if (key.name === "up") return move(-1);
    if (key.name === "down") return move(1);
    if (key.name === "pageup") return move(-PAGE_STEP);
    if (key.name === "pagedown") return move(PAGE_STEP);
    if (key.name === "home") return highlight(currentItems(), 0);
    if (key.name === "end") {
      const visible = currentItems();
      return highlight(visible, visible.length - 1);
    }
    if (key.name === "tab") {
      setPendingDelete(null);
      setDeleteError(null);
      scopeRef.current = scopeRef.current === "project" ? "all" : "project";
      setScope(scopeRef.current);
      return;
    }
    if (key.name === "delete") return armOrDelete();
    if (key.name === "return") {
      if (pendingDeleteRef.current) return;
      const visible = currentItems();
      const item = visible[selectedIndex(visible)];
      if (item && !onResume(item.id)) setDeleteError("Could not load session — choose another saved conversation");
      return;
    }
    if (key.name === "backspace") {
      setQuery(Array.from(filterRef.current).slice(0, -1).join(""));
      return;
    }
    if (!filteringRef.current && sequence === "/") {
      setFiltering(true);
      setQuery("");
      return;
    }
    if (isFilterKey(sequence)) {
      setFiltering(true);
      setQuery(filterRef.current + sequence);
    }
  });

  // Pasted text: decode the raw bytes, sanitize, and append to the filter.
  // Respect pending confirmations — do not start a filter if a delete is armed.
  usePaste((event) => {
    const text = sanitizeTuiText(decodePasteBytes(event.bytes));
    if (!text) return;
    if (pendingDeleteRef.current) return;
    setFiltering(true);
    setQuery(filterRef.current + text);
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

  // Empty-state guidance text, context-aware.
  const totalAll = visibleSessions.length;
  const emptyText = (() => {
    if (filter) return "\uf002 no sessions match this filter";
    if (scopedSessions.length === 0 && scope === "project" && hasOtherSessions && totalAll > 0) {
      return '\uf115 no sessions in this project — press Tab to browse all';
    }
    if (totalAll === 0 && filter.length === 0) return "\u{f0051} no saved sessions to resume";
    return "\uf002 no sessions to show";
  })();

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <DialogSelectBody
        items={items}
        cursor={cursor}
        panel={panel}
        query={filter}
        placeholder={"\uf002 type to filter sessions"}
        gutter={items.some((item) => item.current === true)}
        isCurrent={(item) => item.current === true}
        renderDetail={renderDetail}
        emptyText={emptyText}
      />
      {statusText ? (
        <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
          <Cells width={contentWidth} fg={pendingDelete ? theme.WARNING : theme.ERROR}>
            {statusText}
          </Cells>
        </box>
      ) : null}
      <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
        <Cells width={contentWidth} fg={theme.MUTED}>
          {resumeFooterHint(mode, filter.length > 0, items.length > 0, scope, scopedSessions.length)}
        </Cells>
      </box>
    </box>
  );

  return <>{body}</>;
}
