/** @jsxImportSource @opentui/react */
import React, { useState } from "react";
import { TextAttributes } from "@opentui/core";
import type { TodosEventPayload, TodoStatus } from "@0sec/core";
import { fitTuiText } from "../text.js";
import type { Theme } from "../theme-context.js";
import {
  todoTextWidth,
  wrapCells,
  DEFAULT_WRAP_LINES,
  sidebarItemPriority,
  buildSidebarHeader,
} from "./todos-sidebar-layout.js";

/**
 * The live plan tree from the `update_todos` tool (the `todos` bus event). It
 * renders as a compact checklist: a `Todos · done/total` header, then each
 * declared GROUP as a phase (I./II./III. …) with its items beneath, a checkbox
 * glyph per status. Ungrouped items render flush under the header with no phase
 * heading. Everything is fitted to the transcript width so no row overflows, and
 * the whole block lives inside the scrolling transcript column, so a long plan
 * scrolls rather than squeezing the surface.
 *
 * The glyphs: ☐ pending, ◐ in-progress, ☑ completed — the same "empty / half /
 * full" reading the operator already knows from the herd views.
 */

const STATUS_GLYPH: Record<TodoStatus, string> = {
  pending: "☐",
  in_progress: "◐",
  completed: "☑",
};

/** Roman numerals for the first handful of phases; falls back to arabic. */
const ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"];
function phaseNumeral(index: number): string {
  return ROMAN[index] ?? String(index + 1);
}

interface TodoGroupView {
  group: string;
  items: TodosEventPayload["todos"];
}

/** Bucket the flat todo list into groups, preserving declared order. */
function groupTodos(todos: TodosEventPayload["todos"]): TodoGroupView[] {
  const order: string[] = [];
  const byGroup = new Map<string, TodosEventPayload["todos"]>();
  for (const item of todos) {
    const key = item.group ?? "";
    if (!byGroup.has(key)) {
      byGroup.set(key, []);
      order.push(key);
    }
    byGroup.get(key)!.push(item);
  }
  return order.map((group) => ({ group, items: byGroup.get(group)! }));
}

export function Todos({
  payload,
  width,
  theme,
}: {
  payload: TodosEventPayload;
  width: number;
  theme: Theme;
}) {
  const { MUTED, TEXT, ACCENT, SUCCESS, PRIMARY } = theme;
  if (payload.total <= 0) return null;
  const groups = groupTodos(payload.todos);
  const header = payload.line || `Todos · ${payload.done}/${payload.total}`;
  // A phase heading is only drawn for a real (non-empty) group name; index is
  // tracked separately so the numerals stay contiguous across named phases.
  let phaseIndex = -1;
  return (
    <box flexDirection="column" minWidth={0} marginTop={1}>
      <text fg={PRIMARY}>{fitTuiText(header, Math.max(1, width))}</text>
      {groups.map((view, groupIdx) => {
        const groupDone = view.items.filter((i) => i.status === "completed").length;
        const groupTotal = view.items.length;
        const groupProgress =
          groupTotal > 0 && groupDone > 0 ? ` (${groupDone}/${groupTotal})` : "";
        const heading = view.group
          ? `${phaseNumeral((phaseIndex += 1))}. ${view.group}${groupProgress}`
          : "";
        return (
          <box key={`todo-group-${groupIdx}`} flexDirection="column" minWidth={0}>
            {heading ? (
              <text fg={ACCENT} marginTop={groupIdx > 0 ? 1 : 0}>
                {fitTuiText(heading, Math.max(1, width))}
              </text>
            ) : null}
            {view.items.map((item) => {
              const glyph = STATUS_GLYPH[item.status] ?? STATUS_GLYPH.pending;
              const done = item.status === "completed";
              const active = item.status === "in_progress";
              const glyphColor = done ? SUCCESS : active ? ACCENT : MUTED;
              // Completed items read as "done" at a glance: the WHOLE row goes
              // green and is struck through (glyph + text), the way a checked-off
              // checklist reads. Active is the accent tone; pending stays muted.
              const textColor = done ? SUCCESS : active ? TEXT : MUTED;
              return (
                <box key={item.id} flexDirection="row" minWidth={0}>
                  <box width={2} flexShrink={0} minWidth={0}>
                    <text fg={glyphColor}>{glyph}</text>
                  </box>
                  <box flexGrow={1} minWidth={0}>
                    <text
                      fg={textColor}
                      attributes={done ? TextAttributes.STRIKETHROUGH : undefined}
                    >
                      {item.content}
                    </text>
                  </box>
                </box>
              );
            })}
          </box>
        );
      })}
    </box>
  );
}

/**
 * Narrow, one-line-per-item glyphs for the sidebar variant. Unlike the panel's
 * ☐/◐/☑ checkboxes, the sidebar reads as a sibling of the AGENTS/FINDINGS
 * sections: a muted dot for pending, an accent half-circle for the active item,
 * a muted check for done — the "empty / active / done" reading in one cell.
 */
const SIDEBAR_STATUS_GLYPH: Record<TodoStatus, string> = {
  pending: "·",
  in_progress: "◐",
  completed: "✓",
};

/** Rows the sidebar section spends on its header (the "PLAN done/total" line). */
export const TODOS_SIDEBAR_HEADER_ROWS = 1;

// ── Sidebar display-row model ────────────────────────────────────────────────

/** A row the sidebar paints: either a phase/group label, or one todo item. */
interface SidebarDisplayRow {
  kind: "group" | "item";
  /** `"group"` → the group label. */
  label?: string;
  /** `"item"` → the item data. */
  item?: TodosEventPayload["todos"][number];
  /** `"item"` → pre-wrapped text lines. */
  lines?: string[];
}

/**
 * Build the sidebar's ordered display-row array from the flat payload.
 * Items are sorted within each declared group by status priority
 * (in_progress first, then pending, then completed, preserving original order
 * within each tier). Phase/group labels are inserted as separate rows before
 * the first item of each named group, so context is visible without reading
 * the transcript and phase labels are never lost when prioritizing active work.
 */
function buildSidebarRows(
  payload: TodosEventPayload,
  textCells: number,
  maxLines: number = DEFAULT_WRAP_LINES,
): SidebarDisplayRow[] {
  const groups = groupTodos(payload.todos);
  const rows: SidebarDisplayRow[] = [];

  for (const { group, items } of groups) {
    // Sort items within this group: active → pending → completed
    const sorted = [...items].sort(
      (a, b) => sidebarItemPriority(a.status) - sidebarItemPriority(b.status),
    );
    if (group) {
      rows.push({ kind: "group", label: group });
    }
    for (const item of sorted) {
      rows.push({
        kind: "item",
        item,
        lines: wrapCells(item.content, textCells, maxLines),
      });
    }
  }

  return rows;
}

/**
 * The RIGHT-sidebar variant of the plan: a compact section that preserves
 * declared phase-group order so the tree structure is readable at a glance.
 * Within each phase, items are sorted by status priority so in-progress work
 * is always visible before pending or completed items. Phase/group labels
 * appear as compact muted headings before the first item of each named group.
 *
 * The section header reflects the honest status composition:
 *   - All completed:        "PLAN ● 5/5" header + "● All 5 tasks completed"
 *   - Normal:               "PLAN 3/5"
 *
 * The collapsed overflow tail describes hidden items by status rather than a
 * bare count: "+3 remaining", "+2 remaining, 1 done", "+2 done"
 *
 * Accepts optional `expanded`/`onToggle` for parent-driven expansion. When no
 * parent wiring is provided, uses internal disclosure state — the sidebar
 * starts collapsed and the toggle indicator replaces the overflow summary.
 *
 * Expanded mode shows EVERY item with full-text wrapping inside a scrollbox,
 * so all declared work is reachable without overflowing the sidebar boundary.
 *
 * `rows` is the WHOLE section's row budget (header included). `width` is the
 * sidebar's inner content width (`sidebars.rightInnerWidth`). Renders nothing
 * when the plan is empty or the budget leaves no room for the header.
 */
export function TodosSidebar({
  payload, width, rows, theme, expanded: expandedProp, onToggle,
}: {
  payload: TodosEventPayload;
  width: number;
  rows: number;
  theme: Theme;
  expanded?: boolean;
  onToggle?: (expanded: boolean) => void;
}) {
  const [internalExpanded, setInternalExpanded] = useState(false);
  const expanded = expandedProp ?? internalExpanded;
  const toggle = () => onToggle ? onToggle(!expanded) : setInternalExpanded(!expanded);
  if (payload.total <= 0 || rows < 3) return null;
  const bodyWidth = Math.max(3, width - (expanded ? 1 : 0));
  const textCells = todoTextWidth(bodyWidth);
  const allRows = buildSidebarRows(payload, textCells, expanded ? Number.MAX_SAFE_INTEGER : DEFAULT_WRAP_LINES)
    .flatMap((row) => row.kind === "group"
      ? [{ key: `phase-${row.label}`, text: row.label ?? "", glyph: "", color: theme.ACCENT }]
      : (row.lines ?? []).map((text, index) => ({
          key: `${row.item!.id}-${index}`, text,
          glyph: index === 0 ? SIDEBAR_STATUS_GLYPH[row.item!.status] : "",
          color: row.item!.status === "completed" ? theme.SUCCESS : row.item!.status === "in_progress" ? theme.TEXT : theme.MUTED,
        })));
  const capacity = Math.max(1, rows - 2);
  const visible = expanded ? allRows : allRows.slice(0, capacity);
  const body = visible.map((row) => (
    <box key={row.key} flexDirection="row" width={bodyWidth} flexShrink={0}>
      <text width={2} flexShrink={0} fg={row.color}>{row.glyph}</text>
      <text width={textCells} flexShrink={0} fg={row.color}>{row.text}</text>
    </box>
  ));
  return (
    <box flexDirection="column" width={width} flexShrink={0} marginTop={1}>
      <box width={width} flexShrink={0} onMouseDown={toggle}>
        <text fg={theme.ACCENT}>{fitTuiText(`${expanded ? "▾" : "▸"} ${buildSidebarHeader(payload.done, payload.total, Math.max(1, width - 2))}`, width)}</text>
      </box>
      {expanded
        ? <scrollbox width={width} height={capacity} flexShrink={0} scrollX={false}><box width={bodyWidth} flexDirection="column" flexShrink={0}>{body}</box></scrollbox>
        : body}
      <text fg={theme.MUTED}>{fitTuiText(expanded ? "scroll · click PLAN to collapse" : allRows.length > visible.length ? `+${allRows.length - visible.length} lines · click PLAN to expand` : "click PLAN to expand", width)}</text>
    </box>
  );
}
