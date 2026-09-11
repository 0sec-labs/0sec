/** @jsxImportSource @opentui/react */
import React from "react";
import { TextAttributes } from "@opentui/core";
import type { TodosEventPayload, TodoStatus } from "@0sec/core";
import { fitTuiText } from "../text.js";
import type { Theme } from "../theme-context.js";
import {
  budgetWrappedRows,
  todoTextWidth,
  wrapCells,
  DEFAULT_WRAP_LINES,
  sidebarItemPriority,
  buildSidebarOverflowText,
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
                      {fitTuiText(item.content, Math.max(1, width - 2))}
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
 * Items are sorted by status priority (in_progress first, then pending, then
 * completed, preserving original order within each tier). Phase/group labels
 * are inserted as separate rows before the first item of each new named group,
 * so context is visible without reading the transcript.
 */
function buildSidebarRows(payload: TodosEventPayload, textCells: number): SidebarDisplayRow[] {
  // Priority sort: active → pending → completed
  const sorted = [...payload.todos].sort((a, b) => {
    const pa = sidebarItemPriority(a.status);
    const pb = sidebarItemPriority(b.status);
    return pa - pb;
  });

  const rows: SidebarDisplayRow[] = [];
  let prevGroup = "";

  for (const item of sorted) {
    const group = item.group ?? "";
    if (group && group !== prevGroup) {
      rows.push({ kind: "group", label: group });
    }
    rows.push({
      kind: "item",
      item,
      lines: wrapCells(item.content, textCells, DEFAULT_WRAP_LINES),
    });
    prevGroup = group;
  }

  return rows;
}

/**
 * The RIGHT-sidebar variant of the plan: a compact section that prioritises
 * active/current work over completed items while preserving phase context.
 *
 * Items are sorted by status priority so in-progress work is always visible
 * before pending or completed items, even when earlier phases dominate the
 * declared order. Phase/group labels appear as compact muted headings before
 * the first item of each named group, so an operator can see which phase the
 * current work belongs to.
 *
 * The section header reflects the honest status composition:
 *   - Active items present: "PLAN ● 1 active · 3/5" (compact if tight)
 *   - All completed:        "PLAN ● 5/5" header + "● All 5 tasks completed"
 *   - Normal:               "PLAN 3/5"
 *
 * The overflow tail describes hidden items by status rather than a bare count:
 *   "+3 remaining", "+2 remaining, 1 done", "+2 done"
 *
 * `rows` is the WHOLE section's row budget (header included). `width` is the
 * sidebar's inner content width (`sidebars.rightInnerWidth`). Renders nothing
 * when the plan is empty or the budget leaves no room for the header.
 */
export function TodosSidebar({
  payload,
  width,
  rows,
  theme,
}: {
  payload: TodosEventPayload;
  width: number;
  rows: number;
  theme: Theme;
}) {
  const { MUTED, TEXT, ACCENT, SUCCESS } = theme;
  if (payload.total <= 0) return null;
  if (rows < TODOS_SIDEBAR_HEADER_ROWS + 1) return null;
  const { done, total } = payload;

  const itemRows = Math.max(0, rows - TODOS_SIDEBAR_HEADER_ROWS);

  // ── All completed: compact summary, no item listing ──────────────────────
  if (done === total && total > 0) {
    return (
      <box flexDirection="column" flexShrink={0} minWidth={0} marginTop={1}>
        <box width={width} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{buildSidebarHeader(done, total, width)}</text>
        </box>
        <box width={width} flexShrink={0} minWidth={0}>
          <text fg={SUCCESS}>
            {fitTuiText(`● All ${total} tasks completed`, width)}
          </text>
        </box>
      </box>
    );
  }

  // ── Build priority-ordered rows with phase labels ────────────────────────
  const textCells = todoTextWidth(width);
  let displayRows = buildSidebarRows(payload, textCells);

  // Cost array: group labels = 1 row, items = wrapped line count
  const costs = displayRows.map((r) => (r.kind === "group" ? 1 : (r.lines?.length ?? 1)));
  const { visible } = budgetWrappedRows(costs, itemRows);
  let visibleDisplayRows = displayRows.slice(0, visible);

  // Trim orphan phase headings: never show a group label without at least
  // its first item — a bare heading wastes the budget and hides work.
  while (visibleDisplayRows.length > 0 &&
         visibleDisplayRows[visibleDisplayRows.length - 1].kind === "group") {
    visibleDisplayRows.pop();
  }
  // Under pressure, spend scarce rows on the active task rather than its phase.
  if (!visibleDisplayRows.some((row) => row.kind === "item")) {
    displayRows = displayRows.filter((row) => row.kind === "item");
    const compact = budgetWrappedRows(displayRows.map((row) => row.lines!.length), itemRows);
    visibleDisplayRows = displayRows.slice(0, compact.visible);

  }

  // ── Overflow text from hidden ITEMS only ─────────────────────────────────
  const visibleItems = visibleDisplayRows.filter((r) => r.kind === "item").length;
  const hiddenItems: Array<{ status: string }> = [];
  let itemsSeen = 0;
  for (const row of displayRows) {
    if (row.kind === "item") {
      if (itemsSeen >= visibleItems) {
        hiddenItems.push({ status: row.item!.status });
      }
      itemsSeen++;
    }
  }
  const overflowText =
    hiddenItems.length > 0
      ? buildSidebarOverflowText(hiddenItems, width)
      : "";

  return (
    <box flexDirection="column" flexShrink={0} minWidth={0} marginTop={1}>
      <box width={width} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{buildSidebarHeader(done, total, width)}</text>
      </box>
      {visibleDisplayRows.map((row, rowIdx) => {
        if (row.kind === "group") {
          return (
            <box key={`phase-${rowIdx}`} flexDirection="row" width={width} flexShrink={0} minWidth={0}>
              <text width={1} flexShrink={0}>
                {" "}
              </text>
              <text fg={MUTED}>
                {fitTuiText(row.label ?? "", textCells)}
              </text>
            </box>
          );
        }
        // Item row
        const item = row.item!;
        const glyph = SIDEBAR_STATUS_GLYPH[item.status] ?? SIDEBAR_STATUS_GLYPH.pending;
        const itemDone = item.status === "completed";
        const itemActive = item.status === "in_progress";
        const glyphColor = itemDone ? SUCCESS : itemActive ? ACCENT : MUTED;
        const textColor = itemDone ? SUCCESS : itemActive ? TEXT : MUTED;
        const lines = row.lines!;
        return (
          <box key={item.id} flexDirection="column" width={width} flexShrink={0} minWidth={0}>
            {lines.map((line, lineIdx) => (
              <box
                key={lineIdx}
                flexDirection="row"
                width={width}
                flexShrink={0}
                minWidth={0}
              >
                <text width={1} flexShrink={0} fg={glyphColor}>
                  {lineIdx === 0 ? glyph : " "}
                </text>
                <box width={textCells} flexShrink={0} minWidth={0} marginLeft={1}>
                  <text
                    fg={textColor}
                    attributes={
                      itemDone
                        ? TextAttributes.STRIKETHROUGH
                        : itemActive
                          ? TextAttributes.BOLD
                          : undefined
                    }
                  >
                    {line}
                  </text>
                </box>
              </box>
            ))}
          </box>
        );
      })}
      {overflowText ? (
        <box width={width} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{overflowText}</text>
        </box>
      ) : null}
    </box>
  );
}
