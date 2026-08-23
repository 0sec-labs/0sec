/** @jsxImportSource @opentui/react */
import React from "react";
import { TextAttributes } from "@opentui/core";
import type { TodosEventPayload, TodoStatus } from "@0sec/core";
import { fitTuiText } from "../text.js";
import type { Theme } from "../theme-context.js";
import { budgetSidebarRows, todoTextWidth } from "./todos-sidebar-layout.js";

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
        const heading = view.group ? `${phaseNumeral((phaseIndex += 1))}. ${view.group}` : "";
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
              const textColor = done ? MUTED : active ? TEXT : MUTED;
              return (
                <box key={item.id} flexDirection="row" minWidth={0}>
                  <box width={2} flexShrink={0} minWidth={0}>
                    <text fg={glyphColor}>{glyph}</text>
                  </box>
                  <box flexGrow={1} minWidth={0}>
                    <text fg={textColor}>{fitTuiText(item.content, Math.max(1, width - 2))}</text>
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

/**
 * The RIGHT-sidebar variant of the plan: a compact section that sits beneath
 * the AGENTS / FINDINGS sections in the same narrow column and reads as their
 * sibling. A muted `PLAN done/total` header, then each todo as ONE fitted row —
 * a status glyph + text truncated with `fitTuiText` so it can never wrap or
 * overflow the column. The in-progress item wears the accent tone; completed is
 * a muted check; pending a muted dot. Visible rows are bounded by `rows` via
 * {@link budgetSidebarRows}, with the remainder folded into a "+N more" tail, so
 * the plan can never grow unbounded in the sidebar.
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

  const itemRows = Math.max(0, rows - TODOS_SIDEBAR_HEADER_ROWS);
  const { visible, overflow } = budgetSidebarRows(payload.todos.length, itemRows);
  const shown = payload.todos.slice(0, visible);
  const textCells = todoTextWidth(width);

  return (
    <box flexDirection="column" flexShrink={0} minWidth={0} marginTop={1}>
      <box width={width} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{fitTuiText(`PLAN ${payload.done}/${payload.total}`, width)}</text>
      </box>
      {shown.map((item) => {
        const glyph = SIDEBAR_STATUS_GLYPH[item.status] ?? SIDEBAR_STATUS_GLYPH.pending;
        const done = item.status === "completed";
        const active = item.status === "in_progress";
        const glyphColor = done ? SUCCESS : active ? ACCENT : MUTED;
        const textColor = active ? TEXT : MUTED;
        return (
          <box key={item.id} flexDirection="row" width={width} flexShrink={0} minWidth={0}>
            <text width={1} flexShrink={0} fg={glyphColor}>{glyph}</text>
            <box width={textCells} flexShrink={0} minWidth={0} marginLeft={1}>
              <text fg={textColor} attributes={active ? TextAttributes.BOLD : undefined}>
                {fitTuiText(item.content, textCells)}
              </text>
            </box>
          </box>
        );
      })}
      {overflow > 0 ? (
        <box width={width} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(`+${overflow} more`, width)}</text>
        </box>
      ) : null}
    </box>
  );
}
