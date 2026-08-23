/** @jsxImportSource @opentui/react */
import React from "react";
import type { TodosEventPayload, TodoStatus } from "@0sec/core";
import { fitTuiText } from "../text.js";
import type { Theme } from "../theme-context.js";

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
