/** @jsxImportSource @opentui/react */
import React from "react";
import { TextAttributes } from "@opentui/core";
import type { Theme } from "../theme-context.js";
import { fitTuiText } from "../text.js";

/**
 * ONE agent-row look, shared by the inline ACTIVE SUBAGENTS list below the
 * composer and the RIGHT sidebar's fleet view, so the herd reads identically
 * wherever it appears. The two callers hold different records (the inline list
 * a `SubagentLifecyclePayload`, the sidebar a `HerdSubagentRecord`); each
 * normalises into this flat view so neither reimplements the styling.
 *
 * The visual hierarchy mirrors oh-my-posh's segment lists: a small status
 * bullet, a BOLD accent NAME, then the muted task. Red is spent ONLY on a
 * failed row's glyph — never on a label — so the "red = errors/findings"
 * invariant holds. Selection is an obvious full-width highlight BAR (a
 * PANEL_ALT background across the row) plus a leading accent marker, not a
 * subtle weight change.
 */
export interface AgentRowView {
  id: string;
  /** Short, bold-rendered identifier for the agent. */
  name: string;
  /** One-line task/description, rendered muted and truncated to fit. */
  task: string;
  /** Lifecycle status; drives the bullet glyph and its colour. */
  status: string;
  /** Optional right-aligned meta, e.g. "3/8" or "3/8 · 1f". */
  meta?: string;
  /**
   * Stable per-agent accent colour (from `agentAccent(id)`), used for the NAME so
   * the same agent reads in the same hue here and in the inter-agent chat log.
   * Falls back to the theme ACCENT when absent.
   */
  accent?: string;
}

/**
 * A short, bold-able name from an agent id. Strips the common `agent-` /
 * `subagent-` / `console-` prefixes, collapses a uuid-ish tail to its first
 * few hex digits, and caps the length so a long id cannot blow the column.
 */
export function shortAgentName(id: string): string {
  let n = (id ?? "").trim();
  n = n.replace(/^(agent|subagent|console)[-_]+/i, "");
  const uuid = n.match(/^([0-9a-f]{4,8})[-0-9a-f]*$/i);
  if (uuid?.[1]) n = uuid[1].slice(0, 6);
  if (n.length > 16) n = `${n.slice(0, 15)}…`;
  return n || "agent";
}

/** Bullet glyph + colour for a lifecycle status. Failures keep a red "×". */
function statusMark(status: string, theme: Theme): { glyph: string; color: string } {
  if (status === "failed") return { glyph: "×", color: theme.ERROR };
  if (status === "completed") return { glyph: "·", color: theme.SUCCESS };
  if (status === "running") return { glyph: "·", color: theme.ACCENT };
  return { glyph: "·", color: theme.MUTED };
}

/**
 * The inline (below-composer) variant: a single tree row with a left connector
 * (`├─`, `└─` for the last), then `bullet name: task` and optional right meta.
 * When selected the connector is replaced by an accent `▸` marker and the whole
 * row wears a highlight bar. All widths are explicit and sum to `width`, so the
 * row can never overflow or fuse (the chat-layout row invariant).
 */
export function AgentTreeRow({
  view,
  width,
  theme,
  selected,
  isLast,
}: {
  view: AgentRowView;
  width: number;
  theme: Theme;
  selected: boolean;
  isLast: boolean;
}) {
  const { MUTED, ACCENT, PANEL_ALT } = theme;
  const mark = statusMark(view.status, theme);
  const bg = selected ? PANEL_ALT : undefined;
  const meta = view.meta ?? "";
  const metaCells = meta.length;
  // connector(2) + gap(1) + bullet(1) + gap(1) + [name + task] + [gap + meta].
  const reserved = 2 + 1 + 1 + 1 + (metaCells > 0 ? metaCells + 1 : 0);
  const bodyWidth = Math.max(1, width - reserved);
  const nameCells = Math.min(view.name.length, Math.max(4, Math.floor(bodyWidth * 0.45)));
  const taskCells = Math.max(0, bodyWidth - nameCells);
  const connector = selected ? "▸ " : isLast ? "└─" : "├─";
  const nameFg = view.accent ?? ACCENT;
  return (
    <box flexDirection="row" width={width} flexShrink={0} minWidth={0} backgroundColor={bg}>
      <text width={2} flexShrink={0} fg={selected ? ACCENT : MUTED} bg={bg}>{connector}</text>
      <text width={1} flexShrink={0} marginLeft={1} fg={mark.color} bg={bg}>{mark.glyph}</text>
      <box width={nameCells} flexShrink={0} minWidth={0} marginLeft={1} backgroundColor={bg}>
        <text fg={nameFg} attributes={TextAttributes.BOLD} bg={bg}>{fitTuiText(view.name, nameCells)}</text>
      </box>
      {taskCells > 0 ? (
        <box width={taskCells} flexShrink={0} minWidth={0} backgroundColor={bg}>
          <text fg={MUTED} bg={bg}>{fitTuiText(`: ${view.task}`, taskCells)}</text>
        </box>
      ) : null}
      {metaCells > 0 ? (
        <box width={metaCells} flexShrink={0} minWidth={0} marginLeft={1} backgroundColor={bg}>
          <text fg={MUTED} bg={bg}>{meta}</text>
        </box>
      ) : null}
    </box>
  );
}

/** Rows the sidebar variant paints per agent (a name line + a task line). */
export const AGENT_SIDEBAR_ROWS = 2;

/**
 * The sidebar variant: two lines in a narrow column — `bullet name  meta` over
 * an indented, muted, truncated task — so the connectors are dropped for space
 * but the bold-name / muted-task hierarchy and the selection bar are identical
 * to the inline row. Widths are explicit and sum to `width` on each line.
 */
export function AgentSidebarRow({
  view,
  width,
  theme,
  selected,
}: {
  view: AgentRowView;
  width: number;
  theme: Theme;
  selected: boolean;
}) {
  const { MUTED, ACCENT, PANEL_ALT } = theme;
  const mark = statusMark(view.status, theme);
  const bg = selected ? PANEL_ALT : undefined;
  const meta = view.meta ?? "";
  const metaCells = meta.length;
  const nameCells = Math.max(1, width - 2 - (metaCells > 0 ? metaCells + 1 : 0));
  const taskCells = Math.max(1, width - 2);
  const nameFg = view.accent ?? ACCENT;
  return (
    <box flexDirection="column" width={width} flexShrink={0} minWidth={0} backgroundColor={bg}>
      <box flexDirection="row" width={width} flexShrink={0} minWidth={0}>
        <text width={1} flexShrink={0} fg={selected ? ACCENT : mark.color} bg={bg}>{selected ? "▸" : mark.glyph}</text>
        <box width={nameCells} flexShrink={0} minWidth={0} marginLeft={1} backgroundColor={bg}>
          <text fg={nameFg} attributes={TextAttributes.BOLD} bg={bg}>{fitTuiText(view.name, nameCells)}</text>
        </box>
        {metaCells > 0 ? (
          <box width={metaCells} flexShrink={0} minWidth={0} marginLeft={1} backgroundColor={bg}>
            <text fg={MUTED} bg={bg}>{meta}</text>
          </box>
        ) : null}
      </box>
      <box flexDirection="row" width={width} flexShrink={0} minWidth={0}>
        <box width={taskCells} flexShrink={0} minWidth={0} marginLeft={2} backgroundColor={bg}>
          <text fg={MUTED} bg={bg}>{fitTuiText(view.task, taskCells)}</text>
        </box>
      </box>
    </box>
  );
}
