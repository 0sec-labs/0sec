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
   * What the agent is doing right now, distinct from its assigned `task`.
   * Shown alongside task when space permits; never hides the task.
   */
  activity?: string;
  /**
   * Monotonically advancing frame counter for animated glyphs.
   * Only a "running" status animates (spinner cycle); undefined or
   * non-running statuses stay static (reduceMotion / truthful display).
   */
  animationFrame?: number;
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

/**
 * Bullet glyph + colour for a lifecycle status. Only "running" animates with
 * the provided `animationFrame` (a quarter-block spinner). Failed keeps red
 * "×", completed "✓", parked "◌", and everything else (queued, idle, done,
 * stale) stays "·" — no pretend activity after settlement.
 */
function statusMark(status: string, theme: Theme, animationFrame?: number): { glyph: string; color: string } {
  if (status === "failed") return { glyph: "×", color: theme.ERROR };
  if (status === "completed") return { glyph: "✓", color: theme.SUCCESS };
  if (status === "running") {
    if (typeof animationFrame === "number") {
      const spinners = ["▖", "▘", "▝", "▗"];
      return { glyph: spinners[animationFrame % spinners.length], color: theme.ACCENT };
    }
    // Static fallback when reduceMotion (no frame supplied).
    return { glyph: "▶", color: theme.ACCENT };
  }
  // Parked: finished its task but still alive, ready to be revived.
  if (status === "parked") return { glyph: "◌", color: theme.MUTED };
  // queued / idle / done / stale → static muted dot, no animation.
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
  onSelect,
}: {
  view: AgentRowView;
  width: number;
  theme: Theme;
  selected: boolean;
  isLast: boolean;
  onSelect?: () => void;
}) {
  const { MUTED, ACCENT, PANEL_ALT } = theme;
  const mark = statusMark(view.status, theme, view.animationFrame);
  const bg = selected ? PANEL_ALT : undefined;
  const meta = view.meta ?? "";
  // Bound meta to at most 30% of row width so the name column is never eaten.
  const maxMeta = Math.max(0, Math.floor(width * 0.3));
  const metaCells = Math.min(meta.length, maxMeta);
  // connector(2) + gap(1) + bullet(1) + gap(1) + [name + task] + [gap + meta].
  const reserved = 2 + 1 + 1 + 1 + (metaCells > 0 ? metaCells + 1 : 0);
  const bodyWidth = Math.max(1, width - reserved);
  const nameCells = Math.min(view.name.length, Math.max(4, Math.floor(bodyWidth * 0.45)));
  const taskCells = Math.max(0, bodyWidth - nameCells);
  const connector = selected ? "▸ " : isLast ? "└─" : "├─";
  const nameFg = view.accent ?? ACCENT;

  // Build task label: append activity only when the agent is actively working.
  // Completed/failed/parked keep the activity field out of the task display so
  // an old tool is never presented as current work.
  const isActive = view.status === "running" || view.status === "queued" || view.status === "working" || view.status === "idle";
  const taskLabel = isActive && view.activity
    ? `${view.activity} · ${view.task}`
    : view.task;

  return (
    <box
      flexDirection="row"
      width={width}
      flexShrink={0}
      minWidth={0}
      backgroundColor={bg}
      onMouseDown={onSelect ? (() => onSelect()) : undefined}
    >
      <text width={2} flexShrink={0} fg={selected ? ACCENT : MUTED} bg={bg}>{connector}</text>
      <text width={1} flexShrink={0} marginLeft={1} fg={mark.color} bg={bg}>{mark.glyph}</text>
      <box width={nameCells} flexShrink={0} minWidth={0} marginLeft={1} backgroundColor={bg}>
        <text width={nameCells} height={1} wrapMode="none" truncate fg={nameFg} attributes={TextAttributes.BOLD} bg={bg}>{fitTuiText(view.name, nameCells)}</text>
      </box>
      {taskCells > 0 ? (
        <box width={taskCells} flexShrink={0} minWidth={0} backgroundColor={bg}>
          <text width={taskCells} height={1} wrapMode="none" truncate fg={MUTED} bg={bg}>{fitTuiText(`: ${taskLabel}`, taskCells)}</text>
        </box>
      ) : null}
      {metaCells > 0 ? (
        <box width={metaCells} flexShrink={0} minWidth={0} marginLeft={1} backgroundColor={bg}>
          <text width={metaCells} height={1} wrapMode="none" truncate fg={MUTED} bg={bg}>{fitTuiText(meta, metaCells)}</text>
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
  onSelect,
}: {
  view: AgentRowView;
  width: number;
  theme: Theme;
  selected: boolean;
  onSelect?: () => void;
}) {
  const { MUTED, ACCENT, PANEL_ALT } = theme;
  const mark = statusMark(view.status, theme, view.animationFrame);
  const bg = selected ? PANEL_ALT : undefined;
  const meta = view.meta ?? "";
  // Bound meta to at most 30% of row width so the name column is never eaten.
  const maxMeta = Math.max(0, Math.floor(width * 0.3));
  const metaCells = Math.min(meta.length, maxMeta);
  const nameCells = Math.max(1, width - 2 - (metaCells > 0 ? metaCells + 1 : 0));
  const taskCells = Math.max(1, width - 2);
  const nameFg = view.accent ?? ACCENT;

  // Build task label: only show activity for actively-working statuses so a
  // completed/failed/parked agent's old tool is never presented as current work.
  const isActive = view.status === "running" || view.status === "queued" || view.status === "working" || view.status === "idle";
  const taskLabel = isActive && view.activity
    ? `${view.activity} · ${view.task}`
    : view.task;

  return (
    <box
      flexDirection="column"
      width={width}
      flexShrink={0}
      minWidth={0}
      backgroundColor={bg}
      onMouseDown={onSelect ? (() => onSelect()) : undefined}
    >
      <box flexDirection="row" width={width} flexShrink={0} minWidth={0}>
        <text width={1} flexShrink={0} fg={selected ? ACCENT : mark.color} bg={bg}>{selected ? "▸" : mark.glyph}</text>
        <box width={nameCells} flexShrink={0} minWidth={0} marginLeft={1} backgroundColor={bg}>
          <text width={nameCells} height={1} wrapMode="none" truncate fg={nameFg} attributes={TextAttributes.BOLD} bg={bg}>{fitTuiText(view.name, nameCells)}</text>
        </box>
        {metaCells > 0 ? (
          <box width={metaCells} flexShrink={0} minWidth={0} marginLeft={1} backgroundColor={bg}>
            <text width={metaCells} height={1} wrapMode="none" truncate fg={MUTED} bg={bg}>{fitTuiText(meta, metaCells)}</text>
          </box>
        ) : null}
      </box>
      <box flexDirection="row" width={width} flexShrink={0} minWidth={0}>
        <box width={taskCells} flexShrink={0} minWidth={0} marginLeft={2} backgroundColor={bg}>
          <text width={taskCells} height={1} wrapMode="none" truncate fg={MUTED} bg={bg}>{fitTuiText(taskLabel, taskCells)}</text>
        </box>
      </box>
    </box>
  );
}
