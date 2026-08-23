/** @jsxImportSource @opentui/react */
import React from "react";
import { fitTuiText } from "../text.js";
import type { Theme } from "../theme-context.js";
import { severityToneFor } from "../themes.js";
import {
  budgetWrappedRows,
  findingTitleFirstWidth,
  wrapFinding,
  DEFAULT_WRAP_LINES,
  type SidebarFinding,
} from "./findings-sidebar-layout.js";

/**
 * The RIGHT-sidebar variant of this run's findings: a compact section that sits
 * alongside the AGENTS / PLAN sections in the same narrow column and reads as
 * their sibling. A muted `FINDINGS n` header, then each finding as a
 * severity-coloured title WRAPPED across up to two rows (via {@link wrapFinding})
 * so a long title reads in full rather than being clipped — the severity riding
 * as a trailing badge on the first line (coloured by {@link severityToneFor}:
 * red reserved for high/critical, the title itself in TEXT). Each finding is
 * clickable when its persisted id is known: a mouse-down calls `onOpenFinding`,
 * exactly like the inline block it replaces. Visible ITEMS are bounded by `rows`
 * via {@link budgetWrappedRows} — each item costing 1..2 rows — with the
 * remainder folded into a "+N more" tail, so the section can never overflow.
 *
 * `rows` is the WHOLE section's row budget (header included). `width` is the
 * sidebar's inner content width (`sidebars.rightInnerWidth`). Renders the header
 * with a "none yet" line when there are no findings, and nothing at all when the
 * budget leaves no room for even the header.
 */

/** Rows the section spends on its header (the "FINDINGS n" line). */
export const FINDINGS_SIDEBAR_HEADER_ROWS = 1;

export function FindingsSidebar({
  findings,
  width,
  rows,
  theme,
  onOpenFinding,
}: {
  findings: readonly SidebarFinding[];
  width: number;
  rows: number;
  theme: Theme;
  onOpenFinding?: (id: string) => void;
}) {
  const { TEXT, MUTED } = theme;
  if (rows < FINDINGS_SIDEBAR_HEADER_ROWS + 1) return null;

  const header = (
    <box width={width} flexShrink={0} minWidth={0} marginTop={1}>
      <text fg={MUTED}>{fitTuiText(`FINDINGS ${findings.length}`, width)}</text>
    </box>
  );

  if (findings.length === 0) {
    return (
      <box flexDirection="column" flexShrink={0} minWidth={0}>
        {header}
        <box width={width} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText("none yet", width)}</text>
        </box>
      </box>
    );
  }

  const itemRows = Math.max(0, rows - FINDINGS_SIDEBAR_HEADER_ROWS);
  // Wrap every title first so the budgeter knows each finding's true row cost
  // (1..DEFAULT_WRAP_LINES); findings are admitted whole so a title never shows
  // a dangling half. Newest last, so the most recent that fit are shown.
  const wrapped = findings.map((finding) => wrapFinding(finding, width, DEFAULT_WRAP_LINES));
  const { visible, overflow } = budgetWrappedRows(
    wrapped.map((w) => w.rows),
    itemRows,
  );
  const shown = wrapped.slice(Math.max(0, wrapped.length - visible));
  const overflowCount = overflow;

  return (
    <box flexDirection="column" flexShrink={0} minWidth={0}>
      {header}
      {shown.map((entry, index) => {
        const { finding, lines, severityCells } = entry;
        const sevColor = severityToneFor(theme, finding.severity);
        const firstWidth = findingTitleFirstWidth(width, severityCells);
        // Clickable when the persisted id is known: a mouse-down opens the
        // full-screen detail view via `onOpenFinding`. Guarded exactly like the
        // inline block — the handler is simply omitted when there is no id, so
        // keyboard-only operators are unaffected.
        const id = finding.id;
        return (
          <box
            key={`finding-${index}`}
            flexDirection="column"
            width={width}
            flexShrink={0}
            minWidth={0}
            onMouseDown={id && onOpenFinding ? () => onOpenFinding(id) : undefined}
          >
            {lines.map((line, lineIdx) =>
              lineIdx === 0 ? (
                <box key={lineIdx} flexDirection="row" width={width} flexShrink={0} minWidth={0}>
                  <box width={firstWidth} flexShrink={0} minWidth={0}>
                    <text fg={TEXT}>{fitTuiText(line, firstWidth)}</text>
                  </box>
                  {severityCells > 0 ? (
                    <box width={severityCells} flexShrink={0} minWidth={0} marginLeft={1}>
                      <text fg={sevColor}>{fitTuiText(finding.severity, severityCells)}</text>
                    </box>
                  ) : null}
                </box>
              ) : (
                <box key={lineIdx} width={width} flexShrink={0} minWidth={0}>
                  <text fg={TEXT}>{fitTuiText(line, width)}</text>
                </box>
              ),
            )}
          </box>
        );
      })}
      {overflowCount > 0 ? (
        <box width={width} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(`+${overflowCount} more`, width)}</text>
        </box>
      ) : null}
    </box>
  );
}
