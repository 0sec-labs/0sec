/**
 * Row budgeting for the todos/plan section of the RIGHT sidebar.
 *
 * The sidebar is a narrow, fixed-height column shared by the AGENTS and
 * FINDINGS sections; the plan sits beneath them as a sibling section and must
 * never grow unbounded. This module holds the pieces of arithmetic the
 * component would otherwise inline — how many item rows to draw given the rows
 * the section was granted (folding the remainder into a single "+N more" tail),
 * how many cells an item's text may claim, and how an item's text wraps across
 * a small number of rows — so every invariant is a unit test rather than a code
 * review. It mirrors the cap logic already used by the AGENTS / FINDINGS /
 * SESSIONS sections in chat-screen, and the wrap/budget helpers are shared with
 * the FINDINGS sidebar section (see findings-sidebar-layout.ts).
 */

import { sanitizeTuiText, fitTuiText } from "../text.js";

/** Default number of rows a wrapped sidebar item may span. */
export const DEFAULT_WRAP_LINES = 2;

/**
 * Word-wrap `value` to at most `maxLines` rows, each at most `width` cells. The
 * FIRST row is fitted to `firstWidth` (defaults to `width`) so a caller can
 * reserve trailing cells on line one for a glyph or badge; continuation rows
 * use the full `width`. Words that do not fit on an empty line are hard-split.
 * When content remains after `maxLines` rows, the LAST row is ellipsised (via
 * {@link fitTuiText}). Always returns at least one row (possibly `""`), and
 * every returned row is guaranteed ≤ its row's width in cells.
 */
export function wrapCells(
  value: unknown,
  width: number,
  maxLines: number = DEFAULT_WRAP_LINES,
  firstWidth?: number,
): string[] {
  const w = Math.max(1, Math.floor(width));
  const fw = Math.max(1, Math.floor(firstWidth ?? w));
  const maxL = Math.max(1, Math.floor(maxLines));
  const text = sanitizeTuiText(value);
  const lines: string[] = [];
  let rest = text;
  const widthFor = (index: number): number => (index === 0 ? fw : w);

  while (rest.length > 0 && lines.length < maxL) {
    const lw = widthFor(lines.length);
    if (rest.length <= lw) {
      lines.push(rest);
      rest = "";
      break;
    }
    // Prefer breaking on the last space at or before the width boundary so a
    // word is never split unless it is itself wider than the row.
    let breakAt = -1;
    for (let k = Math.min(lw, rest.length - 1); k > 0; k--) {
      if (rest[k] === " ") {
        breakAt = k;
        break;
      }
    }
    if (breakAt > 0) {
      lines.push(rest.slice(0, breakAt));
      rest = rest.slice(breakAt + 1);
    } else {
      // No space to break on within the width → hard-split the long word.
      lines.push(rest.slice(0, lw));
      rest = rest.slice(lw);
    }
  }

  // Content beyond the last drawable row: ellipsise the final row to its width.
  if (rest.length > 0 && lines.length > 0) {
    const idx = lines.length - 1;
    lines[idx] = fitTuiText(`${lines[idx]} ${rest}`, widthFor(idx));
  }
  if (lines.length === 0) lines.push("");
  return lines;
}

export interface SidebarRowBudget {
  /** How many items to render as full rows. */
  visible: number;
  /** How many are folded into the "+N more" tail (0 ⇒ no tail row). */
  overflow: number;
}

/**
 * Fit variable-height items into `availableRows` sidebar rows. `costs[i]` is the
 * number of rows item `i` occupies (≥1, e.g. from {@link wrapCells}). Items are
 * taken from the front while they fit; when they do not all fit, ONE row is
 * reserved for the "+N more" tail, so the rows actually painted —
 * `sum(costs[0..visible]) + (overflow > 0 ? 1 : 0)` — never exceed
 * `availableRows`. `visible + overflow` always equals the item count.
 */
export function budgetWrappedRows(
  costs: readonly number[],
  availableRows: number,
): SidebarRowBudget {
  const total = costs.length;
  const rows = Math.max(0, Math.floor(availableRows));
  if (rows <= 0) return { visible: 0, overflow: total };

  const sum = costs.reduce((acc, c) => acc + Math.max(1, Math.floor(c)), 0);
  if (sum <= rows) return { visible: total, overflow: 0 };

  // Everything cannot fit: reserve the last row for the tail and pack the rest.
  const budget = rows - 1;
  let used = 0;
  let visible = 0;
  for (const cost of costs) {
    const c = Math.max(1, Math.floor(cost));
    if (used + c <= budget) {
      used += c;
      visible += 1;
    } else break;
  }
  return { visible, overflow: total - visible };
}

/**
 * Fit `itemCount` items into `availableRows` sidebar rows. When everything
 * fits, all items show and there is no tail. When it does not, ONE row is
 * reserved for the "+N more" tail, so the rows actually painted —
 * `visible + (overflow > 0 ? 1 : 0)` — never exceed `availableRows`.
 * `visible + overflow` always equals the (clamped) item count.
 */
export function budgetSidebarRows(itemCount: number, availableRows: number): SidebarRowBudget {
  const count = Math.max(0, Math.floor(itemCount));
  const rows = Math.max(0, Math.floor(availableRows));
  if (rows <= 0) return { visible: 0, overflow: count };
  if (count <= rows) return { visible: count, overflow: 0 };
  const visible = Math.max(0, rows - 1);
  return { visible, overflow: count - visible };
}

/**
 * Cells available for a todo row's text: the column width minus the leading
 * glyph cell and its one-cell gap. Clamped to ≥1 so `fitTuiText` always has a
 * positive budget even in a degenerate 1-cell column.
 */
export function todoTextWidth(columnWidth: number): number {
  return Math.max(1, Math.floor(columnWidth) - 2);
}
