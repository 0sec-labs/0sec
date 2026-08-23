/**
 * Row budgeting for the todos/plan section of the RIGHT sidebar.
 *
 * The sidebar is a narrow, fixed-height column shared by the AGENTS and
 * FINDINGS sections; the plan sits beneath them as a sibling section and must
 * never grow unbounded. This module holds the two pieces of arithmetic the
 * component would otherwise inline — how many item rows to draw given the rows
 * the section was granted (folding the remainder into a single "+N more" tail),
 * and how many cells an item's text may claim — so both invariants are unit
 * tests rather than a code review. It mirrors the cap logic already used by the
 * AGENTS / FINDINGS / SESSIONS sections in chat-screen.
 */

export interface SidebarRowBudget {
  /** How many items to render as full rows. */
  visible: number;
  /** How many are folded into the "+N more" tail (0 ⇒ no tail row). */
  overflow: number;
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
