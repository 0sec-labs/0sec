/** @jsxImportSource @opentui/react */
import React from "react";
import type { Theme } from "../theme-context.js";
import type { TuiSettings } from "../settings.js";
import { fitTuiText } from "../text.js";

/**
 * A comfortable empty composer is a small card, not a single cramped line:
 * the rail frame reserves at least this many rows so the prompt has room to
 * breathe before anything is typed. The input still grows past it with content
 * and shrinks back to it when cleared.
 */
export const COMPOSER_MIN_ROWS = 3;

/**
 * The composer grows to at most this many visual rows; past it the oldest rows
 * scroll out of view so the input can never crowd out the transcript. Shared
 * by the input renderer and the rail-rule height so the two always agree.
 */
export const COMPOSER_MAX_ROWS = 8;

/** Display width of a string in cells (code points), matching markdown.ts. */
function cellCount(text: string): number {
  let n = 0;
  for (const _ of text) n += 1;
  return n;
}

/**
 * The block-cursor glyph. Standard terminal behaviour: a FILLED block when the
 * composer is focused/active, a HOLLOW outline when it is not — so an operator
 * can tell at a glance whether keystrokes land in the composer or elsewhere.
 */
export function composerCursorGlyph(active: boolean): string {
  return active ? "█" : "▯";
}

/**
 * Word-wrap the composer buffer into visual rows.
 *
 * Explicit `\n` (from Shift+Enter) split first; each logical line then
 * soft-wraps to `width` cells on word boundaries, exactly like a message
 * composer. A word wider than the whole row is hard-split rather than
 * overflowing. Whitespace is the operator's content, so nothing is trimmed:
 * the rows always concatenate back to the logical line, which is what keeps the
 * append-only cursor's "end of the last row" position exact.
 *
 * Pure and total — every input, width included, yields an array of rows.
 */
export function wrapComposerInput(text: string, width: number): string[] {
  const w = Math.max(1, Math.trunc(width) || 1);
  const rows: string[] = [];
  for (const logical of String(text ?? "").split("\n")) {
    if (logical.length === 0) {
      rows.push("");
      continue;
    }
    // Runs of non-space and runs of space, so a word wraps as a unit while
    // every character survives.
    const tokens = logical.match(/\s+|\S+/g) ?? [];
    let row = "";
    let rowW = 0;
    const pushRow = (): void => {
      rows.push(row);
      row = "";
      rowW = 0;
    };
    for (let tok of tokens) {
      let tw = cellCount(tok);
      while (rowW + tw > w) {
        if (rowW === 0) {
          if (tw <= w) break; // fits on a fresh row on its own
          // Longer than a whole row: hard-split at the width boundary.
          const chars = Array.from(tok);
          row = chars.slice(0, w).join("");
          rowW = w;
          tok = chars.slice(w).join("");
          tw = cellCount(tok);
        }
        pushRow();
      }
      row += tok;
      rowW += tw;
    }
    pushRow();
  }
  return rows;
}

/**
 * The visual rows the composer body renders, bounded to COMPOSER_MAX_ROWS.
 *
 * A trailing empty row is appended when the last wrapped row is full, so the
 * end-of-buffer cursor spills onto a fresh row instead of overrunning the
 * column — the same reason a terminal wraps the caret. Never empty.
 */
export function composerContentRows(text: string, width: number): string[] {
  const w = Math.max(1, Math.trunc(width) || 1);
  const wrapped = wrapComposerInput(text, w);
  const rows = wrapped.length === 0 ? [""] : wrapped;
  const last = rows[rows.length - 1] ?? "";
  if (cellCount(last) >= w) rows.push("");
  return rows.length > COMPOSER_MAX_ROWS ? rows.slice(rows.length - COMPOSER_MAX_ROWS) : rows;
}

/**
 * Rows the rail rule must span so it matches the frame exactly.
 *
 * Clamped to [COMPOSER_MIN_ROWS, COMPOSER_MAX_ROWS]: an empty composer still
 * reads as the min-height card, and a long one stops growing at the max. Kept
 * here (not inline in the screen) so the rail and the frame's min-height are
 * driven by one rule.
 */
export function composerRailRows(text: string, width: number, composing: boolean): number {
  const content = composing ? composerContentRows(text, width).length : 1;
  return Math.min(COMPOSER_MAX_ROWS, Math.max(COMPOSER_MIN_ROWS, content));
}

/**
 * The composer's editable body: the wrapped input rows with a focus-aware
 * block cursor at the end of the buffer, or the muted placeholder when idle.
 *
 * The input is append-only (the caret always sits at the end), so the cursor
 * is drawn at the tail of the last visual row; `composerContentRows` guarantees
 * that row leaves it a cell. Long text soft-wraps across rows automatically and
 * the box grows with them, up to COMPOSER_MAX_ROWS.
 */
export function ComposerInput({
  composing,
  active,
  text,
  textWidth,
  placeholder,
  placeholderTone,
  theme,
}: {
  composing: boolean;
  /** Focused/active — drives the filled vs hollow cursor block. */
  active: boolean;
  text: string;
  /** Cells available for the input, excluding the "› " prefix. */
  textWidth: number;
  placeholder: string;
  /** Colour for the placeholder (e.g. ERROR for a startup failure). */
  placeholderTone?: string;
  theme: Theme;
}) {
  const { TEXT, MUTED } = theme;
  if (composing) {
    const rows = composerContentRows(text, textWidth);
    const cursor = composerCursorGlyph(active);
    return (
      <box flexDirection="column" minWidth={0}>
        {rows.map((line, i) => {
          const isLast = i === rows.length - 1;
          const shown = fitTuiText(line, Math.max(1, textWidth - (isLast ? 1 : 0)));
          return (
            <text key={`composer-line-${i}`} fg={TEXT}>
              {isLast ? `${shown}${cursor}` : shown}
            </text>
          );
        })}
      </box>
    );
  }
  return <text fg={placeholderTone ?? MUTED}>{fitTuiText(placeholder, textWidth)}</text>;
}

/**
 * Composer chrome, selected by the `composerStyle` setting.
 *
 * Deliberately three distinct elements instead of one box with toggled
 * props: opentui renders a frame whenever `border` is present at all, so a
 * falsy value does not remove it.
 */
export function ComposerFrame({
  style,
  active,
  theme,
  padY = 0,
  children,
}: {
  style: TuiSettings["composerStyle"];
  active: boolean;
  theme: Theme;
  /**
   * Extra rows of vertical padding inside the frame. Used ONLY by the centered
   * hero composer, so the start-screen input reads as a comfortable card rather
   * than a thin sliver; the pinned chat composer leaves it at 0 so its height
   * matches the COMPOSER_ROWS the column reserves.
   */
  padY?: number;
  children: React.ReactNode;
}) {
  const { PRIMARY, MUTED, BORDER, PANEL_ALT } = theme;
  if (style === "border") {
    return (
      <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} border borderColor={active ? PRIMARY : BORDER} backgroundColor={PANEL_ALT} paddingX={1} paddingTop={padY} paddingBottom={padY}>
        {children}
      </box>
    );
  }
  if (style === "rail") {
    // A floor on the frame height so an empty composer is a comfortable card,
    // not a single cramped line; content grows past it (up to
    // COMPOSER_MAX_ROWS) and shrinks back to it. Kept in step with the rail
    // rule via `composerRailRows`. The extra rows land INSIDE the padding, so
    // the card is COMPOSER_MIN_ROWS of body regardless of `padY`.
    const minHeight = COMPOSER_MIN_ROWS + padY * 2;
    return (
      <box flexDirection="column" flexGrow={1} minWidth={0} minHeight={minHeight} flexShrink={0} marginLeft={1} backgroundColor={PANEL_ALT} paddingTop={padY} paddingBottom={padY}>
        {children}
      </box>
    );
  }
  return (
    <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} paddingTop={padY} paddingBottom={padY}>
      {children}
    </box>
  );
}
