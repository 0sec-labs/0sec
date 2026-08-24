/** @jsxImportSource @opentui/react */
/**
 * The full-screen keyboard-shortcuts reference (`/shortcuts`).
 *
 * A read-only cheat-sheet of every chord the chat console binds, grouped by
 * category, rendered inside the console shell. It is the discoverable "all
 * shortcuts in one place" surface the settings screen links to (press `?`
 * there), and the destination the `/shortcuts` command opens.
 *
 * Two properties are load-bearing, both inherited from `usage-screen.tsx`:
 *
 * 1. **This component does no arithmetic and lists no binding.** Every width,
 *    height, row count and column split comes off `keybindings-layout.ts`,
 *    swept across widths and heights by a test — Yoga shrinks siblings rather
 *    than clipping them, so a row that claims one cell too many paints two
 *    strings on top of each other. The content comes off the shared
 *    `keybindings.ts` registry, so a binding added there appears here for free.
 *
 * 2. **The frame is injected.** The console shell arrives as a prop so this
 *    module does not depend on `run.tsx` — the same seam the settings, model
 *    and usage screens use.
 */

import React, { useMemo } from "react";
import { TextAttributes } from "@opentui/core";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";

import { useTheme, type Theme } from "./theme-context.js";
import { Cells } from "./primitives.js";
import {
  buildShortcutsRows,
  clipShortcutsRows,
  computeShortcutsLayout,
  shortcutsFooterHint,
  shortcutsTitle,
  widestKeys,
  type ShortcutsLayout,
  type ShortcutsRow,
  type ShortcutsTone,
} from "./keybindings-layout.js";

export interface ShortcutsFrameInput {
  /** The screen body, already sized to the rows the frame left it. */
  body: React.ReactNode;
  /** Footer text naming the bindings that actually work. */
  hint: string;
}

export interface ShortcutsScreenProps {
  /**
   * Wraps the body in the console shell. Injected rather than imported so this
   * module does not depend on `run.tsx`, which owns `ShellFrame`.
   */
  frame: (input: ShortcutsFrameInput) => React.ReactNode;
  /** Leave the screen — Esc. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
}

function toneColor(theme: Theme, tone: ShortcutsTone | undefined): string | undefined {
  switch (tone) {
    case "heading":
      return theme.PRIMARY;
    case "keys":
      return theme.ACCENT;
    case "description":
      return theme.TEXT;
    case "blank":
      return theme.MUTED;
    default:
      return theme.TEXT;
  }
}

/**
 * A pane that states its own height. `height` includes the borders and
 * `flexShrink={0}` stops the column squeezing the box behind its content's back.
 * When the layout found no room it reports zero and nothing renders.
 */
function Pane({
  layout,
  title,
  children,
}: {
  layout: ShortcutsLayout;
  title: React.ReactNode;
  children: React.ReactNode;
}) {
  const theme = useTheme();
  const { pane, bordered } = layout;
  if (pane.width <= 0 || pane.height <= 0) return null;
  return (
    <box
      flexDirection="column"
      width={pane.width}
      height={pane.height}
      flexShrink={0}
      flexGrow={0}
      minWidth={0}
      border={bordered || undefined}
      borderColor={bordered ? theme.BORDER : undefined}
      backgroundColor={bordered ? theme.PANEL : undefined}
      paddingX={bordered ? 1 : undefined}
    >
      {pane.hasTitle ? title : null}
      {children}
    </box>
  );
}

/** One reference row, rendered against the layout's column allocations. */
function Row({
  row,
  layout,
  theme,
}: {
  row: ShortcutsRow;
  layout: ShortcutsLayout;
  theme: Theme;
}) {
  const inner = layout.pane.innerWidth;

  if (row.kind === "blank") {
    return (
      <Cells width={inner} fg={theme.MUTED}>
        {""}
      </Cells>
    );
  }

  if (row.kind === "heading") {
    return (
      <Cells width={inner} fg={toneColor(theme, row.tone)} attributes={TextAttributes.BOLD}>
        {row.label ?? ""}
      </Cells>
    );
  }

  // binding
  const columns = layout.columns;
  if (columns.descriptionWidth <= 0) {
    // Too narrow for two columns: show the chord alone.
    return (
      <Cells width={inner} fg={theme.ACCENT}>
        {row.keys ?? ""}
      </Cells>
    );
  }
  return (
    <box flexDirection="row" width={columns.width} flexShrink={0} minWidth={0}>
      <Cells width={columns.keysWidth} fg={theme.ACCENT}>
        {row.keys ?? ""}
      </Cells>
      <Cells width={columns.gap}>{""}</Cells>
      <Cells width={columns.descriptionWidth} fg={theme.TEXT}>
        {row.description ?? ""}
      </Cells>
    </box>
  );
}

export function ShortcutsScreen({ frame, onBack, onExit }: ShortcutsScreenProps) {
  const theme = useTheme();
  const { width, height } = useTerminalDimensions();

  const rows = useMemo(() => buildShortcutsRows(), []);
  const maxKeys = useMemo(() => widestKeys(rows), [rows]);
  const layout = computeShortcutsLayout({ width, height }, maxKeys);
  const visible = clipShortcutsRows(rows, layout.visibleRows);

  useKeyboard((key) => {
    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }
    if (key.name === "escape") {
      onBack();
      return;
    }
  });

  const titleRow = (
    <Cells width={layout.pane.innerWidth} fg={theme.PRIMARY} attributes={TextAttributes.BOLD}>
      {shortcutsTitle()}
    </Cells>
  );

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <Pane layout={layout} title={titleRow}>
        {visible.map((row, index) => (
          <Row key={`shortcut-${index}`} row={row} layout={layout} theme={theme} />
        ))}
      </Pane>
    </box>
  );

  return <>{frame({ body, hint: shortcutsFooterHint() })}</>;
}
