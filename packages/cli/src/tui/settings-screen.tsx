/** @jsxImportSource @opentui/react */
/**
 * The full-screen console settings surface.
 *
 * `/settings` used to open a compact picker floating above the composer: ten
 * rows, a value each, and one line of description for whichever row was
 * highlighted. That shape competed with the transcript for the only scarce
 * resource a TUI has — rows — and it left no room for the thing a settings
 * screen is actually for, which is telling you what a setting *does* before
 * you change it. It also had nowhere to put grouping, so a security-relevant
 * toggle sat in the same undifferentiated list as "show the logo".
 *
 * This screen is the replacement. Two panes: the grouped list on the left, the
 * highlighted setting's full description, current value, default and allowed
 * values on the right; stacked when the terminal is too narrow to hold both.
 *
 * Three properties are load-bearing:
 *
 * 1. **Nothing here knows the settings.** The row model is derived from
 *    `SETTING_DEFS` on every render, so a def added to that table appears with
 *    its group heading, its detail text and its keybindings without this file
 *    changing. There is no list, no group order and no row count written down.
 *
 * 2. **This component does no arithmetic.** Every width, height, row count and
 *    window boundary comes off `settings-layout.ts`, where it is swept across
 *    widths 0..200 and heights 0..80 by a test. The reason is in
 *    `PRIMITIVES.md`: Yoga shrinks siblings rather than clipping them, so a
 *    row that claims one cell too many paints two strings on top of each
 *    other, and a bordered box one row short of its content paints its own
 *    border through that content. Both are invisible until someone resizes a
 *    terminal, which is why the arithmetic lives somewhere a sweep can reach.
 *
 * 3. **Every change is persisted immediately, and a failed write is
 *    reported.** A settings screen that silently drops changes on a read-only
 *    `$HOME` is worse than one that refuses to open.
 */

import React, { useEffect, useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";

import {
  ACCENT,
  BORDER,
  ERROR,
  MUTED,
  PANEL,
  PANEL_ALT,
  PRIMARY,
  TEXT,
  WARNING,
} from "../ui/theme.js";
import { Cells } from "./primitives.js";
import {
  buildSettingsRows,
  clampSelection,
  clipDetailLines,
  computeSettingsLayout,
  computeSettingsWindow,
  cycleSetting,
  isFilterKey,
  isSettingModified,
  moveSelection,
  resetAllSettings,
  resetSetting,
  settingValue,
  settingValueLabel,
  settingsDetailLines,
  settingsFooterHint,
  settingsListTitle,
  type SettingsDetailTone,
  type SettingsMode,
  type SettingsPane,
} from "./settings-layout.js";
import { SETTING_DEFS, loadSettings, saveSettings, type TuiSettings } from "./settings.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;

export interface SettingsFrameInput {
  /** The settings body, already sized to the rows the frame left it. */
  body: React.ReactNode;
  /** Footer text for the current mode, naming the bindings that actually work. */
  hint: string;
}

export interface SettingsScreenProps {
  /**
   * Wraps the body in the console shell.
   *
   * Injected rather than imported so this module does not depend on `run.tsx`
   * — which owns `ShellFrame` and pulls in every other screen with it. The
   * screen states what it needs (a frame, and a footer line whose text changes
   * with the mode) and the router supplies it.
   */
  frame: (input: SettingsFrameInput) => React.ReactNode;
  /** Leave the screen — Esc, once any filter has been cleared. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
  /** Overrides the settings file location. Tests only. */
  homeDir?: string;
}

type PendingReset =
  | { kind: "one"; key: string; label: string; value: string }
  | { kind: "all" };

interface Notice {
  text: string;
  tone: "error" | "warn" | "info";
}

function toneColor(tone: SettingsDetailTone): string | undefined {
  switch (tone) {
    case "title":
      return PRIMARY;
    case "accent":
      return ACCENT;
    case "warn":
      return WARNING;
    case "muted":
    case "blank":
      return MUTED;
    default:
      return TEXT;
  }
}

/**
 * A pane that states its own height.
 *
 * `height` includes the borders, and `flexShrink={0}` stops the column
 * squeezing the box behind its content's back — the two halves of the
 * `-/clear--------/new-` corruption. When the layout could not find room for
 * the pane it reports zero and nothing renders at all, which is the correct
 * degradation: a missing pane is missing information, a pane one row short of
 * its content is a frame that looks like a crash.
 */
function Pane({
  pane,
  bordered,
  title,
  titleFg,
  children,
}: {
  pane: SettingsPane;
  bordered: boolean;
  title: string;
  titleFg: string;
  children: React.ReactNode;
}) {
  if (pane.width <= 0 || pane.height <= 0) return null;
  // `hasTitle` is the layout's decision, not the caller's: the row it costs
  // was either budgeted for or it was not, and rendering a title the budget
  // did not include is exactly how a box grows one row past its own border.
  const titleRow = pane.hasTitle ? (
    <Cells width={pane.innerWidth} fg={titleFg}>
      {title}
    </Cells>
  ) : null;
  return (
    <box
      flexDirection="column"
      width={pane.width}
      height={pane.height}
      flexShrink={0}
      flexGrow={0}
      minWidth={0}
      border={bordered || undefined}
      borderColor={bordered ? BORDER : undefined}
      backgroundColor={bordered ? PANEL : undefined}
      paddingX={bordered ? 1 : undefined}
    >
      {titleRow}
      {children}
    </box>
  );
}

export function SettingsScreen({ frame, onBack, onExit, homeDir }: SettingsScreenProps) {
  const { width, height } = useTerminalDimensions();

  // Loaded once, lazily. `loadSettings` never throws and never reports, so a
  // corrupt or unreadable file yields defaults rather than an empty screen.
  const [settings, setSettings] = useState<TuiSettings>(() => loadSettings(homeDir));
  const [filter, setFilter] = useState("");
  const [filtering, setFiltering] = useState(false);
  const [selected, setSelected] = useState(0);
  const [anchor, setAnchor] = useState(0);
  const [pending, setPending] = useState<PendingReset | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);

  const rows = useMemo(() => buildSettingsRows(SETTING_DEFS, filter), [filter]);
  // The highlighted row can vanish from under the cursor between keystrokes as
  // the filter narrows, so the rendered cursor is always the clamped one and
  // the stored index catches up afterwards.
  const cursor = clampSelection(rows, selected);
  const activeRow = cursor >= 0 ? rows[cursor] : undefined;
  const activeDef = activeRow?.kind === "setting" ? activeRow.def : undefined;

  const mode: SettingsMode = pending
    ? pending.kind === "all"
      ? "confirm-reset-all"
      : "confirm-reset"
    : filtering
      ? "filter"
      : "browse";

  // The status line under the panes carries the filter, the confirm prompt and
  // any save failure. It costs a row, so the layout is told whether it exists.
  const statusText = pending
    ? pending.kind === "all"
      ? "Reset ALL settings to their defaults? y confirm / n cancel"
      : `Reset "${pending.label}" to ${pending.value}? y confirm / n cancel`
    : notice
      ? notice.text
      : filtering
        ? `filter: ${filter}_`
        : filter
          ? `filter: ${filter}`
          : "";
  const statusTone = pending ? WARNING : notice?.tone === "error" ? ERROR : MUTED;

  const layout = computeSettingsLayout({
    width,
    height,
    noticeRows: statusText ? 1 : 0,
  });
  const window = computeSettingsWindow({
    rows,
    selected: cursor,
    visible: layout.visibleRows,
    anchor,
  });

  useEffect(() => {
    if (window.start !== anchor) setAnchor(window.start);
  }, [window.start, anchor]);
  useEffect(() => {
    if (cursor >= 0 && cursor !== selected) setSelected(cursor);
  }, [cursor, selected]);

  /**
   * Applies a change and writes it through.
   *
   * `saveSettings` reports failure as a return value rather than throwing,
   * because a read-only `$HOME` must not take the console down. What it must
   * also not do is look like it worked: the change stays live for the session
   * and the status line says so.
   */
  const commit = (next: TuiSettings) => {
    setSettings(next);
    setPending(null);
    if (saveSettings(next, homeDir)) {
      setNotice(null);
      return;
    }
    setNotice({
      tone: "error",
      text: "Changed for this session only - the settings file could not be written.",
    });
  };

  const change = (delta: 1 | -1) => {
    if (!activeDef) return;
    commit(cycleSetting(settings, activeDef.key, delta));
  };

  const move = (delta: number) => {
    const next = moveSelection(rows, cursor, delta);
    if (next >= 0) setSelected(next);
  };

  const setQuery = (next: string) => {
    setFilter(next);
    setSelected(0);
    setAnchor(0);
  };

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";
    const isSpace = key.name === "space" || seq === " ";

    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }

    // ── confirm gate ──
    // Nothing is reset without passing through here. Anything that is not an
    // explicit yes cancels, so a stray keystroke can only ever be a no.
    if (pending) {
      if (key.name === "return" || seq === "y" || seq === "Y") {
        commit(pending.kind === "all" ? resetAllSettings() : resetSetting(settings, pending.key));
        return;
      }
      setPending(null);
      return;
    }

    if (key.name === "up") {
      move(-1);
      return;
    }
    if (key.name === "down") {
      move(1);
      return;
    }
    if (key.name === "pageup") {
      move(-PAGE_STEP);
      return;
    }
    if (key.name === "pagedown") {
      move(PAGE_STEP);
      return;
    }
    if (key.name === "left") {
      change(-1);
      return;
    }
    if (key.name === "right") {
      change(1);
      return;
    }

    // ── filter mode ──
    // Every printable character types here, `r` and `R` included; that is the
    // whole point of having an explicit mode, since browse mode has to give
    // those two letters to reset.
    if (filtering) {
      if (key.name === "escape" || key.name === "return") {
        setFiltering(false);
        return;
      }
      if (key.name === "backspace") {
        setQuery(filter.slice(0, -1));
        return;
      }
      if (seq.length === 1 && seq.charCodeAt(0) >= 0x20 && seq.charCodeAt(0) !== 0x7f) {
        setQuery(filter + seq);
      }
      return;
    }

    // ── browse mode ──
    if (key.name === "escape") {
      // Esc unwinds one step at a time: clear the filter first, leave second.
      // Dropping straight out of a filtered screen loses the filter and the
      // screen in one keystroke, and only one of those was asked for.
      if (filter) {
        setQuery("");
        return;
      }
      onBack();
      return;
    }
    if (key.name === "return" || isSpace) {
      change(1);
      return;
    }
    if (key.name === "backspace") {
      if (filter) setQuery(filter.slice(0, -1));
      return;
    }
    if (seq === "r") {
      if (!activeDef) return;
      setPending({
        kind: "one",
        key: activeDef.key,
        label: activeDef.label,
        value: settingValueLabel(activeDef, activeDef.default),
      });
      return;
    }
    if (seq === "R") {
      setPending({ kind: "all" });
      return;
    }
    if (seq === "/") {
      setFiltering(true);
      setQuery("");
      return;
    }
    if (isFilterKey(seq)) {
      setFiltering(true);
      setQuery(seq);
    }
  });

  const row = layout.row;
  const visible = rows.slice(window.start, window.end);

  const listBody = visible.map((entry, offset) => {
    const index = window.start + offset;
    if (entry.kind === "heading") {
      return (
        <box
          key={`heading-${entry.group}`}
          flexDirection="row"
          width={row.width}
          flexShrink={0}
          minWidth={0}
        >
          <Cells width={row.width} fg={PRIMARY}>
            {entry.group.toUpperCase()}
          </Cells>
        </box>
      );
    }

    const active = index === cursor;
    const value = settingValue(settings, entry.def);
    const modified = isSettingModified(settings, entry.def);
    const background = active ? PANEL_ALT : undefined;
    return (
      <box
        key={`setting-${entry.def.key}`}
        flexDirection="row"
        width={row.width}
        flexShrink={0}
        minWidth={0}
      >
        <Cells width={row.markerWidth} fg={PRIMARY} bg={background}>
          {active ? ">" : ""}
        </Cells>
        <Cells width={row.markerGap} bg={background}>
          {""}
        </Cells>
        <Cells width={row.labelWidth} fg={active ? TEXT : MUTED} bg={background}>
          {entry.def.label}
        </Cells>
        <Cells width={row.valueGap} bg={background}>
          {""}
        </Cells>
        <Cells
          width={row.valueWidth}
          align="right"
          fg={modified ? ACCENT : MUTED}
          bg={background}
        >
          {settingValueLabel(entry.def, value)}
        </Cells>
      </box>
    );
  });

  const detailBody = clipDetailLines(
    settingsDetailLines(activeDef, settingValue(settings, activeDef), layout.detail.innerWidth, {
      compact: layout.detailCompact,
    }),
    layout.detail.bodyRows,
    layout.detail.innerWidth,
  ).map((line, index) => (
    <Cells key={`detail-${index}`} width={layout.detail.innerWidth} fg={toneColor(line.tone)}>
      {line.text}
    </Cells>
  ));

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <box
        flexDirection={layout.stacked ? "column" : "row"}
        gap={layout.paneGap}
        flexShrink={0}
        minWidth={0}
      >
        <Pane
          pane={layout.list}
          bordered={layout.bordered}
          title={settingsListTitle(window)}
          titleFg={MUTED}
        >
          {rows.length === 0 ? (
            <Cells width={row.width} fg={MUTED}>
              no settings match this filter
            </Cells>
          ) : (
            listBody
          )}
        </Pane>
        <Pane
          pane={layout.detail}
          bordered={layout.bordered}
          title={activeDef ? "DETAIL" : "DETAIL -"}
          titleFg={MUTED}
        >
          {detailBody}
        </Pane>
      </box>
      {statusText ? (
        <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
          <Cells width={layout.contentWidth} fg={statusTone}>
            {statusText}
          </Cells>
        </box>
      ) : null}
    </box>
  );

  return <>{frame({ body, hint: settingsFooterHint(mode, filter.length > 0) })}</>;
}
