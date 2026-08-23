/** @jsxImportSource @opentui/react */
/**
 * The full-screen console settings surface.
 *
 * `/settings` used to open a compact picker floating above the composer: ten
 * rows, a value each, and one line of description for whichever row was
 * highlighted. That shape competed with the transcript for the only scarce
 * resource a TUI has — rows — and it left no room for the thing a settings
 * screen is actually for, which is telling you what a setting *does* before
 * you change it.
 *
 * This screen is the replacement, and it is now a projection of the one shared
 * picker body, `DialogSelectBody`: the grouped, windowed list on the left and
 * the highlighted setting's detail plus a LIVE PREVIEW on the right, driven
 * inline (no scrim, no floating panel) inside the console shell. The same body
 * serves the modal `DialogSelect` overlay and the model screen; this file
 * supplies only the domain — which settings exist, how they group, what each
 * one's detail and preview say — and its own keyboard, which unlike a plain
 * picker edits a value in place rather than selecting and closing.
 *
 * Three properties are load-bearing:
 *
 * 1. **Nothing here knows the settings.** The row model is derived from
 *    `SETTING_DEFS` on every render, so a def added to that table appears with
 *    its group heading, its detail text and its preview without this file
 *    changing. There is no list, no group order and no row count written down.
 *
 * 2. **This component does no arithmetic.** Every width, height, row count and
 *    window boundary comes off `dialog-select-layout.ts` via
 *    `computeDialogPanel`, where it is swept across widths and heights by a
 *    test. The reason is in `PRIMITIVES.md`: Yoga shrinks siblings rather than
 *    clipping them, so a row that claims one cell too many paints two strings
 *    on top of each other, and a bordered box one row short of its content
 *    paints its own border through that content.
 *
 * 3. **Every change is persisted immediately, and a failed write is
 *    reported.** A settings screen that silently drops changes on a read-only
 *    `$HOME` is worse than one that refuses to open.
 */

import React, { useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";

import { Cells } from "./primitives.js";
import { setSettings, useSettings } from "./settings-store.js";
import { useTheme, type Theme } from "./theme-context.js";
import { DialogSelectBody, type DialogItem } from "./dialog-select.js";
import {
  clampDialogSelection,
  computeDialogPanel,
  moveDialogSelection,
} from "./dialog-select-layout.js";
import {
  buildSettingsRows,
  clipDetailLines,
  cycleSetting,
  isFilterKey,
  isSettingModified,
  resetAllSettings,
  resetSetting,
  settingValue,
  settingValueLabel,
  settingsDetailLines,
  settingsFooterHint,
  shellChromeRows,
  type SettingsDetailTone,
  type SettingsMode,
  type SettingsRow,
} from "./settings-layout.js";
import { SETTING_DEFS, type SettingDef, type TuiSettings } from "./settings.js";
import { SettingsPreview, previewRowCount } from "./settings-preview.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;
/** Rows kept for the setting's prose before any preview is lent room. */
const MIN_TEXT_ROWS = 3;

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

function toneColor(tone: SettingsDetailTone, theme: Theme): string | undefined {
  switch (tone) {
    case "title":
      return theme.PRIMARY;
    case "accent":
      return theme.ACCENT;
    case "warn":
      return theme.WARNING;
    case "muted":
    case "blank":
      return theme.MUTED;
    default:
      return theme.TEXT;
  }
}

export function SettingsScreen({ frame, onBack, onExit }: SettingsScreenProps) {
  const { width, height } = useTerminalDimensions();
  const theme = useTheme();

  // The live settings, read from the process-wide store. This screen is the
  // writer: `setSettings` (the store's, imported above) persists AND notifies
  // every other subscribed screen synchronously, so a change here takes effect
  // on the chat screen without a remount.
  const settings = useSettings();
  const [filter, setFilter] = useState("");
  const [filtering, setFiltering] = useState(false);
  const [selected, setSelected] = useState(0);
  const [pending, setPending] = useState<PendingReset | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);

  // `buildSettingsRows` does the domain work — grouping by the table's group,
  // first-appearance order, and the AND-over-terms filter across key, label,
  // group, description and choices. The screen keeps only its selectable
  // setting rows and projects them onto `DialogItem`s: the group is the
  // category (so the shared body draws a heading per group), the current value
  // is the right-aligned meta, and a setting that differs from its default
  // carries the current-value dot — the migration of the old accent-coloured
  // value into the picker's gutter.
  const settingsRows = useMemo(() => buildSettingsRows(SETTING_DEFS, filter), [filter]);
  const items = useMemo<DialogItem[]>(
    () =>
      settingsRows
        .filter((row): row is Extract<SettingsRow, { kind: "setting" }> => row.kind === "setting")
        .map((row) => ({
          id: row.def.key,
          label: row.def.label,
          meta: settingValueLabel(row.def, settingValue(settings, row.def)),
          category: row.group,
          current: isSettingModified(settings, row.def),
        })),
    [settingsRows, settings],
  );
  const defByKey = useMemo(() => {
    const map = new Map<string, SettingDef>();
    for (const def of SETTING_DEFS) map.set(def.key, def);
    return map;
  }, []);
  // Display rows (headings interleaved) drive the panel's scroll/height math.
  const totalRows = useMemo(() => {
    let count = 0;
    let group = "";
    for (const item of items) {
      if (item.category && item.category !== group) {
        group = item.category;
        count += 1;
      }
      count += 1;
    }
    return count;
  }, [items]);

  // The highlighted row can vanish from under the cursor as the filter narrows,
  // so the rendered cursor is always the clamped one.
  const cursor = clampDialogSelection(items, selected);
  const activeItem = items.length > 0 ? items[cursor] : undefined;
  const activeDef = activeItem ? defByKey.get(activeItem.id) : undefined;

  const mode: SettingsMode = pending
    ? pending.kind === "all"
      ? "confirm-reset-all"
      : "confirm-reset"
    : filtering
      ? "filter"
      : "browse";

  // The status line under the list carries the confirm prompt and any save
  // failure. The filter now lives in the shared body's search line, so it no
  // longer competes for this row. The line costs a row only when it has text.
  const statusText = pending
    ? pending.kind === "all"
      ? "Reset ALL settings to their defaults? y confirm / n cancel"
      : `Reset "${pending.label}" to ${pending.value}? y confirm / n cancel`
    : notice
      ? notice.text
      : "";
  const statusTone = pending ? theme.WARNING : notice?.tone === "error" ? theme.ERROR : theme.MUTED;

  const contentWidth = Math.max(0, width - 4);
  const bodyRows = Math.max(0, height - shellChromeRows(width) - (statusText ? 1 : 0));
  const panel = computeDialogPanel({
    width: contentWidth,
    height,
    size: "large",
    totalRows,
    withDetail: true,
    bodyRows,
  });

  /**
   * Applies a change and writes it through the store.
   *
   * `setSettings` persists, updates the in-memory copy AND notifies every
   * subscriber synchronously, then reports whether the disk write succeeded as
   * its return value rather than throwing — because a read-only `$HOME` must not
   * take the console down. What it must also not do is look like it worked: the
   * change stays live for the session and the status line says so.
   */
  const commit = (next: TuiSettings) => {
    setPending(null);
    const saved = setSettings(next);
    if (saved) {
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
    if (items.length === 0) return;
    const dir: 1 | -1 = delta >= 0 ? 1 : -1;
    let next = cursor;
    for (let i = 0; i < Math.abs(delta); i += 1) next = moveDialogSelection(items, next, dir);
    setSelected(next);
  };

  const setQuery = (next: string) => {
    setFilter(next);
    setSelected(0);
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

    if (key.name === "up") return move(-1);
    if (key.name === "down") return move(1);
    if (key.name === "pageup") return move(-PAGE_STEP);
    if (key.name === "pagedown") return move(PAGE_STEP);
    if (key.name === "left") return change(-1);
    if (key.name === "right") return change(1);

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
      if (filter) {
        setQuery("");
        return;
      }
      onBack();
      return;
    }
    if (key.name === "return" || isSpace) return change(1);
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

  /**
   * The detail pane: the setting's prose, then — when the pane can spare the
   * rows — a live visual PREVIEW of its current value.
   *
   * The preview reserves rows first, but never so many that the description
   * loses its footing: at least `MIN_TEXT_ROWS` stay with the prose, and the
   * preview only appears when it can show its header plus real content. The
   * width and the total row budget come off the shared body's `pane`; this is
   * the one split the screen performs on top, and the preview physically cannot
   * paint more rows than it is lent.
   */
  const renderDetail = (item: DialogItem, pane: { width: number; height: number }) => {
    const def = defByKey.get(item.id);
    const value = settingValue(settings, def);
    const desired =
      def && pane.width > 0
        ? previewRowCount({ def, value, width: pane.width, settings })
        : 0;
    let previewRows = 0;
    if (desired >= 2 && pane.height >= MIN_TEXT_ROWS + 2) {
      previewRows = Math.min(desired, pane.height - MIN_TEXT_ROWS);
      if (previewRows < 2) previewRows = 0;
    }
    const textRows = pane.height - previewRows;
    const compact = pane.height < 12;

    const detailLines = clipDetailLines(
      settingsDetailLines(def, value, pane.width, { compact }),
      textRows,
      pane.width,
    );
    return (
      <>
        {detailLines.map((line, index) => (
          <Cells key={`detail-${index}`} width={pane.width} fg={toneColor(line.tone, theme)}>
            {line.text}
          </Cells>
        ))}
        {previewRows > 0 ? (
          <SettingsPreview
            def={def}
            value={value}
            width={pane.width}
            settings={settings}
            rowBudget={previewRows}
            theme={theme}
          />
        ) : null}
      </>
    );
  };

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <DialogSelectBody
        items={items}
        cursor={cursor}
        panel={panel}
        query={filter}
        placeholder="type to filter settings"
        isCurrent={(item) => item.current === true}
        renderDetail={renderDetail}
        emptyText="no settings match this filter"
      />
      {statusText ? (
        <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
          <Cells width={contentWidth} fg={statusTone}>
            {statusText}
          </Cells>
        </box>
      ) : null}
    </box>
  );

  return <>{frame({ body, hint: settingsFooterHint(mode, filter.length > 0) })}</>;
}
