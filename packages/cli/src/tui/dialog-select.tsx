/** @jsxImportSource @opentui/react */
/**
 * The one modal picker the console reuses everywhere.
 *
 * OpenCode answers "choose one of these" — a theme, a model, a slash command, a
 * session — with a single floating dialog: a dim scrim, a centred panel anchored
 * in the upper third so it never shifts what is behind it, a title with an `esc`
 * affordance, a filter field, and a scrollable list whose highlighted row is
 * always in view. This component is that dialog, made generic. Every screen that
 * used to hand-roll its own overlay projects onto it.
 *
 * It owns no domain logic. The caller supplies items and a commit callback; the
 * component owns only the transient view state (the filter text and the cursor)
 * and delegates every width, height, column and window decision to
 * `dialog-select-layout.ts`, where a sweep proves nothing overflows the panel.
 * The reasons are in PRIMITIVES.md: Yoga shrinks siblings rather than clipping
 * them, so every leaf is a `Cells` fitted to a budget the layout handed it, and
 * the panel is `flexShrink={0}` so the box cannot be squeezed out from under its
 * own children.
 */

import React, { useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { TextAttributes } from "@opentui/core";

import { useTheme } from "./theme-context.js";
import { Cells, textCells } from "./primitives.js";
import {
  buildDialogRows,
  clampDialogSelection,
  computeDialogPanel,
  dialogDisplayIndex,
  dialogRowColumns,
  dialogWindow,
  filterDialogItems,
  firstEnabled,
  moveDialogSelection,
  type DialogItem,
  type DialogSize,
} from "./dialog-select-layout.js";

export type { DialogItem, DialogSize } from "./dialog-select-layout.js";

export interface DialogSelectProps {
  /** The rows to choose from. Pre-group by `category` if you want headings. */
  items: readonly DialogItem[];
  /**
   * The current selection(s). A `string` (or single-element array) marks one
   * current row and opens the cursor on it; in `multiSelect` mode the whole set
   * seeds the toggled-in rows. Each listed id renders with a gutter dot.
   */
  value?: string | readonly string[];
  /** Toggle rows with space and commit the set with enter. */
  multiSelect?: boolean;
  /**
   * Commit. Single mode passes the highlighted row's id; multi mode passes the
   * toggled-in ids in list order. The caller decides what "select" means.
   */
  onSelect: (selection: string | string[]) => void;
  /** Dismiss without committing — the `esc` affordance and an empty filter. */
  onCancel: () => void;
  /** Shown top-left; `esc` sits top-right. */
  title: string;
  /** Filter-field prompt shown while the query is empty. */
  placeholder?: string;
  /** Panel width band: small 60 / medium 88 / large 116. Default medium. */
  size?: DialogSize;
}

/** How many rows page-up / page-down jump. */
const PAGE_STEP = 5;

function normalizeValue(value: DialogSelectProps["value"]): string[] {
  if (value == null) return [];
  return Array.isArray(value) ? [...value] : [value as string];
}

export function DialogSelect({
  items,
  value,
  multiSelect = false,
  onSelect,
  onCancel,
  title,
  placeholder = "type to filter",
  size = "medium",
}: DialogSelectProps) {
  const theme = useTheme();
  const { width, height } = useTerminalDimensions();

  const initialSelected = useMemo(() => normalizeValue(value), [value]);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(new Set(initialSelected));

  // The filtered, ranked list the cursor moves over — never the full input.
  const filtered = useMemo(() => filterDialogItems(items, query), [items, query]);

  // The cursor is an index into `filtered`; it opens on the current value.
  const [rawCursor, setRawCursor] = useState(() => {
    const currentId = initialSelected[0];
    const at = currentId ? items.findIndex((item) => item.id === currentId && !item.disabled) : -1;
    return at >= 0 ? at : firstEnabled(items);
  });
  // The highlighted row can vanish as the filter narrows, so the rendered
  // cursor is always the clamped one and the stored index catches up on input.
  const cursor = clampDialogSelection(filtered, rawCursor);
  const activeItem = filtered[cursor];

  const rows = useMemo(() => buildDialogRows(filtered), [filtered]);
  const displayIndex = dialogDisplayIndex(rows, cursor);

  // ── geometry ──────────────────────────────────────────────────────────
  const panel = computeDialogPanel({ width, height, size, totalRows: rows.length });
  const window = dialogWindow(rows, displayIndex, panel.visibleRows);
  const visible = rows.slice(window.start, window.end);

  // Gutter is shown whenever any row can carry a dot (a current value, or a
  // multi-select set). Meta / description columns exist only if a visible row
  // actually uses them, so a plain list spends every cell on its labels.
  const hasGutter = multiSelect || items.some((item) => item.current) || initialSelected.length > 0;
  const hasDescription = filtered.some((item) => typeof item.description === "string" && item.description.length > 0);
  const metaContentWidth = filtered.reduce(
    (max, item) => (item.meta ? Math.max(max, textCells(item.meta)) : max),
    0,
  );
  const columns = dialogRowColumns({
    rowWidth: panel.rowWidth,
    hasGutter,
    metaContentWidth,
    hasDescription,
  });

  const isCurrent = (item: DialogItem): boolean =>
    multiSelect ? selected.has(item.id) : item.current === true || selected.has(item.id);

  const commit = () => {
    if (multiSelect) {
      const ids = items.filter((item) => selected.has(item.id)).map((item) => item.id);
      onSelect(ids);
      return;
    }
    if (activeItem && !activeItem.disabled) onSelect(activeItem.id);
  };

  const move = (step: number) => {
    if (filtered.length === 0) return;
    let next = cursor;
    const dir: 1 | -1 = step >= 0 ? 1 : -1;
    for (let i = 0; i < Math.abs(step); i += 1) next = moveDialogSelection(filtered, next, dir);
    setRawCursor(next);
  };

  const setFilter = (next: string) => {
    setQuery(next);
    setRawCursor(0);
  };

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";

    if (key.name === "up") return move(-1);
    if (key.name === "down") return move(1);
    if (key.name === "pageup") return move(-PAGE_STEP);
    if (key.name === "pagedown") return move(PAGE_STEP);

    if (key.name === "return") return commit();

    if (key.name === "escape") {
      // Esc unwinds one step: clear the filter first, dismiss second.
      if (query) return setFilter("");
      return onCancel();
    }

    if (key.name === "backspace") {
      if (query) setFilter(query.slice(0, -1));
      return;
    }

    // Space toggles in multi-select; otherwise it is an ordinary filter char.
    if (multiSelect && (key.name === "space" || seq === " ")) {
      if (activeItem && !activeItem.disabled) {
        setSelected((prev) => {
          const next = new Set(prev);
          if (next.has(activeItem.id)) next.delete(activeItem.id);
          else next.add(activeItem.id);
          return next;
        });
      }
      return;
    }

    // Any other printable single character extends the filter.
    if (seq.length === 1 && seq.charCodeAt(0) >= 0x20 && seq.charCodeAt(0) !== 0x7f) {
      setFilter(query + seq);
    }
  });

  // ── rows ──────────────────────────────────────────────────────────────
  const listBody = visible.map((row) => {
    if (row.kind === "header") {
      return (
        <Cells
          key={row.key}
          width={panel.rowWidth}
          fg={theme.PRIMARY}
          attributes={TextAttributes.BOLD}
        >
          {row.category.toUpperCase()}
        </Cells>
      );
    }

    const item = row.item;
    const isActive = row.itemIndex === cursor;
    const bg = isActive ? theme.PRIMARY : undefined;
    // On the PRIMARY highlight, CANVAS is the readable inverse (PRIMARY is a
    // TEXT token proven to clear contrast against every background token). Off
    // the highlight, disabled rows dim, everything else is body text.
    const labelFg = isActive ? theme.CANVAS : item.disabled ? theme.MUTED : theme.TEXT;
    const metaFg = isActive ? theme.CANVAS : theme.MUTED;
    const dotFg = isActive ? theme.CANVAS : theme.ACCENT;

    return (
      <box
        key={row.key}
        flexDirection="row"
        width={panel.rowWidth}
        flexShrink={0}
        minWidth={0}
        backgroundColor={bg}
      >
        {columns.gutterWidth > 0 ? (
          <Cells width={columns.gutterWidth} fg={dotFg} bg={bg}>
            {isCurrent(item) ? "●" : ""}
          </Cells>
        ) : null}
        <Cells
          width={columns.labelWidth}
          fg={labelFg}
          bg={bg}
          attributes={isActive ? TextAttributes.BOLD : undefined}
        >
          {item.label}
        </Cells>
        {columns.descWidth > 0 ? (
          <>
            <Cells width={columns.descGap} bg={bg}>
              {""}
            </Cells>
            <Cells width={columns.descWidth} fg={isActive ? theme.CANVAS : theme.MUTED} bg={bg}>
              {item.description ?? ""}
            </Cells>
          </>
        ) : null}
        {columns.metaWidth > 0 ? (
          <>
            <Cells width={columns.metaGap} bg={bg}>
              {""}
            </Cells>
            <Cells width={columns.metaWidth} align="right" fg={metaFg} bg={bg}>
              {item.meta ?? ""}
            </Cells>
          </>
        ) : null}
      </box>
    );
  });

  // Title row: title left, "esc" pinned right. Split the inner width so the two
  // can never fuse under pressure.
  const escLabel = "esc";
  const titleGap = 1;
  const escWidth = Math.min(panel.innerWidth, escLabel.length);
  const titleWidth = Math.max(1, panel.innerWidth - escWidth - titleGap);

  const queryDisplay = query.length > 0 ? query : placeholder;

  return (
    <box
      position="absolute"
      top={0}
      left={0}
      width="100%"
      height="100%"
      backgroundColor={theme.CANVAS}
      zIndex={1000}
    >
      <box
        position="absolute"
        top={panel.top}
        left={panel.left}
        width={panel.panelWidth}
        flexShrink={0}
        flexDirection="column"
        border
        borderColor={theme.BORDER}
        backgroundColor={theme.PANEL}
        paddingX={1}
      >
        {/* Title + esc */}
        <box flexDirection="row" width={panel.innerWidth} flexShrink={0} minWidth={0} gap={titleGap}>
          <Cells width={titleWidth} fg={theme.PRIMARY} attributes={TextAttributes.BOLD}>
            {title}
          </Cells>
          <Cells width={escWidth} align="right" fg={theme.MUTED}>
            {escLabel}
          </Cells>
        </box>

        {/* Filter field */}
        <box flexDirection="row" width={panel.innerWidth} flexShrink={0} minWidth={0}>
          <Cells width={2} fg={theme.MUTED}>
            {"› "}
          </Cells>
          <Cells width={Math.max(1, panel.innerWidth - 2)} fg={query ? theme.TEXT : theme.MUTED}>
            {queryDisplay}
          </Cells>
        </box>

        {/* List */}
        <box flexDirection="column" width={panel.innerWidth} height={panel.visibleRows} flexShrink={0} minWidth={0}>
          {rows.length === 0 ? (
            <Cells width={panel.rowWidth} fg={theme.MUTED}>
              no matches
            </Cells>
          ) : (
            listBody
          )}
        </box>

        {/* Footer hint */}
        <Cells width={panel.innerWidth} fg={theme.MUTED}>
          {multiSelect ? "↑↓ move · space toggle · enter confirm · esc close" : "↑↓ move · enter select · esc close"}
        </Cells>
      </box>
    </box>
  );
}
