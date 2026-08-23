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

import React, { useMemo, useState, type ReactNode } from "react";
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
  type DialogPanel,
  type DialogSize,
} from "./dialog-select-layout.js";

export type { DialogItem, DialogSize } from "./dialog-select-layout.js";

/**
 * The bounds the detail column hands its renderer.
 *
 * The renderer MUST fit its output to exactly this box — `width` cells across,
 * `height` rows down — because OpenTUI does not clip: a taller node paints its
 * overflow through the footer (see PRIMITIVES.md). Callers therefore size their
 * content against these numbers and append their own truncation marker, exactly
 * as `clipModelDetailLines` and `fitPreviewBlocks` already do. `width` is the
 * detail pane's inner text width; `height` is the rows it may fill (it matches
 * the list's visible-row body height).
 */
export interface DialogDetailPane {
  width: number;
  height: number;
}

/**
 * Render the detail/preview beside the list for the highlighted row.
 *
 * Called with the active item on every render, so the pane re-renders as the
 * cursor moves — this is how the model picker shows a model's detail and how a
 * setting shows its live preview. Return content bounded to `pane`; anything
 * taller than `pane.height` or wider than `pane.width` overflows the box.
 */
export type DialogRenderDetail = (item: DialogItem, pane: DialogDetailPane) => ReactNode;

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
  /**
   * Optional detail/preview column. When given, the overlay becomes two-column
   * — list on the left, `renderDetail(activeItem, pane)` on the right — and the
   * panel widens to the `large` band. When absent the overlay is the plain
   * single-column list. On a terminal too narrow to hold both columns the
   * detail is hidden and the list takes the full width.
   */
  renderDetail?: DialogRenderDetail;
}

/** How many rows page-up / page-down jump. */
const PAGE_STEP = 5;

function normalizeValue(value: DialogSelectProps["value"]): string[] {
  if (value == null) return [];
  return Array.isArray(value) ? [...value] : [value as string];
}

export interface DialogSelectBodyProps {
  /**
   * The rows to project, ALREADY filtered and ranked by the caller. The body
   * does no filtering of its own — the overlay filters with `filterDialogItems`
   * and each full-screen picker filters through its own domain builder — so this
   * is exactly the list the cursor moves over.
   */
  items: readonly DialogItem[];
  /** Cursor as an index into `items`. Out-of-range is tolerated (clamped). */
  cursor: number;
  /** Geometry from `computeDialogPanel` (overlay or `bodyRows` inline mode). */
  panel: DialogPanel;
  /** The current filter text, shown in the search line. */
  query: string;
  /** Prompt shown in the search line while the query is empty. */
  placeholder?: string;
  /** Drop the search line entirely — a host that shows the filter elsewhere. */
  hideSearch?: boolean;
  /**
   * Reserve the leading gutter column for a current-value dot. Defaults to
   * "whenever any row reports itself current" via `isCurrent`.
   */
  gutter?: boolean;
  /** Predicate for the gutter dot. Defaults to `item.current === true`. */
  isCurrent?: (item: DialogItem) => boolean;
  /**
   * Optional detail/preview column. Rendered beside the list for the active
   * item whenever the panel is wide enough to split (`panel.showDetail`).
   */
  renderDetail?: DialogRenderDetail;
  /** Text shown in place of the list when there is nothing to choose from. */
  emptyText?: string;
}

/**
 * The list-and-detail body every picker shares, with no scrim, border, title,
 * footer or keyboard of its own.
 *
 * This is the extracted heart of `DialogSelect`: the search line, the windowed
 * scrollable list (current-value gutter dot, category headings, active-row
 * highlight, single- and multi-select) and — when a `renderDetail` is given and
 * the panel is wide enough — the detail column beside it. It owns no state: the
 * caller supplies the filtered items, the cursor and the geometry, so the same
 * body serves the centred overlay (`DialogSelect`) and the full-screen `/model`
 * and `/settings` routes, which drive it with their own keyboard and their own
 * `computeDialogPanel({ bodyRows })` inline geometry.
 *
 * Every width, height and column comes off `panel`; every leaf is a `Cells`
 * fitted to the budget the panel handed it (PRIMITIVES.md: Yoga shrinks
 * siblings rather than clipping them), so the body physically cannot overflow
 * the box its host reserved.
 */
export function DialogSelectBody({
  items,
  cursor,
  panel,
  query,
  placeholder = "type to filter",
  hideSearch = false,
  gutter,
  isCurrent,
  renderDetail,
  emptyText = "no matches",
}: DialogSelectBodyProps) {
  const theme = useTheme();

  const rows = useMemo(() => buildDialogRows(items), [items]);
  const displayIndex = dialogDisplayIndex(rows, cursor);
  const window = dialogWindow(rows, displayIndex, panel.visibleRows);
  const visible = rows.slice(window.start, window.end);
  const activeItem = items[cursor];

  const current = isCurrent ?? ((item: DialogItem) => item.current === true);
  // Gutter is reserved whenever any row can carry a dot. Meta / description
  // columns exist only if a visible row actually uses them, so a plain list
  // spends every cell on its labels.
  const hasGutter = gutter ?? items.some((item) => current(item));
  const hasDescription = items.some(
    (item) => typeof item.description === "string" && item.description.length > 0,
  );
  const metaContentWidth = items.reduce(
    (max, item) => (item.meta ? Math.max(max, textCells(item.meta)) : max),
    0,
  );
  const columns = dialogRowColumns({
    rowWidth: panel.rowWidth,
    hasGutter,
    metaContentWidth,
    hasDescription,
  });

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
            {current(item) ? "●" : ""}
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

  const queryDisplay = query.length > 0 ? query : placeholder;

  return (
    <box flexDirection="column" width={panel.innerWidth} flexShrink={0} minWidth={0}>
      {/* Filter field */}
      {hideSearch ? null : (
        <box flexDirection="row" width={panel.innerWidth} flexShrink={0} minWidth={0}>
          <Cells width={2} fg={theme.MUTED}>
            {"› "}
          </Cells>
          <Cells width={Math.max(1, panel.innerWidth - 2)} fg={query ? theme.TEXT : theme.MUTED}>
            {queryDisplay}
          </Cells>
        </box>
      )}

      {/* Body: list, and — when a detail renderer is given and the panel is
          wide enough — a detail/preview column beside it. */}
      <box
        flexDirection="row"
        width={panel.innerWidth}
        height={panel.visibleRows}
        flexShrink={0}
        minWidth={0}
      >
        {/* List column */}
        <box
          flexDirection="column"
          width={panel.listWidth}
          height={panel.visibleRows}
          flexShrink={0}
          minWidth={0}
        >
          {rows.length === 0 ? (
            <Cells width={panel.rowWidth} fg={theme.MUTED}>
              {emptyText}
            </Cells>
          ) : (
            listBody
          )}
        </box>

        {/* Detail column. Bounded to its own width/height; the renderer fits
            its content to `pane` since OpenTUI will not clip an overflow. */}
        {panel.showDetail ? (
          <>
            <box width={panel.detailGap} height={panel.visibleRows} flexShrink={0} />
            <box
              flexDirection="column"
              width={panel.detailWidth}
              height={panel.visibleRows}
              flexShrink={0}
              minWidth={0}
            >
              {activeItem && renderDetail
                ? renderDetail(activeItem, { width: panel.detailWidth, height: panel.visibleRows })
                : null}
            </box>
          </>
        ) : null}
      </box>
    </box>
  );
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
  renderDetail,
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

  // ── geometry ──────────────────────────────────────────────────────────
  const totalRows = useMemo(() => buildDialogRows(filtered).length, [filtered]);
  const panel = computeDialogPanel({
    width,
    height,
    size,
    totalRows,
    withDetail: renderDetail != null,
  });

  // Gutter is shown whenever any row can carry a dot (a current value, or a
  // multi-select set).
  const hasGutter = multiSelect || items.some((item) => item.current) || initialSelected.length > 0;

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

  // Title row: title left, "esc" pinned right. Split the inner width so the two
  // can never fuse under pressure.
  const escLabel = "esc";
  const titleGap = 1;
  const escWidth = Math.min(panel.innerWidth, escLabel.length);
  const titleWidth = Math.max(1, panel.innerWidth - escWidth - titleGap);

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

        {/* Search line + windowed list + optional detail column. */}
        <DialogSelectBody
          items={filtered}
          cursor={cursor}
          panel={panel}
          query={query}
          placeholder={placeholder}
          gutter={hasGutter}
          isCurrent={isCurrent}
          renderDetail={renderDetail}
        />

        {/* Footer hint */}
        <Cells width={panel.innerWidth} fg={theme.MUTED}>
          {multiSelect ? "↑↓ move · space toggle · enter confirm · esc close" : "↑↓ move · enter select · esc close"}
        </Cells>
      </box>
    </box>
  );
}
