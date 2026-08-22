/** @jsxImportSource @opentui/react */
/**
 * The full-screen model picker.
 *
 * `/model` used to open a compact selector floating above the composer: a flat
 * list of every priced model, each with a `provider · price` caption. That
 * shape competed with the transcript for the only scarce resource a TUI has —
 * rows — and it had nowhere to put the one thing an operator needs before
 * switching model, which is whether this machine can reach the vendor at all.
 * A turn started against a dark provider dies with zero tokens and a message
 * about a key nobody knew they needed.
 *
 * This screen is the replacement, and it mirrors `settings-screen.tsx` in
 * shape: the grouped list on the left, the highlighted model's detail on the
 * right, stacked when the terminal is too narrow to hold both.
 *
 * Three properties are load-bearing:
 *
 * 1. **Nothing here knows the models.** The row model is derived from
 *    `model-catalog.ts` — itself derived from the pricing table — and the
 *    provider facts from `provider-status.ts`. There is no list, no vendor
 *    order and no row count written down, so a model added to the pricing
 *    table appears here with its group, its price and its credential state
 *    without this file changing.
 *
 * 2. **This component does no arithmetic.** Every width, height, row count and
 *    window boundary comes off `model-layout.ts`, where it is swept across
 *    widths 0..200 and heights 0..80 by a test. The reason is in
 *    `PRIMITIVES.md`: Yoga shrinks siblings rather than clipping them, so a
 *    row that claims one cell too many paints two strings on top of each
 *    other, and a bordered box one row short of its content paints its own
 *    border through that content.
 *
 * 3. **Credential state is reported per provider, never per model.** A
 *    previous attempt annotated each row "no credentials" using the provider
 *    the catalogue carries. That was wrong and was reverted: the catalogue's
 *    provider comes from the pricing table, while the runtime resolves a
 *    model's provider through its own detection and failover order
 *    (`providerForModel` in `core/src/runtime/llm-api.ts`, which core does not
 *    export). Those disagree — an OpenAI-named model can in fact be served by
 *    the ChatGPT/Codex backend — so a per-row verdict flags working models as
 *    broken. What this screen states is what it can verify: which providers
 *    hold credentials, on the group headings, in the status line and in the
 *    detail pane. The operator judges.
 */

import React, { useEffect, useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";

import { ACCENT, BORDER, MUTED, PANEL, PANEL_ALT, PRIMARY, SUCCESS, TEXT, WARNING } from "../ui/theme.js";
import { Cells } from "./primitives.js";
import {
  buildModelRows,
  clampSelection,
  clipModelDetailLines,
  computeModelLayout,
  computeModelWindow,
  configuredProviderLabels,
  credentialLabel,
  credentialSummary,
  indexOfModel,
  isFilterKey,
  modelDetailLines,
  modelFooterHint,
  modelListTitle,
  moveSelection,
  type ModelDetailTone,
  type ModelMode,
  type ModelPane,
  type ProviderCredential,
} from "./model-layout.js";
import { buildModelCatalog } from "./model-catalog.js";
import { providerStates } from "./provider-status.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;

export interface ModelFrameInput {
  /** The screen body, already sized to the rows the frame left it. */
  body: React.ReactNode;
  /** Footer text for the current mode, naming the bindings that actually work. */
  hint: string;
}

export interface ModelScreenProps {
  /**
   * Wraps the body in the console shell.
   *
   * Injected rather than imported so this module does not depend on `run.tsx`
   * — which owns `ShellFrame` and pulls in every other screen with it. The
   * screen states what it needs (a frame, and a footer line whose text changes
   * with the mode) and the router supplies it.
   */
  frame: (input: ModelFrameInput) => React.ReactNode;
  /** The model the session is currently running, when there is one. */
  currentModel?: string;
  /** Enter on a model row. The router decides what "select" means. */
  onSelect: (id: string) => void;
  /** Leave the screen — Esc, once any filter has been cleared. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
  /**
   * Environment to read credentials from. Defaults to the real one; injected
   * so the screen can be driven under a synthetic environment without the
   * test mutating `process.env`.
   */
  env?: Record<string, string | undefined>;
}

function toneColor(tone: ModelDetailTone): string | undefined {
  switch (tone) {
    case "title":
      return PRIMARY;
    case "accent":
      return ACCENT;
    case "ok":
      return SUCCESS;
    case "warn":
      return WARNING;
    case "muted":
    case "blank":
      return MUTED;
    default:
      return TEXT;
  }
}

function credentialColor(credential: ProviderCredential): string {
  switch (credential) {
    case "ready":
      return SUCCESS;
    case "missing":
      return WARNING;
    default:
      return MUTED;
  }
}

/**
 * A pane that states its own height.
 *
 * `height` includes the borders, and `flexShrink={0}` stops the column
 * squeezing the box behind its content's back — `width="100%"` would not do
 * it, because `@opentui/core` only clears `flexShrink` for an explicit
 * *numeric* width or height and a percentage string is not a number. When the
 * layout could not find room for the pane it reports zero and nothing renders
 * at all, which is the correct degradation: a missing pane is missing
 * information, a pane one row short of its content is a frame that looks like
 * a crash.
 */
function Pane({
  pane,
  bordered,
  title,
  titleFg,
  children,
}: {
  pane: ModelPane;
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

export function ModelScreen({
  frame,
  currentModel,
  onSelect,
  onBack,
  onExit,
  env,
}: ModelScreenProps) {
  const { width, height } = useTerminalDimensions();

  const [filter, setFilter] = useState("");
  const [filtering, setFiltering] = useState(false);
  const [anchor, setAnchor] = useState(0);

  // Read once per mount. Credentials are process-level and cannot change
  // under a screen that has no way to set them; re-deriving them on every
  // keystroke would only make the filter slower.
  const states = useMemo(() => providerStates(env ?? process.env), [env]);
  const configured = useMemo(() => configuredProviderLabels(states), [states]);
  const catalog = useMemo(() => buildModelCatalog(currentModel), [currentModel]);

  const rows = useMemo(
    () => buildModelRows({ catalog, states, filter, activeModel: currentModel }),
    [catalog, states, filter, currentModel],
  );

  // The screen opens on the running model rather than on row zero: the most
  // common reason to open it is to confirm or step off what is already set.
  const [selected, setSelected] = useState(() => {
    const rowsAtMount = buildModelRows({ catalog, states, activeModel: currentModel });
    const at = indexOfModel(rowsAtMount, currentModel);
    return at >= 0 ? at : 0;
  });

  // The highlighted row can vanish from under the cursor between keystrokes as
  // the filter narrows, so the rendered cursor is always the clamped one and
  // the stored index catches up afterwards.
  const cursor = clampSelection(rows, selected);
  const activeRow = cursor >= 0 ? rows[cursor] : undefined;

  const layout = computeModelLayout({ width, height, noticeRows: 1 });
  const window = computeModelWindow({
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

  const mode: ModelMode = filtering ? "filter" : "browse";

  // The status row is unconditional, and it carries the one statement of fact
  // this screen can always make. It matters most for the operator whose only
  // credential is ChatGPT Codex: the catalogue has no chatgpt-codex models to
  // group under, so every heading reads "no credentials" and without this line
  // that would read as "nothing here works".
  const statusText = filtering
    ? `filter: ${filter}_`
    : filter
      ? `filter: ${filter} · ${credentialSummary(states)}`
      : credentialSummary(states);

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

    if (key.ctrl && key.name === "c") {
      onExit();
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
    if (key.name === "return") {
      // Enter selects from either mode: while filtering, the whole point of
      // typing four characters is to reach one row and take it.
      if (activeRow?.kind === "model") onSelect(activeRow.model.id);
      return;
    }

    // ── filter mode ──
    if (filtering) {
      if (key.name === "escape") {
        setFiltering(false);
        return;
      }
      if (key.name === "backspace") {
        setQuery(filter.slice(0, -1));
        return;
      }
      if (isFilterKey(seq)) setQuery(filter + seq);
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
    if (key.name === "backspace") {
      if (filter) setQuery(filter.slice(0, -1));
      return;
    }
    if (seq === "/") {
      setFiltering(true);
      setQuery("");
      return;
    }
    // Unlike the settings screen there is no destructive key to reserve, so
    // every printable character starts a filter. With forty-odd models under
    // ten vendors, typing is how anyone actually reaches a row.
    if (isFilterKey(seq)) {
      setFiltering(true);
      setQuery(seq);
    }
  });

  const row = layout.row;
  const heading = layout.heading;
  const visible = rows.slice(window.start, window.end);

  const listBody = visible.map((entry, offset) => {
    const index = window.start + offset;
    if (entry.kind === "heading") {
      return (
        <box
          key={`heading-${entry.group.id}`}
          flexDirection="row"
          width={heading.width}
          flexShrink={0}
          minWidth={0}
        >
          <Cells width={heading.labelWidth} fg={PRIMARY}>
            {entry.group.label.toUpperCase()}
          </Cells>
          <Cells width={heading.gap}>{""}</Cells>
          <Cells
            width={heading.stateWidth}
            align="right"
            fg={credentialColor(entry.group.credential)}
          >
            {credentialLabel(entry.group.credential)}
          </Cells>
        </box>
      );
    }

    const selectedRow = index === cursor;
    const background = selectedRow ? PANEL_ALT : undefined;
    return (
      <box
        key={`model-${entry.model.id}`}
        flexDirection="row"
        width={row.width}
        flexShrink={0}
        minWidth={0}
      >
        <Cells width={row.markerWidth} fg={PRIMARY} bg={background}>
          {selectedRow ? ">" : ""}
        </Cells>
        <Cells width={row.markerGap} bg={background}>
          {""}
        </Cells>
        <Cells width={row.activeWidth} fg={ACCENT} bg={background}>
          {entry.active ? "*" : ""}
        </Cells>
        <Cells width={row.activeGap} bg={background}>
          {""}
        </Cells>
        <Cells
          width={row.labelWidth}
          fg={entry.active ? ACCENT : selectedRow ? TEXT : MUTED}
          bg={background}
        >
          {entry.model.id}
        </Cells>
        <Cells width={row.priceGap} bg={background}>
          {""}
        </Cells>
        <Cells width={row.priceWidth} align="right" fg={MUTED} bg={background}>
          {entry.model.price}
        </Cells>
      </box>
    );
  });

  const detailBody = clipModelDetailLines(
    modelDetailLines(
      { row: activeRow, configured, compact: layout.detailCompact },
      layout.detail.innerWidth,
    ),
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
          title={modelListTitle(window)}
          titleFg={MUTED}
        >
          {rows.length === 0 ? (
            <Cells width={row.width} fg={MUTED}>
              no models match this filter
            </Cells>
          ) : (
            listBody
          )}
        </Pane>
        <Pane
          pane={layout.detail}
          bordered={layout.bordered}
          title={activeRow ? "MODEL" : "MODEL -"}
          titleFg={MUTED}
        >
          {detailBody}
        </Pane>
      </box>
      <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
        <Cells width={layout.contentWidth} fg={MUTED}>
          {statusText}
        </Cells>
      </box>
    </box>
  );

  return <>{frame({ body, hint: modelFooterHint(mode, filter.length > 0) })}</>;
}
