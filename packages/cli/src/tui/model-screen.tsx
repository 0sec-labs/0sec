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
 * This screen is the replacement, and it is now a projection of the one shared
 * picker body, `DialogSelectBody`: the grouped, windowed list on the left and
 * the highlighted model's detail on the right, driven inline (no scrim, no
 * floating panel) inside the console shell. The same body serves the modal
 * `DialogSelect` overlay and the settings screen; this file supplies only the
 * domain — which models exist, how they group, what their detail says — and its
 * own keyboard.
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
 *    window boundary comes off `dialog-select-layout.ts` via
 *    `computeDialogPanel`, where it is swept across widths and heights by a
 *    test. The reason is in `PRIMITIVES.md`: Yoga shrinks siblings rather than
 *    clipping them, so a row that claims one cell too many paints two strings
 *    on top of each other, and a bordered box one row short of its content
 *    paints its own border through that content.
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
 *    hold credentials, in the status line and in the detail pane. The operator
 *    judges.
 */

import React, { useEffect, useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";

import { useTheme, type Theme } from "./theme-context.js";
import { Cells } from "./primitives.js";
import { DialogSelectBody, type DialogItem } from "./dialog-select.js";
import {
  clampDialogSelection,
  computeDialogPanel,
  moveDialogSelection,
} from "./dialog-select-layout.js";
import {
  buildModelRows,
  clipModelDetailLines,
  configuredProviderLabels,
  credentialSummary,
  isFilterKey,
  modelDetailLines,
  modelFooterHint,
  shellChromeRows,
  type ModelDetailTone,
  type ModelMode,
  type ModelRow,
} from "./model-layout.js";
import { buildFullModelCatalog } from "./model-catalog.js";
import { syncModelCatalog } from "./model-catalog-sync.js";
import { providerStates } from "./provider-status.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;
/** The status line under the list always states which providers are lit. */
const STATUS_ROWS = 1;

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

function toneColor(theme: Theme, tone: ModelDetailTone): string | undefined {
  switch (tone) {
    case "title":
      return theme.PRIMARY;
    case "accent":
      return theme.ACCENT;
    case "ok":
      return theme.SUCCESS;
    case "warn":
      return theme.WARNING;
    case "muted":
    case "blank":
      return theme.MUTED;
    default:
      return theme.TEXT;
  }
}

export function ModelScreen({
  frame,
  currentModel,
  onSelect,
  onBack,
  onExit,
  env,
}: ModelScreenProps) {
  const theme = useTheme();
  const { width, height } = useTerminalDimensions();

  const [filter, setFilter] = useState("");
  const [filtering, setFiltering] = useState(false);

  // Read once per mount. Credentials are process-level and cannot change
  // under a screen that has no way to set them; re-deriving them on every
  // keystroke would only make the filter slower.
  const states = useMemo(() => providerStates(env ?? process.env), [env]);
  const configured = useMemo(() => configuredProviderLabels(states), [states]);
  // Refresh the Models.dev catalog cache in the background whenever the picker
  // opens. Fire-and-forget: it never throws, no-ops when the cache is still
  // fresh, and only affects the *next* open — this render reads whatever cache
  // (or the bundled offline floor) is already on disk, so the list is instant.
  // `catalogNonce` bumps once the refresh lands so an operator who leaves the
  // picker open sees newly-synced models without reopening it.
  const [catalogNonce, setCatalogNonce] = useState(0);
  useEffect(() => {
    let alive = true;
    void syncModelCatalog().then((updated) => {
      if (alive && updated) setCatalogNonce((n) => n + 1);
    });
    return () => {
      alive = false;
    };
  }, []);
  const catalog = useMemo(
    () => buildFullModelCatalog(currentModel),
    // catalogNonce forces a re-read after a background sync writes the cache.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [currentModel, catalogNonce],
  );

  // `buildModelRows` does all the domain work — grouping by provider, credential
  // lookup, credential-band ordering, floating the active model first, and the
  // AND-over-terms filter. The screen keeps only its selectable model rows and
  // projects them onto `DialogItem`s: the provider label is the category (so the
  // shared body draws a heading per provider), the price is the right-aligned
  // meta, and the running model carries the current-value dot.
  const modelRows = useMemo(
    () => buildModelRows({ catalog, states, filter, activeModel: currentModel }),
    [catalog, states, filter, currentModel],
  );
  const items = useMemo<DialogItem[]>(
    () =>
      modelRows
        .filter((row): row is Extract<ModelRow, { kind: "model" }> => row.kind === "model")
        .map((row) => ({
          id: row.model.id,
          label: row.model.id,
          meta: row.model.price,
          category: row.group.label,
          current: row.active,
        })),
    [modelRows],
  );
  // id -> ModelRow, so the detail renderer can reach the full provider/credential
  // facts the flat `DialogItem` does not carry.
  const rowById = useMemo(() => {
    const map = new Map<string, ModelRow>();
    for (const row of modelRows) if (row.kind === "model") map.set(row.model.id, row);
    return map;
  }, [modelRows]);
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

  // Open on the running model rather than on row zero: the most common reason to
  // open the screen is to confirm or step off what is already set. The stored
  // index then catches up as the operator moves or filters.
  const [selected, setSelected] = useState(() =>
    Math.max(0, items.findIndex((item) => item.current)),
  );
  // The highlighted row can vanish from under the cursor as the filter narrows,
  // so the rendered cursor is always the clamped one.
  const cursor = clampDialogSelection(items, selected);
  const activeItem = cursor >= 0 ? items[cursor] : undefined;

  const contentWidth = Math.max(0, width - 4);
  const bodyRows = Math.max(0, height - shellChromeRows(width) - STATUS_ROWS);
  const panel = computeDialogPanel({
    width: contentWidth,
    height,
    size: "large",
    totalRows,
    withDetail: true,
    bodyRows,
  });

  const mode: ModelMode = filtering ? "filter" : "browse";
  // The always-on status line carries the one statement this screen can always
  // make. It matters most for the operator whose only credential is ChatGPT
  // Codex: the catalogue has no chatgpt-codex models to group under, so no
  // heading names them, and without this line that reads as "nothing works".
  const statusText = credentialSummary(states);

  const move = (delta: number) => {
    if (items.length === 0) return;
    const dir: 1 | -1 = delta >= 0 ? 1 : -1;
    let next = cursor < 0 ? 0 : cursor;
    for (let i = 0; i < Math.abs(delta); i += 1) next = moveDialogSelection(items, next, dir);
    setSelected(next);
  };

  const setQuery = (next: string) => {
    setFilter(next);
    setSelected(0);
  };

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";

    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }

    if (key.name === "up") return move(-1);
    if (key.name === "down") return move(1);
    if (key.name === "pageup") return move(-PAGE_STEP);
    if (key.name === "pagedown") return move(PAGE_STEP);
    if (key.name === "return") {
      // Enter selects from either mode: while filtering, the whole point of
      // typing four characters is to reach one row and take it.
      if (activeItem) onSelect(activeItem.id);
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

  // The detail pane shows the highlighted model's full provider/credential
  // story, fitted to the exact box the shared body hands it.
  const renderDetail = (item: DialogItem, pane: { width: number; height: number }) => {
    const row = rowById.get(item.id);
    const compact = pane.height < 12;
    const lines = clipModelDetailLines(
      modelDetailLines({ row, configured, compact }, pane.width),
      pane.height,
      pane.width,
    );
    return (
      <>
        {lines.map((line, index) => (
          <Cells key={`detail-${index}`} width={pane.width} fg={toneColor(theme, line.tone)}>
            {line.text}
          </Cells>
        ))}
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
        placeholder="type to filter models"
        gutter
        isCurrent={(item) => item.current === true}
        renderDetail={renderDetail}
        emptyText="no models match this filter"
      />
      <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
        <Cells width={contentWidth} fg={theme.MUTED}>
          {statusText}
        </Cells>
      </box>
    </box>
  );

  return <>{frame({ body, hint: modelFooterHint(mode, filter.length > 0) })}</>;
}
