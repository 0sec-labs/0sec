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

import React, { useEffect, useMemo, useRef, useState, type SetStateAction } from "react";
import { useKeyboard, usePaste, useTerminalDimensions } from "@opentui/react";
import { decodePasteBytes } from "@opentui/core";

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
import { OFFLINE_MODEL_CATALOG } from "./model-catalog.offline.js";
import { providerStates } from "./provider-status.js";
import { sanitizeTuiText } from "./text.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;
/** One scope row above the list and one credential row below it. */
const STATUS_ROWS = 2;
const CURATED_MODEL_IDS: Readonly<Record<string, true>> = Object.fromEntries(
  OFFLINE_MODEL_CATALOG.map((model) => [model.id, true]),
);

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

function modelDialogItems(rows: ModelRow[]): DialogItem[] {
  return rows
    .filter((row): row is Extract<ModelRow, { kind: "model" }> => row.kind === "model")
    .map((row) => ({
      id: row.model.id,
      label: row.model.id,
      meta: row.model.price,
      category: row.group.label,
      current: row.active,
    }));
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
  const [showAll, setShowAll] = useState(false);
  const [refreshing, setRefreshing] = useState(true);
  const filterRef = useRef("");
  const showAllRef = useRef(false);

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
      if (alive) {
        if (updated) setCatalogNonce((n) => n + 1);
        setRefreshing(false);
      }
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
  const scopedCatalog = useMemo(
    () => showAll ? catalog : catalog.filter((model) => Object.hasOwn(CURATED_MODEL_IDS, model.id) || model.id === currentModel),
    [catalog, currentModel, showAll],
  );

  // `buildModelRows` does all the domain work — grouping by provider, credential
  // lookup, credential-band ordering, floating the active model first, and the
  // AND-over-terms filter. The screen keeps only its selectable model rows and
  // projects them onto `DialogItem`s: the provider label is the category (so the
  // shared body draws a heading per provider), the price is the right-aligned
  // meta, and the running model carries the current-value dot.
  const modelRows = useMemo(
    () => buildModelRows({ catalog: scopedCatalog, states, filter, activeModel: currentModel }),
    [scopedCatalog, states, filter, currentModel],
  );
  const items = useMemo(() => modelDialogItems(modelRows), [modelRows]);
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

  // Keep the highlight on the same model when the background catalog refreshes.
  const [selectedId, setSelectedId] = useState(currentModel);
  const selectedIdRef = useRef(selectedId);
  const cursor = clampDialogSelection(items, items.findIndex((item) => item.id === selectedId));

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

  const mode: ModelMode = filter ? "filter" : "browse";
  // The always-on status line carries the one statement this screen can always
  // make. It matters most for the operator whose only credential is ChatGPT
  // Codex: the catalogue has no chatgpt-codex models to group under, so no
  // heading names them, and without this line that reads as "nothing works".
  const statusText = credentialSummary(states);

  const currentItems = () => filterRef.current === filter && showAllRef.current === showAll
    ? items
    : modelDialogItems(buildModelRows({
      catalog: showAllRef.current
        ? catalog
        : catalog.filter((model) => Object.hasOwn(CURATED_MODEL_IDS, model.id) || model.id === currentModel),
      states,
      filter: filterRef.current,
      activeModel: currentModel,
    }));
  const highlight = (id: string | undefined) => {
    selectedIdRef.current = id;
    setSelectedId(id);
  };

  const move = (delta: number) => {
    const visible = currentItems();
    if (visible.length === 0) return;
    const dir: 1 | -1 = delta >= 0 ? 1 : -1;
    let next = clampDialogSelection(visible, visible.findIndex((item) => item.id === selectedIdRef.current));
    for (let i = 0; i < Math.abs(delta); i += 1) next = moveDialogSelection(visible, next, dir);
    highlight(visible[next]?.id);
  };

  const setQuery = (next: SetStateAction<string>) => {
    filterRef.current = typeof next === "function" ? next(filterRef.current) : next;
    setFilter(filterRef.current);
    highlight(undefined);
  };

  usePaste((event) => {
    const text = sanitizeTuiText(decodePasteBytes(event.bytes));
    if (text) setQuery((current) => current + text);
  });

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";

    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }

    if (key.ctrl && key.name === "u") return setQuery("");
    if (key.ctrl || key.meta || key.option) return;
    if (key.name === "up") return move(-1);
    if (key.name === "down") return move(1);
    if (key.name === "pageup") return move(-PAGE_STEP);
    if (key.name === "pagedown") return move(PAGE_STEP);
    if (key.name === "home") return highlight(currentItems()[0]?.id);
    if (key.name === "end") return highlight(currentItems().at(-1)?.id);
    if (key.name === "tab") {
      showAllRef.current = !showAllRef.current;
      setShowAll(showAllRef.current);
      return;
    }
    if (key.name === "return") {
      const visible = currentItems();
      const activeItem = visible[clampDialogSelection(visible, visible.findIndex((item) => item.id === selectedIdRef.current))];
      if (activeItem) onSelect(activeItem.id);
      return;
    }
    if (key.name === "escape") {
      if (filterRef.current) setQuery("");
      else onBack();
      return;
    }
    if (key.name === "backspace") {
      setQuery((current) => Array.from(current).slice(0, -1).join(""));
      return;
    }
    if (isFilterKey(seq)) {
      // Functional updates preserve every character in a paste/fast key burst.
      // A leading slash still opens search; slashes within model IDs are text.
      setQuery((current) => current === "" && seq === "/" ? "" : current + seq);
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
      <Cells width={contentWidth} fg={theme.ACCENT}>
        {`\uec19 New chat model · ${showAll ? "All" : "Curated"} · ${items.length}/${scopedCatalog.length}${refreshing ? " ⟳" : ""}`}
      </Cells>
      <DialogSelectBody
        items={items}
        cursor={cursor}
        panel={panel}
        query={filter}
        placeholder={"\uf002 Find a model or provider"}
        gutter
        isCurrent={(item) => item.current === true}
        renderDetail={renderDetail}
        emptyText={showAll ? "\uf002 No matches — Ctrl+U clears" : "\uf002 No matches — Tab to browse all models"}
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
