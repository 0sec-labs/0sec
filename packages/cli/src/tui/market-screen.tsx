/** @jsxImportSource @opentui/react */
/**
 * The full-screen marketplace browser.
 *
 * `/market` opens a two-pane browser over the configured registry: the grouped
 * list of installable artifacts on the left (PLUGINS then THEMES), the
 * highlighted artifact's detail on the right, stacked when the terminal is too
 * narrow to hold both. It mirrors `model-screen.tsx` in shape and shares its
 * discipline exactly:
 *
 * 1. **This component does no arithmetic.** Every width, height, row count and
 *    window boundary comes off `market-layout.ts`, where it is swept across
 *    widths 0..200 and heights 0..80 by a test. Yoga shrinks siblings rather
 *    than clipping them, so a row that claims one cell too many paints two
 *    strings on top of each other, and a bordered box one row short of its
 *    content paints its own border through that content.
 *
 * 2. **Install is not enablement, and nothing here runs code.** Installing a
 *    plugin writes its validated bytes to the plugins dir and stops; installing
 *    a theme writes a palette file. Neither enables, applies, or executes
 *    anything. The action is confirmed before it runs, and the detail pane names
 *    the separate, explicit step an operator must take to enable a plugin.
 *
 * 3. **No endpoint ships.** The registry URL comes from `$0SEC_REGISTRY_URL` or
 *    the (empty) core `DEFAULT_REGISTRY_URL`. When none is configured, or the
 *    fetch fails, the screen renders an honest empty state — guidance, not a
 *    crash — and remains a fully functional UI scaffold.
 *
 * The registry fetch, the install action and the installed-state read are all
 * INJECTED (`load`, `installItem`, `readInstalled`) with real defaults that
 * lazily import `@0sec/core`, so the screen can be driven under a test without
 * touching the network or the filesystem.
 */

import React, { useEffect, useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { TextAttributes } from "@opentui/core";

import { useTheme, type Theme } from "./theme-context.js";
import { useSettings } from "./settings-store.js";
import { Cells } from "./primitives.js";
import {
  createPluginService,
  type InstalledIndex,
  type MarketFetchResult,
  type MarketInstallResult,
  type PluginService,
} from "./plugin-service.js";
import {
  actionForRow,
  buildMarketItems,
  buildMarketRows,
  clampSelection,
  clipMarketDetailLines,
  computeMarketLayout,
  computeMarketWindow,
  confirmPrompt,
  isFilterKey,
  marketDetailLines,
  marketEmptyLines,
  marketFooterHint,
  marketListHeading,
  paneTitleColumns,
  moveSelection,
  stateTag,
  type MarketAction,
  type MarketDetailTone,
  type MarketItem,
  type MarketMode,
  type MarketPane,
  type MarketRegistryView,
  type MarketState,
} from "./market-layout.js";

export type { InstalledIndex, MarketFetchResult, MarketInstallResult } from "./plugin-service.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;

// ---------------------------------------------------------------------------
// Registry URL + service wiring
// ---------------------------------------------------------------------------

/** The registry index URL: prop, then env, then the (empty) core default. */
function resolveRegistryUrl(explicit?: string): string {
  return (explicit ?? process.env["0SEC_REGISTRY_URL"] ?? "").trim();
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface MarketFrameInput {
  body: React.ReactNode;
  hint: string;
}

export interface MarketScreenProps {
  /** Wraps the body in the console shell. Injected so this module does not
   *  depend on `run.tsx`, which owns `ShellFrame`. */
  frame: (input: MarketFrameInput) => React.ReactNode;
  /** Leave the screen — Esc, once any filter has been cleared. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
  /** Registry URL override. Defaults to $0SEC_REGISTRY_URL then the empty core default. */
  registryUrl?: string;
  /** Pre-fetched registry (tests / synchronous). When given, no fetch runs. */
  initialData?: MarketRegistryView;
  /**
   * The bridge to the plugin machinery. Injected by `run.tsx` (and by tests);
   * when absent, a default service is built from `registryUrl`/`homeDir`. Every
   * install/enable/run/activate action goes through it.
   */
  service?: PluginService;
  /** Async registry loader override. Falls back to `service.fetchRegistry`. */
  load?: (url: string) => Promise<MarketFetchResult>;
  /** Installed/enabled state read override. Falls back to `service.list`. */
  readInstalled?: (homeDir: string | undefined, activeTheme: string) => Promise<InstalledIndex>;
  /** Install override. Falls back to `service.install`. */
  installItem?: (item: MarketItem, homeDir: string | undefined) => Promise<MarketInstallResult>;
  /** True while a turn is in flight, so a run defers. Forwarded to the service. */
  isTurnActive?: () => boolean;
  /** Home dir override for install + state reads. */
  homeDir?: string;
  /** Active theme name; defaults to the live setting. */
  activeThemeName?: string;
}

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------

function toneColor(theme: Theme, tone: MarketDetailTone): string | undefined {
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

function stateColor(theme: Theme, state: MarketState): string {
  switch (state) {
    case "enabled":
    case "active":
      return theme.SUCCESS;
    case "installed":
      return theme.ACCENT;
    default:
      return theme.MUTED;
  }
}

/**
 * A pane that states its own height. `height` includes the borders, and
 * `flexShrink={0}` stops the column squeezing the box behind its content's back
 * — `width="100%"` would not do it, because `@opentui/core` only clears
 * `flexShrink` for an explicit numeric width or height. When the layout could
 * not find room, it reports zero and nothing renders — a missing pane is missing
 * information; a pane one row short of its content is a frame that looks crashed.
 */
function Pane({
  pane,
  bordered,
  title,
  meta,
  children,
}: {
  pane: MarketPane;
  bordered: boolean;
  title: string;
  /** Right-aligned muted summary on the title row (count/window/version). */
  meta?: string;
  children: React.ReactNode;
}) {
  const theme = useTheme();
  if (pane.width <= 0 || pane.height <= 0) return null;
  // Title row: bold primary title left, right-aligned muted meta — the OMP
  // header the console reuses. The columns sum to the inner width, so the two
  // can never fuse under pressure.
  const cols = paneTitleColumns(pane.innerWidth, (meta ?? "").length);
  const titleRow = pane.hasTitle ? (
    <box flexDirection="row" width={pane.innerWidth} flexShrink={0} minWidth={0}>
      <Cells width={cols.titleWidth} fg={theme.PRIMARY} attributes={TextAttributes.BOLD}>
        {title}
      </Cells>
      <Cells width={cols.gap}>{""}</Cells>
      <Cells width={cols.metaWidth} align="right" fg={theme.MUTED}>
        {meta ?? ""}
      </Cells>
    </box>
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
      borderColor={bordered ? theme.BORDER : undefined}
      backgroundColor={bordered ? theme.PANEL : undefined}
      paddingX={bordered ? 1 : undefined}
    >
      {titleRow}
      {children}
    </box>
  );
}

// ---------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------

export function MarketScreen({
  frame,
  onBack,
  onExit,
  registryUrl,
  initialData,
  service,
  load,
  readInstalled,
  installItem,
  isTurnActive,
  homeDir,
  activeThemeName,
}: MarketScreenProps) {
  const theme = useTheme();
  const settings = useSettings();
  const { width, height } = useTerminalDimensions();

  const url = useMemo(() => resolveRegistryUrl(registryUrl), [registryUrl]);
  const activeTheme = activeThemeName ?? settings.theme;

  // One bridge to the plugin machinery: injected by `run.tsx`/tests, or built
  // here from the resolved URL + home dir. The legacy `load`/`readInstalled`/
  // `installItem` props remain as per-action test overrides on top of it.
  const svc = useMemo<PluginService>(
    () => service ?? createPluginService({ registryUrl: url, homeDir, isTurnActive }),
    [service, url, homeDir, isTurnActive],
  );
  const doLoad = (u: string): Promise<MarketFetchResult> => (load ? load(u) : svc.fetchRegistry());
  const doRead = (h: string | undefined, a: string): Promise<InstalledIndex> =>
    readInstalled ? readInstalled(h, a) : svc.list(a);
  const doInstall = (item: MarketItem, h: string | undefined): Promise<MarketInstallResult> =>
    installItem ? installItem(item, h) : svc.install(item);

  const [filter, setFilter] = useState("");
  const [mode, setMode] = useState<MarketMode>("browse");
  const [anchor, setAnchor] = useState(0);
  const [selected, setSelected] = useState(0);
  const [notice, setNotice] = useState("");

  // Registry data: seeded synchronously from `initialData`, otherwise fetched.
  const [data, setData] = useState<MarketRegistryView | undefined>(initialData);
  const [loaded, setLoaded] = useState(initialData !== undefined || url.length === 0);
  const [error, setError] = useState<string | undefined>(undefined);

  const [installed, setInstalled] = useState<InstalledIndex>(() => ({
    themes: new Set(),
    activeTheme,
    plugins: new Map(),
  }));

  // Fetch the registry once, unless it was handed in or none is configured.
  useEffect(() => {
    if (initialData !== undefined || url.length === 0) return;
    let live = true;
    void doLoad(url).then((result) => {
      if (!live) return;
      if (result.ok) setData(result.result);
      else setError(result.error);
      setLoaded(true);
    });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- doLoad is derived from svc/load, tracked below
  }, [initialData, svc, load, url]);

  // Read installed/enabled state once per mount.
  useEffect(() => {
    let live = true;
    void doRead(homeDir, activeTheme).then((index) => {
      if (live) setInstalled(index);
    });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- doRead is derived from svc/readInstalled, tracked below
  }, [svc, readInstalled, homeDir, activeTheme]);

  const stateFor = useMemo(() => {
    return (item: MarketItem): MarketState => {
      if (item.kind === "theme") {
        if (item.id === installed.activeTheme) return "active";
        return installed.themes.has(item.id) ? "installed" : "available";
      }
      return installed.plugins.get(item.id) ?? "available";
    };
  }, [installed]);

  const items = useMemo(() => buildMarketItems(data), [data]);
  const rows = useMemo(
    () => buildMarketRows({ items, filter, stateFor }),
    [items, filter, stateFor],
  );

  const cursor = clampSelection(rows, selected);
  const activeRow = cursor >= 0 ? rows[cursor] : undefined;
  const activeItem = activeRow?.kind === "item" ? activeRow.item : undefined;
  const activeState = activeRow?.kind === "item" ? activeRow.state : undefined;

  const layout = computeMarketLayout({ width, height, noticeRows: 1 });
  const window = computeMarketWindow({
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

  const reachableButEmpty = loaded && !error && url.length > 0 && items.length === 0;

  const move = (delta: number) => {
    const next = moveSelection(rows, cursor, delta);
    if (next >= 0) setSelected(next);
  };

  const setQuery = (next: string) => {
    setFilter(next);
    setSelected(0);
    setAnchor(0);
  };

  // The action `enter` triggers for the highlighted row: install → enable → run
  // for plugins, install → activate for themes. `none` for a terminal state
  // (an already-enabled plugin, the active theme).
  const activeAction: MarketAction =
    activeItem && activeState ? actionForRow(activeItem.kind, activeState) : "none";

  // Apply a completed action's result: surface its message and, on success,
  // re-read installed/enabled state so the row tag and detail reflect it live.
  const applyResult = (result: { ok: boolean; message: string }) => {
    setNotice(result.message);
    if (result.ok) void doRead(homeDir, activeTheme).then(setInstalled);
  };

  // Each row action maps to exactly one service method. Install writes bytes and
  // runs nothing; enable records the operator's capability approval; run loads an
  // already-enabled plugin (deferring while a turn is in flight); activate hands
  // a theme off to the theme setting. None is ever implied by another.
  const dispatchAction = (action: MarketAction, item: MarketItem) => {
    switch (action) {
      case "install":
        setNotice(`Installing ${item.name}…`);
        void doInstall(item, homeDir).then(applyResult);
        return;
      case "enable":
        setNotice(`Enabling ${item.name}…`);
        void svc.enable(item).then(applyResult);
        return;
      case "run":
        setNotice(`Loading ${item.name}…`);
        void svc.run(item).then(applyResult);
        return;
      case "activate":
        setNotice(`Applying ${item.name}…`);
        void svc.activateTheme(item).then(applyResult);
        return;
      default:
        return;
    }
  };

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";

    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }

    // ── confirm mode ── (nothing effectful happens without a keystroke here)
    if (mode === "confirm") {
      if (seq === "y" || seq === "Y") {
        if (activeItem && activeAction !== "none") dispatchAction(activeAction, activeItem);
        setMode("browse");
        return;
      }
      if (seq === "n" || seq === "N" || key.name === "escape") {
        setNotice("Cancelled.");
        setMode("browse");
        return;
      }
      return;
    }

    if (key.name === "up") return move(-1);
    if (key.name === "down") return move(1);
    if (key.name === "pageup") return move(-PAGE_STEP);
    if (key.name === "pagedown") return move(PAGE_STEP);

    if (key.name === "return") {
      if (!activeItem) return;
      if (activeAction === "none") {
        setNotice(
          activeItem.kind === "theme"
            ? `${activeItem.id} is already the active theme.`
            : `${activeItem.id} is already enabled for this project.`,
        );
      } else {
        // Every effectful action is confirmed before it runs.
        setNotice("");
        setMode("confirm");
      }
      return;
    }

    // ── filter mode ──
    if (mode === "filter") {
      if (key.name === "escape") {
        setMode("browse");
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
      setMode("filter");
      setQuery("");
      return;
    }
    if (isFilterKey(seq)) {
      setMode("filter");
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
          <Cells
            width={heading.labelWidth}
            fg={theme.MUTED}
            attributes={TextAttributes.BOLD}
          >
            {entry.group.label.toUpperCase()}
          </Cells>
          <Cells width={heading.gap}>{""}</Cells>
          <Cells width={heading.countWidth} align="right" fg={theme.MUTED}>
            {String(entry.count)}
          </Cells>
        </box>
      );
    }

    const selectedRow = index === cursor;
    const background = selectedRow ? theme.PANEL_ALT : undefined;
    // The marker column doubles as a selection caret and an installed-state
    // dot, exactly like the shared agent row: a selected row shows an accent
    // "▸", an installed/enabled/active item a state-coloured "●", and an
    // available one nothing. The highlighted row's label is accent + bold.
    const installed = entry.state !== "available";
    const markerGlyph = selectedRow ? "▸" : installed ? "●" : "";
    const markerFg = selectedRow ? theme.ACCENT : stateColor(theme, entry.state);
    const labelFg = selectedRow ? theme.ACCENT : installed ? theme.TEXT : theme.MUTED;
    return (
      <box
        key={`item-${entry.item.kind}-${entry.item.id}`}
        flexDirection="row"
        width={row.width}
        flexShrink={0}
        minWidth={0}
      >
        <Cells width={row.markerWidth} fg={markerFg} bg={background}>
          {markerGlyph}
        </Cells>
        <Cells width={row.markerGap} bg={background}>
          {""}
        </Cells>
        <Cells
          width={row.labelWidth}
          fg={labelFg}
          bg={background}
          attributes={selectedRow ? TextAttributes.BOLD : undefined}
        >
          {entry.item.name}
        </Cells>
        <Cells width={row.versionGap} bg={background}>
          {""}
        </Cells>
        <Cells width={row.versionWidth} align="right" fg={theme.MUTED} bg={background}>
          {entry.item.version}
        </Cells>
        <Cells width={row.stateGap} bg={background}>
          {""}
        </Cells>
        <Cells
          width={row.stateWidth}
          align="right"
          fg={stateColor(theme, entry.state)}
          bg={background}
        >
          {entry.state === "available" ? "" : stateTag(entry.state)}
        </Cells>
      </box>
    );
  });

  // The detail pane shows the selected artifact, or — when the list is empty —
  // the honest empty/error state, so the two-pane scaffold survives an
  // unconfigured registry intact.
  const detailLines = activeRow
    ? clipMarketDetailLines(
        marketDetailLines({ row: activeRow, compact: layout.detailCompact }, layout.detail.innerWidth),
        layout.detail.bodyRows,
        layout.detail.innerWidth,
      )
    : clipMarketDetailLines(
        marketEmptyLines(
          { registryUrl: url, error, reachableButEmpty },
          layout.detail.innerWidth,
        ),
        layout.detail.bodyRows,
        layout.detail.innerWidth,
      );

  const detailBody = detailLines.map((line, index) => (
    <Cells
      key={`detail-${index}`}
      width={layout.detail.innerWidth}
      fg={toneColor(theme, line.tone)}
    >
      {line.text}
    </Cells>
  ));

  const listEmptyText = !loaded
    ? "loading…"
    : filter
      ? "no items match this filter"
      : url.length === 0
        ? "no registry configured"
        : "no items available";

  const statusText =
    mode === "confirm" && activeItem
      ? confirmPrompt(activeItem.name, activeItem.kind, activeAction, activeItem.capabilities)
      : mode === "filter"
        ? `filter: ${filter}_`
        : notice
          ? notice
          : url.length === 0
            ? "registry: not configured — set 0SEC_REGISTRY_URL"
            : `registry: ${url}`;

  const statusTone =
    mode === "confirm"
      ? theme.WARNING
      : notice && mode !== "filter"
        ? theme.TEXT
        : theme.MUTED;

  const detailTitle = activeItem
    ? activeItem.kind === "plugin"
      ? "PLUGIN"
      : "THEME"
    : "MARKETPLACE";
  // The detail header's right meta names the artifact's install state (for a
  // selected item) or nothing (empty/error state), so the pane header agrees
  // with the state tag in the list row and the sentence in the body.
  const detailMeta = activeItem && activeState ? stateTag(activeState) : "";
  const listHeading = marketListHeading(window);

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
          title={listHeading.title}
          meta={listHeading.meta}
        >
          {rows.length === 0 ? (
            <Cells width={row.width} fg={theme.MUTED}>
              {listEmptyText}
            </Cells>
          ) : (
            listBody
          )}
        </Pane>
        <Pane
          pane={layout.detail}
          bordered={layout.bordered}
          title={detailTitle}
          meta={detailMeta}
        >
          {detailBody}
        </Pane>
      </box>
      <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
        <Cells width={layout.contentWidth} fg={statusTone}>
          {statusText}
        </Cells>
      </box>
    </box>
  );

  const hasFilter = filter.length > 0;
  return <>{frame({ body, hint: marketFooterHint(mode, hasFilter, activeAction) })}</>;
}
