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

import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import React, { useEffect, useMemo, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { TextAttributes } from "@opentui/core";

import { useTheme, type Theme } from "./theme-context.js";
import { useSettings } from "./settings-store.js";
import { Cells } from "./primitives.js";
import {
  installedThemeEntries,
  isSafeThemeId,
  reloadInstalledThemes,
  validateTheme,
  writeInstalledTheme,
  type ThemeEntry,
} from "./themes.js";
import {
  buildMarketItems,
  buildMarketRows,
  clampSelection,
  clipMarketDetailLines,
  computeMarketLayout,
  computeMarketWindow,
  isFilterKey,
  marketDetailLines,
  marketEmptyLines,
  marketFooterHint,
  marketListHeading,
  paneTitleColumns,
  moveSelection,
  stateTag,
  type MarketDetailTone,
  type MarketItem,
  type MarketMode,
  type MarketPane,
  type MarketRegistryView,
  type MarketState,
} from "./market-layout.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;

// ---------------------------------------------------------------------------
// Injected ports (real defaults lazily import @0sec/core)
// ---------------------------------------------------------------------------

export type MarketFetchResult =
  | { ok: true; result: MarketRegistryView }
  | { ok: false; error: string };

export interface MarketInstallResult {
  ok: boolean;
  /** One-line status for the notice bar. */
  message: string;
  /** The state to reflect inline after a successful install. */
  state?: MarketState;
}

/** The installed/enabled state of everything on this machine, read once. */
export interface InstalledIndex {
  themes: Set<string>;
  activeTheme: string;
  plugins: Map<string, "installed" | "enabled">;
}

/** Structural view of a theme artifact's installable palette (from core). */
interface RawThemeArtifact {
  manifest?: {
    theme?: {
      label?: string;
      description?: string;
      mode?: "dark" | "light";
      palette?: Record<string, string>;
    };
  };
}

/** Structural view of a plugin entry's installable files (from core). */
interface RawPluginEntry {
  id: string;
  version: string;
  manifest?: unknown;
  files?: Record<string, string>;
}

/** The registry index URL: prop, then env, then the (empty) core default. */
function resolveRegistryUrl(explicit?: string): string {
  return (explicit ?? process.env["0SEC_REGISTRY_URL"] ?? "").trim();
}

/** Default loader: fetch + validate the index through the core registry client. */
async function defaultLoad(url: string): Promise<MarketFetchResult> {
  try {
    const core = (await import("@0sec/core")) as unknown as {
      fetchRegistryIndex: (
        u: string,
        opts: { fetchImpl: typeof fetch; verifier: unknown },
      ) => Promise<{ ok: true; result: MarketRegistryView } | { ok: false; error: string }>;
      unconfiguredVerifier: unknown;
    };
    const fetched = await core.fetchRegistryIndex(url, {
      fetchImpl: fetch,
      verifier: core.unconfiguredVerifier,
    });
    if (!fetched.ok) return { ok: false, error: fetched.error };
    return { ok: true, result: fetched.result };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

/** Default installed-state read: installed themes here, installed/enabled plugins. */
async function defaultReadInstalled(homeDir: string | undefined, activeTheme: string): Promise<InstalledIndex> {
  const themes = new Set<string>();
  try {
    for (const entry of installedThemeEntries(homeDir)) themes.add(entry.name);
  } catch {
    // fail-soft: no installed themes readable
  }
  const plugins = new Map<string, "installed" | "enabled">();
  try {
    const core = (await import("@0sec/core")) as unknown as {
      pluginsRootDir: (homeDir?: string) => string;
      listInstalledPluginIds: (root: string) => string[];
      readEnablement: (projectPath: string, homeDir?: string) => unknown;
      isEnabled: (record: unknown, pluginId: string) => boolean;
    };
    const root = core.pluginsRootDir(homeDir);
    const record = core.readEnablement(process.cwd(), homeDir);
    for (const id of core.listInstalledPluginIds(root)) {
      plugins.set(id, core.isEnabled(record, id) ? "enabled" : "installed");
    }
  } catch {
    // fail-soft: no installed plugins readable
  }
  return { themes, activeTheme, plugins };
}

/** Default theme install: validate the palette, write the file. Runs nothing. */
function installTheme(item: MarketItem, homeDir: string | undefined): MarketInstallResult {
  if (!isSafeThemeId(item.id)) {
    return { ok: false, message: `"${item.id}" is not a valid theme id; refused.` };
  }
  const theme = (item.raw as RawThemeArtifact)?.manifest?.theme;
  const palette = theme?.palette;
  if (!palette || typeof palette !== "object") {
    return { ok: false, message: `Theme "${item.id}" is missing its palette.` };
  }
  if (validateTheme(palette).length > 0) {
    return { ok: false, message: `Theme "${item.id}" has an invalid palette; refused.` };
  }
  const written = writeInstalledTheme(
    {
      id: item.id,
      label: theme.label,
      description: theme.description,
      mode: theme.mode,
      palette: palette as ThemeEntry["palette"],
    },
    homeDir,
  );
  if (!written.ok) return { ok: false, message: `Could not install "${item.id}": ${written.error}` };
  reloadInstalledThemes(homeDir);
  return {
    ok: true,
    message: `Installed theme ${item.id}. Apply with \`0sec theme apply ${item.id}\`.`,
    state: "installed",
  };
}

/** Default plugin install: copy the validated bytes. Never enables or executes. */
async function installPlugin(item: MarketItem, homeDir: string | undefined): Promise<MarketInstallResult> {
  const entry = item.raw as RawPluginEntry;
  try {
    const core = (await import("@0sec/core")) as unknown as {
      isSafePluginId: (value: unknown) => boolean;
      pluginsRootDir: (homeDir?: string) => string;
      ensurePluginsRoot: (dir: string) => boolean;
      PLUGIN_MANIFEST_FILE: string;
      PLUGIN_ENTRY_FILE: string;
      PLUGIN_DIR_MODE: number;
      PLUGIN_FILE_MODE: number;
    };
    if (!core.isSafePluginId(item.id)) {
      return { ok: false, message: `"${item.id}" is not a valid plugin id; refused.` };
    }
    const entryBody = entry.files?.[core.PLUGIN_ENTRY_FILE];
    if (typeof entryBody !== "string") {
      return { ok: false, message: `Registry entry is missing its ${core.PLUGIN_ENTRY_FILE}.` };
    }
    const root = core.pluginsRootDir(homeDir);
    if (!core.ensurePluginsRoot(root)) {
      return { ok: false, message: `Could not create the plugins root at ${root}.` };
    }
    // The directory is the validated id; the filenames are the loader's FIXED
    // convention, never taken from the untrusted index — no path-traversal surface.
    const dir = join(root, item.id);
    mkdirSync(dir, { recursive: true, mode: core.PLUGIN_DIR_MODE });
    chmodSync(dir, core.PLUGIN_DIR_MODE);
    const manifestPath = join(dir, core.PLUGIN_MANIFEST_FILE);
    writeFileSync(manifestPath, `${JSON.stringify(entry.manifest, null, 2)}\n`, {
      mode: core.PLUGIN_FILE_MODE,
    });
    chmodSync(manifestPath, core.PLUGIN_FILE_MODE);
    const entryPath = join(dir, core.PLUGIN_ENTRY_FILE);
    writeFileSync(entryPath, entryBody, { mode: core.PLUGIN_FILE_MODE });
    chmodSync(entryPath, core.PLUGIN_FILE_MODE);
    return {
      ok: true,
      message: `Installed ${item.id}. NOT enabled — enable with \`0sec plugin enable ${item.id}\`.`,
      state: "installed",
    };
  } catch (error) {
    return { ok: false, message: `Could not install "${item.id}": ${error instanceof Error ? error.message : String(error)}` };
  }
}

async function defaultInstall(item: MarketItem, homeDir: string | undefined): Promise<MarketInstallResult> {
  return item.kind === "theme" ? installTheme(item, homeDir) : installPlugin(item, homeDir);
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
  /** Async registry loader. Injected in tests; defaults to the core client. */
  load?: (url: string) => Promise<MarketFetchResult>;
  /** Reads installed/enabled state. Injected in tests; defaults to the real dirs. */
  readInstalled?: (homeDir: string | undefined, activeTheme: string) => Promise<InstalledIndex>;
  /** Installs the selected item. Injected in tests; defaults to the core install APIs. */
  installItem?: (item: MarketItem, homeDir: string | undefined) => Promise<MarketInstallResult>;
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
  load = defaultLoad,
  readInstalled = defaultReadInstalled,
  installItem = defaultInstall,
  homeDir,
  activeThemeName,
}: MarketScreenProps) {
  const theme = useTheme();
  const settings = useSettings();
  const { width, height } = useTerminalDimensions();

  const url = useMemo(() => resolveRegistryUrl(registryUrl), [registryUrl]);
  const activeTheme = activeThemeName ?? settings.theme;

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
    void load(url).then((result) => {
      if (!live) return;
      if (result.ok) setData(result.result);
      else setError(result.error);
      setLoaded(true);
    });
    return () => {
      live = false;
    };
  }, [initialData, load, url]);

  // Read installed/enabled state once per mount.
  useEffect(() => {
    let live = true;
    void readInstalled(homeDir, activeTheme).then((index) => {
      if (live) setInstalled(index);
    });
    return () => {
      live = false;
    };
  }, [readInstalled, homeDir, activeTheme]);

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

  const runInstall = (item: MarketItem) => {
    setNotice(`Installing ${item.name}…`);
    void installItem(item, homeDir).then((result) => {
      setNotice(result.message);
      if (result.ok) {
        // Re-read installed state so the inline tag and detail reflect the change.
        void readInstalled(homeDir, activeTheme).then(setInstalled);
      }
    });
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
        if (activeItem && activeState === "available") runInstall(activeItem);
        setMode("browse");
        return;
      }
      if (seq === "n" || seq === "N" || key.name === "escape") {
        setNotice("Install cancelled.");
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
      if (activeState === "available") {
        setNotice("");
        setMode("confirm");
      } else {
        setNotice(
          activeItem.kind === "plugin"
            ? `${activeItem.id} is already installed — enable with \`0sec plugin enable\`.`
            : `${activeItem.id} is already installed.`,
        );
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
      ? `Install ${activeItem.name} (${activeItem.kind})? y to confirm, n to cancel`
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
  return <>{frame({ body, hint: marketFooterHint(mode, hasFilter) })}</>;
}
