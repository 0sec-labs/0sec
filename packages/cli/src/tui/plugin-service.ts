/**
 * The bridge between the marketplace UI (`market-screen.tsx`) and the plugin
 * machinery in `@0sec/core` (`plugins/registry-client.ts`, `plugins/loader.ts`,
 * `plugins/enablement.ts`, `plugins/manifest.ts`).
 *
 * The screen does no policy of its own: it renders a {@link MarketState} per row
 * and calls one of the five methods below when an operator confirms an action.
 * Every security invariant the core modules already enforce is preserved here,
 * NOT re-implemented — this module only sequences the existing calls:
 *
 *   1. **Install ≠ enable ≠ run.** {@link PluginService.install} copies the
 *      registry's validated bytes to the plugins root and STOPS — it never writes
 *      an enablement record and never spawns a process. {@link
 *      PluginService.enable} writes exactly one enablement record (the operator's
 *      explicit approval of a specific capability set) and spawns nothing.
 *      {@link PluginService.run} is the only method that loads code, and it does
 *      so through `PluginHost.load`, which refuses any id absent from the enabled
 *      set. The three are separate, deliberate operator actions.
 *
 *   2. **Enablement pins the capabilities the operator saw.** `enable` reads the
 *      capability set off the ON-DISK manifest (`aggregateCapabilities`) and
 *      records THAT set. `list` then reports a plugin as `enabled` only when
 *      `reconcile` + `loadableIds` still agree the approval is valid — a plugin
 *      whose capabilities widened since approval reverts to `installed` and can
 *      no longer load, exactly per the re-approval rule.
 *
 *   3. **Reload is only safe at a turn boundary.** `run` consults the injected
 *      {@link PluginServiceDeps.isTurnActive}; if a turn is in flight it DEFERS
 *      (queues the id and returns a clear operator-facing message) rather than
 *      tearing a child down mid-turn. {@link PluginService.flushDeferred} drains
 *      the queue and is meant to be called by the session at a turn boundary.
 *
 *   4. **Themes are inert data.** `install` of a theme writes a palette file and
 *      `activateTheme` HANDS OFF to the theme setting (an injected `applyTheme`,
 *      the console's own `updateSetting("theme", …)`). This module never
 *      reimplements the palette swap — that belongs to `themes.ts`.
 *
 *   5. **Fail-soft, always.** A bad manifest, a registry error, an unreadable
 *      plugins dir, or a `@0sec/core` import failure all resolve to an `ok:false`
 *      result carrying a one-line message. Nothing here throws into the screen.
 *
 * Every dependency on `@0sec/core`, the filesystem, and the theme setting is
 * INJECTED with a real default, so the service can be exercised under a unit test
 * without a network, a spawned subprocess, or a real state dir.
 */

import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  installedThemeEntries,
  isSafeThemeId,
  reloadInstalledThemes,
  validateTheme,
  writeInstalledTheme,
  type ThemeEntry,
} from "./themes.js";
import { updateSetting } from "./settings-store.js";
import type { MarketItem, MarketRegistryView, MarketState } from "./market-layout.js";

// ---------------------------------------------------------------------------
// Result shapes the screen renders
// ---------------------------------------------------------------------------

export type MarketFetchResult =
  | { ok: true; result: MarketRegistryView }
  | { ok: false; error: string };

export interface MarketInstallResult {
  ok: boolean;
  /** One-line status for the notice bar. */
  message: string;
  /** The state to reflect inline after a successful action. */
  state?: MarketState;
}

/** The result of recording (or refusing) an enablement approval. */
export interface PluginEnableResult {
  ok: boolean;
  message: string;
  /** The capability set the operator approved (empty when refused). */
  capabilities: readonly string[];
  state?: MarketState;
}

/** The result of loading (or deferring) an enabled plugin. */
export interface PluginRunResult {
  ok: boolean;
  message: string;
  /** True when a turn was in flight, so the load was queued, not performed. */
  deferred?: boolean;
  state?: MarketState;
}

/** The installed/enabled state of everything on this machine, read once. */
export interface InstalledIndex {
  themes: Set<string>;
  activeTheme: string;
  plugins: Map<string, "installed" | "enabled">;
}

// ---------------------------------------------------------------------------
// Structural views of the untrusted registry entries (no core d.ts imported)
// ---------------------------------------------------------------------------

/** A theme artifact's installable palette, as core reports it. */
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

/** A plugin entry's installable files, as core reports it. */
interface RawPluginEntry {
  id: string;
  version: string;
  manifest?: unknown;
  files?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// The subset of @0sec/core this bridge drives (injected; real default below)
// ---------------------------------------------------------------------------

/** A validated manifest, as far as this bridge needs to see it. */
interface CorePluginManifest {
  id: string;
  name: string;
  version: string;
  tools?: { capabilities?: string[] }[];
}

interface CoreDiscoveryResult {
  ok: boolean;
  plugin?: { manifest: CorePluginManifest };
  errors?: string[];
}

interface CoreEnablementRecord {
  enabled: Record<string, unknown>;
}

interface CoreReconciledPlugin {
  pluginId: string;
  status: string;
}

interface CoreInstalledView {
  id: string;
  version: string;
  capabilities: string[];
}

interface CoreLoadResult {
  ok: boolean;
  pluginId: string;
  tools?: string[];
  errors?: string[];
}

/** The one method of `PluginHost` this bridge uses. */
export interface PluginHostLike {
  load(pluginId: string): Promise<CoreLoadResult>;
}

/** Everything this bridge imports from `@0sec/core`. Injected for tests. */
export interface CorePluginApi {
  // registry
  fetchRegistryIndex(
    url: string,
    opts: { fetchImpl: typeof fetch; verifier: unknown },
  ): Promise<{ ok: true; result: MarketRegistryView } | { ok: false; error: string }>;
  unconfiguredVerifier: unknown;
  // ids + paths + install
  isSafePluginId(value: unknown): boolean;
  pluginsRootDir(homeDir?: string): string;
  ensurePluginsRoot(dir: string): boolean;
  listInstalledPluginIds(root: string): string[];
  readInstalledPlugin(
    root: string,
    pluginId: string,
    opts?: { reservedToolNames?: readonly string[] },
  ): CoreDiscoveryResult;
  aggregateCapabilities(manifest: CorePluginManifest): string[];
  readonly PLUGIN_MANIFEST_FILE: string;
  readonly PLUGIN_ENTRY_FILE: string;
  readonly PLUGIN_DIR_MODE: number;
  readonly PLUGIN_FILE_MODE: number;
  // enablement
  readEnablement(projectPath: string, homeDir?: string): CoreEnablementRecord;
  writeEnablement(projectPath: string, record: CoreEnablementRecord, homeDir?: string): boolean;
  enable(
    record: CoreEnablementRecord,
    pluginId: string,
    opts: { version: string; capabilities: readonly string[]; now: number },
  ): { ok: true; record: CoreEnablementRecord } | { ok: false; error: string };
  reconcile(record: CoreEnablementRecord, installed: readonly CoreInstalledView[]): CoreReconciledPlugin[];
  loadableIds(reconciled: readonly CoreReconciledPlugin[]): string[];
  // host
  PluginHost: new (opts: {
    homeDir?: string;
    enabled?: readonly string[];
    reservedToolNames?: readonly string[];
    coreVersion?: string;
  }) => PluginHostLike;
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

export interface PluginServiceDeps {
  /** Registry index URL. Empty ⇒ every fetch is a clean no-op (no endpoint). */
  registryUrl?: string;
  /** Per-user state dir override, forwarded to every core path helper. */
  homeDir?: string;
  /** Project the enablement record is keyed to. Defaults to `process.cwd()`. */
  projectPath?: string;
  /** Built-in tool names a plugin may not shadow, forwarded to load/read. */
  reservedToolNames?: readonly string[];
  /** Running @0sec/core version, for `minCoreVersion` enforcement on load. */
  coreVersion?: string;
  /** Injected clock (ms). Defaults to `Date.now`. */
  now?: () => number;
  /** Injected fetch, HTTPS-guarded by core. Defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /**
   * True when a turn is in flight. `run` defers a load while this is true, since
   * reload is only safe at a turn boundary. Defaults to `() => false` (no turn
   * information is reachable from the market overlay; a first load with no child
   * in flight is safe, and a real session getter can be wired in later).
   */
  isTurnActive?: () => boolean;
  /**
   * Apply an installed theme id — the HAND-OFF to the theme setting. Defaults to
   * the console's `updateSetting("theme", id)`. This bridge never swaps palettes
   * itself; `themes.ts` owns that.
   */
  applyTheme?: (themeId: string) => boolean;
  /** Injected @0sec/core. Defaults to a lazy `import("@0sec/core")`. */
  core?: CorePluginApi | (() => Promise<CorePluginApi>);
  /** Injected host factory. Defaults to `new core.PluginHost(...)`. */
  hostFactory?: (opts: {
    homeDir?: string;
    enabled: readonly string[];
    reservedToolNames?: readonly string[];
    coreVersion?: string;
  }) => PluginHostLike;
}

// ---------------------------------------------------------------------------
// The service surface the UI calls
// ---------------------------------------------------------------------------

export interface PluginService {
  /** Fetch + validate the configured registry index (HTTPS only, via core). */
  fetchRegistry(): Promise<MarketFetchResult>;
  /** The install/enable state of every plugin + theme on this machine. */
  list(activeTheme: string): Promise<InstalledIndex>;
  /** Copy a plugin's (or theme's) validated bytes to disk. Runs NOTHING. */
  install(item: MarketItem): Promise<MarketInstallResult>;
  /**
   * Record the operator's explicit approval of a plugin's declared capabilities.
   * A separate, deliberate action — never implied by install. Writes one record;
   * spawns nothing.
   */
  enable(item: MarketItem): Promise<PluginEnableResult>;
  /**
   * Load an ENABLED plugin through `PluginHost` (the enable→load path). Refuses
   * anything not loadable, and DEFERS while a turn is in flight.
   */
  run(item: MarketItem): Promise<PluginRunResult>;
  /** Apply an installed theme by handing off to the theme setting. */
  activateTheme(item: MarketItem): Promise<MarketInstallResult>;
  /**
   * Drain loads deferred because a turn was in flight; call at a turn boundary.
   * Returns one result per queued id.
   */
  flushDeferred(): Promise<PluginRunResult[]>;
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/** Lazily import @0sec/core once, honouring an injected override. */
function coreLoader(
  injected: PluginServiceDeps["core"],
): () => Promise<CorePluginApi> {
  if (typeof injected === "function") return injected as () => Promise<CorePluginApi>;
  if (injected) return async () => injected;
  let cached: Promise<CorePluginApi> | undefined;
  return () => {
    if (!cached) cached = import("@0sec/core") as unknown as Promise<CorePluginApi>;
    return cached;
  };
}

/** Default theme apply: hand off to the console's theme setting. */
function defaultApplyTheme(themeId: string): boolean {
  try {
    return updateSetting("theme", themeId) === true;
  } catch {
    return false;
  }
}

export function createPluginService(deps: PluginServiceDeps = {}): PluginService {
  const getCore = coreLoader(deps.core);
  const homeDir = deps.homeDir;
  const projectPath = deps.projectPath ?? process.cwd();
  const now = deps.now ?? Date.now;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const isTurnActive = deps.isTurnActive ?? (() => false);
  const applyTheme = deps.applyTheme ?? defaultApplyTheme;
  const reservedToolNames = deps.reservedToolNames;
  const registryUrl = (deps.registryUrl ?? "").trim();

  // One host per service instance, so repeat loads dedupe and the child persists
  // for the life of the overlay rather than re-spawning on every keystroke.
  let host: PluginHostLike | undefined;
  const deferred: string[] = [];

  async function core(): Promise<CorePluginApi> {
    return getCore();
  }

  /** Build the InstalledPluginView list for `reconcile`, skipping unreadable. */
  function installedViews(
    c: CorePluginApi,
    root: string,
    ids: readonly string[],
  ): CoreInstalledView[] {
    const views: CoreInstalledView[] = [];
    for (const id of ids) {
      let disc: CoreDiscoveryResult;
      try {
        disc = c.readInstalledPlugin(root, id, reservedToolNames ? { reservedToolNames } : undefined);
      } catch {
        continue;
      }
      if (!disc.ok || !disc.plugin) continue;
      const manifest = disc.plugin.manifest;
      views.push({
        id,
        version: manifest.version,
        capabilities: c.aggregateCapabilities(manifest),
      });
    }
    return views;
  }

  async function fetchRegistry(): Promise<MarketFetchResult> {
    try {
      const c = await core();
      const fetched = await c.fetchRegistryIndex(registryUrl, {
        fetchImpl,
        verifier: c.unconfiguredVerifier,
      });
      if (!fetched.ok) return { ok: false, error: fetched.error };
      return { ok: true, result: fetched.result };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  }

  async function list(activeTheme: string): Promise<InstalledIndex> {
    const themes = new Set<string>();
    try {
      for (const entry of installedThemeEntries(homeDir)) themes.add(entry.name);
    } catch {
      // fail-soft: no installed themes readable
    }

    const plugins = new Map<string, "installed" | "enabled">();
    try {
      const c = await core();
      const root = c.pluginsRootDir(homeDir);
      const ids = c.listInstalledPluginIds(root);
      const record = c.readEnablement(projectPath, homeDir);
      // A plugin reports `enabled` ONLY when its approval still reconciles
      // against the on-disk manifest — a widened capability set reverts it to
      // `installed`, and it can no longer load, per the re-approval rule.
      const loadable = new Set(c.loadableIds(c.reconcile(record, installedViews(c, root, ids))));
      for (const id of ids) {
        plugins.set(id, loadable.has(id) ? "enabled" : "installed");
      }
    } catch {
      // fail-soft: no installed plugins readable
    }

    return { themes, activeTheme, plugins };
  }

  function installTheme(item: MarketItem): MarketInstallResult {
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
      message: `Installed theme ${item.id}. Select it to apply.`,
      state: "installed",
    };
  }

  async function installPlugin(item: MarketItem): Promise<MarketInstallResult> {
    const entry = item.raw as RawPluginEntry;
    try {
      const c = await core();
      if (!c.isSafePluginId(item.id)) {
        return { ok: false, message: `"${item.id}" is not a valid plugin id; refused.` };
      }
      const entryBody = entry.files?.[c.PLUGIN_ENTRY_FILE];
      if (typeof entryBody !== "string") {
        return { ok: false, message: `Registry entry is missing its ${c.PLUGIN_ENTRY_FILE}.` };
      }
      const root = c.pluginsRootDir(homeDir);
      if (!c.ensurePluginsRoot(root)) {
        return { ok: false, message: `Could not create the plugins root at ${root}.` };
      }
      // The directory is the validated id; the filenames are the loader's FIXED
      // convention, never taken from the untrusted index — no path-traversal surface.
      const dir = join(root, item.id);
      mkdirSync(dir, { recursive: true, mode: c.PLUGIN_DIR_MODE });
      chmodSync(dir, c.PLUGIN_DIR_MODE);
      const manifestPath = join(dir, c.PLUGIN_MANIFEST_FILE);
      writeFileSync(manifestPath, `${JSON.stringify(entry.manifest, null, 2)}\n`, {
        mode: c.PLUGIN_FILE_MODE,
      });
      chmodSync(manifestPath, c.PLUGIN_FILE_MODE);
      const entryPath = join(dir, c.PLUGIN_ENTRY_FILE);
      writeFileSync(entryPath, entryBody, { mode: c.PLUGIN_FILE_MODE });
      chmodSync(entryPath, c.PLUGIN_FILE_MODE);
      return {
        ok: true,
        message: `Installed ${item.id}. NOT enabled — select it again to enable it.`,
        state: "installed",
      };
    } catch (error) {
      return {
        ok: false,
        message: `Could not install "${item.id}": ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  async function install(item: MarketItem): Promise<MarketInstallResult> {
    return item.kind === "theme" ? installTheme(item) : installPlugin(item);
  }

  async function enable(item: MarketItem): Promise<PluginEnableResult> {
    if (item.kind !== "plugin") {
      return { ok: false, message: "Only a plugin can be enabled.", capabilities: [] };
    }
    try {
      const c = await core();
      if (!c.isSafePluginId(item.id)) {
        return { ok: false, message: `"${item.id}" is not a valid plugin id; refused.`, capabilities: [] };
      }
      const root = c.pluginsRootDir(homeDir);
      const disc = c.readInstalledPlugin(
        root,
        item.id,
        reservedToolNames ? { reservedToolNames } : undefined,
      );
      if (!disc.ok || !disc.plugin) {
        const why = disc.errors?.join("; ") ?? "not installed";
        return { ok: false, message: `Cannot enable ${item.id}: ${why}. Install it first.`, capabilities: [] };
      }
      const manifest = disc.plugin.manifest;
      // Approval pins the capability set read off the ON-DISK manifest — exactly
      // what will later be compared on load, so the operator approves what runs.
      const capabilities = c.aggregateCapabilities(manifest);
      const record = c.readEnablement(projectPath, homeDir);
      const result = c.enable(record, item.id, {
        version: manifest.version,
        capabilities,
        now: now(),
      });
      if (!result.ok) {
        return { ok: false, message: `Cannot enable ${item.id}: ${result.error}`, capabilities: [] };
      }
      if (!c.writeEnablement(projectPath, result.record, homeDir)) {
        return {
          ok: false,
          message: `Could not persist the enablement approval for ${item.id}.`,
          capabilities: [],
        };
      }
      const capText = capabilities.length > 0 ? capabilities.join(", ") : "no capabilities";
      return {
        ok: true,
        message: `Enabled ${item.id} for this project (approved: ${capText}). Select it again to run it.`,
        capabilities,
        state: "enabled",
      };
    } catch (error) {
      return {
        ok: false,
        message: `Could not enable "${item.id}": ${error instanceof Error ? error.message : String(error)}`,
        capabilities: [],
      };
    }
  }

  async function loadEnabled(c: CorePluginApi, pluginId: string): Promise<PluginRunResult> {
    if (!host) {
      // Enabled ids the host will accept: recomputed so a just-enabled plugin is
      // loadable and a since-widened one is not.
      const root = c.pluginsRootDir(homeDir);
      const record = c.readEnablement(projectPath, homeDir);
      const loadable = c.loadableIds(c.reconcile(record, installedViews(c, root, c.listInstalledPluginIds(root))));
      host = deps.hostFactory
        ? deps.hostFactory({ homeDir, enabled: loadable, reservedToolNames, coreVersion: deps.coreVersion })
        : new c.PluginHost({ homeDir, enabled: loadable, reservedToolNames, coreVersion: deps.coreVersion });
    }
    const result = await host.load(pluginId);
    if (result.ok) {
      const tools = result.tools ?? [];
      const toolText = tools.length > 0 ? `tools: ${tools.join(", ")}` : "no tools";
      return { ok: true, message: `Loaded ${pluginId} (${toolText}).`, state: "enabled" };
    }
    return { ok: false, message: `Could not load ${pluginId}: ${result.errors?.join("; ") ?? "unknown error"}` };
  }

  async function run(item: MarketItem): Promise<PluginRunResult> {
    if (item.kind !== "plugin") {
      return { ok: false, message: "Only a plugin can be run." };
    }
    try {
      const c = await core();
      const root = c.pluginsRootDir(homeDir);
      const record = c.readEnablement(projectPath, homeDir);
      const loadable = new Set(
        c.loadableIds(c.reconcile(record, installedViews(c, root, c.listInstalledPluginIds(root)))),
      );
      if (!loadable.has(item.id)) {
        return {
          ok: false,
          message: `${item.id} is not enabled (or its capabilities changed since approval) — enable it first.`,
        };
      }
      // Reload is only safe at a turn boundary: if a turn is in flight, DEFER.
      if (isTurnActive()) {
        if (!deferred.includes(item.id)) deferred.push(item.id);
        return {
          ok: false,
          deferred: true,
          message: `A turn is in progress; loading ${item.id} is deferred to the next turn boundary.`,
        };
      }
      return await loadEnabled(c, item.id);
    } catch (error) {
      return { ok: false, message: `Could not run "${item.id}": ${error instanceof Error ? error.message : String(error)}` };
    }
  }

  async function flushDeferred(): Promise<PluginRunResult[]> {
    if (deferred.length === 0) return [];
    const ids = deferred.splice(0, deferred.length);
    const results: PluginRunResult[] = [];
    try {
      const c = await core();
      for (const id of ids) results.push(await loadEnabled(c, id));
    } catch (error) {
      for (const id of ids) {
        results.push({
          ok: false,
          message: `Could not load ${id}: ${error instanceof Error ? error.message : String(error)}`,
        });
      }
    }
    return results;
  }

  async function activateTheme(item: MarketItem): Promise<MarketInstallResult> {
    if (item.kind !== "theme") {
      return { ok: false, message: "Only a theme can be applied." };
    }
    if (!isSafeThemeId(item.id)) {
      return { ok: false, message: `"${item.id}" is not a valid theme id; refused.` };
    }
    // Ensure the just-installed id is in the installed-theme cache the setting
    // validates against, then hand off — the setting owns the actual swap.
    try {
      reloadInstalledThemes(homeDir);
    } catch {
      // fail-soft: the setting still validates against whatever is cached
    }
    const applied = applyTheme(item.id);
    if (!applied) {
      return { ok: false, message: `Could not apply theme ${item.id}.` };
    }
    return { ok: true, message: `Applied theme ${item.id}.`, state: "active" };
  }

  return { fetchRegistry, list, install, enable, run, activateTheme, flushDeferred };
}
