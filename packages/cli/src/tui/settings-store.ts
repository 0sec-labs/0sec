/**
 * A live, process-wide store for the interactive console's display settings.
 *
 * The problem it solves: every TUI screen used to read settings with
 * `useState(() => loadSettings())` — a snapshot frozen at mount. A change made
 * in the settings screen only reached another screen when that screen was
 * unmounted and remounted, which is both a lie (the change was "saved" but the
 * chat kept its stale copy) and a bug waiting to surface the moment chat stops
 * being torn down on navigation. This module is the single source of truth:
 * the settings screen writes it, and every screen subscribes to it, so a
 * change re-renders every consumer synchronously with no remount.
 *
 * It owns no persistence or validation of its own. `settings.ts` already holds
 * the total `normalizeSettings`, the never-throwing layered `loadSettings`, and
 * the report-by-return-value `saveSettings`; this is a thin, subscribable cache
 * in front of them. Two contracts inherited from that module carry through here:
 * nothing throws on an I/O failure (a read-only `$HOME` is an inconvenience,
 * not a lost session), and a failed save still takes effect in memory so the
 * UI reflects the operator's choice — it just reports `false`.
 *
 * ── Two-level configuration ──────────────────────────────────────────────────
 *
 * Reads resolve the GLOBAL file (`~/.0sec/tui-settings.json`) with a per-project
 * OVERRIDE (`<cwd>/.0sec/tui-settings.json`) layered on top, per key, falling
 * through to the built-in defaults. This happens automatically on the load path
 * (`getSettings`/`reloadSettings`) — no bootstrap wiring is needed anywhere.
 *
 * Writes target a LAYER. `updateSetting` writes to the PROJECT file when a
 * project override file already exists, or when the caller passes
 * `scope: "project"`; otherwise it writes the GLOBAL file. `setSettings` (the
 * whole-object write the settings screen uses) always writes the global base.
 * The provenance of every effective value is exposed via `getSettingSources` so
 * `0sec config show` can label each key default/global/project.
 */

import { useSyncExternalStore } from "react";

import {
  loadLayeredSettings,
  normalizeSettings,
  projectSettingsExist,
  saveSettings,
  setProjectOverride,
  type LayeredSettings,
  type SettingLayer,
  type TuiSettings,
} from "./settings.js";

type Subscriber = (settings: TuiSettings) => void;

/**
 * The one cached value for the whole process. `null` until the first read, so
 * the disk hit is lazy — a session that never opens settings never loads them
 * eagerly, and tests can point the store at a temp home before it reads. Holds
 * the effective settings AND their per-key provenance together, so both stay in
 * lock-step through every swap.
 */
let cached: LayeredSettings | null = null;

/**
 * Directories passed through to the load/save paths. Both undefined in
 * production (home defaults to the real home; project defaults to the process
 * cwd inside `settings.ts`); set via `configureSettingsStore` for a custom
 * `--home`/project and by tests to redirect the files into temp dirs.
 */
let homeDir: string | undefined;
let projectDir: string | undefined;

const subscribers = new Set<Subscriber>();

/**
 * Fan a new value out to every subscriber, fail-soft. A throwing subscriber
 * must not break the others or the setter that triggered the notify — the same
 * contract the diagnostics channel and the output guard hold in this codebase.
 * Iterate a snapshot of the set so a subscriber that unsubscribes (or a new one
 * that subscribes) from inside its own callback cannot corrupt the walk.
 */
function notify(settings: TuiSettings): void {
  for (const fn of [...subscribers]) {
    try {
      fn(settings);
    } catch {
      // A broken consumer is its own problem; the store stays consistent.
    }
  }
}

function loadLayered(): LayeredSettings {
  return loadLayeredSettings({ homeDir, projectDir });
}

/**
 * The current settings, always a complete and valid object. The first call
 * lazily loads (and layers) from disk; every later call returns the cached
 * reference unchanged until a write replaces it, which is what keeps
 * `useSyncExternalStore` from tearing or looping.
 */
export function getSettings(): TuiSettings {
  if (cached === null) cached = loadLayered();
  return cached.settings;
}

/**
 * Per-key provenance for the currently effective settings: which layer
 * (default/global/project) each value came from. Lazily loads like `getSettings`.
 */
export function getSettingSources(): Record<keyof TuiSettings, SettingLayer> {
  if (cached === null) cached = loadLayered();
  return cached.sources;
}

/**
 * Replace the whole settings object: persist it to the GLOBAL base, update
 * memory, and notify every subscriber synchronously. Returns whether the save
 * succeeded; a failure still updates memory and notifies (so the change is live
 * for the session) and only the return value tells the caller it did not reach
 * disk.
 *
 * The value is normalised on the way in so the in-memory copy is as valid as one
 * freshly loaded. Note: because a project override shadows the global base on the
 * next full load, prefer `updateSetting` for per-key changes when a project layer
 * is in play; `setSettings` is the whole-object write the settings screen uses.
 */
export function setSettings(next: TuiSettings): boolean {
  const value = normalizeSettings(next);
  const saved = saveSettings(value, homeDir);
  // Re-derive the effective view: on a successful write the global base changed,
  // so a fresh layered load reflects it (and keeps project provenance correct);
  // on a failed write disk is unchanged, so mark the whole object as the global
  // layer in memory to reflect the operator's intent for this session.
  if (saved) {
    cached = loadLayered();
  } else {
    cached = { settings: value, sources: allFromLayer(value, "global") };
  }
  notify(cached.settings);
  return saved;
}

/** A provenance map that assigns every key of `settings` to one layer. */
function allFromLayer(
  settings: TuiSettings,
  layer: SettingLayer,
): Record<keyof TuiSettings, SettingLayer> {
  const sources = {} as Record<keyof TuiSettings, SettingLayer>;
  for (const key of Object.keys(settings) as (keyof TuiSettings)[]) {
    sources[key] = layer;
  }
  return sources;
}

/**
 * Which layer a plain `updateSetting` (no explicit scope) would write to: the
 * project file when a project override already exists, otherwise the global base.
 */
export function defaultWriteLayer(): Exclude<SettingLayer, "default"> {
  return projectSettingsExist(projectDir) ? "project" : "global";
}

/**
 * Change one key and persist to the correct layer, then re-derive the effective
 * view and notify. Returns the save result, same reporting contract as
 * `setSettings`.
 *
 * Target layer: `opts.scope` when given; otherwise `defaultWriteLayer()` — the
 * project file if one exists, else global. A project write is SPARSE (only the
 * changed key is added to the override, the rest keep falling through); a global
 * write goes through the full-object `saveSettings`. An out-of-range value is
 * coerced back to a default by the sanitiser/normaliser, never persisted raw.
 */
export function updateSetting<K extends keyof TuiSettings>(
  key: K,
  value: TuiSettings[K],
  opts: { scope?: Exclude<SettingLayer, "default"> } = {},
): boolean {
  const layer = opts.scope ?? defaultWriteLayer();

  if (layer === "global") {
    return setSettings({ ...getSettings(), [key]: value });
  }

  // Project layer: sparse write of the one key, preserving other overrides.
  const saved = setProjectOverride(key, value, projectDir);
  if (saved) {
    cached = loadLayered();
  } else {
    // Reflect the intent in memory even though it did not reach disk.
    const settings = normalizeSettings({ ...getSettings(), [key]: value });
    const sources = { ...getSettingSources(), [key]: "project" as SettingLayer };
    cached = { settings, sources };
  }
  notify(cached.settings);
  return saved;
}

/**
 * Subscribe to settings changes. Returns an unsubscribe function; calling it
 * more than once is harmless. Subscribers fire synchronously inside
 * `setSettings`/`updateSetting`/`reloadSettings`, never on a plain read.
 */
export function subscribeSettings(fn: Subscriber): () => void {
  subscribers.add(fn);
  return () => {
    subscribers.delete(fn);
  };
}

/**
 * Re-read both layers and notify — for when a settings file was edited by hand
 * or by another process while a session is open. Replaces the cached value
 * unconditionally, so the next `getSettings` and every subscriber see disk.
 */
export function reloadSettings(): TuiSettings {
  cached = loadLayered();
  notify(cached.settings);
  return cached.settings;
}

/**
 * Point the store at specific home/project directories and reload. Production
 * leaves this alone (the real home and cwd are the defaults); it exists for a
 * custom `--home`/project at startup and for tests that redirect the files into
 * temp dirs. Reloading eagerly means a call made after subscribers exist
 * notifies them of the swap.
 */
export function configureSettingsStore(options: { homeDir?: string; projectDir?: string }): void {
  homeDir = options.homeDir;
  projectDir = options.projectDir;
  reloadSettings();
}

/**
 * Drop all cached state and subscribers. Test-only: the store is a process
 * singleton, so each test must start from a clean slate.
 */
export function __resetSettingsStoreForTests(): void {
  cached = null;
  homeDir = undefined;
  projectDir = undefined;
  subscribers.clear();
}

/**
 * React hook: subscribe to the store and re-render exactly when settings
 * change, never otherwise. A thin `useSyncExternalStore` — it does not tear
 * (the store hands back a stable reference between changes) and it unsubscribes
 * on unmount via the subscribe function's returned disposer.
 */
export function useSettings(): TuiSettings {
  return useSyncExternalStore(subscribeSettings, getSettings, getSettings);
}
