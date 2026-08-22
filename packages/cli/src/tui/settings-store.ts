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
 * the total `normalizeSettings`, the never-throwing `loadSettings`, and the
 * report-by-return-value `saveSettings`; this is a thin, subscribable cache in
 * front of them. Two contracts inherited from that module carry through here:
 * nothing throws on an I/O failure (a read-only `$HOME` is an inconvenience,
 * not a lost session), and a failed save still takes effect in memory so the
 * UI reflects the operator's choice — it just reports `false` so the caller can
 * say "changed for this session only".
 */

import { useSyncExternalStore } from "react";

import {
  loadSettings,
  normalizeSettings,
  saveSettings,
  type TuiSettings,
} from "./settings.js";

type Subscriber = (settings: TuiSettings) => void;

/**
 * The one cached value for the whole process. `null` until the first read, so
 * the disk hit is lazy — a session that never opens settings never loads them
 * eagerly, and tests can point the store at a temp home before it reads.
 */
let current: TuiSettings | null = null;

/**
 * Home directory passed through to `loadSettings`/`saveSettings`. Undefined in
 * production (they default to the real home); set via `configureSettingsStore`
 * for a custom `--home` and by tests to redirect the file into a temp dir.
 */
let homeDir: string | undefined;

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

/**
 * The current settings, always a complete and valid object. The first call
 * lazily loads from disk; every later call returns the cached reference
 * unchanged until a write replaces it, which is what keeps `useSyncExternalStore`
 * from tearing or looping.
 */
export function getSettings(): TuiSettings {
  if (current === null) current = loadSettings(homeDir);
  return current;
}

/**
 * Replace the whole settings object: persist it, update memory, and notify
 * every subscriber synchronously. Returns whether the save succeeded; a
 * failure still updates memory and notifies (so the change is live for the
 * session) and only the return value tells the caller it did not reach disk.
 *
 * The value is normalised on the way in so the in-memory copy is as valid as
 * one freshly loaded, mirroring what `saveSettings` writes to disk anyway.
 */
export function setSettings(next: TuiSettings): boolean {
  const value = normalizeSettings(next);
  current = value;
  const saved = saveSettings(value, homeDir);
  notify(value);
  return saved;
}

/**
 * Change one key and persist, on top of the current value. Returns the save
 * result, same contract as `setSettings`. `normalizeSettings` (run inside
 * `setSettings`) coerces an out-of-range value back to a default rather than
 * letting it into memory.
 */
export function updateSetting<K extends keyof TuiSettings>(
  key: K,
  value: TuiSettings[K],
): boolean {
  return setSettings({ ...getSettings(), [key]: value });
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
 * Re-read the file and notify — for when the settings file was edited by hand
 * or by another process while a session is open. Replaces the cached value
 * unconditionally, so the next `getSettings` and every subscriber see disk.
 */
export function reloadSettings(): TuiSettings {
  current = loadSettings(homeDir);
  notify(current);
  return current;
}

/**
 * Point the store at a specific home directory and reload. Production leaves
 * this alone (the real home is the default); it exists for a custom `--home`
 * at startup and for tests that redirect the file into a temp dir. Reloading
 * eagerly means a call made after subscribers exist notifies them of the swap.
 */
export function configureSettingsStore(options: { homeDir?: string }): void {
  homeDir = options.homeDir;
  reloadSettings();
}

/**
 * Drop all cached state and subscribers. Test-only: the store is a process
 * singleton, so each test must start from a clean slate.
 */
export function __resetSettingsStoreForTests(): void {
  current = null;
  homeDir = undefined;
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
