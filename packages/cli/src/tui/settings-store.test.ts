import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_SETTINGS, loadSettings, type TuiSettings } from "./settings.js";
import {
  __resetSettingsStoreForTests,
  configureSettingsStore,
  getSettings,
  reloadSettings,
  setSettings,
  subscribeSettings,
  updateSetting,
  useSettings,
} from "./settings-store.js";

/** Temp homes created by a test, torn down after it regardless of outcome. */
const tempHomes: string[] = [];

function makeHome(): string {
  const dir = mkdtempSync(join(tmpdir(), "0sec-settings-store-"));
  tempHomes.push(dir);
  return dir;
}

/**
 * A home path that is actually a *file*, so `saveSettings`' `mkdirSync` of the
 * `.0sec` directory underneath it throws (ENOTDIR) and the save reports false —
 * while `loadSettings` still degrades to defaults without throwing.
 */
function makeUnwritableHome(): string {
  const file = join(makeHome(), "not-a-dir");
  writeFileSync(file, "x", "utf8");
  return file;
}

beforeEach(() => {
  __resetSettingsStoreForTests();
});

afterEach(() => {
  __resetSettingsStoreForTests();
  while (tempHomes.length > 0) {
    const dir = tempHomes.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("getSettings", () => {
  it("lazily loads a complete, valid object", () => {
    configureSettingsStore({ homeDir: makeHome() });
    const settings = getSettings();
    expect(settings).toEqual(DEFAULT_SETTINGS);
  });

  it("returns a stable reference between reads (no tearing)", () => {
    configureSettingsStore({ homeDir: makeHome() });
    expect(getSettings()).toBe(getSettings());
  });

  it("reads an existing file through loadSettings", () => {
    const home = makeHome();
    configureSettingsStore({ homeDir: home });
    setSettings({ ...DEFAULT_SETTINGS, theme: "light" });
    // A fresh load off disk sees the persisted value.
    expect(loadSettings(home).theme).toBe("light");
  });
});

describe("setSettings / updateSetting", () => {
  it("persists to disk and returns true on success", () => {
    const home = makeHome();
    configureSettingsStore({ homeDir: home });

    const ok = setSettings({ ...DEFAULT_SETTINGS, showLogo: false });

    expect(ok).toBe(true);
    expect(getSettings().showLogo).toBe(false);
    expect(loadSettings(home).showLogo).toBe(false);
  });

  it("updateSetting changes one key and leaves the rest", () => {
    configureSettingsStore({ homeDir: makeHome() });

    const ok = updateSetting("theme", "high-contrast");

    expect(ok).toBe(true);
    expect(getSettings().theme).toBe("high-contrast");
    expect(getSettings().showStatusBar).toBe(DEFAULT_SETTINGS.showStatusBar);
  });

  it("normalises an out-of-range value back to a default", () => {
    configureSettingsStore({ homeDir: makeHome() });
    // Force a bogus enum value past the type system, as a hand-edit might.
    updateSetting("theme", "chartreuse" as unknown as TuiSettings["theme"]);
    expect(getSettings().theme).toBe(DEFAULT_SETTINGS.theme);
  });

  it("notifies every subscriber synchronously with the new value", () => {
    configureSettingsStore({ homeDir: makeHome() });
    const a = vi.fn();
    const b = vi.fn();
    subscribeSettings(a);
    subscribeSettings(b);

    updateSetting("showTimestamps", true);

    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
    expect(a.mock.calls[0]![0].showTimestamps).toBe(true);
    expect(b.mock.calls[0]![0].showTimestamps).toBe(true);
    // The value handed to subscribers is exactly what getSettings now returns.
    expect(a.mock.calls[0]![0]).toBe(getSettings());
  });

  it("does not notify on a plain read", () => {
    configureSettingsStore({ homeDir: makeHome() });
    const fn = vi.fn();
    subscribeSettings(fn);
    getSettings();
    getSettings();
    expect(fn).not.toHaveBeenCalled();
  });
});

describe("failed save", () => {
  it("still updates memory and notifies but returns false", () => {
    configureSettingsStore({ homeDir: makeUnwritableHome() });
    const fn = vi.fn();
    subscribeSettings(fn);

    const ok = setSettings({ ...DEFAULT_SETTINGS, density: "compact" });

    expect(ok).toBe(false);
    expect(getSettings().density).toBe("compact");
    expect(fn).toHaveBeenCalledTimes(1);
    expect(fn.mock.calls[0]![0].density).toBe("compact");
  });
});

describe("subscriptions", () => {
  it("unsubscribe stops delivery", () => {
    configureSettingsStore({ homeDir: makeHome() });
    const fn = vi.fn();
    const off = subscribeSettings(fn);

    updateSetting("showLogo", false);
    off();
    updateSetting("showLogo", true);

    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("a throwing subscriber does not block others or the setter", () => {
    configureSettingsStore({ homeDir: makeHome() });
    const boom = vi.fn(() => {
      throw new Error("subscriber blew up");
    });
    const after = vi.fn();
    subscribeSettings(boom);
    subscribeSettings(after);

    const ok = setSettings({ ...DEFAULT_SETTINGS, showLogo: false });

    expect(ok).toBe(true);
    expect(boom).toHaveBeenCalledTimes(1);
    expect(after).toHaveBeenCalledTimes(1);
  });

  it("unsubscribe is idempotent", () => {
    configureSettingsStore({ homeDir: makeHome() });
    const fn = vi.fn();
    const off = subscribeSettings(fn);
    off();
    off();
    updateSetting("showLogo", false);
    expect(fn).not.toHaveBeenCalled();
  });
});

describe("reloadSettings", () => {
  it("re-reads disk and notifies", () => {
    const home = makeHome();
    configureSettingsStore({ homeDir: home });
    // Persist once so the `.0sec` directory and file exist on disk.
    setSettings({ ...DEFAULT_SETTINGS, theme: "dark" });
    const fn = vi.fn();
    subscribeSettings(fn);

    // An external edit to the file the store is not aware of.
    writeFileSync(
      join(home, ".0sec", "tui-settings.json"),
      JSON.stringify({ ...DEFAULT_SETTINGS, theme: "ansi" }),
      "utf8",
    );

    const reloaded = reloadSettings();

    expect(reloaded.theme).toBe("ansi");
    expect(getSettings().theme).toBe("ansi");
    expect(fn).toHaveBeenCalledTimes(1);
  });
});

describe("concurrency", () => {
  it("two rapid updates leave the store consistent and both notify", () => {
    configureSettingsStore({ homeDir: makeHome() });
    const fn = vi.fn();
    subscribeSettings(fn);

    updateSetting("showLogo", false);
    updateSetting("showStatusBar", false);

    expect(fn).toHaveBeenCalledTimes(2);
    const final = getSettings();
    expect(final.showLogo).toBe(false);
    expect(final.showStatusBar).toBe(false);
  });
});

/**
 * `useSettings` cannot be rendered here: this package has no React renderer or
 * DOM environment in its test setup (vitest runs in node, and only `.test.ts`
 * is collected, so no `.tsx` renderer harness). The hook is a thin
 * `useSyncExternalStore(subscribeSettings, getSettings, getSettings)`, so its
 * whole contract is the store primitives it is given — which are exercised
 * above. Here we assert those primitives compose the way the hook needs:
 * `getSettings` is a stable snapshot between changes, and `subscribeSettings`
 * fires then cleans up. That is exactly what `useSyncExternalStore` relies on
 * to re-render on change and unsubscribe on unmount.
 */
describe("useSettings (store contract behind the hook)", () => {
  it("is exported as a function", () => {
    expect(typeof useSettings).toBe("function");
  });

  it("snapshot is referentially stable until a change, then swaps", () => {
    configureSettingsStore({ homeDir: makeHome() });
    const first = getSettings();
    expect(getSettings()).toBe(first);
    updateSetting("showLogo", !first.showLogo);
    expect(getSettings()).not.toBe(first);
  });

  it("the subscribe primitive delivers a change then stops after cleanup", () => {
    configureSettingsStore({ homeDir: makeHome() });
    const onStoreChange = vi.fn();
    const cleanup = subscribeSettings(onStoreChange);

    updateSetting("showLogo", false);
    expect(onStoreChange).toHaveBeenCalledTimes(1);

    cleanup(); // what React calls on unmount
    updateSetting("showLogo", true);
    expect(onStoreChange).toHaveBeenCalledTimes(1);
  });
});
