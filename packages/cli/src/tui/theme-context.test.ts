import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { DEFAULT_SETTINGS, type TuiSettings } from "./settings.js";
import {
  __resetSettingsStoreForTests,
  configureSettingsStore,
  getSettings,
  updateSetting,
} from "./settings-store.js";
import { DEFAULT_THEME_NAME, THEMES } from "./themes.js";
import { activeTheme, useTheme } from "./theme-context.js";

const tempHomes: string[] = [];

function makeHome(): string {
  const dir = mkdtempSync(join(tmpdir(), "0sec-theme-context-"));
  tempHomes.push(dir);
  return dir;
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

describe("activeTheme", () => {
  it("returns the palette named by the setting", () => {
    for (const name of ["dark", "light", "high-contrast", "ansi"] as const) {
      expect(activeTheme({ ...DEFAULT_SETTINGS, theme: name })).toBe(THEMES[name].palette);
    }
  });

  it("degrades an unknown theme name to the default palette", () => {
    const settings = {
      ...DEFAULT_SETTINGS,
      theme: "chartreuse" as unknown as TuiSettings["theme"],
    };
    expect(activeTheme(settings)).toBe(THEMES[DEFAULT_THEME_NAME].palette);
  });

  it("changes no colour values — it only selects an existing palette", () => {
    // Every token in the returned palette is identical to the registry's.
    const palette = activeTheme({ ...DEFAULT_SETTINGS, theme: "light" });
    expect(palette).toEqual(THEMES.light.palette);
  });
});

describe("live selection through the store", () => {
  it("follows a theme change made on the store", () => {
    configureSettingsStore({ homeDir: makeHome() });
    expect(activeTheme(getSettings())).toBe(THEMES[DEFAULT_THEME_NAME].palette);

    updateSetting("theme", "high-contrast");
    expect(activeTheme(getSettings())).toBe(THEMES["high-contrast"].palette);
  });
});

/**
 * `useTheme` cannot be rendered here (no React renderer / DOM env; see the note
 * in settings-store.test.ts). It is `paletteFor(useSettings().theme)`, so its
 * contract is: subscribe to the store (covered by the store tests) and map the
 * current theme name to a palette (covered by `activeTheme` above, which shares
 * the same `getTheme` selection). We assert only that it is exported.
 *
 * Terminal-capability handling: `useTheme` applies `degradePalette` for the
 * colour depth `detectColorDepth(process.env)` infers once at module load. On a
 * truecolor terminal — the default in this test env — `degradePalette` returns
 * the palette unchanged, which is why `activeTheme` (no degrade) and the palette
 * the hook would return are identical here. The degrade path itself is covered
 * by `themes.test.ts`.
 */
describe("useTheme", () => {
  it("is exported as a function", () => {
    expect(typeof useTheme).toBe("function");
  });
});
