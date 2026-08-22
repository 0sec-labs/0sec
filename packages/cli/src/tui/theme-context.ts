/**
 * The active colour palette, derived from the live settings and delivered
 * subscribably.
 *
 * Until now the `theme` setting was read by nothing: components imported
 * hardcoded hex from `ui/theme.ts`, so switching themes changed a stored value
 * that no pixel ever consulted. This layer closes that gap. It selects a
 * palette from the registry in `themes.ts` by name and hands it to consumers,
 * re-rendering them when the setting changes — but it changes no colour VALUE.
 * Every hex still lives in `themes.ts`; this only chooses and delivers one.
 *
 * `getTheme` is already total (an unknown or hand-corrupted name degrades to
 * the default), so nothing here needs to guard the name.
 */

import {
  degradePalette,
  detectColorDepth,
  getTheme,
  type ColorDepth,
  type Theme,
} from "./themes.js";
import type { TuiSettings } from "./settings.js";
import { useSettings } from "./settings-store.js";

export type { Theme } from "./themes.js";

/**
 * The terminal's colour depth, inferred once from the environment at module
 * load. `themes.ts` is explicit that this is inference from env vars only — no
 * terminal query, no terminfo — so it is a safe, side-effect-free read done a
 * single time. `degradePalette` snaps a palette's tokens onto the values a
 * 16- or 256-colour terminal can actually show; at truecolor (and "none") it
 * returns the palette untouched, which is the common case.
 */
const colorDepth: ColorDepth = detectColorDepth(process.env);

/**
 * Degraded palettes are cached by theme name so a given theme always yields
 * the *same* object reference across renders. That stability matters: a fresh
 * object every render would defeat downstream memoisation and prop-identity
 * checks even when the theme never changed.
 */
const paletteCache = new Map<string, Theme>();

function paletteFor(name: TuiSettings["theme"]): Theme {
  let cached = paletteCache.get(name);
  if (!cached) {
    cached = degradePalette(getTheme(name), colorDepth);
    paletteCache.set(name, cached);
  }
  return cached;
}

/**
 * Pure selection of the palette for a settings object: `getTheme(settings.theme)`,
 * no environment, no degradation. Use this when you already hold a settings
 * value and want the theme it names (tests, non-React call sites). React
 * components want `useTheme`, which also applies the terminal-capability
 * degrade and delivers changes live.
 */
export function activeTheme(settings: TuiSettings): Theme {
  return getTheme(settings.theme);
}

/**
 * React hook: the live palette. Subscribes to the settings store, so a theme
 * change re-renders every consumer, and applies the terminal-capability
 * degrade for the detected colour depth. Returns a stable reference while the
 * theme is unchanged.
 */
export function useTheme(): Theme {
  const settings = useSettings();
  return paletteFor(settings.theme);
}
