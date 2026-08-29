/**
 * Selectable colour themes for the interactive console.
 *
 * The console's palette used to be twelve loose `export const` hex strings in
 * `ui/theme.ts`, imported directly by `chat-screen.tsx` and `run.tsx`. That
 * shape has exactly one palette in it: there is nowhere to put a second set of
 * values, and nowhere to assert anything about the first set. The result was a
 * console that is unreadable on a light terminal, that renders `ERROR` at
 * 3.77:1 on its own panels, and that signals tool success and tool failure with
 * two colours a deuteranope cannot tell apart by hue.
 *
 * So the palette becomes a *table* — `THEMES` — keyed by name, with the token
 * set expressed as a type so a new token cannot be added to one theme and
 * forgotten in the other three. Everything else here exists to make that table
 * checkable rather than decorative:
 *
 *   - `contrastRatio` / `relativeLuminance` are the WCAG 2.2 definitions, so
 *     "is this readable" is arithmetic a test can run, not a judgement call.
 *   - `validateTheme` runs the completeness and contrast checks over any
 *     candidate palette, including one a user might supply later.
 *   - `CONTRAST_WAIVERS` enumerates — with measured ratios — the places the
 *     default palette knowingly fails AA. They are recorded, not hidden: the
 *     test asserts the measured ratio still matches the recorded one, so
 *     changing the default palette fails loudly in either direction.
 *
 * Two constraints drove the palette design and are worth stating up front.
 *
 * First, semantic colour must survive colour blindness. `SUCCESS`, `WARNING`
 * and `ERROR` mark tool outcomes; red/green at equal luminance is a blank to
 * roughly 8% of men. Every theme therefore separates the three by *luminance*
 * as well as hue — see `MIN_SEMANTIC_CONTRAST`.
 *
 * Second, a truecolor hex is a lie on a 16-colour terminal. `detectColorDepth`
 * and `degradePalette` handle that honestly and narrowly; read the "Terminal
 * capability" section of `THEMES.md` for exactly what they do and do not do.
 *
 * The colour/validation core of this module is pure: no I/O, no React, no
 * process access; the one function that reads the environment takes it as an
 * argument. The single exception is the clearly-fenced "Installed themes"
 * section at the foot of the file, which reads validated theme palettes off disk
 * (`~/.0sec/themes/`). That I/O is total and fail-soft — an unreadable dir or a
 * corrupt file is skipped, never thrown — so it cannot take a session down, and
 * the pure functions above it never call into it.
 */

import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import { homeStateDir } from "@0sec/shared";

import type { SettingDef } from "./settings.js";
import { loadUserThemes } from "./user-themes.js";

/* ------------------------------------------------------------------ tokens */

/**
 * Tokens that are painted *behind* text. Derived from the actual call sites:
 * `backgroundColor={CANVAS}` on the two screen roots, `backgroundColor={PANEL}`
 * and `backgroundColor={PANEL_ALT}` on cards and inset rows. `PRIMARY`,
 * `ACCENT` and `ERROR` also appear as `backgroundColor` in `chat-screen.tsx`,
 * but only on `width={1}` rails that never carry text, so they are not
 * background tokens for contrast purposes.
 */
export const BACKGROUND_TOKENS = ["CANVAS", "PANEL", "PANEL_ALT"] as const;

/**
 * Tokens used as `fg` on text. These are the ones WCAG 1.4.3 applies to, and
 * the ones the 4.5:1 sweep covers.
 */
export const TEXT_TOKENS = [
  "TEXT",
  "MUTED",
  "PRIMARY",
  "ACCENT",
  "BRAND",
  "SUCCESS",
  "WARNING",
  "ERROR",
  "INFO",
] as const;

/**
 * Non-text UI chrome. `BORDER` is only ever a `borderColor`; it draws box-
 * drawing glyphs that carry no information a reader must decode. WCAG 2.2
 * governs it under 1.4.11 (non-text contrast, 3:1), not 1.4.3 (text, 4.5:1),
 * and holding a hairline rule to text contrast would make every panel edge as
 * loud as the text inside it. The distinction is enforced, not assumed: see
 * `MIN_CHROME_CONTRAST` and the waiver for the default theme.
 */
export const CHROME_TOKENS = ["BORDER"] as const;

/**
 * Semantic background-layering tokens, added on top of the original
 * `CANVAS`/`PANEL`/`PANEL_ALT` trio to give consumers role-named surfaces:
 *
 *   - `background`  the root/app background (mirrors `CANVAS`)
 *   - `surface`     the background of a bordered section/panel (mirrors `PANEL`)
 *   - `surfaceAlt`  a slightly offset surface for nested/alternating blocks
 *                   (mirrors `PANEL_ALT`)
 *   - `overlay`     the background for a full-screen overlay (settings/model
 *                   screens, pickers) — a step past `surfaceAlt` so a floating
 *                   panel reads as "on top" of the transcript beneath it.
 *
 * On *light* themes `surface` is a few percent darker than `background` and
 * `surfaceAlt` darker still, so a low-contrast hairline still reads as a
 * section edge; on *dark* themes the step goes the other way (each surface a
 * touch lighter). These are painted-behind tokens, never text, and every value
 * sits inside the luminance band the text tokens are already validated against,
 * so they are checked for completeness and well-formedness but not swept for
 * text contrast (that sweep runs against `BACKGROUND_TOKENS`, which they mirror).
 */
export const LAYER_TOKENS = ["background", "surface", "surfaceAlt", "overlay"] as const;

export type BackgroundToken = (typeof BACKGROUND_TOKENS)[number];
export type TextToken = (typeof TEXT_TOKENS)[number];
export type ChromeToken = (typeof CHROME_TOKENS)[number];
export type LayerToken = (typeof LAYER_TOKENS)[number];
export type ThemeToken = BackgroundToken | TextToken | ChromeToken | LayerToken;

/** Every token, in a stable order, for iteration and validation. */
export const THEME_TOKENS: readonly ThemeToken[] = [
  ...BACKGROUND_TOKENS,
  ...TEXT_TOKENS,
  ...CHROME_TOKENS,
  ...LAYER_TOKENS,
];

/**
 * A complete palette. Mapped over `ThemeToken` on purpose: adding a token to
 * the union makes every theme literal below fail to compile until it is
 * filled in, which is the "no gaps" guarantee the tests then re-check at
 * runtime for anything typed loosely.
 */
export type Theme = { readonly [K in ThemeToken]: string };

/* ---------------------------------------------------------- colour numbers */

export interface Rgb {
  readonly r: number;
  readonly g: number;
  readonly b: number;
}

const HEX_RE = /^#[0-9a-fA-F]{6}$/;

/**
 * Parse `#RRGGBB`. Returns `null` rather than throwing so the validator can
 * report a malformed value as an issue instead of exploding mid-sweep.
 *
 * Deliberately strict: no 3-digit shorthand, no 8-digit alpha, no named
 * colours. OpenTUI is handed these strings verbatim and a terminal has no
 * alpha channel, so accepting forms we cannot render would only move the
 * failure further from its cause.
 */
export function parseHex(hex: string): Rgb | null {
  if (typeof hex !== "string" || !HEX_RE.test(hex)) return null;
  return {
    r: Number.parseInt(hex.slice(1, 3), 16),
    g: Number.parseInt(hex.slice(3, 5), 16),
    b: Number.parseInt(hex.slice(5, 7), 16),
  };
}

/** True when `value` is a hex colour this module can render and measure. */
export function isHexColor(value: unknown): value is string {
  return typeof value === "string" && HEX_RE.test(value);
}

/** sRGB 8-bit channel to linear light. WCAG 2.2 definition. */
function linearize(channel: number): number {
  const c = channel / 255;
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

/**
 * WCAG 2.2 relative luminance, 0 (black) to 1 (white).
 *
 * Throws on malformed input. Callers that cannot guarantee a good hex should
 * go through `parseHex` first; the validator does.
 */
export function relativeLuminance(hex: string): number {
  const rgb = parseHex(hex);
  if (!rgb) throw new TypeError(`relativeLuminance: not a #RRGGBB colour: ${String(hex)}`);
  return 0.2126 * linearize(rgb.r) + 0.7152 * linearize(rgb.g) + 0.0722 * linearize(rgb.b);
}

/**
 * WCAG 2.2 contrast ratio, 1 (identical) to 21 (black on white). Symmetric —
 * argument order does not matter.
 */
export function contrastRatio(a: string, b: string): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  const hi = Math.max(la, lb);
  const lo = Math.min(la, lb);
  return (hi + 0.05) / (lo + 0.05);
}

/* -------------------------------------------------------------- thresholds */

/** WCAG 2.2 SC 1.4.3 (AA), normal-size text. The bar for every `TEXT_TOKEN`. */
export const MIN_TEXT_CONTRAST = 4.5;

/** WCAG 2.2 SC 1.4.11 (non-text contrast). The bar for `BORDER`. */
export const MIN_CHROME_CONTRAST = 3;

/** WCAG 2.2 SC 1.4.6 (AAA), normal-size text. The bar the `high-contrast` theme holds itself to. */
export const AAA_TEXT_CONTRAST = 7;

/**
 * Minimum contrast ratio *between* any two of `SUCCESS` / `WARNING` / `ERROR`.
 *
 * Hue alone does not distinguish them: deuteranopia and protanopia collapse
 * red-green, and green-yellow is the classic residual confusion. Requiring a
 * luminance step means the three read as three even in greyscale.
 *
 * The value is a floor, not a target. The preserved default measures 1.19:1
 * across its `SUCCESS`/`WARNING` pair; the tightest of the designed themes is
 * `paper` at 1.16:1. Every theme clears the 1.15:1 floor. If any theme is ever
 * allowed to drop below it, raise the offending palette rather than this bar.
 */
export const MIN_SEMANTIC_CONTRAST = 1.15;

/* ----------------------------------------------------------------- palettes */

/**
 * `0sec Dark` — the palette shipped today, byte-for-byte from `ui/theme.ts`.
 *
 * It is the default because an existing operator must see no change unless
 * they opt in; a theme system that silently restyles everyone's console on
 * upgrade is a regression wearing a feature's clothes. It is therefore also
 * the one palette here that is *not* free to be fixed, and it carries the only
 * contrast waivers in the module (see `CONTRAST_WAIVERS`).
 */
const DARK: Theme = {
  CANVAS: "#080808",
  PANEL: "#1C1A18",
  PANEL_ALT: "#2A2724",
  BORDER: "#302E2C",
  TEXT: "#F3EEE9",
  MUTED: "#A79A8D",
  PRIMARY: "#FFFFFF",
  ACCENT: "#F3EEE9",
  BRAND: "#A78BFA",
  SUCCESS: "#22C55E",
  WARNING: "#EAB308",
  ERROR: "#F4695E",
  INFO: "#B8AFA6",
  background: "#080808",
  surface: "#111111",
  surfaceAlt: "#171515",
  overlay: "#1C1A18",
};

/**
 * `Standard` — the light theme, built so bordered sections are separable.
 *
 * The complaint this answers is that a light console reads as one flat sheet:
 * borders are near-invisible and every panel is the same white. So the three
 * background layers are deliberately *stepped* — `background` (near-white),
 * `surface` a few percent darker, `surfaceAlt` darker still — and `BORDER` is a
 * mid slate-grey that clears the 3:1 non-text bar on all three. A section now
 * reads as a section by fill even before the border is drawn.
 *
 * Neutral, not warm: the highlight (`PRIMARY`/`ACCENT`) is a near-black grey,
 * never orange — the mono-chrome discipline the dark theme keeps with white.
 * Foregrounds are all dark (anything lighter than L≈0.13 cannot reach 4.5:1
 * against `surfaceAlt`), so the semantic trio is separated by *darkness*:
 * `SUCCESS` mid, `WARNING` darker, `ERROR` darkest. `INFO` is a slate blue,
 * the one strongly-separated hue not used for a semantic.
 */
const LIGHT: Theme = {
  CANVAS: "#FCFCFD",
  PANEL: "#EFF1F4",
  PANEL_ALT: "#E2E5EA",
  BORDER: "#7A828F",
  TEXT: "#191C22",
  MUTED: "#565D68",
  PRIMARY: "#111318",
  ACCENT: "#2E333B",
  BRAND: "#6D28D9",
  SUCCESS: "#136B31",
  WARNING: "#654A00",
  ERROR: "#74130B",
  INFO: "#1F4E7A",
  background: "#FCFCFD",
  surface: "#EFF1F4",
  surfaceAlt: "#E2E5EA",
  overlay: "#D7DBE1",
};

/**
 * `Contrast` — every text token at WCAG AAA (7:1) or better.
 *
 * Pure-black canvas, near-white text, and foregrounds pushed up until the
 * weakest of them clears 7:1 rather than 4.5:1. The `high-contrast` theme is
 * the one that is *tested* against `AAA_TEXT_CONTRAST`, so the name is a
 * guarantee rather than a mood. `BORDER` is a mid grey at 8.6:1 — visible
 * chrome is the point here, not a hairline.
 */
const HIGH_CONTRAST: Theme = {
  CANVAS: "#000000",
  PANEL: "#0B0B0B",
  PANEL_ALT: "#161616",
  BORDER: "#B3B3B3",
  TEXT: "#FFFFFF",
  MUTED: "#BCBCBC",
  PRIMARY: "#FFFFFF",
  ACCENT: "#E6E6E6",
  BRAND: "#C4B5FD",
  SUCCESS: "#3AE483",
  WARNING: "#FFE635",
  ERROR: "#FC8979",
  INFO: "#82DAFF",
  background: "#000000",
  surface: "#0B0B0B",
  surfaceAlt: "#161616",
  overlay: "#1E1E1E",
};

/**
 * `ANSI 16` — every value is a canonical xterm 16-colour entry.
 *
 * The point is that `nearestAnsi16` is the *identity* on this palette: on a
 * terminal that approximates truecolor down to its 16 slots, this theme lands
 * exactly where it was drawn instead of drifting somewhere unreadable. That
 * constraint costs two things, both real and both documented in `THEMES.md`:
 *
 *   - all three background tokens are index 0, because the only other dark-ish
 *     slot is `#808080`, and white on `#808080` is 3.95:1 — below AA. Panels
 *     are therefore delimited by `BORDER` glyphs, not by fill.
 *   - `MUTED` and `BORDER` share index 8. Sixteen slots do not stretch to nine
 *     distinct roles once index 12 (`#0000FF`, 2.44:1 on black) is ruled out
 *     as text.
 *
 * Semantic separation is the best of any theme here — 1.28:1 minimum, 3.72:1
 * between `WARNING` and `ERROR` — because the bright ANSI primaries are far
 * apart in luminance by construction.
 */
const ANSI: Theme = {
  CANVAS: "#000000",
  PANEL: "#000000",
  PANEL_ALT: "#000000",
  BORDER: "#808080",
  TEXT: "#FFFFFF",
  MUTED: "#808080",
  PRIMARY: "#FFFFFF",
  ACCENT: "#C0C0C0",
  BRAND: "#FF00FF",
  SUCCESS: "#00FF00",
  WARNING: "#FFFF00",
  ERROR: "#FF0000",
  INFO: "#C0C0C0",
  background: "#000000",
  surface: "#000000",
  surfaceAlt: "#000000",
  overlay: "#000000",
};

/**
 * `Midnight` — a deep blue-black dark theme.
 *
 * Cool where `dark` is warm: the surfaces carry a faint blue cast and step up
 * in luminance so panels separate. Highlight is white, accents near-white — no
 * cyan, no orange. The semantic trio is muted (a soft green, a gold, a rose
 * red) but held apart by luminance for colour-blind separation.
 */
const MIDNIGHT: Theme = {
  CANVAS: "#0A0E14",
  PANEL: "#121824",
  PANEL_ALT: "#1B2333",
  BORDER: "#6B7688",
  TEXT: "#E8ECF2",
  MUTED: "#93A0B5",
  PRIMARY: "#FFFFFF",
  ACCENT: "#DDE3EC",
  BRAND: "#A78BFA",
  SUCCESS: "#57BE86",
  WARNING: "#E2C14E",
  ERROR: "#F0686C",
  INFO: "#8FB4E0",
  background: "#0A0E14",
  surface: "#121824",
  surfaceAlt: "#1B2333",
  overlay: "#232D40",
};

/**
 * `Slate` — a neutral grey dark theme.
 *
 * No hue in the chrome at all: pure grey surfaces, a grey border, a white
 * highlight. The most restrained of the dark themes; the only colour is in the
 * semantic trio, kept muted and luminance-separated.
 */
const SLATE: Theme = {
  CANVAS: "#141516",
  PANEL: "#1D1F21",
  PANEL_ALT: "#26292C",
  BORDER: "#6E7379",
  TEXT: "#E9EAEC",
  MUTED: "#9A9EA4",
  PRIMARY: "#FFFFFF",
  ACCENT: "#D8DADD",
  BRAND: "#A78BFA",
  SUCCESS: "#5BC088",
  WARNING: "#DEBB4E",
  ERROR: "#EB767A",
  INFO: "#9FB3C8",
  background: "#141516",
  surface: "#1D1F21",
  surfaceAlt: "#26292C",
  overlay: "#303438",
};

/**
 * `Paper` — a warm off-white light theme.
 *
 * The counterpart to `Standard` for readers who prefer a warm page. Surfaces
 * are a stepped warm off-white so sections separate; the highlight is a warm
 * near-black, never orange. Foregrounds are dark, the semantic trio separated
 * by darkness.
 */
const PAPER: Theme = {
  CANVAS: "#FBF7EF",
  PANEL: "#F1EADC",
  PANEL_ALT: "#EAE1CF",
  BORDER: "#7C7158",
  TEXT: "#201C15",
  MUTED: "#5A5140",
  PRIMARY: "#1A1712",
  ACCENT: "#3A342A",
  BRAND: "#5B2A86",
  SUCCESS: "#155E2C",
  WARNING: "#78560E",
  ERROR: "#8A2015",
  INFO: "#2A5578",
  background: "#FBF7EF",
  surface: "#F1EADC",
  surfaceAlt: "#EAE1CF",
  overlay: "#DACFB8",
};

/**
 * `Mono Dim` — a very low-contrast dark theme for long sessions.
 *
 * Minimalist and quiet: the whole palette sits in a narrow grey band so nothing
 * shouts. Every text token still clears AA (4.5:1) — "low contrast" means muted,
 * not illegible — and the border still clears the 3:1 non-text bar so sections
 * remain separable. Semantics are desaturated but luminance-separated.
 */
const MONO_DIM: Theme = {
  CANVAS: "#161616",
  PANEL: "#1E1E1E",
  PANEL_ALT: "#262626",
  BORDER: "#787878",
  TEXT: "#C9C9C9",
  MUTED: "#8C8C8C",
  PRIMARY: "#E4E4E4",
  ACCENT: "#B8B8B8",
  BRAND: "#A99BC9",
  SUCCESS: "#63AE7B",
  WARNING: "#C9B25E",
  ERROR: "#D47878",
  INFO: "#93A7BC",
  background: "#161616",
  surface: "#1E1E1E",
  surfaceAlt: "#262626",
  overlay: "#2E2E2E",
};

/**
 * `Swiss` — a red-forward Swiss-flag palette for the Swiss Applied AI
 * Cybersecurity Research Lab: Swiss red framing crisp white over a near-black
 * red-tinted ground.
 *
 * Red is structural here, not just an accent. `BORDER` is a mid Swiss red, so
 * every bordered box — frame, cards, panels, sidebars — reads red at rest; the
 * `CANVAS`/`PANEL`/surface grounds are near-black but tinted red rather than
 * neutral grey, and even `MUTED` (secondary text) is a dusty rose red. `TEXT`
 * stays a crisp near-white, and the highlight — `PRIMARY`, `ACCENT`, `BRAND`
 * and `ERROR` — is strong Swiss red. The flag's `#D52B1E` is too dark to clear
 * 4.5:1 on a near-black surface, so the highlight red is tuned up to `#F26257`
 * — unmistakably the same red, now AA-legible as text on every surface. `ERROR`
 * shares that red (red *is* the error colour here); `SUCCESS`/`WARNING` are
 * pulled apart from it by luminance so the semantic trio still survives colour
 * blindness, and `INFO` is the one cool hue.
 */
const SWISS: Theme = {
  CANVAS: "#120809",
  PANEL: "#1C0C0E",
  PANEL_ALT: "#260F12",
  BORDER: "#D9534C",
  TEXT: "#FBF3F3",
  MUTED: "#D69B9E",
  PRIMARY: "#F26257",
  ACCENT: "#F58379",
  BRAND: "#F26257",
  SUCCESS: "#4FB477",
  WARNING: "#E0A83C",
  ERROR: "#F26257",
  INFO: "#8FB4E0",
  background: "#120809",
  surface: "#1C0C0E",
  surfaceAlt: "#260F12",
  overlay: "#301418",
};

/* ----------------------------------------------------------------- registry */

export const THEME_NAMES = [
  "dark",
  "light",
  "high-contrast",
  "ansi",
  "midnight",
  "slate",
  "paper",
  "mono-dim",
  "swiss",
] as const;
export type ThemeName = (typeof THEME_NAMES)[number];

export const DEFAULT_THEME_NAME: ThemeName = "dark";

/** Whether a theme is meant for a dark or a light terminal — for picker grouping. */
export type ThemeMode = "dark" | "light";

export interface ThemeEntry {
  /** Built-in theme name, or an installed theme id (an arbitrary safe string). */
  readonly name: string;
  /** Short human label for the settings UI. */
  readonly label: string;
  /** One line explaining who this theme is for. */
  readonly description: string;
  /** Dark- or light-terminal theme, so a picker can group and preview them. */
  readonly mode: ThemeMode;
  readonly palette: Theme;
}

export const THEMES: Readonly<Record<ThemeName, ThemeEntry>> = {
  dark: {
    name: "dark",
    label: "Carbon",
    description: "The shipped default. Warm dark surfaces, neutral white highlight.",
    mode: "dark",
    palette: DARK,
  },
  light: {
    name: "light",
    label: "Standard",
    description: "Light theme with clearly stepped section surfaces. Neutral highlight.",
    mode: "light",
    palette: LIGHT,
  },
  "high-contrast": {
    name: "high-contrast",
    label: "Contrast",
    description: "Pure black canvas, every text colour at WCAG AAA (7:1) or better.",
    mode: "dark",
    palette: HIGH_CONTRAST,
  },
  ansi: {
    name: "ansi",
    label: "ANSI 16",
    description: "Only the 16 standard terminal colours. For terminals without truecolor.",
    mode: "dark",
    palette: ANSI,
  },
  midnight: {
    name: "midnight",
    label: "Midnight",
    description: "Deep blue-black dark. Cool stepped surfaces, white highlight.",
    mode: "dark",
    palette: MIDNIGHT,
  },
  slate: {
    name: "slate",
    label: "Slate",
    description: "Neutral grey dark. No hue in the chrome, white highlight.",
    mode: "dark",
    palette: SLATE,
  },
  paper: {
    name: "paper",
    label: "Paper",
    description: "Warm off-white light. Stepped paper surfaces, warm near-black highlight.",
    mode: "light",
    palette: PAPER,
  },
  "mono-dim": {
    name: "mono-dim",
    label: "Mono Dim",
    description: "Very low-contrast dark, minimalist. Muted but still AA-legible.",
    mode: "dark",
    palette: MONO_DIM,
  },
  swiss: {
    name: "swiss",
    label: "Swiss",
    description: "Swiss-flag red on near-black, crisp white text. For the Swiss Applied AI Cybersecurity Research Lab.",
    mode: "dark",
    palette: SWISS,
  },
};

/** Narrowing guard for anything read off disk, a flag, or an env var. */
export function isThemeName(value: unknown): value is ThemeName {
  return typeof value === "string" && (THEME_NAMES as readonly string[]).includes(value);
}

/**
 * Look up a palette by name.
 *
 * Total by design. This is called from the render path with a value that came
 * out of a hand-editable settings file, so an unknown or missing name degrades
 * to the default — the same contract `normalizeSettings` already holds itself
 * to. A typo in `tui-settings.json` must not be able to take down a session.
 */
export function getTheme(name: unknown): Theme {
  return getThemeEntry(name).palette;
}

/**
 * As `getTheme`, but returns the label and description too. Also total.
 *
 * Resolution order: a built-in name wins, then a currently-loaded INSTALLED
 * theme id, then the default. Installed themes only resolve once the cache has
 * been populated (see `ensureInstalledThemesLoaded`), which the settings load
 * path does before any render; this function itself performs NO I/O so it stays
 * deterministic and safe to call from the render path.
 */
export function getThemeEntry(name: unknown): ThemeEntry {
  if (isThemeName(name)) return THEMES[name];
  if (typeof name === "string" && installedThemes !== null) {
    const installed = installedThemes.get(name);
    if (installed) return installed;
  }
  return THEMES[DEFAULT_THEME_NAME];
}

/**
 * Theme-aware replacement for `severityTone` in `ui/theme.ts`, which closes
 * over the module-level constants and so cannot follow a theme switch.
 * Same mapping, same fallback.
 */
export function severityToneFor(palette: Theme, severity: string): string {
  switch (String(severity).toLowerCase()) {
    case "critical":
    case "high":
      return palette.ERROR;
    case "medium":
      return palette.WARNING;
    case "low":
      return palette.INFO;
    default:
      return palette.MUTED;
  }
}

/* ------------------------------------------------------------------ waivers */

export interface ContrastWaiver {
  readonly theme: ThemeName;
  readonly token: ThemeToken;
  readonly against: BackgroundToken;
  /** Ratio measured at the time the waiver was written, to 2 decimal places. */
  readonly ratio: number;
  readonly reason: string;
}

/**
 * Known, deliberate failures against `MIN_TEXT_CONTRAST` / `MIN_CHROME_CONTRAST`.
 *
 * Every entry is in the `dark` theme, and every one exists for the same
 * reason: `dark` is required to be byte-identical to today's `ui/theme.ts` so
 * that upgrading does not restyle anybody's console. Those two requirements —
 * "preserve exactly" and "meet AA" — are in direct conflict for two tokens,
 * and preserving won, because the fix is one line the operator can take
 * whenever they are willing to accept a visible change (`THEMES.md` gives the
 * replacement values).
 *
 * They are enumerated here rather than excluded by a lowered threshold so that
 * the failure stays counted, stays visible in the test output, and stays
 * pinned: the test asserts each measured ratio still matches the number
 * recorded here, so editing the default palette breaks the build whether it
 * makes contrast better or worse.
 */
export const CONTRAST_WAIVERS: readonly ContrastWaiver[] = [
  {
    theme: "dark",
    token: "BORDER",
    against: "CANVAS",
    ratio: 1.48,
    reason:
      "Preserved default: #302E2C is an intentional hairline, well below even the 3:1 " +
      "non-text bar. #8C8580 reaches 3:1 on all three surfaces if visible panel edges are wanted.",
  },
  {
    theme: "dark",
    token: "BORDER",
    against: "PANEL",
    ratio: 1.28,
    reason: "Preserved default: see the CANVAS waiver for BORDER.",
  },
  {
    theme: "dark",
    token: "BORDER",
    against: "PANEL_ALT",
    ratio: 1.1,
    reason: "Preserved default: see the CANVAS waiver for BORDER.",
  },
];

/** True when this exact theme/token/background triple is a recorded waiver. */
export function isWaived(
  theme: ThemeName,
  token: ThemeToken,
  against: BackgroundToken,
): boolean {
  return CONTRAST_WAIVERS.some(
    (w) => w.theme === theme && w.token === token && w.against === against,
  );
}

/* --------------------------------------------------------------- validation */

/** The three tool-outcome colours, as the pairs that must stay separable. */
export const SEMANTIC_PAIRS: readonly (readonly [TextToken, TextToken])[] = [
  ["SUCCESS", "WARNING"],
  ["SUCCESS", "ERROR"],
  ["WARNING", "ERROR"],
];

export type ThemeIssueKind = "missing" | "extra" | "malformed" | "contrast" | "semantic";

export interface ThemeIssue {
  readonly kind: ThemeIssueKind;
  /** The offending token, or `"*"` for a whole-palette problem. */
  readonly token: ThemeToken | string;
  /** Background the token was measured against, for `kind === "contrast"`. */
  readonly against?: BackgroundToken;
  /** Measured ratio, for `kind === "contrast"` and `kind === "semantic"`. */
  readonly ratio?: number;
  /** Threshold the ratio failed to reach. */
  readonly required?: number;
  readonly message: string;
}

export interface ValidateThemeOptions {
  /**
   * Theme name, used only to consult `CONTRAST_WAIVERS`. Omit to validate
   * with no waivers at all — which is what you want for a palette that is not
   * one of the built-ins.
   */
  readonly name?: ThemeName;
  /** Override the text-contrast bar, e.g. `AAA_TEXT_CONTRAST`. */
  readonly minTextContrast?: number;
  /** Override the non-text-contrast bar for `BORDER`. */
  readonly minChromeContrast?: number;
  /** Override the SUCCESS/WARNING/ERROR separation bar. */
  readonly minSemanticContrast?: number;
}

/**
 * Check a candidate palette for completeness, well-formedness and contrast.
 *
 * Returns every issue found rather than the first, so a bad palette produces
 * one actionable report instead of a game of whack-a-mole. An empty array
 * means the palette is shippable at the thresholds given.
 *
 * Accepts `unknown` on purpose: the interesting callers are a test sweeping
 * the registry and, later, a user-supplied palette parsed from JSON.
 */
export function validateTheme(palette: unknown, options: ValidateThemeOptions = {}): ThemeIssue[] {
  const issues: ThemeIssue[] = [];

  if (typeof palette !== "object" || palette === null || Array.isArray(palette)) {
    return [{ kind: "missing", token: "*", message: "palette is not an object" }];
  }
  const record = palette as Record<string, unknown>;

  for (const token of THEME_TOKENS) {
    if (!(token in record)) {
      issues.push({ kind: "missing", token, message: `missing token ${token}` });
    } else if (!isHexColor(record[token])) {
      issues.push({
        kind: "malformed",
        token,
        message: `token ${token} is not a #RRGGBB colour: ${JSON.stringify(record[token])}`,
      });
    }
  }
  for (const key of Object.keys(record)) {
    if (!(THEME_TOKENS as readonly string[]).includes(key)) {
      issues.push({ kind: "extra", token: key, message: `unknown token ${key}` });
    }
  }

  // Contrast checks need every value to be parseable; bail out rather than
  // report a cascade of ratios computed from garbage.
  if (issues.some((i) => i.kind === "missing" || i.kind === "malformed")) return issues;

  const theme = record as unknown as Theme;
  const minText = options.minTextContrast ?? MIN_TEXT_CONTRAST;
  const minChrome = options.minChromeContrast ?? MIN_CHROME_CONTRAST;
  const minSemantic = options.minSemanticContrast ?? MIN_SEMANTIC_CONTRAST;

  const checkAgainstBackgrounds = (token: TextToken | ChromeToken, required: number): void => {
    for (const bg of BACKGROUND_TOKENS) {
      if (options.name && isWaived(options.name, token, bg)) continue;
      const ratio = contrastRatio(theme[token], theme[bg]);
      if (ratio < required) {
        issues.push({
          kind: "contrast",
          token,
          against: bg,
          ratio,
          required,
          message: `${token} on ${bg} is ${ratio.toFixed(2)}:1, below ${required}:1`,
        });
      }
    }
  };

  for (const token of TEXT_TOKENS) checkAgainstBackgrounds(token, minText);
  for (const token of CHROME_TOKENS) checkAgainstBackgrounds(token, minChrome);

  for (const [a, b] of SEMANTIC_PAIRS) {
    const ratio = contrastRatio(theme[a], theme[b]);
    if (ratio < minSemantic) {
      issues.push({
        kind: "semantic",
        token: `${a}/${b}`,
        ratio,
        required: minSemantic,
        message:
          `${a} and ${b} differ by only ${ratio.toFixed(3)}:1 in luminance ` +
          `(need ${minSemantic}:1) — indistinguishable without colour vision`,
      });
    }
  }

  return issues;
}

/**
 * Worst text-token contrast in a palette, ignoring waivers. Useful for the
 * summary line in `THEMES.md` and for a quick regression assertion.
 */
export function worstTextContrast(palette: Theme): { token: TextToken; against: BackgroundToken; ratio: number } {
  let worst: { token: TextToken; against: BackgroundToken; ratio: number } = {
    token: TEXT_TOKENS[0],
    against: BACKGROUND_TOKENS[0],
    ratio: Number.POSITIVE_INFINITY,
  };
  for (const token of TEXT_TOKENS) {
    for (const bg of BACKGROUND_TOKENS) {
      const ratio = contrastRatio(palette[token], palette[bg]);
      if (ratio < worst.ratio) worst = { token, against: bg, ratio };
    }
  }
  return worst;
}

/** Smallest contrast ratio among the SUCCESS/WARNING/ERROR pairs. */
export function semanticSeparation(palette: Theme): number {
  return Math.min(...SEMANTIC_PAIRS.map(([a, b]) => contrastRatio(palette[a], palette[b])));
}

/* ------------------------------------------------------- terminal capability */

export type ColorDepth = "none" | "ansi16" | "ansi256" | "truecolor";

/**
 * The 16 standard terminal colours, in SGR index order, at their canonical
 * xterm values.
 *
 * These are *nominal*. Almost every terminal lets the user retheme its 16
 * slots, so index 2 is "whatever this terminal calls green", not `#008000`.
 * That is the honest limit of what any static palette can know, and it is why
 * `degradePalette` snaps to nominal values while `ansiIndexFor` exists for
 * renderers that would rather emit the index and let the terminal decide.
 */
export const ANSI_16: readonly { readonly index: number; readonly name: string; readonly hex: string }[] = [
  { index: 0, name: "black", hex: "#000000" },
  { index: 1, name: "red", hex: "#800000" },
  { index: 2, name: "green", hex: "#008000" },
  { index: 3, name: "yellow", hex: "#808000" },
  { index: 4, name: "blue", hex: "#000080" },
  { index: 5, name: "magenta", hex: "#800080" },
  { index: 6, name: "cyan", hex: "#008080" },
  { index: 7, name: "white", hex: "#C0C0C0" },
  { index: 8, name: "bright black", hex: "#808080" },
  { index: 9, name: "bright red", hex: "#FF0000" },
  { index: 10, name: "bright green", hex: "#00FF00" },
  { index: 11, name: "bright yellow", hex: "#FFFF00" },
  { index: 12, name: "bright blue", hex: "#0000FF" },
  { index: 13, name: "bright magenta", hex: "#FF00FF" },
  { index: 14, name: "bright cyan", hex: "#00FFFF" },
  { index: 15, name: "bright white", hex: "#FFFFFF" },
];

/**
 * "Redmean" colour distance — a cheap low-cost approximation of perceptual
 * distance that behaves far better than plain RGB Euclidean on saturated
 * colours, which is most of a semantic palette. Deterministic and dependency
 * free, which matters more here than the last few percent of accuracy a full
 * CIEDE2000 would buy.
 */
function redmeanDistance(a: Rgb, b: Rgb): number {
  const rmean = (a.r + b.r) / 2;
  const dr = a.r - b.r;
  const dg = a.g - b.g;
  const db = a.b - b.b;
  return (2 + rmean / 256) * dr * dr + 4 * dg * dg + (2 + (255 - rmean) / 256) * db * db;
}

/** SGR index (0-15) of the standard colour nearest to `hex`. */
export function nearestAnsi16(hex: string): number {
  const rgb = parseHex(hex);
  if (!rgb) throw new TypeError(`nearestAnsi16: not a #RRGGBB colour: ${String(hex)}`);
  let best = 0;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (const entry of ANSI_16) {
    const d = redmeanDistance(rgb, parseHex(entry.hex) as Rgb);
    if (d < bestDistance) {
      bestDistance = d;
      best = entry.index;
    }
  }
  return best;
}

const CUBE_LEVELS = [0, 95, 135, 175, 215, 255];

function ansi256Hex(index: number): string {
  if (index < 16) return ANSI_16[index]!.hex;
  const toHex = (n: number): string => n.toString(16).padStart(2, "0").toUpperCase();
  if (index < 232) {
    const n = index - 16;
    const r = CUBE_LEVELS[Math.floor(n / 36) % 6]!;
    const g = CUBE_LEVELS[Math.floor(n / 6) % 6]!;
    const b = CUBE_LEVELS[n % 6]!;
    return `#${toHex(r)}${toHex(g)}${toHex(b)}`;
  }
  const level = 8 + (index - 232) * 10;
  return `#${toHex(level)}${toHex(level)}${toHex(level)}`;
}

/** SGR index (0-255) of the xterm-256 entry nearest to `hex`. */
export function nearestAnsi256(hex: string): number {
  const rgb = parseHex(hex);
  if (!rgb) throw new TypeError(`nearestAnsi256: not a #RRGGBB colour: ${String(hex)}`);
  let best = 0;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (let i = 0; i < 256; i += 1) {
    const d = redmeanDistance(rgb, parseHex(ansi256Hex(i)) as Rgb);
    if (d < bestDistance) {
      bestDistance = d;
      best = i;
    }
  }
  return best;
}

/** SGR palette index for `hex` at the given depth, or `null` when indexing does not apply. */
export function ansiIndexFor(hex: string, depth: ColorDepth): number | null {
  if (depth === "ansi16") return nearestAnsi16(hex);
  if (depth === "ansi256") return nearestAnsi256(hex);
  return null;
}

/**
 * Best-effort colour depth from environment variables.
 *
 * This is *inference from env vars only*. It does not query the terminal, does
 * not parse terminfo, and does not probe with an OSC sequence — there is no
 * synchronous, side-effect-free way to do any of that, and this module is
 * pure. Treat the result as a default the operator may override; that is
 * exactly why `degradePalette` takes a depth rather than detecting one.
 *
 * Rules, in order:
 *   - `NO_COLOR` set to anything (the no-color.org convention) -> "none".
 *   - `TERM=dumb` -> "none".
 *   - `FORCE_COLOR` present -> honoured: "0" is none, "1" ansi16, "2" ansi256,
 *     "3" or "true" truecolor.
 *   - `COLORTERM` containing "truecolor" or "24bit" -> "truecolor".
 *   - `TERM` containing "truecolor" or "direct" -> "truecolor".
 *   - `TERM` containing "256" -> "ansi256".
 *   - anything else, including an unset `TERM` -> "ansi16".
 *
 * The final fallback is conservative on purpose: guessing low costs fidelity,
 * guessing high costs legibility.
 */
export function detectColorDepth(env: Record<string, string | undefined> = {}): ColorDepth {
  const term = (env.TERM ?? "").toLowerCase();

  if (typeof env.NO_COLOR === "string") return "none";
  if (term === "dumb") return "none";

  const force = env.FORCE_COLOR;
  if (typeof force === "string") {
    if (force === "0" || force === "false") return "none";
    if (force === "1") return "ansi16";
    if (force === "2") return "ansi256";
    if (force === "3" || force === "true" || force === "") return "truecolor";
  }

  const colorterm = (env.COLORTERM ?? "").toLowerCase();
  if (colorterm.includes("truecolor") || colorterm.includes("24bit")) return "truecolor";
  if (term.includes("truecolor") || term.includes("direct")) return "truecolor";
  if (term.includes("256")) return "ansi256";
  return "ansi16";
}

/**
 * Snap every token in `palette` onto the values the terminal can actually
 * show at `depth`.
 *
 * What this does: replaces each hex with the nominal hex of the nearest entry
 * in the 16- or 256-colour palette, so the values the renderer is handed are
 * ones the terminal's own down-conversion will land on exactly rather than
 * approximately.
 *
 * What this does *not* do: it does not change how colour reaches the terminal.
 * OpenTUI is handed hex strings and emits 24-bit SGR either way; a genuinely
 * 16-colour terminal still performs its own approximation of that sequence.
 * Snapping first removes the drift, it does not remove the conversion. A
 * renderer that can emit indexed SGR should use `ansiIndexFor` instead.
 *
 * `"none"` returns the palette unchanged — suppressing colour entirely is the
 * renderer's job, not the palette's, and pretending otherwise here would just
 * hand back twelve identical strings.
 */
export function degradePalette(palette: Theme, depth: ColorDepth): Theme {
  if (depth === "truecolor" || depth === "none") return palette;
  const map = depth === "ansi16" ? nearestAnsi16 : nearestAnsi256;
  const out = {} as Record<ThemeToken, string>;
  for (const token of THEME_TOKENS) {
    out[token] = depth === "ansi16" ? ANSI_16[map(palette[token])]!.hex : ansi256Hex(map(palette[token]));
  }
  return out as Theme;
}

/**
 * The theme a given terminal should get if the operator has expressed no
 * preference: `ansi` when we believe the terminal has only 16 slots, the
 * default otherwise. Pure — pass `process.env` in at the call site.
 */
export function recommendedThemeName(env: Record<string, string | undefined> = {}): ThemeName {
  return detectColorDepth(env) === "ansi16" ? "ansi" : DEFAULT_THEME_NAME;
}

/* -------------------------------------------------------------- settings def */

/**
 * Drop-in entry for the `DEFS` table in `settings.ts`.
 *
 * Typed against that module's exported `SettingDef` so the shape is checked by
 * the compiler rather than by eyeballing. Wiring is: add `theme: ThemeName` to
 * `TuiSettings`, spread this into `DEFS`, and add `theme: DEFAULT_THEME_NAME`
 * to `DEFAULT_SETTINGS`. See the checklist in `THEMES.md`.
 */
export const THEME_SETTING_DEF: SettingDef<ThemeName> & {
  key: "theme";
  kind: "enum";
  choices: readonly ThemeName[];
} = {
  key: "theme",
  label: "Theme",
  description: "Colour palette for the console. Restart or re-render to apply.",
  kind: "enum",
  default: DEFAULT_THEME_NAME,
  choices: THEME_NAMES,
  group: "Display",
};

/* ----------------------------------------------------- installed themes (I/O) */
//
// Themes become shareable artifacts by living as validated JSON palettes under
// the per-user state dir (`~/.0sec/themes/<id>.json`). This is the ONLY part of
// the module that touches the filesystem. Every read is total and fail-soft: a
// missing dir, an unreadable file, malformed JSON, or a palette that fails
// `validateTheme` is skipped, never thrown. Installed themes carry NO code and
// NO capabilities — they are a palette plus display metadata, nothing more, so
// loading one can never reach the tool loader or a capability gate.

/** Directory name for installed themes inside the 0sec state dir. */
export const INSTALLED_THEMES_DIRNAME = "themes";

/** On-disk shape of an installed theme file. `id` is authoritative (the file's
 *  resolvable name); the rest is display metadata plus the palette. */
export interface InstalledThemeFile {
  readonly id: string;
  readonly label?: string;
  readonly description?: string;
  readonly mode?: ThemeMode;
  readonly palette: Theme;
}

/** Absolute path to the installed-themes directory. */
export function installedThemesDir(homeDir?: string): string {
  return join(homeStateDir(homeDir), INSTALLED_THEMES_DIRNAME);
}

/** Absolute path to one installed theme's file. Caller must pass a safe id. */
export function installedThemeFilePath(id: string, homeDir?: string): string {
  return join(installedThemesDir(homeDir), `${id}.json`);
}

/**
 * Ids must be a single safe path segment so an installed theme can never write
 * or read outside the themes dir. Mirrors the plugin-id charset: lowercase
 * dotted/hyphenated identifier, bounded length, no separators or traversal.
 */
const THEME_ID_RE = /^[a-z][a-z0-9]*([._-][a-z0-9]+)*$/;
const THEME_ID_MAX = 64;

/** True when `id` is a safe installed-theme id (a single path segment). */
export function isSafeThemeId(id: unknown): id is string {
  return (
    typeof id === "string" &&
    id.length > 0 &&
    id.length <= THEME_ID_MAX &&
    THEME_ID_RE.test(id) &&
    !id.includes("/") &&
    !id.includes("\\") &&
    id !== "." &&
    id !== ".."
  );
}

/**
 * The installed-theme cache. `null` until first loaded so a session that never
 * resolves a theme does no I/O; `installedFromHome` records which home it was
 * loaded from so pointing at a different home (a `--home`, or a test's temp dir)
 * reloads rather than serving a stale set.
 */
let installedThemes: Map<string, ThemeEntry> | null = null;
let installedFromHome: string | undefined;

/**
 * Coerce one parsed theme file into a validated `ThemeEntry`, or `null`.
 *
 * The palette must pass the FULL `validateTheme` (completeness + contrast, no
 * waivers — waivers exist only for the preserved built-in default), so an
 * installed theme is held to the same legibility bar as a shipped one. Fail
 * closed: any problem drops the theme.
 */
export function installedThemeEntryFromFile(id: string, raw: unknown): ThemeEntry | null {
  if (!isSafeThemeId(id)) return null;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const palette = record.palette;
  if (validateTheme(palette).length > 0) return null;
  const label = typeof record.label === "string" && record.label.length > 0 ? record.label : id;
  const description =
    typeof record.description === "string" ? record.description : "Installed theme.";
  const mode: ThemeMode = record.mode === "light" ? "light" : "dark";
  return { name: id, label, description, mode, palette: palette as Theme };
}

/**
 * Read + validate every installed theme file. Total, fail-soft.
 *
 * Delegates the scan and per-file validation to the pure `loadUserThemes`
 * loader, then keeps only its `valid` entries — so the resolvable set is
 * *exactly* the set that loader accepts, and its `rejected` diagnostics (used by
 * `theme list`/settings) describe the same files this cache silently drops.
 * There is one reader of the themes dir, not two.
 */
function readInstalledThemes(homeDir?: string): Map<string, ThemeEntry> {
  const out = new Map<string, ThemeEntry>();
  for (const entry of loadUserThemes(installedThemesDir(homeDir)).valid) {
    out.set(entry.name, entry);
  }
  return out;
}

/**
 * Ensure the installed-theme cache is populated for `homeDir`, loading it once
 * (or reloading when the home changed). Returns the cache. Safe to call on the
 * settings load path — it is total and fail-soft.
 */
export function ensureInstalledThemesLoaded(homeDir?: string): Map<string, ThemeEntry> {
  if (installedThemes === null || installedFromHome !== homeDir) {
    installedThemes = readInstalledThemes(homeDir);
    installedFromHome = homeDir;
  }
  return installedThemes;
}

/**
 * Re-read the themes dir unconditionally and swap the cache — for after a fresh
 * `theme install`, so a newly-written theme is resolvable live without a
 * restart. Returns the reloaded cache.
 */
export function reloadInstalledThemes(homeDir?: string): Map<string, ThemeEntry> {
  installedThemes = readInstalledThemes(homeDir);
  installedFromHome = homeDir;
  return installedThemes;
}

/** The installed theme entries currently resolvable (loads lazily). */
export function installedThemeEntries(homeDir?: string): ThemeEntry[] {
  return [...ensureInstalledThemesLoaded(homeDir).values()];
}

/**
 * Every resolvable theme name: the stable built-ins first, then installed ids.
 * This is the picker's full set; `THEME_NAMES` remains the built-ins-only list
 * that settings.ts and the enum cycler depend on.
 */
export function allThemeNames(homeDir?: string): string[] {
  return [...THEME_NAMES, ...ensureInstalledThemesLoaded(homeDir).keys()];
}

/**
 * Predicate: is `value` a resolvable theme — a built-in name OR a currently
 * loaded installed id? Performs NO I/O (reads the current cache only), so it is
 * safe to call from the pure `normalizeSettings` path and stays deterministic:
 * the caller (the settings load path) is responsible for having loaded the
 * installed themes first via `ensureInstalledThemesLoaded`.
 */
export function isKnownTheme(value: unknown): boolean {
  if (isThemeName(value)) return true;
  return typeof value === "string" && installedThemes !== null && installedThemes.has(value);
}

/**
 * Persist a validated palette as an installed theme file. Fail closed: the
 * palette is re-validated with `validateTheme` before anything is written, and
 * an invalid palette or a bad id is refused rather than written. Reports success
 * as a return value; never throws on an I/O failure.
 */
export function writeInstalledTheme(file: InstalledThemeFile, homeDir?: string): { ok: true; path: string } | { ok: false; error: string } {
  if (!isSafeThemeId(file.id)) return { ok: false, error: `unsafe theme id ${JSON.stringify(file.id)}` };
  if (isThemeName(file.id)) return { ok: false, error: `"${file.id}" is a built-in theme name and cannot be overridden` };
  const issues = validateTheme(file.palette);
  if (issues.length > 0) {
    return { ok: false, error: `invalid palette: ${issues.map((i) => i.message).join("; ")}` };
  }
  try {
    const path = installedThemeFilePath(file.id, homeDir);
    mkdirSync(dirname(path), { recursive: true });
    const body: InstalledThemeFile = {
      id: file.id,
      ...(file.label !== undefined ? { label: file.label } : {}),
      ...(file.description !== undefined ? { description: file.description } : {}),
      ...(file.mode !== undefined ? { mode: file.mode } : {}),
      palette: file.palette,
    };
    writeFileSync(path, `${JSON.stringify(body, null, 2)}\n`, "utf8");
    return { ok: true, path };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Delete an installed theme file. Refuses a built-in name or an unsafe id.
 * Reports success as a return value; a missing file is reported, not thrown.
 */
export function removeInstalledTheme(id: string, homeDir?: string): { ok: true } | { ok: false; error: string } {
  if (!isSafeThemeId(id)) return { ok: false, error: `unsafe theme id ${JSON.stringify(id)}` };
  if (isThemeName(id)) return { ok: false, error: `"${id}" is a built-in theme and cannot be removed` };
  const cache = ensureInstalledThemesLoaded(homeDir);
  if (!cache.has(id)) return { ok: false, error: `theme "${id}" is not installed` };
  try {
    rmSync(installedThemeFilePath(id, homeDir), { force: true });
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Test-only: drop the installed-theme cache so each test starts clean. */
export function __resetInstalledThemesForTests(): void {
  installedThemes = null;
  installedFromHome = undefined;
}
