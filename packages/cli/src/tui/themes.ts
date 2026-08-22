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
 * Everything in this module is pure: no I/O, no React, no process access. The
 * one function that reads the environment takes it as an argument.
 */

import type { SettingDef } from "./settings.js";

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

export type BackgroundToken = (typeof BACKGROUND_TOKENS)[number];
export type TextToken = (typeof TEXT_TOKENS)[number];
export type ChromeToken = (typeof CHROME_TOKENS)[number];
export type ThemeToken = BackgroundToken | TextToken | ChromeToken;

/** Every token, in a stable order, for iteration and validation. */
export const THEME_TOKENS: readonly ThemeToken[] = [
  ...BACKGROUND_TOKENS,
  ...TEXT_TOKENS,
  ...CHROME_TOKENS,
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
 * The value is a floor, not a target. It is set here by the one palette that
 * cannot be changed — the preserved default measures 1.19:1 across its
 * `SUCCESS`/`WARNING` pair, the tightest of any theme. The three designed
 * themes all clear 1.26:1. If the default is ever allowed to move, raise this.
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
  PANEL: "#111111",
  PANEL_ALT: "#171515",
  BORDER: "#25201D",
  TEXT: "#F3EEE9",
  MUTED: "#8A7D73",
  PRIMARY: "#E28553",
  ACCENT: "#F0B08D",
  SUCCESS: "#22C55E",
  WARNING: "#EAB308",
  ERROR: "#DC2626",
  INFO: "#C99A7A",
};

/**
 * `Paper` — for terminals on a light background.
 *
 * Not an inversion of the dark palette. On paper the usable foreground
 * luminance band is roughly [0, 0.13]: anything lighter than L≈0.13 cannot
 * reach 4.5:1 against the darkest surface (`PANEL_ALT`). Every foreground here
 * is therefore a *dark* colour, and the palette's expressive range is hue and
 * saturation rather than brightness. The brand orange survives as a burnt
 * `PRIMARY`; `INFO` moves from the dark theme's tan to a slate blue, because a
 * light tan on paper is invisible and blue is the one strongly-separated hue
 * the warm palette was not already using.
 */
const LIGHT: Theme = {
  CANVAS: "#FDFBF7",
  PANEL: "#F3EEE5",
  PANEL_ALT: "#E7E0D3",
  BORDER: "#837767",
  TEXT: "#1C1713",
  MUTED: "#564C43",
  PRIMARY: "#903F0E",
  ACCENT: "#8B5429",
  SUCCESS: "#1A6934",
  WARNING: "#654700",
  ERROR: "#750E0E",
  INFO: "#17456B",
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
  PRIMARY: "#F89E4B",
  ACCENT: "#FCCFA6",
  SUCCESS: "#3AE483",
  WARNING: "#FFE635",
  ERROR: "#FC8979",
  INFO: "#82DAFF",
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
  PRIMARY: "#00FFFF",
  ACCENT: "#FF00FF",
  SUCCESS: "#00FF00",
  WARNING: "#FFFF00",
  ERROR: "#FF0000",
  INFO: "#C0C0C0",
};

/* ----------------------------------------------------------------- registry */

export const THEME_NAMES = ["dark", "light", "high-contrast", "ansi"] as const;
export type ThemeName = (typeof THEME_NAMES)[number];

export const DEFAULT_THEME_NAME: ThemeName = "dark";

export interface ThemeEntry {
  readonly name: ThemeName;
  /** Short human label for the settings UI. */
  readonly label: string;
  /** One line explaining who this theme is for. */
  readonly description: string;
  readonly palette: Theme;
}

export const THEMES: Readonly<Record<ThemeName, ThemeEntry>> = {
  dark: {
    name: "dark",
    label: "0sec Dark",
    description: "The shipped palette. Warm dark surfaces, brand orange. Default.",
    palette: DARK,
  },
  light: {
    name: "light",
    label: "Paper",
    description: "For terminals on a light background. Dark foregrounds on warm paper.",
    palette: LIGHT,
  },
  "high-contrast": {
    name: "high-contrast",
    label: "Contrast",
    description: "Pure black canvas, every text colour at WCAG AAA (7:1) or better.",
    palette: HIGH_CONTRAST,
  },
  ansi: {
    name: "ansi",
    label: "ANSI 16",
    description: "Only the 16 standard terminal colours. For terminals without truecolor.",
    palette: ANSI,
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

/** As `getTheme`, but returns the label and description too. Also total. */
export function getThemeEntry(name: unknown): ThemeEntry {
  return isThemeName(name) ? THEMES[name] : THEMES[DEFAULT_THEME_NAME];
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
    token: "ERROR",
    against: "CANVAS",
    ratio: 4.15,
    reason:
      "Preserved default: #DC2626 is the shipped error red. Below AA on all three surfaces. " +
      "#F4695E clears 4.5:1 everywhere if a visible change is acceptable.",
  },
  {
    theme: "dark",
    token: "ERROR",
    against: "PANEL",
    ratio: 3.91,
    reason: "Preserved default: see the CANVAS waiver for ERROR.",
  },
  {
    theme: "dark",
    token: "ERROR",
    against: "PANEL_ALT",
    ratio: 3.77,
    reason: "Preserved default: see the CANVAS waiver for ERROR.",
  },
  {
    theme: "dark",
    token: "BORDER",
    against: "CANVAS",
    ratio: 1.24,
    reason:
      "Preserved default: #25201D is an intentional hairline, well below even the 3:1 " +
      "non-text bar. #726359 reaches 3:1 on all three surfaces if visible panel edges are wanted.",
  },
  {
    theme: "dark",
    token: "BORDER",
    against: "PANEL",
    ratio: 1.17,
    reason: "Preserved default: see the CANVAS waiver for BORDER.",
  },
  {
    theme: "dark",
    token: "BORDER",
    against: "PANEL_ALT",
    ratio: 1.13,
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
