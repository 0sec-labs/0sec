import { describe, expect, it } from "vitest";

import {
  AAA_TEXT_CONTRAST,
  ANSI_16,
  BACKGROUND_TOKENS,
  CHROME_TOKENS,
  CONTRAST_WAIVERS,
  DEFAULT_THEME_NAME,
  LAYER_TOKENS,
  MIN_CHROME_CONTRAST,
  MIN_SEMANTIC_CONTRAST,
  MIN_TEXT_CONTRAST,
  SEMANTIC_PAIRS,
  TEXT_TOKENS,
  THEMES,
  THEME_NAMES,
  THEME_SETTING_DEF,
  THEME_TOKENS,
  ansiIndexFor,
  contrastRatio,
  degradePalette,
  detectColorDepth,
  getTheme,
  getThemeEntry,
  isHexColor,
  isThemeName,
  isWaived,
  nearestAnsi16,
  nearestAnsi256,
  parseHex,
  recommendedThemeName,
  relativeLuminance,
  semanticSeparation,
  severityToneFor,
  validateTheme,
  worstTextContrast,
  type BackgroundToken,
  type Theme,
  type ThemeName,
  type ThemeToken,
} from "./themes.js";

/**
 * The default palette, transcribed by hand.
 *
 * The twelve text/background/chrome tokens are byte-for-byte the values
 * `ui/theme.ts` exports (white highlight, neutral accent — no orange). The four
 * `LAYER_TOKENS` (`background`/`surface`/`surfaceAlt`/`overlay`) are the theme
 * system's own additions, not present in `ui/theme.ts`; for the default they
 * mirror `CANVAS`/`PANEL`/`PANEL_ALT` with an `overlay` a step past the rest.
 *
 * Deliberately *not* imported from `../ui/theme.js`: importing it would make
 * this assertion tautological the moment somebody edits that file, which is
 * precisely the event it is here to catch. If the shipped palette legitimately
 * changes, both this literal and the waiver ratios must be updated together,
 * and the diff is then visible in review.
 */
const SHIPPED_PALETTE: Record<string, string> = {
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

const allThemes = (): { name: ThemeName; palette: Theme }[] =>
  THEME_NAMES.map((name) => ({ name, palette: THEMES[name].palette }));

/* ------------------------------------------------------------ completeness */

describe("token coverage", () => {
  it("splits every token into exactly one role", () => {
    const roles = [...BACKGROUND_TOKENS, ...TEXT_TOKENS, ...CHROME_TOKENS, ...LAYER_TOKENS];
    expect([...roles].sort()).toEqual([...THEME_TOKENS].sort());
    expect(new Set(roles).size).toBe(roles.length);
  });

  it("covers exactly the tokens the default palette defines", () => {
    expect([...THEME_TOKENS].sort()).toEqual(Object.keys(SHIPPED_PALETTE).sort());
  });

  it.each(allThemes())("$name defines every token and no extras", ({ palette }) => {
    // Driven off THEME_TOKENS, so adding a token to the type fails here for
    // any theme that has not been updated.
    expect(Object.keys(palette).sort()).toEqual([...THEME_TOKENS].sort());
    for (const token of THEME_TOKENS) {
      expect(isHexColor(palette[token])).toBe(true);
    }
  });

  it.each(allThemes())("$name uses uppercase 6-digit hex throughout", ({ palette }) => {
    for (const token of THEME_TOKENS) {
      expect(palette[token]).toMatch(/^#[0-9A-F]{6}$/);
    }
  });

  it("registers every name in THEME_NAMES and nothing else", () => {
    expect(Object.keys(THEMES).sort()).toEqual([...THEME_NAMES].sort());
    for (const name of THEME_NAMES) expect(THEMES[name].name).toBe(name);
  });
});

/* --------------------------------------------------- the preserved default */

describe("default theme", () => {
  it("is byte-identical to the palette ui/theme.ts ships today", () => {
    expect({ ...THEMES.dark.palette }).toEqual(SHIPPED_PALETTE);
  });

  it("is the fallback", () => {
    expect(DEFAULT_THEME_NAME).toBe("dark");
    expect(getTheme(DEFAULT_THEME_NAME)).toBe(THEMES.dark.palette);
  });

  it("reproduces severityTone's mapping", () => {
    const p = THEMES.dark.palette;
    expect(severityToneFor(p, "critical")).toBe(p.ERROR);
    expect(severityToneFor(p, "HIGH")).toBe(p.ERROR);
    expect(severityToneFor(p, "medium")).toBe(p.WARNING);
    expect(severityToneFor(p, "low")).toBe(p.INFO);
    expect(severityToneFor(p, "informational")).toBe(p.MUTED);
    expect(severityToneFor(p, "")).toBe(p.MUTED);
  });
});

/* ------------------------------------------------------------- colour maths */

describe("contrastRatio", () => {
  it("matches the WCAG reference extremes", () => {
    expect(contrastRatio("#000000", "#FFFFFF")).toBeCloseTo(21, 10);
    expect(contrastRatio("#FFFFFF", "#000000")).toBeCloseTo(21, 10);
    expect(contrastRatio("#000000", "#000000")).toBeCloseTo(1, 10);
    expect(contrastRatio("#FFFFFF", "#FFFFFF")).toBeCloseTo(1, 10);
    expect(contrastRatio("#7A7A7A", "#7A7A7A")).toBeCloseTo(1, 10);
  });

  it("matches published ratios for known pairs", () => {
    // Values from the WebAIM contrast checker.
    expect(contrastRatio("#777777", "#FFFFFF")).toBeCloseTo(4.48, 2);
    expect(contrastRatio("#767676", "#FFFFFF")).toBeCloseTo(4.54, 2);
    expect(contrastRatio("#0000FF", "#FFFFFF")).toBeCloseTo(8.59, 2);
    expect(contrastRatio("#FF0000", "#000000")).toBeCloseTo(5.25, 2);
  });

  it("is symmetric across the whole registry", () => {
    for (const { palette } of allThemes()) {
      for (const a of THEME_TOKENS) {
        for (const b of THEME_TOKENS) {
          expect(contrastRatio(palette[a], palette[b])).toBeCloseTo(
            contrastRatio(palette[b], palette[a]),
            12,
          );
        }
      }
    }
  });

  it("never leaves the 1..21 range", () => {
    for (const { palette } of allThemes()) {
      for (const a of THEME_TOKENS) {
        for (const b of THEME_TOKENS) {
          const r = contrastRatio(palette[a], palette[b]);
          expect(r).toBeGreaterThanOrEqual(1);
          expect(r).toBeLessThanOrEqual(21);
        }
      }
    }
  });

  it("accepts lowercase hex", () => {
    expect(contrastRatio("#ffffff", "#000000")).toBeCloseTo(21, 10);
  });

  it("throws on a malformed colour", () => {
    expect(() => contrastRatio("#FFF", "#000000")).toThrow(TypeError);
    expect(() => relativeLuminance("rebeccapurple")).toThrow(TypeError);
  });
});

describe("relativeLuminance", () => {
  it("anchors at 0 and 1", () => {
    expect(relativeLuminance("#000000")).toBeCloseTo(0, 12);
    expect(relativeLuminance("#FFFFFF")).toBeCloseTo(1, 12);
  });

  it("weights the channels per WCAG", () => {
    expect(relativeLuminance("#FF0000")).toBeCloseTo(0.2126, 6);
    expect(relativeLuminance("#00FF00")).toBeCloseTo(0.7152, 6);
    expect(relativeLuminance("#0000FF")).toBeCloseTo(0.0722, 6);
  });

  it("is monotone along the grey ramp", () => {
    let previous = -1;
    for (let v = 0; v <= 255; v += 5) {
      const hex = `#${v.toString(16).padStart(2, "0").repeat(3)}`;
      const l = relativeLuminance(hex);
      expect(l).toBeGreaterThan(previous);
      previous = l;
    }
  });
});

describe("parseHex", () => {
  it("parses a well-formed colour", () => {
    expect(parseHex("#1A2B3C")).toEqual({ r: 0x1a, g: 0x2b, b: 0x3c });
  });

  it.each([
    ["#FFF", "3-digit shorthand"],
    ["#FFFFFFFF", "8-digit alpha"],
    ["FFFFFF", "missing hash"],
    ["#GGGGGG", "non-hex digits"],
    ["#12345", "too short"],
    ["", "empty"],
    ["  #FFFFFF ", "surrounding whitespace"],
  ])("rejects %s (%s)", (value) => {
    expect(parseHex(value)).toBeNull();
    expect(isHexColor(value)).toBe(false);
  });

  it("rejects non-strings without throwing", () => {
    for (const value of [null, undefined, 42, {}, [], true]) {
      expect(parseHex(value as unknown as string)).toBeNull();
      expect(isHexColor(value)).toBe(false);
    }
  });
});

/* ---------------------------------------------------------- contrast sweep */

describe("contrast sweep", () => {
  it("holds every text token to 4.5:1 on every surface it renders on", () => {
    const failures: string[] = [];
    for (const { name, palette } of allThemes()) {
      for (const token of TEXT_TOKENS) {
        for (const bg of BACKGROUND_TOKENS) {
          const ratio = contrastRatio(palette[token], palette[bg]);
          if (ratio >= MIN_TEXT_CONTRAST) continue;
          if (isWaived(name, token, bg)) continue;
          failures.push(`${name}: ${token} on ${bg} = ${ratio.toFixed(2)}:1`);
        }
      }
    }
    expect(failures).toEqual([]);
  });

  it("holds BORDER to the 3:1 non-text bar on every surface", () => {
    const failures: string[] = [];
    for (const { name, palette } of allThemes()) {
      for (const token of CHROME_TOKENS) {
        for (const bg of BACKGROUND_TOKENS) {
          const ratio = contrastRatio(palette[token], palette[bg]);
          if (ratio >= MIN_CHROME_CONTRAST) continue;
          if (isWaived(name, token, bg)) continue;
          failures.push(`${name}: ${token} on ${bg} = ${ratio.toFixed(2)}:1`);
        }
      }
    }
    expect(failures).toEqual([]);
  });

  it("high-contrast earns its name at AAA (7:1)", () => {
    const palette = THEMES["high-contrast"].palette;
    for (const token of TEXT_TOKENS) {
      for (const bg of BACKGROUND_TOKENS) {
        expect(contrastRatio(palette[token], palette[bg])).toBeGreaterThanOrEqual(
          AAA_TEXT_CONTRAST,
        );
      }
    }
    expect(validateTheme(palette, { minTextContrast: AAA_TEXT_CONTRAST })).toEqual([]);
  });

  it("records the worst-case text ratio of each theme", () => {
    const worst = Object.fromEntries(
      allThemes().map(({ name, palette }) => {
        const w = worstTextContrast(palette);
        return [name, Number(w.ratio.toFixed(2))];
      }),
    );
    expect(worst).toEqual({
      dark: 4.97,
      light: 5.24,
      "high-contrast": 7.75,
      ansi: 5.25,
      midnight: 5.17,
      slate: 5.16,
      paper: 5.16,
      "mono-dim": 4.5,
      swiss: 5.74,
    });
  });
});

/* --------------------------------------------------------------- waivers */

describe("contrast waivers", () => {
  it("exist only for the theme that may not be changed", () => {
    for (const waiver of CONTRAST_WAIVERS) {
      expect(waiver.theme).toBe(DEFAULT_THEME_NAME);
    }
  });

  it("pins the measured ratio, so any edit to the default palette fails here", () => {
    for (const waiver of CONTRAST_WAIVERS) {
      const palette = THEMES[waiver.theme].palette;
      const measured = contrastRatio(palette[waiver.token], palette[waiver.against]);
      expect(Number(measured.toFixed(2))).toBe(waiver.ratio);
    }
  });

  it("covers a genuine failure — no waiver for a pair that already passes", () => {
    for (const waiver of CONTRAST_WAIVERS) {
      const palette = THEMES[waiver.theme].palette;
      const measured = contrastRatio(palette[waiver.token], palette[waiver.against]);
      const bar = (CHROME_TOKENS as readonly string[]).includes(waiver.token)
        ? MIN_CHROME_CONTRAST
        : MIN_TEXT_CONTRAST;
      expect(measured).toBeLessThan(bar);
    }
  });

  it("is exactly the set of known failures — nothing new slips in silently", () => {
    const recorded = CONTRAST_WAIVERS.map((w) => `${w.theme}/${w.token}/${w.against}`).sort();
    expect(recorded).toEqual([
      "dark/BORDER/CANVAS",
      "dark/BORDER/PANEL",
      "dark/BORDER/PANEL_ALT",
    ]);
  });

  it("names the replacement colours it claims fix the default", () => {
    const dark = THEMES.dark.palette;
    for (const bg of BACKGROUND_TOKENS) {
      expect(contrastRatio("#8C8580", dark[bg])).toBeGreaterThanOrEqual(MIN_CHROME_CONTRAST);
    }
  });

  it("does not suppress a failure in any other theme", () => {
    for (const name of THEME_NAMES) {
      if (name === DEFAULT_THEME_NAME) continue;
      expect(validateTheme(THEMES[name].palette, { name })).toEqual([]);
    }
  });
});

/* ------------------------------------------------------- colour blindness */

describe("semantic colours survive colour blindness", () => {
  it("separates SUCCESS, WARNING and ERROR by luminance in every theme", () => {
    for (const { name, palette } of allThemes()) {
      for (const [a, b] of SEMANTIC_PAIRS) {
        const ratio = contrastRatio(palette[a], palette[b]);
        expect(
          ratio,
          `${name}: ${a} vs ${b} is only ${ratio.toFixed(3)}:1`,
        ).toBeGreaterThanOrEqual(MIN_SEMANTIC_CONTRAST);
      }
    }
  });

  it("gives the three tokens a strict luminance ordering (no ties)", () => {
    for (const { name, palette } of allThemes()) {
      const luminances = ["SUCCESS", "WARNING", "ERROR"].map((t) =>
        relativeLuminance(palette[t as ThemeToken]),
      );
      expect(new Set(luminances).size, `${name} has a luminance tie`).toBe(3);
    }
  });

  it("still separates them after conversion to greyscale", () => {
    // Greyscale here means: keep only relative luminance. If the three map to
    // three distinguishable greys, hue was never load-bearing.
    for (const { palette } of allThemes()) {
      const greys = ["SUCCESS", "WARNING", "ERROR"].map((t) => {
        const l = relativeLuminance(palette[t as ThemeToken]);
        const srgb = l <= 0.0031308 ? l * 12.92 : 1.055 * l ** (1 / 2.4) - 0.055;
        const v = Math.round(srgb * 255);
        return `#${v.toString(16).padStart(2, "0").repeat(3)}`.toUpperCase();
      });
      for (let i = 0; i < greys.length; i += 1) {
        for (let j = i + 1; j < greys.length; j += 1) {
          expect(contrastRatio(greys[i]!, greys[j]!)).toBeGreaterThanOrEqual(
            MIN_SEMANTIC_CONTRAST,
          );
        }
      }
    }
  });

  it("records the separation each theme actually achieves", () => {
    const achieved = Object.fromEntries(
      allThemes().map(({ name, palette }) => [name, Number(semanticSeparation(palette).toFixed(3))]),
    );
    expect(achieved).toEqual({
      dark: 1.188,
      light: 1.254,
      "high-contrast": 1.319,
      ansi: 1.278,
      midnight: 1.313,
      slate: 1.212,
      paper: 1.162,
      "mono-dim": 1.165,
      swiss: 1.21,
    });
    // Every theme clears the floor; paper is the tightest of the set.
    expect(Math.min(...Object.values(achieved))).toBe(achieved.paper);
    expect(Math.min(...Object.values(achieved))).toBeGreaterThanOrEqual(MIN_SEMANTIC_CONTRAST);
  });
});

/* ------------------------------------------------------------- validation */

describe("validateTheme", () => {
  it("passes every registered theme", () => {
    for (const name of THEME_NAMES) {
      expect(validateTheme(THEMES[name].palette, { name })).toEqual([]);
    }
  });

  it("reports a missing token", () => {
    const { TEXT: _dropped, ...rest } = THEMES["high-contrast"].palette;
    const issues = validateTheme(rest);
    expect(issues).toContainEqual(
      expect.objectContaining({ kind: "missing", token: "TEXT" }),
    );
  });

  it("reports an unknown token", () => {
    const issues = validateTheme({ ...THEMES["high-contrast"].palette, SPARKLE: "#123456" });
    expect(issues).toContainEqual(expect.objectContaining({ kind: "extra", token: "SPARKLE" }));
  });

  it.each(["#FFF", "#FFFFFFFF", "red", "0xFFFFFF", "#ZZZZZZ", ""])(
    "rejects malformed hex %s",
    (bad) => {
      const issues = validateTheme({ ...THEMES["high-contrast"].palette, TEXT: bad });
      expect(issues).toContainEqual(
        expect.objectContaining({ kind: "malformed", token: "TEXT" }),
      );
    },
  );

  it("rejects a non-object outright instead of throwing", () => {
    for (const bad of [null, undefined, 42, "dark", [], true]) {
      const issues = validateTheme(bad);
      expect(issues.length).toBe(1);
      expect(issues[0]!.kind).toBe("missing");
    }
  });

  it("does not attempt contrast maths on a malformed palette", () => {
    const issues = validateTheme({ ...THEMES.light.palette, TEXT: "nope" });
    expect(issues.every((i) => i.kind === "malformed")).toBe(true);
  });

  it("reports a contrast failure with the ratio and the surface", () => {
    const issues = validateTheme({ ...THEMES["high-contrast"].palette, MUTED: "#0F0F0F" });
    const contrast = issues.filter((i) => i.kind === "contrast");
    expect(contrast.length).toBe(BACKGROUND_TOKENS.length);
    for (const issue of contrast) {
      expect(issue.token).toBe("MUTED");
      expect(BACKGROUND_TOKENS).toContain(issue.against as BackgroundToken);
      expect(issue.ratio!).toBeLessThan(MIN_TEXT_CONTRAST);
      expect(issue.required).toBe(MIN_TEXT_CONTRAST);
    }
  });

  it("reports an indistinguishable semantic pair", () => {
    // A red and a green chosen to sit at near-identical luminance: the exact
    // failure mode a deuteranope cannot see around.
    const issues = validateTheme({
      ...THEMES["high-contrast"].palette,
      SUCCESS: "#3AE483",
      WARNING: "#3AE483",
    });
    expect(issues).toContainEqual(
      expect.objectContaining({ kind: "semantic", token: "SUCCESS/WARNING" }),
    );
  });

  it("applies waivers only for the named theme", () => {
    expect(validateTheme(THEMES.dark.palette, { name: "dark" })).toEqual([]);
    const unwaived = validateTheme(THEMES.dark.palette);
    expect(unwaived.length).toBe(CONTRAST_WAIVERS.length);
    expect(unwaived.every((i) => i.kind === "contrast")).toBe(true);
  });

  it("honours a raised threshold", () => {
    const issues = validateTheme(THEMES.light.palette, { minTextContrast: 12 });
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.every((i) => i.kind === "contrast" && i.required === 12)).toBe(true);
  });
});

/* ------------------------------------------------------------------ lookup */

describe("getTheme", () => {
  it("returns the requested palette", () => {
    for (const name of THEME_NAMES) {
      expect(getTheme(name)).toBe(THEMES[name].palette);
      expect(getThemeEntry(name).name).toBe(name);
    }
  });

  it.each([
    ["solarized", "an unknown name"],
    ["", "the empty string"],
    ["DARK", "the wrong case"],
    ["dark ", "trailing whitespace"],
  ])("falls back to the default for %s (%s)", (value) => {
    expect(getTheme(value)).toBe(THEMES[DEFAULT_THEME_NAME].palette);
    expect(getThemeEntry(value).name).toBe(DEFAULT_THEME_NAME);
  });

  it("falls back for non-strings rather than throwing", () => {
    for (const bad of [undefined, null, 0, {}, [], true, Symbol("dark")]) {
      expect(() => getTheme(bad)).not.toThrow();
      expect(getTheme(bad)).toBe(THEMES[DEFAULT_THEME_NAME].palette);
    }
  });

  it("narrows correctly", () => {
    expect(isThemeName("light")).toBe(true);
    expect(isThemeName("Light")).toBe(false);
    expect(isThemeName(undefined)).toBe(false);
    expect(isThemeName("toString")).toBe(false);
  });
});

/* -------------------------------------------------- terminal capability */

describe("detectColorDepth", () => {
  it.each<[Record<string, string | undefined>, string]>([
    [{ COLORTERM: "truecolor" }, "truecolor"],
    [{ COLORTERM: "24bit" }, "truecolor"],
    [{ TERM: "xterm-truecolor" }, "truecolor"],
    [{ TERM: "xterm-direct" }, "truecolor"],
    [{ TERM: "xterm-256color" }, "ansi256"],
    [{ TERM: "screen-256color" }, "ansi256"],
    [{ TERM: "xterm" }, "ansi16"],
    [{ TERM: "linux" }, "ansi16"],
    [{}, "ansi16"],
    [{ TERM: "dumb" }, "none"],
    [{ NO_COLOR: "1", COLORTERM: "truecolor" }, "none"],
    [{ NO_COLOR: "", COLORTERM: "truecolor" }, "none"],
    [{ FORCE_COLOR: "0", COLORTERM: "truecolor" }, "none"],
    [{ FORCE_COLOR: "1", COLORTERM: "truecolor" }, "ansi16"],
    [{ FORCE_COLOR: "2" }, "ansi256"],
    [{ FORCE_COLOR: "3" }, "truecolor"],
    [{ FORCE_COLOR: "true", TERM: "xterm" }, "truecolor"],
  ])("maps %o to %s", (env, expected) => {
    expect(detectColorDepth(env)).toBe(expected);
  });

  it("lets NO_COLOR win over FORCE_COLOR", () => {
    expect(detectColorDepth({ NO_COLOR: "1", FORCE_COLOR: "3" })).toBe("none");
  });

  it("defaults to ansi16 with no argument", () => {
    expect(detectColorDepth()).toBe("ansi16");
  });

  it("recommends the ANSI theme only for a 16-colour terminal", () => {
    expect(recommendedThemeName({ TERM: "xterm" })).toBe("ansi");
    expect(recommendedThemeName({ COLORTERM: "truecolor" })).toBe(DEFAULT_THEME_NAME);
    expect(recommendedThemeName({ TERM: "xterm-256color" })).toBe(DEFAULT_THEME_NAME);
    expect(recommendedThemeName({ TERM: "dumb" })).toBe(DEFAULT_THEME_NAME);
  });
});

describe("ANSI_16", () => {
  it("is the canonical table, indexed by position", () => {
    expect(ANSI_16.length).toBe(16);
    ANSI_16.forEach((entry, i) => {
      expect(entry.index).toBe(i);
      expect(isHexColor(entry.hex)).toBe(true);
    });
  });

  it("round-trips through nearestAnsi16", () => {
    for (const entry of ANSI_16) {
      expect(nearestAnsi16(entry.hex)).toBe(entry.index);
    }
  });

  it("maps obvious colours to the obvious slot", () => {
    expect(nearestAnsi16("#010101")).toBe(0);
    expect(nearestAnsi16("#FEFEFE")).toBe(15);
    expect(nearestAnsi16("#FE0202")).toBe(9);
    expect(nearestAnsi16("#02FE02")).toBe(10);
  });

  it("throws on malformed input", () => {
    expect(() => nearestAnsi16("#FFF")).toThrow(TypeError);
    expect(() => nearestAnsi256("nope")).toThrow(TypeError);
  });
});

describe("the ansi theme", () => {
  const palette = THEMES.ansi.palette;

  it("uses only the 16 standard colours", () => {
    const standard = new Set(ANSI_16.map((e) => e.hex));
    for (const token of THEME_TOKENS) {
      expect(standard.has(palette[token])).toBe(true);
    }
  });

  it("is a fixed point of ansi16 degradation", () => {
    expect({ ...degradePalette(palette, "ansi16") }).toEqual({ ...palette });
    expect({ ...degradePalette(palette, "ansi256") }).toEqual({ ...palette });
  });

  it("keeps every text token above AA on its single background", () => {
    for (const token of TEXT_TOKENS) {
      expect(contrastRatio(palette[token], palette.CANVAS)).toBeGreaterThanOrEqual(
        MIN_TEXT_CONTRAST,
      );
    }
  });

  it("documents its trade-off: all three surfaces collapse to index 0", () => {
    // Not an accident. #808080 is the only other dark slot and white on it is
    // 3.95:1 — below AA — so panels are delimited by BORDER, not by fill.
    expect(palette.CANVAS).toBe(palette.PANEL);
    expect(palette.PANEL).toBe(palette.PANEL_ALT);
    expect(contrastRatio("#FFFFFF", "#808080")).toBeLessThan(MIN_TEXT_CONTRAST);
  });
});

describe("degradePalette", () => {
  it("is a no-op for truecolor and for none", () => {
    for (const { palette } of allThemes()) {
      expect(degradePalette(palette, "truecolor")).toBe(palette);
      expect(degradePalette(palette, "none")).toBe(palette);
    }
  });

  it("produces a complete, well-formed palette at every depth", () => {
    for (const { palette } of allThemes()) {
      for (const depth of ["ansi16", "ansi256"] as const) {
        const out = degradePalette(palette, depth);
        expect(Object.keys(out).sort()).toEqual([...THEME_TOKENS].sort());
        for (const token of THEME_TOKENS) expect(isHexColor(out[token])).toBe(true);
      }
    }
  });

  it("is idempotent", () => {
    for (const { palette } of allThemes()) {
      for (const depth of ["ansi16", "ansi256"] as const) {
        const once = degradePalette(palette, depth);
        expect({ ...degradePalette(once, depth) }).toEqual({ ...once });
      }
    }
  });

  it("keeps ansi256 close enough that AA survives", () => {
    for (const { name, palette } of allThemes()) {
      const out = degradePalette(palette, "ansi256");
      for (const token of TEXT_TOKENS) {
        for (const bg of BACKGROUND_TOKENS) {
          if (isWaived(name, token, bg)) continue;
          expect(contrastRatio(out[token], out[bg])).toBeGreaterThanOrEqual(4.3);
        }
      }
    }
  });

  it("does not pretend AA survives ansi16 for arbitrary themes", () => {
    // The honest floor, measured rather than asserted-by-hope: snapping a
    // 24-bit palette onto 16 slots collapses backgrounds together and can only
    // be relied on to keep text legible, not to preserve AA. The `ansi` theme
    // exists precisely because this is not good enough.
    const collapsed = THEME_NAMES.filter((name) => {
      const out = degradePalette(THEMES[name].palette, "ansi16");
      return BACKGROUND_TOKENS.some((bg) => out[bg] !== out.CANVAS) === false;
    });
    expect(collapsed).toContain("dark");
    expect(collapsed).toContain("high-contrast");
  });

  it("hands back an SGR index only where indexing applies", () => {
    expect(ansiIndexFor("#FF0000", "ansi16")).toBe(9);
    expect(ansiIndexFor("#FF0000", "ansi256")).toBe(9);
    expect(ansiIndexFor("#FF0000", "truecolor")).toBeNull();
    expect(ansiIndexFor("#FF0000", "none")).toBeNull();
    for (const { palette } of allThemes()) {
      for (const token of THEME_TOKENS) {
        const i16 = ansiIndexFor(palette[token], "ansi16")!;
        const i256 = ansiIndexFor(palette[token], "ansi256")!;
        expect(i16).toBeGreaterThanOrEqual(0);
        expect(i16).toBeLessThanOrEqual(15);
        expect(i256).toBeGreaterThanOrEqual(0);
        expect(i256).toBeLessThanOrEqual(255);
      }
    }
  });
});

/* ---------------------------------------------------------- settings wiring */

describe("THEME_SETTING_DEF", () => {
  it("matches the shape settings.ts DEFS entries use", () => {
    expect(THEME_SETTING_DEF).toEqual({
      key: "theme",
      label: "Theme",
      description: expect.any(String),
      kind: "enum",
      default: DEFAULT_THEME_NAME,
      choices: THEME_NAMES,
      group: "Display",
    });
  });

  it("offers exactly the registered themes as choices", () => {
    expect([...THEME_SETTING_DEF.choices].sort()).toEqual([...THEME_NAMES].sort());
    for (const choice of THEME_SETTING_DEF.choices) {
      expect(getThemeEntry(choice).name).toBe(choice);
    }
  });

  it("defaults to a choice it actually offers", () => {
    expect(THEME_SETTING_DEF.choices).toContain(THEME_SETTING_DEF.default);
  });

  it("uses a group settings.ts already has, so nothing new needs a heading", () => {
    expect(THEME_SETTING_DEF.group).toBe("Display");
  });
});

/* ------------------------------------------------------------------ purity */

describe("purity", () => {
  it("never mutates a registered palette", () => {
    const before = allThemes().map(({ palette }) => ({ ...palette }));
    for (const { name, palette } of allThemes()) {
      validateTheme(palette, { name });
      worstTextContrast(palette);
      semanticSeparation(palette);
      degradePalette(palette, "ansi16");
      degradePalette(palette, "ansi256");
      severityToneFor(palette, "high");
    }
    expect(allThemes().map(({ palette }) => ({ ...palette }))).toEqual(before);
  });

  it("returns a fresh object from degradePalette rather than aliasing the input", () => {
    const palette = THEMES.light.palette;
    expect(degradePalette(palette, "ansi16")).not.toBe(palette);
  });

  it("gives identical answers on repeated calls", () => {
    for (const { name, palette } of allThemes()) {
      expect(validateTheme(palette, { name })).toEqual(validateTheme(palette, { name }));
      expect(worstTextContrast(palette)).toEqual(worstTextContrast(palette));
    }
  });
});

// ── Installed themes (disk-backed, shareable) ─────────────────────────────────

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach } from "vitest";

import {
  INSTALLED_THEMES_DIRNAME,
  __resetInstalledThemesForTests,
  allThemeNames,
  ensureInstalledThemesLoaded,
  installedThemeEntries,
  installedThemesDir,
  isKnownTheme,
  isSafeThemeId,
  reloadInstalledThemes,
  removeInstalledTheme,
  writeInstalledTheme,
} from "./themes.js";

const themeHomes: string[] = [];
function makeThemeHome(): string {
  const dir = mkdtempSync(join(tmpdir(), "0sec-installed-themes-"));
  themeHomes.push(dir);
  return dir;
}
afterEach(() => {
  __resetInstalledThemesForTests();
  while (themeHomes.length > 0) {
    const dir = themeHomes.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

/** A full, valid palette to seed installed themes with. */
const GOOD_PALETTE = THEMES.midnight.palette;

function seedInstalledTheme(home: string, id: string, palette = GOOD_PALETTE): void {
  const dir = installedThemesDir(home);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${id}.json`), JSON.stringify({ id, label: id, palette }), "utf8");
}

describe("installed theme paths + id safety", () => {
  it("places themes under the shared 0sec state dir", () => {
    expect(installedThemesDir("/home/x")).toBe(`/home/x/.0sec/${INSTALLED_THEMES_DIRNAME}`);
  });
  it("accepts safe ids and rejects traversal / unsafe ones", () => {
    expect(isSafeThemeId("acme.midnight")).toBe(true);
    expect(isSafeThemeId("a_b-c")).toBe(true);
    for (const bad of ["../x", "a/b", "A", "1abc", "", ".", ".."]) {
      expect(isSafeThemeId(bad)).toBe(false);
    }
  });
});

describe("loading installed themes", () => {
  it("returns no installed themes when the dir is absent", () => {
    const home = makeThemeHome();
    expect(installedThemeEntries(home)).toEqual([]);
  });

  it("loads a valid installed palette and makes it resolvable", () => {
    const home = makeThemeHome();
    seedInstalledTheme(home, "acme.midnight");
    const entries = reloadInstalledThemes(home);
    expect([...entries.keys()]).toEqual(["acme.midnight"]);
    expect(isKnownTheme("acme.midnight")).toBe(true);
    expect(getThemeEntry("acme.midnight").name).toBe("acme.midnight");
    expect(getTheme("acme.midnight")).toEqual(GOOD_PALETTE);
  });

  it("adds installed ids to allThemeNames after the built-ins", () => {
    const home = makeThemeHome();
    seedInstalledTheme(home, "acme.midnight");
    reloadInstalledThemes(home);
    expect(allThemeNames(home)).toEqual([...THEME_NAMES, "acme.midnight"]);
  });

  it("skips a corrupt file and a palette that fails validateTheme (fail-soft)", () => {
    const home = makeThemeHome();
    const dir = installedThemesDir(home);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "broken.json"), "{ not json", "utf8");
    writeFileSync(join(dir, "thin.json"), JSON.stringify({ id: "thin", palette: { CANVAS: "#000000" } }), "utf8");
    seedInstalledTheme(home, "acme.midnight");
    const entries = reloadInstalledThemes(home);
    expect([...entries.keys()]).toEqual(["acme.midnight"]);
  });

  it("never lets an installed file shadow a built-in name", () => {
    const home = makeThemeHome();
    seedInstalledTheme(home, "dark"); // would collide with the built-in
    const entries = reloadInstalledThemes(home);
    expect(entries.has("dark")).toBe(false);
  });

  it("isKnownTheme does no I/O — unknown until the cache is populated", () => {
    const home = makeThemeHome();
    seedInstalledTheme(home, "acme.midnight");
    __resetInstalledThemesForTests();
    expect(isKnownTheme("acme.midnight")).toBe(false); // cache empty
    ensureInstalledThemesLoaded(home);
    expect(isKnownTheme("acme.midnight")).toBe(true);
  });
});

describe("writeInstalledTheme / removeInstalledTheme", () => {
  it("writes a valid palette then resolves it after reload", () => {
    const home = makeThemeHome();
    const res = writeInstalledTheme({ id: "acme.midnight", label: "Mid", palette: GOOD_PALETTE }, home);
    expect(res.ok).toBe(true);
    reloadInstalledThemes(home);
    expect(isKnownTheme("acme.midnight")).toBe(true);
  });

  it("fails closed on an invalid palette", () => {
    const home = makeThemeHome();
    const res = writeInstalledTheme({ id: "bad", palette: { CANVAS: "#000000" } as never }, home);
    expect(res.ok).toBe(false);
  });

  it("refuses a built-in name and an unsafe id", () => {
    const home = makeThemeHome();
    expect(writeInstalledTheme({ id: "dark", palette: GOOD_PALETTE }, home).ok).toBe(false);
    expect(writeInstalledTheme({ id: "../x", palette: GOOD_PALETTE }, home).ok).toBe(false);
  });

  it("removes an installed theme and refuses built-ins", () => {
    const home = makeThemeHome();
    seedInstalledTheme(home, "acme.midnight");
    reloadInstalledThemes(home);
    expect(removeInstalledTheme("acme.midnight", home).ok).toBe(true);
    expect(reloadInstalledThemes(home).has("acme.midnight")).toBe(false);
    expect(removeInstalledTheme("dark", home).ok).toBe(false);
    expect(removeInstalledTheme("acme.midnight", home).ok).toBe(false); // already gone
  });
});

/**
 * Live theme hot-swap, at the resolver the React provider uses.
 *
 * `theme-context.ts`'s `paletteFor` maps the current `theme` setting to a palette
 * with `getTheme(name)` on every render, and re-renders when the setting changes
 * (it subscribes to the settings store). So "switching the theme applies live" is,
 * at the resolver level, exactly: feeding `getTheme`/`getThemeEntry` a new name
 * returns the new palette immediately — no restart, no cached previous palette.
 * These assert that for built-ins AND for a loaded user theme.
 */
describe("live hot-swap resolution (getTheme follows the setting name)", () => {
  it("returns the new palette the instant the name changes, across built-ins", () => {
    // Simulate the setting flipping between palettes on successive renders.
    let name: string = "dark";
    expect(getTheme(name)).toBe(THEMES.dark.palette);
    name = "high-contrast";
    expect(getTheme(name)).toBe(THEMES["high-contrast"].palette);
    name = "light";
    expect(getTheme(name)).toBe(THEMES.light.palette);
  });

  it("resolves a loaded user theme live, then swaps back to a built-in", () => {
    const home = makeThemeHome();
    seedInstalledTheme(home, "acme.midnight");
    reloadInstalledThemes(home); // the load path populates the cache before render

    // Setting points at the user theme -> its palette resolves.
    expect(getTheme("acme.midnight")).toEqual(GOOD_PALETTE);
    expect(getThemeEntry("acme.midnight").name).toBe("acme.midnight");

    // Setting flips to a built-in -> the built-in resolves, no stale user palette.
    expect(getTheme("light")).toBe(THEMES.light.palette);
  });
});

/* ------------------------------------------------------------------- swiss */

describe("swiss theme", () => {
  it("is registered and listed in THEME_NAMES", () => {
    expect(THEME_NAMES).toContain("swiss");
    expect(isThemeName("swiss")).toBe(true);
    expect(THEMES.swiss.name).toBe("swiss");
    expect(THEMES.swiss.label).toBe("Swiss");
    expect(THEMES.swiss.mode).toBe("dark");
  });

  it("resolves through every accessor and the settings picker choices", () => {
    expect(getTheme("swiss")).toBe(THEMES.swiss.palette);
    expect(getThemeEntry("swiss").name).toBe("swiss");
    // The settings theme picker syncs its choices off THEME_NAMES.
    expect(THEME_SETTING_DEF.choices).toContain("swiss");
  });

  it("defines every token, no extras, uppercase 6-digit hex", () => {
    const palette = THEMES.swiss.palette as Record<string, string>;
    expect(new Set(Object.keys(palette))).toEqual(new Set(THEME_TOKENS));
    for (const token of THEME_TOKENS) {
      expect(palette[token], token).toMatch(/^#[0-9A-F]{6}$/);
    }
  });

  it("passes validateTheme with NO waiver — every contrast floor met", () => {
    // No `name` option: validated with zero waivers, exactly as a shipped
    // non-default theme must be.
    expect(validateTheme(THEMES.swiss.palette)).toEqual([]);
  });

  it("holds each key contrast pair above its floor", () => {
    const p = THEMES.swiss.palette;
    // TEXT on CANVAS well past the 4.5:1 text bar.
    expect(contrastRatio(p.TEXT, p.CANVAS)).toBeGreaterThanOrEqual(MIN_TEXT_CONTRAST);
    // BORDER above the 3:1 non-text bar on every surface.
    for (const bg of BACKGROUND_TOKENS) {
      expect(contrastRatio(p.BORDER, p[bg]), bg).toBeGreaterThanOrEqual(MIN_CHROME_CONTRAST);
    }
    // Swiss red as ERROR is AA-legible on the canvas.
    expect(contrastRatio(p.ERROR, p.CANVAS)).toBeGreaterThanOrEqual(MIN_TEXT_CONTRAST);
    // Semantic trio stays separable for colour-blind readers.
    for (const [a, b] of SEMANTIC_PAIRS) {
      expect(contrastRatio(p[a], p[b]), `${a}/${b}`).toBeGreaterThanOrEqual(MIN_SEMANTIC_CONTRAST);
    }
  });

  it("leans red for the highlight tokens", () => {
    const p = THEMES.swiss.palette;
    const red = parseHex(p.PRIMARY)!;
    expect(red.r).toBeGreaterThan(red.g);
    expect(red.r).toBeGreaterThan(red.b);
    expect(p.BRAND).toBe(p.PRIMARY);
    expect(p.ERROR).toBe(p.PRIMARY);
  });
});
