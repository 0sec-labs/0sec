# Console themes

`themes.ts` replaces the single hardcoded palette in `../ui/theme.ts` with a
checked registry of four. It is pure — no I/O, no React, no `process` access —
in the same spirit as `chat-layout.ts`, so every claim below is a unit test in
`themes.test.ts` rather than a designer's assurance.

Nothing is wired yet. `ui/theme.ts`, `chat-screen.tsx`, `run.tsx` and
`settings.ts` are untouched; see [Wiring checklist](#wiring-checklist).

---

## The token set

Twelve tokens, derived by reading `ui/theme.ts` and grepping both consumers.
Both `chat-screen.tsx` and `run.tsx` import all twelve, and nothing else — no
token is exported-but-unused, and no token is used-but-unexported. `Theme` is a
mapped type over exactly this union, so adding a thirteenth token breaks
compilation on every palette that has not been updated.

The twelve split into three *roles*, and the role decides which contrast bar
applies:

| Role | Tokens | Bar | Why |
| --- | --- | --- | --- |
| Background | `CANVAS`, `PANEL`, `PANEL_ALT` | — | The surfaces text is painted on |
| Text | `TEXT`, `MUTED`, `PRIMARY`, `ACCENT`, `SUCCESS`, `WARNING`, `ERROR`, `INFO` | **4.5:1** | WCAG 2.2 SC 1.4.3 (AA, normal text) |
| Chrome | `BORDER` | **3:1** | WCAG 2.2 SC 1.4.11 (non-text contrast) |

Two facts from the call sites shaped that table:

- **`PRIMARY`, `ACCENT` and `ERROR` also appear as `backgroundColor`** — at
  `chat-screen.tsx:412`, `:424` and `:487` — but only on `width={1}`
  `alignSelf="stretch"` rails that never carry text. They are not text
  backgrounds and are not swept as such. The only surfaces text lands on are
  `CANVAS` (the two screen roots, `chat-screen.tsx:2751` and `run.tsx:1434`),
  `PANEL` and `PANEL_ALT`.
- **`BORDER` is only ever a `borderColor`.** It draws box-drawing glyphs that
  carry no information a reader has to decode, which is WCAG's definition of a
  non-text UI component. Holding a hairline rule to 4.5:1 would make every
  panel edge as loud as the text inside it. The distinction is explicit
  (`CHROME_TOKENS`, `MIN_CHROME_CONTRAST`), not a silent exemption.

### One discrepancy worth fixing separately

`run.tsx` hardcodes `"#CCCCCC"` six times (lines 788, 941, 1627, 1652, 2120,
2840) as the "inactive row" foreground — `fg={active ? TEXT : "#CCCCCC"}`. It is
a colour with a job and no token, so it will not follow a theme switch. It is
not in `Theme` because inventing a token for it would mean editing `run.tsx`,
which this module may not do. Suggested follow-up: add a `TEXT_DIM` token and
replace the six literals. On the dark palette `#CCCCCC` sits at 12.47:1 on
`CANVAS`, so it is safe today and only becomes a bug on the light theme, where
it drops to **1.55:1 on `CANVAS` and 1.22:1 on `PANEL_ALT` — illegible**. This
is the single hard blocker on shipping `light`.

`severityTone` is a function, not a token. `severityToneFor(palette, severity)`
is the theme-aware replacement with an identical mapping.

---

## The four themes

Contrast columns are ratios against `CANVAS` / `PANEL` / `PANEL_ALT` in that
order. Every number here is asserted in `themes.test.ts`.

### `dark` — "0sec Dark" (default)

The palette shipped today, **byte-for-byte**. It is the default because an
upgrade must not restyle anyone's console; a theme system that silently
changes what everybody already has is a regression wearing a feature's
clothes. It is therefore the one palette that is not free to be fixed, and it
holds the only contrast waivers in the module.

Surfaces: `CANVAS` `#080808` · `PANEL` `#111111` · `PANEL_ALT` `#171515`

| Token | Swatch | vs CANVAS | vs PANEL | vs PANEL_ALT |
| --- | --- | --- | --- | --- |
| `TEXT` | `#F3EEE9` | 17.37 | 16.38 | 15.78 |
| `MUTED` | `#8A7D73` | 5.02 | 4.73 | 4.56 |
| `PRIMARY` | `#E28553` | 7.36 | 6.94 | 6.68 |
| `ACCENT` | `#F0B08D` | 10.78 | 10.16 | 9.79 |
| `SUCCESS` | `#22C55E` | 8.79 | 8.29 | 7.98 |
| `WARNING` | `#EAB308` | 10.44 | 9.85 | 9.48 |
| `ERROR` | `#DC2626` | **4.15** | **3.91** | **3.77** |
| `INFO` | `#C99A7A` | 8.00 | 7.54 | 7.26 |
| `BORDER` | `#25201D` | **1.24** | **1.17** | **1.13** |

**Worst text ratio: 3.77:1** (`ERROR` on `PANEL_ALT`) — a waived failure.
**Semantic separation: 1.188:1** — the tightest of the four, and the value that
sets the floor for every other theme.

### `light` — "Paper"

For terminals on a light background, which are currently unusable: `TEXT`
`#F3EEE9` on white is 1.15:1.

Not an inversion of the dark palette, and it could not be. On paper the usable
foreground luminance band is roughly **[0, 0.13]** — anything lighter than
L≈0.13 cannot reach 4.5:1 against `PANEL_ALT`, the darkest surface. Every
foreground here is therefore a dark colour, and the palette's expressive range
is hue and saturation rather than brightness. The brand orange survives as a
burnt `PRIMARY`; `INFO` moves from the dark theme's tan to a slate blue,
because a light tan on paper is invisible and blue is the one strongly
separated hue the warm palette was not already using.

Surfaces: `CANVAS` `#FDFBF7` · `PANEL` `#F3EEE5` · `PANEL_ALT` `#E7E0D3`

| Token | Swatch | vs CANVAS | vs PANEL | vs PANEL_ALT |
| --- | --- | --- | --- | --- |
| `TEXT` | `#1C1713` | 17.20 | 15.38 | 13.54 |
| `MUTED` | `#564C43` | 8.09 | 7.24 | 6.37 |
| `PRIMARY` | `#903F0E` | 7.00 | 6.26 | 5.51 |
| `ACCENT` | `#8B5429` | 5.98 | 5.35 | 4.71 |
| `SUCCESS` | `#1A6934` | 6.52 | 5.84 | 5.14 |
| `WARNING` | `#654700` | 8.28 | 7.40 | 6.52 |
| `ERROR` | `#750E0E` | 11.13 | 9.95 | 8.76 |
| `INFO` | `#17456B` | 9.68 | 8.65 | 7.62 |
| `BORDER` | `#837767` | 4.23 | 3.79 | 3.33 |

**Worst text ratio: 4.71:1** (`ACCENT` on `PANEL_ALT`) — passes AA, no waivers.
**Semantic separation: 1.269:1.**

`PRIMARY` and `ACCENT` sit closer in luminance here (1.17:1) than they do on
dark (1.46:1). That is the [0, 0.13] band again: widening them would push
`ACCENT` past the 4.5:1 line. They stay separated by saturation instead.

### `high-contrast` — "Contrast"

Every text token at **WCAG AAA (7:1) or better**, on a pure black canvas. The
name is a guarantee, not a mood: `themes.test.ts` validates this palette
against `AAA_TEXT_CONTRAST` specifically. `BORDER` is a mid grey at 8.63:1,
because visible chrome is the point here rather than a hairline.

Surfaces: `CANVAS` `#000000` · `PANEL` `#0B0B0B` · `PANEL_ALT` `#161616`

| Token | Swatch | vs CANVAS | vs PANEL | vs PANEL_ALT |
| --- | --- | --- | --- | --- |
| `TEXT` | `#FFFFFF` | 21.00 | 19.68 | 18.10 |
| `MUTED` | `#BCBCBC` | 11.06 | 10.36 | 9.53 |
| `PRIMARY` | `#F89E4B` | 9.98 | 9.36 | 8.60 |
| `ACCENT` | `#FCCFA6` | 14.61 | 13.70 | 12.59 |
| `SUCCESS` | `#3AE483` | 12.61 | 11.81 | 10.86 |
| `WARNING` | `#FFE635` | 16.62 | 15.58 | 14.32 |
| `ERROR` | `#FC8979` | 8.99 | 8.43 | 7.75 |
| `INFO` | `#82DAFF` | 13.42 | 12.58 | 11.57 |
| `BORDER` | `#B3B3B3` | 10.02 | 9.39 | 8.63 |

**Worst text ratio: 7.75:1** (`ERROR` on `PANEL_ALT`) — AAA throughout.
**Semantic separation: 1.319:1** — the widest of the four.

### `ansi` — "ANSI 16"

Every value is a canonical xterm 16-colour entry, so `nearestAnsi16` is the
**identity** on this palette. On a terminal that approximates truecolor down to
its sixteen slots, this theme lands exactly where it was drawn instead of
drifting somewhere unreadable — see [Terminal capability](#terminal-capability)
for what that drift looks like.

Surfaces: `CANVAS` = `PANEL` = `PANEL_ALT` = `#000000` (index 0)

| Token | Swatch | SGR | vs any surface |
| --- | --- | --- | --- |
| `TEXT` | `#FFFFFF` | 15 | 21.00 |
| `MUTED` | `#808080` | 8 | 5.32 |
| `PRIMARY` | `#00FFFF` | 14 | 16.75 |
| `ACCENT` | `#FF00FF` | 13 | 6.70 |
| `SUCCESS` | `#00FF00` | 10 | 15.30 |
| `WARNING` | `#FFFF00` | 11 | 19.56 |
| `ERROR` | `#FF0000` | 9 | 5.25 |
| `INFO` | `#C0C0C0` | 7 | 11.54 |
| `BORDER` | `#808080` | 8 | 5.32 |

**Worst text ratio: 5.25:1** (`ERROR`). **Semantic separation: 1.278:1**, and
3.72:1 between `WARNING` and `ERROR` — the bright ANSI primaries are far apart
in luminance by construction, which makes this the most colour-blind-robust
palette of the four.

Two costs, both real and both asserted in the tests rather than glossed:

- **All three surfaces are index 0.** The only other dark-ish slot is `#808080`,
  and white on `#808080` is 3.95:1 — below AA. Panels are therefore delimited
  by `BORDER` glyphs, not by fill.
- **`MUTED` and `BORDER` share index 8.** Sixteen slots do not stretch to nine
  distinct roles once index 12 (`#0000FF`, **2.44:1** on black) is ruled out as
  a text colour.

---

## Waivers: where the default knowingly fails

"Preserve the shipped palette byte-for-byte" and "meet 4.5:1" are in direct
conflict for two tokens in `dark`. Preserving won, because the alternative is
restyling every existing operator's console on upgrade, and because the fix is
one line whenever the operator decides a visible change is acceptable.

The failures are **enumerated in `CONTRAST_WAIVERS`, not hidden behind a
lowered threshold** — the threshold is still 4.5:1, and these six triples are
listed individually with their measured ratios:

| Theme | Token | Surface | Measured | Bar | Fix if a visible change is acceptable |
| --- | --- | --- | --- | --- | --- |
| `dark` | `ERROR` | `CANVAS` | 4.15:1 | 4.5 | `#DC2626` → `#F4695E` (6.70 / 6.32 / 6.09) |
| `dark` | `ERROR` | `PANEL` | 3.91:1 | 4.5 | ” |
| `dark` | `ERROR` | `PANEL_ALT` | 3.77:1 | 4.5 | ” |
| `dark` | `BORDER` | `CANVAS` | 1.24:1 | 3.0 | `#25201D` → `#726359` (3.48 / 3.28 / 3.16) |
| `dark` | `BORDER` | `PANEL` | 1.17:1 | 3.0 | ” |
| `dark` | `BORDER` | `PANEL_ALT` | 1.13:1 | 3.0 | ” |

Each waiver **pins its measured ratio to two decimal places**, and the test
asserts the palette still measures exactly that. Editing the default palette
therefore fails the build whether it makes contrast better or worse — the
waiver cannot rot into a rubber stamp. Further tests assert that no waiver
covers a pair that already passes, that no theme other than `dark` has one, and
that the replacement colours above actually clear their bars.

`light`, `high-contrast` and `ansi` have **no waivers**: `validateTheme` returns
an empty issue list for all three.

---

## Colour blindness

`SUCCESS`, `WARNING` and `ERROR` signal tool outcomes. Distinguishing them by
hue alone fails for roughly 8% of men: deuteranopia and protanopia collapse
red-green, and green-yellow is the classic residual confusion. A red and a
green at identical luminance are the same cell to a deuteranope.

**The constraint enforced:** every pair drawn from `{SUCCESS, WARNING, ERROR}`
must reach **`MIN_SEMANTIC_CONTRAST` = 1.15:1** against *each other* — a
luminance step, not a hue step. Contrast ratio rather than an absolute
luminance delta, because the ratio is scale-invariant and so means the same
thing on the light palette (where all three foregrounds live below L = 0.13) as
on the dark one.

| Theme | SUCCESS/WARNING | SUCCESS/ERROR | WARNING/ERROR | **min** |
| --- | --- | --- | --- | --- |
| `dark` | **1.188** | 2.119 | 2.518 | **1.188** |
| `light` | **1.269** | 1.706 | 1.345 | **1.269** |
| `high-contrast` | **1.319** | 1.402 | 1.848 | **1.319** |
| `ansi` | **1.278** | 2.914 | 3.724 | **1.278** |

The threshold is a floor set by the one palette that may not move: `dark`'s
green/yellow pair measures 1.188:1, the tightest of the four. The three
designed palettes all clear 1.26:1. **If the default is ever allowed to change,
raise `MIN_SEMANTIC_CONTRAST`** — a test asserts `dark` is currently the
minimum, so the day that stops being true is visible.

Three tests back this up: the pairwise sweep, a strict-ordering check (no two
of the three may share a luminance in any theme), and a greyscale round-trip
that discards hue entirely, converts each token to the grey of equal relative
luminance, and re-runs the separation check on the greys.

---

## Terminal capability

**What is implemented — and only this.**

`detectColorDepth(env)` infers a `ColorDepth` from environment variables, in
order:

| Condition | Result |
| --- | --- |
| `NO_COLOR` set to anything (no-color.org convention) | `none` |
| `TERM=dumb` | `none` |
| `FORCE_COLOR` = `0`/`false` · `1` · `2` · `3`/`true`/empty | `none` · `ansi16` · `ansi256` · `truecolor` |
| `COLORTERM` contains `truecolor` or `24bit` | `truecolor` |
| `TERM` contains `truecolor` or `direct` | `truecolor` |
| `TERM` contains `256` | `ansi256` |
| anything else, including unset `TERM` | `ansi16` |

`NO_COLOR` beats `FORCE_COLOR`. The final fallback is deliberately
conservative: guessing low costs fidelity, guessing high costs legibility.

**What is not implemented, and is not claimed.** This is inference from
environment variables only. It does not query the terminal, parse terminfo, or
probe with an OSC/DA sequence — none of which can be done synchronously and
side-effect-free, and this module is pure. `detectColorDepth` takes the
environment as an argument rather than reading `process.env`, precisely so the
result is a *suggestion the operator can override*, which is also why
`degradePalette` takes a depth rather than detecting one. `recommendedThemeName(env)`
wraps the two into a starting suggestion: `ansi` when the terminal looks
16-colour, the default otherwise.

### What the fallback actually does

`degradePalette(palette, depth)` replaces each hex with the nominal hex of the
nearest entry in the 16- or 256-colour palette, using redmean distance (a cheap
approximation of perceptual distance that behaves far better than plain RGB
Euclidean on saturated colours, and needs no dependency).

It **does not change how colour reaches the terminal.** OpenTUI is handed hex
strings and emits 24-bit SGR either way; a genuinely 16-colour terminal still
performs its own approximation of that sequence. Snapping first removes the
*drift* between what we picked and where the terminal lands — it does not
remove the conversion. A renderer that can emit indexed SGR should call
`ansiIndexFor(hex, depth)` instead, which returns an SGR index (or `null` for
`truecolor`/`none`). Nothing in the TUI emits indexed SGR today.

`depth: "none"` returns the palette unchanged. Suppressing colour is the
renderer's job, not the palette's; returning twelve identical strings would be
a worse lie than doing nothing.

### Why the `ansi` theme exists at all

Because automatic degradation of a truecolor palette is not good enough, and
the test says so. Snapping `dark` to 16 colours gives:

```
TEXT->15  MUTED->8  PRIMARY->8  ACCENT->7  SUCCESS->6  WARNING->11
ERROR->9  INFO->8   BORDER->0   CANVAS->0  PANEL->0    PANEL_ALT->0
```

`SUCCESS` becomes **cyan**. `MUTED`, `PRIMARY` and `INFO` all collapse onto
index 8, so three roles become one colour. All three surfaces flatten to index
0, so panels disappear. `high-contrast` degrades no better — five of its
foregrounds land on index 7.

A palette designed *in* the sixteen colours is the only honest answer, and
`degradePalette(ANSI, "ansi16")` is a fixed point.

Note that the sixteen are **nominal**. Almost every terminal lets the user
retheme its slots, so index 2 is "whatever this terminal calls green", not
`#008000`. That is the limit of what any static palette can know, and the
reason `ansiIndexFor` exists as an alternative to snapping.

---

## API

All pure. No I/O, no React, no `process`.

```ts
// registry
THEMES: Readonly<Record<ThemeName, ThemeEntry>>
THEME_NAMES: readonly ThemeName[]
DEFAULT_THEME_NAME: ThemeName            // "dark"
getTheme(name: unknown): Theme           // total; unknown name -> default
getThemeEntry(name: unknown): ThemeEntry // total
isThemeName(value: unknown): value is ThemeName
severityToneFor(palette: Theme, severity: string): string

// colour maths (WCAG 2.2)
parseHex(hex: string): Rgb | null        // null, never throws
isHexColor(value: unknown): value is string
relativeLuminance(hex: string): number   // throws TypeError on bad hex
contrastRatio(a: string, b: string): number

// thresholds
MIN_TEXT_CONTRAST = 4.5    // SC 1.4.3 AA
MIN_CHROME_CONTRAST = 3    // SC 1.4.11
AAA_TEXT_CONTRAST = 7      // SC 1.4.6
MIN_SEMANTIC_CONTRAST = 1.15

// validation
validateTheme(palette: unknown, options?: ValidateThemeOptions): ThemeIssue[]
CONTRAST_WAIVERS: readonly ContrastWaiver[]
isWaived(theme, token, against): boolean
worstTextContrast(palette): { token; against; ratio }
semanticSeparation(palette): number

// terminal capability
detectColorDepth(env?): ColorDepth
degradePalette(palette: Theme, depth: ColorDepth): Theme
ansiIndexFor(hex: string, depth: ColorDepth): number | null
nearestAnsi16(hex): number   nearestAnsi256(hex): number
recommendedThemeName(env?): ThemeName
ANSI_16: readonly { index; name; hex }[]

// settings
THEME_SETTING_DEF   // a SettingDef<ThemeName>, ready to drop into DEFS
```

`getTheme` is **total by design**: it is called from the render path with a
value that came out of a hand-editable `tui-settings.json`, so an unknown name,
the wrong case, or a non-string degrades to the default. Same contract
`normalizeSettings` already holds itself to — a typo in a config file must not
be able to take down a session.

`validateTheme` returns *every* issue rather than the first, so a bad palette
produces one actionable report instead of whack-a-mole. It accepts `unknown`,
because the interesting future caller is a user-supplied palette parsed from
JSON.

---

## Wiring checklist

Six steps. Nothing below has been done — every file named is owned by someone
else right now.

1. **`settings.ts`** — add `theme: ThemeName` to `TuiSettings`; add
   `THEME_SETTING_DEF` to the `DEFS` array; add `theme: DEFAULT_THEME_NAME` to
   `DEFAULT_SETTINGS`. `THEME_SETTING_DEF` is typed against that module's
   exported `SettingDef` and already uses the existing `"Display"` group, so no
   new heading is needed. `DEFS` is typed as a union of narrow per-key defs; the
   entry may need a `EnumSettingDef<"theme">` arm added to `TuiSettingDef`.

2. **`ui/theme.ts`** — keep the twelve `export const`s as-is so nothing breaks
   mid-migration. They become "the dark palette, spelled out"; `themes.test.ts`
   asserts `THEMES.dark.palette` still matches them byte-for-byte, so the two
   cannot drift silently.

3. **A theme context** — the palette has to reach the components. Either a
   React context provider around the two screen roots, or a prop threaded from
   `run.tsx`. Context is less invasive given the depth of the trees.

4. **`chat-screen.tsx` / `run.tsx`** — replace the `import { ACCENT, … } from
   "../ui/theme.js"` block with a palette read, and each bare `TEXT` with
   `theme.TEXT`. Mechanical: 12 tokens, ~480 references. Replace
   `severityTone(s)` in `run.tsx` (6 call sites) with
   `severityToneFor(theme, s)`.

5. **Fix the `#CCCCCC` literals** in `run.tsx` (6 sites) before enabling
   `light` — see [the discrepancy note](#one-discrepancy-worth-fixing-separately).
   This is a hard blocker: `#CCCCCC` is 1.55:1 on Paper's canvas.

6. **Optional, capability-aware default** — if the operator has never chosen a
   theme, `recommendedThemeName(process.env)` gives `ansi` on a terminal that
   looks 16-colour. Call it once at startup; do not call it on every render, and
   do not let it override an explicit setting.

Extending the token set: add the name to `BACKGROUND_TOKENS`, `TEXT_TOKENS` or
`CHROME_TOKENS` in `themes.ts` and the compiler will refuse to build until all
four palettes define it. The contrast sweep then covers it automatically.

## Verification

```
pnpm --filter 0sec-cli exec vitest run src/tui/themes.test.ts
pnpm --filter 0sec-cli exec tsc --noEmit -p tsconfig.json
```
