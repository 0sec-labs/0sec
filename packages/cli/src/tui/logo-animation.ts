/**
 * Pure, deterministic per-frame animation for the "0SEC" block-logo intro.
 *
 * This module owns only the *logic* of the intro: given the base logo grid
 * (the three-letter colour map used by the masthead — `' '` empty, `'#'` white,
 * `'/'` red), an animation style, and a frame index, it returns the per-cell
 * render state for that frame. It renders nothing, imports no theme, reads no
 * clock — `computeLogoFrame(grid, style, frame)` is a pure function of its
 * inputs, so every frame is unit-testable in isolation.
 *
 * The caller (the masthead) drives it with a frame ticker and maps each cell's
 * `tone` to a theme token and `visible`/tone to `TextAttributes.DIM`:
 *
 *   tone "text"  -> theme.TEXT   (full)
 *   tone "error" -> theme.ERROR  (full, the red slash)
 *   tone "dim"   -> theme.TEXT (or a dim token) + TextAttributes.DIM
 *   tone "muted" -> theme.MUTED  (the mid/highlight tone; DIM optional)
 *   tone "brand" -> theme.BRAND  (the purple accent — a bright leading edge or
 *                                 pulse peak)
 *   tone "#rrggbb" -> that literal colour as the foreground (see COLOUR below)
 *   visible:false -> render a single space (the cell is not yet drawn)
 *
 * COLOUR CONTRACT. The flashy styles (rainbow, matrix-rain, wave, neon, and the
 * comet gradients of shimmer/fade/strike/draw) need arbitrary per-cell colour,
 * not just the five named tones. Rather than smuggle a second field through the
 * render (the masthead paints one coalesced run at a time and reads only
 * `run.tone`), a cell's `tone` may itself BE an explicit `#rrggbb` hex string.
 * `logoRunStyle` (chat/logo.ts) recognises a leading `#` and passes it straight
 * through as the foreground; every other value is one of the named tones it maps
 * to a theme token. This module stays pure — it computes the hex (see
 * `hslToHex`/`greyHex`) and never imports a theme; the theme mapping lives in the
 * caller. A hex tone is transient: no colourful style carries one into its final
 * frame, so `finalLogoFrame` (the `off`/`reduceMotion`/settled mark) is always
 * the mono/red-slash resting frame with only named tones.
 *
 * Because the caller renders cell-by-cell from this state, the row widths are
 * preserved verbatim (every row is padded to the grid's max width), so no
 * `fitTuiText` pass is needed and the OpenTUI row-overflow invariant holds.
 */

/**
 * Intro styles, matching settings.ts `logoAnimation`.
 *
 * One-shot reveals play once and settle to `finalLogoFrame`:
 *   - `glitch`  a deterministic scramble (now with neon flashes) that resolves
 *               cell by cell — the DEFAULT.
 *   - `matrix`  a matrix-rain reveal: staggered green drops fall column by
 *               column, each leaving the settled mark behind it.
 *   - `wave`    a rippling cyan wavefront (a sine-bent edge) wipes the mark in.
 *   - `neon`    a neon-sign warm-up: cells buzz on in neon colours, then settle.
 *   - `strike`  a red slash strikes the 0 along its diagonal (purple hot edge).
 *   - `draw`    a left-to-right column reveal behind a bright pen tip.
 *   - `fade`    a centre-out brightness bloom (a purple-tinted multi-step ramp).
 *   - `typein`  per-cell reveal in reading order with a purple leading glow.
 *   - `sweep`   a bright bar wipes L→R revealing the mark behind it.
 * Looping idle effects run forever (the caller wraps the frame modulo the count):
 *   - `rainbow` a hue sweep cycling the spectrum across the mark, forever.
 *   - `shimmer` a bright comet (a multi-step grey gradient tail) sweeps across.
 *   - `pulse`   the red slash breathes dim→red→purple.
 * `off` is the static settled mark.
 */
export type LogoAnimStyle =
  | "glitch"
  | "rainbow"
  | "matrix"
  | "wave"
  | "neon"
  | "shimmer"
  | "pulse"
  | "strike"
  | "draw"
  | "fade"
  | "typein"
  | "sweep"
  | "off";

/** The logo alphabet: empty, white block, red-slash block. */
export type LogoCellChar = " " | "#" | "/";

/** The five named render tones the caller maps to theme tokens (and DIM). */
export type LogoNamedTone = "text" | "error" | "dim" | "muted" | "brand";

/**
 * Render tone for one cell. Either a NAMED tone (`text`/`error` are the final
 * full colours; `dim` a DIM step; `muted` the mid/highlight tone; `brand` the
 * purple accent) OR an explicit `#rrggbb` hex the caller paints as-is (the
 * rainbow/matrix/neon/comet colours — see the COLOUR CONTRACT above). The `&
 * {}` keeps named-tone autocomplete while still admitting any hex string. A hex
 * tone is never a *final* tone, so `finalLogoFrame` and `reduceMotion` carry
 * only named tones.
 */
export type LogoCellTone = LogoNamedTone | (string & {});

/** Per-cell render state for a single frame. */
export interface LogoCellState {
  /** The cell's glyph class from the base grid (unchanged by the animation). */
  ch: LogoCellChar;
  /** Whether the cell is drawn this frame. `false` -> render a space. */
  visible: boolean;
  /** Which tone token (or explicit hex) the caller should paint the cell with. */
  tone: LogoCellTone;
}

/** A full frame: one `LogoCellState` per grid cell, row-major, rectangular. */
export type LogoFrame = LogoCellState[][];

/**
 * One coalesced run of adjacent cells sharing a `(tone, visible)` pair, so the
 * caller can paint each run as a single explicitly-sized `<text>` rather than a
 * cell per element — the animated analogue of the masthead's raw-glyph runs, but
 * keyed on the frame's render state instead of the raw glyph alphabet. Run
 * lengths across a row sum to the frame's (padded) width, so no run overflows.
 */
export interface LogoRun {
  /** Number of cells this run spans. */
  length: number;
  /** The shared tone (or hex); the caller maps it to a foreground colour (+ DIM). */
  tone: LogoCellTone;
  /** Shared visibility; `false` runs render as `length` spaces. */
  visible: boolean;
}

/** Coalesce one frame row into `(tone, visible)` runs, preserving order. */
export function logoRowRuns(row: readonly LogoCellState[]): LogoRun[] {
  const runs: LogoRun[] = [];
  for (const cell of row) {
    const last = runs[runs.length - 1];
    if (last && last.tone === cell.tone && last.visible === cell.visible) {
      last.length += 1;
    } else {
      runs.push({ length: 1, tone: cell.tone, visible: cell.visible });
    }
  }
  return runs;
}

/**
 * One-shot frame budgets per style (the number of distinct frames in the
 * intro). Sized for the shipped 0SEC mark (5 rows x 35 cols) but the compute
 * function scales its thresholds to the actual grid, so a differently-sized
 * grid still reveals fully by the final frame.
 *
 * Looping styles (`rainbow`, `shimmer`, `pulse`) treat their count as the loop
 * *period*. For `shimmer` the comet sweeps columns 0..width-1 then the remaining
 * frames are a rest gap before it repeats — keep the period comfortably above
 * the grid width so every column is highlighted once per loop.
 */
const FRAME_COUNTS: Record<LogoAnimStyle, number> = {
  glitch: 20,
  rainbow: 42,
  matrix: 26,
  wave: 24,
  neon: 20,
  shimmer: 48,
  pulse: 24,
  strike: 16,
  draw: 22,
  fade: 16,
  typein: 28,
  sweep: 20,
  off: 1,
};

/** Styles that loop forever (the caller wraps the frame index modulo count). */
const LOOPS: Record<LogoAnimStyle, boolean> = {
  glitch: false,
  rainbow: true,
  matrix: false,
  wave: false,
  neon: false,
  shimmer: true,
  pulse: true,
  strike: false,
  draw: false,
  fade: false,
  typein: false,
  sweep: false,
  off: false,
};

/** Total frames in the one-shot intro (loop period for looping styles). */
export function logoAnimationFrameCount(style: LogoAnimStyle): number {
  return FRAME_COUNTS[style] ?? 1;
}

/** Whether the style loops (rainbow, shimmer, pulse) vs playing once and settling. */
export function logoAnimationLoops(style: LogoAnimStyle): boolean {
  return LOOPS[style] ?? false;
}

/** Normalise a raw grid char to the logo alphabet. */
function cellCharAt(grid: readonly string[], row: number, col: number): LogoCellChar {
  const ch = grid[row]?.[col];
  return ch === "#" ? "#" : ch === "/" ? "/" : " ";
}

/** The widest row's length; the frame is padded to this many columns. */
function gridWidth(grid: readonly string[]): number {
  let w = 0;
  for (const row of grid) if (row.length > w) w = row.length;
  return w;
}

/** Final full colour of a cell, ignoring animation. */
function finalTone(ch: LogoCellChar): LogoCellTone {
  return ch === "/" ? "error" : "text";
}

/**
 * The static, fully-revealed frame: every non-space cell visible at its final
 * (named) tone. This is the target of `off`, of `reduceMotion`, and of the last
 * frame of every one-shot style — always mono/red-slash, never a hex.
 */
export function finalLogoFrame(grid: readonly string[]): LogoFrame {
  const width = gridWidth(grid);
  const frame: LogoFrame = [];
  for (let r = 0; r < grid.length; r += 1) {
    const rowState: LogoCellState[] = [];
    for (let c = 0; c < width; c += 1) {
      const ch = cellCharAt(grid, r, c);
      rowState.push(
        ch === " "
          ? { ch, visible: false, tone: "text" }
          : { ch, visible: true, tone: finalTone(ch) },
      );
    }
    frame.push(rowState);
  }
  return frame;
}

/** Build a blank rectangular frame (all cells hidden) to fill in per style. */
function blankFrame(grid: readonly string[], width: number): LogoFrame {
  const frame: LogoFrame = [];
  for (let r = 0; r < grid.length; r += 1) {
    const rowState: LogoCellState[] = [];
    for (let c = 0; c < width; c += 1) {
      rowState.push({ ch: cellCharAt(grid, r, c), visible: false, tone: "text" });
    }
    frame.push(rowState);
  }
  return frame;
}

/** Progress in [0,1] across a one-shot of `count` frames at clamped `frame`. */
function progressOf(frame: number, count: number): number {
  if (count <= 1) return 1;
  return frame / (count - 1);
}

/** Clamp to [0,1]. */
function clamp01(x: number): number {
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

/**
 * Smoothstep easing on [0,1]: an ease-in-out that starts and ends flat. It is
 * monotonically increasing with `f(0)=0` and `f(1)=1`, so it preserves both the
 * "reveal never goes backwards" and "settles exactly at the final frame"
 * contracts every one-shot style relies on, while making the middle of the
 * reveal glide rather than march.
 */
function smoothstep(t: number): number {
  if (t <= 0) return 0;
  if (t >= 1) return 1;
  return t * t * (3 - 2 * t);
}

/**
 * Snappier ease-out (cubic): quick off the mark, then a soft settle. Monotonic
 * with `f(0)=0`/`f(1)=1`, so it keeps the same reveal contracts as smoothstep
 * but reads as a more decisive "snap" — used by strike and draw.
 */
function easeOutCubic(t: number): number {
  if (t <= 0) return 0;
  if (t >= 1) return 1;
  const u = 1 - t;
  return 1 - u * u * u;
}

/** A small deterministic hash of three integers (FNV-1a style). Pure. */
function hash3(a: number, b: number, c: number): number {
  let h = 2166136261 >>> 0;
  for (const x of [a >>> 0, b >>> 0, c >>> 0]) {
    h ^= x;
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}

const EPS = 1e-9;

/** Clamp a channel to [0,255] and render as two lowercase hex digits. */
function channelHex(v: number): string {
  const n = Math.max(0, Math.min(255, Math.round(v)));
  return n.toString(16).padStart(2, "0");
}

/** An `#rrggbb` string from 0..255 channels (clamped). Pure. */
function rgbHex(r: number, g: number, b: number): string {
  return `#${channelHex(r)}${channelHex(g)}${channelHex(b)}`;
}

/** A neutral grey at lightness `l` in [0,1] as `#rrggbb`. */
function greyHex(l: number): string {
  const v = clamp01(l) * 255;
  return rgbHex(v, v, v);
}

/**
 * HSL -> `#rrggbb`. `h` in degrees (wrapped), `s`/`l` in [0,1]. Pure and
 * deterministic — the rainbow hue sweep and the neon/matrix/wave gradients are
 * all built from this, so no theme is consulted here.
 */
function hslToHex(h: number, s: number, l: number): string {
  const hh = ((h % 360) + 360) % 360;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((hh / 60) % 2) - 1));
  const m = l - c / 2;
  let r = 0;
  let g = 0;
  let b = 0;
  if (hh < 60) [r, g, b] = [c, x, 0];
  else if (hh < 120) [r, g, b] = [x, c, 0];
  else if (hh < 180) [r, g, b] = [0, c, x];
  else if (hh < 240) [r, g, b] = [0, x, c];
  else if (hh < 300) [r, g, b] = [x, 0, c];
  else [r, g, b] = [c, 0, x];
  return rgbHex((r + m) * 255, (g + m) * 255, (b + m) * 255);
}

/**
 * The set of tones a glitch scramble flickers a cell through before it settles.
 * A mix of named tones and two neon hexes so the DEFAULT style flashes colour.
 */
const SCRAMBLE_TONES: readonly LogoCellTone[] = [
  "text",
  "error",
  "brand",
  "dim",
  "#00e5ff",
  "#ff2d95",
];

/** Neon palette for the `neon` warm-up flicker (pink, cyan, purple, amber, white). */
const NEON_TONES: readonly string[] = ["#ff2d95", "#00e5ff", "#b388ff", "#fde74c", "#ffffff"];

/** Matrix-rain drop gradient, head (brightest) -> tail (deep green). */
const MATRIX_GREENS: readonly string[] = ["#b9f6ca", "#69f0ae", "#00c853", "#1b5e20"];

/** Wave crest gradient, lead (brightest) -> trailing (deep cyan). */
const WAVE_CYANS: readonly string[] = ["#e0ffff", "#7cf9ff", "#29d3e6", "#1197a6"];

/** Draw pen-tip gradient, tip (white) -> trailing (light purple). */
const DRAW_TIP: readonly string[] = ["#ffffff", "#c4b5fd"];

/**
 * strike: the SEC outline and the "0" white cells are visible from frame 0; the
 * red slash ("/") cells reveal progressively along the diagonal from the
 * lower-left corner to the upper-right, striking through the zero. Ordering is by
 * the anti-diagonal key `col - row` (lower-left is the smallest key). The
 * just-struck leading edge flashes purple ("brand") and settles to red ("error")
 * behind it — the snappy easeOutCubic threshold gives the strike a decisive
 * snap. At the final frame the flash is gone, so every slash cell is red and the
 * frame equals `finalLogoFrame`.
 */
function strikeFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  let minKey = Number.POSITIVE_INFINITY;
  let maxKey = Number.NEGATIVE_INFINITY;
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      if (cellCharAt(grid, r, c) === "/") {
        const key = c - r;
        if (key < minKey) minKey = key;
        if (key > maxKey) maxKey = key;
      }
    }
  }
  const progress = easeOutCubic(progressOf(frame, FRAME_COUNTS.strike));
  const threshold = minKey + progress * (maxKey - minKey);
  // The purple hot edge only exists mid-strike; at p=1 it is gone so the last
  // frame settles exactly to the red slash.
  const hotBand = progress < 1 - EPS ? 1.5 : 0;
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === "#") {
        out[r]![c] = { ch, visible: true, tone: "text" };
      } else if (ch === "/") {
        const key = c - r;
        const reached = key <= threshold + EPS;
        const hot = reached && threshold - key < hotBand;
        out[r]![c] = { ch, visible: reached, tone: hot ? "brand" : "error" };
      }
    }
  }
  return out;
}

/**
 * draw: the whole mark reveals column-by-column, left to right. A non-space cell
 * is drawn once the snappy easeOutCubic sweep passes its column; the two columns
 * at the pen tip glow bright (white -> light-purple) and settle to their final
 * tone behind it. Fully visible on the final frame, with the tip past the edge
 * so it equals `finalLogoFrame`.
 */
function drawFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const progress = easeOutCubic(progressOf(frame, FRAME_COUNTS.draw));
  const threshold = progress * (width - 1);
  const tip = progress < 1 - EPS ? DRAW_TIP.length : 0;
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      if (c > threshold + EPS) continue;
      const depth = Math.round(threshold - c);
      const tone: LogoCellTone = depth < tip ? DRAW_TIP[Math.min(depth, DRAW_TIP.length - 1)]! : finalTone(ch);
      out[r]![c] = { ch, visible: true, tone };
    }
  }
  return out;
}

/**
 * fade: every non-space cell is present (visible) from frame 0; the mark
 * brightens dim -> muted -> full, blooming out from the grid centre. A
 * purple-tinted colour gradient fills the dim and muted phases so the ramp reads
 * as a smooth multi-step bloom rather than two hard steps, while the NAMED tone
 * (dim/muted/text) still advances monotonically dim->full. At p=1 every cell is
 * full with no hex, so the last frame equals `finalLogoFrame`.
 */
function fadeFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const rows = grid.length;
  const cx = (width - 1) / 2;
  const cy = (rows - 1) / 2;
  const maxDist = Math.hypot(Math.max(cx, width - 1 - cx), Math.max(cy, rows - 1 - cy)) || 1;
  const SPREAD = 0.6;
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.fade));
  for (let r = 0; r < rows; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      const dist = Math.hypot(c - cx, r - cy) / maxDist;
      const local = progress * (1 + SPREAD) - dist * SPREAD;
      let tone: LogoCellTone;
      if (local < 1 / 3 - EPS) {
        // Deep purple bloom deepening toward the dim step.
        const t = clamp01(local / (1 / 3));
        tone = hslToHex(262, 0.6, 0.14 + t * 0.24);
      } else if (local < 2 / 3 - EPS) {
        // Brightening lilac toward the muted step.
        const t = clamp01((local - 1 / 3) / (1 / 3));
        tone = hslToHex(280, 0.5, 0.42 + t * 0.2);
      } else {
        tone = finalTone(ch);
      }
      out[r]![c] = { ch, visible: true, tone };
    }
  }
  return out;
}

/**
 * typein: non-space cells reveal one after another in reading order (row-major,
 * left to right), like a cursor typing the mark out. The most-recently revealed
 * cells carry a short purple "brand" glow that trails the leading edge and
 * settles to their final tone behind it; at the final frame every cell has
 * settled so the mark equals `finalLogoFrame`.
 */
function typeinFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const order: Array<{ r: number; c: number }> = [];
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      if (out[r]![c]!.ch !== " ") order.push({ r, c });
    }
  }
  const total = order.length;
  if (total === 0) return out;
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.typein));
  const revealed = Math.round(progress * total);
  const GLOW = progress < 1 - EPS ? 3 : 0;
  for (let i = 0; i < revealed; i += 1) {
    const { r, c } = order[i]!;
    const ch = out[r]![c]!.ch;
    const isLeadingEdge = i >= revealed - GLOW;
    out[r]![c] = { ch, visible: true, tone: isLeadingEdge ? "brand" : finalTone(ch) };
  }
  return out;
}

/**
 * sweep: a two-column bright "brand" bar wipes left to right; everything behind
 * the bar is revealed at its final tone, the bar itself glows purple, and
 * everything ahead is still hidden. The bar travels one bar-width past the right
 * edge by the final frame, so it has cleared the mark and the last frame equals
 * `finalLogoFrame`.
 */
function sweepFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const BAR = 2;
  const lead = smoothstep(progressOf(frame, FRAME_COUNTS.sweep)) * (width + BAR);
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      if (c <= lead - BAR - EPS) {
        out[r]![c] = { ch, visible: true, tone: finalTone(ch) };
      } else if (c <= lead + EPS) {
        out[r]![c] = { ch, visible: true, tone: "brand" };
      }
    }
  }
  return out;
}

/**
 * glitch (DEFAULT): the mark resolves out of a deterministic scramble. Each
 * non-space cell has a fixed per-cell settle threshold (a hash of its position);
 * once the eased progress passes that threshold the cell locks to its final tone.
 * Cells that have not settled yet flicker — visibility and tone are a hash of
 * (position, frame), scrambling through the palette (named tones plus two neon
 * hexes) frame to frame, but the *set* of settled cells only grows. By the final
 * frame progress is 1, exceeding every threshold, so the whole mark has settled
 * to `finalLogoFrame`.
 */
function glitchFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.glitch));
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      const threshold = (hash3(r, c, 0) % 1000) / 1000;
      if (progress > threshold + EPS) {
        out[r]![c] = { ch, visible: true, tone: finalTone(ch) };
        continue;
      }
      const noise = hash3(r, c, frame + 1);
      const lit = noise % 4 !== 0;
      const tone = SCRAMBLE_TONES[(noise >>> 3) % SCRAMBLE_TONES.length]!;
      out[r]![c] = { ch, visible: lit, tone };
    }
  }
  return out;
}

/**
 * matrix: a matrix-rain reveal. Each column has a hashed start delay, so drops
 * fall in a staggered cascade. Within a column a falling "drop" (a short green
 * gradient, head brightest) descends top to bottom; cells the drop has passed
 * are settled to their final tone, cells under the drop glow green, cells below
 * are still hidden. The drop front runs one trail-length past the bottom by the
 * final frame, so every cell has settled and the frame equals `finalLogoFrame`.
 */
function matrixFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const rows = grid.length;
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.matrix));
  const TRAIL = MATRIX_GREENS.length - 1;
  const DELAY = 0.55;
  for (let c = 0; c < width; c += 1) {
    const delay = ((hash3(c, 0, 7) % 1000) / 1000) * DELAY;
    // Column progress: reaches 1 for every column at p=1 (since p*(1+DELAY)-delay
    // >= (1+DELAY)-DELAY = 1), so the whole column settles by the final frame.
    const cp = clamp01(progress * (1 + DELAY) - delay);
    const front = cp * (rows + TRAIL);
    for (let r = 0; r < rows; r += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      if (r < front - TRAIL - EPS) {
        out[r]![c] = { ch, visible: true, tone: finalTone(ch) };
      } else if (r <= front + EPS) {
        const depth = Math.min(TRAIL, Math.max(0, Math.round(front - r)));
        out[r]![c] = { ch, visible: true, tone: MATRIX_GREENS[depth]! };
      }
    }
  }
  return out;
}

/**
 * wave: a rippling wavefront wipes the mark in left to right. The reveal edge is
 * bent by a sine over the rows, so it advances as a travelling ripple rather
 * than a straight bar. Cells behind the crest are settled to their final tone;
 * the crest itself is a short cyan gradient (lead brightest). The crest clears
 * the right edge by the final frame, so the last frame equals `finalLogoFrame`.
 */
function waveFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const rows = grid.length;
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.wave));
  const AMP = 2.2;
  const CREST = WAVE_CYANS.length;
  const K = (2 * Math.PI) / Math.max(1, rows);
  // Base sweeps far enough that at p=1 the crest has cleared the mark entirely.
  const base = progress * (width + 2 * AMP + CREST + 1);
  for (let r = 0; r < rows; r += 1) {
    const front = base - AMP + AMP * Math.sin(r * K);
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      if (c <= front - CREST - EPS) {
        out[r]![c] = { ch, visible: true, tone: finalTone(ch) };
      } else if (c <= front + EPS) {
        const depth = Math.min(CREST - 1, Math.max(0, Math.round(front - c)));
        out[r]![c] = { ch, visible: true, tone: WAVE_CYANS[depth]! };
      }
    }
  }
  return out;
}

/**
 * neon: a neon-sign warm-up. Each non-space cell has a hashed settle threshold;
 * once the eased progress passes it the cell locks to its final tone. Before
 * that the cell buzzes on and off in neon colours (a hash of position+frame), so
 * the mark flickers to life like a cold neon tube. By the final frame progress
 * is 1, exceeding every threshold, so the whole mark has settled to
 * `finalLogoFrame`.
 */
function neonFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.neon));
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      const threshold = (hash3(r, c, 3) % 1000) / 1000;
      if (progress > threshold + EPS) {
        out[r]![c] = { ch, visible: true, tone: finalTone(ch) };
        continue;
      }
      const noise = hash3(r, c, frame + 1);
      const lit = noise % 5 !== 0;
      const tone = NEON_TONES[(noise >>> 4) % NEON_TONES.length]!;
      out[r]![c] = { ch, visible: lit, tone };
    }
  }
  return out;
}

/**
 * rainbow (looping): the mark stays fully visible while a hue sweep cycles the
 * spectrum across it — each column's hue is offset by its position and drifts
 * with time, so bands of colour roll across the letters forever. Seamless: the
 * time offset is `360 * idx/period`, so frame 0 and frame `period` are identical.
 * Never hides a cell. Under reduceMotion the caller returns `finalLogoFrame`, so
 * no colour flashes.
 */
function rainbowFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = finalLogoFrame(grid);
  const period = FRAME_COUNTS.rainbow;
  const idx = ((frame % period) + period) % period;
  const phase = (idx / period) * 360;
  const span = width > 1 ? width - 1 : 1;
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const cell = out[r]![c]!;
      if (cell.ch === " ") continue;
      const hue = phase + (c / span) * 300;
      out[r]![c] = { ch: cell.ch, visible: true, tone: hslToHex(hue, 0.9, 0.62) };
    }
  }
  return out;
}

/**
 * shimmer (looping): fully visible at final tones, with a bright comet sweeping
 * left to right. The comet is a multi-step grey gradient — a bright head trailing
 * a fading tail (`SHIMMER_TAIL` cells) — so it reads as several brightness levels
 * rather than one column. While the comet is over the grid it recolours those
 * columns; once it has swept past (head and tail both off-grid) the remaining
 * frames of the period are a clean rest gap equal to the final frame. Never hides
 * a cell.
 */
const SHIMMER_TAIL = 5;
function shimmerFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = finalLogoFrame(grid);
  const period = FRAME_COUNTS.shimmer;
  const idx = ((frame % period) + period) % period;
  for (let offset = -SHIMMER_TAIL; offset <= SHIMMER_TAIL; offset += 1) {
    const col = idx + offset;
    if (col < 0 || col >= width) continue;
    // The mark is white, so shimmer is a DARK band sweeping across it: the
    // head (offset 0) is DARKEST and it brightens back toward white
    // SYMMETRICALLY on BOTH sides — white -> black -> white, not the inverse.
    const dist = Math.abs(offset);
    const l = 0.33 + (dist / SHIMMER_TAIL) * 0.62;
    const tone = greyHex(l);
    for (let r = 0; r < grid.length; r += 1) {
      const cell = out[r]![col]!;
      if (cell.ch !== " ") out[r]![col] = { ch: cell.ch, visible: true, tone };
    }
  }
  return out;
}

/**
 * pulse (looping): fully visible at final tones; the red slash ("/") cells
 * breathe on a cosine — dim -> error (red) -> brand (purple) and back — while the
 * white cells hold steady. Looping and seamless: the phase uses
 * `cos(2π·idx/period)`, so frame 0 and frame `period` are identical. Never hides
 * a cell.
 */
function pulseFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = finalLogoFrame(grid);
  const period = FRAME_COUNTS.pulse;
  const idx = ((frame % period) + period) % period;
  const v = (1 - Math.cos((2 * Math.PI * idx) / period)) / 2;
  const slashTone: LogoCellTone = v < 1 / 3 - EPS ? "dim" : v < 2 / 3 - EPS ? "error" : "brand";
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const cell = out[r]![c]!;
      if (cell.ch === "/") out[r]![c] = { ch: cell.ch, visible: true, tone: slashTone };
    }
  }
  return out;
}

/**
 * Compute the per-cell render state for one frame of the logo intro.
 *
 * Deterministic: the same (grid, style, frame, opts) always yields the same
 * frame. Out-of-range frames are guarded — one-shot styles clamp to [0, last]
 * (so any frame at or past the end is the settled final frame), and the looping
 * styles (rainbow, shimmer, pulse) wrap modulo their period. `reduceMotion`
 * forces the static final frame for every style, so no colour ever flashes.
 */
export function computeLogoFrame(
  grid: readonly string[],
  style: LogoAnimStyle,
  frame: number,
  opts?: { reduceMotion?: boolean },
): LogoFrame {
  if (grid.length === 0) return [];
  if (opts?.reduceMotion) return finalLogoFrame(grid);
  if (style === "off") return finalLogoFrame(grid);

  const width = gridWidth(grid);
  const count = FRAME_COUNTS[style];

  if (LOOPS[style]) {
    // Looping: normalise the frame into an integer before dispatch (each looping
    // style wraps modulo its own period internally).
    const safe = Number.isFinite(frame) ? Math.trunc(frame) : 0;
    if (style === "rainbow") return rainbowFrame(grid, safe, width);
    if (style === "shimmer") return shimmerFrame(grid, safe, width);
    if (style === "pulse") return pulseFrame(grid, safe, width);
    return finalLogoFrame(grid);
  }

  // One-shot: clamp the frame into [0, count-1]; anything past the end settles.
  const clamped = Number.isFinite(frame) ? Math.min(Math.max(Math.trunc(frame), 0), count - 1) : count - 1;
  switch (style) {
    case "glitch":
      return glitchFrame(grid, clamped, width);
    case "matrix":
      return matrixFrame(grid, clamped, width);
    case "wave":
      return waveFrame(grid, clamped, width);
    case "neon":
      return neonFrame(grid, clamped, width);
    case "strike":
      return strikeFrame(grid, clamped, width);
    case "draw":
      return drawFrame(grid, clamped, width);
    case "fade":
      return fadeFrame(grid, clamped, width);
    case "typein":
      return typeinFrame(grid, clamped, width);
    case "sweep":
      return sweepFrame(grid, clamped, width);
    default:
      return finalLogoFrame(grid);
  }
}
