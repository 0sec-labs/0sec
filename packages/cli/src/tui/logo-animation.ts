/**
 * Pure, deterministic per-frame animation for the "0SEC" block-logo intro.
 *
 * This module owns only the *logic* of the intro: given the base logo grid
 * (the three-letter colour map used by chat-screen — `' '` empty, `'#'` white,
 * `'/'` red), an animation style, and a frame index, it returns the per-cell
 * render state for that frame. It renders nothing, imports no theme, reads no
 * clock — `computeLogoFrame(grid, style, frame)` is a pure function of its
 * inputs, so every frame is unit-testable in isolation.
 *
 * The caller (chat-screen) drives it with a frame ticker and maps each cell's
 * `tone` to a theme token and `visible`/tone to `TextAttributes.DIM`:
 *
 *   tone "text"  -> theme.TEXT   (full)
 *   tone "error" -> theme.ERROR  (full, the red slash)
 *   tone "dim"   -> theme.TEXT (or a dim token) + TextAttributes.DIM
 *   tone "muted" -> theme.MUTED  (the mid/highlight tone; DIM optional)
 *   tone "brand" -> theme.BRAND  (the purple accent — a bright leading edge or
 *                                 pulse peak; see the caller-mapping note below)
 *   visible:false -> render a single space (the cell is not yet drawn)
 *
 * Because the caller renders cell-by-cell from this state, the row widths are
 * preserved verbatim (every row is padded to the grid's max width), so no
 * `fitTuiText` pass is needed and the OpenTUI row-overflow invariant holds.
 *
 * CALLER MAPPING NOTE (`brand`). Older callers whose `logoRunStyle` predates
 * this module only switch on text/error/dim/muted and fall a "brand" cell
 * through to their `text` (TEXT) default — a graceful degradation (the cell is
 * still visible, just white instead of purple). To light the purple accent the
 * caller must add one arm to its tone→token switch:
 *
 *   case "brand": return { fg: theme.BRAND };
 *
 * `brand` never appears in `finalLogoFrame`, so `reduceMotion`/`off`/the settled
 * last frame are unaffected whether or not the caller wires it.
 */

/**
 * Intro styles, matching settings.ts `logoAnimation`.
 *
 * One-shot reveals play once and settle: `strike` (a red slash strikes the 0
 * along its diagonal), `draw` (a left-to-right column reveal), `fade` (a
 * centre-out brightness bloom), `typein` (per-cell reveal in reading order with
 * a purple leading glow), `sweep` (a bright bar wipes L→R revealing behind it),
 * `glitch` (a deterministic scramble that resolves cell by cell). Looping idle
 * effects run forever: `shimmer` (a highlight column with a dim comet tail
 * sweeps across) and `pulse` (the red slash breathes dim→red→purple). `off` is
 * the static settled mark.
 */
export type LogoAnimStyle =
  | "strike"
  | "draw"
  | "fade"
  | "shimmer"
  | "typein"
  | "sweep"
  | "glitch"
  | "pulse"
  | "off";

/** The logo alphabet: empty, white block, red-slash block. */
export type LogoCellChar = " " | "#" | "/";

/**
 * Render tone for one cell. The caller maps these to theme tokens (and DIM):
 * "text"/"error" are the final full colours; "dim" is a DIM step; "muted" is
 * the mid/highlight tone (fade mid-step and the shimmer sweep band); "brand" is
 * the purple accent (a bright leading edge, a scramble flicker, a pulse peak) —
 * it is never a *final* tone, so a caller that has not wired it degrades to TEXT.
 */
export type LogoCellTone = "text" | "error" | "dim" | "muted" | "brand";

/** Per-cell render state for a single frame. */
export interface LogoCellState {
  /** The cell's glyph class from the base grid (unchanged by the animation). */
  ch: LogoCellChar;
  /** Whether the cell is drawn this frame. `false` -> render a space. */
  visible: boolean;
  /** Which tone token the caller should paint the cell with. */
  tone: LogoCellTone;
}

/** A full frame: one `LogoCellState` per grid cell, row-major, rectangular. */
export type LogoFrame = LogoCellState[][];

/**
 * One coalesced run of adjacent cells sharing a `(tone, visible)` pair, so the
 * caller can paint each run as a single explicitly-sized `<text>` rather than a
 * cell per element — the animated analogue of chat-screen's `logoCellRuns`, but
 * keyed on the frame's render state instead of the raw glyph alphabet. Run
 * lengths across a row sum to the frame's (padded) width, so no run overflows.
 */
export interface LogoRun {
  /** Number of cells this run spans. */
  length: number;
  /** The shared tone; the caller maps it to a theme token (+ DIM). */
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
 * grid still reveals fully by the final frame. Counts are deliberately a touch
 * higher than the original set so the eased reveals read as smooth motion
 * rather than a handful of steps.
 *
 * Looping styles (`shimmer`, `pulse`) treat their count as the loop *period*.
 * For `shimmer` the highlight sweeps columns 0..width-1 and the remaining frames
 * are a rest gap before the sweep repeats — keep the period comfortably above
 * the grid width so every column is highlighted once per loop.
 */
const FRAME_COUNTS: Record<LogoAnimStyle, number> = {
  strike: 16,
  draw: 22,
  fade: 14,
  shimmer: 48,
  typein: 28,
  sweep: 20,
  glitch: 18,
  pulse: 24,
  off: 1,
};

/** Styles that loop forever (the caller wraps the frame index modulo count). */
const LOOPS: Record<LogoAnimStyle, boolean> = {
  strike: false,
  draw: false,
  fade: false,
  shimmer: true,
  typein: false,
  sweep: false,
  glitch: false,
  pulse: true,
  off: false,
};

/** Total frames in the one-shot intro (loop period for looping styles). */
export function logoAnimationFrameCount(style: LogoAnimStyle): number {
  return FRAME_COUNTS[style] ?? 1;
}

/** Whether the style loops (shimmer, pulse) versus playing once and settling. */
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
 * tone. This is the target of `off`, of `reduceMotion`, and of the last frame
 * of every one-shot style.
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

/** The set of tones a glitch scramble flickers a cell through before it settles. */
const SCRAMBLE_TONES: readonly LogoCellTone[] = ["text", "error", "brand", "dim"];

/**
 * strike: the SEC outline and the "0" white cells are visible from frame 0;
 * the red slash ("/") cells reveal progressively along the diagonal from the
 * lower-left corner to the upper-right, striking through the zero. Ordering is
 * by the anti-diagonal key `col - row` (lower-left is the smallest key), so the
 * reveal is monotonic and every slash cell is shown by the final frame. The
 * threshold advances on an eased curve so the strike accelerates through the
 * middle and settles softly rather than stepping at a constant rate.
 */
function strikeFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  // Diagonal key range of the slash cells.
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
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.strike));
  const threshold = minKey + progress * (maxKey - minKey);
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === "#") {
        out[r]![c] = { ch, visible: true, tone: "text" };
      } else if (ch === "/") {
        const reached = c - r <= threshold + EPS;
        out[r]![c] = { ch, visible: reached, tone: "error" };
      }
    }
  }
  return out;
}

/**
 * draw: the whole mark reveals column-by-column, left to right. A non-space
 * cell is drawn (at its final tone) once the eased sweep passes its column;
 * empty cells stay blank. Fully visible on the final frame. The easing gives
 * the pen a smooth acceleration and a soft stop.
 */
function drawFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.draw));
  const threshold = progress * (width - 1);
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      out[r]![c] = { ch, visible: c <= threshold + EPS, tone: finalTone(ch) };
    }
  }
  return out;
}

/**
 * fade: every non-space cell is present (visible) from frame 0; the mark
 * brightens in DIM steps dim -> muted -> full, blooming out from the grid
 * centre so the middle of the mark warms first and the corners last. The caller
 * paints "dim"/"muted" with DIM (and the muted token), resolving to the true
 * colours (text/error) at the end. The global brightness only ever increases,
 * so the ramp is monotonic; the centre-out ordering is the "subtle settle".
 */
function fadeFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const rows = grid.length;
  const cx = (width - 1) / 2;
  const cy = (rows - 1) / 2;
  // Largest centre distance in the grid, so `dist` normalises into [0,1].
  const maxDist = Math.hypot(Math.max(cx, width - 1 - cx), Math.max(cy, rows - 1 - cy)) || 1;
  // How far ahead the centre runs of the edges. 0 would be a flat global fade;
  // this staggers the bloom while still guaranteeing every cell is full at p=1.
  const SPREAD = 0.6;
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.fade));
  for (let r = 0; r < rows; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      const dist = Math.hypot(c - cx, r - cy) / maxDist;
      // local in [0,1]: at p=0 every cell is <=0 (dim); at p=1 every cell is
      // >=1 (full), because progress*(1+SPREAD) - SPREAD >= 1 - SPREAD*dist.
      const local = progress * (1 + SPREAD) - dist * SPREAD;
      const tone: LogoCellTone =
        local < 1 / 3 - EPS ? "dim" : local < 2 / 3 - EPS ? "muted" : finalTone(ch);
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
 * settled so the mark is exactly `finalLogoFrame`. The revealed count advances
 * on an eased curve, so it is monotonic and complete by the last frame.
 */
function typeinFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  // Reading-order list of the non-space cells.
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
  // The trailing glow only exists mid-reveal; at p=1 it is gone so the last
  // frame settles exactly to the final tones.
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
 * sweep: a two-column bright "brand" bar wipes left to right; everything the
 * bar has already passed is revealed at its final tone, the bar itself glows
 * purple, and everything ahead of the bar is still hidden. The bar travels one
 * bar-width past the right edge by the final frame, so it has cleared the mark
 * and every cell is settled — the last frame equals `finalLogoFrame`. The lead
 * position advances on an eased curve, so the revealed region only grows.
 */
function sweepFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const BAR = 2;
  // Lead runs from 0 to width+BAR: past width+BAR every column is behind the bar.
  const lead = smoothstep(progressOf(frame, FRAME_COUNTS.sweep)) * (width + BAR);
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      if (c <= lead - BAR - EPS) {
        out[r]![c] = { ch, visible: true, tone: finalTone(ch) }; // revealed, behind the bar
      } else if (c <= lead + EPS) {
        out[r]![c] = { ch, visible: true, tone: "brand" }; // under the bar
      }
      // else: ahead of the bar, stays hidden.
    }
  }
  return out;
}

/**
 * glitch: the mark resolves out of a deterministic scramble. Each non-space
 * cell has a fixed per-cell settle threshold (a hash of its position); once the
 * eased progress passes that threshold the cell locks to its final tone. Cells
 * that have not settled yet flicker — their visibility and tone are a hash of
 * (position, frame), so they scramble between the palette tones frame to frame
 * but the *set* of settled cells only grows. By the final frame progress is 1,
 * which exceeds every threshold, so the whole mark has settled to
 * `finalLogoFrame`.
 */
function glitchFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const progress = smoothstep(progressOf(frame, FRAME_COUNTS.glitch));
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      // Per-cell settle threshold in [0, 0.999] — strictly below 1 so that a
      // final-frame progress of exactly 1 settles every cell.
      const threshold = (hash3(r, c, 0) % 1000) / 1000;
      if (progress > threshold + EPS) {
        out[r]![c] = { ch, visible: true, tone: finalTone(ch) };
        continue;
      }
      // Unsettled: scramble this frame. ~3/4 of the time the cell is lit, in one
      // of the scramble tones; otherwise it blinks out.
      const noise = hash3(r, c, frame + 1);
      const lit = noise % 4 !== 0;
      const tone = SCRAMBLE_TONES[(noise >>> 3) % SCRAMBLE_TONES.length]!;
      out[r]![c] = { ch, visible: lit, tone };
    }
  }
  return out;
}

/**
 * shimmer: fully visible at final tones, with a single highlighted column band
 * ("muted") sweeping left to right, trailing a one-column "dim" comet tail,
 * looping. The sweep exists only while the head is over the grid (idx < width);
 * the remaining frames of the period are a clean rest gap (identical to the
 * final frame) before it repeats. Never hides a cell.
 */
function shimmerFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = finalLogoFrame(grid);
  const period = FRAME_COUNTS.shimmer;
  const idx = ((frame % period) + period) % period;
  if (idx < width) {
    for (let r = 0; r < grid.length; r += 1) {
      const head = out[r]![idx]!;
      if (head.ch !== " ") out[r]![idx] = { ch: head.ch, visible: true, tone: "muted" };
      const tailCol = idx - 1;
      if (tailCol >= 0) {
        const tail = out[r]![tailCol]!;
        if (tail.ch !== " ") out[r]![tailCol] = { ch: tail.ch, visible: true, tone: "dim" };
      }
    }
  }
  return out;
}

/**
 * pulse: fully visible at final tones; the red slash ("/") cells breathe on a
 * cosine — dim -> error (red) -> brand (purple) and back — while the white
 * cells hold steady. Looping and seamless: the phase uses `cos(2π·idx/period)`,
 * so frame 0 and frame `period` are identical. Never hides a cell. Under
 * reduceMotion the slash collapses to its resting `error` tone (handled by the
 * caller returning `finalLogoFrame`).
 */
function pulseFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = finalLogoFrame(grid);
  const period = FRAME_COUNTS.pulse;
  const idx = ((frame % period) + period) % period;
  // v in [0,1], 0 at the loop seam so the cycle is continuous.
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
 * styles (shimmer, pulse) wrap modulo their period. `reduceMotion` forces the
 * static final frame for every style.
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
    if (style === "shimmer") return shimmerFrame(grid, safe, width);
    if (style === "pulse") return pulseFrame(grid, safe, width);
    return finalLogoFrame(grid);
  }

  // One-shot: clamp the frame into [0, count-1]; anything past the end settles.
  const clamped = Number.isFinite(frame) ? Math.min(Math.max(Math.trunc(frame), 0), count - 1) : count - 1;
  switch (style) {
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
    case "glitch":
      return glitchFrame(grid, clamped, width);
    default:
      return finalLogoFrame(grid);
  }
}
