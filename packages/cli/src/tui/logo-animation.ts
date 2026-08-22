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
 *   visible:false -> render a single space (the cell is not yet drawn)
 *
 * Because the caller renders cell-by-cell from this state, the row widths are
 * preserved verbatim (every row is padded to the grid's max width), so no
 * `fitTuiText` pass is needed and the OpenTUI row-overflow invariant holds.
 */

/** The five intro styles, matching settings.ts `logoAnimation`. */
export type LogoAnimStyle = "strike" | "draw" | "fade" | "shimmer" | "off";

/** The logo alphabet: empty, white block, red-slash block. */
export type LogoCellChar = " " | "#" | "/";

/**
 * Render tone for one cell. The caller maps these to theme tokens (and DIM):
 * "text"/"error" are the final full colours; "dim" is a DIM step; "muted" is
 * the mid/highlight tone (fade mid-step and the shimmer sweep band).
 */
export type LogoCellTone = "text" | "error" | "dim" | "muted";

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
 * One-shot frame budgets per style (the number of distinct frames in the
 * intro). Sized for the shipped 0SEC mark (5 rows x 35 cols) but the compute
 * function scales its thresholds to the actual grid, so a differently-sized
 * grid still reveals fully by the final frame.
 *
 * `shimmer` is a looping idle effect: its count is the loop *period*, and the
 * highlight sweeps columns 0..period-1 (columns past the grid width are a rest
 * gap before the sweep repeats). Keep the period comfortably above the grid
 * width so every column is highlighted once per loop.
 */
const FRAME_COUNTS: Record<LogoAnimStyle, number> = {
  strike: 12,
  draw: 20,
  fade: 10,
  shimmer: 48,
  off: 1,
};

/** Styles that loop forever (the caller wraps the frame index modulo count). */
const LOOPS: Record<LogoAnimStyle, boolean> = {
  strike: false,
  draw: false,
  fade: false,
  shimmer: true,
  off: false,
};

/** Total frames in the one-shot intro (loop period for looping styles). */
export function logoAnimationFrameCount(style: LogoAnimStyle): number {
  return FRAME_COUNTS[style] ?? 1;
}

/** Whether the style loops (shimmer) versus playing once and settling. */
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

const EPS = 1e-9;

/**
 * strike: the SEC outline and the "0" white cells are visible from frame 0;
 * the red slash ("/") cells reveal progressively along the diagonal from the
 * lower-left corner to the upper-right, striking through the zero. Ordering is
 * by the anti-diagonal key `col - row` (lower-left is the smallest key), so the
 * reveal is monotonic and every slash cell is shown by the final frame.
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
  const progress = progressOf(frame, FRAME_COUNTS.strike);
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
 * cell is drawn (at its final tone) once the sweep passes its column; empty
 * cells stay blank. Fully visible on the final frame.
 */
function drawFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const progress = progressOf(frame, FRAME_COUNTS.draw);
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
 * fade: every cell is present (visible) from frame 0; the whole mark brightens
 * globally in DIM steps, dim -> muted -> full, over the frames. The caller
 * paints "dim"/"muted" with DIM (and the muted token), resolving to the true
 * colours (text/error) at the end.
 */
function fadeFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = blankFrame(grid, width);
  const progress = progressOf(frame, FRAME_COUNTS.fade);
  const stageTone: LogoCellTone | null = progress < 1 / 3 ? "dim" : progress < 2 / 3 ? "muted" : null;
  for (let r = 0; r < grid.length; r += 1) {
    for (let c = 0; c < width; c += 1) {
      const ch = out[r]![c]!.ch;
      if (ch === " ") continue;
      const tone = stageTone ?? finalTone(ch);
      out[r]![c] = { ch, visible: true, tone };
    }
  }
  return out;
}

/**
 * shimmer: fully visible at final tones, with a single highlighted column band
 * ("muted") sweeping left to right, looping. Columns past the grid width are a
 * rest gap before the sweep repeats. Never hides a cell.
 */
function shimmerFrame(grid: readonly string[], frame: number, width: number): LogoFrame {
  const out = finalLogoFrame(grid);
  const period = FRAME_COUNTS.shimmer;
  const idx = ((frame % period) + period) % period;
  if (idx < width) {
    for (let r = 0; r < grid.length; r += 1) {
      const cell = out[r]![idx]!;
      if (cell.ch !== " ") out[r]![idx] = { ch: cell.ch, visible: true, tone: "muted" };
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
 * shimmer wraps modulo its period. `reduceMotion` forces the static final frame
 * for every style.
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
    // Looping: normalise the frame into [0, period) before dispatch.
    const safe = Number.isFinite(frame) ? Math.trunc(frame) : 0;
    if (style === "shimmer") return shimmerFrame(grid, safe, width);
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
    default:
      return finalLogoFrame(grid);
  }
}
