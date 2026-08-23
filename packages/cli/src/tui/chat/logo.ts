import { TextAttributes } from "@opentui/core";
import type { Theme } from "../theme-context.js";
import type { LogoCellTone } from "../logo-animation.js";

/**
 * The 0sec block mark as a per-cell colour grid, one string per row over a
 * three-letter alphabet: ' ' is an empty cell, '#' a white (`theme.TEXT`)
 * block, '/' a red (`theme.ERROR`) block. The "0" is drawn wider than the
 * other letters so its interior has room for a two-cell-thick red diagonal
 * slash — lower-left to upper-right — that clears the white outline on both
 * sides: a slashed zero. "SEC" stays white. This grid is the fixed base the
 * intro animation reveals: `computeLogoFrame` (logo-animation.ts) turns it into
 * a per-cell frame and `logoRowRuns` coalesces each row into same-tone runs the
 * render draws as explicitly-sized `<text>`s (widths sum to exactly
 * `TERMINAL_BLOCK_LOGO_WIDTH`), which keeps a row's segments from overflowing.
 */
export const TERMINAL_BLOCK_LOGO = [
  " ######   #######  #######   ######",
  "##  //##  ##       ##       ##     ",
  "## // ##  #######  #####    ##     ",
  "##//  ##       ##  ##       ##     ",
  " ######   #######  #######   ######",
] as const;
export const TERMINAL_BLOCK_LOGO_WIDTH = 35;

/**
 * Milliseconds between logo intro frames. One rate for every style — the frame
 * *counts* differ (see logo-animation.ts), so a shorter style simply settles
 * sooner; shimmer loops at this cadence. ~14 Hz reads as motion without the
 * repaint cost of the busy spinners.
 */
export const LOGO_FRAME_INTERVAL_MS = 70;

/**
 * How a computed logo frame's per-cell `tone` maps onto the theme (and DIM):
 *   text  -> TEXT             error -> ERROR
 *   dim   -> TEXT + DIM       muted -> MUTED
 *   brand -> BRAND            #rrggbb -> that literal colour as the foreground
 *
 * The colourful intro styles (rainbow, matrix, wave, neon, and the comet
 * gradients of shimmer/fade/strike/draw) can't be expressed in the five named
 * tones, so `logo-animation.ts` computes an explicit `#rrggbb` and carries it in
 * the `tone` field itself (it stays pure — no theme). Any value starting with
 * `#` is passed straight through as the foreground; everything else is a named
 * tone mapped to a theme token here. A hidden cell renders as spaces (the caller
 * picks the glyph), so this is only consulted for visible runs; the fg is
 * harmless on a space run regardless.
 */
export function logoRunStyle(tone: LogoCellTone, theme: Theme): { fg: string; attributes?: number } {
  if (tone.startsWith("#")) return { fg: tone };
  switch (tone) {
    case "error":
      return { fg: theme.ERROR };
    case "muted":
      return { fg: theme.MUTED };
    case "dim":
      return { fg: theme.TEXT, attributes: TextAttributes.DIM };
    case "brand":
      return { fg: theme.BRAND };
    default:
      return { fg: theme.TEXT };
  }
}
