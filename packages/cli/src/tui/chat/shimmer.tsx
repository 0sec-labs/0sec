/** @jsxImportSource @opentui/react */
import React from "react";
import { parseHex } from "../themes.js";
import { sanitizeTuiText } from "../text.js";
import { shimmerText, type ShimmerTextOptions } from "../animations.js";

/**
 * The render half of the text shimmer (`shimmerText` in animations.ts owns the
 * pure per-character intensities). A running LOADING label — the thinking
 * indicator, a running tool-call row, a running subagent row — sits at a muted
 * base while a bright band sweeps across it, the "alive while working" feel from
 * oh-my-pi. animations.ts stays theme-free and returns intensities; THIS module
 * blends `base` (intensity 0) up to `peak` (intensity 1) and coalesces adjacent
 * equal-tone characters into runs, mirroring `logoRowRuns` so the label paints
 * as a handful of explicitly-sized `<text>`s rather than one node per character.
 *
 * Every run is `flexShrink={0}` with an explicit width equal to its character
 * count (the TUI's width model — see `fitTuiText`), and the caller has already
 * fitted the label to the cells it owns, so the run widths sum to the fitted
 * length and never overflow their row (the chat-layout invariant).
 */

/** Clamp a channel and format it as a two-digit hex byte. */
function toHexByte(value: number): string {
  const v = value < 0 ? 0 : value > 255 ? 255 : Math.round(value);
  return v.toString(16).padStart(2, "0");
}

/**
 * Blend two `#RRGGBB` colours by `t` in [0,1] (0 = `from`, 1 = `to`). Falls back
 * to `to` when either input is not a parseable hex colour, so a themed token
 * that is somehow malformed degrades to the bright end rather than throwing.
 */
export function blendHex(from: string, to: string, t: number): string {
  const a = parseHex(from);
  const b = parseHex(to);
  if (!a || !b) return to;
  const k = t < 0 ? 0 : t > 1 ? 1 : t;
  return `#${toHexByte(a.r + (b.r - a.r) * k)}${toHexByte(a.g + (b.g - a.g) * k)}${toHexByte(
    a.b + (b.b - a.b) * k,
  )}`.toUpperCase();
}

export interface ShimmerRun {
  text: string;
  fg: string;
}

/**
 * Coalesce a fitted label into (text, colour) runs for one shimmer `frame`. The
 * intensity is quantised to a few steps before blending so adjacent characters
 * in the band share a tone and collapse into one run — a short label becomes a
 * handful of nodes, not one per character.
 */
export function shimmerRuns(
  label: string,
  frame: number,
  base: string,
  peak: string,
  opts?: ShimmerTextOptions,
): ShimmerRun[] {
  const text = sanitizeTuiText(label);
  if (text.length === 0) return [];
  const intensities = shimmerText(text.length, frame, opts);
  const runs: ShimmerRun[] = [];
  for (let i = 0; i < text.length; i += 1) {
    const quantised = Math.round((intensities[i] ?? 0) * 4) / 4;
    const fg = blendHex(base, peak, quantised);
    const last = runs[runs.length - 1];
    if (last && last.fg === fg) last.text += text.charAt(i);
    else runs.push({ text: text.charAt(i), fg });
  }
  return runs;
}

/**
 * A single row of shimmer runs. `label` must already be fitted to the cells it
 * is allowed to occupy; each run is drawn at its exact character width so the
 * row's children never over-subscribe it. Under `reduceMotion` every intensity
 * is 0, so the whole label renders flat at `base` — the honest still frame.
 */
export function ShimmerText({
  label,
  frame,
  base,
  peak,
  opts,
  attributes,
}: {
  label: string;
  frame: number;
  base: string;
  peak: string;
  opts?: ShimmerTextOptions;
  attributes?: number;
}) {
  const runs = shimmerRuns(label, frame, base, peak, opts);
  return (
    <box flexDirection="row" flexShrink={0} minWidth={0}>
      {runs.map((run, index) => (
        <text
          key={index}
          width={run.text.length}
          flexShrink={0}
          fg={run.fg}
          attributes={attributes}
        >
          {run.text}
        </text>
      ))}
    </box>
  );
}
