/** @jsxImportSource @opentui/react */
import React from "react";
import { parseHex } from "../themes.js";
import { sanitizeTuiText } from "../text.js";
import { shimmerText, type ShimmerTextOptions } from "../animations.js";

/** Shared working-text shimmer, rendered as one native styled text row. */
const GRAPHEMES = new Intl.Segmenter(undefined, { granularity: "grapheme" });

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
  if (opts?.reduceMotion) return [{ text, fg: base }];
  const intensities = shimmerText(text.length, frame, opts);
  const colors = [base, blendHex(base, peak, 0.25), blendHex(base, peak, 0.5), blendHex(base, peak, 0.75), peak];
  const runs: ShimmerRun[] = [];
  // Never split a surrogate pair or combining sequence between color runs.
  for (const { segment, index } of GRAPHEMES.segment(text)) {
    const fg = colors[Math.round((intensities[index] ?? 0) * 4)]!;
    const last = runs[runs.length - 1];
    if (last && last.fg === fg) last.text += segment;
    else runs.push({ text: segment, fg });
  }
  return runs;
}

/** Native spans share text measurement, so color changes cannot shift glyphs. */
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
    <text wrapMode="none" attributes={attributes}>
      {runs.map((run, index) => (
        <span key={index} fg={run.fg}>{run.text}</span>
      ))}
    </text>
  );
}
