/**
 * Stable per-agent accent colour.
 *
 * Every agent (Main, a spawned child, another session) is given a colour derived
 * from its id, reused everywhere the agent appears — its roster row, the marker
 * on its transcript turns, and its name in the inter-agent (IRC) chat log. Same
 * id → same hue, always, so a reader learns "purple is Explorer" once and it
 * holds across the whole console. This mirrors Oh My Pi's `getSessionAccentAnsi`
 * (id → djb2 hash → hue → truecolor), the single biggest thing that makes a
 * multi-agent chat legible.
 *
 * Pure and dependency-free: `id → hex`. The only theme input is whether the
 * background is dark or light, which sets the lightness band so the colour stays
 * legible on the surface it's drawn against.
 */

/**
 * djb2 string hash (Bernstein), xor variant — the exact shape OMP uses. Folded
 * to an unsigned 32-bit int so the result is stable and platform-independent.
 */
export function djb2(text: string): number {
  let hash = 5381;
  for (let i = 0; i < text.length; i += 1) {
    hash = ((hash << 5) + hash) ^ text.charCodeAt(i);
  }
  return hash >>> 0;
}

/**
 * Hues (degrees, 0–360) that read as muddy or low-contrast on a dark terminal
 * and are skipped so every agent colour stays crisp: a yellow-green band and a
 * dead cyan band. The hash lands in the remaining arc, so two ids can still
 * collide on hue, but never on an illegible one.
 */
const DARK_SKIP_BANDS: readonly (readonly [number, number])[] = [
  [64, 96], // olive / yellow-green — turns muddy on near-black
  [166, 194], // flat cyan — low chroma separation from blue
];

/** Map a raw hue into the allowed arc for a dark background. */
function legibleDarkHue(rawHue: number): number {
  let hue = rawHue % 360;
  for (const [lo, hi] of DARK_SKIP_BANDS) {
    if (hue >= lo && hue < hi) {
      // Push it just past the band, wrapping the remainder so the distribution
      // stays even rather than piling up on the band edge.
      hue = (hi + (hue - lo)) % 360;
    }
  }
  return hue;
}

/** HSL (h in degrees, s/l in 0..1) → `#RRGGBB`. */
export function hslToHex(h: number, s: number, l: number): string {
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const hp = (((h % 360) + 360) % 360) / 60;
  const x = c * (1 - Math.abs((hp % 2) - 1));
  let r = 0;
  let g = 0;
  let b = 0;
  if (hp < 1) [r, g, b] = [c, x, 0];
  else if (hp < 2) [r, g, b] = [x, c, 0];
  else if (hp < 3) [r, g, b] = [0, c, x];
  else if (hp < 4) [r, g, b] = [0, x, c];
  else if (hp < 5) [r, g, b] = [x, 0, c];
  else [r, g, b] = [c, 0, x];
  const m = l - c / 2;
  const to255 = (v: number): string =>
    Math.round((v + m) * 255)
      .toString(16)
      .padStart(2, "0")
      .toUpperCase();
  return `#${to255(r)}${to255(g)}${to255(b)}`;
}

/**
 * The stable accent colour for `id`, tuned to a dark or light background.
 *
 * Dark backgrounds get a bright, mid-saturation pastel (legible on near-black);
 * light backgrounds get a darker, saturated tone (legible on near-white). The
 * hue comes from the id hash, snapped out of the illegible bands on dark.
 */
export function agentAccent(id: string, dark: boolean): string {
  const rawHue = djb2(id || "peer") % 360;
  if (dark) {
    return hslToHex(legibleDarkHue(rawHue), 0.62, 0.68);
  }
  return hslToHex(rawHue, 0.6, 0.38);
}

/**
 * True when a `#RRGGBB` background reads as dark (so light-on-dark text wins).
 * A cheap perceptual-ish luminance, enough to pick the accent lightness band —
 * this deliberately does not pull in the WCAG luminance util.
 */
export function isDarkHex(hex: string): boolean {
  if (typeof hex !== "string" || !/^#[0-9a-fA-F]{6}$/.test(hex)) return true;
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return 0.299 * r + 0.587 * g + 0.114 * b < 128;
}

/**
 * The accent for `id`, tuned to a theme by reading whether its canvas is dark.
 * The convenience call sites use so they don't each recompute dark/light.
 */
export function agentAccentFor(id: string, canvasHex: string): string {
  return agentAccent(id, isDarkHex(canvasHex));
}
