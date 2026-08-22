import { describe, expect, it } from "vitest";

import {
  computeLogoFrame,
  finalLogoFrame,
  logoAnimationFrameCount,
  logoAnimationLoops,
  logoRowRuns,
  type LogoAnimStyle,
  type LogoFrame,
} from "./logo-animation.js";

/** The shipped 0SEC block mark (mirrors chat-screen's TERMINAL_BLOCK_LOGO). */
const LOGO = [
  " ######   #######  #######   ######",
  "##  //##  ##       ##       ##     ",
  "## // ##  #######  #####    ##     ",
  "##//  ##       ##  ##       ##     ",
  " ######   #######  #######   ######",
] as const;

const ONE_SHOT: LogoAnimStyle[] = ["strike", "draw", "fade", "off"];
const ALL_STYLES: LogoAnimStyle[] = ["strike", "draw", "fade", "shimmer", "off"];

/** Count cells matching a predicate across a frame. */
function count(frame: LogoFrame, pred: (c: LogoFrame[number][number]) => boolean): number {
  let n = 0;
  for (const row of frame) for (const c of row) if (pred(c)) n += 1;
  return n;
}

/** Deep-equality of two frames (state is plain data). */
function framesEqual(a: LogoFrame, b: LogoFrame): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

const finalFrame = finalLogoFrame(LOGO);
const visibleNonSpace = count(finalFrame, (c) => c.ch !== " ");
const slashTotal = count(finalFrame, (c) => c.ch === "/");

describe("finalLogoFrame", () => {
  it("is rectangular at the grid's max width", () => {
    expect(finalFrame).toHaveLength(LOGO.length);
    for (const row of finalFrame) expect(row).toHaveLength(35);
  });

  it("shows every non-space cell at its final tone; spaces hidden", () => {
    for (const [r, row] of finalFrame.entries()) {
      for (const [c, cell] of row.entries()) {
        const raw = LOGO[r]![c] ?? " ";
        if (raw === " ") {
          expect(cell.visible).toBe(false);
        } else {
          expect(cell.visible).toBe(true);
          expect(cell.tone).toBe(raw === "/" ? "error" : "text");
        }
      }
    }
  });

  it("has the expected slash cells (the diagonal through the zero)", () => {
    expect(slashTotal).toBe(6);
  });
});

describe("frame-count / loop metadata", () => {
  it("reports positive one-shot counts and shimmer looping", () => {
    for (const s of ONE_SHOT) expect(logoAnimationFrameCount(s)).toBeGreaterThanOrEqual(1);
    expect(logoAnimationFrameCount("shimmer")).toBeGreaterThan(35); // period > grid width
    expect(logoAnimationLoops("shimmer")).toBe(true);
    for (const s of ONE_SHOT) expect(logoAnimationLoops(s)).toBe(false);
  });

  it("off has a single static frame", () => {
    expect(logoAnimationFrameCount("off")).toBe(1);
  });
});

describe("strike", () => {
  const last = logoAnimationFrameCount("strike") - 1;

  it("shows all white/outline cells from frame 0", () => {
    const f0 = computeLogoFrame(LOGO, "strike", 0);
    for (const row of f0) for (const cell of row) {
      if (cell.ch === "#") expect(cell.visible).toBe(true);
    }
  });

  it("reveals slash cells monotonically along the frames", () => {
    let prev = -1;
    for (let f = 0; f <= last; f += 1) {
      const visibleSlashes = count(computeLogoFrame(LOGO, "strike", f), (c) => c.ch === "/" && c.visible);
      expect(visibleSlashes).toBeGreaterThanOrEqual(prev);
      prev = visibleSlashes;
    }
  });

  it("reveals lower-left before upper-right (diagonal order)", () => {
    // Early frame: the lower-left slash (row 3) shows before the upper-right (row 1).
    const early = computeLogoFrame(LOGO, "strike", 0);
    const lowerLeft = early[3]!.some((c) => c.ch === "/" && c.visible);
    const upperRight = early[1]!.some((c) => c.ch === "/" && c.visible);
    expect(lowerLeft).toBe(true);
    expect(upperRight).toBe(false);
  });

  it("ends fully visible (equals the final frame)", () => {
    expect(framesEqual(computeLogoFrame(LOGO, "strike", last), finalFrame)).toBe(true);
    expect(count(computeLogoFrame(LOGO, "strike", last), (c) => c.ch === "/" && c.visible)).toBe(slashTotal);
  });

  it("slash tone is error, and hidden slash cells keep their ch", () => {
    const f0 = computeLogoFrame(LOGO, "strike", 0);
    for (const row of f0) for (const cell of row) {
      if (cell.ch === "/") expect(cell.tone).toBe("error");
    }
  });
});

describe("draw", () => {
  const last = logoAnimationFrameCount("draw") - 1;

  it("reveals cells monotonically column-by-column", () => {
    let prev = -1;
    for (let f = 0; f <= last; f += 1) {
      const vis = count(computeLogoFrame(LOGO, "draw", f), (c) => c.visible);
      expect(vis).toBeGreaterThanOrEqual(prev);
      prev = vis;
    }
  });

  it("starts nearly empty and ends fully visible", () => {
    const f0 = computeLogoFrame(LOGO, "draw", 0);
    expect(count(f0, (c) => c.visible)).toBeLessThan(visibleNonSpace);
    expect(framesEqual(computeLogoFrame(LOGO, "draw", last), finalFrame)).toBe(true);
  });

  it("only ever draws non-space cells (never lights a blank)", () => {
    for (let f = 0; f <= last; f += 1) {
      for (const row of computeLogoFrame(LOGO, "draw", f)) {
        for (const cell of row) if (cell.ch === " ") expect(cell.visible).toBe(false);
      }
    }
  });
});

describe("fade", () => {
  const last = logoAnimationFrameCount("fade") - 1;
  const rank: Record<string, number> = { dim: 0, muted: 1, text: 2, error: 2 };

  it("keeps every non-space cell visible across all frames", () => {
    for (let f = 0; f <= last; f += 1) {
      for (const row of computeLogoFrame(LOGO, "fade", f)) {
        for (const cell of row) if (cell.ch !== " ") expect(cell.visible).toBe(true);
      }
    }
  });

  it("ramps brightness dim -> full monotonically per cell", () => {
    let prevMin = -1;
    for (let f = 0; f <= last; f += 1) {
      let minRank = Number.POSITIVE_INFINITY;
      for (const row of computeLogoFrame(LOGO, "fade", f)) {
        for (const cell of row) if (cell.ch !== " ") minRank = Math.min(minRank, rank[cell.tone]!);
      }
      expect(minRank).toBeGreaterThanOrEqual(prevMin);
      prevMin = minRank;
    }
  });

  it("starts dim and ends at full colour", () => {
    const f0 = computeLogoFrame(LOGO, "fade", 0);
    for (const row of f0) for (const cell of row) if (cell.ch !== " ") expect(cell.tone).toBe("dim");
    expect(framesEqual(computeLogoFrame(LOGO, "fade", last), finalFrame)).toBe(true);
  });
});

describe("shimmer", () => {
  const period = logoAnimationFrameCount("shimmer");

  it("never hides a non-space cell", () => {
    for (let f = 0; f < period; f += 1) {
      for (const row of computeLogoFrame(LOGO, "shimmer", f)) {
        for (const cell of row) if (cell.ch !== " ") expect(cell.visible).toBe(true);
      }
    }
  });

  it("highlights exactly one column band as it sweeps", () => {
    // While the sweep is over the grid (idx < width) exactly one column is muted.
    const f = 3;
    const frame = computeLogoFrame(LOGO, "shimmer", f);
    const mutedCols = new Set<number>();
    for (const row of frame) {
      for (const [c, cell] of row.entries()) if (cell.tone === "muted") mutedCols.add(c);
    }
    expect(mutedCols.size).toBe(1);
    expect([...mutedCols][0]).toBe(f);
  });

  it("loops seamlessly (frame and frame+period are identical)", () => {
    for (const f of [0, 5, 12]) {
      expect(framesEqual(computeLogoFrame(LOGO, "shimmer", f), computeLogoFrame(LOGO, "shimmer", f + period))).toBe(true);
    }
  });

  it("rests (no highlight) when the sweep is past the grid width", () => {
    const frame = computeLogoFrame(LOGO, "shimmer", 40); // 35 <= 40 < 48
    expect(count(frame, (c) => c.tone === "muted")).toBe(0);
    expect(framesEqual(frame, finalFrame)).toBe(true);
  });
});

describe("off", () => {
  it("is a single static frame equal to the final frame, for any index", () => {
    for (const f of [0, 1, 7, 999, -3]) {
      expect(framesEqual(computeLogoFrame(LOGO, "off", f), finalFrame)).toBe(true);
    }
  });
});

describe("reduceMotion", () => {
  it("forces the static final frame for every style and frame", () => {
    for (const style of ALL_STYLES) {
      for (const f of [0, 1, 5, 100]) {
        expect(framesEqual(computeLogoFrame(LOGO, style, f, { reduceMotion: true }), finalFrame)).toBe(true);
      }
    }
  });
});

describe("frame clamping / guards", () => {
  it("clamps one-shot frames past the end to the final frame", () => {
    for (const style of ["strike", "draw", "fade"] as LogoAnimStyle[]) {
      const last = logoAnimationFrameCount(style) - 1;
      expect(framesEqual(computeLogoFrame(LOGO, style, 9999), finalFrame)).toBe(true);
      expect(framesEqual(computeLogoFrame(LOGO, style, 9999), computeLogoFrame(LOGO, style, last))).toBe(true);
    }
  });

  it("clamps negative frames to frame 0", () => {
    for (const style of ["strike", "draw", "fade"] as LogoAnimStyle[]) {
      expect(framesEqual(computeLogoFrame(LOGO, style, -5), computeLogoFrame(LOGO, style, 0))).toBe(true);
    }
  });

  it("tolerates non-finite frame indices", () => {
    expect(() => computeLogoFrame(LOGO, "strike", Number.NaN)).not.toThrow();
    expect(framesEqual(computeLogoFrame(LOGO, "draw", Number.POSITIVE_INFINITY), finalFrame)).toBe(true);
    expect(() => computeLogoFrame(LOGO, "shimmer", Number.NaN)).not.toThrow();
  });

  it("returns an empty frame for an empty grid", () => {
    expect(computeLogoFrame([], "strike", 0)).toEqual([]);
  });

  it("is deterministic (same inputs -> identical output)", () => {
    expect(framesEqual(computeLogoFrame(LOGO, "strike", 4), computeLogoFrame(LOGO, "strike", 4))).toBe(true);
  });
});

describe("logoRowRuns", () => {
  it("run lengths across a row sum to the grid width (no overflow)", () => {
    const frame = finalLogoFrame(LOGO);
    const width = LOGO.reduce((w, row) => Math.max(w, row.length), 0);
    for (const row of frame) {
      const runs = logoRowRuns(row);
      expect(runs.reduce((n, r) => n + r.length, 0)).toBe(width);
    }
  });

  it("coalesces adjacent cells sharing (tone, visible)", () => {
    // Row 0 of the mark: a leading empty cell, then a run of white blocks.
    const row0 = finalLogoFrame(LOGO)[0]!;
    const runs = logoRowRuns(row0);
    expect(runs.length).toBeGreaterThan(1);
    expect(runs[0]).toMatchObject({ tone: "text", visible: false });
    expect(runs[1]).toMatchObject({ tone: "text", visible: true });
    // Neighbouring runs never share the same (tone, visible) pair.
    for (let i = 1; i < runs.length; i += 1) {
      const same = runs[i]!.tone === runs[i - 1]!.tone && runs[i]!.visible === runs[i - 1]!.visible;
      expect(same).toBe(false);
    }
  });

  it("keeps the red slash tone distinct from the white blocks", () => {
    // A mid-strike frame reveals some slash cells: an "error" run must appear.
    const frame = computeLogoFrame(LOGO, "strike", logoAnimationFrameCount("strike") - 1);
    const tones = new Set(frame.flatMap((row) => logoRowRuns(row).map((r) => r.tone)));
    expect(tones.has("error")).toBe(true);
    expect(tones.has("text")).toBe(true);
  });
});
