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

const ONE_SHOT: LogoAnimStyle[] = ["strike", "draw", "fade", "typein", "sweep", "glitch", "off"];
const LOOPING: LogoAnimStyle[] = ["shimmer", "pulse"];
/** One-shot reveals whose last frame settles to the final frame (excludes off). */
const REVEALS: LogoAnimStyle[] = ["strike", "draw", "fade", "typein", "sweep", "glitch"];
const ALL_STYLES: LogoAnimStyle[] = [
  "strike",
  "draw",
  "fade",
  "shimmer",
  "typein",
  "sweep",
  "glitch",
  "pulse",
  "off",
];

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

  it("marks both shimmer and pulse as looping, every other style one-shot", () => {
    for (const s of LOOPING) expect(logoAnimationLoops(s)).toBe(true);
    for (const s of ONE_SHOT) expect(logoAnimationLoops(s)).toBe(false);
  });

  it("gives every reveal at least two frames so a reveal actually reveals", () => {
    for (const s of REVEALS) expect(logoAnimationFrameCount(s)).toBeGreaterThanOrEqual(2);
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
    for (const style of REVEALS) {
      const last = logoAnimationFrameCount(style) - 1;
      expect(framesEqual(computeLogoFrame(LOGO, style, 9999), finalFrame)).toBe(true);
      expect(framesEqual(computeLogoFrame(LOGO, style, 9999), computeLogoFrame(LOGO, style, last))).toBe(true);
    }
  });

  it("clamps negative frames to frame 0", () => {
    for (const style of REVEALS) {
      expect(framesEqual(computeLogoFrame(LOGO, style, -5), computeLogoFrame(LOGO, style, 0))).toBe(true);
    }
  });

  it("tolerates non-finite frame indices", () => {
    expect(() => computeLogoFrame(LOGO, "strike", Number.NaN)).not.toThrow();
    expect(framesEqual(computeLogoFrame(LOGO, "draw", Number.POSITIVE_INFINITY), finalFrame)).toBe(true);
    expect(() => computeLogoFrame(LOGO, "shimmer", Number.NaN)).not.toThrow();
    expect(() => computeLogoFrame(LOGO, "pulse", Number.NaN)).not.toThrow();
    expect(() => computeLogoFrame(LOGO, "glitch", Number.NaN)).not.toThrow();
    // A non-finite frame for a looping style rests at its phase-0 frame.
    expect(framesEqual(computeLogoFrame(LOGO, "pulse", Number.NaN), computeLogoFrame(LOGO, "pulse", 0))).toBe(true);
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

/** Tones a run may legitimately carry, for alphabet-conformance checks. */
const TONES = new Set(["text", "error", "dim", "muted", "brand"]);

describe("reveal styles settle to the final frame", () => {
  for (const style of REVEALS) {
    it(`${style} ends exactly at the settled final frame`, () => {
      const last = logoAnimationFrameCount(style) - 1;
      expect(framesEqual(computeLogoFrame(LOGO, style, last), finalFrame)).toBe(true);
    });
    it(`${style} never lights a blank cell and only ever uses known tones`, () => {
      const last = logoAnimationFrameCount(style) - 1;
      for (let f = 0; f <= last; f += 1) {
        for (const row of computeLogoFrame(LOGO, style, f)) {
          for (const cell of row) {
            if (cell.ch === " ") expect(cell.visible).toBe(false);
            expect(TONES.has(cell.tone)).toBe(true);
          }
        }
      }
    });
    it(`${style} never carries the transient 'brand' tone into the final frame`, () => {
      const last = logoAnimationFrameCount(style) - 1;
      const brandAtEnd = count(computeLogoFrame(LOGO, style, last), (c) => c.tone === "brand");
      expect(brandAtEnd).toBe(0);
    });
  }
});

describe("typein", () => {
  const last = logoAnimationFrameCount("typein") - 1;

  it("reveals cells monotonically in reading order", () => {
    let prev = -1;
    for (let f = 0; f <= last; f += 1) {
      const vis = count(computeLogoFrame(LOGO, "typein", f), (c) => c.visible);
      expect(vis).toBeGreaterThanOrEqual(prev);
      prev = vis;
    }
  });

  it("starts empty and ends fully visible", () => {
    expect(count(computeLogoFrame(LOGO, "typein", 0), (c) => c.visible)).toBe(0);
    expect(framesEqual(computeLogoFrame(LOGO, "typein", last), finalFrame)).toBe(true);
  });

  it("shows a purple leading glow mid-reveal that is gone by the end", () => {
    let sawBrand = false;
    for (let f = 0; f < last; f += 1) {
      if (count(computeLogoFrame(LOGO, "typein", f), (c) => c.tone === "brand") > 0) sawBrand = true;
    }
    expect(sawBrand).toBe(true);
    expect(count(computeLogoFrame(LOGO, "typein", last), (c) => c.tone === "brand")).toBe(0);
  });

  it("reveals top-left before bottom-right (reading order)", () => {
    // A frame partway through the reveal.
    const mid = computeLogoFrame(LOGO, "typein", Math.floor(last / 2));
    const topLeft = mid[0]!.some((c) => c.visible);
    const bottomRight = mid[4]![34]!.visible;
    expect(topLeft).toBe(true);
    expect(bottomRight).toBe(false);
  });
});

describe("sweep", () => {
  const last = logoAnimationFrameCount("sweep") - 1;

  it("reveals cells monotonically left to right", () => {
    let prev = -1;
    for (let f = 0; f <= last; f += 1) {
      const vis = count(computeLogoFrame(LOGO, "sweep", f), (c) => c.visible);
      expect(vis).toBeGreaterThanOrEqual(prev);
      prev = vis;
    }
  });

  it("starts near-empty and ends fully visible", () => {
    expect(count(computeLogoFrame(LOGO, "sweep", 0), (c) => c.visible)).toBeLessThan(visibleNonSpace);
    expect(framesEqual(computeLogoFrame(LOGO, "sweep", last), finalFrame)).toBe(true);
  });

  it("shows a purple bar mid-sweep that has cleared the mark by the end", () => {
    let sawBar = false;
    for (let f = 0; f < last; f += 1) {
      if (count(computeLogoFrame(LOGO, "sweep", f), (c) => c.tone === "brand") > 0) sawBar = true;
    }
    expect(sawBar).toBe(true);
    expect(count(computeLogoFrame(LOGO, "sweep", last), (c) => c.tone === "brand")).toBe(0);
  });

  it("reveals the left of the mark before the right", () => {
    const mid = computeLogoFrame(LOGO, "sweep", Math.floor(last / 3));
    const leftCol = mid.some((row) => row[1]!.visible);
    const rightCol = mid.some((row) => row[34]!.visible);
    expect(leftCol).toBe(true);
    expect(rightCol).toBe(false);
  });
});

describe("glitch", () => {
  const last = logoAnimationFrameCount("glitch") - 1;

  it("is deterministic (same inputs -> identical output)", () => {
    expect(framesEqual(computeLogoFrame(LOGO, "glitch", 4), computeLogoFrame(LOGO, "glitch", 4))).toBe(true);
    expect(framesEqual(computeLogoFrame(LOGO, "glitch", 7), computeLogoFrame(LOGO, "glitch", 7))).toBe(true);
  });

  it("never lights a blank cell during the scramble", () => {
    for (let f = 0; f <= last; f += 1) {
      for (const row of computeLogoFrame(LOGO, "glitch", f)) {
        for (const cell of row) if (cell.ch === " ") expect(cell.visible).toBe(false);
      }
    }
  });

  it("scrambles before it resolves, then settles to the final frame", () => {
    // An early frame is not yet the settled mark.
    expect(framesEqual(computeLogoFrame(LOGO, "glitch", 0), finalFrame)).toBe(false);
    expect(framesEqual(computeLogoFrame(LOGO, "glitch", last), finalFrame)).toBe(true);
  });

  it("grows the settled set: cells matching the final frame trend upward", () => {
    const matchFinal = (f: number): number => {
      const frame = computeLogoFrame(LOGO, "glitch", f);
      let n = 0;
      for (const [r, row] of frame.entries()) {
        for (const [c, cell] of row.entries()) {
          const target = finalFrame[r]![c]!;
          if (cell.visible === target.visible && cell.tone === target.tone) n += 1;
        }
      }
      return n;
    };
    // Not strictly monotonic frame-to-frame (scramble noise can coincide with
    // the final tone), but the endpoints bracket the trend: far more cells
    // match the final frame late than at the very start.
    expect(matchFinal(last)).toBeGreaterThan(matchFinal(0));
    expect(matchFinal(last)).toBe(count(finalFrame, () => true));
  });
});

describe("pulse", () => {
  const period = logoAnimationFrameCount("pulse");

  it("never hides a non-space cell", () => {
    for (let f = 0; f < period; f += 1) {
      for (const row of computeLogoFrame(LOGO, "pulse", f)) {
        for (const cell of row) if (cell.ch !== " ") expect(cell.visible).toBe(true);
      }
    }
  });

  it("holds the white cells at text while the slash breathes", () => {
    for (const f of [0, 4, 8, 12, 18]) {
      const frame = computeLogoFrame(LOGO, "pulse", f);
      const slashTones = new Set<string>();
      for (const row of frame) {
        for (const cell of row) {
          if (cell.ch === "#") expect(cell.tone).toBe("text");
          if (cell.ch === "/") slashTones.add(cell.tone);
        }
      }
      // All slash cells share exactly one breathing tone this frame.
      expect(slashTones.size).toBe(1);
      expect(["dim", "error", "brand"]).toContain([...slashTones][0]);
    }
  });

  it("passes through the purple peak and the dim trough over a cycle", () => {
    const seen = new Set<string>();
    for (let f = 0; f < period; f += 1) {
      const frame = computeLogoFrame(LOGO, "pulse", f);
      for (const row of frame) for (const cell of row) if (cell.ch === "/") seen.add(cell.tone);
    }
    expect(seen.has("brand")).toBe(true); // peak
    expect(seen.has("dim")).toBe(true); // trough
    expect(seen.has("error")).toBe(true); // mid
  });

  it("starts at the dim trough (loop seam)", () => {
    const f0 = computeLogoFrame(LOGO, "pulse", 0);
    const slash = f0.flatMap((row) => row.filter((c) => c.ch === "/"));
    for (const cell of slash) expect(cell.tone).toBe("dim");
  });

  it("loops seamlessly (frame and frame+period are identical)", () => {
    for (const f of [0, 3, 9, 17]) {
      expect(framesEqual(computeLogoFrame(LOGO, "pulse", f), computeLogoFrame(LOGO, "pulse", f + period))).toBe(true);
    }
  });
});

describe("shimmer comet tail", () => {
  it("trails a dim column one step behind the muted head", () => {
    const frame = computeLogoFrame(LOGO, "shimmer", 5);
    const mutedCols = new Set<number>();
    const dimCols = new Set<number>();
    for (const row of frame) {
      for (const [c, cell] of row.entries()) {
        if (cell.tone === "muted") mutedCols.add(c);
        if (cell.tone === "dim") dimCols.add(c);
      }
    }
    expect([...mutedCols]).toEqual([5]);
    expect([...dimCols]).toEqual([4]);
  });

  it("has no tail at column 0 (head just entering)", () => {
    const frame = computeLogoFrame(LOGO, "shimmer", 0);
    expect(count(frame, (c) => c.tone === "dim")).toBe(0);
    expect(count(frame, (c) => c.tone === "muted")).toBeGreaterThan(0);
  });
});
