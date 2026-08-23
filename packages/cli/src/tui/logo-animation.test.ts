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

const ONE_SHOT: LogoAnimStyle[] = [
  "glitch",
  "matrix",
  "wave",
  "neon",
  "strike",
  "draw",
  "fade",
  "typein",
  "sweep",
  "off",
];
const LOOPING: LogoAnimStyle[] = ["rainbow", "shimmer", "pulse"];
/** One-shot reveals whose last frame settles to the final frame (excludes off). */
const REVEALS: LogoAnimStyle[] = [
  "glitch",
  "matrix",
  "wave",
  "neon",
  "strike",
  "draw",
  "fade",
  "typein",
  "sweep",
];
const ALL_STYLES: LogoAnimStyle[] = [
  "glitch",
  "rainbow",
  "matrix",
  "wave",
  "neon",
  "shimmer",
  "pulse",
  "strike",
  "draw",
  "fade",
  "typein",
  "sweep",
  "off",
];

/** A cell's tone is legitimate if it is a named tone or an explicit #rrggbb hex. */
const NAMED_TONES = new Set(["text", "error", "dim", "muted", "brand"]);
const isKnownTone = (t: string): boolean => NAMED_TONES.has(t) || /^#[0-9a-fA-F]{6}$/.test(t);

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

  it("marks rainbow, shimmer and pulse as looping, every other style one-shot", () => {
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

  it("hidden slash cells stay error-toned; the struck edge flashes purple", () => {
    const f0 = computeLogoFrame(LOGO, "strike", 0);
    for (const row of f0) for (const cell of row) {
      if (cell.ch === "/" && !cell.visible) expect(cell.tone).toBe("error");
      if (cell.ch === "/" && cell.visible) expect(["error", "brand"]).toContain(cell.tone);
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

describe("fade (multi-step bloom)", () => {
  const last = logoAnimationFrameCount("fade") - 1;
  /** Brightness of a cell's tone: the channel sum of a hex bloom step, or the
   *  maximum for a settled full tone (text/error is the brightest final state). */
  const bright = (t: string): number => {
    if (t.startsWith("#")) {
      return parseInt(t.slice(1, 3), 16) + parseInt(t.slice(3, 5), 16) + parseInt(t.slice(5, 7), 16);
    }
    return 765;
  };

  it("keeps every non-space cell visible across all frames", () => {
    for (let f = 0; f <= last; f += 1) {
      for (const row of computeLogoFrame(LOGO, "fade", f)) {
        for (const cell of row) if (cell.ch !== " ") expect(cell.visible).toBe(true);
      }
    }
  });

  it("blooms brightness monotonically (the dimmest cell only brightens)", () => {
    let prevMin = -1;
    for (let f = 0; f <= last; f += 1) {
      let minBright = Number.POSITIVE_INFINITY;
      for (const row of computeLogoFrame(LOGO, "fade", f)) {
        for (const cell of row) if (cell.ch !== " ") minBright = Math.min(minBright, bright(cell.tone));
      }
      expect(minBright).toBeGreaterThanOrEqual(prevMin);
      prevMin = minBright;
    }
  });

  it("starts as a deep hex bloom and ends at the settled final frame", () => {
    const f0 = computeLogoFrame(LOGO, "fade", 0);
    for (const row of f0) for (const cell of row) {
      if (cell.ch !== " ") expect(cell.tone.startsWith("#")).toBe(true);
    }
    expect(framesEqual(computeLogoFrame(LOGO, "fade", last), finalFrame)).toBe(true);
  });
});

describe("shimmer (comet gradient)", () => {
  const period = logoAnimationFrameCount("shimmer");
  const isHex = (t: string): boolean => t.startsWith("#");
  /** Brightness of a neutral-grey #rrggbb by its red channel (r===g===b). */
  const greyLevel = (t: string): number => parseInt(t.slice(1, 3), 16);

  it("never hides a non-space cell", () => {
    for (let f = 0; f < period; f += 1) {
      for (const row of computeLogoFrame(LOGO, "shimmer", f)) {
        for (const cell of row) if (cell.ch !== " ") expect(cell.visible).toBe(true);
      }
    }
  });

  const headCol = (frame: number): number => {
    const f2 = computeLogoFrame(LOGO, "shimmer", frame);
    const colored = new Map<number, number>();
    for (const row of f2) {
      for (const [c, cell] of row.entries()) if (isHex(cell.tone)) colored.set(c, greyLevel(cell.tone));
    }
    return [...colored.entries()].reduce((a, b) => (b[1] < a[1] ? b : a))[0];
  };

  it("sweeps a symmetric DARK band, darkest at the head, brightening both sides", () => {
    const frame = computeLogoFrame(LOGO, "shimmer", 20); // mid-sweep, fully on-screen
    const colored = new Map<number, string>();
    for (const row of frame) {
      for (const [c, cell] of row.entries()) if (isHex(cell.tone)) colored.set(c, cell.tone);
    }
    const cols = [...colored.keys()];
    // The mark is white; shimmer is a dark band whose head (darkest cell) has
    // lit cols on both sides, each brighter than the head.
    expect(cols.length).toBeGreaterThan(2);
    const head = [...colored.entries()].reduce((a, b) => (greyLevel(b[1]) < greyLevel(a[1]) ? b : a))[0];
    expect(Math.min(...cols)).toBeLessThan(head);
    expect(Math.max(...cols)).toBeGreaterThan(head);
    expect(greyLevel(colored.get(head)!)).toBeLessThan(greyLevel(colored.get(Math.min(...cols))!));
    expect(greyLevel(colored.get(head)!)).toBeLessThan(greyLevel(colored.get(Math.max(...cols))!));
  });

  it("enters from the left edge and sweeps rightward (not popping in at the 0)", () => {
    // Frame 0: only the band's leading edge has reached column 0.
    const start = computeLogoFrame(LOGO, "shimmer", 0);
    const startCols = new Set<number>();
    for (const row of start) {
      for (const [c, cell] of row.entries()) if (isHex(cell.tone)) startCols.add(c);
    }
    expect([...startCols]).toEqual([0]); // hugs the far left, hasn't reached the 0's body yet
    // The (darkest) head marches rightward as the animation advances.
    expect(headCol(20)).toBeGreaterThan(headCol(10));
  });

  it("loops seamlessly (frame and frame+period are identical)", () => {
    for (const f of [0, 5, 12]) {
      expect(framesEqual(computeLogoFrame(LOGO, "shimmer", f), computeLogoFrame(LOGO, "shimmer", f + period))).toBe(true);
    }
  });

  it("rests (no comet) once it has swept past the grid", () => {
    const frame = computeLogoFrame(LOGO, "shimmer", 45); // head+tail all off-grid
    expect(count(frame, (c) => isHex(c.tone))).toBe(0);
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
    expect(() => computeLogoFrame(LOGO, "rainbow", Number.NaN)).not.toThrow();
    expect(() => computeLogoFrame(LOGO, "matrix", Number.NaN)).not.toThrow();
    expect(() => computeLogoFrame(LOGO, "wave", Number.NaN)).not.toThrow();
    expect(() => computeLogoFrame(LOGO, "neon", Number.NaN)).not.toThrow();
    // A non-finite frame for a looping style rests at its phase-0 frame.
    expect(framesEqual(computeLogoFrame(LOGO, "pulse", Number.NaN), computeLogoFrame(LOGO, "pulse", 0))).toBe(true);
    expect(framesEqual(computeLogoFrame(LOGO, "rainbow", Number.NaN), computeLogoFrame(LOGO, "rainbow", 0))).toBe(true);
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
            expect(isKnownTone(cell.tone)).toBe(true);
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

describe("shimmer comet tail brightness", () => {
  const greyLevel = (t: string): number => parseInt(t.slice(1, 3), 16);

  it("brightens monotonically on both sides of the head", () => {
    const frame = computeLogoFrame(LOGO, "shimmer", 20); // mid-sweep, fully on-screen
    // Collect the (col -> grey level) of the band, one entry per lit column.
    const byCol = new Map<number, number>();
    for (const row of frame) {
      for (const [c, cell] of row.entries()) {
        if (cell.tone.startsWith("#")) byCol.set(c, greyLevel(cell.tone));
      }
    }
    const cols = [...byCol.keys()];
    const head = [...byCol.entries()].reduce((a, b) => (b[1] < a[1] ? b : a))[0];
    expect(cols.length).toBeGreaterThan(2);
    // Brightness never DECREASES as we walk AWAY from the (darkest) head in
    // either direction — white -> black -> white.
    const left = cols.filter((c) => c <= head).sort((a, b) => b - a); // head -> left
    const right = cols.filter((c) => c >= head).sort((a, b) => a - b); // head -> right
    for (let i = 1; i < left.length; i += 1) {
      expect(byCol.get(left[i]!)!).toBeGreaterThanOrEqual(byCol.get(left[i - 1]!)!);
    }
    for (let i = 1; i < right.length; i += 1) {
      expect(byCol.get(right[i]!)!).toBeGreaterThanOrEqual(byCol.get(right[i - 1]!)!);
    }
  });
});

const isHex = (t: string): boolean => t.startsWith("#");

describe("rainbow", () => {
  const period = logoAnimationFrameCount("rainbow");

  it("loops (metadata) and never hides a non-space cell", () => {
    expect(logoAnimationLoops("rainbow")).toBe(true);
    for (let f = 0; f < period; f += 1) {
      for (const row of computeLogoFrame(LOGO, "rainbow", f)) {
        for (const cell of row) if (cell.ch !== " ") expect(cell.visible).toBe(true);
      }
    }
  });

  it("colours every non-space cell with an explicit hex", () => {
    const frame = computeLogoFrame(LOGO, "rainbow", 3);
    for (const row of frame) {
      for (const cell of row) if (cell.ch !== " ") expect(isHex(cell.tone)).toBe(true);
    }
  });

  it("spreads many hues across the mark (a spectrum, not one colour)", () => {
    const frame = computeLogoFrame(LOGO, "rainbow", 3);
    const hues = new Set<string>();
    for (const row of frame) for (const cell of row) if (cell.ch !== " ") hues.add(cell.tone);
    expect(hues.size).toBeGreaterThan(5);
  });

  it("loops seamlessly (frame and frame+period are identical)", () => {
    for (const f of [0, 7, 20]) {
      expect(framesEqual(computeLogoFrame(LOGO, "rainbow", f), computeLogoFrame(LOGO, "rainbow", f + period))).toBe(true);
    }
  });
});

describe("matrix", () => {
  const last = logoAnimationFrameCount("matrix") - 1;

  it("reveals cells monotonically (the visible set only grows)", () => {
    let prev = -1;
    for (let f = 0; f <= last; f += 1) {
      const vis = count(computeLogoFrame(LOGO, "matrix", f), (c) => c.visible);
      expect(vis).toBeGreaterThanOrEqual(prev);
      prev = vis;
    }
  });

  it("starts near-empty and ends fully visible", () => {
    expect(count(computeLogoFrame(LOGO, "matrix", 0), (c) => c.visible)).toBeLessThan(visibleNonSpace);
    expect(framesEqual(computeLogoFrame(LOGO, "matrix", last), finalFrame)).toBe(true);
  });

  it("shows green drop colours mid-reveal that are gone by the end", () => {
    let sawHex = false;
    for (let f = 0; f < last; f += 1) {
      if (count(computeLogoFrame(LOGO, "matrix", f), (c) => isHex(c.tone)) > 0) sawHex = true;
    }
    expect(sawHex).toBe(true);
    expect(count(computeLogoFrame(LOGO, "matrix", last), (c) => isHex(c.tone))).toBe(0);
  });

  it("never lights a blank cell", () => {
    for (let f = 0; f <= last; f += 1) {
      for (const row of computeLogoFrame(LOGO, "matrix", f)) {
        for (const cell of row) if (cell.ch === " ") expect(cell.visible).toBe(false);
      }
    }
  });

  it("is deterministic (same inputs -> identical output)", () => {
    expect(framesEqual(computeLogoFrame(LOGO, "matrix", 6), computeLogoFrame(LOGO, "matrix", 6))).toBe(true);
  });
});

describe("wave", () => {
  const last = logoAnimationFrameCount("wave") - 1;

  it("reveals cells monotonically (the visible set only grows)", () => {
    let prev = -1;
    for (let f = 0; f <= last; f += 1) {
      const vis = count(computeLogoFrame(LOGO, "wave", f), (c) => c.visible);
      expect(vis).toBeGreaterThanOrEqual(prev);
      prev = vis;
    }
  });

  it("starts near-empty and ends fully visible", () => {
    expect(count(computeLogoFrame(LOGO, "wave", 0), (c) => c.visible)).toBeLessThan(visibleNonSpace);
    expect(framesEqual(computeLogoFrame(LOGO, "wave", last), finalFrame)).toBe(true);
  });

  it("shows a cyan crest mid-reveal that has cleared the mark by the end", () => {
    let sawHex = false;
    for (let f = 0; f < last; f += 1) {
      if (count(computeLogoFrame(LOGO, "wave", f), (c) => isHex(c.tone)) > 0) sawHex = true;
    }
    expect(sawHex).toBe(true);
    expect(count(computeLogoFrame(LOGO, "wave", last), (c) => isHex(c.tone))).toBe(0);
  });

  it("reveals the left of the mark before the right", () => {
    const mid = computeLogoFrame(LOGO, "wave", Math.floor(last / 4));
    const leftCol = mid.some((row) => row[1]!.visible);
    const rightCol = mid.some((row) => row[34]!.visible);
    expect(leftCol).toBe(true);
    expect(rightCol).toBe(false);
  });

  it("never lights a blank cell", () => {
    for (let f = 0; f <= last; f += 1) {
      for (const row of computeLogoFrame(LOGO, "wave", f)) {
        for (const cell of row) if (cell.ch === " ") expect(cell.visible).toBe(false);
      }
    }
  });
});

describe("neon", () => {
  const last = logoAnimationFrameCount("neon") - 1;

  it("flickers on with neon colours, then settles to the final frame", () => {
    let sawHex = false;
    for (let f = 0; f < last; f += 1) {
      if (count(computeLogoFrame(LOGO, "neon", f), (c) => isHex(c.tone)) > 0) sawHex = true;
    }
    expect(sawHex).toBe(true);
    expect(framesEqual(computeLogoFrame(LOGO, "neon", last), finalFrame)).toBe(true);
    expect(count(computeLogoFrame(LOGO, "neon", last), (c) => isHex(c.tone))).toBe(0);
  });

  it("never lights a blank cell during the flicker", () => {
    for (let f = 0; f <= last; f += 1) {
      for (const row of computeLogoFrame(LOGO, "neon", f)) {
        for (const cell of row) if (cell.ch === " ") expect(cell.visible).toBe(false);
      }
    }
  });

  it("is deterministic (same inputs -> identical output)", () => {
    expect(framesEqual(computeLogoFrame(LOGO, "neon", 5), computeLogoFrame(LOGO, "neon", 5))).toBe(true);
  });

  it("grows the settled set (endpoints bracket the trend)", () => {
    const matchFinal = (f: number): number => {
      const frame = computeLogoFrame(LOGO, "neon", f);
      let n = 0;
      for (const [r, row] of frame.entries()) {
        for (const [c, cell] of row.entries()) {
          const target = finalFrame[r]![c]!;
          if (cell.visible === target.visible && cell.tone === target.tone) n += 1;
        }
      }
      return n;
    };
    expect(matchFinal(last)).toBeGreaterThan(matchFinal(0));
    expect(matchFinal(last)).toBe(count(finalFrame, () => true));
  });
});
