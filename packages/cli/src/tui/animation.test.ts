import { describe, expect, it } from "vitest";

import {
  ANIMATION_KINDS,
  ELAPSED_VISIBLE_AFTER_MS,
  GLYPH_CELLS,
  frameAt,
  frameCount,
  frameIntervalMs,
  framePeriodMs,
  formatElapsed,
  type AnimationKind,
} from "./animation.js";

const SETS = [
  { name: "unicode", ascii: false },
  { name: "ascii", ascii: true },
] as const;

const BUSY_KINDS: AnimationKind[] = ["connecting", "thinking", "streaming", "tool"];

/** Every frame of a kind, in cycle order, for one glyph set. */
function cycle(kind: AnimationKind, ascii: boolean): string[] {
  const interval = frameIntervalMs(kind);
  return Array.from(
    { length: frameCount(kind) },
    (_, i) => frameAt(kind, i * interval, { ascii }).glyph,
  );
}

/**
 * Cell width, computed from an allowlist rather than guessed.
 *
 * The module's width guarantee is that frames only contain code points from
 * ranges that are one cell wide in every terminal: printable ASCII
 * (East_Asian_Width=Na) and Braille Patterns (East_Asian_Width=N). Anything
 * outside those ranges could be wide, ambiguous, zero-width or combining, so
 * this helper refuses to measure it at all.
 */
function cellWidth(glyph: string): number {
  let width = 0;
  for (const char of glyph) {
    const cp = char.codePointAt(0)!;
    const narrow = (cp >= 0x20 && cp <= 0x7e) || (cp >= 0x2800 && cp <= 0x28ff);
    if (!narrow) {
      throw new Error(
        `glyph ${JSON.stringify(glyph)} contains untrusted code point U+${cp.toString(16).toUpperCase()}`,
      );
    }
    width += 1;
  }
  return width;
}

describe("frame geometry", () => {
  for (const kind of ANIMATION_KINDS) {
    for (const set of SETS) {
      it(`${kind} (${set.name}) frames all occupy exactly ${GLYPH_CELLS} cells`, () => {
        const frames = cycle(kind, set.ascii);
        expect(frames.length).toBeGreaterThan(1);
        for (const glyph of frames) {
          expect([...glyph].length).toBe(GLYPH_CELLS);
          expect(cellWidth(glyph)).toBe(GLYPH_CELLS);
        }
        // The same assertion phrased as the bug it prevents: one width per kind.
        expect(new Set(frames.map((glyph) => [...glyph].length)).size).toBe(1);
        expect(new Set(frames.map(cellWidth)).size).toBe(1);
      });
    }

    it(`${kind} has the same frame count in both sets, so the period is set-independent`, () => {
      expect(cycle(kind, false).length).toBe(cycle(kind, true).length);
      expect(framePeriodMs(kind)).toBe(frameCount(kind) * frameIntervalMs(kind));
    });
  }
});

describe("terminal safety", () => {
  const FORBIDDEN = [
    { name: "ANSI escape or control character", re: /[\x00-\x1f\x7f]/ },
    { name: "combining mark", re: /\p{M}/u },
    { name: "emoji or pictograph", re: /\p{Extended_Pictographic}/u },
    { name: "variation selector", re: /[\ufe00-\ufe0f]/ },
    { name: "zero-width or bidi control", re: /[\u200b-\u200f\u2028\u2029\u202a-\u202e\ufeff]/ },
    {
      name: "east-asian wide range",
      re: /[\u1100-\u115f\u2e80-\u4dbf\u4e00-\u9fff\uac00-\ud7a3\uf900-\ufaff\ufe30-\ufe4f\uff00-\uff60\uffe0-\uffe6]/,
    },
  ];

  for (const kind of ANIMATION_KINDS) {
    for (const set of SETS) {
      it(`${kind} (${set.name}) frames are plain, single-width glyphs`, () => {
        for (const glyph of cycle(kind, set.ascii)) {
          for (const rule of FORBIDDEN) {
            expect(rule.re.test(glyph), `${rule.name} in ${JSON.stringify(glyph)}`).toBe(false);
          }
          // No astral code points at all: every char is a single UTF-16 unit.
          expect(glyph.length).toBe([...glyph].length);
        }
      });
    }
  }

  it("unicode frames use braille blank, never ASCII space, so trimming cannot shorten them", () => {
    for (const kind of ANIMATION_KINDS) {
      for (const glyph of cycle(kind, false)) {
        expect(glyph).not.toContain(" ");
        expect(glyph.trim()).toBe(glyph);
      }
    }
  });

  it("ascii frames avoid spaces too, so a whitespace-collapsing renderer cannot damage them", () => {
    for (const kind of ANIMATION_KINDS) {
      for (const glyph of cycle(kind, true)) {
        expect(glyph).not.toContain(" ");
        expect(glyph.replace(/\s+/g, " ").trim()).toBe(glyph);
      }
    }
  });
});

describe("determinism and cycling", () => {
  for (const kind of ANIMATION_KINDS) {
    it(`${kind} returns the same frame for the same elapsed value`, () => {
      for (const elapsed of [0, 37, 501, 1234, 60_000]) {
        expect(frameAt(kind, elapsed)).toEqual(frameAt(kind, elapsed));
        expect(frameAt(kind, elapsed, { ascii: true })).toEqual(
          frameAt(kind, elapsed, { ascii: true }),
        );
      }
    });

    it(`${kind} advances one frame per interval and repeats after its period`, () => {
      const interval = frameIntervalMs(kind);
      const period = framePeriodMs(kind);
      const frames = cycle(kind, false);

      // A frame is held for the whole interval, then swaps.
      expect(frameAt(kind, interval - 1).glyph).toBe(frames[0]);
      expect(frameAt(kind, interval).glyph).toBe(frames[1]);

      // Same phase, three cycles later.
      for (let i = 0; i < frames.length; i += 1) {
        expect(frameAt(kind, i * interval + 3 * period).glyph).toBe(frames[i]);
      }
    });

    it(`${kind} never repaints faster than 10 Hz`, () => {
      expect(frameIntervalMs(kind)).toBeGreaterThanOrEqual(100);
    });

    it(`${kind} has no two consecutive frames identical, so the motion never stalls`, () => {
      for (const set of SETS) {
        const frames = cycle(kind, set.ascii);
        for (let i = 0; i < frames.length; i += 1) {
          expect(frames[i], `${set.name} frame ${i}`).not.toBe(frames[(i + 1) % frames.length]);
        }
      }
    });
  }
});

describe("motion: false", () => {
  for (const kind of ANIMATION_KINDS) {
    it(`${kind} is pinned to a single frame when motion is disabled`, () => {
      const stable = frameAt(kind, 0, { motion: false }).glyph;
      const stableAscii = frameAt(kind, 0, { motion: false, ascii: true }).glyph;
      for (const elapsed of [0, 17, 250, 999, 5_000, 3_600_000, Number.NaN]) {
        expect(frameAt(kind, elapsed, { motion: false }).glyph).toBe(stable);
        expect(frameAt(kind, elapsed, { motion: false, ascii: true }).glyph).toBe(stableAscii);
      }
    });
  }

  it("still reports elapsed with motion off, because that is what proves it is not hung", () => {
    expect(frameAt("thinking", 12_000, { motion: false }).elapsedLabel).toBe("12s");
  });
});

describe("elapsed label", () => {
  it("is omitted below the threshold", () => {
    for (const elapsed of [0, 500, ELAPSED_VISIBLE_AFTER_MS - 1]) {
      expect(frameAt("thinking", elapsed).elapsedLabel).toBeUndefined();
    }
    expect(frameAt("thinking", ELAPSED_VISIBLE_AFTER_MS).elapsedLabel).toBe("3s");
  });

  it("formats compactly across the whole range", () => {
    expect(formatElapsed(9_000)).toBe("9s");
    expect(formatElapsed(9_999)).toBe("9s");
    expect(formatElapsed(59_000)).toBe("59s");
    expect(formatElapsed(60_000)).toBe("1m00s");
    expect(formatElapsed(64_000)).toBe("1m04s");
    expect(formatElapsed(3_599_000)).toBe("59m59s");
    expect(formatElapsed(3_600_000)).toBe("1h00m");
    expect(formatElapsed(7_500_000)).toBe("2h05m");
  });

  it("never fabricates a percentage or an ETA", () => {
    const frame = frameAt("tool", 90_000, { label: "http_probe" });
    expect(frame.elapsedLabel).toBe("1m30s");
    expect(JSON.stringify(frame)).not.toMatch(/%|eta|remaining/i);
  });

  it("clamps absurd values instead of producing an unbounded label", () => {
    expect(formatElapsed(Number.MAX_SAFE_INTEGER)).toBe("99h59m");
    expect(formatElapsed(Number.MAX_SAFE_INTEGER).length).toBeLessThanOrEqual(6);
  });
});

describe("hostile inputs", () => {
  const NASTY = [
    -1,
    -100_000,
    0,
    0.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    Number.MAX_SAFE_INTEGER,
    1e308,
  ];

  for (const kind of ANIMATION_KINDS) {
    it(`${kind} produces a valid frame for degenerate elapsed values`, () => {
      for (const elapsed of NASTY) {
        for (const set of SETS) {
          const frame = frameAt(kind, elapsed, { ascii: set.ascii });
          expect(() => cellWidth(frame.glyph)).not.toThrow();
          expect(cellWidth(frame.glyph)).toBe(GLYPH_CELLS);
          expect(cycle(kind, set.ascii)).toContain(frame.glyph);
          expect(frame.label.length).toBeGreaterThan(0);
        }
      }
    });
  }

  it("treats negative and non-finite elapsed as zero", () => {
    for (const elapsed of [-1, -50_000, Number.NaN, Number.NEGATIVE_INFINITY]) {
      expect(frameAt("thinking", elapsed).glyph).toBe(frameAt("thinking", 0).glyph);
      expect(frameAt("thinking", elapsed).elapsedLabel).toBeUndefined();
    }
  });

  it("falls back to a valid frame rather than throwing on an unknown kind", () => {
    const frame = frameAt("not-a-kind" as AnimationKind, 0);
    expect(cellWidth(frame.glyph)).toBe(GLYPH_CELLS);
    expect(frame.label).toBe("thinking");
  });
});

describe("labels", () => {
  it("uses a distinct default per kind", () => {
    const labels = ANIMATION_KINDS.map((kind) => frameAt(kind, 0).label);
    expect(new Set(labels).size).toBe(ANIMATION_KINDS.length);
  });

  it("accepts an override, typically the tool name", () => {
    expect(frameAt("tool", 0, { label: "sqlmap" }).label).toBe("sqlmap");
  });

  it("strips control characters and ANSI from an untrusted label", () => {
    const frame = frameAt("tool", 0, { label: "\u001b[31mrm\n-rf /" });
    expect(frame.label).toBe("rm -rf /");
    expect(/[\x00-\x1f\x7f]/.test(frame.label)).toBe(false);
  });

  it("caps a runaway label", () => {
    expect(frameAt("tool", 0, { label: "x".repeat(500) }).label.length).toBeLessThanOrEqual(48);
  });

  it("falls back to the default when the override is empty or whitespace", () => {
    expect(frameAt("tool", 0, { label: "   " }).label).toBe(frameAt("tool", 0).label);
    expect(frameAt("tool", 0, { label: "" }).label).toBe(frameAt("tool", 0).label);
  });
});

describe("awaiting-operator is not a busy state", () => {
  it("shares no frame with any busy animation, in either glyph set", () => {
    for (const set of SETS) {
      const waiting = new Set(cycle("awaiting-operator", set.ascii));
      for (const kind of BUSY_KINDS) {
        for (const glyph of cycle(kind, set.ascii)) {
          expect(
            waiting.has(glyph),
            `${kind} (${set.name}) frame ${JSON.stringify(glyph)} leaked into awaiting-operator`,
          ).toBe(false);
        }
      }
    }
  });

  it("moves at least four times slower than every busy animation", () => {
    const slowestBusy = Math.max(...BUSY_KINDS.map(frameIntervalMs));
    expect(frameIntervalMs("awaiting-operator")).toBeGreaterThanOrEqual(slowestBusy * 4);
  });

  it("has the shortest cycle of all, so it reads as a blink and not a spinner", () => {
    expect(frameCount("awaiting-operator")).toBe(2);
    for (const kind of BUSY_KINDS) expect(frameCount(kind)).toBeGreaterThan(2);
  });
});

describe("the busy kinds are distinguishable from each other", () => {
  it("no two busy kinds share a cycle", () => {
    const seen = new Map<string, AnimationKind>();
    for (const kind of BUSY_KINDS) {
      const key = cycle(kind, false).join("");
      expect(seen.has(key), `${kind} duplicates ${String(seen.get(key))}`).toBe(false);
      seen.set(key, kind);
    }
  });

  it("thinking deliberates slower than streaming produces", () => {
    expect(frameIntervalMs("streaming")).toBeLessThan(frameIntervalMs("thinking"));
    expect(frameIntervalMs("streaming")).toBeLessThanOrEqual(
      Math.min(...BUSY_KINDS.map(frameIntervalMs)),
    );
  });
});
