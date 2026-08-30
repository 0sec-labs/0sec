import { describe, expect, it } from "vitest";

import { agentAccent, djb2, hslToHex } from "./agent-color.js";

describe("djb2", () => {
  it("is deterministic and unsigned", () => {
    expect(djb2("Main")).toBe(djb2("Main"));
    expect(djb2("Main")).toBeGreaterThanOrEqual(0);
    expect(djb2("Explorer")).not.toBe(djb2("Scout"));
  });

  it("handles the empty string without throwing", () => {
    expect(Number.isFinite(djb2(""))).toBe(true);
  });
});

describe("hslToHex", () => {
  it("maps the primaries", () => {
    expect(hslToHex(0, 1, 0.5)).toBe("#FF0000");
    expect(hslToHex(120, 1, 0.5)).toBe("#00FF00");
    expect(hslToHex(240, 1, 0.5)).toBe("#0000FF");
  });

  it("always yields a well-formed #RRGGBB", () => {
    for (let h = 0; h < 360; h += 7) {
      expect(hslToHex(h, 0.62, 0.68)).toMatch(/^#[0-9A-F]{6}$/);
    }
  });

  it("normalizes out-of-range and negative hues", () => {
    expect(hslToHex(360, 1, 0.5)).toBe(hslToHex(0, 1, 0.5));
    expect(hslToHex(-120, 1, 0.5)).toBe(hslToHex(240, 1, 0.5));
  });
});

describe("agentAccent", () => {
  it("is stable for an id", () => {
    expect(agentAccent("Explorer", true)).toBe(agentAccent("Explorer", true));
  });

  it("differs between dark and light tuning", () => {
    expect(agentAccent("Explorer", true)).not.toBe(agentAccent("Explorer", false));
  });

  it("is always a legible-length hex, even for empty/degenerate ids", () => {
    for (const id of ["", "Main", "a", "subagent-1234-5678", "🙂"]) {
      expect(agentAccent(id, true)).toMatch(/^#[0-9A-F]{6}$/);
      expect(agentAccent(id, false)).toMatch(/^#[0-9A-F]{6}$/);
    }
  });

  it("keeps dark-theme hues out of the skipped muddy bands", () => {
    // Sweep many ids; none should land an accent whose hue sits in the olive or
    // flat-cyan bands the dark tuning avoids. We reconstruct hue from the hex.
    const inSkip = (hex: string): boolean => {
      const r = parseInt(hex.slice(1, 3), 16) / 255;
      const g = parseInt(hex.slice(3, 5), 16) / 255;
      const b = parseInt(hex.slice(5, 7), 16) / 255;
      const max = Math.max(r, g, b);
      const min = Math.min(r, g, b);
      const d = max - min;
      if (d === 0) return false;
      let h: number;
      if (max === r) h = 60 * (((g - b) / d) % 6);
      else if (max === g) h = 60 * ((b - r) / d + 2);
      else h = 60 * ((r - g) / d + 4);
      if (h < 0) h += 360;
      return (h >= 64 && h < 96) || (h >= 166 && h < 194);
    };
    for (let i = 0; i < 500; i += 1) {
      expect(inSkip(agentAccent(`agent-${i}`, true))).toBe(false);
    }
  });
});
