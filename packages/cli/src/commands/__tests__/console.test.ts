import { describe, expect, it } from "vitest";

import {
  CONSOLE_AUTONOMY_MODES,
  resolveConsoleAutonomyMode,
} from "../console.js";

describe("resolveConsoleAutonomyMode", () => {
  it("defaults to standard when no flag is given", () => {
    // The commander option carries a "standard" default, so real invocations
    // pass autonomy:"standard"; a bare object must resolve the same way.
    expect(resolveConsoleAutonomyMode({})).toEqual({ ok: true, mode: "standard" });
    expect(resolveConsoleAutonomyMode({ autonomy: "standard" })).toEqual({
      ok: true,
      mode: "standard",
    });
  });

  it("accepts every valid --mode value", () => {
    for (const mode of CONSOLE_AUTONOMY_MODES) {
      expect(resolveConsoleAutonomyMode({ mode })).toEqual({ ok: true, mode });
    }
  });

  it("maps --yolo to autonomyMode yolo", () => {
    expect(resolveConsoleAutonomyMode({ yolo: true, autonomy: "standard" })).toEqual({
      ok: true,
      mode: "yolo",
    });
  });

  it("rejects an invalid --mode with a message listing the choices", () => {
    const result = resolveConsoleAutonomyMode({ mode: "foo" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("Invalid --mode 'foo'");
      expect(result.error).toContain("standard, recon, copilot, yolo");
    }
  });

  it("rejects an invalid --autonomy alias value", () => {
    const result = resolveConsoleAutonomyMode({ autonomy: "bogus" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("Invalid --autonomy 'bogus'");
    }
  });

  it("lets --mode win over the --autonomy alias", () => {
    expect(resolveConsoleAutonomyMode({ mode: "recon", autonomy: "copilot" })).toEqual({
      ok: true,
      mode: "recon",
    });
  });

  it("lets --yolo win over the --autonomy alias", () => {
    expect(resolveConsoleAutonomyMode({ yolo: true, autonomy: "copilot" })).toEqual({
      ok: true,
      mode: "yolo",
    });
  });

  it("allows the redundant but non-conflicting --mode yolo --yolo", () => {
    expect(resolveConsoleAutonomyMode({ mode: "yolo", yolo: true })).toEqual({
      ok: true,
      mode: "yolo",
    });
  });

  it("errors when --mode conflicts with --yolo", () => {
    const result = resolveConsoleAutonomyMode({ mode: "copilot", yolo: true });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("Conflicting flags");
    }
  });
});
