import { describe, expect, it } from "vitest";

import {
  CONSOLE_AUTONOMY_MODES,
  resolveConsoleAutonomyMode,
} from "../console.js";

describe("resolveConsoleAutonomyMode", () => {
  it("defaults to yolo when no flag is given", () => {
    // The commander option no longer carries a default; the resolver
    // fallback is the shared constant.
    expect(resolveConsoleAutonomyMode({})).toEqual({ ok: true, mode: "yolo" });
    expect(resolveConsoleAutonomyMode({ autonomy: "yolo" })).toEqual({
      ok: true,
      mode: "yolo",
    });
  });

  it("accepts every valid --mode value", () => {
    for (const mode of CONSOLE_AUTONOMY_MODES) {
      expect(resolveConsoleAutonomyMode({ mode })).toEqual({ ok: true, mode });
    }
  });

  it("maps --yolo to autonomyMode yolo", () => {
    expect(resolveConsoleAutonomyMode({ yolo: true, autonomy: "recon" })).toEqual({
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
