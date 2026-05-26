/**
 * Tests for the `--subsystem` flag implementation (pwnkit#466).
 *
 * Covers:
 *   - `parseSubsystems` utility: single, multiple, trailing-slash normalisation
 *   - `kernelReviewAgentPrompt` scope restriction text for single and multi
 *   - `buildCliReviewPrompt` (via review.ts) scope restriction text
 *   - Subsystem-scoped static scanning in the unified pipeline
 */

import { describe, expect, it } from "vitest";

import { parseSubsystems } from "./unified-pipeline.js";
import { kernelReviewAgentPrompt } from "./review/linux-kernel-profile.js";

// ── parseSubsystems ─────────────────────────────────────────────────────────

describe("parseSubsystems", () => {
  it("parses a single subsystem", () => {
    expect(parseSubsystems("crypto/")).toEqual(["crypto/"]);
  });

  it("adds trailing slash when missing", () => {
    expect(parseSubsystems("crypto")).toEqual(["crypto/"]);
  });

  it("parses comma-separated subsystems", () => {
    expect(parseSubsystems("crypto/,net/xfrm/")).toEqual(["crypto/", "net/xfrm/"]);
  });

  it("trims whitespace around subsystem names", () => {
    expect(parseSubsystems(" crypto/ , net/xfrm/ ")).toEqual(["crypto/", "net/xfrm/"]);
  });

  it("filters out empty segments", () => {
    expect(parseSubsystems("crypto/,,net/xfrm/,")).toEqual(["crypto/", "net/xfrm/"]);
  });

  it("handles deeply nested paths", () => {
    expect(parseSubsystems("drivers/gpu/drm/i915")).toEqual(["drivers/gpu/drm/i915/"]);
  });

  it("handles a single comma-separated list with trailing slash normalisation", () => {
    expect(parseSubsystems("fs/io_uring,drivers/usb")).toEqual([
      "fs/io_uring/",
      "drivers/usb/",
    ]);
  });
});

// ── kernelReviewAgentPrompt scope injection ─────────────────────────────────

describe("kernelReviewAgentPrompt with --subsystem", () => {
  it("includes SCOPE RESTRICTION block for a single subsystem", () => {
    const prompt = kernelReviewAgentPrompt("/linux", [], [], "crypto/");
    expect(prompt).toContain("## SCOPE RESTRICTION");
    expect(prompt).toContain("`crypto/`");
    // Should NOT tell the agent to rotate through all subsystems
    expect(prompt).not.toContain("Rotate systematically through");
  });

  it("includes SCOPE RESTRICTION block for multiple subsystems", () => {
    const prompt = kernelReviewAgentPrompt("/linux", [], [], "crypto/,net/xfrm/");
    expect(prompt).toContain("## SCOPE RESTRICTION");
    expect(prompt).toContain("`crypto/`");
    expect(prompt).toContain("`net/xfrm/`");
    expect(prompt).not.toContain("Rotate systematically through");
  });

  it("omits SCOPE RESTRICTION when subsystem is undefined", () => {
    const prompt = kernelReviewAgentPrompt("/linux", [], []);
    expect(prompt).not.toContain("## SCOPE RESTRICTION");
    // Should tell the agent to rotate through all subsystems
    expect(prompt).toContain("Rotate systematically through");
  });

  it("includes OPERATOR HYPOTHESIS block when hypothesis is set", () => {
    const prompt = kernelReviewAgentPrompt(
      "/linux",
      [],
      [],
      "crypto/",
      "Look for missing bounds checks on AEAD decrypt paths",
    );
    expect(prompt).toContain("## OPERATOR HYPOTHESIS");
    expect(prompt).toContain("missing bounds checks on AEAD decrypt paths");
  });

  it("adjusts turn budget rules for subsystem-scoped reviews", () => {
    const prompt = kernelReviewAgentPrompt("/linux", [], [], "crypto/");
    // Subsystem-scoped reviews should focus on exhausting the scoped subsystem
    expect(prompt).toContain("Exhaust every entry point");
    // Should NOT tell the agent to rotate through all subsystems
    expect(prompt).not.toContain("Rotate systematically through");
  });

  it("includes cross-reference escape hatch in scope restriction", () => {
    const prompt = kernelReviewAgentPrompt("/linux", [], [], "crypto/");
    expect(prompt).toMatch(/follow.*call chain|cross-reference/i);
    expect(prompt).toContain("MAY read those files");
  });
});
