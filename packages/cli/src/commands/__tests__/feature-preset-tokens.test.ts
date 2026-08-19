/**
 * Anti-drift pin between the CLI's preset-token set and core's resolver.
 *
 * `scan.ts` recognises preset tokens from a local literal so it does not have
 * to import core just to parse `--features`. That duplication is safe only if
 * both sides agree, and the failure mode if they don't is silent: an
 * unrecognised token becomes a meaningless `0SEC_FEATURE_*` var and enables
 * nothing, while the run still succeeds and reports findings. This test makes
 * that divergence loud.
 *
 * Deliberately does NOT mock `@0sec/core` — the point is to check the CLI
 * against the real resolver.
 */

import { describe, it, expect } from "vitest";
import { resolveFeaturePreset, FEATURE_PRESETS } from "@0sec/core";
import { PRESET_TOKENS } from "../scan.js";

describe("CLI preset tokens match core's resolver", () => {
  it("every CLI preset token resolves to a real preset in core", () => {
    for (const token of PRESET_TOKENS) {
      const resolved = resolveFeaturePreset(token);
      expect(resolved, `token '${token}' does not resolve in core`).toBeDefined();
      expect(FEATURE_PRESETS[resolved!]).toBeDefined();
    }
  });

  it("covers the fp-moat preset, the one the docs tell operators to use", () => {
    expect(PRESET_TOKENS.has("fp-moat")).toBe(true);
    expect(resolveFeaturePreset("fp-moat")).toBe("fp-moat");
  });

  it("does not claim ordinary feature flags as presets", () => {
    expect(PRESET_TOKENS.has("wp_fingerprint")).toBe(false);
    expect(PRESET_TOKENS.has("web_search")).toBe(false);
  });
});
