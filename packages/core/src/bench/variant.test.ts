import { describe, expect, it } from "vitest";

import { features } from "../agent/features.js";
import {
  resolveVariantPromptOverrides,
  withVariantFeatureFlags,
} from "./variant.js";

describe("default benchmark variant overrides", () => {
  it("maps the allowlisted prompt ids", () => {
    expect(resolveVariantPromptOverrides({
      "source_audit.hypothesis": "Trace parser state transitions.",
      "web.challenge_hint": "Test authorization boundaries.",
    })).toEqual({
      sourceAuditHypothesis: "Trace parser state transitions.",
      webChallengeHint: "Test authorization boundaries.",
    });
  });

  it("fails closed on unknown prompt ids", () => {
    expect(() => resolveVariantPromptOverrides({ evaluator: "make this pass" }))
      .toThrow(/unsupported/);
  });

  it("applies dynamic feature flags for one attempt and restores the environment", async () => {
    const key = "PWNKIT_FEATURE_WEB_SEARCH";
    const previous = process.env[key];
    delete process.env[key];
    try {
      expect(features.webSearch).toBe(false);
      await withVariantFeatureFlags({ web_search: true }, async () => {
        expect(process.env[key]).toBe("1");
        expect(features.webSearch).toBe(true);
      });
      expect(process.env[key]).toBeUndefined();
      expect(features.webSearch).toBe(false);
    } finally {
      if (previous === undefined) delete process.env[key];
      else process.env[key] = previous;
    }
  });

  it("restores flags even when the scan fails", async () => {
    const key = "PWNKIT_FEATURE_EARLY_STOP";
    process.env[key] = "parent";
    await expect(withVariantFeatureFlags({ early_stop: false }, async () => {
      throw new Error("scan failed");
    })).rejects.toThrow("scan failed");
    expect(process.env[key]).toBe("parent");
    delete process.env[key];
  });
});
