import { describe, expect, it } from "vitest";

import { features } from "../agent/features.js";
import {
  resolveVariantPromptOverrides,
  snapshotBenchVariant,
  withVariantFeatureFlags,
} from "./variant.js";

describe("default benchmark variant overrides", () => {
  it("validates, sorts, and deeply freezes execution descriptors", () => {
    const snapshot = snapshotBenchVariant({
      id: "challenger",
      promptOverrides: {
        "web.challenge_hint": "Test authorization boundaries.",
        "source_audit.hypothesis": "Trace parser state transitions.",
      },
      featureFlags: { web_search: true, early_stop: false },
    });
    expect(Object.keys(snapshot.promptOverrides!)).toEqual([
      "source_audit.hypothesis",
      "web.challenge_hint",
    ]);
    expect(Object.keys(snapshot.featureFlags!)).toEqual(["early_stop", "web_search"]);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.promptOverrides)).toBe(true);
    expect(Object.isFrozen(snapshot.featureFlags)).toBe(true);
  });

  it("fails closed on unknown fields and invalid execution settings", () => {
    expect(() => snapshotBenchVariant({ id: "challenger", evaluator: "pass" } as never))
      .toThrow(/unsupported bench variant field/);
    expect(() => snapshotBenchVariant({ id: "challenger", model: " padded " }))
      .toThrow(/model/);
    expect(() => snapshotBenchVariant({ id: "challenger", costCeilingUsdPerAttempt: 0 }))
      .toThrow(/cost ceiling/);
  });

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
    const key = "0SEC_FEATURE_WEB_SEARCH";
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
    const key = "0SEC_FEATURE_EARLY_STOP";
    process.env[key] = "parent";
    await expect(withVariantFeatureFlags({ early_stop: false }, async () => {
      throw new Error("scan failed");
    })).rejects.toThrow("scan failed");
    expect(process.env[key]).toBe("parent");
    delete process.env[key];
  });
});
