import { describe, it, expect, afterEach } from "vitest";
import {
  FEATURE_PRESETS,
  applyFeaturePreset,
  applyFeaturePresetFromEnv,
  resolveFeaturePreset,
} from "./feature-presets.js";
import { features } from "./features.js";

describe("feature presets — fp-moat membership", () => {
  /**
   * Pins the exact flag set. This is the whole value of the preset: an A/B
   * result is only citable if the enabled set is written down and stable, so a
   * change to membership must be a deliberate, reviewed diff rather than an
   * incidental edit.
   */
  it("enables exactly the six opt-in FP-moat flags", () => {
    expect([...FEATURE_PRESETS["fp-moat"]].sort()).toEqual([
      "0SEC_FEATURE_CONSENSUS_VERIFY",
      "0SEC_FEATURE_MULTIMODAL",
      "0SEC_FEATURE_POC_GEN_STATIC",
      "0SEC_FEATURE_POV_GATE",
      "0SEC_FEATURE_PUBLISHABILITY_GATE",
      "0SEC_FEATURE_REACHABILITY_GATE",
    ]);
  });

  /**
   * The routers decide which layers to SKIP. Enabling them inside the moat
   * preset would let the router suppress the very layers the A/B measures, so
   * their absence is a correctness property, not an omission.
   */
  it("excludes the triage routers and inline validation", () => {
    const flags = FEATURE_PRESETS["fp-moat"];
    expect(flags).not.toContain("0SEC_FEATURE_LEARNED_ROUTER");
    expect(flags).not.toContain("0SEC_FEATURE_DYNAMIC_TRIAGE");
    expect(flags).not.toContain("0SEC_FEATURE_INLINE_VALIDATION");
  });

  /** The always-on filters already run; including them would overstate the preset. */
  it("excludes the always-on filters", () => {
    const flags = FEATURE_PRESETS["fp-moat"];
    expect(flags).not.toContain("0SEC_FEATURE_HOLDING_IT_WRONG");
    expect(flags).not.toContain("0SEC_FEATURE_EVIDENCE_GATE");
  });

  /**
   * `egats` is the one layer our own ablation measured as genuinely broken
   * (2 -> 1 flags at 10x the worst per-flag cost on stubborn-14; removed from
   * the default aliases in 0sec#116). Its flag no longer exists in the
   * codebase, and the preset must never resurrect it — an A/B arm containing a
   * known-regressing layer would invalidate the comparison.
   */
  it("never enables the measured-broken egats layer", () => {
    for (const flag of FEATURE_PRESETS["fp-moat"]) {
      expect(flag).not.toMatch(/EGATS/i);
    }
  });
});

describe("feature presets — application", () => {
  it("sets every flag to '1' on a clean env", () => {
    const env: NodeJS.ProcessEnv = {};
    const result = applyFeaturePreset("fp-moat", env);

    expect(result.applied).toHaveLength(6);
    expect(result.preserved).toHaveLength(0);
    for (const flag of FEATURE_PRESETS["fp-moat"]) {
      expect(env[flag]).toBe("1");
    }
  });

  /**
   * The per-layer ablation guarantee. An operator disabling one layer while
   * running the preset must get "moat minus that layer" — if the preset
   * overrode them, attributing an effect to a single layer would be
   * impossible.
   */
  it("never overwrites an explicitly-set flag, including '0'", () => {
    const env: NodeJS.ProcessEnv = { "0SEC_FEATURE_POV_GATE": "0" };
    const result = applyFeaturePreset("fp-moat", env);

    expect(env["0SEC_FEATURE_POV_GATE"]).toBe("0");
    expect(result.preserved).toEqual(["0SEC_FEATURE_POV_GATE"]);
    expect(result.applied).not.toContain("0SEC_FEATURE_POV_GATE");
    // Every other layer still came on.
    expect(env["0SEC_FEATURE_REACHABILITY_GATE"]).toBe("1");
    expect(result.applied).toHaveLength(5);
  });

  it("is idempotent — a second application changes nothing", () => {
    const env: NodeJS.ProcessEnv = {};
    applyFeaturePreset("fp-moat", env);
    const second = applyFeaturePreset("fp-moat", env);

    expect(second.applied).toHaveLength(0);
    expect(second.preserved).toHaveLength(6);
  });

  it("does not touch flags outside the preset", () => {
    const env: NodeJS.ProcessEnv = {};
    applyFeaturePreset("fp-moat", env);
    expect(env["0SEC_FEATURE_WEB_SEARCH"]).toBeUndefined();
    expect(env["0SEC_FEATURE_DYNAMIC_TRIAGE"]).toBeUndefined();
  });
});

describe("feature presets — token resolution", () => {
  it("accepts hyphen, underscore, bare and short spellings", () => {
    for (const token of ["fp-moat", "fp_moat", "fpmoat", "moat", "FP-MOAT", " Moat "]) {
      expect(resolveFeaturePreset(token)).toBe("fp-moat");
    }
  });

  it("returns undefined for a non-preset token so it falls through to a plain flag", () => {
    expect(resolveFeaturePreset("wp_fingerprint")).toBeUndefined();
    expect(resolveFeaturePreset("")).toBeUndefined();
  });
});

describe("0SEC_FEATURE_PRESET is honoured by the feature flags themselves", () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  /**
   * The whole-engine wiring. Setting one variable must flip the moat flags for
   * ANY entry point that reads `features.*` — not just the CLI. If this
   * regresses, a CI A/B run would silently measure the default arm twice.
   */
  it("turns on every moat layer from the single preset variable", () => {
    expect(features.povGate).toBe(false);
    expect(features.reachabilityGate).toBe(false);

    process.env["0SEC_FEATURE_PRESET"] = "fp-moat";

    expect(features.povGate).toBe(true);
    expect(features.reachabilityGate).toBe(true);
    expect(features.multiModalAgreement).toBe(true);
    expect(features.publishabilityGate).toBe(true);
    expect(features.pocGenStatic).toBe(true);
    expect(features.selfConsistencyVerify).toBe(true);
  });

  /** An explicit `0` beats the preset — this is the per-layer ablation path. */
  it("lets an explicit flag override the preset in both directions", () => {
    process.env["0SEC_FEATURE_PRESET"] = "fp-moat";
    process.env["0SEC_FEATURE_POV_GATE"] = "0";

    expect(features.povGate).toBe(false);
    expect(features.reachabilityGate).toBe(true);
  });

  it("leaves flags outside the preset at their own defaults", () => {
    process.env["0SEC_FEATURE_PRESET"] = "fp-moat";

    // Routers are excluded so they cannot skip the layers being measured.
    expect(features.learnedRouter).toBe(false);
    expect(features.dynamicTriageRouting).toBe(false);
    expect(features.inlineValidation).toBe(false);
    // Unrelated experimental flags are untouched.
    expect(features.webSearch).toBe(false);
    // Always-on flags stay on.
    expect(features.holdingItWrong).toBe(true);
  });

  it("ignores an unrecognized preset name rather than failing the scan", () => {
    process.env["0SEC_FEATURE_PRESET"] = "not-a-preset";
    expect(features.povGate).toBe(false);
    expect(features.holdingItWrong).toBe(true);
  });
});

describe("feature presets — env-driven application", () => {
  it("applies the preset named by 0SEC_FEATURE_PRESET", () => {
    const env: NodeJS.ProcessEnv = { "0SEC_FEATURE_PRESET": "fp-moat" };
    const result = applyFeaturePresetFromEnv(env);

    expect(result?.preset).toBe("fp-moat");
    expect(env["0SEC_FEATURE_POV_GATE"]).toBe("1");
  });

  /**
   * A stale or misspelled CI variable degrades to default behaviour rather
   * than failing the run — a scan that still produces findings under the
   * documented default is strictly better than a hard stop.
   */
  it("ignores an unset or unrecognized preset name without throwing", () => {
    expect(applyFeaturePresetFromEnv({})).toBeUndefined();

    const env: NodeJS.ProcessEnv = { "0SEC_FEATURE_PRESET": "not-a-preset" };
    expect(applyFeaturePresetFromEnv(env)).toBeUndefined();
    expect(env["0SEC_FEATURE_POV_GATE"]).toBeUndefined();
  });
});
