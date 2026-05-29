/**
 * Tests for the triage layer registry.
 */

import { describe, it, expect } from "vitest";
import {
  LAYER_REGISTRY,
  LAYER_REGISTRY_BY_ID,
  DEFAULT_STATIC_LAYER_SET,
  FREE_LAYER_SET,
  EXPENSIVE_LAYER_SET,
} from "./layer-registry.js";

describe("LAYER_REGISTRY", () => {
  it("contains exactly 12 triage layers (11 from pwnkit#113 + publishability #539)", () => {
    expect(LAYER_REGISTRY).toHaveLength(12);
  });

  it("every entry has an id, name, env_flag, cost_factor, description", () => {
    for (const entry of LAYER_REGISTRY) {
      expect(typeof entry.id).toBe("string");
      expect(entry.id.length).toBeGreaterThan(0);
      expect(typeof entry.name).toBe("string");
      expect(typeof entry.env_flag).toBe("string");
      expect(typeof entry.cost_factor).toBe("number");
      expect(entry.cost_factor).toBeGreaterThanOrEqual(0);
      expect(entry.cost_factor).toBeLessThanOrEqual(1);
      expect(typeof entry.description).toBe("string");
    }
  });

  it("layer ids are unique", () => {
    const ids = LAYER_REGISTRY.map((e) => e.id);
    const set = new Set(ids);
    expect(set.size).toBe(ids.length);
  });

  it("LAYER_REGISTRY_BY_ID indexes every entry", () => {
    for (const entry of LAYER_REGISTRY) {
      expect(LAYER_REGISTRY_BY_ID[entry.id]).toBe(entry);
    }
  });

  it("DEFAULT_STATIC_LAYER_SET only references known layer ids", () => {
    for (const id of DEFAULT_STATIC_LAYER_SET) {
      expect(LAYER_REGISTRY_BY_ID[id]).toBeDefined();
    }
  });

  it("FREE_LAYER_SET layers all have cost_factor <= 0.25", () => {
    for (const id of FREE_LAYER_SET) {
      expect(LAYER_REGISTRY_BY_ID[id].cost_factor).toBeLessThanOrEqual(0.25);
    }
  });

  it("EXPENSIVE_LAYER_SET layers all have cost_factor > 0.4", () => {
    for (const id of EXPENSIVE_LAYER_SET) {
      expect(LAYER_REGISTRY_BY_ID[id].cost_factor).toBeGreaterThan(0.4);
    }
  });

  it("contains the canonical layers referenced in pwnkit#112's LayerVerdict union", () => {
    const expected = [
      "holding_it_wrong",
      "evidence_gate",
      "reachability",
      "multi_modal",
      "oracle",
      "pov_gate",
      "structured_verify",
      "consensus",
      "memories",
      "debate",
      "kernel_oracle",
    ];
    const ids = LAYER_REGISTRY.map((e) => e.id);
    for (const id of expected) {
      expect(ids).toContain(id);
    }
  });

  it("registers the publishability layer after multi_modal, before pov_gate (issue #539)", () => {
    const ids = LAYER_REGISTRY.map((e) => e.id);
    expect(ids).toContain("publishability");
    expect(ids.indexOf("publishability")).toBeGreaterThan(ids.indexOf("multi_modal"));
    expect(ids.indexOf("publishability")).toBeLessThan(ids.indexOf("pov_gate"));
    const entry = LAYER_REGISTRY_BY_ID["publishability"];
    expect(entry.env_flag).toBe("PWNKIT_FEATURE_PUBLISHABILITY_GATE");
    expect(entry.cost_factor).toBeCloseTo(0.3);
  });
});
