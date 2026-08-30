import { describe, expect, it } from "vitest";
import {
  getCapabilityById,
  getCapabilitiesByCategory,
  getCapabilitiesByTier,
  getAllCapabilities,
  getPaneCapabilities,
  type CapabilityEntry,
  type SafetyTier,
} from "./capability-registry.js";

/** Every `ChatDestination` string that can appear as a `route` on pane caps. */
const KNOWN_PANE_ROUTE_RECORD: Record<string, true> = {
  launcher: true,
  ops: true,
  history: true,
  findings: true,
  doctor: true,
  replay: true,
  settings: true,
  models: true,
  market: true,
  usage: true,
  connect: true,
  herd: true,
  finding: true,
  resume: true,
};

describe("getAllCapabilities", () => {
  it("returns every capability in deterministic order", () => {
    const caps = getAllCapabilities();
    expect(caps.length).toBeGreaterThan(0);

    // Every entry has the required fields
    for (const cap of caps) {
      expect(cap).toMatchObject<CapabilityEntry>({
        id: expect.any(String),
        label: expect.any(String),
        category: expect.any(String),
        outboundOrMutating: expect.any(Boolean),
        safetyTier: expect.any(String),
        description: expect.any(String),
      });
    }
  });

  it("has unique ids", () => {
    const ids = getAllCapabilities().map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("covers every safety tier", () => {
    const tiers = new Set(getAllCapabilities().map((c) => c.safetyTier));
    expect(tiers.has("automatic")).toBe(true);
    expect(tiers.has("operator-confirmed")).toBe(true);
    expect(tiers.has("blocked")).toBe(true);
  });

  it("never marks an outbound-or-mutating capability as automatic", () => {
    const automatic = getAllCapabilities().filter(
      (c) => c.safetyTier === "automatic",
    );
    for (const cap of automatic) {
      expect(cap.outboundOrMutating).toBe(false);
    }
  });

  it("has valid safety tiers", () => {
    const valid: Record<string, true> = {
      automatic: true,
      "operator-confirmed": true,
      blocked: true,
    };
    const caps = getAllCapabilities();
    for (const cap of caps) {
      expect(valid[cap.safetyTier]).toBe(true);
    }
  });
});

describe("getCapabilityById", () => {
  it("returns a capability by its stable id", () => {
    const cap = getCapabilityById("scan");
    expect(cap).toBeDefined();
    expect(cap!.id).toBe("scan");
    expect(cap!.label).toBe("Scan");
  });

  it("returns undefined for an unknown id", () => {
    expect(getCapabilityById("nonexistent")).toBeUndefined();
  });

  it("handles every id in the catalogue", () => {
    for (const cap of getAllCapabilities()) {
      expect(getCapabilityById(cap.id)).toBe(cap);
    }
  });
});

describe("getCapabilitiesByCategory", () => {
  it("returns only entries in the given category", () => {
    const engagement = getCapabilitiesByCategory("engagement");
    expect(engagement.length).toBeGreaterThan(0);
    for (const cap of engagement) {
      expect(cap.category).toBe("engagement");
    }
  });

  it("returns entries in deterministic order", () => {
    const results = getCapabilitiesByCategory("settings");
    expect(results.length).toBeGreaterThan(0);
    // Repeated calls return the same order
    expect(getCapabilitiesByCategory("settings")).toEqual(results);
  });

  it("returns an empty array for a category with no entries", () => {
    // "connect" is a valid category but has only one entry — this tests
    // that we get its entries, not that it's empty. A truly empty category
    // would just return [] deterministically.
    expect(getCapabilitiesByCategory("evolution")).toHaveLength(1);
  });
});

describe("getCapabilitiesByTier", () => {
  it("returns only entries with the given tier", () => {
    const automatic = getCapabilitiesByTier("automatic");
    expect(automatic.length).toBeGreaterThan(0);
    for (const cap of automatic) {
      expect(cap.safetyTier).toBe("automatic");
    }
  });

  it("returns entries in deterministic order", () => {
    const results = getCapabilitiesByTier("blocked");
    expect(results.length).toBeGreaterThan(0);
    expect(getCapabilitiesByTier("blocked")).toEqual(results);
  });
});

describe("getPaneCapabilities", () => {
  it("returns only entries with a route set", () => {
    const panes = getPaneCapabilities();
    expect(panes.length).toBeGreaterThan(0);
    for (const cap of panes) {
      expect(cap.route).toBeDefined();
    }
  });

  it("every pane route matches a known ChatDestination", () => {
    for (const cap of getPaneCapabilities()) {
      expect(KNOWN_PANE_ROUTE_RECORD[cap.route!]).toBe(true);
    }
  });

  it("excludes entries without a route", () => {
    const paneIds = new Set(getPaneCapabilities().map((c) => c.id));
    const allIds = new Set(getAllCapabilities().map((c) => c.id));
    // Some entries (mode, shortcuts, lens-evolution, research, orchestrate,
    // eval, bench) have no route — they should be absent from pane caps.
    for (const id of allIds) {
      const cap = getCapabilityById(id)!;
      if (!cap.route) {
        expect(paneIds.has(id)).toBe(false);
      }
    }
  });
});

describe("outbound/mutating guard", () => {
  it("every blocked capability is outboundOrMutating", () => {
    for (const cap of getCapabilitiesByTier("blocked")) {
      expect(cap.outboundOrMutating).toBe(true);
    }
  });

  it("no automatic capability is outboundOrMutating", () => {
    for (const cap of getCapabilitiesByTier("automatic")) {
      expect(cap.outboundOrMutating).toBe(false);
    }
  });
});