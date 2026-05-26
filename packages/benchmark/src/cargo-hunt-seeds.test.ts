import { describe, expect, it } from "vitest";
import {
  CARGO_HUNT_SEED_CATEGORIES,
  CARGO_HUNT_SEEDS,
  cargoHuntSeedsCsv,
} from "./cargo-hunt-seeds.js";

describe("CARGO_HUNT_SEED_CATEGORIES", () => {
  it("defines multiple security-relevant categories", () => {
    expect(CARGO_HUNT_SEED_CATEGORIES.length).toBeGreaterThanOrEqual(5);
    for (const category of CARGO_HUNT_SEED_CATEGORIES) {
      expect(category.id.length).toBeGreaterThan(0);
      expect(category.label.length).toBeGreaterThan(0);
      expect(category.rationale.length).toBeGreaterThan(0);
      expect(category.crates.length).toBeGreaterThan(0);
    }
  });

  it("produces a de-duplicated flat seed list", () => {
    expect(CARGO_HUNT_SEEDS.length).toBeGreaterThanOrEqual(24);
    expect(new Set(CARGO_HUNT_SEEDS).size).toBe(CARGO_HUNT_SEEDS.length);
  });

  it("keeps crate names normalized for workflow dispatch input", () => {
    for (const crate of CARGO_HUNT_SEEDS) {
      expect(crate).toBe(crate.trim());
      expect(crate).toBe(crate.toLowerCase());
      expect(crate).not.toContain(" ");
    }
  });

  it("renders a comma-separated workflow input string", () => {
    const csv = cargoHuntSeedsCsv();
    expect(csv.split(",")).toEqual(CARGO_HUNT_SEEDS);
  });
});
