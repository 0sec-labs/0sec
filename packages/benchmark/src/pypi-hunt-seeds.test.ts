import { describe, expect, it } from "vitest";
import {
  PYPI_HUNT_SEED_CATEGORIES,
  PYPI_HUNT_SEEDS,
  pypiHuntSeedsCsv,
} from "./pypi-hunt-seeds.js";

describe("PYPI_HUNT_SEED_CATEGORIES", () => {
  it("defines multiple security-relevant categories", () => {
    expect(PYPI_HUNT_SEED_CATEGORIES.length).toBeGreaterThanOrEqual(5);
    for (const category of PYPI_HUNT_SEED_CATEGORIES) {
      expect(category.id.length).toBeGreaterThan(0);
      expect(category.label.length).toBeGreaterThan(0);
      expect(category.rationale.length).toBeGreaterThan(0);
      expect(category.packages.length).toBeGreaterThan(0);
    }
  });

  it("produces a de-duplicated flat seed list", () => {
    expect(PYPI_HUNT_SEEDS.length).toBeGreaterThanOrEqual(24);
    expect(new Set(PYPI_HUNT_SEEDS).size).toBe(PYPI_HUNT_SEEDS.length);
  });

  it("keeps package names normalized for workflow dispatch input", () => {
    for (const pkg of PYPI_HUNT_SEEDS) {
      expect(pkg).toBe(pkg.trim());
      expect(pkg).toBe(pkg.toLowerCase());
      expect(pkg).not.toContain(" ");
    }
  });

  it("renders a comma-separated workflow input string", () => {
    const csv = pypiHuntSeedsCsv();
    expect(csv.split(",")).toEqual(PYPI_HUNT_SEEDS);
  });
});
