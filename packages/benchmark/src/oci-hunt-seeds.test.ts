import { describe, expect, it } from "vitest";
import {
  OCI_HUNT_SEED_CATEGORIES,
  OCI_HUNT_SEEDS,
  ociHuntSeedsCsv,
} from "./oci-hunt-seeds.js";

describe("OCI_HUNT_SEED_CATEGORIES", () => {
  it("defines multiple image categories", () => {
    expect(OCI_HUNT_SEED_CATEGORIES.length).toBeGreaterThanOrEqual(4);
    for (const category of OCI_HUNT_SEED_CATEGORIES) {
      expect(category.id.length).toBeGreaterThan(0);
      expect(category.label.length).toBeGreaterThan(0);
      expect(category.rationale.length).toBeGreaterThan(0);
      expect(category.images.length).toBeGreaterThan(0);
    }
  });

  it("produces a de-duplicated flat seed list", () => {
    expect(OCI_HUNT_SEEDS.length).toBeGreaterThanOrEqual(12);
    expect(new Set(OCI_HUNT_SEEDS).size).toBe(OCI_HUNT_SEEDS.length);
  });

  it("keeps image refs normalized for workflow input", () => {
    for (const image of OCI_HUNT_SEEDS) {
      expect(image).toBe(image.trim());
      expect(image).not.toContain(" ");
      expect(image).toContain(":");
    }
  });

  it("renders a comma-separated workflow input string", () => {
    const csv = ociHuntSeedsCsv();
    expect(csv.split(",")).toEqual(OCI_HUNT_SEEDS);
  });
});
