import { describe, it, expect } from "vitest";
import { compareVersions } from "./update-check.js";

describe("compareVersions", () => {
  it("equal versions return 0", () => {
    expect(compareVersions("0.10.0", "0.10.0")).toBe(0);
    expect(compareVersions("v0.10.0", "0.10.0")).toBe(0);
  });

  it("major bump: 1.0.0 > 0.99.99", () => {
    expect(compareVersions("1.0.0", "0.99.99")).toBeGreaterThan(0);
  });

  it("minor bump: 0.10.0 > 0.9.0 (lexicographic trap)", () => {
    // The lexicographic-string trap that breaks naive `a > b` checks.
    expect(compareVersions("0.10.0", "0.9.0")).toBeGreaterThan(0);
    expect(compareVersions("0.9.0", "0.10.0")).toBeLessThan(0);
  });

  it("patch bump: 0.9.1 > 0.9.0", () => {
    expect(compareVersions("0.9.1", "0.9.0")).toBeGreaterThan(0);
  });

  it("strips leading v prefix from either side", () => {
    expect(compareVersions("v0.10.0", "v0.9.0")).toBeGreaterThan(0);
    expect(compareVersions("v0.10.0", "0.9.0")).toBeGreaterThan(0);
    expect(compareVersions("0.10.0", "v0.9.0")).toBeGreaterThan(0);
  });

  it("ignores pre-release tags after the first hyphen", () => {
    // We don't want pre-releases (e.g. "0.10.0-rc.1") to fool the
    // notifier into bouncing forever. Treat the base release as
    // canonical.
    expect(compareVersions("0.10.0-rc.1", "0.10.0")).toBe(0);
    expect(compareVersions("0.10.0", "0.10.0-rc.1")).toBe(0);
  });

  it("missing patch defaults to 0", () => {
    expect(compareVersions("0.10", "0.10.0")).toBe(0);
    expect(compareVersions("1", "0.99.99")).toBeGreaterThan(0);
  });

  it("non-numeric segments coerce to 0 (be permissive on garbage)", () => {
    // `parseInt("abc", 10)` yields NaN → coerced to 0.
    expect(compareVersions("0.abc.0", "0.0.0")).toBe(0);
  });
});
