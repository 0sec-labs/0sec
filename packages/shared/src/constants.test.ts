import { describe, it, expect } from "vitest";
import {
  DEFAULT_SEVERITY_FLOOR,
  SEVERITY_RANK,
  severityRank,
  meetsSeverityFloor,
} from "./constants.js";

// The shared severity floor (#582) gates below-medium findings out of the
// engine's disclosure funnel. This is the single source of truth the
// `disclose` command compares against.

describe("severity floor (engine)", () => {
  it("defaults to medium", () => {
    expect(DEFAULT_SEVERITY_FLOOR).toBe("medium");
  });

  it("ranks ascending (info lowest, critical highest)", () => {
    expect(SEVERITY_RANK.info).toBeLessThan(SEVERITY_RANK.medium);
    expect(SEVERITY_RANK.medium).toBeLessThan(SEVERITY_RANK.critical);
  });

  it("ranks the informational alias as info, unknowns below info", () => {
    expect(severityRank("informational")).toBe(SEVERITY_RANK.info);
    expect(severityRank("INFO")).toBe(SEVERITY_RANK.info);
    expect(severityRank("bogus")).toBe(-1);
  });

  it("gates low/info out under the default floor and admits medium+", () => {
    expect(meetsSeverityFloor("info")).toBe(false);
    expect(meetsSeverityFloor("low")).toBe(false);
    expect(meetsSeverityFloor("medium")).toBe(true);
    expect(meetsSeverityFloor("critical")).toBe(true);
  });

  it("respects a configurable floor and falls back for unknown floors", () => {
    expect(meetsSeverityFloor("low", "low")).toBe(true);
    expect(meetsSeverityFloor("medium", "high")).toBe(false);
    // Unknown floor → default (medium).
    expect(meetsSeverityFloor("low", "bogus")).toBe(false);
    expect(meetsSeverityFloor("high", "bogus")).toBe(true);
  });
});
