/**
 * Unit tests for the pure `cross_validated_leads` formatter (0sec FoxGuard
 * Phase 4). Covers ordering, capping, singular/plural + percentage rendering,
 * and — critically — fail-soft handling of malformed payloads (the formatter
 * must never throw, so a bad bus payload can never crash the scan output).
 */
import { describe, expect, it } from "vitest";
import {
  CROSS_VALIDATED_LEADS_CAP,
  formatCrossValidatedLeads,
} from "../cross-validated-leads.js";

function lead(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    findingId: "f-1",
    title: "SQL injection in login",
    severity: "high",
    confidence: 0.82,
    foxguardMatches: 3,
    ...overrides,
  };
}

describe("formatCrossValidatedLeads", () => {
  it("returns null for non-object / empty / lead-less payloads", () => {
    expect(formatCrossValidatedLeads(null)).toBeNull();
    expect(formatCrossValidatedLeads(undefined)).toBeNull();
    expect(formatCrossValidatedLeads("nope")).toBeNull();
    expect(formatCrossValidatedLeads(42)).toBeNull();
    expect(formatCrossValidatedLeads({})).toBeNull();
    expect(formatCrossValidatedLeads({ count: 0, leads: [] })).toBeNull();
  });

  it("builds a header + one line per lead with matches and confidence", () => {
    const summary = formatCrossValidatedLeads({ count: 1, leads: [lead()] });
    expect(summary).not.toBeNull();
    expect(summary!.header).toBe(
      "Cross-validated leads — 1 finding both scanners agree on (investigate first)",
    );
    expect(summary!.lines).toHaveLength(1);
    expect(summary!.lines[0]!.severity).toBe("high");
    expect(summary!.lines[0]!.text).toBe(
      "[HIGH] SQL injection in login · 3 foxguard matches · 82% confidence",
    );
    expect(summary!.moreCount).toBe(0);
  });

  it("pluralizes the header count", () => {
    const summary = formatCrossValidatedLeads({
      count: 3,
      leads: [lead(), lead({ findingId: "f-2" }), lead({ findingId: "f-3" })],
    });
    expect(summary!.header).toContain("3 findings both scanners agree on");
  });

  it("orders leads critical-first regardless of payload order", () => {
    const summary = formatCrossValidatedLeads({
      count: 3,
      leads: [
        lead({ findingId: "a", severity: "low", title: "L" }),
        lead({ findingId: "b", severity: "critical", title: "C" }),
        lead({ findingId: "c", severity: "medium", title: "M" }),
      ],
    });
    expect(summary!.lines.map((l) => l.severity)).toEqual([
      "critical",
      "medium",
      "low",
    ]);
  });

  it("caps the list and reports the overflow via moreCount", () => {
    const many = Array.from({ length: CROSS_VALIDATED_LEADS_CAP + 3 }, (_, i) =>
      lead({ findingId: `f-${i}`, title: `Finding ${i}` }),
    );
    const summary = formatCrossValidatedLeads({ count: many.length, leads: many });
    expect(summary!.lines).toHaveLength(CROSS_VALIDATED_LEADS_CAP);
    expect(summary!.moreCount).toBe(3);
  });

  it("honors an explicit cap argument", () => {
    const many = Array.from({ length: 5 }, (_, i) =>
      lead({ findingId: `f-${i}` }),
    );
    const summary = formatCrossValidatedLeads({ count: 5, leads: many }, 2);
    expect(summary!.lines).toHaveLength(2);
    expect(summary!.moreCount).toBe(3);
  });

  it("uses singular 'match' for exactly one foxguard match", () => {
    const summary = formatCrossValidatedLeads({
      count: 1,
      leads: [lead({ foxguardMatches: 1 })],
    });
    expect(summary!.lines[0]!.text).toContain("1 foxguard match ·");
    expect(summary!.lines[0]!.text).not.toContain("1 foxguard matches");
  });

  it("is fail-soft: omits missing fields, defaults title + severity, never throws", () => {
    const summary = formatCrossValidatedLeads({
      // count missing → falls back to lead count
      leads: [
        { findingId: "x" }, // no title / severity / confidence / matches
        { findingId: "y", title: "  ", severity: 123, confidence: "high", foxguardMatches: "lots" },
      ],
    });
    expect(summary).not.toBeNull();
    expect(summary!.header).toContain("2 findings");
    // Neither entry carries matches/confidence, so the line is just the tag+title.
    expect(summary!.lines[0]!.text).toBe("[UNKNOWN] (untitled finding)");
    expect(summary!.lines[1]!.text).toBe("[UNKNOWN] (untitled finding)");
  });

  it("clamps confidence into 0-100%", () => {
    const summary = formatCrossValidatedLeads({
      count: 2,
      leads: [
        lead({ findingId: "hi", confidence: 1.5 }),
        lead({ findingId: "lo", confidence: -0.2 }),
      ],
    });
    expect(summary!.lines[0]!.text).toContain("100% confidence");
    expect(summary!.lines[1]!.text).toContain("0% confidence");
  });

  it("drops malformed (non-object) lead entries", () => {
    const summary = formatCrossValidatedLeads({
      count: 1,
      leads: [null, "bad", 7, lead()],
    });
    expect(summary!.lines).toHaveLength(1);
    expect(summary!.lines[0]!.severity).toBe("high");
  });
});
