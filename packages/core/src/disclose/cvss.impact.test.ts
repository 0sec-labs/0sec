/**
 * CVSS derivation from a reachability assessment (issue: wire impactAssessment
 * into the vector).
 *
 * The guarantee under test is that this is STRICTLY ADDITIVE: a finding with no
 * `impactAssessment` produces byte-identical output to before (AV:N, UI:N,
 * PR-from-severity, source "heuristic"), while a finding that carries a real
 * assessment gets its exploitability metrics (AV/PR/UI) from the reachability
 * tier — the attack-prerequisites axis that severity + category cannot express.
 */

import { describe, it, expect } from "vitest";
import type { Finding, ImpactAssessment, ReachabilityTier } from "@0sec/shared";
import { suggestCvss } from "./cvss.js";

function mkFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "F-1",
    templateId: "t-1",
    title: "Heap overflow in parser",
    description: "…",
    severity: "high",
    category: "heap-overflow",
    status: "verified",
    evidence: { request: "", response: "", analysis: "" },
    ...overrides,
  } as Finding;
}

function assessment(tier: ReachabilityTier): ImpactAssessment {
  return {
    reachability_tier: tier,
    blast_radius: "test",
    weaponizability: "rce",
    business_impact: "notable",
    rationale: "test",
  };
}

describe("suggestCvss — additive over impactAssessment", () => {
  it("is unchanged when the finding has no assessment", () => {
    const r = suggestCvss(mkFinding());
    expect(r.source).toBe("heuristic");
    // The historic default: network vector, no UI.
    expect(r.vector).toContain("/AV:N/");
    expect(r.vector).toContain("/UI:N/");
  });

  it("still takes an agent-supplied full vector verbatim, over any assessment", () => {
    const r = suggestCvss(
      mkFinding({
        cvssVector: "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
        cvssScore: 2.4,
        impactAssessment: assessment("remote-unauth"),
      }),
    );
    expect(r.source).toBe("finding");
    expect(r.score).toBe(2.4);
  });

  it("derives AV:N/PR:N for a remote-unauth assessment", () => {
    const r = suggestCvss(mkFinding({ impactAssessment: assessment("remote-unauth") }));
    expect(r.source).toBe("impact-assessment");
    expect(r.vector).toContain("/AV:N/");
    expect(r.vector).toContain("/PR:N/");
  });

  it("derives AV:L/PR:L for a local-unpriv assessment", () => {
    const r = suggestCvss(mkFinding({ impactAssessment: assessment("local-unpriv") }));
    expect(r.vector).toContain("/AV:L/");
    expect(r.vector).toContain("/PR:L/");
  });

  it("derives AV:L/PR:H for a local-priv assessment", () => {
    const r = suggestCvss(mkFinding({ impactAssessment: assessment("local-priv") }));
    expect(r.vector).toContain("/AV:L/");
    expect(r.vector).toContain("/PR:H/");
  });

  it("derives AV:A for RF proximity (not Network)", () => {
    const r = suggestCvss(mkFinding({ impactAssessment: assessment("proximity-rf") }));
    expect(r.vector).toContain("/AV:A/");
  });

  it("derives AV:P for a hardware requirement", () => {
    const r = suggestCvss(mkFinding({ impactAssessment: assessment("needs-hardware") }));
    expect(r.vector).toContain("/AV:P/");
  });

  it("derives UI:R for a host-migration requirement", () => {
    const r = suggestCvss(mkFinding({ impactAssessment: assessment("needs-host-migration") }));
    expect(r.vector).toContain("/UI:R/");
    expect(r.vector).toContain("/AV:L/");
  });

  it("scores a remote-unauth assessment strictly above a local-priv one, same impact", () => {
    // Reachability is the whole point: same bug, worse position ⇒ higher score.
    const remote = suggestCvss(mkFinding({ impactAssessment: assessment("remote-unauth") }));
    const local = suggestCvss(mkFinding({ impactAssessment: assessment("local-priv") }));
    expect(remote.score).toBeGreaterThan(local.score);
  });

  it("keeps every derived vector a well-formed CVSS 3.1 base string", () => {
    const tiers: ReachabilityTier[] = [
      "remote-unauth", "proximity-rf", "local-unpriv",
      "local-priv", "needs-hardware", "needs-host-migration",
    ];
    for (const tier of tiers) {
      const r = suggestCvss(mkFinding({ impactAssessment: assessment(tier) }));
      expect(r.vector).toMatch(
        /^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/,
      );
      expect(r.score).toBeGreaterThan(0);
      expect(r.score).toBeLessThanOrEqual(10);
    }
  });
});
