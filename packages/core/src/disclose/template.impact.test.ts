/**
 * Advisory Impact + attack-prerequisites section (impactAssessment wiring).
 *
 * Rendered only when the finding carries an assessment, so an unassessed
 * advisory is byte-identical to before. When present, it must surface the two
 * facts a vendor triager acts on: what the attacker gains and how they must be
 * positioned.
 */

import { describe, it, expect } from "vitest";
import type { Finding, ImpactAssessment } from "@0sec/shared";
import { renderAdvisoryMarkdown } from "./template.js";

function mkFinding(assessment?: ImpactAssessment): Finding {
  return {
    id: "F-1",
    templateId: "t-1",
    title: "SSRF in webhook fetcher",
    description: "The url parameter is fetched server-side without allow-listing.",
    severity: "high",
    category: "ssrf",
    status: "verified",
    evidence: {
      request: "POST /webhook {\"url\":\"http://169.254.169.254/\"}",
      response: "200 OK (metadata returned)",
      analysis: "reproduced",
    },
    ...(assessment ? { impactAssessment: assessment } : {}),
  } as Finding;
}

const REMOTE: ImpactAssessment = {
  reachability_tier: "remote-unauth",
  blast_radius: "every tenant on the shared egress path",
  weaponizability: "info-leak",
  business_impact: "headline",
  rationale: "Cloud metadata is reachable and unauthenticated.",
};

describe("renderAdvisoryMarkdown — Impact section", () => {
  it("omits the Impact section entirely when there is no assessment", () => {
    const { markdown } = renderAdvisoryMarkdown(mkFinding());
    expect(markdown).not.toContain("# Impact");
    // The historic sections are still all present.
    expect(markdown).toContain("# Severity");
    expect(markdown).toContain("# Affected versions");
  });

  it("renders attacker-gain and attack-prerequisites when assessed", () => {
    const { markdown } = renderAdvisoryMarkdown(mkFinding(REMOTE));
    expect(markdown).toContain("# Impact");
    expect(markdown).toContain("Attacker gains:");
    expect(markdown).toContain("information disclosure");
    expect(markdown).toContain("Attack prerequisites:");
    expect(markdown).toContain("remote, unauthenticated");
    expect(markdown).toContain("every tenant on the shared egress path");
  });

  it("labels the CVSS source as assessment-derived when assessed", () => {
    const { markdown } = renderAdvisoryMarkdown(mkFinding(REMOTE));
    expect(markdown).toContain("reachability assessment");
  });

  it("still exposes the derived vector on the returned advisory", () => {
    const advisory = renderAdvisoryMarkdown(mkFinding(REMOTE));
    // remote-unauth ⇒ AV:N in the derived vector.
    expect(advisory.cvssVector).toContain("/AV:N/");
    expect(advisory.cvssScore).toBeGreaterThan(0);
  });
});
