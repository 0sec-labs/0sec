/**
 * Platform report templates (HackerOne / Bugcrowd / Intigriti / Immunefi /
 * generic). Each template must render a real finding without throwing, contain
 * its platform's required sections, redact secrets from PoC content, and enforce
 * the empty-PoC gate. The existing GHSA advisory renderer stays byte-compatible.
 */

import { describe, it, expect } from "vitest";
import type { Finding, ImpactAssessment } from "@0sec/shared";
import {
  reportTemplate,
  renderPlatformReport,
  REPORT_PLATFORMS,
  EmptyPocError,
  renderAdvisoryMarkdown,
  type ReportPlatform,
} from "./template.js";

const ASSESSMENT: ImpactAssessment = {
  reachability_tier: "remote-unauth",
  blast_radius: "every unauthenticated visitor",
  weaponizability: "rce",
  business_impact: "headline",
  rationale: "Reachable pre-auth over the network.",
};

function mkFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "F-42",
    templateId: "t-42",
    title: "Unauthenticated RCE via webhook command injection",
    description: "The `cmd` field of /webhook is passed to a shell without escaping.",
    severity: "critical",
    category: "command-injection",
    status: "verified",
    evidence: {
      request: "POST /webhook\nAuthorization: Bearer eyJhbGciOi.secret.token\n\n{\"cmd\":\"id\"}",
      response: "200 OK\nuid=0(root)",
      analysis: "reproduced end to end",
    },
    impactAssessment: ASSESSMENT,
    pocSteps: [
      {
        id: "s1",
        kind: "exploit",
        summary: "Send the payload",
        action: { type: "shell", cmd: "curl -H 'Authorization: Bearer eyJreal.tok.en' https://t/webhook -d '{\"cmd\":\"id\"}'" },
      },
    ],
    remediation: {
      summary: "Never pass user input to a shell.",
      steps: ["Use execFile with an argument array.", "Add an allow-list."],
      references: ["https://owasp.org/www-community/attacks/Command_Injection"],
    },
    ...overrides,
  } as Finding;
}

const PLATFORMS: ReportPlatform[] = ["hackerone", "bugcrowd", "intigriti", "immunefi", "generic"];

describe("platform templates — smoke + required sections", () => {
  for (const platform of PLATFORMS) {
    it(`${platform} renders a finding and includes all required sections`, () => {
      const tpl = reportTemplate(platform);
      const report = tpl.render(mkFinding());
      expect(report.platform).toBe(platform);
      expect(report.markdown).toContain(`# ${mkFinding().title}`);
      const headings = report.sections.map((s) => s.heading);
      for (const required of tpl.requiredSections) {
        expect(headings, `missing "${required}" for ${platform}`).toContain(required);
        expect(report.markdown).toContain(`## ${required}`);
      }
      // Impact-first, submission-ready essentials: a CVSS vector + score.
      expect(report.cvssVector.length).toBeGreaterThan(0);
      expect(report.cvssScore).toBeGreaterThan(0);
    });
  }
});

describe("platform templates — content guarantees", () => {
  it("redacts secrets from PoC/evidence in every template", () => {
    for (const platform of PLATFORMS) {
      const report = renderPlatformReport(mkFinding(), platform);
      expect(report.markdown).not.toContain("eyJhbGciOi.secret.token");
      expect(report.markdown).not.toContain("eyJreal.tok.en");
      // The secret sweep masked both — under the Authorization header label.
      expect(report.markdown).toContain("<REDACTED-Authorization>");
    }
  });

  it("leads HackerOne with Summary then Steps then Impact ordering", () => {
    const report = reportTemplate("hackerone").render(mkFinding());
    const headings = report.sections.map((s) => s.heading);
    expect(headings.indexOf("Steps To Reproduce")).toBeLessThan(headings.indexOf("Impact"));
    expect(headings.indexOf("Summary")).toBe(0);
  });

  it("Bugcrowd surfaces a VRT priority and business impact first", () => {
    const report = reportTemplate("bugcrowd").render(mkFinding());
    expect(report.markdown).toContain("P1 (Critical)");
    expect(report.sections[0].heading).toBe("Business Impact");
  });

  it("Immunefi surfaces impact-based severity and a CVSS 4.0 vector", () => {
    const report = reportTemplate("immunefi").render(mkFinding());
    expect(report.markdown).toContain("CVSS 4.0");
    expect(report.markdown).toContain("Attack Scenario");
    expect(report.markdown.toLowerCase()).toContain("funds");
  });

  it("Intigriti surfaces the CWE vulnerability type", () => {
    const report = reportTemplate("intigriti").render(mkFinding());
    expect(report.markdown).toContain("CWE-");
  });

  it("falls back to generic for an unknown platform id", () => {
    expect(reportTemplate("nope").id).toBe("generic");
    expect(reportTemplate(undefined).id).toBe("generic");
    expect(renderPlatformReport(mkFinding(), "nope").platform).toBe("generic");
  });
});

describe("platform templates — empty-PoC gate", () => {
  it("throws EmptyPocError when the finding has no PoC content", () => {
    const bare = mkFinding({ evidence: { request: "", response: "", analysis: "" }, pocSteps: undefined });
    for (const platform of PLATFORMS) {
      expect(() => renderPlatformReport(bare, platform)).toThrow(EmptyPocError);
    }
  });

  it("renders from evidence alone (no structured steps)", () => {
    const evidenceOnly = mkFinding({ pocSteps: undefined });
    const report = renderPlatformReport(evidenceOnly, "generic");
    expect(report.markdown).toContain("## Proof of Concept");
  });
});

describe("registry / picker", () => {
  it("exposes every platform with a label and description", () => {
    expect(REPORT_PLATFORMS.map((p) => p.id).sort()).toEqual(
      ["bugcrowd", "generic", "hackerone", "immunefi", "intigriti"],
    );
    for (const p of REPORT_PLATFORMS) {
      expect(p.label.length).toBeGreaterThan(0);
      expect(p.description.length).toBeGreaterThan(0);
    }
  });
});

describe("existing GHSA advisory renderer still works", () => {
  it("renderAdvisoryMarkdown is unaffected by the new templates", () => {
    const adv = renderAdvisoryMarkdown(mkFinding());
    expect(adv.markdown).toContain("# Title");
    expect(adv.markdown).toContain("## PoC");
    expect(adv.cvssVector).toContain("CVSS:3.1/");
  });
});
