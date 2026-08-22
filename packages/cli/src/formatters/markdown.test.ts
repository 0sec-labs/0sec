/**
 * Markdown scan-report formatter.
 *
 * The property that matters most here is that the default human-readable
 * format never lies by omission. It previously cut request/response evidence
 * at 500 characters with NO marker, so a reader could not distinguish a short
 * request from the first paragraph of a long one — and a PoC sitting just past
 * the cut simply vanished. These tests pin that every elision is disclosed with
 * its exact size, and that enrichment we already compute (CVSS, confidence,
 * remediation, PoC steps) actually reaches the page instead of being dropped.
 */

import { describe, it, expect } from "vitest";
import type { Finding, ScanReport } from "@0sec/shared";
import { formatMarkdown } from "./markdown.js";

function mkFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "F-1",
    templateId: "t-1",
    title: "SQL injection in /search",
    description: "The q parameter reaches a raw query.",
    severity: "high",
    category: "injection",
    status: "verified",
    evidence: { request: "GET /search?q=1", response: "HTTP/1.1 500", analysis: "" },
    ...overrides,
  } as Finding;
}

function mkReport(findings: Finding[]): ScanReport {
  return {
    target: "https://example.com",
    scanDepth: "deep",
    startedAt: "2026-08-22T00:00:00Z",
    durationMs: 12_000,
    summary: {
      totalAttacks: 3,
      totalFindings: findings.length,
      critical: 0,
      high: findings.length,
      medium: 0,
      low: 0,
    },
    warnings: [],
    findings,
  } as unknown as ScanReport;
}

describe("formatMarkdown — evidence truncation", () => {
  it("renders short evidence verbatim with no truncation note", () => {
    const out = formatMarkdown(mkReport([mkFinding()]));
    expect(out).toContain("GET /search?q=1");
    expect(out).not.toContain("Truncated for readability");
  });

  it("discloses truncation with the exact number of characters dropped", () => {
    const long = "A".repeat(4500);
    const out = formatMarkdown(
      mkReport([mkFinding({ evidence: { request: long, response: "ok", analysis: "" } })]),
    );
    // 4500 - 4000 = 500 characters elided, and the reader is told so.
    expect(out).toContain("Truncated for readability: 500 of 4500 characters not shown");
    expect(out).toContain("--format json");
  });

  it("puts the truncation note OUTSIDE the code fence", () => {
    // Inside the fence it would read as part of the captured traffic.
    const out = formatMarkdown(
      mkReport([
        mkFinding({ evidence: { request: "B".repeat(5000), response: "ok", analysis: "" } }),
      ]),
    );
    const noteIdx = out.indexOf("_Truncated for readability");
    const fenceClose = out.lastIndexOf("```", noteIdx);
    expect(fenceClose).toBeGreaterThan(-1);
    expect(fenceClose).toBeLessThan(noteIdx);
  });

  it("marks uncaptured evidence rather than emitting an empty fence", () => {
    const out = formatMarkdown(
      mkReport([mkFinding({ evidence: { request: "", response: "", analysis: "" } })]),
    );
    expect(out).toContain("_(not captured)_");
  });
});

describe("formatMarkdown — enrichment reaches the page", () => {
  it("renders a CVSS vector and score when present", () => {
    const out = formatMarkdown(
      mkReport([
        mkFinding({ cvssScore: 9.8, cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }),
      ]),
    );
    expect(out).toContain("**CVSS:** 9.8");
    expect(out).toContain("AV:N/AC:L/PR:N");
  });

  it("never synthesises a CVSS line when the finding has none", () => {
    // This formatter must not invent a severity justification.
    const out = formatMarkdown(mkReport([mkFinding()]));
    expect(out).not.toContain("**CVSS:**");
  });

  it("renders remediation summary, steps, code example and references", () => {
    const out = formatMarkdown(
      mkReport([
        mkFinding({
          remediation: {
            summary: "Use a parameterised query.",
            steps: ["Replace string concatenation", "Add a regression test"],
            codeExample: { before: "q + input", after: "db.query(sql, [input])", language: "ts" },
            references: ["https://owasp.org/sqli"],
          },
        }),
      ]),
    );
    expect(out).toContain("Use a parameterised query.");
    expect(out).toContain("Replace string concatenation");
    expect(out).toContain("db.query(sql, [input])");
    expect(out).toContain("https://owasp.org/sqli");
  });

  it("renders PoC steps as numbered reproduction steps", () => {
    const out = formatMarkdown(
      mkReport([
        mkFinding({
          pocSteps: [
            { id: "s1", kind: "setup", summary: "Log in as a low-priv user", action: {} },
            { id: "s2", kind: "exploit", summary: "POST the crafted payload", action: {} },
          ] as unknown as Finding["pocSteps"],
        }),
      ]),
    );
    expect(out).toContain("**Reproduction steps:**");
    expect(out).toContain("1. **[setup]** Log in as a low-priv user");
    expect(out).toContain("2. **[exploit]** POST the crafted payload");
  });

  it("summarises an overlong PoC graph instead of dumping it", () => {
    const steps = Array.from({ length: 25 }, (_, i) => ({
      id: `s${i}`,
      kind: "exploit",
      summary: `step ${i}`,
      action: {},
    }));
    const out = formatMarkdown(
      mkReport([mkFinding({ pocSteps: steps as unknown as Finding["pocSteps"] })]),
    );
    expect(out).toContain("5 further step(s) omitted");
  });

  it("still renders a finding carrying none of the optional enrichment", () => {
    // Findings predating these fields must not crash or render placeholders.
    const out = formatMarkdown(mkReport([mkFinding()]));
    expect(out).toContain("SQL injection in /search");
    expect(out).not.toContain("undefined");
    expect(out).not.toContain("**Remediation:**");
  });
});

describe("formatMarkdown — report skeleton", () => {
  it("keeps the summary table and severity counts", () => {
    const out = formatMarkdown(mkReport([mkFinding()]));
    expect(out).toContain("# 0sec Scan Report");
    expect(out).toContain("| Target | https://example.com |");
    expect(out).toContain("- **High:** 1");
  });

  it("distinguishes 'no findings' from 'no confirmed findings with warnings'", () => {
    const clean = formatMarkdown(mkReport([]));
    expect(clean).toContain("## No Vulnerabilities Found");

    const warned = mkReport([]);
    warned.warnings = [{ stage: "verify", message: "probe timed out" }] as ScanReport["warnings"];
    expect(formatMarkdown(warned)).toContain("## No Confirmed Vulnerabilities");
  });
});
