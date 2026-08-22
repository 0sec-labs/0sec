import type { ScanReport, Finding, FindingRemediation, PocStep } from "@0sec/shared";

/**
 * Per-block cap on raw request/response evidence in the markdown report.
 *
 * This format is what a human reads by default, so it has to be readable —
 * a 200 KB response body pasted inline is not. But truncation must never be
 * SILENT: the previous implementation cut at 500 characters with no marker,
 * so a reader could not tell whether they were looking at the whole request
 * or the first paragraph of it, and a PoC that mattered could be sitting just
 * past the cut. Every elision below is annotated with the exact byte count
 * dropped and a pointer to the lossless formats.
 *
 * 4000 fits a realistic HTTP exchange or a source excerpt while still bounding
 * the page. `--format sarif` and `--format json` carry evidence in full.
 */
const EVIDENCE_BLOCK_LIMIT = 4000;

/** Longest single PoC step list rendered before summarising the remainder. */
const POC_STEP_LIMIT = 20;

export function formatMarkdown(report: ScanReport): string {
  const lines: string[] = [];

  lines.push("# 0sec Scan Report");
  lines.push("");
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Target | ${report.target} |`);
  lines.push(`| Depth | ${report.scanDepth} |`);
  lines.push(`| Started | ${report.startedAt} |`);
  lines.push(`| Duration | ${(report.durationMs / 1000).toFixed(1)}s |`);
  lines.push("");

  // Summary
  lines.push("## Summary");
  lines.push("");
  lines.push(`- **Attacks:** ${report.summary.totalAttacks}`);
  lines.push(`- **Findings:** ${report.summary.totalFindings}`);
  if (report.summary.critical > 0)
    lines.push(`- **Critical:** ${report.summary.critical}`);
  if (report.summary.high > 0) lines.push(`- **High:** ${report.summary.high}`);
  if (report.summary.medium > 0) lines.push(`- **Medium:** ${report.summary.medium}`);
  if (report.summary.low > 0) lines.push(`- **Low:** ${report.summary.low}`);
  lines.push("");

  if (report.warnings.length > 0) {
    lines.push("## Warnings");
    lines.push("");
    for (const warning of report.warnings) {
      lines.push(`- **${warning.stage}:** ${warning.message}`);
    }
    lines.push("");
  }

  // Findings
  if (report.findings.length > 0) {
    lines.push("## Findings");
    lines.push("");
    for (const finding of report.findings) {
      lines.push(formatFinding(finding));
    }
  } else {
    lines.push(report.warnings.length > 0 ? "## No Confirmed Vulnerabilities" : "## No Vulnerabilities Found");
    lines.push("");
    lines.push(
      report.warnings.length > 0
        ? "The scanner did not confirm vulnerabilities, but target validation or probe execution produced warnings."
        : "The target passed all tests."
    );
  }

  return lines.join("\n");
}

/**
 * Render one evidence blob inside a fenced block, disclosing any elision.
 *
 * Returns the marker line separately from the body so the caller can place it
 * outside the code fence — a truncation note inside the fence would read as
 * part of the captured traffic, which is exactly the kind of ambiguity this
 * function exists to remove.
 */
function evidenceBlock(label: string, raw: string): string[] {
  const lines: string[] = [];
  lines.push(`**${label}:**`);
  if (!raw) {
    lines.push("");
    lines.push("_(not captured)_");
    return lines;
  }
  const truncated = raw.length > EVIDENCE_BLOCK_LIMIT;
  const body = truncated ? raw.slice(0, EVIDENCE_BLOCK_LIMIT) : raw;
  lines.push("```");
  lines.push(body);
  lines.push("```");
  if (truncated) {
    lines.push(
      `_Truncated for readability: ${raw.length - EVIDENCE_BLOCK_LIMIT} of ` +
        `${raw.length} characters not shown. Use \`--format json\` or ` +
        `\`--format sarif\` for the complete evidence._`,
    );
  }
  return lines;
}

/** Render the structured remediation block when the finding carries one. */
function remediationSection(remediation: FindingRemediation): string[] {
  const lines: string[] = [];
  lines.push("**Remediation:**");
  lines.push("");
  lines.push(remediation.summary);
  if (remediation.steps.length > 0) {
    lines.push("");
    for (const step of remediation.steps) lines.push(`1. ${step}`);
  }
  if (remediation.codeExample) {
    const { before, after, language } = remediation.codeExample;
    lines.push("");
    lines.push("<details>");
    lines.push("<summary>Suggested change</summary>");
    lines.push("");
    lines.push("Before:");
    lines.push("");
    lines.push("```" + language);
    lines.push(before);
    lines.push("```");
    lines.push("");
    lines.push("After:");
    lines.push("");
    lines.push("```" + language);
    lines.push(after);
    lines.push("```");
    lines.push("</details>");
  }
  if (remediation.references.length > 0) {
    lines.push("");
    lines.push("References:");
    for (const ref of remediation.references) lines.push(`- ${ref}`);
  }
  lines.push("");
  return lines;
}

/**
 * Render the ordered PoC step graph as human-followable reproduction steps.
 *
 * A disclosure reader's first question is "how do I reproduce this"; when the
 * structured graph exists it answers that far better than the prose evidence
 * blob, so it is rendered ahead of the raw request/response.
 */
function reproductionSection(steps: PocStep[]): string[] {
  const lines: string[] = [];
  lines.push("**Reproduction steps:**");
  lines.push("");
  const shown = steps.slice(0, POC_STEP_LIMIT);
  shown.forEach((step, i) => {
    lines.push(`${i + 1}. **[${step.kind}]** ${step.summary}`);
  });
  if (steps.length > shown.length) {
    lines.push("");
    lines.push(
      `_${steps.length - shown.length} further step(s) omitted; the full graph ` +
        `is in \`--format json\`._`,
    );
  }
  lines.push("");
  return lines;
}

function formatFinding(finding: Finding): string {
  const lines: string[] = [];
  const badge = severityBadge(finding.severity);

  lines.push(`### ${badge} ${finding.title}`);
  lines.push("");
  lines.push(`- **Category:** ${finding.category}`);
  lines.push(`- **Status:** ${finding.status}`);
  // Severity justification: a bare "high" is an assertion; a CVSS vector is a
  // claim a vendor can check. Rendered only when actually present — this
  // formatter never synthesises one.
  if (finding.cvssScore !== undefined || finding.cvssVector) {
    const score = finding.cvssScore !== undefined ? `${finding.cvssScore}` : "n/a";
    const vector = finding.cvssVector ? ` (\`${finding.cvssVector}\`)` : "";
    lines.push(`- **CVSS:** ${score}${vector}`);
  }
  if (finding.confidence !== undefined) {
    lines.push(`- **Confidence:** ${(finding.confidence * 100).toFixed(0)}%`);
  }
  if (finding.triageNote) {
    lines.push(`- **Triage:** ${finding.triageNote}`);
  }
  lines.push(`- **Description:** ${finding.description}`);
  lines.push("");

  if (finding.evidence.analysis) {
    lines.push(`**Evidence:** ${finding.evidence.analysis}`);
    lines.push("");
  }

  if (finding.pocSteps && finding.pocSteps.length > 0) {
    lines.push(...reproductionSection(finding.pocSteps));
  }

  if (finding.remediation) {
    lines.push(...remediationSection(finding.remediation));
  }

  lines.push("<details>");
  lines.push("<summary>Request / Response</summary>");
  lines.push("");
  lines.push(...evidenceBlock("Request", finding.evidence.request));
  lines.push("");
  lines.push(...evidenceBlock("Response", finding.evidence.response));
  lines.push("</details>");
  lines.push("");

  return lines.join("\n");
}

function severityBadge(severity: string): string {
  const badges: Record<string, string> = {
    critical: "[CRITICAL]",
    high: "[HIGH]",
    medium: "[MEDIUM]",
    low: "[LOW]",
    info: "[INFO]",
  };
  return badges[severity] ?? `[${severity.toUpperCase()}]`;
}
