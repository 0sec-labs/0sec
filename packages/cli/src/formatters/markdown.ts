import type { ScanReport, Finding } from "@pwnkit/shared";

export function formatMarkdown(report: ScanReport): string {
  const lines: string[] = [];

  lines.push("# pwnkit Scan Report");
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

function formatFinding(finding: Finding): string {
  const lines: string[] = [];
  const badge = severityBadge(finding.severity);

  lines.push(`### ${badge} ${finding.title}`);
  lines.push("");
  lines.push(`- **Category:** ${finding.category}`);
  lines.push(`- **Status:** ${finding.status}`);
  lines.push(`- **Description:** ${finding.description}`);
  lines.push("");

  if (finding.evidence.analysis) {
    lines.push(`**Evidence:** ${finding.evidence.analysis}`);
    lines.push("");
  }

  lines.push("<details>");
  lines.push("<summary>Request / Response</summary>");
  lines.push("");
  lines.push("**Request:**");
  lines.push("```");
  lines.push(finding.evidence.request.slice(0, 500));
  lines.push("```");
  lines.push("");
  lines.push("**Response:**");
  lines.push("```");
  lines.push(finding.evidence.response.slice(0, 500));
  lines.push("```");
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
