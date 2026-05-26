import type { ScanReport, AuditReport, ReviewReport, OutputFormat } from "@pwnkit/shared";
import { formatTerminal } from "./terminal.js";
import { formatJson } from "./json.js";
import { formatMarkdown } from "./markdown.js";
import { formatHtml } from "./html.js";
import { formatSarif } from "./sarif.js";
export { generatePdfReport } from "./pdf.js";
export { renderReplay, renderReplayStatic, replayDataFromReport, createReplayCollector } from "./replay.js";
export type { ReplayData, ReplayCollector } from "./replay.js";

export function formatReport(report: ScanReport, format: OutputFormat): string {
  switch (format) {
    case "terminal":
      return formatTerminal(report);
    case "json":
      return formatJson(report);
    case "markdown":
      return formatMarkdown(report);
    case "html":
      return formatHtml(report);
    case "sarif":
      return formatSarif(report);
    case "pdf":
      // PDF generation is async and writes directly to a file.
      // Use generatePdfReport() instead of formatReport() for PDF output.
      return "[PDF output requires generatePdfReport()]";
  }
}

/**
 * Format an audit report. Adapts AuditReport to ScanReport for reuse,
 * but adds audit-specific header information.
 */
export function formatAuditReport(
  report: AuditReport,
  format: OutputFormat,
): string {
  // Convert to ScanReport shape for formatters
  const scanReport: ScanReport = {
    target: `${report.package}@${report.version}`,
    scanDepth: "deep",
    startedAt: report.startedAt,
    completedAt: report.completedAt,
    durationMs: report.durationMs,
    summary: report.summary,
    findings: report.findings,
    warnings: [],
  };

  if (format === "json") {
    // For JSON, return the full audit report with extra fields
    return JSON.stringify(report, null, 2);
  }

  return formatReport(scanReport, format);
}

/**
 * Format a review report. Adapts ReviewReport to ScanReport for reuse.
 */
export function formatReviewReport(
  report: ReviewReport,
  format: OutputFormat,
): string {
  const scanReport: ScanReport = {
    target: report.repo,
    scanDepth: "deep",
    startedAt: report.startedAt,
    completedAt: report.completedAt,
    durationMs: report.durationMs,
    summary: report.summary,
    findings: report.findings,
    warnings: [],
  };

  if (format === "json") {
    return JSON.stringify(report, null, 2);
  }

  return formatReport(scanReport, format);
}
