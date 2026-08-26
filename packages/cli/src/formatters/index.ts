import {
  createAuditReportDocument,
  createReviewReportDocument,
  createScanReportDocument,
  type AuditReport,
  type OutputFormat,
  type PresentationReportDocument,
  type ReviewReport,
  type ScanReport,
} from "@0sec/shared";
import { formatTerminal } from "./terminal.js";
import { formatJson } from "./json.js";
import { formatMarkdown } from "./markdown.js";
import { formatHtml } from "./html.js";
import { formatSarif } from "./sarif.js";
export { generatePdfReport } from "./pdf.js";
export { renderReplay } from "./replay.js";
export type { ReplayData } from "./replay.js";
export { formatTimeline, isTimelineFormat, TIMELINE_FORMATS } from "./timeline.js";
export type { TimelineEntry, TimelineExport, TimelineFormat } from "./timeline.js";

/**
 * Terminal, browser, and machine-output adapters all begin with the same
 * versioned report document. The individual formatter bytes remain unchanged.
 */
export function formatPresentationDocument(
  document: PresentationReportDocument,
  format: OutputFormat,
): string {
  if (format === "json" && document.documentType !== "scan-report") {
    return JSON.stringify(document.report, null, 2);
  }

  const report: ScanReport = document.documentType === "scan-report"
    ? document.report
    : document.documentType === "audit-report"
      ? {
          target: `${document.report.package}@${document.report.version}`,
          scanDepth: "deep",
          startedAt: document.report.startedAt,
          completedAt: document.report.completedAt,
          durationMs: document.report.durationMs,
          summary: document.report.summary,
          findings: document.report.findings,
          warnings: [],
        }
      : {
          target: document.report.repo,
          scanDepth: "deep",
          startedAt: document.report.startedAt,
          completedAt: document.report.completedAt,
          durationMs: document.report.durationMs,
          summary: document.report.summary,
          findings: document.report.findings,
          warnings: [],
        };

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
      // Use generatePdfReport() instead of formatPresentationDocument() for PDF output.
      return "[PDF output requires generatePdfReport()]";
  }
}

export function formatReport(report: ScanReport, format: OutputFormat): string {
  return formatPresentationDocument(createScanReportDocument(report), format);
}

/**
 * Format an audit report. Adapts AuditReport to ScanReport for reuse,
 * but adds audit-specific header information.
 */
export function formatAuditReport(
  report: AuditReport,
  format: OutputFormat,
): string {
  return formatPresentationDocument(createAuditReportDocument(report), format);
}

/**
 * Format a review report. Adapts ReviewReport to ScanReport for reuse.
 */
export function formatReviewReport(
  report: ReviewReport,
  format: OutputFormat,
): string {
  return formatPresentationDocument(createReviewReportDocument(report), format);
}
