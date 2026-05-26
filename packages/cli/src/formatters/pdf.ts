// pdfkit is loaded lazily via createRequire(import.meta.url) inside
// generatePdfReport so that the bun-compiled binary never bundles it.
// Static `import PDFDocument from "pdfkit"` would run pdfkit's
// module-level code at startup, which resolves font files via
// __dirname — and __dirname after `bun build --compile` is the
// build host's filesystem path, which doesn't exist on user machines.
// Mirrors the same pattern PR #242 used for node-sqlite3-wasm.
import { createRequire } from "node:module";
import { createWriteStream } from "node:fs";
import type { ScanReport, Finding, Severity, ReportSummary } from "@pwnkit/shared";
import type PDFDocumentType from "pdfkit";

type PDFDoc = InstanceType<typeof PDFDocumentType>;

// ── Color palette (RGB) ──

const COLORS = {
  primary: "#1a1a2e" as const,
  accent: "#e94560" as const,
  background: "#f8f9fa" as const,
  text: "#2d2d2d" as const,
  textLight: "#6c757d" as const,
  white: "#ffffff" as const,
  severity: {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#ca8a04",
    low: "#2563eb",
    info: "#6b7280",
  } as Record<Severity, string>,
} as const;

const PAGE_MARGIN = 50;
const CONTENT_WIDTH = 612 - PAGE_MARGIN * 2; // US Letter width minus margins

// ── Helpers ──

function severityLabel(s: Severity): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSec = seconds % 60;
  return `${minutes}m ${remainingSec}s`;
}

function riskScore(summary: ReportSummary): number {
  const score =
    summary.critical * 40 +
    summary.high * 20 +
    summary.medium * 10 +
    summary.low * 3 +
    summary.info * 0;
  return Math.min(100, score);
}

function riskRating(score: number): string {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 30) return "Medium";
  if (score >= 10) return "Low";
  return "Informational";
}

function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen - 3) + "...";
}

// ── Main export ──

export async function generatePdfReport(
  report: ScanReport,
  outputPath: string,
): Promise<void> {
  // Lazy-load pdfkit so the bun-compiled binary doesn't try to resolve
  // its build-host font path at startup. See header comment.
  const require_ = createRequire(import.meta.url);
  const PDFDocument = require_("pdfkit") as typeof PDFDocumentType;
  return new Promise<void>((resolve, reject) => {
    const doc = new PDFDocument({
      size: "LETTER",
      margins: { top: PAGE_MARGIN, bottom: PAGE_MARGIN, left: PAGE_MARGIN, right: PAGE_MARGIN },
      info: {
        Title: `pwnkit Pentest Report - ${report.target}`,
        Author: "pwnkit",
        Subject: "Automated Penetration Test Report",
        CreationDate: new Date(),
      },
      bufferPages: true,
    });

    const stream = createWriteStream(outputPath);
    stream.on("error", reject);
    stream.on("finish", resolve);
    doc.pipe(stream);

    renderCoverPage(doc, report);
    renderExecutiveSummary(doc, report);
    renderFindingsTable(doc, report);
    renderFindingDetails(doc, report);
    renderMethodology(doc, report);
    renderFooters(doc);

    doc.end();
  });
}

// ── Cover Page ──

function renderCoverPage(doc: PDFDoc, report: ScanReport): void {
  // Background
  doc.rect(0, 0, 612, 792).fill(COLORS.primary);

  // Logo placeholder
  doc
    .fontSize(48)
    .font("Helvetica-Bold")
    .fillColor(COLORS.accent)
    .text("pwnkit", PAGE_MARGIN, 200, { align: "center" });

  doc
    .fontSize(14)
    .font("Helvetica")
    .fillColor(COLORS.white)
    .text("Automated Penetration Test Report", PAGE_MARGIN, 260, { align: "center" });

  // Divider
  doc
    .moveTo(200, 300)
    .lineTo(412, 300)
    .strokeColor(COLORS.accent)
    .lineWidth(2)
    .stroke();

  // Target info
  doc
    .fontSize(18)
    .font("Helvetica-Bold")
    .fillColor(COLORS.white)
    .text(report.target, PAGE_MARGIN, 330, { align: "center" });

  doc
    .fontSize(12)
    .font("Helvetica")
    .fillColor(COLORS.textLight)
    .text(`Scan Depth: ${report.scanDepth}`, PAGE_MARGIN, 370, { align: "center" })
    .text(`Date: ${formatDate(report.startedAt)}`, PAGE_MARGIN, 390, { align: "center" })
    .text(`Duration: ${formatDuration(report.durationMs)}`, PAGE_MARGIN, 410, { align: "center" });

  // Risk badge
  const score = riskScore(report.summary);
  const rating = riskRating(score);

  doc
    .fontSize(14)
    .font("Helvetica-Bold")
    .fillColor(COLORS.accent)
    .text(`Risk Score: ${score}/100 (${rating})`, PAGE_MARGIN, 460, { align: "center" });

  // Footer
  doc
    .fontSize(9)
    .font("Helvetica")
    .fillColor(COLORS.textLight)
    .text("CONFIDENTIAL - For authorized recipients only", PAGE_MARGIN, 700, { align: "center" });
}

// ── Executive Summary ──

function renderExecutiveSummary(doc: PDFDoc, report: ScanReport): void {
  doc.addPage();
  sectionTitle(doc, "Executive Summary");

  const score = riskScore(report.summary);
  const rating = riskRating(score);
  const { summary } = report;

  doc
    .fontSize(11)
    .font("Helvetica")
    .fillColor(COLORS.text)
    .text(
      `An automated penetration test was conducted against ${report.target} ` +
      `on ${formatDate(report.startedAt)}. The scan ran for ${formatDuration(report.durationMs)} ` +
      `at "${report.scanDepth}" depth.`,
      PAGE_MARGIN, doc.y + 10,
      { width: CONTENT_WIDTH },
    );

  doc.moveDown(0.5);
  doc.text(
    `The overall risk score is ${score}/100 (${rating}). ` +
    `A total of ${summary.totalFindings} finding(s) were identified across ${summary.totalAttacks} attack(s).`,
    { width: CONTENT_WIDTH },
  );

  // Severity breakdown
  doc.moveDown(1);
  subSectionTitle(doc, "Findings by Severity");

  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  const sevCounts: Record<Severity, number> = {
    critical: summary.critical,
    high: summary.high,
    medium: summary.medium,
    low: summary.low,
    info: summary.info,
  };

  for (const sev of severities) {
    const count = sevCounts[sev];
    if (count === 0) continue;

    const barWidth = Math.max(4, (count / Math.max(summary.totalFindings, 1)) * (CONTENT_WIDTH - 140));
    const y = doc.y;

    // Severity label
    doc
      .fontSize(10)
      .font("Helvetica-Bold")
      .fillColor(COLORS.severity[sev])
      .text(severityLabel(sev), PAGE_MARGIN, y, { width: 70 });

    // Bar
    doc
      .rect(PAGE_MARGIN + 80, y + 2, barWidth, 12)
      .fill(COLORS.severity[sev]);

    // Count
    doc
      .fontSize(10)
      .font("Helvetica")
      .fillColor(COLORS.text)
      .text(String(count), PAGE_MARGIN + 90 + barWidth, y, { width: 40 });

    doc.y = y + 22;
  }

  // Warnings
  if (report.warnings.length > 0) {
    doc.moveDown(1);
    subSectionTitle(doc, "Warnings");
    for (const w of report.warnings) {
      doc
        .fontSize(9)
        .font("Helvetica")
        .fillColor(COLORS.textLight)
        .text(`[${w.stage}] ${w.message}`, PAGE_MARGIN, doc.y, { width: CONTENT_WIDTH });
      doc.moveDown(0.3);
    }
  }
}

// ── Findings Table ──

function renderFindingsTable(doc: PDFDoc, report: ScanReport): void {
  if (report.findings.length === 0) return;

  doc.addPage();
  sectionTitle(doc, "Findings Overview");

  const colWidths = { severity: 70, title: 220, category: 120, status: 80 };
  const tableX = PAGE_MARGIN;

  // Header row
  const headerY = doc.y + 5;
  doc.rect(tableX, headerY, CONTENT_WIDTH, 20).fill(COLORS.primary);

  doc.fontSize(9).font("Helvetica-Bold").fillColor(COLORS.white);
  doc.text("Severity", tableX + 5, headerY + 5, { width: colWidths.severity });
  doc.text("Title", tableX + colWidths.severity + 5, headerY + 5, { width: colWidths.title });
  doc.text("Category", tableX + colWidths.severity + colWidths.title + 5, headerY + 5, { width: colWidths.category });
  doc.text("Status", tableX + colWidths.severity + colWidths.title + colWidths.category + 5, headerY + 5, { width: colWidths.status });

  doc.y = headerY + 22;

  // Sort findings by severity
  const sevOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...report.findings].sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity]);

  for (let i = 0; i < sorted.length; i++) {
    const finding = sorted[i];
    const rowY = doc.y;

    // Check for page overflow
    if (rowY > 720) {
      doc.addPage();
      doc.y = PAGE_MARGIN;
    }

    // Alternate row background
    if (i % 2 === 0) {
      doc.rect(tableX, rowY, CONTENT_WIDTH, 18).fill(COLORS.background);
    }

    doc.fontSize(8).font("Helvetica");

    // Severity (colored)
    doc
      .fillColor(COLORS.severity[finding.severity])
      .font("Helvetica-Bold")
      .text(severityLabel(finding.severity), tableX + 5, rowY + 5, { width: colWidths.severity });

    // Title
    doc
      .fillColor(COLORS.text)
      .font("Helvetica")
      .text(truncate(finding.title, 45), tableX + colWidths.severity + 5, rowY + 5, { width: colWidths.title });

    // Category
    doc.text(finding.category, tableX + colWidths.severity + colWidths.title + 5, rowY + 5, { width: colWidths.category });

    // Status
    doc.text(finding.status, tableX + colWidths.severity + colWidths.title + colWidths.category + 5, rowY + 5, { width: colWidths.status });

    doc.y = rowY + 20;
  }
}

// ── Finding Details ──

function renderFindingDetails(doc: PDFDoc, report: ScanReport): void {
  if (report.findings.length === 0) return;

  const sevOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...report.findings].sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity]);

  for (const finding of sorted) {
    doc.addPage();
    sectionTitle(doc, finding.title);

    // Metadata line
    doc
      .fontSize(10)
      .font("Helvetica-Bold")
      .fillColor(COLORS.severity[finding.severity])
      .text(`${severityLabel(finding.severity)} Severity`, PAGE_MARGIN, doc.y, { continued: true })
      .fillColor(COLORS.textLight)
      .font("Helvetica")
      .text(`  |  ${finding.category}  |  ${finding.status}  |  ID: ${finding.id}`);

    if (finding.cvssScore != null) {
      doc
        .fontSize(9)
        .fillColor(COLORS.text)
        .text(`CVSS Score: ${finding.cvssScore}${finding.cvssVector ? ` (${finding.cvssVector})` : ""}`, PAGE_MARGIN, doc.y + 2);
    }

    // Description
    doc.moveDown(1);
    subSectionTitle(doc, "Description");
    doc
      .fontSize(10)
      .font("Helvetica")
      .fillColor(COLORS.text)
      .text(finding.description, PAGE_MARGIN, doc.y, { width: CONTENT_WIDTH });

    // Evidence: Request
    if (finding.evidence.request) {
      doc.moveDown(1);
      subSectionTitle(doc, "Request");
      codeBlock(doc, finding.evidence.request);
    }

    // Evidence: Response
    if (finding.evidence.response) {
      doc.moveDown(0.5);
      subSectionTitle(doc, "Response");
      codeBlock(doc, finding.evidence.response);
    }

    // Analysis / Remediation
    if (finding.evidence.analysis) {
      doc.moveDown(0.5);
      subSectionTitle(doc, "Analysis & Remediation");
      doc
        .fontSize(10)
        .font("Helvetica")
        .fillColor(COLORS.text)
        .text(finding.evidence.analysis, PAGE_MARGIN, doc.y, { width: CONTENT_WIDTH });
    }
  }
}

// ── Methodology ──

function renderMethodology(doc: PDFDoc, report: ScanReport): void {
  doc.addPage();
  sectionTitle(doc, "Methodology");

  doc
    .fontSize(10)
    .font("Helvetica")
    .fillColor(COLORS.text)
    .text(
      "This report was generated by pwnkit, a fully autonomous agentic pentesting framework. " +
      "The tool uses AI-driven attack generation and multi-agent consensus verification " +
      "to identify security vulnerabilities.",
      PAGE_MARGIN, doc.y + 10,
      { width: CONTENT_WIDTH },
    );

  doc.moveDown(1);
  subSectionTitle(doc, "Scan Parameters");

  const params = [
    ["Target", report.target],
    ["Scan Depth", report.scanDepth],
    ["Started", formatDate(report.startedAt)],
    ["Completed", formatDate(report.completedAt)],
    ["Duration", formatDuration(report.durationMs)],
    ["Total Attacks", String(report.summary.totalAttacks)],
    ["Total Findings", String(report.summary.totalFindings)],
  ];

  for (const [label, value] of params) {
    doc
      .fontSize(10)
      .font("Helvetica-Bold")
      .fillColor(COLORS.text)
      .text(`${label}: `, PAGE_MARGIN, doc.y, { continued: true })
      .font("Helvetica")
      .text(value);
    doc.moveDown(0.2);
  }

  doc.moveDown(1);
  subSectionTitle(doc, "Severity Definitions");

  const sevDefs: [string, string][] = [
    ["Critical", "Immediate exploitation possible with severe business impact. Requires urgent remediation."],
    ["High", "Easily exploitable vulnerability with significant impact. Should be fixed in the next release cycle."],
    ["Medium", "Exploitable with some prerequisites. Should be addressed in planned maintenance."],
    ["Low", "Minor issue with limited impact. Fix as part of regular development."],
    ["Info", "Informational finding or best-practice recommendation. No immediate risk."],
  ];

  for (const [sev, desc] of sevDefs) {
    doc
      .fontSize(10)
      .font("Helvetica-Bold")
      .fillColor(COLORS.text)
      .text(`${sev}: `, PAGE_MARGIN, doc.y, { continued: true })
      .font("Helvetica")
      .fillColor(COLORS.textLight)
      .text(desc, { width: CONTENT_WIDTH - 60 });
    doc.moveDown(0.3);
  }

  doc.moveDown(1);
  subSectionTitle(doc, "Disclaimer");
  doc
    .fontSize(9)
    .font("Helvetica")
    .fillColor(COLORS.textLight)
    .text(
      "This automated scan provides a point-in-time assessment. It may not identify all vulnerabilities. " +
      "Results should be validated by security professionals. The findings do not guarantee the absence of " +
      "other security issues. This report is confidential and intended for authorized recipients only.",
      PAGE_MARGIN, doc.y,
      { width: CONTENT_WIDTH },
    );
}

// ── Shared rendering helpers ──

function sectionTitle(doc: PDFDoc, title: string): void {
  doc
    .fontSize(20)
    .font("Helvetica-Bold")
    .fillColor(COLORS.primary)
    .text(title, PAGE_MARGIN, PAGE_MARGIN);

  doc
    .moveTo(PAGE_MARGIN, doc.y + 4)
    .lineTo(PAGE_MARGIN + CONTENT_WIDTH, doc.y + 4)
    .strokeColor(COLORS.accent)
    .lineWidth(1.5)
    .stroke();

  doc.y += 12;
}

function subSectionTitle(doc: PDFDoc, title: string): void {
  doc
    .fontSize(12)
    .font("Helvetica-Bold")
    .fillColor(COLORS.primary)
    .text(title, PAGE_MARGIN, doc.y);
  doc.moveDown(0.3);
}

function codeBlock(doc: PDFDoc, text: string): void {
  const maxChars = 2000;
  const displayText = truncate(text, maxChars);

  // Measure height needed
  doc.font("Courier").fontSize(8);
  const textHeight = doc.heightOfString(displayText, {
    width: CONTENT_WIDTH - 20,
  });

  const blockHeight = Math.min(textHeight + 16, 300);
  const y = doc.y;

  // Check for page overflow
  if (y + blockHeight > 740) {
    doc.addPage();
  }

  // Background
  doc
    .rect(PAGE_MARGIN, doc.y, CONTENT_WIDTH, blockHeight)
    .fill("#f1f3f5");

  // Text
  doc
    .fontSize(8)
    .font("Courier")
    .fillColor(COLORS.text)
    .text(displayText, PAGE_MARGIN + 10, doc.y - blockHeight + 8, {
      width: CONTENT_WIDTH - 20,
      height: blockHeight - 16,
      ellipsis: true,
    });

  doc.y = doc.y + 4;
}

function renderFooters(doc: PDFDoc): void {
  const pageCount = doc.bufferedPageRange().count;
  for (let i = 0; i < pageCount; i++) {
    doc.switchToPage(i);

    // Skip cover page
    if (i === 0) continue;

    doc
      .fontSize(8)
      .font("Helvetica")
      .fillColor(COLORS.textLight)
      .text(
        `pwnkit Pentest Report  |  Page ${i + 1} of ${pageCount}  |  CONFIDENTIAL`,
        PAGE_MARGIN,
        760,
        { width: CONTENT_WIDTH, align: "center" },
      );
  }
}
