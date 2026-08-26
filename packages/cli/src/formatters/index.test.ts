import { describe, expect, it } from "vitest";
import {
  createAuditReportDocument,
  createScanReportDocument,
  type AuditReport,
  type ScanReport,
} from "@0sec/shared";
import {
  formatAuditReport,
  formatPresentationDocument,
  formatReport,
} from "./index.js";

const summary = {
  totalAttacks: 0,
  totalFindings: 0,
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};

const scan: ScanReport = {
  target: "https://example.test",
  scanDepth: "quick",
  startedAt: "2026-08-26T00:00:00.000Z",
  completedAt: "2026-08-26T00:00:01.000Z",
  durationMs: 1_000,
  summary,
  findings: [],
  warnings: [],
};

const audit: AuditReport = {
  package: "example",
  version: "1.0.0",
  startedAt: "2026-08-26T00:00:00.000Z",
  completedAt: "2026-08-26T00:00:01.000Z",
  durationMs: 1_000,
  semgrepFindings: 0,
  npmAuditFindings: [],
  summary,
  findings: [],
};

describe("formatPresentationDocument", () => {
  it("preserves scan JSON bytes through the canonical document adapter", () => {
    expect(formatPresentationDocument(createScanReportDocument(scan), "json"))
      .toBe(formatReport(scan, "json"));
  });

  it("preserves audit JSON bytes through the canonical document adapter", () => {
    expect(formatPresentationDocument(createAuditReportDocument(audit), "json"))
      .toBe(JSON.stringify(audit, null, 2));
    expect(formatAuditReport(audit, "json"))
      .toBe(JSON.stringify(audit, null, 2));
  });
});
