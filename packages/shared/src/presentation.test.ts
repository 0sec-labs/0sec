import { describe, expect, it } from "vitest";
import {
  PRESENTATION_PROTOCOL,
  createPresentationEvent,
  createScanReportDocument,
  isPresentationEvent,
} from "./presentation.js";
import type { ScanReport } from "./types.js";

const report: ScanReport = {
  target: "https://example.test",
  scanDepth: "quick",
  startedAt: "2026-08-26T00:00:00.000Z",
  completedAt: "2026-08-26T00:00:01.000Z",
  durationMs: 1_000,
  summary: {
    totalAttacks: 0,
    totalFindings: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  },
  findings: [],
  warnings: [],
};

describe("presentation protocol", () => {
  it("preserves producer ordering and correlation fields without transport framing", () => {
    const event = createPresentationEvent({
      source: "core",
      sequence: 7,
      at: "2026-08-26T00:00:00.000Z",
      eventType: "tool_call_started",
      payload: { tool: "read" },
      scanId: "scan-1",
      sessionId: "session-1",
    });

    expect(event).toEqual({
      protocol: PRESENTATION_PROTOCOL,
      kind: "event",
      source: "core",
      sequence: 7,
      at: "2026-08-26T00:00:00.000Z",
      eventType: "tool_call_started",
      payload: { tool: "read" },
      scanId: "scan-1",
      sessionId: "session-1",
    });
    expect(isPresentationEvent(event)).toBe(true);
  });

  it("rejects non-versioned or malformed event envelopes", () => {
    expect(isPresentationEvent({ type: "tool_call_started", payload: {} })).toBe(false);
    expect(isPresentationEvent({
      protocol: PRESENTATION_PROTOCOL,
      kind: "event",
      source: "core",
      sequence: 1,
      at: "now",
      eventType: "x",
      payload: [],
    })).toBe(false);
  });

  it("wraps reports without changing their public schema", () => {
    const document = createScanReportDocument(report);

    expect(document.protocol).toBe(PRESENTATION_PROTOCOL);
    expect(document.documentType).toBe("scan-report");
    expect(document.report).toBe(report);
  });
});
