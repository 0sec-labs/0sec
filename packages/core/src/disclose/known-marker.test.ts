import { describe, it, expect } from "vitest";
import {
  detectKnownMarkers,
  analyzeFindingForKnownMarkers,
} from "./known-marker.js";
import type { Finding } from "@pwnkit/shared";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-test-123",
    templateId: "test-template",
    title: "Test finding",
    description: "A test vulnerability.",
    severity: "medium",
    category: "injection",
    status: "verified",
    evidence: {
      request: "GET / HTTP/1.1",
      response: "200 OK",
      analysis: "Standard analysis.",
    },
    timestamp: 1712345678,
    ...overrides,
  };
}

describe("detectKnownMarkers", () => {
  it("recognizes explicit source markers with location and context", () => {
    const src = [
      "function parse(input: string) {",
      "  // TODO: validate input length",
      "  return JSON.parse(input);",
      "}",
    ].join("\n");
    const signal = detectKnownMarkers(src, "src/parser.c");

    expect(signal.hasKnownMarker).toBe(true);
    expect(signal.markers).toHaveLength(1);
    expect(signal.markers[0]).toMatchObject({
      marker: "todo",
      lineNumber: 2,
      sourcePath: "src/parser.c",
    });
    expect(signal.markers[0].context).toContain("function parse");
    expect(signal.markers[0].context).toContain("return JSON.parse");
  });

  it("recognizes TODO, FIXME, XXX, and documented limitation phrasing", () => {
    const signal = detectKnownMarkers([
      "// TODO: handle edge case",
      "// FIXME(security): validate URL",
      "// XXX: revisit before shipping",
      "This is a known limitation of the parser.",
      "This behavior is a documented limitation.",
    ].join("\n"));
    expect(signal.markers.map((marker) => marker.marker)).toEqual([
      "todo",
      "fixme",
      "xxx",
      "known limitation",
      "documented limitation",
    ]);
  });

  it("keeps normal prose and embedded words out of the advisory signal", () => {
    const signal = detectKnownMarkers(
      "The todolist module validates user input before sending it to the database.",
    );
    expect(signal).toEqual({ hasKnownMarker: false, markers: [] });
  });

  it("truncates long marker lines without losing the marker", () => {
    const signal = detectKnownMarkers("x".repeat(250) + " // TODO: fix this");
    expect(signal.markers[0].line.length).toBeLessThanOrEqual(203);
    expect(signal.markers[0].line).toContain("TODO");
  });
});

describe("analyzeFindingForKnownMarkers", () => {
  it("aggregates evidence fields without mutating the finding", () => {
    const finding = baseFinding({
      evidence: {
        request: "POST /api // TODO: check auth",
        response: "200 OK // FIXME: leaks internal ID",
        analysis: "Standard analysis.",
      },
    });
    const originalAnalysis = finding.evidence.analysis;

    const signal = analyzeFindingForKnownMarkers(finding);
    expect(signal.markers.map((marker) => marker.marker)).toEqual(["todo", "fixme"]);
    expect(finding.evidence.analysis).toBe(originalAnalysis);
  });
});
