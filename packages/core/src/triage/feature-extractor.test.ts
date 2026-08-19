import { describe, it, expect } from "vitest";
import { extractFeatures, FEATURE_NAMES } from "./feature-extractor.js";
import type { Finding } from "@pwnkit/shared";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "test-1",
    templateId: "sqli-error",
    title: "SQL Injection in login endpoint",
    description: "The login endpoint is vulnerable to SQL injection via the username parameter.",
    severity: "high",
    category: "sqli",
    status: "confirmed",
    evidence: {
      request: "POST /login HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nusername=' OR 1=1--&password=test",
      response: "HTTP/1.1 500 Internal Server Error\n\nYou have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
    },
    confidence: 0.85,
    timestamp: Date.now(),
    ...overrides,
  };
}

const idx = (name: string) => {
  const i = FEATURE_NAMES.indexOf(name);
  if (i === -1) throw new Error(`Unknown feature: ${name}. Available: ${FEATURE_NAMES.join(", ")}`);
  return i;
};

describe("extractFeatures", () => {
  it("returns a 55-element vector", () => {
    const features = extractFeatures(makeFinding());
    expect(features).toHaveLength(55);
    expect(features).toHaveLength(FEATURE_NAMES.length);
  });

  it("returns all numbers (no NaN)", () => {
    const features = extractFeatures(makeFinding());
    for (let i = 0; i < features.length; i++) {
      expect(typeof features[i]).toBe("number");
      expect(isNaN(features[i]!)).toBe(false);
    }
  });

  it("detects SQL error in response", () => {
    const features = extractFeatures(makeFinding());
    expect(features[idx("resp_sql_error")]).toBe(1);
  });

  it("detects 5xx status in response", () => {
    const features = extractFeatures(makeFinding());
    expect(features[idx("resp_5xx_status")]).toBe(1);
  });

  it("extracts HTTP status code", () => {
    const features = extractFeatures(makeFinding());
    expect(features[idx("resp_http_status")]).toBe(500);
  });

  it("detects SQL syntax in request", () => {
    const features = extractFeatures(makeFinding());
    expect(features[idx("req_sql_syntax")]).toBe(1);
  });

  it("sets severity ordinal correctly", () => {
    expect(extractFeatures(makeFinding({ severity: "critical" }))[idx("meta_severity_ordinal")]).toBe(4);
    expect(extractFeatures(makeFinding({ severity: "high" }))[idx("meta_severity_ordinal")]).toBe(3);
    expect(extractFeatures(makeFinding({ severity: "medium" }))[idx("meta_severity_ordinal")]).toBe(2);
    expect(extractFeatures(makeFinding({ severity: "low" }))[idx("meta_severity_ordinal")]).toBe(1);
    expect(extractFeatures(makeFinding({ severity: "informational" }))[idx("meta_severity_ordinal")]).toBe(0);
  });

  it("sets confidence correctly", () => {
    const features = extractFeatures(makeFinding({ confidence: 0.92 }));
    expect(features[idx("meta_confidence")]).toBeCloseTo(0.92);
  });

  it("detects XSS payloads in request", () => {
    const xssFinding = makeFinding({
      category: "xss",
      evidence: {
        request: "GET /search?q=<script>alert(1)</script> HTTP/1.1",
        response: "HTTP/1.1 200 OK\n\n<html><script>alert(1)</script></html>",
      },
    });
    expect(extractFeatures(xssFinding)[idx("req_xss_payload")]).toBe(1);
  });

  it("detects SSTI syntax in request", () => {
    const finding = makeFinding({
      category: "ssti",
      evidence: {
        request: "GET /template?name={{7*7}} HTTP/1.1",
        response: "HTTP/1.1 200 OK\n\n49",
      },
    });
    expect(extractFeatures(finding)[idx("req_ssti_syntax")]).toBe(1);
  });

  it("detects command injection in request", () => {
    const finding = makeFinding({
      category: "command_injection",
      evidence: {
        request: "GET /ping?host=127.0.0.1;whoami HTTP/1.1",
        response: "HTTP/1.1 200 OK\n\nroot",
      },
    });
    expect(extractFeatures(finding)[idx("req_command_injection")]).toBe(1);
  });

  it("detects hedging language in description", () => {
    const finding = makeFinding({
      description: "The endpoint might be vulnerable. It's possible that the parameter is not sanitized.",
    });
    expect(extractFeatures(finding)[idx("text_hedging_language")]).toBe(1);
  });

  it("detects verification language in description", () => {
    const finding = makeFinding({
      description: "Confirmed SQL injection. The payload was verified to extract data.",
    });
    expect(extractFeatures(finding)[idx("text_verification_language")]).toBe(1);
  });

  it("handles empty evidence gracefully", () => {
    const finding = makeFinding({ evidence: { request: "", response: "" } });
    const features = extractFeatures(finding);
    expect(features).toHaveLength(55);
    for (const f of features) {
      expect(typeof f).toBe("number");
      expect(isNaN(f)).toBe(false);
    }
  });

  it("handles minimal finding gracefully", () => {
    const minimal: Finding = {
      id: "min",
      templateId: "",
      title: "",
      description: "",
      severity: "informational",
      category: "unknown" as any,
      status: "unverified",
      evidence: { request: "", response: "" },
      timestamp: Date.now(),
    };
    const features = extractFeatures(minimal);
    expect(features).toHaveLength(55);
    for (const f of features) {
      expect(typeof f).toBe("number");
      expect(isNaN(f)).toBe(false);
    }
  });

  it("evidence completeness: full evidence = 1.0", () => {
    const finding = makeFinding({
      evidence: { request: "GET /", response: "200 OK", analysis: "Vulnerable" },
    });
    const features = extractFeatures(finding);
    expect(features[idx("cross_evidence_completeness")]).toBeCloseTo(1.0);
  });

  it("evidence completeness: no analysis = 0.67", () => {
    const finding = makeFinding({
      evidence: { request: "GET /", response: "200 OK" },
    });
    const features = extractFeatures(finding);
    expect(features[idx("cross_evidence_completeness")]).toBeCloseTo(0.67, 1);
  });
});
