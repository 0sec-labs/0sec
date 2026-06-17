import { describe, it, expect } from "vitest";
import type { Finding, PocStep, LayerVerdict } from "@pwnkit/shared";
import {
  assembleEvidencePack,
  renderVendorNotificationMarkdown,
  UnreproducedFindingError,
} from "./evidence-pack.js";

function reproducingLayerVerdict(): LayerVerdict {
  return { layer: "oracle", verdict: "pass", reason: "PoC reproduced in sandbox", durationMs: 10, costUsd: 0 };
}

function pocSteps(): PocStep[] {
  return [
    { id: "setup-1", kind: "setup", summary: "Stand up target", action: { type: "shell", cmd: "docker compose up -d" } },
    {
      id: "exploit-1",
      kind: "exploit",
      summary: "Send the malicious request",
      action: {
        type: "http",
        method: "GET",
        url: "/api/foo?url=http://169.254.169.254/",
        headers: { Authorization: "Bearer ***REMOVED***" },
      },
    },
  ];
}

function reproducedFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-abcdef123456",
    templateId: "ssrf-template",
    title: "SSRF via /api/foo",
    description: "Attacker-controlled URL reaches fetch without an allowlist.",
    severity: "high",
    category: "ssrf",
    status: "verified",
    evidence: {
      request: "GET /api/foo?url=http://169.254.169.254/ HTTP/1.1\nAuthorization: Bearer ***REMOVED***",
      response: '{"status":"reachable"}',
      analysis: "Full SSRF.",
    },
    pocSteps: pocSteps(),
    layerVerdicts: [reproducingLayerVerdict()],
    remediation: {
      summary: "Enforce an allowlist on the fetch target.",
      steps: ["Parse the URL", "Reject non-allowlisted hosts"],
      references: [],
    },
    timestamp: 1712345678,
    ...overrides,
  };
}

describe("assembleEvidencePack", () => {
  it("assembles the what/where/impact/repro/remediation spine from a reproduced finding", () => {
    const draft = assembleEvidencePack(reproducedFinding(), {
      target: "acme-app",
      affectedRef: "v1.2.3",
    });
    expect(draft.reproduced).toBe(true);
    expect(draft.what).toContain("Attacker-controlled URL");
    expect(draft.where).toContain("acme-app");
    expect(draft.where).toContain("v1.2.3");
    expect(draft.impact).toMatch(/High/);
    expect(draft.reproSteps.length).toBe(2);
    expect(draft.remediation).toContain("allowlist");
  });

  it("redacts secrets in the reproduction steps (no auto-leak of tokens)", () => {
    const draft = assembleEvidencePack(reproducedFinding(), { target: "acme-app" });
    const joined = draft.reproSteps.join("\n");
    expect(joined).not.toContain("sk-supersecret-token-value");
  });

  it("refuses to assemble for an unreproduced finding by default", () => {
    const unreproduced = reproducedFinding({ layerVerdicts: [], pocSteps: [] });
    expect(() => assembleEvidencePack(unreproduced)).toThrow(UnreproducedFindingError);
  });

  it("stages an internal draft for an unreproduced finding under the override", () => {
    const unreproduced = reproducedFinding({ layerVerdicts: [], pocSteps: [] });
    const draft = assembleEvidencePack(unreproduced, { allowUnreproduced: true });
    expect(draft.reproduced).toBe(false);
    expect(draft.reproSteps).toEqual([]);
  });

  it("fills in a placeholder when target/version unknown", () => {
    const draft = assembleEvidencePack(reproducedFinding());
    expect(draft.where).toMatch(/to be filled in/i);
  });
});

describe("renderVendorNotificationMarkdown", () => {
  it("always emits a DRAFT — NOT SENT banner", () => {
    const md = renderVendorNotificationMarkdown(
      assembleEvidencePack(reproducedFinding(), { target: "acme-app" }),
    );
    expect(md).toContain("DRAFT — NOT SENT");
    expect(md).toMatch(/operator must review/i);
  });

  it("renders the canonical section headings", () => {
    const md = renderVendorNotificationMarkdown(
      assembleEvidencePack(reproducedFinding(), { target: "acme-app" }),
    );
    expect(md).toContain("## What");
    expect(md).toContain("## Where");
    expect(md).toContain("## Impact");
    expect(md).toContain("## Reproduction");
    expect(md).toContain("## Suggested remediation");
  });

  it("flags an unreproduced internal draft with a do-not-send warning", () => {
    const draft = assembleEvidencePack(
      reproducedFinding({ layerVerdicts: [], pocSteps: [] }),
      { allowUnreproduced: true },
    );
    const md = renderVendorNotificationMarkdown(draft);
    expect(md).toMatch(/did \*\*not\*\* reproduce/i);
    expect(md).toMatch(/do not send/i);
  });

  it("never leaks a secret into the rendered draft", () => {
    const md = renderVendorNotificationMarkdown(
      assembleEvidencePack(reproducedFinding(), { target: "acme-app" }),
    );
    expect(md).not.toContain("sk-supersecret-token-value");
  });
});
