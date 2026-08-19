import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding, ScanReport } from "@pwnkit/shared";
import { runResearch } from "../research-runner.js";
import { ResearchAdapterRegistry } from "../adapter-registry.js";
import { LiveAgenticScanResearchAdapter, type LiveAgenticScanTarget } from "./live-agentic-scan-adapter.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function tmpRoot(prefix: string): string {
  const root = mkdtempSync(join(tmpdir(), prefix));
  roots.push(root);
  return root;
}

function reportWith(finding: Finding, target = "https://target.test"): ScanReport {
  return {
    target, scanDepth: "quick",
    startedAt: "2026-07-17T00:00:00Z", completedAt: "2026-07-17T00:00:01Z", durationMs: 1000,
    summary: { totalAttacks: 1, totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    findings: [finding], warnings: [],
  };
}

function target(location = "https://target.test"): LiveAgenticScanTarget {
  return {
    kind: "live.agentic-scan", id: "live", location,
    config: { options: { config: { target: "https://placeholder.test", depth: "quick", format: "json" } } },
  };
}

describe("LiveAgenticScanResearchAdapter", () => {
  it("wraps the native agentic scanner once and preserves its verified finding", async () => {
    const finding = {
      id: "live-f", templateId: "ssrf", title: "SSRF", description: "reproduced SSRF",
      severity: "high", category: "ssrf", status: "confirmed",
      evidence: { request: "GET /", response: "200" }, timestamp: 1,
    } as Finding;
    const scan = vi.fn(async () => reportWith(finding));
    const result = await runResearch(new LiveAgenticScanResearchAdapter(scan), target(), {
      artifactRoot: tmpRoot("pwnkit-live-"), runId: "live-run",
    });

    expect(scan).toHaveBeenCalledOnce();
    // location is the authoritative scan target; it overrides config.target.
    expect(scan.mock.calls[0][0].config.target).toBe("https://target.test");
    expect(result.findings[0].finding).toBe(finding);
    expect(result.envelopes[0].grade).toBe("observed");
  });

  it("keeps an unverified (discovered) finding at candidate grade", async () => {
    const finding = {
      id: "held", templateId: "cmd", title: "Held", description: "needs proof",
      severity: "high", category: "command-injection", status: "discovered",
      publishability: "needs_verify", evidence: { request: "", response: "" }, timestamp: 1,
    } as Finding;
    const result = await runResearch(new LiveAgenticScanResearchAdapter(async () => reportWith(finding)), target(), {
      artifactRoot: tmpRoot("pwnkit-live-held-"), runId: "held-run",
    });
    expect(result.envelopes[0]?.grade).toBe("candidate");
    expect(result.findings[0]?.evidence[0]?.status).toBe("inconclusive");
  });

  it("is reachable through the registry spine and delegates to the wrapped scanner", async () => {
    const finding = {
      id: "reg-f", templateId: "ssrf", title: "SSRF", description: "via registry",
      severity: "high", category: "ssrf", status: "confirmed",
      evidence: { request: "GET /", response: "200" }, timestamp: 1,
    } as Finding;
    const scan = vi.fn(async () => reportWith(finding));
    const registry = new ResearchAdapterRegistry()
      .register("live.agentic-scan", () => new LiveAgenticScanResearchAdapter(scan));

    const result = await registry.run(target(), { artifactRoot: tmpRoot("pwnkit-live-reg-"), runId: "reg-run" });

    expect(scan).toHaveBeenCalledOnce();
    expect(result.findings[0].finding).toBe(finding);
    expect(result.envelopes[0].grade).toBe("observed");
  });
});
