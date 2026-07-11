import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import type { PipelineReport } from "../../unified-pipeline.js";
import { runResearch } from "../research-runner.js";
import { UnifiedPipelineResearchAdapter, type UnifiedPipelineTarget } from "./unified-pipeline-adapter.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe("UnifiedPipelineResearchAdapter", () => {
  it("wraps the native web/AI/source pipeline once and preserves its finding", async () => {
    const finding = {
      id: "web-f", templateId: "ssrf", title: "SSRF", description: "reproduced SSRF",
      severity: "high", category: "ssrf", status: "confirmed",
      evidence: { request: "GET /", response: "200" }, timestamp: 1,
    } as Finding;
    const report: PipelineReport = {
      target: "https://target.test", targetType: "web-app",
      startedAt: "2026-07-11T00:00:00Z", completedAt: "2026-07-11T00:00:01Z", durationMs: 1000,
      summary: { totalAttacks: 1, totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      findings: [finding], warnings: [],
    };
    const pipeline = vi.fn(async () => report);
    const target: UnifiedPipelineTarget = {
      kind: "pipeline.unified", id: "web", location: report.target,
      config: { options: { targetType: "web-app", depth: "quick", format: "json" } },
    };
    const artifactRoot = mkdtempSync(join(tmpdir(), "pwnkit-unified-"));
    roots.push(artifactRoot);
    const result = await runResearch(new UnifiedPipelineResearchAdapter(pipeline), target, { artifactRoot, runId: "pipeline-run" });

    expect(pipeline).toHaveBeenCalledOnce();
    expect(result.findings[0].finding).toBe(finding);
    expect(result.envelopes[0].grade).toBe("observed");
  });

  it("keeps a needs-verify retained finding at candidate grade", async () => {
    const finding = {
      id: "held", templateId: "cmd", title: "Held", description: "needs proof",
      severity: "high", category: "command-injection", status: "discovered",
      publishability: "needs_verify", evidence: { request: "", response: "" }, timestamp: 1,
    } as Finding;
    const report = {
      target: "/src", targetType: "source-code", startedAt: "2026-07-11T00:00:00Z",
      completedAt: "2026-07-11T00:00:01Z", durationMs: 1,
      summary: { totalAttacks: 1, totalFindings: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      findings: [finding], warnings: [],
    } as PipelineReport;
    const root = mkdtempSync(join(tmpdir(), "pwnkit-unified-held-"));
    roots.push(root);
    const result = await runResearch(new UnifiedPipelineResearchAdapter(async () => report), {
      kind: "pipeline.unified", id: "held", location: "/src",
      config: { options: { targetType: "source-code", depth: "quick", format: "json" } },
    }, { artifactRoot: root, runId: "held-run" });
    expect(result.envelopes[0]?.grade).toBe("candidate");
    expect(result.findings[0]?.evidence[0]?.status).toBe("inconclusive");
  });
});
