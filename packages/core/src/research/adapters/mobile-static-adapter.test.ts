import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { MobileStaticIntakeReport } from "../../mobile/intake.js";
import { runResearch } from "../research-runner.js";
import { MobileStaticResearchAdapter, type MobileStaticTarget } from "./mobile-static-adapter.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

const report: MobileStaticIntakeReport = {
  target: "/app",
  platform: "android",
  summary: { endpointCount: 2, backendCandidateCount: 2, highPriorityEndpoints: 1, mediumPriorityEndpoints: 1, lowPriorityEndpoints: 0, riskCount: 1 },
  endpoints: [],
  backendCandidates: [
    { value: "https://api.example.test", kind: "url", sources: ["a.xml"], priority: "high", tags: [], scope: { allowed: true, reason: "engagement scope" } },
    { value: "outside.test", kind: "host", sources: ["a.xml"], priority: "medium", tags: [], scope: { allowed: false, reason: "out of scope" } },
  ],
  risks: [{ id: "exported", severity: "medium", title: "Exported component", evidence: ["MainActivity"] }],
  warnings: [],
};

describe("MobileStaticResearchAdapter", () => {
  it("derives only explicitly in-scope backend targets and never promotes passive indicators", async () => {
    const target: MobileStaticTarget = { kind: "mobile.static-intake", id: "app", location: "/app", config: {} };
    const artifactRoot = mkdtempSync(join(tmpdir(), "pwnkit-mobile-"));
    roots.push(artifactRoot);
    const result = await runResearch(new MobileStaticResearchAdapter(() => report), target, { artifactRoot, runId: "mobile-run" });

    expect(result.candidates).toHaveLength(3);
    expect(result.handoffs).toHaveLength(1);
    expect(result.handoffs[0].target).toMatchObject({ kind: "web.http", location: "https://api.example.test" });
    expect(result.findings).toHaveLength(0);
    expect(result.evidence.some((e) => e.stage === "verify" && e.status === "inconclusive")).toBe(true);
  });
});
