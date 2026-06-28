import { describe, expect, it } from "vitest";
import type { ScanReport } from "@pwnkit/shared";
import { formatSarif } from "./sarif.js";

describe("formatSarif", () => {
  it("emits GitHub Code Security metadata for PoC-backed findings", () => {
    const report: ScanReport = {
      target: "pkg/file.ts",
      scanDepth: "deep",
      startedAt: "2026-06-28T18:00:00.000Z",
      completedAt: "2026-06-28T18:01:00.000Z",
      durationMs: 60_000,
      warnings: [],
      summary: {
        totalAttacks: 1,
        totalFindings: 1,
        critical: 0,
        high: 1,
        medium: 0,
        low: 0,
        info: 0,
      },
      findings: [
        {
          id: "finding-1",
          templateId: "pwnkit:path-traversal",
          title: "Path traversal reads secrets",
          description: "A crafted path reads /etc/passwd.",
          severity: "high",
          category: "path-traversal",
          status: "confirmed",
          fingerprint: "stable-fp",
          confidence: 0.97,
          evidence: {
            request: "GET /download?file=../../etc/passwd",
            response: "root:x:0:0",
            analysis: "PoC reproduced in the target harness.",
          },
          pocSteps: [
            {
              id: "exploit",
              kind: "exploit",
              summary: "Request traversal payload",
              action: {
                type: "http",
                method: "GET",
                url: "https://example.test/download?file=../../etc/passwd",
              },
              expect: { type: "body-contains", text: "root:x:0:0" },
            },
          ],
          verification_result: {
            status: "reproduced",
            mode: "deterministic_replay",
            finding_id: "finding-1",
            engine_version: "0.12.0",
            started_at: "2026-06-28T18:00:00.000Z",
            completed_at: "2026-06-28T18:00:30.000Z",
            duration_ms: 30_000,
            commands: [],
            assertions: [],
            evidence_artifacts: [],
            engine_metadata: { os: "linux", arch: "x64", runner: "local" },
          },
          timestamp: 1_800_000_000_000,
        },
      ],
    };

    const sarif = JSON.parse(formatSarif(report));
    const result = sarif.runs[0].results[0];

    expect(sarif.version).toBe("2.1.0");
    expect(result.partialFingerprints.primary).toBe("stable-fp|pwnkit:path-traversal|path-traversal|Path traversal reads secrets|pkg/file.ts");
    expect(result.properties.evidence.request).toContain("../../etc/passwd");
    expect(result.properties.verificationResult.status).toBe("reproduced");
    expect(result.codeFlows[0].threadFlows[0].locations[0].location.message.text).toBe("exploit: Request traversal payload");
    expect(result.codeFlows[0].threadFlows[0].locations[0].location.properties.action).toMatchObject({
      type: "http",
      method: "GET",
    });
  });
});
