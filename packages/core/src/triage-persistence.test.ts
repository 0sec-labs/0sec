import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { osecDB } from "@0sec/db";
import type { Finding, PocStep, ScanConfig } from "@0sec/shared";

const tempDirs: string[] = [];

function makeDb(): { db: osecDB; scanId: string } {
  const dir = mkdtempSync(join(tmpdir(), "0sec-triage-persist-"));
  tempDirs.push(dir);
  const db = new osecDB(join(dir, "0sec.db"));
  const scanConfig: ScanConfig = {
    target: "http://example.test",
    depth: "default",
    format: "json",
    runtime: "api",
    mode: "deep",
  };
  const scanId = db.createScan(scanConfig);
  return { db, scanId };
}

function makeFinding(): Finding {
  return {
    id: randomUUID(),
    templateId: "manual",
    title: "Reflected XSS",
    description: "raw finding",
    severity: "high",
    category: "xss",
    status: "discovered",
    evidence: {
      request: "POST /page",
      response: "<script>alert(1)</script>",
      analysis: "initial evidence",
    },
    timestamp: Date.now(),
  };
}

describe("triage persistence", () => {
  afterEach(() => {
    for (const dir of tempDirs.splice(0)) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("persists triage fields when a finding is re-saved after triage", () => {
    const { db, scanId } = makeDb();
    try {
      const finding = makeFinding();
      db.saveFinding(scanId, finding);

      finding.severity = "info";
      finding.status = "false-positive";
      finding.triageStatus = "suppressed";
      finding.triageNote = "rejected: holding-it-wrong";
      finding.evidence.analysis = "updated after triage";

      db.saveFinding(scanId, finding);

      const persisted = db.getFinding(finding.id);
      expect(persisted?.severity).toBe("info");
      expect(persisted?.status).toBe("false-positive");
      expect(persisted?.triageStatus).toBe("suppressed");
      expect(persisted?.triageNote).toBe("rejected: holding-it-wrong");
      expect(persisted?.evidenceAnalysis).toBe("updated after triage");
      expect(persisted?.triagedAt).toBeTruthy();
    } finally {
      db.close();
    }
  });

  // 0sec#170 — PoC step graph DB round-trip.
  //
  // Findings can carry an optional `pocSteps` field. The DB persists it as a
  // JSON-stringified blob in a new `pocSteps` text column. Round-trip must be
  // byte-identical for save → read, and findings without the field must keep
  // working unchanged (the column is NULL).
  it("persists pocSteps as JSON and reads it back byte-identically", () => {
    const { db, scanId } = makeDb();
    try {
      const steps: PocStep[] = [
        {
          id: "setup",
          kind: "setup",
          summary: "Boot target in docker",
          action: { type: "shell", cmd: "docker run vuln" },
          expect: { type: "exit-zero" },
        },
        {
          id: "exp",
          kind: "exploit",
          summary: "Trigger SQLi",
          action: {
            type: "http",
            method: "POST",
            url: "http://localhost/login",
            body: "user=' OR 1=1--",
          },
          expect: { type: "http-status", status: [200, 302] },
        },
      ];
      const finding = makeFinding();
      finding.pocSteps = steps;
      db.saveFinding(scanId, finding);

      const persisted = db.getFinding(finding.id) as { pocSteps: string | null } | undefined;
      expect(persisted?.pocSteps).toBeTruthy();
      // Byte-identical persistence: the column stores exactly JSON.stringify(steps),
      // so disclosure replay can fingerprint by hash without reserializing.
      expect(persisted!.pocSteps).toBe(JSON.stringify(steps));
      // Stored as JSON text — round-trip parses to the original array.
      const restored = JSON.parse(persisted!.pocSteps as string);
      expect(restored).toEqual(steps);
    } finally {
      db.close();
    }
  });

  it("leaves pocSteps NULL on findings that don't carry a step graph", () => {
    const { db, scanId } = makeDb();
    try {
      const finding = makeFinding();
      // Intentionally NOT setting pocSteps. The legacy prose-only path must
      // keep working; the DB column should be NULL.
      db.saveFinding(scanId, finding);

      const persisted = db.getFinding(finding.id) as { pocSteps: string | null } | undefined;
      expect(persisted?.pocSteps ?? null).toBeNull();
    } finally {
      db.close();
    }
  });
});
