/**
 * Round-trip coverage for the two source-fix gate fields on `findings`:
 * `verification_result` and `reviewAnnotation`.
 *
 * Before these columns existed `saveFinding` silently dropped both, so every
 * finding reloaded from the local database reported "finding is not
 * reproduced" and the TUI `f` (source-fix) action could never run. The tests
 * below pin the three properties that matter:
 *
 *   1. a reproduced verification result survives a save/load cycle intact,
 *   2. absence stays absence — never `{}` or any other truthy stand-in
 *      (a false "reproduced" would let the fix action patch source for an
 *      unverified finding), and
 *   3. a database file created BEFORE the columns existed still opens,
 *      migrates, and reads back with both fields absent.
 */
import { describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding, VerificationResult } from "@0sec/shared";
import { osecDB, restoreFindingReviewFields } from "./database.js";
import { createShimmedDatabase } from "./wasm-shim.js";

function makeFinding(overrides?: Partial<Finding>): Finding {
  return {
    id: `f-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    templateId: "test",
    title: "test",
    description: "test desc",
    severity: "high",
    category: "xss",
    status: "discovered",
    evidence: { request: "req", response: "res" },
    timestamp: Date.now(),
    ...overrides,
  } as Finding;
}

function reproducedResult(findingId: string): VerificationResult {
  return {
    status: "reproduced",
    mode: "deterministic_replay",
    finding_id: findingId,
    engine_version: "0.0.0-test",
    started_at: "2026-08-22T00:00:00.000Z",
    completed_at: "2026-08-22T00:00:01.000Z",
    duration_ms: 1000,
    commands: [],
    assertions: [],
    evidence_artifacts: [],
    engine_metadata: { runner: "local" },
  } as unknown as VerificationResult;
}

function withTempDir(fn: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "0sec-db-review-fields-"));
  try {
    fn(dir);
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }
}

function withTempDb(fn: (db: osecDB) => void): void {
  withTempDir((dir) => {
    const db = new osecDB(join(dir, "test.db"));
    try {
      fn(db);
    } finally {
      db.close();
    }
  });
}

function seedScan(db: osecDB): string {
  return db.createScan({
    target: "https://example.com",
    depth: "full",
  } as unknown as Parameters<typeof db.createScan>[0]);
}

describe("findings.verificationResult round-trip", () => {
  it("preserves a reproduced verification result", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      const finding = makeFinding({ id: "f-vr-1" });
      db.saveFinding(scanId, {
        ...finding,
        verification_result: reproducedResult(finding.id),
      });

      const hydrated = db.getFindingReviewFields("f-vr-1");
      expect(hydrated.verification_result?.status).toBe("reproduced");
      expect(hydrated.verification_result?.finding_id).toBe("f-vr-1");
      expect(hydrated.verification_result?.mode).toBe("deterministic_replay");

      // The same hydration applies to rows coming off the list read path.
      const [row] = db.getScanFindings(scanId);
      expect(restoreFindingReviewFields(row).verification_result?.status).toBe("reproduced");
    });
  });

  it("preserves a non-reproduced status verbatim (no coercion to reproduced)", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      const finding = makeFinding({ id: "f-vr-2" });
      db.saveFinding(scanId, {
        ...finding,
        verification_result: {
          ...reproducedResult(finding.id),
          status: "not_reproduced",
        } as VerificationResult,
      });

      expect(db.getFindingReviewFields("f-vr-2").verification_result?.status).toBe("not_reproduced");
    });
  });

  it("round-trips a finding saved WITHOUT a verification result as absent", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      db.saveFinding(scanId, makeFinding({ id: "f-vr-3" }));

      const hydrated = db.getFindingReviewFields("f-vr-3");
      expect(hydrated.verification_result).toBeUndefined();
      // Absent means the key is not even present — `{}` (or any truthy empty
      // value) would let a consumer treat the finding as verified.
      expect("verification_result" in hydrated).toBe(false);
      expect(hydrated).toEqual({});

      // And the column itself is NULL, not the string "{}".
      const [row] = db.getScanFindings(scanId);
      expect(row.verificationResult).toBeNull();
    });
  });

  it("stores NULL for an empty / statusless verification result object", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      db.saveFinding(scanId, {
        ...makeFinding({ id: "f-vr-4" }),
        verification_result: {} as VerificationResult,
      });

      const [row] = db.getScanFindings(scanId);
      expect(row.verificationResult).toBeNull();
      expect(db.getFindingReviewFields("f-vr-4").verification_result).toBeUndefined();
    });
  });

  it("hydrates malformed JSON in the column as absent", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      db.saveFinding(scanId, makeFinding({ id: "f-vr-5" }));
      expect(
        restoreFindingReviewFields({ verificationResult: "{not json [" }).verification_result,
      ).toBeUndefined();
      expect(restoreFindingReviewFields({ verificationResult: "[]" }).verification_result).toBeUndefined();
      expect(restoreFindingReviewFields({ verificationResult: "" }).verification_result).toBeUndefined();
      expect(restoreFindingReviewFields({ verificationResult: null }).verification_result).toBeUndefined();
    });
  });

  it("updates the column when a finding is re-saved (upsert path)", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      const finding = makeFinding({ id: "f-vr-6" });
      db.saveFinding(scanId, finding);
      expect(db.getFindingReviewFields("f-vr-6").verification_result).toBeUndefined();

      db.saveFinding(scanId, {
        ...finding,
        verification_result: reproducedResult(finding.id),
      });
      expect(db.getFindingReviewFields("f-vr-6").verification_result?.status).toBe("reproduced");
    });
  });
});

describe("findings.reviewAnnotation round-trip", () => {
  it("preserves the scoped source reference including path", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      db.saveFinding(scanId, {
        ...makeFinding({ id: "f-ra-1" }),
        reviewAnnotation: {
          path: "src/parser.ts",
          startLine: 12,
          endLine: 18,
          suggestion: "escapeHtml(input)",
          knownMarker: true,
        },
      });

      const hydrated = db.getFindingReviewFields("f-ra-1");
      expect(hydrated.reviewAnnotation).toEqual({
        path: "src/parser.ts",
        startLine: 12,
        endLine: 18,
        suggestion: "escapeHtml(input)",
        knownMarker: true,
      });
      expect(hydrated.reviewAnnotation?.path).toBe("src/parser.ts");
    });
  });

  it("round-trips a finding saved WITHOUT an annotation as absent", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      db.saveFinding(scanId, makeFinding({ id: "f-ra-2" }));

      const hydrated = db.getFindingReviewFields("f-ra-2");
      expect(hydrated.reviewAnnotation).toBeUndefined();
      expect("reviewAnnotation" in hydrated).toBe(false);

      const [row] = db.getScanFindings(scanId);
      expect(row.reviewAnnotation).toBeNull();
    });
  });

  it("stores NULL for a pathless annotation and hydrates it as absent", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      db.saveFinding(scanId, {
        ...makeFinding({ id: "f-ra-3" }),
        reviewAnnotation: { startLine: 3 } as unknown as Finding["reviewAnnotation"],
      });

      const [row] = db.getScanFindings(scanId);
      expect(row.reviewAnnotation).toBeNull();
      expect(db.getFindingReviewFields("f-ra-3").reviewAnnotation).toBeUndefined();
    });
  });

  it("keeps both fields independent — one present, one absent", () => {
    withTempDb((db) => {
      const scanId = seedScan(db);
      const finding = makeFinding({ id: "f-ra-4" });
      db.saveFinding(scanId, {
        ...finding,
        verification_result: reproducedResult(finding.id),
      });

      const hydrated = db.getFindingReviewFields("f-ra-4");
      expect(hydrated.verification_result?.status).toBe("reproduced");
      expect(hydrated.reviewAnnotation).toBeUndefined();
    });
  });
});

describe("pre-migration database files", () => {
  /**
   * Build a database whose `findings` table predates verificationResult /
   * reviewAnnotation (the shape shipped alongside findingRank), insert a row,
   * then open it through the normal `osecDB` code path.
   */
  it("opens a database created without the new columns and reads absent values", () => {
    withTempDir((dir) => {
      const path = join(dir, "legacy.db");
      const legacy = createShimmedDatabase(path);
      legacy.exec(`
        CREATE TABLE scans (
          id TEXT PRIMARY KEY,
          target TEXT NOT NULL,
          depth TEXT NOT NULL,
          runtime TEXT NOT NULL DEFAULT 'api',
          mode TEXT NOT NULL DEFAULT 'probe',
          status TEXT NOT NULL DEFAULT 'running',
          startedAt TEXT NOT NULL,
          completedAt TEXT,
          durationMs INTEGER,
          summary TEXT
        );
        CREATE TABLE findings (
          id TEXT PRIMARY KEY,
          scanId TEXT NOT NULL REFERENCES scans(id),
          templateId TEXT NOT NULL,
          title TEXT NOT NULL,
          description TEXT NOT NULL,
          severity TEXT NOT NULL,
          category TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'discovered',
          fingerprint TEXT,
          triageStatus TEXT NOT NULL DEFAULT 'new',
          triageNote TEXT,
          triagedAt TEXT,
          workflowStatus TEXT NOT NULL DEFAULT 'backlog',
          workflowAssignee TEXT,
          workflowUpdatedAt TEXT,
          score INTEGER,
          confidence REAL,
          cvssVector TEXT,
          cvssScore REAL,
          evidenceRequest TEXT NOT NULL,
          evidenceResponse TEXT NOT NULL,
          evidenceAnalysis TEXT,
          layerVerdicts TEXT,
          impactAssessment TEXT,
          pocSteps TEXT,
          verificationSpec TEXT,
          pocExecution TEXT,
          semanticDedupe TEXT,
          findingRank INTEGER,
          timestamp INTEGER NOT NULL
        );
      `);
      legacy
        .prepare(
          "INSERT INTO scans (id, target, depth, startedAt) VALUES ('legacy-scan', 'https://example.com', 'full', '2026-01-01T00:00:00.000Z')",
        )
        .run();
      legacy
        .prepare(
          `INSERT INTO findings
             (id, scanId, templateId, title, description, severity, category, status,
              evidenceRequest, evidenceResponse, timestamp)
           VALUES ('legacy-finding', 'legacy-scan', 'test', 'Legacy', 'desc', 'high', 'xss',
                   'discovered', 'req', 'res', 1)`,
        )
        .run();
      // Sanity: the file really lacks the new columns before we open it.
      const legacyCols = new Set(
        (legacy.prepare("PRAGMA table_info(findings)").all() as { name: string }[]).map((c) => c.name),
      );
      expect(legacyCols.has("verificationResult")).toBe(false);
      expect(legacyCols.has("reviewAnnotation")).toBe(false);
      legacy.close();

      // Normal open path: must migrate rather than fail.
      const db = new osecDB(path);
      try {
        const rows = db.getScanFindings("legacy-scan");
        expect(rows.length).toBe(1);
        expect(rows[0].title).toBe("Legacy");
        expect(rows[0].verificationResult).toBeNull();
        expect(rows[0].reviewAnnotation).toBeNull();

        const hydrated = db.getFindingReviewFields("legacy-finding");
        expect(hydrated).toEqual({});
        expect(hydrated.verification_result).toBeUndefined();
        expect(hydrated.reviewAnnotation).toBeUndefined();

        // A migrated file also accepts writes to the new columns.
        db.saveFinding("legacy-scan", {
          ...makeFinding({ id: "legacy-finding-2" }),
          verification_result: reproducedResult("legacy-finding-2"),
          reviewAnnotation: { path: "src/a.ts", startLine: 1 },
        });
        const after = db.getFindingReviewFields("legacy-finding-2");
        expect(after.verification_result?.status).toBe("reproduced");
        expect(after.reviewAnnotation?.path).toBe("src/a.ts");
      } finally {
        db.close();
      }

      // And re-opening the now-migrated (newer) file still works.
      const reopened = new osecDB(path);
      try {
        expect(reopened.getFindingReviewFields("legacy-finding-2").verification_result?.status).toBe(
          "reproduced",
        );
        expect(reopened.getFindingReviewFields("legacy-finding")).toEqual({});
      } finally {
        reopened.close();
      }
    });
  });
});
