import { describe, expect, it, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding } from "@pwnkit/shared";
import { pwnkitDB } from "./database.js";

function makeFinding(overrides?: Partial<Finding>): Finding {
  return {
    id: overrides?.id ?? `f-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    templateId: overrides?.templateId ?? "test",
    title: overrides?.title ?? "test",
    description: overrides?.description ?? "test desc",
    severity: overrides?.severity ?? "high",
    category: overrides?.category ?? "xss",
    status: overrides?.status ?? "discovered",
    evidence: overrides?.evidence ?? { request: "req", response: "res" },
    timestamp: overrides?.timestamp ?? Date.now(),
  };
}

function withTempDb(fn: (db: pwnkitDB, cleanup: () => void) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "pwnkit-db-test-"));
  const clean = () => {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  };
  const db = new pwnkitDB(join(dir, "test.db"));
  try {
    fn(db, clean);
    clean();
  } catch (e) {
    clean();
    throw e;
  }
}

describe("pwnkitDB listScansByTarget", () => {
  it("returns scans for the matching target ordered desc(startedAt)", () => {
    withTempDb((db) => {
      const s1 = db.createScan({
        target: "https://example.com",
        depth: "full",
      } as Parameters<typeof db.createScan>[0]);
      // Small delay so timestamps differ
      const s2 = db.createScan({
        target: "https://example.com",
        depth: "probe",
      } as Parameters<typeof db.createScan>[0]);
      // Different target — should not appear
      db.createScan({
        target: "https://other.com",
        depth: "probe",
      } as Parameters<typeof db.createScan>[0]);

      const results = db.listScansByTarget("https://example.com");
      expect(results.length).toBe(2);
      // Most recent first (desc startedAt)
      expect(results[0].id).toBe(s2);
      expect(results[1].id).toBe(s1);
      expect(results[0].target).toBe("https://example.com");
      expect(results[0].status).toBe("running");
    });
  });

  it("excludes other targets", () => {
    withTempDb((db) => {
      db.createScan({
        target: "https://example.com",
        depth: "full",
      } as Parameters<typeof db.createScan>[0]);
      db.createScan({
        target: "https://other.com",
        depth: "probe",
      } as Parameters<typeof db.createScan>[0]);

      const results = db.listScansByTarget("https://example.com");
      expect(results.length).toBe(1);
      expect(results[0].target).toBe("https://example.com");
    });
  });

  it("honours limit option", () => {
    withTempDb((db) => {
      // Create 3 scans for the same target
      for (let i = 0; i < 3; i++) {
        db.createScan({
          target: "https://example.com",
          depth: "probe",
        } as Parameters<typeof db.createScan>[0]);
      }

      const results = db.listScansByTarget("https://example.com", { limit: 2 });
      expect(results.length).toBe(2);
    });
  });

  it("returns empty array when no scans match", () => {
    withTempDb((db) => {
      db.createScan({
        target: "https://example.com",
        depth: "probe",
      } as Parameters<typeof db.createScan>[0]);

      const results = db.listScansByTarget("https://nonexistent.com");
      expect(results).toEqual([]);
    });
  });
});

describe("pwnkitDB getScanFindings", () => {
  it("returns findings for a given scan", () => {
    withTempDb((db) => {
      const scanId = db.createScan({
        target: "https://example.com",
        depth: "full",
      } as Parameters<typeof db.createScan>[0]);

      db.saveFinding(scanId, makeFinding({ id: "f-1", title: "Test Finding" }));

      const findings = db.getScanFindings(scanId);
      expect(findings.length).toBe(1);
      expect(findings[0].title).toBe("Test Finding");
    });
  });

  it("returns empty array when scan has no findings", () => {
    withTempDb((db) => {
      const scanId = db.createScan({
        target: "https://example.com",
        depth: "probe",
      } as Parameters<typeof db.createScan>[0]);

      const findings = db.getScanFindings(scanId);
      expect(findings).toEqual([]);
    });
  });
});