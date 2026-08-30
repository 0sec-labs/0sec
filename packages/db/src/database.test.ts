import { describe, expect, it, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { Finding } from "@0sec/shared";
import { osecDB } from "./database.js";

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

function withTempDb(fn: (db: osecDB, cleanup: () => void) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "0sec-db-test-"));
  const clean = () => {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  };
  const db = new osecDB(join(dir, "test.db"));
  try {
    fn(db, clean);
    clean();
  } catch (e) {
    clean();
    throw e;
  }
}

describe("osecDB read-only open", () => {
  it("reads an existing database without running the writer initialization path", () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-db-read-only-"));
    const path = join(dir, "test.db");
    const writer = new osecDB(path);
    let reader: osecDB | undefined;
    try {
      const scanId = writer.createScan({
        target: "https://example.com",
        depth: "default",
      } as Parameters<typeof writer.createScan>[0]);
      writer.saveFinding(scanId, makeFinding({ id: "read-only-finding" }));

      reader = new osecDB(path, { readOnly: true });
      expect(reader.getFinding("read-only-finding")?.id).toBe("read-only-finding");
    } finally {
      reader?.close();
      writer.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses to create a missing database in read-only mode", () => {
    const dir = mkdtempSync(join(tmpdir(), "0sec-db-read-only-"));
    try {
      expect(() => new osecDB(join(dir, "missing.db"), { readOnly: true }))
        .toThrow("Database does not exist");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("osecDB listScansByTarget", () => {
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

describe("osecDB getScanFindings", () => {
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

describe("osecDB presentation event cursor", () => {
  it("persists provenance and reads strictly after a timestamp/id cursor", () => {
    withTempDb((db) => {
      const scanId = db.createScan({
        target: "https://example.test",
        depth: "quick",
      } as Parameters<typeof db.createScan>[0]);
      for (const [eventType, timestamp, source] of [
        ["tool_call_started", 100, "core"],
        ["tool_call_completed", 100, "cli"],
        ["finding_ingested", 101, "adapter"],
      ] as const) {
        db.logEvent({
          scanId,
          stage: "discovery",
          eventType,
          payload: { eventType },
          timestamp,
          source,
        });
      }

      const all = db.listEventsAfter(undefined, 10);
      expect(all).toHaveLength(3);
      expect(all.map((event) => event.source).sort()).toEqual(["adapter", "cli", "core"]);

      const cursor = { timestamp: all[0]!.timestamp, id: all[0]!.id };
      const after = db.listEventsAfter(cursor, 10);
      expect(after.map((event) => event.id)).toEqual(all.slice(1).map((event) => event.id));
    });
  });
});