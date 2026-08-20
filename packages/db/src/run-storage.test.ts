import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { osecDB } from "./database.js";
import {
  listOsecRunDatabasePaths,
  resolveOsecRunStorage,
  writeOsecRunReport,
} from "./run-storage.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("run-scoped local storage", () => {
  it("gives concurrent executions independent SQLite state", () => {
    const homeDir = mkdtempSync(join(tmpdir(), "0sec-run-storage-"));
    temporaryDirectories.push(homeDir);

    const first = resolveOsecRunStorage({ homeDir, env: {} });
    const second = resolveOsecRunStorage({ homeDir, env: {} });
    expect(first.runId).not.toBe(second.runId);
    expect(first.dbPath).not.toBe(second.dbPath);

    const firstDb = new osecDB(first.dbPath);
    const secondDb = new osecDB(second.dbPath);
    try {
      firstDb.createScan({ target: "first", depth: "quick" }, first.runId);
      secondDb.createScan({ target: "second", depth: "quick" }, second.runId);

      expect(firstDb.getScan(first.runId)?.target).toBe("first");
      expect(firstDb.getScan(second.runId)).toBeUndefined();
      expect(secondDb.getScan(second.runId)?.target).toBe("second");
      expect(secondDb.getScan(first.runId)).toBeUndefined();
    } finally {
      firstDb.close();
      secondDb.close();
    }
    expect(listOsecRunDatabasePaths(homeDir).sort()).toEqual(
      [first.dbPath, second.dbPath].sort(),
    );
  });

  it("binds managed worker state to the orchestrator scan id", () => {
    const homeDir = mkdtempSync(join(tmpdir(), "0sec-managed-run-"));
    temporaryDirectories.push(homeDir);
    const runDir = join(homeDir, "sandbox-run");

    const storage = resolveOsecRunStorage({
      homeDir,
      env: {
        "0SEC_CLOUD_SCAN_ID": "scan-123",
        "0SEC_RUN_DIR": runDir,
        "0SEC_DB_PATH": join(runDir, "state.sqlite"),
        "0SEC_REPORT_PATH": join(runDir, "final.json"),
      },
    });

    expect(storage).toEqual({
      runId: "scan-123",
      runDir,
      dbPath: join(runDir, "state.sqlite"),
      reportPath: join(runDir, "final.json"),
    });
  });

  it("resolves an unambiguous abbreviated run id for resume", () => {
    const homeDir = mkdtempSync(join(tmpdir(), "0sec-resume-storage-"));
    temporaryDirectories.push(homeDir);
    const original = resolveOsecRunStorage({
      homeDir,
      runId: "b5c81eb2-6d4e-4c8f-9b1c-7dca7c0c0a11",
      env: {},
    });
    const db = new osecDB(original.dbPath);
    try {
      db.createScan({ target: "resumable", depth: "quick" }, original.runId);
    } finally {
      db.close();
    }

    const resumed = resolveOsecRunStorage({
      homeDir,
      runId: original.runId.slice(0, 8),
      resume: true,
      env: {},
    });
    expect(resumed.runId).toBe(original.runId);
    expect(resumed.dbPath).toBe(original.dbPath);
  });

  it("commits final reports atomically with owner-only permissions", () => {
    const homeDir = mkdtempSync(join(tmpdir(), "0sec-report-storage-"));
    temporaryDirectories.push(homeDir);
    const storage = resolveOsecRunStorage({ homeDir, runId: "report-1", env: {} });

    writeOsecRunReport(storage, { findings: [{ id: "f-1" }], complete: true });
    const reportPath = storage.reportPath;
    if (!reportPath) throw new Error("run storage did not allocate a report path");

    expect(JSON.parse(readFileSync(reportPath, "utf8"))).toEqual({
      findings: [{ id: "f-1" }],
      complete: true,
    });
    expect(statSync(reportPath).mode & 0o777).toBe(0o600);
  });
});
