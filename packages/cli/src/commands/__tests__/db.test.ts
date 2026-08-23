/**
 * Coverage seed for `0sec-cli`'s `db` command. This is the local SQLite
 * management surface — `0sec db reset` (destructive: deletes the local
 * DB + reseeds the verification workbench) and `0sec db repair` (backs
 * up a malformed file and recreates a clean one). Both call into
 * `@0sec/db` (WASM SQLite per memory `project_db_wasm` — we never want
 * to touch a real DB from a unit test).
 *
 * Strategy: mock the `@0sec/db` boundary with a chatty fake that records
 * every method call db.ts makes (saveFinding, upsertWorkItem, addVerdict,
 * etc.), register the command on a fresh Commander program, and drive
 * `parseAsync` with the argv the operator would type. The `seedVerificationWorkbench`
 * helper is also exported, so we exercise it directly to assert the
 * fixture wiring (number of scans / families / verdicts) without paying
 * the Commander round-trip.
 *
 * What's covered:
 *   • `db reset` happy path (default seed=verification)
 *   • `db reset --seed empty` (no fixture written, but DB still created+closed)
 *   • `db reset --seed bogus` rejected with a clear error
 *   • `db reset --db-path` threaded through to `resetOsecDatabase`
 *     AND `new osecDB(opts.dbPath)`
 *   • `db reset` always closes the DB in `finally` even when the seed
 *     helper throws (no leaked handle — load-bearing for the WASM
 *     migration window)
 *   • `db repair` happy path (no backupPath)
 *   • `db repair` with a backupPath logs the backup line
 *   • `db repair --db-path` threaded through to `repairOsecDatabase`
 *   • `seedVerificationWorkbench` writes the expected fixture shape
 *     (4 scans, 8 families, work items + artifacts per family,
 *     verdicts on the families that have them, events for every step)
 *
 * Out of scope (note in PR body):
 *   • Anything that requires opening real WASM SQLite — file I/O,
 *     PRAGMA quick_check, migrateWalHeaderIfNeeded — is exercised by
 *     `packages/db/src/wasm-shim.test.ts` and the database tests.
 *     Here the entire `@0sec/db` module is mocked.
 *   • The chalk-coloured stdout banner is not asserted exactly — we
 *     only assert the substrings that downstream parsing/relays rely on.
 *
 * Precedent: PR #307 (`disclose.test.ts`) and PR #301 (`run.test.ts` +
 * `scan.test.ts`).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Command } from "commander";

// ── Module-level mocks ──────────────────────────────────────────────────────
//
// db.ts imports `osecDB`, `repairOsecDatabase`, and `resetOsecDatabase`
// statically from `@0sec/db`. Vitest hoists `vi.mock`, so the static
// imports resolve to our stub.

interface DbCall {
  method: string;
  args: unknown[];
}

const dbState: {
  instances: number;
  lastConstructorArg: string | undefined;
  calls: DbCall[];
  closed: boolean;
  scanIdCounter: number;
} = {
  instances: 0,
  lastConstructorArg: undefined,
  calls: [],
  closed: false,
  scanIdCounter: 0,
};

const resetOsecDatabaseMock = vi.fn();
const repairOsecDatabaseMock = vi.fn();

vi.mock("@0sec/db", () => {
  class FakeOsecDB {
    constructor(dbPath?: string) {
      dbState.instances += 1;
      dbState.lastConstructorArg = dbPath;
      dbState.closed = false;
    }
    createScan(config: unknown): string {
      dbState.scanIdCounter += 1;
      const id = `scan-${dbState.scanIdCounter}`;
      dbState.calls.push({ method: "createScan", args: [config, id] });
      return id;
    }
    completeScan(scanId: string, summary: unknown): void {
      dbState.calls.push({ method: "completeScan", args: [scanId, summary] });
    }
    getScan(scanId: string): { id: string; target: string } | null {
      dbState.calls.push({ method: "getScan", args: [scanId] });
      return { id: scanId, target: `target-for-${scanId}` };
    }
    saveFinding(scanId: string, finding: unknown): void {
      dbState.calls.push({ method: "saveFinding", args: [scanId, finding] });
    }
    updateFindingWorkflowByFingerprint(
      fingerprint: string,
      status: string,
      assignee: string | null,
    ): void {
      dbState.calls.push({
        method: "updateFindingWorkflowByFingerprint",
        args: [fingerprint, status, assignee],
      });
    }
    upsertWorkItem(record: unknown): void {
      dbState.calls.push({ method: "upsertWorkItem", args: [record] });
    }
    upsertArtifact(record: unknown): void {
      dbState.calls.push({ method: "upsertArtifact", args: [record] });
    }
    saveSession(session: unknown): void {
      dbState.calls.push({ method: "saveSession", args: [session] });
    }
    addVerdict(verdict: unknown): void {
      dbState.calls.push({ method: "addVerdict", args: [verdict] });
    }
    logEvent(event: unknown): string {
      dbState.calls.push({ method: "logEvent", args: [event] });
      return "evt-id";
    }
    close(): void {
      dbState.closed = true;
      dbState.calls.push({ method: "close", args: [] });
    }
  }
  return {
    osecDB: FakeOsecDB,
    repairOsecDatabase: repairOsecDatabaseMock,
    resetOsecDatabase: resetOsecDatabaseMock,
  };
});

const { registerDbCommand, seedVerificationWorkbench } = await import("../db.js");

// ── Helpers ─────────────────────────────────────────────────────────────────

async function runCli(argv: string[]): Promise<unknown> {
  const program = new Command();
  program.exitOverride();
  program.configureOutput({
    writeOut: () => undefined,
    writeErr: () => undefined,
  });
  registerDbCommand(program);
  try {
    await program.parseAsync(["node", "0sec-cli", ...argv]);
    return null;
  } catch (err) {
    // The `db reset --seed bogus` path throws an Error from inside
    // the .action handler; commander surfaces it via parseAsync. We
    // return it so individual tests can assert on the message.
    return err;
  }
}

function callsByMethod(method: string): DbCall[] {
  return dbState.calls.filter((c) => c.method === method);
}

let logSpy: ReturnType<typeof vi.spyOn>;
let errSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  dbState.instances = 0;
  dbState.lastConstructorArg = undefined;
  dbState.calls = [];
  dbState.closed = false;
  dbState.scanIdCounter = 0;

  resetOsecDatabaseMock.mockReset().mockReturnValue("/fake/0sec.db");
  repairOsecDatabaseMock
    .mockReset()
    .mockReturnValue({ path: "/fake/0sec.db" });

  logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
  errSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  logSpy.mockRestore();
  errSpy.mockRestore();
});

// ── Tests: `db reset` ───────────────────────────────────────────────────────

describe("db reset — destructive happy path", () => {
  it("default seed=verification: calls resetOsecDatabase, opens a fresh osecDB, seeds, closes", async () => {
    const err = await runCli(["db", "reset"]);
    expect(err).toBeNull();

    // 1) DB on disk wiped.
    expect(resetOsecDatabaseMock).toHaveBeenCalledOnce();
    expect(resetOsecDatabaseMock).toHaveBeenCalledWith(undefined);

    // 2) A fresh in-process handle was created (with no override path).
    expect(dbState.instances).toBe(1);
    expect(dbState.lastConstructorArg).toBeUndefined();

    // 3) The seed actually ran — verification fixture has 4 scans.
    expect(callsByMethod("createScan").length).toBe(4);
    expect(callsByMethod("saveFinding").length).toBeGreaterThan(0);

    // 4) Always closed in finally.
    expect(dbState.closed).toBe(true);

    // 5) The summary line surfaces the seed counts for relay consumers.
    const out = logSpy.mock.calls.map((c: unknown[]) => String(c[0])).join("\n");
    expect(out).toMatch(/db reset/);
    expect(out).toMatch(/seed: verification/);
    expect(out).toMatch(/scans: 4/);
  });

  it("--seed empty: still wipes + opens + closes, but writes no fixture rows", async () => {
    const err = await runCli(["db", "reset", "--seed", "empty"]);
    expect(err).toBeNull();

    expect(resetOsecDatabaseMock).toHaveBeenCalledOnce();
    expect(dbState.instances).toBe(1);
    expect(dbState.closed).toBe(true);

    // No fixture rows written.
    expect(callsByMethod("createScan")).toHaveLength(0);
    expect(callsByMethod("saveFinding")).toHaveLength(0);
    expect(callsByMethod("addVerdict")).toHaveLength(0);

    const out = logSpy.mock.calls.map((c: unknown[]) => String(c[0])).join("\n");
    expect(out).toMatch(/seed: empty/);
    expect(out).toMatch(/scans: 0/);
  });

  it("--seed verification (explicit, lowercased) also routes to the fixture", async () => {
    const err = await runCli(["db", "reset", "--seed", "VERIFICATION"]);
    expect(err).toBeNull();
    // Case-insensitive normalisation happens before the gate.
    expect(callsByMethod("createScan").length).toBe(4);
  });

  it("--seed bogus is rejected before opening a DB handle", async () => {
    const err = await runCli(["db", "reset", "--seed", "bogus"]);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/Unsupported seed preset: bogus/);

    // We bail BEFORE wiping the DB or constructing osecDB — preserves
    // the "type the wrong thing, lose no data" invariant.
    expect(resetOsecDatabaseMock).not.toHaveBeenCalled();
    expect(dbState.instances).toBe(0);
  });

  it("--db-path is threaded into both resetOsecDatabase and the osecDB constructor", async () => {
    const err = await runCli([
      "db",
      "reset",
      "--db-path",
      "/tmp/custom-0sec.db",
      "--seed",
      "empty",
    ]);
    expect(err).toBeNull();
    expect(resetOsecDatabaseMock).toHaveBeenCalledWith("/tmp/custom-0sec.db");
    expect(dbState.lastConstructorArg).toBe("/tmp/custom-0sec.db");
  });

  it("closes the DB even if the seed helper throws (no leaked handle)", async () => {
    // Make `getScan` (the first thing every family calls) throw, so the
    // seed loop dies mid-way and the `finally` is the only path to close().
    const originalGetScan = (
      await import("@0sec/db")
    ).osecDB.prototype.getScan;
    const seedExplosion = new Error("boom mid-seed");
    (
      await import("@0sec/db")
    ).osecDB.prototype.getScan = function getScanSpy(): never {
      throw seedExplosion;
    };

    try {
      const err = await runCli(["db", "reset"]);
      expect(err).toBeInstanceOf(Error);
      // finally-closed even though the action threw.
      expect(dbState.closed).toBe(true);
    } finally {
      (
        await import("@0sec/db")
      ).osecDB.prototype.getScan = originalGetScan;
    }
  });
});

// ── Tests: `db repair` ──────────────────────────────────────────────────────

describe("db repair", () => {
  it("happy path: calls repairOsecDatabase and logs the resulting path", async () => {
    repairOsecDatabaseMock.mockReturnValueOnce({ path: "/fake/0sec.db" });
    const err = await runCli(["db", "repair"]);
    expect(err).toBeNull();
    expect(repairOsecDatabaseMock).toHaveBeenCalledOnce();
    expect(repairOsecDatabaseMock).toHaveBeenCalledWith(undefined);

    const out = logSpy.mock.calls.map((c: unknown[]) => String(c[0])).join("\n");
    expect(out).toMatch(/db repair/);
    expect(out).toMatch(/\/fake\/0sec\.db/);
    // No backupPath means no `backup:` line.
    expect(out).not.toMatch(/backup:/);
  });

  it("logs a `backup:` line when repair quarantined a corrupt file", async () => {
    repairOsecDatabaseMock.mockReturnValueOnce({
      path: "/fake/0sec.db",
      backupPath: "/fake/0sec.db.corrupt-2026-05-13",
    });
    const err = await runCli(["db", "repair"]);
    expect(err).toBeNull();

    const out = logSpy.mock.calls.map((c: unknown[]) => String(c[0])).join("\n");
    expect(out).toMatch(/backup: \/fake\/0sec\.db\.corrupt-2026-05-13/);
  });

  it("--db-path is threaded through to repairOsecDatabase", async () => {
    const err = await runCli([
      "db",
      "repair",
      "--db-path",
      "/tmp/custom-0sec.db",
    ]);
    expect(err).toBeNull();
    expect(repairOsecDatabaseMock).toHaveBeenCalledWith("/tmp/custom-0sec.db");
  });

  it("does NOT open a osecDB handle from the CLI layer (repair owns the open/close)", async () => {
    // `repairOsecDatabase` internally opens + closes the DB to verify
    // healthiness — but the CLI action itself should not also new up a
    // osecDB instance after the call (would double-close). This is a
    // regression guard for that contract.
    const err = await runCli(["db", "repair"]);
    expect(err).toBeNull();
    expect(dbState.instances).toBe(0);
  });
});

// ── Tests: `seedVerificationWorkbench` direct ───────────────────────────────
//
// The helper is exported, so we exercise it directly with a fake DB to
// assert the fixture shape end-to-end (no Commander round-trip).

describe("seedVerificationWorkbench — fixture shape", () => {
  it("returns the documented {scans, families, workers} counts", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    const result = seedVerificationWorkbench(db as never);
    expect(result.scans).toBe(4);
    expect(result.families).toBe(8);
    expect(result.workers).toBe(0);
  });

  it("creates a scan per scan-key and completes each one with a summary", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    seedVerificationWorkbench(db as never);

    expect(callsByMethod("createScan")).toHaveLength(4);
    expect(callsByMethod("completeScan")).toHaveLength(4);
  });

  it("writes one saveFinding + one workflow update per family (8 families)", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    seedVerificationWorkbench(db as never);

    expect(callsByMethod("saveFinding")).toHaveLength(8);
    expect(callsByMethod("updateFindingWorkflowByFingerprint")).toHaveLength(8);
  });

  it("writes 6 work items per family (one per pipeline kind) — 48 total", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    seedVerificationWorkbench(db as never);

    // Each family has exactly 6 workItems entries in the fixture
    // (surface_map, hypothesis, poc_build, blind_verify, consensus, human_review).
    expect(callsByMethod("upsertWorkItem")).toHaveLength(8 * 6);
  });

  it("writes one runbook artifact per family", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    seedVerificationWorkbench(db as never);
    expect(callsByMethod("upsertArtifact")).toHaveLength(8);
  });

  it("only emits saveSession for families that declare a `session` block", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    seedVerificationWorkbench(db as never);

    // Inspecting the fixture in db.ts: exactly one family declares a
    // session (the `example-active` prompt-injection one).
    expect(callsByMethod("saveSession")).toHaveLength(1);
  });

  it("emits addVerdict only for families with verdicts (not all 8)", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    seedVerificationWorkbench(db as never);

    // CORS reflection (2) + indirect prompt injection (2) + mcp tool exposure (1)
    // + mcp ssrf FP (1) + cross-tenant memory (1) = 7 verdicts total.
    expect(callsByMethod("addVerdict")).toHaveLength(7);
  });

  it("rewrites verdict.findingId to the parent finding.id before persisting", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    seedVerificationWorkbench(db as never);

    // The fixture defines verdicts with `findingId: ""` then the loop
    // rewrites them to family.finding.id. None of the saved verdicts
    // should end up with the empty placeholder.
    const verdictCalls = callsByMethod("addVerdict");
    for (const call of verdictCalls) {
      const v = call.args[0] as { findingId: string };
      expect(v.findingId).not.toBe("");
      expect(v.findingId.length).toBeGreaterThan(0);
    }
  });

  it("logs `finding_seeded` + `work_item_seeded` events for every family", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    seedVerificationWorkbench(db as never);

    const events = callsByMethod("logEvent");
    const findingSeeded = events.filter(
      (e) => (e.args[0] as { eventType: string }).eventType === "finding_seeded",
    );
    const workItemSeeded = events.filter(
      (e) => (e.args[0] as { eventType: string }).eventType === "work_item_seeded",
    );
    expect(findingSeeded).toHaveLength(8); // 1 per family
    expect(workItemSeeded).toHaveLength(8 * 6); // 6 work items per family
  });

  it("tags every seeded event with `seeded: true` so they can be filtered out later", async () => {
    const { osecDB } = await import("@0sec/db");
    const db = new osecDB();
    seedVerificationWorkbench(db as never);

    const events = callsByMethod("logEvent");
    expect(events.length).toBeGreaterThan(0);
    for (const e of events) {
      const payload = (e.args[0] as { payload: { seeded?: boolean } }).payload;
      expect(payload.seeded).toBe(true);
    }
  });
});
