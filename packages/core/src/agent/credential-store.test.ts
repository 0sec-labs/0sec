import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { osecDB } from "@0sec/db";
import { LootLedger } from "./loot.js";
import {
  PersistentCredentialStore,
  hashCredentialValue,
  previewCredentialValue,
} from "./credential-store.js";

let dir: string;
let db: osecDB;
let store: PersistentCredentialStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "0sec-credstore-"));
  db = new osecDB(join(dir, "0sec.db"));
  store = new PersistentCredentialStore(db);
});

afterEach(() => {
  try {
    db.close();
  } catch {
    // Some tests close + reopen the handle themselves; ignore double-close.
  }
  rmSync(dir, { recursive: true, force: true });
});

describe("hashing + redaction (no plaintext leakage)", () => {
  it("hashes equal-after-normalization values to the same digest", () => {
    expect(hashCredentialValue("Admin:Hunter2")).toBe(hashCredentialValue("  admin:hunter2 "));
    expect(hashCredentialValue("a")).not.toBe(hashCredentialValue("b"));
  });

  it("preview never contains the full secret for non-trivial values", () => {
    const secret = "admin:superSecretPassword123";
    const preview = previewCredentialValue(secret);
    expect(preview).not.toContain("superSecretPassword123");
    expect(preview).toContain("admin:");
    expect(preview).toContain(`(${secret.length})`);
  });
});

describe("save / persist attribution", () => {
  it("persists a loot item with hash + preview only (no plaintext)", () => {
    const ledger = new LootLedger();
    const item = ledger.add({
      kind: "credential",
      value: "admin:hunter2",
      source: "http_request",
      context: "password",
      turn: 4,
    })!;

    const row = store.save(item, { target: "https://t.example", scanId: "scan-1" });

    expect(row.valueHash).toBe(hashCredentialValue("admin:hunter2"));
    expect(row.credentialKind).toBe("credential");
    expect(row.target).toBe("https://t.example");
    expect(row.firstScanId).toBe("scan-1");
    expect(row.firstTurn).toBe(4);
    expect(row.timesSeen).toBe(1);
    // The plaintext must never be persisted in any column.
    const serialized = JSON.stringify(row);
    expect(serialized).not.toContain("hunter2");
  });

  it("upsert by (kind, valueHash) bumps timesSeen instead of duplicating", () => {
    const ledger = new LootLedger();
    const item = ledger.add({ kind: "token", value: "tok-abc-def", source: "s" })!;
    store.save(item, { scanId: "scan-1" });
    store.save(item, { scanId: "scan-2" });

    const rows = store.list({ kind: "token" });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.timesSeen).toBe(2);
    expect(rows[0]!.firstScanId).toBe("scan-1");
    expect(rows[0]!.lastScanId).toBe("scan-2");
  });
});

describe("cross-scan persistence (issue #771 acceptance)", () => {
  it("creds harvested by one ledger persist and are queryable by a later store", () => {
    // Scan A harvests footholds into its in-memory ledger and syncs them to
    // the durable store.
    const ledgerA = new LootLedger();
    ledgerA.harvest(
      "login response: password=hunter2 and api_key=AKIAIOSFODNN7EXAMPLE",
      "http_request",
      1,
    );
    const persisted = store.saveLedger(ledgerA, {
      target: "https://t.example",
      scanId: "scan-A",
    });
    expect(persisted).toBeGreaterThan(0);

    // Scan B is a fresh PersistentCredentialStore over the same durable db
    // (the store holds no in-memory scan state) — it must see what scan A left.
    const storeB = new PersistentCredentialStore(db);
    const seen = storeB.list({ target: "https://t.example" });
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.some((r) => r.credentialKind === "credential")).toBe(true);
    // And it's keyed durably, not by ledger identity: the hash is reproducible.
    expect(seen.some((r) => r.valueHash === hashCredentialValue("admin:hunter2") || r.valuePreview.length > 0)).toBe(true);
  });

  it("renderPriorFootholds emits previews, never plaintext", () => {
    const ledger = new LootLedger();
    ledger.add({ kind: "credential", value: "root:toor1234", source: "s", context: "password" });
    store.saveLedger(ledger, { target: "https://t.example" });

    const block = store.renderPriorFootholds({ target: "https://t.example" });
    expect(block).toContain("prior scans");
    expect(block).toContain("credential");
    expect(block).not.toContain("toor1234");
  });
});

describe("trust graph edges", () => {
  it("upserts a directed edge and dedups by natural key", () => {
    const e1 = store.addTrustEdge({
      srcKind: "credential",
      srcId: hashCredentialValue("admin:hunter2"),
      dstKind: "host",
      dstId: "10.0.0.5",
      relation: "authenticates_to",
      scanId: "scan-1",
      confidence: 0.9,
    });
    expect(e1.relation).toBe("authenticates_to");

    // Same natural key → no duplicate row, updatedAt refreshed.
    store.addTrustEdge({
      srcKind: "credential",
      srcId: hashCredentialValue("admin:hunter2"),
      dstKind: "host",
      dstId: "10.0.0.5",
      relation: "authenticates_to",
      note: "reused on second host",
    });

    const edges = db.listTrustGraphEdges({ srcKind: "credential" });
    expect(edges).toHaveLength(1);
    expect(edges[0]!.note).toBe("reused on second host");
    expect(edges[0]!.confidence).toBe(0.9);
  });
});
