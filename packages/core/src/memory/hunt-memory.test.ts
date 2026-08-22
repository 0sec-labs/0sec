/**
 * Tests for the hunt-memory store (hunt-memory.ts).
 *
 * These exercise real filesystem behaviour — append-only JSONL, permission
 * bits, oldest-out rotation, atomic compaction — under a temp "home" root, so
 * no test ever touches the operator's real `~/.0sec`. Time is always injected
 * via `createdAt` / `now`; ids are injected too, so everything is deterministic.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  appendFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
  mkdirSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  HuntMemoryStore,
  huntMemoryPath,
  redactSecrets,
  HUNT_REDACTED,
  type HuntRecordInput,
} from "./hunt-memory.js";

let home: string;
let storePath: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "hunt-mem-"));
  storePath = huntMemoryPath(home);
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

/** Deterministic id factory. */
function seqIds() {
  let n = 0;
  return () => `id-${++n}`;
}

function baseInput(over: Partial<HuntRecordInput> = {}): HuntRecordInput {
  return {
    kind: "finding",
    target: "shop.example.com",
    vulnClass: "sqli",
    title: "Blind SQLi in search",
    summary: "boolean-based blind sqli via q= parameter",
    source: "scan:1",
    createdAt: 1000,
    ...over,
  };
}

describe("append / query", () => {
  it("appends and reads back with normalization", () => {
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    const rec = store.append(
      baseInput({ target: "Shop.Example.COM", tags: ["Auth", "auth", "IDOR"] }),
    );
    expect(rec.id).toBe("id-1");
    expect(rec.target).toBe("shop.example.com"); // lowercased
    expect(rec.vulnClass).toBe("sqli");
    expect(rec.tags).toEqual(["auth", "idor"]); // deduped + lowercased
    expect(rec.schemaVersion).toBe(1);

    // A fresh store instance reads the same record from disk.
    const reopened = new HuntMemoryStore({ home });
    expect(reopened.all()).toHaveLength(1);
    expect(reopened.all()[0].id).toBe("id-1");
  });

  it("uses injected now() when createdAt is omitted", () => {
    const store = new HuntMemoryStore({ home, now: () => 42, idFactory: seqIds() });
    const rec = store.append(baseInput({ createdAt: undefined }));
    expect(rec.createdAt).toBe(42);
  });

  it("filters by target, vulnClass, kind, tags, and sinceTs", () => {
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    store.append(baseInput({ target: "a.com", vulnClass: "sqli", createdAt: 100, tags: ["p1"] }));
    store.append(baseInput({ target: "b.com", vulnClass: "sqli", createdAt: 200, tags: ["p1", "p2"] }));
    store.append(baseInput({ target: "a.com", vulnClass: "xss", createdAt: 300, kind: "pattern" }));

    expect(store.query({ target: "a.com" }).map((r) => r.id)).toEqual(["id-3", "id-1"]);
    expect(store.query({ vulnClass: "sqli" }).map((r) => r.id)).toEqual(["id-2", "id-1"]);
    expect(store.query({ kind: "pattern" }).map((r) => r.id)).toEqual(["id-3"]);
    expect(store.query({ tags: ["p1", "p2"] }).map((r) => r.id)).toEqual(["id-2"]);
    expect(store.query({ sinceTs: 200 }).map((r) => r.id)).toEqual(["id-3", "id-2"]);
    expect(store.query({ limit: 1 }).map((r) => r.id)).toEqual(["id-3"]); // most-recent-first
  });

  it("recent() returns most-recent-first across targets", () => {
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    store.append(baseInput({ createdAt: 10 }));
    store.append(baseInput({ createdAt: 30 }));
    store.append(baseInput({ createdAt: 20 }));
    expect(store.recent().map((r) => r.createdAt)).toEqual([30, 20, 10]);
  });
});

describe("cross-target query", () => {
  it("finds the vuln class across all assets, and can exclude the current one", () => {
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    store.append(baseInput({ target: "a.com", vulnClass: "ssrf", createdAt: 100 }));
    store.append(baseInput({ target: "b.com", vulnClass: "ssrf", createdAt: 200 }));
    store.append(baseInput({ target: "c.com", vulnClass: "ssrf", createdAt: 300 }));

    // "what have we historically found for ssrf, anywhere"
    expect(store.crossTarget({ vulnClass: "ssrf" }).map((r) => r.target)).toEqual([
      "c.com",
      "b.com",
      "a.com",
    ]);

    // learn from OTHER assets only
    const others = store.crossTarget({ vulnClass: "ssrf", excludeTarget: "b.com" });
    expect(others.map((r) => r.target)).toEqual(["c.com", "a.com"]);
  });
});

describe("redaction", () => {
  it("never writes a secret to disk", () => {
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    const secretSummary = [
      "creds were password=SuperSecret123 and",
      "Authorization: Bearer abc123DEFtokenvalue456",
      "aws key AKIAIOSFODNN7EXAMPLE and",
      "api_key=sk-ant-0123456789abcdefghij",
      "url https://user:hunter2@internal.example/path",
    ].join(" ");
    const pem =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEabcdef1234==\n-----END RSA PRIVATE KEY-----";

    store.append(
      baseInput({
        summary: secretSummary,
        evidenceRef: pem,
        title: "token=leakedtokenvalue1234567",
        tags: ["password=inatag123456"],
        source: "scan:PASSWORD=oops123456",
      }),
    );

    const raw = readFileSync(storePath, "utf8");
    // None of the raw secrets survive.
    for (const leak of [
      "SuperSecret123",
      "abc123DEFtokenvalue456",
      "AKIAIOSFODNN7EXAMPLE",
      "sk-ant-0123456789abcdefghij",
      "hunter2",
      "leakedtokenvalue1234567",
      "inatag123456",
      "MIIEabcdef1234",
      "oops123456",
    ]) {
      expect(raw).not.toContain(leak);
    }
    expect(raw).toContain(HUNT_REDACTED);

    // Evidence content hashes are legitimate and must NOT be redacted.
    const store2 = new HuntMemoryStore({ home: mkdtempSync(join(tmpdir(), "hm2-")), idFactory: seqIds() });
    const hash = "a".repeat(64);
    const rec = store2.append(baseInput({ evidenceRef: `sha256:${hash}` }));
    expect(rec.evidenceRef).toContain(hash);
  });

  it("redactSecrets keeps benign prose intact", () => {
    expect(redactSecrets("the token was valid for the session")).toBe(
      "the token was valid for the session",
    );
    expect(redactSecrets("password=hunter2")).toBe(`password=${HUNT_REDACTED}`);
  });
});

describe("GC / rotation", () => {
  it("caps the record count with oldest-out rotation", () => {
    const store = new HuntMemoryStore({ home, maxRecords: 3, idFactory: seqIds() });
    for (let i = 1; i <= 6; i++) store.append(baseInput({ createdAt: i * 10 }));

    const all = store.all();
    expect(all).toHaveLength(3);
    // Newest three retained (createdAt 40,50,60); oldest dropped.
    expect(all.map((r) => r.createdAt).sort((a, b) => a - b)).toEqual([40, 50, 60]);

    // Persisted to disk, too — a reopen sees exactly the retained set.
    const reopened = new HuntMemoryStore({ home });
    expect(reopened.all()).toHaveLength(3);
    expect(reopened.all().map((r) => r.createdAt).sort((a, b) => a - b)).toEqual([40, 50, 60]);
  });

  it("caps total bytes with oldest-out rotation", () => {
    const store = new HuntMemoryStore({ home, maxBytes: 900, idFactory: seqIds() });
    for (let i = 1; i <= 40; i++) store.append(baseInput({ createdAt: i }));
    expect(statSync(storePath).size).toBeLessThanOrEqual(900);
    // The most-recent record is always retained.
    expect(store.recent(1)[0].createdAt).toBe(40);
    expect(store.all().length).toBeGreaterThan(0);
  });

  it("compact() rewrites and drops corrupt trailing lines", () => {
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    store.append(baseInput({ createdAt: 1 }));
    // Simulate a crash mid-append: a trailing partial line.
    appendFileSync(storePath, '{"id":"broken","kind":"fin');

    const reopened = new HuntMemoryStore({ home });
    expect(reopened.all()).toHaveLength(1); // corrupt line skipped
    reopened.compact();

    const raw = readFileSync(storePath, "utf8");
    expect(raw).not.toContain("broken");
    // Reopen once more to confirm the compacted file parses cleanly.
    expect(new HuntMemoryStore({ home }).all()).toHaveLength(1);
  });
});

describe("totality", () => {
  it("skips corrupt / partial lines without throwing", () => {
    mkdirSync(join(home, ".0sec", "hunt-memory"), { recursive: true });
    const good = JSON.stringify({
      id: "id-good",
      kind: "finding",
      target: "a.com",
      vulnClass: "sqli",
      title: "t",
      summary: "s",
      tags: [],
      createdAt: 1,
      source: "x",
      schemaVersion: 1,
    });
    writeFileSync(
      storePath,
      [
        good,
        "not json at all",
        "{ half written",
        JSON.stringify({ id: "missing-fields" }), // fails required-field check
        "",
        good.replace("id-good", "id-good-2"),
      ].join("\n"),
    );

    const store = new HuntMemoryStore({ home });
    expect(store.all().map((r) => r.id)).toEqual(["id-good", "id-good-2"]);
  });

  it("reads a missing store as empty and reports empty stats", () => {
    const store = new HuntMemoryStore({ home });
    expect(existsSync(storePath)).toBe(false);
    expect(store.all()).toEqual([]);
    expect(store.query()).toEqual([]);
    const s = store.stats();
    expect(s.total).toBe(0);
    expect(s.byKind).toEqual({ finding: 0, pattern: 0 });
    expect(s.distinctTargets).toBe(0);
    expect(s.oldestTs).toBeNull();
    expect(s.newestTs).toBeNull();
  });
});

describe("stats", () => {
  it("aggregates kinds, severities, classes and targets", () => {
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    store.append(baseInput({ target: "a.com", vulnClass: "sqli", severity: "high", createdAt: 10 }));
    store.append(baseInput({ target: "b.com", vulnClass: "sqli", severity: "low", createdAt: 20 }));
    store.append(baseInput({ target: "*", vulnClass: "xss", kind: "pattern", createdAt: 30 }));

    const s = store.stats();
    expect(s.total).toBe(3);
    expect(s.byKind).toEqual({ finding: 2, pattern: 1 });
    expect(s.bySeverity).toEqual({ high: 1, low: 1, unknown: 1 });
    expect(Object.keys(s.byVulnClass)[0]).toBe("sqli"); // most frequent first
    expect(s.distinctTargets).toBe(2); // "*" excluded
    expect(s.oldestTs).toBe(10);
    expect(s.newestTs).toBe(30);
  });
});

describe("permissions", () => {
  it("creates the dir 0700 and file 0600", () => {
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    store.append(baseInput());
    const dirMode = statSync(join(home, ".0sec", "hunt-memory")).mode & 0o777;
    const fileMode = statSync(storePath).mode & 0o777;
    expect(dirMode).toBe(0o700);
    expect(fileMode).toBe(0o600);
  });
});
