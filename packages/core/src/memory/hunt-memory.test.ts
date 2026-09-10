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
  linkSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
  mkdirSync,
  symlinkSync,
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

describe("rememberCodebase / recallCodebase", () => {
  /** Create a temp workspace with real files for codebase tests. */
  function setupWorkspace(): { ws: string; store: HuntMemoryStore } {
    const ws = mkdtempSync(join(tmpdir(), "cb-ws-"));
    mkdirSync(join(ws, "src"), { recursive: true });
    writeFileSync(join(ws, "src", "index.ts"), "export const x = 1;\n");
    writeFileSync(join(ws, "src", "util.ts"), 'export const greet = () => "hi";\n');
    const store = new HuntMemoryStore({ home, idFactory: seqIds(), now: () => 1000 });
    return { ws, store };
  }

  it("persists codebase evidence and survives store reload", () => {
    const { ws, store } = setupWorkspace();

    const rec = store.rememberCodebase({
      root: ws,
      paths: ["src/index.ts", "src/util.ts"],
      title: "Project entry point",
      summary: "exports and greet function",
      source: "test:1",
    });

    expect(rec.kind).toBe("pattern");
    expect(rec.vulnClass).toBe("codebase-context");
    expect(rec.codebase).toBeDefined();
    expect(rec.codebase!.files).toHaveLength(2);
    expect(rec.codebase!.files[0].path).toBe("src/index.ts");
    expect(rec.codebase!.files[0].digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(rec.codebase!.root).toBe(ws); // canonical = what we passed (no symlink)

    // Fresh store instance reads the same record from disk.
    const reopened = new HuntMemoryStore({ home });
    const recalled = reopened.recallCodebase(ws);
    expect(recalled).toHaveLength(1);
    expect(recalled[0].id).toBe(rec.id);
    expect(recalled[0].codebase!.files[0].digest).toBe(rec.codebase!.files[0].digest);

    rmSync(ws, { recursive: true, force: true });
  });

  it("excludes records with changed file content", () => {
    const { ws, store } = setupWorkspace();

    store.rememberCodebase({
      root: ws,
      paths: ["src/index.ts"],
      title: "Entry point",
      summary: "original content",
      source: "test:1",
    });

    // Modify the file content.
    writeFileSync(join(ws, "src", "index.ts"), 'export const x = 42;\n');

    expect(store.recallCodebase(ws)).toHaveLength(0);

    rmSync(ws, { recursive: true, force: true });
  });

  it("excludes records with deleted files", () => {
    const { ws, store } = setupWorkspace();

    store.rememberCodebase({
      root: ws,
      paths: ["src/index.ts"],
      title: "Entry point",
      summary: "original content",
      source: "test:1",
    });

    // Delete the file.
    rmSync(join(ws, "src", "index.ts"));

    expect(store.recallCodebase(ws)).toHaveLength(0);

    rmSync(ws, { recursive: true, force: true });
  });

  it("isolates records by repository root", () => {
    const { ws: ws1, store: s1 } = setupWorkspace();
    const ws2 = mkdtempSync(join(tmpdir(), "cb-ws2-"));
    mkdirSync(join(ws2, "lib"), { recursive: true });
    writeFileSync(join(ws2, "lib", "helper.ts"), "export const y = 2;\n");

    s1.rememberCodebase({
      root: ws1,
      paths: ["src/index.ts"],
      title: "First repo",
      summary: "repo one",
      source: "test:1",
    });

    // Use the same store instance.
    s1.rememberCodebase({
      root: ws2,
      paths: ["lib/helper.ts"],
      title: "Second repo",
      summary: "repo two",
      source: "test:2",
    });

    expect(s1.recallCodebase(ws1)).toHaveLength(1);
    expect(s1.recallCodebase(ws1)[0].title).toBe("First repo");
    expect(s1.recallCodebase(ws2)).toHaveLength(1);
    expect(s1.recallCodebase(ws2)[0].title).toBe("Second repo");

    rmSync(ws1, { recursive: true, force: true });
    rmSync(ws2, { recursive: true, force: true });
  });

  it("refuses symlink paths", () => {
    const { ws, store } = setupWorkspace();
    const linkTarget = join(ws, "linked.txt");
    writeFileSync(linkTarget, "linked content\n");
    const linkPath = join(ws, "the-link");
    symlinkSync("linked.txt", linkPath);

    expect(() =>
      store.rememberCodebase({
        root: ws,
        paths: ["the-link"],
        title: "Linked file",
        summary: "should be rejected",
        source: "test:1",
      }),
    ).toThrow(/symlink/);

    rmSync(ws, { recursive: true, force: true });
  });

  it("refuses path traversal", () => {
    const { ws, store } = setupWorkspace();
    expect(() =>
      store.rememberCodebase({
        root: ws,
        paths: ["../etc/passwd"],
        title: "Traversal",
        summary: "should be rejected",
        source: "test:1",
      }),
    ).toThrow(/traversal/);

    rmSync(ws, { recursive: true, force: true });
  });

  it("refuses absolute paths", () => {
    const { ws, store } = setupWorkspace();
    expect(() =>
      store.rememberCodebase({
        root: ws,
        paths: ["/etc/hostname"],
        title: "Absolute",
        summary: "should be rejected",
        source: "test:1",
      }),
    ).toThrow(/absolute/);

    rmSync(ws, { recursive: true, force: true });
  });

  it("returns no results for non-existent root", () => {
    const { ws, store } = setupWorkspace();
    expect(store.recallCodebase(join(ws, "nonexistent"))).toEqual([]);
    rmSync(ws, { recursive: true, force: true });
  });

  it("does not recall records without codebase evidence", () => {
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    // Add a regular (non-codebase) record.
    store.append(baseInput({ createdAt: 100 }));
    // Also add a codebase-context record with no codebase field via direct append.
    store.append({
      kind: "pattern",
      target: "*",
      vulnClass: "codebase-context",
      title: "No evidence",
      summary: "no codebase attached",
      source: "test",
      createdAt: 200,
    });

    // Neither should appear in recallCodebase.
    expect(store.recallCodebase("*")).toHaveLength(0);
    expect(store.recallCodebase("anything")).toHaveLength(0);
  });

  it("rejects empty paths array", () => {
    const ws = mkdtempSync(join(tmpdir(), "cb-empty-"));
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    expect(() =>
      store.rememberCodebase({
        root: ws,
        paths: [],
        title: "Empty",
        summary: "no files",
        source: "test",
      }),
    ).toThrow(/at least one path/);
    rmSync(ws, { recursive: true, force: true });
  });

  it("rejects too many paths", () => {
    const ws = mkdtempSync(join(tmpdir(), "cb-toomany-"));
    mkdirSync(ws, { recursive: true });
    const paths = Array.from({ length: 17 }, (_, i) => `file${i}.ts`);
    for (const p of paths) writeFileSync(join(ws, p), `// ${p}\n`);
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });

    expect(() =>
      store.rememberCodebase({
        root: ws,
        paths,
        title: "Too many",
        summary: "exceeds max",
        source: "test",
      }),
    ).toThrow(/too many paths/);

    rmSync(ws, { recursive: true, force: true });
  });

  it("accepts filenames containing dots (component-aware .. check)", () => {
    const ws = mkdtempSync(join(tmpdir(), "cb-dots-"));
    writeFileSync(join(ws, "some..file.ts"), "export const x = 1;\n");
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    expect(() =>
      store.rememberCodebase({
        root: ws,
        paths: ["some..file.ts"],
        title: "Dotted filename",
        summary: "should be accepted",
        source: "test",
      }),
    ).not.toThrow();
    // Verify it can also be recalled.
    expect(store.recallCodebase(ws)).toHaveLength(1);
    rmSync(ws, { recursive: true, force: true });
  });

  it("rejects recall when intermediate directory is replaced by symlink after note creation", () => {
    const { ws, store } = setupWorkspace();
    // Remember a note pointing at src/index.ts.
    store.rememberCodebase({
      root: ws,
      paths: ["src/index.ts"],
      title: "Entry point",
      summary: "original content",
      source: "test:1",
    });

    // Replace the src/ directory with a symlink pointing outside root.
    const outside = mkdtempSync(join(tmpdir(), "cb-outside-"));
    writeFileSync(join(outside, "index.ts"), readFileSync(join(ws, "src", "index.ts")));
    rmSync(join(ws, "src"), { recursive: true });
    symlinkSync(outside, join(ws, "src"));

    // recallCodebase must reject the record because the resolved realpath
    // of src/index.ts now points outside the canonical root.
    expect(store.recallCodebase(ws)).toHaveLength(0);

    rmSync(ws, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  });

  it("rejects evidence that acquires an out-of-root hardlink", () => {
    const root = join(home, "repo");
    mkdirSync(root);
    const file = join(root, "app.ts");
    writeFileSync(file, "export const healthy = true;\n");
    const store = new HuntMemoryStore({ home });
    const note = {
      root, paths: ["app.ts"], title: "Health module",
      summary: "The module exports a health constant.", source: "test",
    };
    store.rememberCodebase(note);
    linkSync(file, join(home, "outside.ts"));
    expect(store.recallCodebase(root)).toEqual([]);
    expect(() => store.rememberCodebase(note)).toThrow(/unsafe/);
  });

  it("ignores records with malformed stored paths", () => {
    const ws = mkdtempSync(join(tmpdir(), "cb-malformed-"));
    mkdirSync(join(ws, "src"), { recursive: true });
    writeFileSync(join(ws, "src", "safe.ts"), "safe content\n");
    const store = new HuntMemoryStore({ home, idFactory: seqIds(), now: () => 200 });

    // Store a valid note via rememberCodebase, then directly append
    // malformed ones to simulate corrupted/persisted bad evidence.
    store.rememberCodebase({
      root: ws,
      paths: ["src/safe.ts"],
      title: "Safe note",
      summary: "valid",
      source: "test",
    });
    // Malformed: absolute path in stored evidence.
    store.append({
      kind: "pattern",
      target: ws,
      vulnClass: "codebase-context",
      title: "Absolute path in evidence",
      summary: "should be skipped",
      source: "test",
      tags: [],
      createdAt: 300,
      codebase: { root: ws, files: [{ path: "/etc/passwd", digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000" }] },
    });
    // Malformed: traversal path in stored evidence.
    store.append({
      kind: "pattern",
      target: ws,
      vulnClass: "codebase-context",
      title: "Traversal in evidence",
      summary: "should be skipped",
      source: "test",
      tags: [],
      createdAt: 400,
      codebase: { root: ws, files: [{ path: "../etc/passwd", digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000" }] },
    });

    // Only the valid note should appear.
    const result = store.recallCodebase(ws);
    expect(result).toHaveLength(1);
    expect(result[0].title).toBe("Safe note");

    rmSync(ws, { recursive: true, force: true });
  });

  it("rejects files exceeding size limit", () => {
    const ws = mkdtempSync(join(tmpdir(), "cb-size-"));
    // Create a file larger than MAX_CODEBASE_FILE_BYTES (1 MiB).
    const buf = Buffer.alloc(2 * 1024 * 1024, "a");
    writeFileSync(join(ws, "large.bin"), buf);
    const store = new HuntMemoryStore({ home, idFactory: seqIds() });
    expect(() =>
      store.rememberCodebase({
        root: ws,
        paths: ["large.bin"],
        title: "Large file",
        summary: "should be rejected",
        source: "test",
      }),
    ).toThrow(/too large/);
    rmSync(ws, { recursive: true, force: true });
  });

  it("returns most recent valid records first and stops at limit", () => {
    const ws = mkdtempSync(join(tmpdir(), "cb-limit-"));
    mkdirSync(join(ws, "lib"), { recursive: true });
    let t = 1000;
    const store = new HuntMemoryStore({ home, idFactory: seqIds(), now: () => ++t });

    for (let i = 1; i <= 5; i++) {
      writeFileSync(join(ws, "lib", `f${i}.ts`), `export const f${i} = ${i};\n`);
      store.rememberCodebase({
        root: ws,
        paths: [`lib/f${i}.ts`],
        title: `Note ${i}`,
        summary: `file ${i}`,
        source: "test",
      });
    }

    const result = store.recallCodebase(ws, 3);
    expect(result).toHaveLength(3);
    expect(result[0].title).toBe("Note 5");
    expect(result[1].title).toBe("Note 4");
    expect(result[2].title).toBe("Note 3");

    rmSync(ws, { recursive: true, force: true });
  });

  it("normal memory queries remain unaffected by codebase records", () => {
    const ws = mkdtempSync(join(tmpdir(), "cb-unaffected-"));
    writeFileSync(join(ws, "app.ts"), "export const a = 1;\n");
    const store = new HuntMemoryStore({ home, idFactory: seqIds(), now: () => 100 });

    // Add a standard finding.
    store.append(baseInput({ createdAt: 50, target: "a.com" }));
    // Add a codebase note.
    store.rememberCodebase({
      root: ws,
      paths: ["app.ts"],
      title: "App file",
      summary: "codebase note",
      source: "test",
    });

    // Standard query should return the finding (kind=finding) but the
    // codebase note (kind=pattern) only when asking for patterns.
    expect(store.query({ kind: "finding" })).toHaveLength(1);
    expect(store.query({ kind: "pattern" })).toHaveLength(1);
    // Cross-target without filter still returns the codebase note (it has
    // kind=pattern, vulnClass=codebase-context).
    const cross = store.crossTarget();
    expect(cross.length).toBeGreaterThanOrEqual(1);
    // Unrelated queries remain intact.
    expect(store.query({ vulnClass: "sqli" }).length).toBeGreaterThanOrEqual(1);

    rmSync(ws, { recursive: true, force: true });
  });
});
