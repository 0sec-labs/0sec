import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync } from "node:fs";
import { fork } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  JOURNAL_SCHEMA_VERSION,
  branchJournal,
  createJournalWriter,
  loadJournal,
  migrateJournalEntry,
  streamJournal,
  type JournalEntry,
} from "./index.js";

let tmpRoot: string;
let id = 0;

function nextId(): string {
  id += 1;
  return `entry-${id}`;
}

function fixedNow(): Date {
  return new Date("2026-05-14T12:00:00.000Z");
}

function sha256(text: string): string {
  return createHash("sha256").update(Buffer.from(text, "utf8")).digest("hex");
}

async function collectStream(path: string, options?: Parameters<typeof streamJournal>[1]): Promise<JournalEntry[]> {
  const entries: JournalEntry[] = [];
  for await (const entry of streamJournal(path, options)) {
    entries.push(entry);
  }
  return entries;
}

describe("journal writer", () => {
  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), "0sec-journal-"));
    id = 0;
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("appends typed v1 entries to journal.jsonl with run metadata", () => {
    const writer = createJournalWriter({
      runId: "run-1",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });

    const entry = writer.append({
      kind: "dispatch",
      targetAgent: "researcher",
      objective: "inspect target",
      context: { target: "https://example.test" },
    });

    expect(entry).toMatchObject({
      schemaVersion: JOURNAL_SCHEMA_VERSION,
      id: "entry-1",
      runId: "run-1",
      timestamp: "2026-05-14T12:00:00.000Z",
      kind: "dispatch",
      targetAgent: "researcher",
      objective: "inspect target",
    });

    const lines = readFileSync(writer.paths.journalPath, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!)).toEqual(entry);
    expect(writer.load()).toEqual([entry]);
  });

  it("keeps small artifacts inline with size and sha256", () => {
    const writer = createJournalWriter({
      runId: "run-inline",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 100,
      now: fixedNow,
      idFactory: nextId,
    });

    const entry = writer.append({
      kind: "observation",
      source: "crawl",
      summary: "small response",
      artifacts: [{ name: "body", mediaType: "text/plain", content: "hello" }],
    });

    expect(entry.artifacts).toEqual([
      {
        kind: "inline",
        name: "body",
        mediaType: "text/plain",
        content: "hello",
        encoding: "utf8",
        sha256: sha256("hello"),
        size: 5,
      },
    ]);
  });

  it("moves large artifacts to sidecar files and stores only refs in the journal", () => {
    const writer = createJournalWriter({
      runId: "run-sidecar",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 16,
      now: fixedNow,
      idFactory: nextId,
    });
    const content = "x".repeat(64);

    const entry = writer.append({
      kind: "observation",
      source: "http_request",
      summary: "large response",
      artifacts: [{ name: "response", ext: "txt", mediaType: "text/plain", content }],
    });

    const artifact = entry.artifacts?.[0];
    expect(artifact).toEqual({
      kind: "ref",
      name: "response",
      mediaType: "text/plain",
      ref: `artifacts/${sha256(content)}.txt`,
      sha256: sha256(content),
      size: 64,
    });
    expect(readFileSync(join(writer.paths.runDir, `artifacts/${sha256(content)}.txt`), "utf8")).toBe(content);

    const line = readFileSync(writer.paths.journalPath, "utf8");
    expect(line).toContain('"kind":"ref"');
    expect(line).not.toContain(content);
  });

  it("loads complete entries when a crash leaves a trailing partial line", () => {
    const writer = createJournalWriter({
      runId: "run-partial",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    const entry = writer.append({
      kind: "decision",
      decision: "continue",
      rationale: "first observation was useful",
    });
    writeFileSync(writer.paths.journalPath, `${readFileSync(writer.paths.journalPath, "utf8")}{"schemaVersion":`, "utf8");

    expect(loadJournal({ runId: "run-partial", rootDir: tmpRoot })).toEqual([entry]);
  });

  it("throws on malformed complete journal lines", () => {
    const writer = createJournalWriter({
      runId: "run-bad-line",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    writeFileSync(writer.paths.journalPath, "{not json}\n", "utf8");

    expect(() => loadJournal({ runId: "run-bad-line", rootDir: tmpRoot })).toThrow(/Invalid journal line 1/);
  });

  it("ignores orphan temporary files left by atomic writes", () => {
    const writer = createJournalWriter({
      runId: "run-temp",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    const entry = writer.append({
      kind: "done",
      status: "success",
      summary: "finished",
    });
    writeFileSync(join(writer.paths.runDir, ".orphan.tmp"), JSON.stringify({ broken: true }), "utf8");

    expect(existsSync(join(writer.paths.runDir, ".orphan.tmp"))).toBe(true);
    expect(writer.load()).toEqual([entry]);
  });

  it("invokes migration while loading v1 entries", () => {
    const writer = createJournalWriter({
      runId: "run-migrate",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    writer.append({
      kind: "error",
      message: "tool failed",
      code: "E_TOOL",
    });
    const seen: unknown[] = [];

    const entries = loadJournal({
      runId: "run-migrate",
      rootDir: tmpRoot,
      migrate: (raw): JournalEntry => {
        seen.push(raw);
        return migrateJournalEntry(raw);
      },
    });

    expect(seen).toHaveLength(1);
    expect(entries[0]).toMatchObject({ schemaVersion: 1, kind: "error", message: "tool failed" });
  });
});

describe("loadJournal(path) replay", () => {
  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), "0sec-journal-load-"));
    id = 0;
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("returns an empty array when the journal file does not exist", async () => {
    const missing = join(tmpRoot, "no-such-journal.jsonl");
    await expect(loadJournal(missing)).resolves.toEqual([]);
  });

  it("returns an empty array for an empty journal file", async () => {
    const journalPath = join(tmpRoot, "empty.jsonl");
    writeFileSync(journalPath, "", "utf8");
    await expect(loadJournal(journalPath)).resolves.toEqual([]);
  });

  it("round-trips a single entry without artifacts", async () => {
    const writer = createJournalWriter({
      runId: "run-roundtrip-single",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    const entry = writer.append({
      kind: "dispatch",
      targetAgent: "recon",
      objective: "map endpoints",
    });

    const loaded = await loadJournal(writer.paths.journalPath);
    expect(loaded).toEqual([entry]);
  });

  it("rehydrates sidecar artifact refs into inline artifacts", async () => {
    const writer = createJournalWriter({
      runId: "run-sidecar-inline",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 16,
      now: fixedNow,
      idFactory: nextId,
    });
    const content = "x".repeat(64);
    const entry = writer.append({
      kind: "observation",
      source: "http_request",
      summary: "large response",
      artifacts: [{ name: "response", ext: "txt", mediaType: "text/plain", content }],
    });

    const stored = entry.artifacts?.[0];
    expect(stored?.kind).toBe("ref");

    const [loaded] = await loadJournal(writer.paths.journalPath);
    expect(loaded?.artifacts).toEqual([
      {
        kind: "inline",
        name: "response",
        mediaType: "text/plain",
        content,
        encoding: "utf8",
        sha256: sha256(content),
        size: 64,
      },
    ]);
  });

  it("decodes binary sidecar artifacts as base64", async () => {
    const writer = createJournalWriter({
      runId: "run-sidecar-binary",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 8,
      now: fixedNow,
      idFactory: nextId,
    });
    const bytes = new Uint8Array([0x00, 0x10, 0xff, 0xab, 0xcd, 0xef, 0x42, 0x07, 0x99]);
    writer.append({
      kind: "observation",
      source: "binary_dump",
      summary: "raw bytes",
      artifacts: [{ name: "blob", ext: "bin", mediaType: "application/octet-stream", content: bytes }],
    });

    const [loaded] = await loadJournal(writer.paths.journalPath);
    const artifact = loaded?.artifacts?.[0];
    expect(artifact?.kind).toBe("inline");
    if (artifact?.kind !== "inline") throw new Error("expected inline artifact");
    expect(artifact.encoding).toBe("base64");
    expect(Buffer.from(artifact.content, "base64").equals(Buffer.from(bytes))).toBe(true);
  });

  it("preserves ref artifacts when preserveRefs is set", async () => {
    const writer = createJournalWriter({
      runId: "run-preserve-refs",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 8,
      now: fixedNow,
      idFactory: nextId,
    });
    const content = "preserve me";
    const entry = writer.append({
      kind: "observation",
      source: "http_request",
      summary: "ref test",
      artifacts: [{ name: "body", ext: "txt", content }],
    });

    const loaded = await loadJournal(writer.paths.journalPath, { preserveRefs: true });
    expect(loaded).toEqual([entry]);
  });

  it("streams ref artifacts without opening sidecars when preserveRefs is set", async () => {
    const writer = createJournalWriter({
      runId: "run-stream-preserve-refs",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 8,
      now: fixedNow,
      idFactory: nextId,
    });
    const entry = writer.append({
      kind: "observation",
      source: "http_request",
      summary: "stream ref",
      artifacts: [{ name: "body", ext: "txt", content: "stream me later" }],
    });
    const ref = entry.artifacts?.[0];
    if (!ref || ref.kind !== "ref") throw new Error("expected ref artifact");
    rmSync(join(writer.paths.runDir, ref.ref));

    await expect(collectStream(writer.paths.journalPath, { preserveRefs: true }))
      .resolves
      .toEqual([entry]);
  });

  it("streams sidecar artifacts lazily by entry", async () => {
    const writer = createJournalWriter({
      runId: "run-stream-lazy-sidecars",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 8,
      now: fixedNow,
      idFactory: nextId,
    });
    const first = writer.append({
      kind: "observation",
      source: "http_request",
      summary: "first response",
      artifacts: [{ name: "body", ext: "txt", mediaType: "text/plain", content: "first response body" }],
    });
    const second = writer.append({
      kind: "observation",
      source: "http_request",
      summary: "second response",
      artifacts: [{ name: "body", ext: "txt", mediaType: "text/plain", content: "second response body" }],
    });
    const secondRef = second.artifacts?.[0];
    if (!secondRef || secondRef.kind !== "ref") throw new Error("expected ref artifact");
    rmSync(join(writer.paths.runDir, secondRef.ref));

    const iterator = streamJournal(writer.paths.journalPath)[Symbol.asyncIterator]();
    const firstResult = await iterator.next();
    expect(firstResult.done).toBe(false);
    expect(firstResult.value).toMatchObject({
      id: first.id,
      artifacts: [{ kind: "inline", content: "first response body" }],
    });
    await expect(iterator.next()).rejects.toThrow(/Journal sidecar artifact missing: artifacts\//);
  });

  it("streams a >1GiB synthetic sidecar ref without materializing it", async () => {
    const runDir = join(tmpRoot, "run-huge-sidecar");
    const artifactsDir = join(runDir, "artifacts");
    mkdirSync(artifactsDir, { recursive: true });
    const hugeSidecar = join(artifactsDir, "huge.txt");
    writeFileSync(hugeSidecar, "");
    truncateSync(hugeSidecar, 1024 * 1024 * 1024 + 1);

    const entry = {
      schemaVersion: JOURNAL_SCHEMA_VERSION,
      id: "entry-1",
      runId: "run-huge-sidecar",
      timestamp: "2026-05-14T12:00:00.000Z",
      kind: "observation",
      source: "http_request",
      summary: "huge response sidecar",
      artifacts: [
        {
          kind: "ref",
          name: "body",
          mediaType: "text/plain",
          ref: "artifacts/huge.txt",
          sha256: "0".repeat(64),
          size: 1024 * 1024 * 1024 + 1,
        },
      ],
    };
    const journalPath = join(runDir, "journal.jsonl");
    writeFileSync(journalPath, JSON.stringify(entry) + "\n", "utf8");

    expect(statSync(hugeSidecar).size).toBeGreaterThan(1024 * 1024 * 1024);
    await expect(collectStream(journalPath, { preserveRefs: true }))
      .resolves
      .toEqual([entry]);
  });

  it("throws a clear error when a sidecar file is missing", async () => {
    const writer = createJournalWriter({
      runId: "run-missing-sidecar",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 8,
      now: fixedNow,
      idFactory: nextId,
    });
    const entry = writer.append({
      kind: "observation",
      source: "http_request",
      summary: "missing later",
      artifacts: [{ name: "body", ext: "txt", content: "x".repeat(32) }],
    });
    const ref = entry.artifacts?.[0];
    if (!ref || ref.kind !== "ref") throw new Error("expected ref artifact");
    rmSync(join(writer.paths.runDir, ref.ref));

    await expect(loadJournal(writer.paths.journalPath))
      .rejects
      .toThrow(/Journal sidecar artifact missing: artifacts\//);
  });

  it("rejects sidecar refs that escape the run directory", async () => {
    const journalPath = join(tmpRoot, "evil.jsonl");
    const entry = {
      schemaVersion: JOURNAL_SCHEMA_VERSION,
      id: "entry-1",
      runId: "evil",
      timestamp: "2026-05-14T12:00:00.000Z",
      kind: "observation",
      source: "x",
      summary: "x",
      artifacts: [
        {
          kind: "ref",
          ref: "../escape.txt",
          sha256: "0".repeat(64),
          size: 1,
        },
      ],
    };
    writeFileSync(journalPath, JSON.stringify(entry) + "\n", "utf8");

    await expect(loadJournal(journalPath))
      .rejects
      .toThrow(/Journal artifact ref escapes run directory/);
  });

  it("uses the runDir override when sidecars live outside dirname(path)", async () => {
    const writer = createJournalWriter({
      runId: "run-altpath",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 8,
      now: fixedNow,
      idFactory: nextId,
    });
    const content = "moved journal";
    const entry = writer.append({
      kind: "observation",
      source: "http_request",
      summary: "relocate",
      artifacts: [{ name: "body", ext: "txt", content }],
    });

    const movedJournal = join(tmpRoot, "moved.jsonl");
    writeFileSync(movedJournal, readFileSync(writer.paths.journalPath));

    const [loaded] = await loadJournal(movedJournal, { runDir: writer.paths.runDir });
    expect(loaded?.artifacts?.[0]).toMatchObject({
      kind: "inline",
      content,
      sha256: (entry.artifacts?.[0] as { sha256: string }).sha256,
    });
  });
});

describe("atomicAppendJsonLine (O_APPEND fast path) — #415", () => {
  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), "0sec-journal-append-"));
    id = 0;
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  // Regression for the exact pre-#415 read→temp→rename implementation: it
  // replaced the journal inode on every append. The O_APPEND implementation
  // keeps one file in place, so inode stability detects that regression
  // deterministically without making wall-clock claims about a shared runner.
  it("does not replace the journal file across many appends", () => {
    // Each production append includes a synchronous fsync. One hundred
    // inode-checked, content-verified writes exercise the regression without
    // monopolizing a shared CI runner's disk long enough to starve Vitest RPC.
    const appendCount = 100;
    const writer = createJournalWriter({
      runId: "run-append-many",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    writer.append({
      kind: "decision",
      decision: "continue",
      rationale: "iteration 0",
    });
    const initialInode = statSync(writer.paths.journalPath).ino;
    if (process.platform !== "win32") expect(initialInode).toBeGreaterThan(0);
    for (let i = 1; i < appendCount; i += 1) {
      writer.append({
        kind: "decision",
        decision: "continue",
        rationale: `iteration ${i}`,
      });
    }
    const finalStat = statSync(writer.paths.journalPath);
    expect(finalStat.ino).toBe(initialInode);

    // Keep the journal bounded and verify every record, not merely parseability.
    expect(finalStat.size).toBeLessThan(32 * 1024);

    const raw = readFileSync(writer.paths.journalPath, "utf8");
    expect(Buffer.byteLength(raw, "utf8")).toBe(finalStat.size);
    const lines = raw.trim().split("\n");
    expect(lines).toHaveLength(appendCount);
    for (const [index, line] of lines.entries()) {
      expect(JSON.parse(line)).toMatchObject({
        id: `entry-${index + 1}`,
        seq: index,
        rationale: `iteration ${index}`,
      });
    }
  });

  // Durability: O_APPEND + fsync must persist the entry before append()
  // returns. We can't truly crash the process mid-test, so we simulate by
  // reading the file back after the synchronous append — if fsync was
  // skipped the file might still be empty in some adversarial timings;
  // even without that, the entry MUST be visible to a subsequent read.
  it("persists entries durably so a fresh reader sees them immediately", () => {
    const writer = createJournalWriter({
      runId: "run-durable",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });

    const entry = writer.append({
      kind: "observation",
      source: "probe",
      summary: "durable write",
    });

    // Fresh path-based loader (mimics a post-crash reopen) must see the entry.
    const raw = readFileSync(writer.paths.journalPath, "utf8");
    const parsed = JSON.parse(raw.trim());
    expect(parsed).toEqual(entry);

    // And the standard load path should round-trip identically.
    expect(loadJournal({ runId: "run-durable", rootDir: tmpRoot })).toEqual([entry]);
  });

  // Concurrent writers via two child processes hitting the same journal.
  // POSIX guarantees O_APPEND writes up to PIPE_BUF are atomic, so even with
  // interleaved scheduling we must end up with exactly 200 valid JSON lines.
  it("survives two concurrent writers without byte interleaving", async () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const childScript = join(here, "__concurrent_append_child.mjs");
    const runDir = mkdtempSync(join(tmpRoot, "concurrent-"));
    const journalPath = join(runDir, "journal.jsonl");

    // The child is a tiny ESM script that imports the writer and appends
    // 100 entries tagged by its `WRITER_ID`. We fork two of them in
    // parallel and wait for both to settle.
    const spawnChild = (writerId: string): Promise<number> =>
      new Promise((resolvePromise, reject) => {
        const child = fork(childScript, {
          env: {
            ...process.env,
            "0SEC_TEST_RUN_DIR": runDir,
            "0SEC_TEST_WRITER_ID": writerId,
            "0SEC_TEST_ITERATIONS": "100",
          },
          stdio: ["ignore", "ignore", "pipe", "ipc"],
        });
        child.on("error", reject);
        child.on("exit", (code) => {
          if (code === 0) resolvePromise(code);
          else reject(new Error(`child ${writerId} exited with code ${code}`));
        });
      });

    await Promise.all([spawnChild("A"), spawnChild("B")]);

    const text = readFileSync(journalPath, "utf8");
    const lines = text.split("\n").filter((l) => l.length > 0);
    expect(lines).toHaveLength(200);

    let countA = 0;
    let countB = 0;
    for (const line of lines) {
      const parsed = JSON.parse(line) as { writer?: string };
      expect(parsed).toHaveProperty("writer");
      if (parsed.writer === "A") countA += 1;
      else if (parsed.writer === "B") countB += 1;
    }
    expect(countA).toBe(100);
    expect(countB).toBe(100);
  }, 30_000);

  it("warns when an emitted line exceeds the Linux PIPE_BUF threshold", () => {
    const writer = createJournalWriter({
      runId: "run-warn",
      rootDir: tmpRoot,
      // Push the sidecar threshold above PIPE_BUF so we can force a line
      // larger than 4096B through the inline path for this test.
      sidecarThresholdBytes: 64 * 1024,
      now: fixedNow,
      idFactory: nextId,
    });
    const warnings: string[] = [];
    const originalEmit = process.emitWarning;
    // Vitest's spy types are picky across overloads; a plain monkey-patch is fine.
    (process as { emitWarning: typeof process.emitWarning }).emitWarning = ((
      warning: string | Error,
      options?: unknown,
    ) => {
      const code =
        options && typeof options === "object" && "code" in options
          ? (options as { code?: string }).code
          : undefined;
      if (code === "0SEC_JOURNAL_LINE_TOO_LARGE") {
        warnings.push(typeof warning === "string" ? warning : warning.message);
        return;
      }
      return originalEmit.call(process, warning as string, options as never);
    }) as typeof process.emitWarning;

    try {
      writer.append({
        kind: "observation",
        source: "big-line",
        // 6 KiB summary forces the JSONL line past Linux PIPE_BUF (4096).
        summary: "x".repeat(6 * 1024),
      });
    } finally {
      (process as { emitWarning: typeof process.emitWarning }).emitWarning = originalEmit;
    }

    expect(warnings.length).toBeGreaterThanOrEqual(1);
    expect(warnings[0]).toMatch(/exceeds PIPE_BUF/);
  });

  it("does NOT warn for typical small journal lines", () => {
    const writer = createJournalWriter({
      runId: "run-no-warn",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    const warnings: string[] = [];
    const originalEmit = process.emitWarning;
    (process as { emitWarning: typeof process.emitWarning }).emitWarning = ((
      warning: string | Error,
      options?: unknown,
    ) => {
      const code =
        options && typeof options === "object" && "code" in options
          ? (options as { code?: string }).code
          : undefined;
      if (code === "0SEC_JOURNAL_LINE_TOO_LARGE") {
        warnings.push(typeof warning === "string" ? warning : warning.message);
        return;
      }
      return originalEmit.call(process, warning as string, options as never);
    }) as typeof process.emitWarning;

    try {
      writer.append({
        kind: "decision",
        decision: "continue",
        rationale: "small line, well under PIPE_BUF",
      });
    } finally {
      (process as { emitWarning: typeof process.emitWarning }).emitWarning = originalEmit;
    }

    expect(warnings).toEqual([]);
  });
});

describe("branchJournal (0sec#250)", () => {
  beforeEach(() => {
    tmpRoot = mkdtempSync(join(tmpdir(), "0sec-journal-branch-"));
    id = 0;
  });

  afterEach(() => {
    rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("creates a new run with the correct prefix of entries", () => {
    const writer = createJournalWriter({
      runId: "run-src",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    writer.append({ kind: "dispatch", targetAgent: "recon", objective: "step 0" });
    writer.append({ kind: "observation", source: "crawl", summary: "step 1" });
    writer.append({ kind: "decision", decision: "continue", rationale: "step 2" });
    writer.append({ kind: "done", status: "success", summary: "step 3" });

    const result = branchJournal({ runId: "run-src", fromEntry: 1, rootDir: tmpRoot });

    expect(result.entriesCopied).toBe(2);
    expect(result.newRunId).toContain("run-src-branch-");

    // Load the branch journal and verify.
    const branchEntries = loadJournal({ runId: result.newRunId, rootDir: tmpRoot });
    expect(branchEntries).toHaveLength(2);
    expect(branchEntries[0]).toMatchObject({ kind: "dispatch", objective: "step 0" });
    expect(branchEntries[1]).toMatchObject({ kind: "observation", summary: "step 1" });
    // runId must be rewritten to the new run.
    expect(branchEntries[0]!.runId).toBe(result.newRunId);
    expect(branchEntries[1]!.runId).toBe(result.newRunId);
  });

  it("does not modify the parent journal", () => {
    const writer = createJournalWriter({
      runId: "run-parent",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    writer.append({ kind: "dispatch", targetAgent: "recon", objective: "a" });
    writer.append({ kind: "observation", source: "crawl", summary: "b" });
    writer.append({ kind: "decision", decision: "continue", rationale: "c" });

    const parentBefore = readFileSync(writer.paths.journalPath, "utf8");

    branchJournal({ runId: "run-parent", fromEntry: 0, rootDir: tmpRoot });

    const parentAfter = readFileSync(writer.paths.journalPath, "utf8");
    expect(parentAfter).toBe(parentBefore);
  });

  it("allows independent appends to the branched run", () => {
    const writer = createJournalWriter({
      runId: "run-ind",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    writer.append({ kind: "dispatch", targetAgent: "recon", objective: "base" });
    writer.append({ kind: "observation", source: "crawl", summary: "shared" });
    writer.append({ kind: "done", status: "success", summary: "parent done" });

    const result = branchJournal({ runId: "run-ind", fromEntry: 1, rootDir: tmpRoot });

    // Create a writer for the branch and append new entries.
    const branchWriter = createJournalWriter({
      runId: result.newRunId,
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    branchWriter.append({ kind: "decision", decision: "diverge", rationale: "branch-only" });

    const branchEntries = branchWriter.load();
    expect(branchEntries).toHaveLength(3); // 2 copied + 1 new
    expect(branchEntries[2]).toMatchObject({ kind: "decision", decision: "diverge" });

    // Parent must still have its original 3 entries, untouched.
    const parentEntries = loadJournal({ runId: "run-ind", rootDir: tmpRoot });
    expect(parentEntries).toHaveLength(3);
    expect(parentEntries[2]).toMatchObject({ kind: "done", summary: "parent done" });
  });

  it("copies sidecar artifacts correctly", () => {
    const writer = createJournalWriter({
      runId: "run-sidecar-branch",
      rootDir: tmpRoot,
      sidecarThresholdBytes: 16,
      now: fixedNow,
      idFactory: nextId,
    });
    const content = "x".repeat(64);
    writer.append({
      kind: "observation",
      source: "http_request",
      summary: "large response",
      artifacts: [{ name: "response", ext: "txt", mediaType: "text/plain", content }],
    });
    writer.append({ kind: "decision", decision: "continue" });

    const result = branchJournal({ runId: "run-sidecar-branch", fromEntry: 0, rootDir: tmpRoot });

    expect(result.artifactsCopied).toBe(1);

    // Verify the sidecar file exists in the branch's artifacts directory.
    const branchEntries = loadJournal({ runId: result.newRunId, rootDir: tmpRoot });
    expect(branchEntries).toHaveLength(1);
    const artifact = branchEntries[0]!.artifacts?.[0];
    expect(artifact).toBeDefined();
    expect(artifact!.kind).toBe("ref");
    if (artifact!.kind !== "ref") throw new Error("expected ref artifact");
    const sidecarPath = join(result.paths.runDir, artifact!.ref);
    expect(existsSync(sidecarPath)).toBe(true);
    expect(readFileSync(sidecarPath, "utf8")).toBe(content);
  });

  it("includes a label in the new run ID when provided", () => {
    const writer = createJournalWriter({
      runId: "run-label",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    writer.append({ kind: "dispatch", targetAgent: "recon", objective: "test" });

    const result = branchJournal({ runId: "run-label", fromEntry: 0, label: "alt-path", rootDir: tmpRoot });
    expect(result.newRunId).toContain("-branch-alt-path-");
  });

  it("throws when fromEntry is out of range", () => {
    const writer = createJournalWriter({
      runId: "run-range",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    writer.append({ kind: "dispatch", targetAgent: "recon", objective: "only entry" });

    expect(() => branchJournal({ runId: "run-range", fromEntry: 5, rootDir: tmpRoot }))
      .toThrow(/fromEntry 5 is out of range/);
    expect(() => branchJournal({ runId: "run-range", fromEntry: -1, rootDir: tmpRoot }))
      .toThrow(/fromEntry -1 is out of range/);
  });

  it("throws when source journal does not exist", () => {
    expect(() => branchJournal({ runId: "nonexistent", fromEntry: 0, rootDir: tmpRoot }))
      .toThrow(/Source journal not found/);
  });

  it("throws when source journal is empty", () => {
    const runDir = join(tmpRoot, "run-empty");
    mkdirSync(runDir, { recursive: true });
    writeFileSync(join(runDir, "journal.jsonl"), "", "utf8");

    expect(() => branchJournal({ runId: "run-empty", fromEntry: 0, rootDir: tmpRoot }))
      .toThrow(/Source journal is empty/);
  });

  it("copies all entries when fromEntry equals the last index", () => {
    const writer = createJournalWriter({
      runId: "run-all",
      rootDir: tmpRoot,
      now: fixedNow,
      idFactory: nextId,
    });
    writer.append({ kind: "dispatch", targetAgent: "a", objective: "1" });
    writer.append({ kind: "observation", source: "b", summary: "2" });

    const result = branchJournal({ runId: "run-all", fromEntry: 1, rootDir: tmpRoot });
    expect(result.entriesCopied).toBe(2);
    const branchEntries = loadJournal({ runId: result.newRunId, rootDir: tmpRoot });
    expect(branchEntries).toHaveLength(2);
  });
});
