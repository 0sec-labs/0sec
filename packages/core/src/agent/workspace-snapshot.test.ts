import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { readFileSync, existsSync } from "node:fs";

import {
  snapshotWorkspace,
  diffSnapshots,
  isEmptyDiff,
  summarizeDiff,
  captureCheckpoint,
  restoreCheckpoint,
  summarizeRestore,
} from "./workspace-snapshot.js";

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "0sec-snap-"));
});
afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

const write = (rel: string, content: string): void => {
  const abs = join(root, rel);
  mkdirSync(join(abs, ".."), { recursive: true });
  writeFileSync(abs, content);
};

describe("snapshotWorkspace", () => {
  it("hashes files into a manifest keyed by relative posix path", () => {
    write("a.txt", "hello");
    write("sub/b.py", "print(1)");
    const m = snapshotWorkspace(root);
    expect(Object.keys(m).sort()).toEqual(["a.txt", "sub/b.py"]);
    expect(m["a.txt"]!.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(m["a.txt"]!.size).toBe(5);
  });

  it("skips .git and node_modules", () => {
    write("keep.txt", "x");
    write(".git/config", "junk");
    write("node_modules/pkg/index.js", "junk");
    expect(Object.keys(snapshotWorkspace(root))).toEqual(["keep.txt"]);
  });

  it("does not follow symlinks", () => {
    write("real.txt", "x");
    symlinkSync(join(root, "real.txt"), join(root, "link.txt"));
    expect(Object.keys(snapshotWorkspace(root))).toEqual(["real.txt"]);
  });

  it("records oversized files by size without hashing", () => {
    write("big.bin", "x".repeat(200));
    const m = snapshotWorkspace(root, { maxFileBytes: 100 });
    expect(m["big.bin"]!.hash).toBe("size:200");
  });
});

describe("diffSnapshots", () => {
  it("detects added, modified, and deleted files", () => {
    write("keep.txt", "same");
    write("change.txt", "before");
    write("gone.txt", "bye");
    const base = snapshotWorkspace(root);

    write("change.txt", "after");
    write("new.txt", "hi");
    rmSync(join(root, "gone.txt"));
    const cur = snapshotWorkspace(root);

    const d = diffSnapshots(base, cur);
    expect(d.added).toEqual(["new.txt"]);
    expect(d.modified).toEqual(["change.txt"]);
    expect(d.deleted).toEqual(["gone.txt"]);
  });

  it("is empty when nothing changed", () => {
    write("a.txt", "x");
    const base = snapshotWorkspace(root);
    const d = diffSnapshots(base, snapshotWorkspace(root));
    expect(isEmptyDiff(d)).toBe(true);
    expect(summarizeDiff(d)).toBe("no workspace changes");
  });

  it("summarizes a non-empty diff", () => {
    const d = { added: ["a"], modified: ["b", "c"], deleted: [] };
    expect(summarizeDiff(d)).toBe("workspace changes: +1 added, ~2 modified, -0 deleted");
  });
});

const read = (rel: string): string => readFileSync(join(root, rel), "utf8");

describe("captureCheckpoint / restoreCheckpoint", () => {
  it("restores a modified file back to its checkpoint content", () => {
    write("a.txt", "original");
    const cp = captureCheckpoint(root);
    write("a.txt", "changed by agent");
    const report = restoreCheckpoint(root, cp);
    expect(read("a.txt")).toBe("original");
    expect(report.restored).toEqual(["a.txt"]);
    expect(report.errors).toEqual([]);
  });

  it("re-creates a file that was deleted since the checkpoint", () => {
    write("keep.txt", "v1");
    write("sub/gone.txt", "will be deleted");
    const cp = captureCheckpoint(root);
    rmSync(join(root, "sub/gone.txt"));
    const report = restoreCheckpoint(root, cp);
    expect(read("sub/gone.txt")).toBe("will be deleted");
    expect(report.created).toEqual(["sub/gone.txt"]);
    expect(report.unchanged).toContain("keep.txt");
  });

  it("prunes files created after the checkpoint by default", () => {
    write("a.txt", "keep");
    const cp = captureCheckpoint(root);
    write("new-poc.py", "print('agent artifact')");
    const report = restoreCheckpoint(root, cp);
    expect(existsSync(join(root, "new-poc.py"))).toBe(false);
    expect(report.pruned).toEqual(["new-poc.py"]);
  });

  it("keeps created files when pruneCreated is false", () => {
    write("a.txt", "keep");
    const cp = captureCheckpoint(root);
    write("new.txt", "agent made this");
    const report = restoreCheckpoint(root, cp, { pruneCreated: false });
    expect(existsSync(join(root, "new.txt"))).toBe(true);
    expect(report.pruned).toEqual([]);
  });

  it("dryRun reports without touching the filesystem", () => {
    write("a.txt", "original");
    const cp = captureCheckpoint(root);
    write("a.txt", "changed");
    write("created.txt", "new");
    const report = restoreCheckpoint(root, cp, { dryRun: true });
    // Nothing actually changed on disk.
    expect(read("a.txt")).toBe("changed");
    expect(existsSync(join(root, "created.txt"))).toBe(true);
    // But the report predicts the actions.
    expect(report.restored).toEqual(["a.txt"]);
    expect(report.pruned).toEqual(["created.txt"]);
  });

  it("leaves an unchanged file alone", () => {
    write("a.txt", "same");
    const cp = captureCheckpoint(root);
    const report = restoreCheckpoint(root, cp);
    expect(report.unchanged).toEqual(["a.txt"]);
    expect(report.restored).toEqual([]);
    expect(report.created).toEqual([]);
  });

  it("never captures or prunes an over-cap file", () => {
    write("small.txt", "x");
    write("big.bin", "y".repeat(50));
    const cp = captureCheckpoint(root, { maxFileBytes: 10 });
    expect(Object.keys(cp)).toEqual(["small.txt"]);
    // big.bin is over-cap → restore must not delete it even though it's not in cp.
    const report = restoreCheckpoint(root, cp, { maxFileBytes: 10 });
    expect(existsSync(join(root, "big.bin"))).toBe(true);
    expect(report.pruned).toEqual([]);
  });

  it("guards against a checkpoint key that escapes the root", () => {
    write("a.txt", "ok");
    const cp = { ...captureCheckpoint(root), "../evil.txt": { content: Buffer.from("x").toString("base64"), mode: 0o644 } };
    const report = restoreCheckpoint(root, cp);
    expect(report.errors.some((e) => e.path === "../evil.txt")).toBe(true);
    expect(existsSync(join(root, "../evil.txt"))).toBe(false);
  });

  it("round-trips a full undo (modify + delete + create)", () => {
    write("mod.txt", "before");
    write("del.txt", "keep me");
    const cp = captureCheckpoint(root);
    write("mod.txt", "after");        // modified
    rmSync(join(root, "del.txt"));    // deleted
    write("extra.txt", "artifact");   // created
    restoreCheckpoint(root, cp);
    expect(read("mod.txt")).toBe("before");
    expect(read("del.txt")).toBe("keep me");
    expect(existsSync(join(root, "extra.txt"))).toBe(false);
  });

  it("summarizeRestore is a readable one-liner", () => {
    const s = summarizeRestore({ restored: ["a"], created: ["b"], pruned: [], unchanged: ["c", "d"], errors: [] });
    expect(s).toBe("workspace restore: ~1 restored, +1 recreated, -0 pruned, =2 unchanged");
  });
});
