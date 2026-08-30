import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  snapshotWorkspace,
  diffSnapshots,
  isEmptyDiff,
  summarizeDiff,
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
