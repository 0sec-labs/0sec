import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectTargetType, prepare } from "./prepare.js";

const originalCwd = process.cwd();
let tmpRoot: string | undefined;

afterEach(() => {
  process.chdir(originalCwd);
  if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
  tmpRoot = undefined;
});

describe("detectTargetType local path semantics", () => {
  it("treats ~/ targets as source code paths", () => {
    expect(detectTargetType("~/project")).toBe("source-code");
  });

  it("treats ../ targets as source code paths", () => {
    expect(detectTargetType("../project")).toBe("source-code");
  });

  it("treats ./ targets as source code paths", () => {
    expect(detectTargetType("./project")).toBe("source-code");
  });

  it("treats absolute directory targets as source code paths", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "0sec-prepare-"));
    const absPath = join(tmpRoot, "project");
    mkdirSync(absPath, { recursive: true });

    expect(detectTargetType(absPath)).toBe("source-code");
  });

  it("prefers an existing cwd-relative directory over an npm package name", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "0sec-prepare-"));
    mkdirSync(join(tmpRoot, "express"), { recursive: true });
    process.chdir(tmpRoot);

    expect(detectTargetType("express")).toBe("source-code");
  });
});

// #1051 — `0sec hunt --source` may be a git URL (the cloud recency feed) or a
// local checkout. hunt.ts delegates the URL-vs-localpath decision to prepare()
// (→ resolveRepo: clone a URL shallow, use a local path as-is). These pin the
// branch behaviour hunt relies on, without doing a network clone.
describe("prepare source-code URL-vs-localpath branch (#1051)", () => {
  it("classifies git URLs as source-code (→ clone branch in resolveRepo)", () => {
    expect(detectTargetType("https://github.com/torvalds/linux.git")).toBe("source-code");
    expect(detectTargetType("git@github.com:torvalds/linux.git")).toBe("source-code");
    expect(detectTargetType("git://example.com/linux.git")).toBe("source-code");
  });

  it("uses an existing local path as-is — no clone, no temp dir, no-op cleanup", async () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "0sec-prepare-"));
    const repoDir = join(tmpRoot, "checkout");
    mkdirSync(repoDir, { recursive: true });

    const before = readdirSync(tmpdir());
    const result = await prepare(repoDir, "source-code", {}, () => {});

    // Local path resolves to itself (not a cloned `${tmp}/repo`).
    expect(result.resolvedTarget).toBe(repoDir);
    // Cleanup is a no-op for a local path (the checkout must survive).
    result.cleanup();
    expect(existsSync(repoDir)).toBe(true);
    // No new `0sec-review-*` clone temp dir was created.
    const after = readdirSync(tmpdir());
    const newCloneDirs = after.filter(
      (d) => !before.includes(d) && d.startsWith("0sec-review-"),
    );
    expect(newCloneDirs).toEqual([]);
  });

  it("throws on a non-existent local source path (fail loud)", async () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "0sec-prepare-"));
    const missing = join(tmpRoot, "does-not-exist");
    await expect(prepare(missing, "source-code", {}, () => {})).rejects.toThrow(
      /Repository path not found/,
    );
  });
});
