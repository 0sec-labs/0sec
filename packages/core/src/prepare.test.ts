import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectTargetType } from "./prepare.js";

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
    tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-prepare-"));
    const absPath = join(tmpRoot, "project");
    mkdirSync(absPath, { recursive: true });

    expect(detectTargetType(absPath)).toBe("source-code");
  });

  it("prefers an existing cwd-relative directory over an npm package name", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-prepare-"));
    mkdirSync(join(tmpRoot, "express"), { recursive: true });
    process.chdir(tmpRoot);

    expect(detectTargetType("express")).toBe("source-code");
  });
});
