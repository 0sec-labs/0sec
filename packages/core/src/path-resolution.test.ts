import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  expandHomePath,
  isExistingLocalTargetPath,
  isExplicitLocalTargetPath,
  resolveLocalTargetPath,
} from "./path-resolution.js";

let tmpRoot: string | undefined;

afterEach(() => {
  if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
  tmpRoot = undefined;
});

describe("resolveLocalTargetPath", () => {
  it("resolves ~/ paths from the user home directory", () => {
    expect(resolveLocalTargetPath("~/project", { homeDir: "/home/alice", cwd: "/work/current" }))
      .toBe(resolve("/home/alice/project"));
  });

  it("resolves ./ paths relative to the active cwd", () => {
    expect(resolveLocalTargetPath("./project", { cwd: "/work/current", homeDir: "/home/alice" }))
      .toBe(resolve("/work/current/project"));
  });

  it("resolves plain relative paths relative to the active cwd", () => {
    expect(resolveLocalTargetPath("project", { cwd: "/work/current", homeDir: "/home/alice" }))
      .toBe(resolve("/work/current/project"));
  });

  it("keeps absolute paths rooted at the filesystem root", () => {
    expect(resolveLocalTargetPath("/srv/project", { cwd: "/work/current", homeDir: "/home/alice" }))
      .toBe(resolve("/srv/project"));
  });
});

describe("expandHomePath", () => {
  it("expands bare ~ to the home directory", () => {
    expect(expandHomePath("~", "/home/alice")).toBe("/home/alice");
  });

  it("does not expand shell user shorthand", () => {
    expect(expandHomePath("~bob/project", "/home/alice")).toBe("~bob/project");
  });
});

describe("isExplicitLocalTargetPath", () => {
  it("recognizes terminal-style local path prefixes", () => {
    expect(isExplicitLocalTargetPath("~")).toBe(true);
    expect(isExplicitLocalTargetPath("~/project")).toBe(true);
    expect(isExplicitLocalTargetPath("./project")).toBe(true);
    expect(isExplicitLocalTargetPath("../project")).toBe(true);
    expect(isExplicitLocalTargetPath("/srv/project")).toBe(true);
  });

  it("does not treat package-like names as explicit paths", () => {
    expect(isExplicitLocalTargetPath("express")).toBe(false);
  });
});

describe("isExistingLocalTargetPath", () => {
  it("only accepts existing directories", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "pwnkit-path-resolution-"));
    mkdirSync(join(tmpRoot, "project"));
    writeFileSync(join(tmpRoot, "README.md"), "hello", "utf8");

    expect(isExistingLocalTargetPath("project", { cwd: tmpRoot })).toBe(true);
    expect(isExistingLocalTargetPath("README.md", { cwd: tmpRoot })).toBe(false);
  });
});
