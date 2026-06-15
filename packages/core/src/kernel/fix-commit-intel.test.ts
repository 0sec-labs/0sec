import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  checkAlreadyFixed,
  isKernelGitTree,
  mineFixCommits,
} from "./fix-commit-intel.js";

/**
 * Build a throwaway git repo that mimics a kernel subsystem with a recent
 * security fix, so the git-mining functions exercise real `git log` output
 * (not a mock). One file, two commits: an introducing commit, then a
 * `Fixes:`-tagged UAF fix that pickaxe-touches the faulting function.
 */
function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

describe("kernel/fix-commit-intel", () => {
  let repo: string;
  const FILE = "net/tipc/crypto.c";
  const FN = "tipc_aead_decrypt";

  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "pwnkit-fixintel-"));
    git(repo, ["init", "-q"]);
    git(repo, ["config", "user.email", "test@example.com"]);
    git(repo, ["config", "user.name", "Test"]);
    git(repo, ["config", "commit.gpgsign", "false"]);

    // Introducing commit: a file with the function (and a sibling).
    execFileSync("mkdir", ["-p", join(repo, "net/tipc")]);
    writeFileSync(
      join(repo, FILE),
      [
        "int tipc_aead_encrypt(void) { return 0; }",
        `int ${FN}(void) { return 0; }`,
        "int unrelated_helper(void) { return 0; }",
        "",
      ].join("\n"),
    );
    git(repo, ["add", "."]);
    git(repo, ["commit", "-q", "-m", "tipc: introduce crypto"]);

    // Fix commit: security subject + Fixes: trailer, changing a line that
    // mentions the faulting function (so the pickaxe -S<fn> catches it).
    writeFileSync(
      join(repo, FILE),
      [
        "int tipc_aead_encrypt(void) { return 0; }",
        `int ${FN}(void) { /* added bound check */ return 0; }`,
        "int unrelated_helper(void) { return 0; }",
        "",
      ].join("\n"),
    );
    git(repo, ["add", "."]);
    git(repo, [
      "commit",
      "-q",
      "-m",
      'tipc: fix use-after-free in tipc_aead_decrypt\n\nFixes: 19cfe5843e86 ("NFC: Initial SNL support")',
    ]);
  });

  afterAll(() => {
    if (repo) rmSync(repo, { recursive: true, force: true });
  });

  it("recognises a real git work tree and rejects a non-git dir", () => {
    expect(isKernelGitTree(repo)).toBe(true);
    const notGit = mkdtempSync(join(tmpdir(), "pwnkit-notgit-"));
    try {
      expect(isKernelGitTree(notGit)).toBe(false);
    } finally {
      rmSync(notGit, { recursive: true, force: true });
    }
  });

  it("mines the security/Fixes-tagged commit from the corpus", () => {
    const commits = mineFixCommits({ tree: repo, paths: ["net/tipc"] });
    expect(commits.length).toBeGreaterThanOrEqual(1);
    const fix = commits.find((c) => c.subject.includes("use-after-free"));
    expect(fix).toBeDefined();
    expect(fix?.securityKeyword).toBe("use-after-free");
    expect(fix?.fixesTag).toBe("19cfe5843e86");
  });

  it("flags a function-level match as already-fixed (the FP gate)", () => {
    const res = checkAlreadyFixed({
      tree: repo,
      filePath: FILE,
      faultingFunction: FN,
    });
    expect(res.likelyFixed).toBe(true);
    expect(res.functionLevelMatch).toBe(true);
    expect(res.commits[0]?.securityKeyword).toBe("use-after-free");
    expect(res.reason).toContain(FN);
  });

  it("does NOT function-level-match a sibling the fix never touched", () => {
    const res = checkAlreadyFixed({
      tree: repo,
      filePath: FILE,
      faultingFunction: "unrelated_helper",
    });
    // The fix commit is still a file-level security touch, but the pickaxe on
    // an untouched function must not produce the strong (gate-firing) signal.
    expect(res.functionLevelMatch).toBe(false);
  });

  it("fails soft on a non-git tree (never gates a finding out)", () => {
    const notGit = mkdtempSync(join(tmpdir(), "pwnkit-soft-"));
    try {
      const res = checkAlreadyFixed({
        tree: notGit,
        filePath: FILE,
        faultingFunction: FN,
      });
      expect(res.likelyFixed).toBe(false);
      expect(res.functionLevelMatch).toBe(false);
      expect(mineFixCommits({ tree: notGit })).toEqual([]);
    } finally {
      rmSync(notGit, { recursive: true, force: true });
    }
  });
});
