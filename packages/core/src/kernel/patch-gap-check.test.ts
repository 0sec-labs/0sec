import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { checkFixPresentInTarget, checkNotYetIntroduced, defaultGitExec, type GitExec } from "./patch-gap-check.js";
import type { UpstreamFixEntry } from "./patch-gap-feed.js";

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
}

describe("kernel/patch-gap-check: checkFixPresentInTarget against a real throwaway git tree", () => {
  let target: string;
  let backportedSha: string;

  beforeAll(() => {
    target = mkdtempSync(join(tmpdir(), "0sec-patchgap-target-"));
    git(target, ["init", "-q"]);
    git(target, ["config", "user.email", "test@example.com"]);
    git(target, ["config", "user.name", "Test"]);
    git(target, ["config", "commit.gpgsign", "false"]);

    writeFileSync(join(target, "drivers.c"), "int f(void) { return 0; }\n");
    git(target, ["add", "."]);
    git(target, ["commit", "-q", "-m", "base"]);

    // A commit that mirrors a stable cherry-pick: different SHA from any CVE
    // feed entry, but carries the "commit X upstream." trailer.
    writeFileSync(join(target, "drivers.c"), "int f(void) { /* fixed */ return 0; }\n");
    git(target, ["add", "."]);
    git(target, [
      "commit",
      "-q",
      "-m",
      "drivers: fix bug\n\ncommit deadbeefcafef00d1234567890abcdef12345678 upstream.",
    ]);
    backportedSha = git(target, ["rev-parse", "HEAD"]).trim();
  });

  afterAll(() => {
    if (target) rmSync(target, { recursive: true, force: true });
  });

  it("confirms 'present' via direct ancestor match (target literally has the fix commit object)", () => {
    const entry: UpstreamFixEntry = {
      cve: "CVE-2026-00001",
      title: "test fix",
      files: ["drivers.c"],
      candidateShas: [backportedSha],
      causeShas: [],
    };
    const res = checkFixPresentInTarget(entry, target);
    expect(res.present).toBe(true);
    expect(res.method).toBe("ancestor-sha");
    expect(res.matchedSha).toBe(backportedSha);
  });

  it("confirms 'present' via the cherry-pick-reference trailer when the SHA itself is a stranger to the target", () => {
    const entry: UpstreamFixEntry = {
      cve: "CVE-2026-00002",
      title: "test fix",
      files: ["drivers.c"],
      // Neither of these SHAs is an ancestor of the target — only the
      // "commit ... upstream." trailer ties this entry to the backport.
      mainlineSha: "deadbeefcafef00d1234567890abcdef12345678",
      candidateShas: ["1111111111111111111111111111111111111a", "2222222222222222222222222222222222222b"],
      causeShas: [],
    };
    const res = checkFixPresentInTarget(entry, target);
    expect(res.present).toBe(true);
    expect(res.method).toBe("cherry-pick-reference");
    expect(res.matchedSha).toBe("deadbeefcafef00d1234567890abcdef12345678");
  });

  it("returns present:false (a live 1day candidate) when neither check matches", () => {
    const entry: UpstreamFixEntry = {
      cve: "CVE-2026-00003",
      title: "unrelated, unfixed bug",
      files: ["net/foo.c"],
      mainlineSha: "3333333333333333333333333333333333333c",
      candidateShas: ["4444444444444444444444444444444444444d"],
      causeShas: [],
    };
    const res = checkFixPresentInTarget(entry, target);
    expect(res.present).toBe(false);
    expect(res.method).toBe("none");
    expect(res.reason).toMatch(/live 1day candidate/);
  });

  it("fails soft (present:false, never throws) on a non-git tree", () => {
    const notGit = mkdtempSync(join(tmpdir(), "0sec-patchgap-notgit-"));
    try {
      const entry: UpstreamFixEntry = {
        cve: "CVE-2026-00004",
        title: "x",
        files: ["a.c"],
        candidateShas: [backportedSha],
        causeShas: [],
      };
      const res = checkFixPresentInTarget(entry, notGit);
      expect(res.present).toBe(false);
      expect(res.reason).toMatch(/not a git work tree/);
    } finally {
      rmSync(notGit, { recursive: true, force: true });
    }
  });

  it("fails soft on a malformed SHA rather than shelling an unsafe git arg", () => {
    const entry: UpstreamFixEntry = {
      cve: "CVE-2026-00005",
      title: "x",
      files: ["a.c"],
      candidateShas: ["not-a-sha; rm -rf /"],
      causeShas: [],
    };
    const res = checkFixPresentInTarget(entry, target);
    expect(res.present).toBe(false);
  });
});

describe("kernel/patch-gap-check: injected GitExec seam (pure mock, no real git process)", () => {
  const entry: UpstreamFixEntry = {
    cve: "CVE-2026-00006",
    title: "mock-driven",
    files: ["a.c"],
    mainlineSha: "abcabcabcabcabcabcabcabcabcabcabcabcabc",
    candidateShas: ["1234567890abcdef1234567890abcdef12345678"],
    causeShas: [],
  };

  it("reports 'present' when the injected exec's merge-base call exits clean", () => {
    const fakeExec: GitExec = (_tree, args) => {
      if (args[0] === "rev-parse") return "true"; // isKernelGitTree probe
      if (args[0] === "merge-base") return ""; // exit 0 == present
      throw new Error("unexpected git call in mock");
    };
    const res = checkFixPresentInTarget(entry, "/fake/tree", fakeExec);
    expect(res.present).toBe(true);
    expect(res.method).toBe("ancestor-sha");
  });

  it("reports absent when the injected exec always throws (non-ancestor / no log hit)", () => {
    const fakeExec: GitExec = (_tree, args) => {
      if (args[0] === "rev-parse") return "true";
      throw new Error("exit 1");
    };
    const res = checkFixPresentInTarget(entry, "/fake/tree", fakeExec);
    expect(res.present).toBe(false);
    expect(res.method).toBe("none");
  });

  it("defaultGitExec is exported and shells real git (smoke check, not asserting output)", () => {
    expect(() => defaultGitExec(process.cwd(), ["--version"])).not.toThrow();
  });
});

describe("kernel/patch-gap-check: checkNotYetIntroduced (the 71%-false-positive fix)", () => {
  describe("cause-commit ancestry, against a real throwaway git tree", () => {
    let target: string;
    let headSha: string; // HEAD — the "target tree" cut point
    let laterSha: string; // exists as an object, but NOT an ancestor of HEAD

    beforeAll(() => {
      target = mkdtempSync(join(tmpdir(), "0sec-notyetintro-target-"));
      git(target, ["init", "-q"]);
      git(target, ["config", "user.email", "test@example.com"]);
      git(target, ["config", "user.name", "Test"]);
      git(target, ["config", "commit.gpgsign", "false"]);

      writeFileSync(join(target, "a.c"), "int f(void) { return 0; }\n");
      git(target, ["add", "."]);
      git(target, ["commit", "-q", "-m", "base"]);
      headSha = git(target, ["rev-parse", "HEAD"]).trim();

      // A commit that lands on a SEPARATE branch off the same base — its
      // object is known to the repo (same object store) but it is NOT an
      // ancestor of `main`'s HEAD. Mirrors "cause commit landed after the
      // target tree's cut, but the full-history clone still has the object".
      git(target, ["checkout", "-q", "-b", "future"]);
      writeFileSync(join(target, "b.c"), "int g(void) { return 1; }\n");
      git(target, ["add", "."]);
      git(target, ["commit", "-q", "-m", "introduces the bug (lands later)"]);
      laterSha = git(target, ["rev-parse", "HEAD"]).trim();
      // Return to the exact target cut. CI checkouts are commonly detached and
      // git's default initial branch is not guaranteed to be named `main`.
      git(target, ["checkout", "-q", headSha]);
    });

    afterAll(() => {
      if (target) rmSync(target, { recursive: true, force: true });
    });

    it("drops a candidate whose cause commit exists but is NOT an ancestor of HEAD (introduced after the target's cut)", () => {
      const entry: UpstreamFixEntry = {
        cve: "CVE-2026-10001",
        title: "not yet introduced",
        files: ["b.c"],
        candidateShas: [],
        causeShas: [laterSha],
      };
      const res = checkNotYetIntroduced(entry, target);
      expect(res.notYetIntroduced).toBe(true);
      expect(res.method).toBe("cause-not-ancestor");
    });

    it("keeps a candidate whose cause commit IS an ancestor of HEAD (introduced, real gap candidate)", () => {
      const entry: UpstreamFixEntry = {
        cve: "CVE-2026-10002",
        title: "introduced in 6.10, fix absent",
        files: ["a.c"],
        candidateShas: [],
        causeShas: [headSha],
      };
      const res = checkNotYetIntroduced(entry, target);
      expect(res.notYetIntroduced).toBe(false);
      expect(res.method).toBe("cause-not-ancestor");
    });

    it("stays inconclusive (kept) when the cause SHA is an unknown object to the tree", () => {
      const entry: UpstreamFixEntry = {
        cve: "CVE-2026-10003",
        title: "unknown cause commit",
        files: ["a.c"],
        candidateShas: [],
        causeShas: ["abcdefabcdefabcdefabcdefabcdefabcdefabcd"],
      };
      const res = checkNotYetIntroduced(entry, target);
      expect(res.notYetIntroduced).toBe(false);
      expect(res.method).toBe("no-signal");
    });
  });

  describe("numeric introduced-in version (no git needed)", () => {
    it("drops a CVE introduced in 6.14 against a 6.12 target", () => {
      const entry: UpstreamFixEntry = {
        cve: "CVE-2026-20001",
        title: "introduced in 6.14",
        files: ["net/foo.c"],
        candidateShas: [],
        causeShas: [],
        introducedVersion: "6.14",
      };
      const res = checkNotYetIntroduced(entry, "/fake/tree", () => {
        throw new Error("must not shell git for a pure numeric-version drop");
      });
      expect(res.notYetIntroduced).toBe(true);
      expect(res.method).toBe("version-numeric");
    });

    it("keeps a CVE introduced in 6.10 against a 6.12 target (older-or-equal, no drop from this signal)", () => {
      const entry: UpstreamFixEntry = {
        cve: "CVE-2026-20002",
        title: "introduced in 6.10",
        files: ["net/foo.c"],
        candidateShas: [],
        causeShas: [],
        introducedVersion: "6.10",
      };
      const res = checkNotYetIntroduced(entry, "/fake/tree", () => {
        throw new Error("no causeShas — must not shell git");
      });
      expect(res.notYetIntroduced).toBe(false);
      expect(res.method).toBe("no-signal");
    });
  });

  it("defaults to kept (no-signal) when the entry carries neither a cause SHA nor an introduced-in version", () => {
    const entry: UpstreamFixEntry = {
      cve: "CVE-2026-30001",
      title: "no introduced-in signal at all",
      files: ["net/foo.c"],
      candidateShas: ["1111111111111111111111111111111111111a"],
      causeShas: [],
    };
    const res = checkNotYetIntroduced(entry, "/fake/tree", () => {
      throw new Error("must not shell git with no signal to check");
    });
    expect(res.notYetIntroduced).toBe(false);
    expect(res.method).toBe("no-signal");
  });
});
