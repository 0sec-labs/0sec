import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { parseGitStatus, readGitStatus } from "./git-status.js";

describe("parseGitStatus", () => {
  it("reads a clean branch tracking an in-sync upstream", () => {
    // A pristine checkout still emits the header block, which is how we know
    // we are inside a work tree despite there being zero change records.
    const output = [
      "# branch.oid 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",
      "# branch.head main",
      "# branch.upstream origin/main",
      "# branch.ab +0 -0",
      "",
    ].join("\n");

    const status = parseGitStatus(output);

    expect(status.isRepo).toBe(true);
    expect(status.branch).toBe("main");
    expect(status.detachedSha).toBe("1a2b3c4");
    expect(status.modified).toBe(0);
    expect(status.untracked).toBe(0);
    expect(status.ahead).toBe(0);
    expect(status.behind).toBe(0);
  });

  it("reports commits ahead of and behind the upstream", () => {
    const output = [
      "# branch.oid deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
      "# branch.head feature/status-bar",
      "# branch.upstream origin/feature/status-bar",
      "# branch.ab +3 -5",
    ].join("\n");

    const status = parseGitStatus(output);

    expect(status.branch).toBe("feature/status-bar");
    expect(status.ahead).toBe(3);
    expect(status.behind).toBe(5);
  });

  it("leaves ahead/behind null when there is no upstream line", () => {
    // A local-only branch has no branch.ab record at all; that absence — not
    // a "+0 -0" — is what distinguishes "no upstream" from "in sync".
    const output = [
      "# branch.oid 0000000000000000000000000000000000000000",
      "# branch.head local-only",
    ].join("\n");

    const status = parseGitStatus(output);

    expect(status.isRepo).toBe(true);
    expect(status.branch).toBe("local-only");
    expect(status.ahead).toBeNull();
    expect(status.behind).toBeNull();
  });

  it("treats a detached HEAD as no branch and exposes the short sha", () => {
    const output = [
      "# branch.oid abcdef1234567890abcdef1234567890abcdef12",
      "# branch.head (detached)",
    ].join("\n");

    const status = parseGitStatus(output);

    expect(status.branch).toBeNull();
    expect(status.detachedSha).toBe("abcdef1");
    expect(status.detachedSha).toHaveLength(7);
  });

  it("counts ordinary, rename, unmerged, and untracked records correctly", () => {
    // One line of each tracked flavour ("1 " ordinary, "2 " rename, "u "
    // unmerged) all roll up into `modified`; only "? " lines are untracked,
    // and "! " ignored lines must be skipped entirely.
    const output = [
      "# branch.oid 1111111222222223333333344444444555555556",
      "# branch.head work",
      "# branch.upstream origin/work",
      "# branch.ab +0 -0",
      "1 .M N... 100644 100644 100644 aaa bbb src/changed.ts",
      "1 M. N... 100644 100644 100644 ccc ddd src/staged.ts",
      "2 R. N... 100644 100644 100644 eee fff R100 dst.ts\tsrc.ts",
      "u UU N... 100644 100644 100644 100644 ggg hhh iii merge.ts",
      "? untracked-one.ts",
      "? untracked-two.ts",
      "? untracked-three.ts",
      "! ignored.log",
    ].join("\n");

    const status = parseGitStatus(output);

    // 2 ordinary + 1 rename + 1 unmerged = 4 modified.
    expect(status.modified).toBe(4);
    expect(status.untracked).toBe(3);
    expect(status.branch).toBe("work");
  });

  it("tolerates CRLF line endings", () => {
    const output =
      "# branch.oid 9876543210fedcba9876543210fedcba98765432\r\n" +
      "# branch.head windows\r\n" +
      "1 .M N... 100644 100644 100644 aaa bbb file.ts\r\n";

    const status = parseGitStatus(output);

    expect(status.branch).toBe("windows");
    expect(status.modified).toBe(1);
  });

  it("returns a sane, non-throwing result for empty input", () => {
    const status = parseGitStatus("");

    expect(status.isRepo).toBe(false);
    expect(status.branch).toBeNull();
    expect(status.modified).toBe(0);
    expect(status.untracked).toBe(0);
    expect(status.ahead).toBeNull();
    expect(status.behind).toBeNull();
  });

  it("ignores garbage lines without throwing", () => {
    const output = [
      "not a git line at all",
      "   ",
      "1", // too short to be a real change record prefix
      "1x still not a change record",
      "??? malformed",
      "# nonsense.header value",
    ].join("\n");

    let status: ReturnType<typeof parseGitStatus>;
    expect(() => {
      status = parseGitStatus(output);
    }).not.toThrow();

    // "# " lines are always headers, so the last line flips isRepo true even
    // though its key is unknown; none of the garbage touches the counters.
    expect(status!.isRepo).toBe(true);
    expect(status!.modified).toBe(0);
    expect(status!.untracked).toBe(0);
    expect(status!.branch).toBeNull();
  });
});

describe("readGitStatus", () => {
  const tempDirs: string[] = [];

  afterAll(() => {
    for (const dir of tempDirs) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resolves with isRepo false for a directory that is not a repo", async () => {
    // A fresh temp dir under the OS tmp root is guaranteed not to be a work
    // tree, so git exits non-zero; the function must swallow that and resolve.
    const dir = mkdtempSync(join(tmpdir(), "git-status-test-"));
    tempDirs.push(dir);

    const status = await readGitStatus(dir);

    expect(status.isRepo).toBe(false);
    expect(status.branch).toBeNull();
    expect(status.modified).toBe(0);
    expect(status.untracked).toBe(0);
    expect(status.ahead).toBeNull();
    expect(status.behind).toBeNull();
  });

  it("never rejects even when pointed at a nonexistent directory", async () => {
    const missing = join(tmpdir(), "git-status-does-not-exist-1234567890");

    await expect(readGitStatus(missing)).resolves.toMatchObject({
      isRepo: false,
    });
  });
});
