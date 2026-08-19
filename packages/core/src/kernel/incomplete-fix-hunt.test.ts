import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  badFixLeadToBrief,
  familyStem,
  findBadFixes,
  huntIncompleteFixSiblings,
  incompleteFixLeadToFinding,
  siblingDefsForStem,
} from "./incomplete-fix-hunt.js";

function git(cwd: string, args: string[], env?: Record<string, string>): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    ...(env ? { env: { ...process.env, ...env } } : {}),
  });
}

const FILE = "net/tipc/crypto.c";

function crypto(withGuard: boolean): string {
  return [
    "int tipc_aead_encrypt(struct foo *aead)",
    "{",
    `\tint rc = 0;${withGuard ? " /* maybe_get_net guard */" : ""}`,
    "\treturn rc;",
    "}",
    "",
    "int tipc_aead_decrypt(struct foo *aead)",
    "{",
    "\tint rc = 0;",
    "\treturn rc;",
    "}",
    "",
    "int tipc_unrelated_helper(void)",
    "{",
    "\treturn 0;",
    "}",
    "",
  ].join("\n");
}

describe("kernel/incomplete-fix-hunt", () => {
  let repo: string;

  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "pwnkit-incfix-"));
    git(repo, ["init", "-q"]);
    git(repo, ["config", "user.email", "test@example.com"]);
    git(repo, ["config", "user.name", "Test"]);
    git(repo, ["config", "commit.gpgsign", "false"]);
    execFileSync("mkdir", ["-p", join(repo, "net/tipc")]);

    writeFileSync(join(repo, FILE), crypto(false));
    git(repo, ["add", "."]);
    git(repo, ["commit", "-q", "-m", "tipc: introduce crypto"]);

    // Fix touches ONLY tipc_aead_encrypt's body (the hunk context names it).
    writeFileSync(join(repo, FILE), crypto(true));
    git(repo, ["add", "."]);
    git(repo, [
      "commit",
      "-q",
      "-m",
      "net/tipc: fix slab-use-after-free Read in tipc_aead_encrypt_done",
    ]);
  });

  afterAll(() => {
    if (repo) rmSync(repo, { recursive: true, force: true });
  });

  it("derives a family stem and rejects trivial names", () => {
    expect(familyStem("tipc_aead_encrypt")).toBe("tipc_aead_");
    expect(familyStem("foo")).toBeUndefined();
  });

  it("finds same-stem definitions, not prototypes", () => {
    const defs = siblingDefsForStem(crypto(false), "tipc_aead_");
    const names = defs.map((d) => d.name).sort();
    expect(names).toEqual(["tipc_aead_decrypt", "tipc_aead_encrypt"]);
  });

  it("surfaces the untouched decrypt sibling of an encrypt-only fix", () => {
    const leads = huntIncompleteFixSiblings({ tree: repo, paths: ["net/tipc"] });
    const decrypt = leads.find((l) => l.siblingFunction === "tipc_aead_decrypt");
    expect(decrypt).toBeDefined();
    expect(decrypt?.fixedFunction).toBe("tipc_aead_encrypt");
    expect(decrypt?.file).toBe(FILE);
    expect(decrypt?.fix.securityKeyword).toBe("use-after-free");
    // the unrelated helper shares no family stem -> never a lead
    expect(leads.some((l) => l.siblingFunction === "tipc_unrelated_helper")).toBe(
      false,
    );
  });

  it("renders a lead as a verify-compatible kernel Finding", () => {
    const leads = huntIncompleteFixSiblings({ tree: repo, paths: ["net/tipc"] });
    const finding = incompleteFixLeadToFinding(leads[0]!);
    // evidence.request must be file:line so extractKernelFindingMetadata parses it
    expect(finding.evidence?.request).toMatch(/^net\/tipc\/crypto\.c:\d+$/);
    expect(finding.title.startsWith("tipc_aead_decrypt:")).toBe(true);
    expect(finding.evidence?.analysis).toContain("Hypothesis: true");
  });

  it("fails soft on a non-git tree", () => {
    const notGit = mkdtempSync(join(tmpdir(), "pwnkit-incfix-soft-"));
    try {
      expect(huntIncompleteFixSiblings({ tree: notGit })).toEqual([]);
    } finally {
      rmSync(notGit, { recursive: true, force: true });
    }
  });
});

describe("kernel/incomplete-fix-hunt — bad-fix (fix-of-fix) ingest", () => {
  const SFQ = "net/sched/sch_sfq.c";
  let repo: string;

  /** Commit `content` to SFQ with a fixed committer/author date. */
  function commitOn(dateIso: string, subject: string, content: string): void {
    writeFileSync(join(repo, SFQ), content);
    git(repo, ["add", "."]);
    git(repo, ["commit", "-q", "-m", subject], {
      GIT_AUTHOR_DATE: dateIso,
      GIT_COMMITTER_DATE: dateIso,
    });
  }

  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "pwnkit-badfix-"));
    git(repo, ["init", "-q"]);
    git(repo, ["config", "user.email", "test@example.com"]);
    git(repo, ["config", "user.name", "Test"]);
    git(repo, ["config", "commit.gpgsign", "false"]);
    execFileSync("mkdir", ["-p", join(repo, "net/sched")]);

    // Three security fixes on the SAME file. The last two are 5 days apart
    // (within the 30-day window => a bad-fix pair); the first is ~90 days before
    // the second (outside the window => NOT paired with it).
    commitOn("2026-04-01T00:00:00", "net/sched: sch_sfq: initial use-after-free fix", "v1\n");
    commitOn("2026-06-27T00:00:00", "net/sched: sch_sfq: fix use-after-free in enqueue", "v2\n");
    commitOn("2026-07-02T00:00:00", "net/sched: sch_sfq: fix use-after-free again", "v3\n");
  });

  afterAll(() => {
    if (repo) rmSync(repo, { recursive: true, force: true });
  });

  it("flags a second security fix that lands within N days of a prior one", () => {
    const leads = findBadFixes({ tree: repo, paths: ["net/sched"], withinDays: 30 });
    // Only the 5-day pair qualifies; the 90-day gap does not.
    expect(leads.length).toBe(1);
    const lead = leads[0]!;
    expect(lead.file).toBe(SFQ);
    expect(lead.daysApart).toBe(5);
    expect(lead.fix.subject).toContain("again");
    expect(lead.priorFix.subject).toContain("in enqueue");
    expect(lead.subsystem).toBe("net/sched");
  });

  it("does not flag anything when the window is tighter than the gap", () => {
    const leads = findBadFixes({ tree: repo, paths: ["net/sched"], withinDays: 2 });
    expect(leads).toEqual([]);
  });

  it("renders a bad-fix lead as a HuntBrief hint", () => {
    const leads = findBadFixes({ tree: repo, paths: ["net/sched"], withinDays: 30 });
    const brief = badFixLeadToBrief(leads[0]!);
    expect(brief.bugClass).toMatch(/bad-fix|fix-of-fix/i);
    expect(brief.bugClass).toContain(SFQ);
    expect(brief.pattern).toMatch(/incomplete|bypassable/i);
    expect(brief.fixReference).toBe(leads[0]!.fix.sha);
  });

  it("fails soft on a non-git tree", () => {
    const notGit = mkdtempSync(join(tmpdir(), "pwnkit-badfix-soft-"));
    try {
      expect(findBadFixes({ tree: notGit })).toEqual([]);
    } finally {
      rmSync(notGit, { recursive: true, force: true });
    }
  });
});
