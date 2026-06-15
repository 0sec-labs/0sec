import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  familyStem,
  huntIncompleteFixSiblings,
  incompleteFixLeadToFinding,
  siblingDefsForStem,
} from "./incomplete-fix-hunt.js";

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf8" });
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
