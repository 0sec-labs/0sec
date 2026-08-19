/**
 * 0sec#193 / 0sec-cloud#111 — VerificationSpec evaluator tests.
 *
 * Coverage:
 *   1. file-contains predicate: passes when pattern matches, fails when it
 *      doesn't, and gracefully handles missing files.
 *   2. file-missing-pattern predicate: passes when the pattern is absent,
 *      fails when it's present, conservatively fails on missing files.
 *   3. file-exists predicate: passes when the file exists, fails when not.
 *   4. ast-shape predicate: surfaced as not-yet-implemented (failed) until
 *      tree-sitter is wired in as a runtime dep.
 *   5. Aggregate: passed === true only when every predicate held.
 *   6. failedPredicates list captures each predicate that flipped (with
 *      reasons), so callers can render "these predicates flipped → finding
 *      is partial-fix".
 *   7. Behaviour predicates short-circuit with "behavior eval not yet
 *      supported" — code result is reported but caller knows it's
 *      incomplete.
 *   8. Path safety: absolute paths and `..` escapes are rejected.
 *   9. Bad regex patterns flip the predicate to failed without throwing.
 */
import { execFileSync } from "node:child_process";
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  mkdtempSync,
  writeFileSync,
  mkdirSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { VerificationSpec } from "@0sec/shared";
import { evaluateVerificationSpec } from "./spec.js";

let repoRoot: string;

beforeAll(() => {
  repoRoot = mkdtempSync(join(tmpdir(), "0sec-verify-"));
  mkdirSync(join(repoRoot, "app"), { recursive: true });
  mkdirSync(join(repoRoot, "lib"), { recursive: true });
  writeFileSync(
    join(repoRoot, "app", "users.ts"),
    [
      "import { db } from '../lib/db';",
      "export async function listUsers(req, res) {",
      "  // Vulnerable: SQL string built from req.body without parameterisation",
      "  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.body.name}'`);",
      "  res.json(rows);",
      "}",
      "",
    ].join("\n"),
  );
  writeFileSync(
    join(repoRoot, "lib", "db.ts"),
    [
      "export const db = {",
      "  async query(sql: string) { /* ... */ return []; },",
      "};",
      "",
    ].join("\n"),
  );
  // app/users-fixed.ts is the patched sibling — it uses parameterised query
  // and lacks the vulnerable shape.
  writeFileSync(
    join(repoRoot, "app", "users-fixed.ts"),
    [
      "import { db } from '../lib/db';",
      "export async function listUsers(req, res) {",
      "  const rows = await db.query('SELECT * FROM users WHERE name = ?', [req.body.name]);",
      "  res.json(rows);",
      "}",
      "",
    ].join("\n"),
  );
});

afterAll(() => {
  rmSync(repoRoot, { recursive: true, force: true });
});

function createGitDiffFixture(): {
  root: string;
  baseCommit: string;
  diff: string;
} {
  const root = mkdtempSync(join(tmpdir(), "0sec-verify-git-"));
  try {
    writeFileSync(join(root, "proof.ts"), "export const vulnerable = true;\n");
    execFileSync("git", ["init", "--quiet"], { cwd: root });
    execFileSync("git", ["add", "proof.ts"], { cwd: root });
    execFileSync(
      "git",
      [
        "-c",
        "user.name=0sec Test",
        "-c",
        "user.email=0sec-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "base",
      ],
      { cwd: root },
    );
    const baseCommit = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: root,
      encoding: "utf8",
    }).trim();
    writeFileSync(join(root, "proof.ts"), "export const vulnerable = false;\n");
    const diff = execFileSync("git", ["diff", "--", "proof.ts"], {
      cwd: root,
      encoding: "utf8",
    });
    execFileSync("git", ["checkout", "--quiet", "--", "proof.ts"], { cwd: root });
    return { root, baseCommit, diff };
  } catch (err) {
    rmSync(root, { recursive: true, force: true });
    throw err;
  }
}

describe("evaluateVerificationSpec — file-contains", () => {
  it("passes when the pattern matches", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: "db\\.query.*\\$\\{req\\.body",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
    expect(result.failedPredicates).toEqual([]);
  });

  it("fails when the pattern does not match", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users-fixed.ts",
          pattern: "db\\.query.*\\$\\{req\\.body",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates).toHaveLength(1);
    expect(result.failedPredicates[0].reason).toMatch(/pattern not found/);
  });

  it("fails gracefully when the file is missing", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/does-not-exist.ts",
          pattern: "anything",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates).toHaveLength(1);
    expect(result.failedPredicates[0].reason).toMatch(/file not found/);
  });

  it("respects regex flags", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          // Case-insensitive match against a SQL keyword
          pattern: "select \\* from users",
          flags: "i",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
  });

  it("flips to failed without throwing on a bad regex", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: "[unclosed",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(/invalid regex/);
  });
});

describe("evaluateVerificationSpec — file-missing-pattern", () => {
  it("passes when the pattern is absent (fix marker still missing)", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-missing-pattern",
          file: "app/users.ts",
          // The fixed sibling uses parameterised "?" placeholders. The
          // vulnerable file does not — predicate should pass.
          pattern: "WHERE name = \\?",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
  });

  it("fails when the pattern is present (fix marker introduced)", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-missing-pattern",
          file: "app/users-fixed.ts",
          pattern: "WHERE name = \\?",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(/pattern unexpectedly present/);
  });

  it("fails conservatively when the file is missing", async () => {
    // A missing file cannot be asserted to "lack a pattern" in any
    // meaningful sense — treat as failed so the result surfaces as
    // partial-fix rather than silently passing.
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-missing-pattern",
          file: "app/never-existed.ts",
          pattern: "anything",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(/file not found/);
  });
});

describe("evaluateVerificationSpec — file-exists", () => {
  it("passes when the file exists", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "lib/db.ts" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
  });

  it("fails when the file is missing", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "lib/missing.ts" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(/file not found/);
  });
});

describe("evaluateVerificationSpec — ast-shape", () => {
  it("is reported as not-yet-implemented (conservative failed)", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "ast-shape",
          file: "app/users.ts",
          query: "(call_expression function: (member_expression))",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates).toHaveLength(1);
    expect(result.failedPredicates[0].reason).toMatch(/ast-shape.*not yet implemented/);
  });
});

describe("evaluateVerificationSpec — git-diff-applies", () => {
  it("passes when the evidence diff applies alongside an independent source predicate", async () => {
    const fixture = createGitDiffFixture();
    try {
      const result = await evaluateVerificationSpec(
        {
          code: [
            { kind: "file-exists", file: "proof.ts" },
            {
              kind: "git-diff-applies",
              baseCommit: fixture.baseCommit,
              diff: fixture.diff,
            },
          ],
        },
        fixture.root,
      );
      expect(result.passed).toBe(true);
      expect(result.failedPredicates).toEqual([]);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it("never treats a source-compatibility receipt as vulnerability proof alone", async () => {
    const fixture = createGitDiffFixture();
    try {
      const result = await evaluateVerificationSpec(
        {
          code: [
            {
              kind: "git-diff-applies",
              baseCommit: fixture.baseCommit,
              diff: fixture.diff,
            },
          ],
        },
        fixture.root,
      );
      expect(result.passed).toBe(false);
      expect(result.failedPredicates).toEqual([]);
      expect(result.reason).toBe("no vulnerability predicates");
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it("fails when HEAD no longer matches the artifact base commit", async () => {
    const fixture = createGitDiffFixture();
    try {
      execFileSync(
        "git",
        [
          "-c",
          "user.name=0sec Test",
          "-c",
          "user.email=0sec-test@example.invalid",
          "commit",
          "--allow-empty",
          "--quiet",
          "-m",
          "new head",
        ],
        { cwd: fixture.root },
      );
      const result = await evaluateVerificationSpec(
        {
          code: [
            {
              kind: "git-diff-applies",
              baseCommit: fixture.baseCommit,
              diff: fixture.diff,
            },
          ],
        },
        fixture.root,
      );
      expect(result.passed).toBe(false);
      expect(result.failedPredicates[0]?.reason).toBe(
        "git HEAD does not match diff base commit",
      );
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it("fails when the diff cannot apply to the base checkout", async () => {
    const fixture = createGitDiffFixture();
    try {
      const result = await evaluateVerificationSpec(
        {
          code: [
            {
              kind: "git-diff-applies",
              baseCommit: fixture.baseCommit,
              diff: fixture.diff.replace(
                "export const vulnerable = true;",
                "export const missing = true;",
              ),
            },
          ],
        },
        fixture.root,
      );
      expect(result.passed).toBe(false);
      expect(result.failedPredicates[0]?.reason).toBe(
        "git diff does not apply cleanly",
      );
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  it("fails an empty diff without invoking git apply", async () => {
    const fixture = createGitDiffFixture();
    try {
      const result = await evaluateVerificationSpec(
        {
          code: [
            {
              kind: "git-diff-applies",
              baseCommit: fixture.baseCommit,
              diff: "",
            },
          ],
        },
        fixture.root,
      );
      expect(result.passed).toBe(false);
      expect(result.failedPredicates[0]?.reason).toBe("git diff is empty");
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });
});

describe("evaluateVerificationSpec — aggregate semantics", () => {
  it("passed=true only when every predicate held", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: "db\\.query",
        },
        { kind: "file-exists", file: "lib/db.ts" },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(true);
    expect(result.failedPredicates).toEqual([]);
  });

  it("failedPredicates lists every predicate that flipped", async () => {
    const spec: VerificationSpec = {
      code: [
        // pass
        { kind: "file-exists", file: "lib/db.ts" },
        // fail — file gone
        { kind: "file-exists", file: "lib/gone.ts" },
        // fail — pattern missing
        {
          kind: "file-contains",
          file: "app/users-fixed.ts",
          pattern: "\\$\\{req\\.body",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates).toHaveLength(2);
    const reasons = result.failedPredicates.map((p) => p.reason);
    expect(reasons.some((r) => r.includes("file not found"))).toBe(true);
    expect(reasons.some((r) => r.includes("pattern not found"))).toBe(true);
  });

  it("empty code[] with no behavior surfaces a 'no predicates' reason", async () => {
    const spec: VerificationSpec = { code: [] };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.reason).toBe("no predicates");
    expect(result.failedPredicates).toEqual([]);
  });
});

describe("evaluateVerificationSpec — behavior predicate", () => {
  it("returns 'behavior eval not yet supported' when behavior is set", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: "db\\.query",
        },
      ],
      behavior: {
        steps: [
          { method: "GET", path: "/users", expect: "success" },
        ],
      },
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    // Code-level still passes…
    expect(result.passed).toBe(true);
    // …but the caller is told that behavioural verification didn't run.
    expect(result.reason).toBe("behavior eval not yet supported");
  });
});

describe("evaluateVerificationSpec — path safety", () => {
  it("rejects absolute paths", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "/etc/passwd" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(
      /path escapes repo root or is invalid/,
    );
  });

  it("rejects ../ escapes", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "../../../etc/passwd" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(
      /path escapes repo root or is invalid/,
    );
  });

  it("rejects empty paths", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "" }],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
  });
});

/**
 * 0sec#193 follow-up — defence-in-depth against symlink traversal.
 *
 * `resolveRepoPath` rejects lexical escapes (`..`, absolute paths) but
 * cannot detect a symlink *inside* the repo whose real target is outside.
 * A malicious finding could otherwise smuggle a `read /etc/passwd` into a
 * `file-contains` predicate by pointing at a symlink the agent created
 * during the original scan. Every read/access path is wrapped in a
 * realpath-based boundary check; broken symlinks, links to outside files,
 * and link chains all fail closed with a stable reason.
 */
describe("evaluateVerificationSpec — symlink traversal guards", () => {
  let symlinkRoot: string;
  let outsideDir: string;

  beforeAll(() => {
    // We need an outside directory we can point a symlink at. Use a
    // sibling of the repo root so the symlink target is real but outside
    // the verifier sandbox.
    outsideDir = mkdtempSync(join(tmpdir(), "0sec-verify-outside-"));
    writeFileSync(
      join(outsideDir, "secrets.env"),
      "SECRET_KEY=should-never-be-readable\n",
    );

    symlinkRoot = mkdtempSync(join(tmpdir(), "0sec-verify-symlink-"));
    mkdirSync(join(symlinkRoot, "app"), { recursive: true });
    writeFileSync(
      join(symlinkRoot, "app", "real.ts"),
      "// inside the repo, perfectly fine to read\n",
    );

    // Symlink that resolves *outside* the repo.
    symlinkSync(
      join(outsideDir, "secrets.env"),
      join(symlinkRoot, "app", "leak.env"),
    );

    // Symlink to a directory outside the repo.
    symlinkSync(outsideDir, join(symlinkRoot, "app", "leak-dir"));

    // Broken symlink (target does not exist).
    symlinkSync(
      join(outsideDir, "does-not-exist"),
      join(symlinkRoot, "app", "broken"),
    );

    // Chain: link → link → outside file.
    symlinkSync(
      join(symlinkRoot, "app", "leak.env"),
      join(symlinkRoot, "app", "chained.env"),
    );

    // Inside-only symlink (target inside the repo) — must still resolve.
    symlinkSync(
      join(symlinkRoot, "app", "real.ts"),
      join(symlinkRoot, "app", "alias.ts"),
    );
  });

  afterAll(() => {
    rmSync(symlinkRoot, { recursive: true, force: true });
    rmSync(outsideDir, { recursive: true, force: true });
  });

  it("rejects file-exists on a symlink that escapes the repo", async () => {
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "app/leak.env" }],
    };
    const result = await evaluateVerificationSpec(spec, symlinkRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(
      /path resolves outside repo root/,
    );
  });

  it("rejects file-contains read through an escaping symlink", async () => {
    // Without the realpath guard, this would happily read the contents of
    // an outside-the-repo file and run a regex over it.
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/leak.env",
          pattern: "SECRET_KEY",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, symlinkRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(
      /path resolves outside repo root/,
    );
  });

  it("rejects file-missing-pattern through an escaping symlink", async () => {
    // file-missing-pattern would otherwise be exploitable as an oracle:
    // attacker sets a pattern that matches /etc/passwd, learns whether
    // the file contains it from passed=true/false.
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-missing-pattern",
          file: "app/leak.env",
          pattern: "SECRET_KEY",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, symlinkRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(
      /path resolves outside repo root/,
    );
  });

  it("rejects symlink chains that ultimately escape the repo", async () => {
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/chained.env",
          pattern: "SECRET_KEY",
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, symlinkRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(
      /path resolves outside repo root/,
    );
  });

  it("treats broken symlinks conservatively as failed", async () => {
    // Broken symlink → realpath rejects → conservative fail. Either
    // "outside repo" or "file not found" reason is acceptable; the key
    // requirement is that the predicate does not throw and does not pass.
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "app/broken" }],
    };
    const result = await evaluateVerificationSpec(spec, symlinkRoot);
    expect(result.passed).toBe(false);
  });

  it("still allows reads through symlinks that stay inside the repo", async () => {
    // Inside-only symlinks must keep working — otherwise we'd break repos
    // that legitimately use symlinks for monorepo aliasing.
    const spec: VerificationSpec = {
      code: [{ kind: "file-exists", file: "app/alias.ts" }],
    };
    const result = await evaluateVerificationSpec(spec, symlinkRoot);
    expect(result.passed).toBe(true);
  });
});

/**
 * 0sec#193 follow-up — ReDoS + oversized-input guards.
 *
 * The verifier is the inner loop of cloud's canary watcher. An LLM-emitted
 * spec that contains a pathological regex like `(a+)+$` matched against a
 * large file would stall the worker via catastrophic backtracking. The
 * evaluator caps both the pattern length and the file size before any
 * regex match runs.
 */
describe("evaluateVerificationSpec — ReDoS + oversize guards", () => {
  it("rejects oversized regex patterns without compiling them", async () => {
    // 513 chars is just over MAX_PATTERN_LENGTH; the predicate must flip
    // to failed with an `invalid regex` reason rather than running the
    // pattern over the file.
    const oversized = "a".repeat(513);
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: oversized,
        },
      ],
    };
    const result = await evaluateVerificationSpec(spec, repoRoot);
    expect(result.passed).toBe(false);
    expect(result.failedPredicates[0].reason).toMatch(/invalid regex/);
  });

  it("refuses to read files larger than the byte cap", async () => {
    // Build a fresh repo with a >1MB file. We don't want to pollute the
    // shared repoRoot with multi-megabyte fixtures.
    const big = mkdtempSync(join(tmpdir(), "0sec-verify-big-"));
    try {
      writeFileSync(join(big, "huge.txt"), "x".repeat(1_000_001));
      const spec: VerificationSpec = {
        code: [
          {
            kind: "file-contains",
            file: "huge.txt",
            pattern: "x",
          },
        ],
      };
      const result = await evaluateVerificationSpec(spec, big);
      expect(result.passed).toBe(false);
      // readFileSafe returns null for oversized files; the contained-pattern
      // branch surfaces it as "file not found or unreadable" — same stable
      // reason as a missing file, which the canary watcher already handles.
      expect(result.failedPredicates[0].reason).toMatch(
        /file not found or unreadable/,
      );
    } finally {
      rmSync(big, { recursive: true, force: true });
    }
  });

  it("does not hang on a small ReDoS-prone pattern over a small file", async () => {
    // Sanity check on the combined defence: a small ReDoS-prone pattern
    // compiles and runs because it's under the length cap, but the file
    // is small (< 1MB) so backtracking is bounded. This test exists to
    // document the contract — pattern bound is a guard, file bound is the
    // second guard. The test should not hang.
    const start = Date.now();
    const spec: VerificationSpec = {
      code: [
        {
          kind: "file-contains",
          file: "app/users.ts",
          pattern: "(a+)+$",
        },
      ],
    };
    await evaluateVerificationSpec(spec, repoRoot);
    expect(Date.now() - start).toBeLessThan(2000);
  });
});
