/**
 * The oversized-review guard must apply the file cap to the CHANGED set for a
 * diff-aware (`--changed-only --diff-base`) review, not the whole repo —
 * otherwise a 1-file PR on a large repo is rejected for the repo's size. We
 * set PWNKIT_REVIEW_MAX_FILES tiny so a repo with a handful of files exceeds
 * the whole-repo cap while a 1-file diff stays under it.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// An INVALID runtime makes the pipeline short-circuit right AFTER the
// oversized-review guard (which runs at prepare, before runtime validation) —
// so a diff that passes the guard fails fast with "no runtime", and a repo
// that fails the guard throws "too large" first. No agent stage, no hang.
vi.mock("./runtime/llm-api.js", () => {
  class FakeLlmApiRuntime {
    constructor(_: unknown) {}
    getConfigurationDiagnostics() {
      return { valid: true, provider: "anthropic", providerLabel: "Anthropic" };
    }
    resolvedModel() {
      return "claude-fake-default";
    }
  }
  return { LlmApiRuntime: FakeLlmApiRuntime };
});

// Stub the agent loop to resolve immediately (no real LLM call) — matches the
// other unified-pipeline test files, so the run completes fast regardless of
// which file's mock registration wins in a shared worker.
vi.mock("./agent-runner.js", () => ({
  runAnalysisAgent: vi.fn(async () => ({ findings: [] })),
}));

// Fake the static scanner so the test never shells out to a real
// foxguard/semgrep binary (npx download hangs in CI). The pipeline then fails
// fast at the (invalid) runtime validation, right after the guard.
vi.mock("./shared-analysis.js", () => ({
  selectedStaticScanner: () => "foxguard",
  runSelectedStaticScan: () => [],
}));

const { runPipeline } = await import("./unified-pipeline.js");

function git(args: string[], cwd: string) {
  execFileSync("git", args, { cwd, stdio: "pipe" });
}

/** Repo with 6 files on main (over a cap of 3) and 1 file changed on a branch. */
function makeRepo(): { dir: string; baseSha: string } {
  const dir = mkdtempSync(join(tmpdir(), "pwnkit-cap-"));
  git(["init", "-q"], dir);
  git(["config", "user.email", "t@t.t"], dir);
  git(["config", "user.name", "t"], dir);
  for (let i = 0; i < 6; i++) writeFileSync(join(dir, `f${i}.c`), `int f${i};\n`);
  git(["add", "-A"], dir);
  git(["commit", "-q", "-m", "init"], dir);
  const baseSha = git(["rev-parse", "HEAD"], dir) && "";
  git(["checkout", "-q", "-b", "feature"], dir);
  writeFileSync(join(dir, "f0.c"), "int f0_changed;\n");
  git(["add", "-A"], dir);
  git(["commit", "-q", "-m", "change f0"], dir);
  const sha = execFileSync("git", ["rev-parse", "main"], {
    cwd: dir,
    stdio: "pipe",
  })
    .toString()
    .trim();
  void baseSha;
  return { dir, baseSha: sha };
}

describe("runPipeline — oversized-review guard vs diff-aware reviews", () => {
  let dir: string;
  let baseSha: string;
  const savedCap = process.env.PWNKIT_REVIEW_MAX_FILES;

  beforeEach(() => {
    process.env.PWNKIT_REVIEW_MAX_FILES = "3";
    ({ dir, baseSha } = makeRepo());
  });
  afterEach(() => {
    if (savedCap === undefined) delete process.env.PWNKIT_REVIEW_MAX_FILES;
    else process.env.PWNKIT_REVIEW_MAX_FILES = savedCap;
    rmSync(dir, { recursive: true, force: true });
  });

  it(
    "a small diff on a repo over the whole-repo cap completes (changedOnly)",
    { timeout: 30_000 },
    async () => {
      // 6 files > cap 3, but only 1 changed file — the diff-scoped guard applies
      // the cap to the 1 changed file, so the run completes instead of throwing
      // "too large".
      const report = await runPipeline({
        target: dir,
        targetType: "source-code",
        depth: "quick",
        format: "json",
        runtime: "api",
        apiKey: "sk-fake",
        diffBase: baseSha,
        changedOnly: true,
        dbPath: join(mkdtempSync(join(tmpdir(), "pwnkit-cap-db-")), "s.db"),
      });
      expect(report).toBeTruthy();
    },
  );

  it("a full review of the same repo IS rejected as too large (control)", async () => {
    await expect(
      runPipeline({
        target: dir,
        targetType: "source-code",
        depth: "quick",
        format: "json",
        runtime: "api",
        apiKey: "sk-fake",
        dbPath: join(mkdtempSync(join(tmpdir(), "pwnkit-cap-db-")), "s.db"),
      }),
    ).rejects.toThrow(/too large/i);
  });
});
