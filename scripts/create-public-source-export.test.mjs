import assert from "node:assert/strict";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { constants } from "node:fs";
import { execFile } from "node:child_process";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import test from "node:test";

const execFileAsync = promisify(execFile);
const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const exporter = join(repoRoot, "scripts", "create-public-source-export.mjs");

async function exists(path) {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

test("public source export contains build inputs and excludes private material", async () => {
  const tempDir = await mkdtemp(join(tmpdir(), "pwnkit-public-source-"));
  const outputDir = join(tempDir, "export");

  try {
    await execFileAsync(process.execPath, [exporter, outputDir], { cwd: repoRoot });

    for (const required of [
      "LICENSE",
      "NOTICE",
      "README.md",
      "package.json",
      "packages/core",
      "scripts/bundle-cli.mjs",
      "LICENSE-MIT",
      "scripts/dist-package-lock.json",
      "scripts/docker-contract.test.mjs",
      "scripts/runtime-lock.test.mjs",
      ".github/workflows/public-pr.yml",
      "scripts/ci-runner-bootstrap.sh",
      ".github/workflows/main.yml",
      ".github/workflows/docker-publish.yml",
    ]) {
      assert.equal(await exists(join(outputDir, required)), true, `${required} is missing`);
    }

    for (const forbidden of [
      "AGENTS.md",
      "CLAUDE.md",
      "packages/core/src/bench/corpus-v1.json",
      "docs",
      "release-staging",
      "research",
      "packages/benchmark/results",
      ".github/workflows/ci.yml",
      ".github/workflows/docker-kali-publish.yml",
    ]) {
      assert.equal(await exists(join(outputDir, forbidden)), false, `${forbidden} leaked`);
    }

    for (const sourcePath of [
      "Dockerfile",
      ".github/workflows/docker-publish.yml",
      "packages/cli/src/commands/review.ts",
      "packages/cli/src/commands/run.ts",
      "packages/core/src/seed-findings.ts",
      "packages/core/src/scope/scope-guard.ts",
      "packages/core/src/stages/novelty-check.ts",
      "packages/benchmark/README.md",
    ]) {
      const text = await readFile(join(outputDir, sourcePath), "utf8");
      assert.doesNotMatch(text, /peaktwilight|github\.com\/0sec-labs\/0sec/i, `${sourcePath} leaks private source references`);
    }

    const publicPrWorkflow = await readFile(join(outputDir, ".github/workflows/public-pr.yml"), "utf8");
    assert.match(
      publicPrWorkflow,
      /^\s*runs-on:\s+ubuntu-latest\s*$/m,
      "untrusted public PRs must use an ephemeral hosted runner",
    );
    assert.doesNotMatch(
      publicPrWorkflow,
      /\bself-hosted\b/i,
      "untrusted public PRs must not execute on persistent runners",
    );
    assert.doesNotMatch(
      publicPrWorkflow,
      /\bsecrets\./i,
      "untrusted public PRs must not receive repository secrets",
    );
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});
