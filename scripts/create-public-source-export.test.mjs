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
  const tempDir = await mkdtemp(join(tmpdir(), "0sec-public-source-"));
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
      "scripts/runtime-lock.test.mjs",
      ".github/workflows/public-pr.yml",
      "scripts/ci-runner-bootstrap.sh",
      ".github/workflows/main.yml",
      ".github/workflows/docker-publish.yml",
      "assets/0sec-aperture-ink.svg",
      "assets/0sec-aperture-white.svg",
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
      "node_modules",
      "dist",
      "packages/core/dist",
      "packages/dashboard/dist",
      "test-targets/dist",
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
      assert.doesNotMatch(text, /peaktwilight|github\.com\/0sec-labs\/0cloud/i, `${sourcePath} leaks private source references`);
    }

    const publicGitignore = await readFile(join(outputDir, ".gitignore"), "utf8");
    assert.doesNotMatch(
      publicGitignore,
      /release-staging|marketing|positioning/i,
      "public ignore rules must not preserve private release-planning paths",
    );

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
    assert.match(
      publicPrWorkflow,
      /^\s*pull_request_target:/m,
      "public PR policy must be sourced from protected main",
    );
    assert.doesNotMatch(
      publicPrWorkflow,
      /^\s*pull_request:/m,
      "fork-provided workflows must not execute contributor code",
    );
    assert.doesNotMatch(
      publicPrWorkflow,
      /actions\/checkout|pnpm (?:install|build|test)|node dist\/0sec\.js/,
      "public PR policy must not check out or execute contributor code",
    );

    const publishWorkflow = await readFile(join(outputDir, ".github/workflows/docker-publish.yml"), "utf8");
    const triggerBoundary = publishWorkflow.indexOf("\npermissions:");
    assert.notEqual(triggerBoundary, -1, "publisher workflow must declare permissions after triggers");
    const publishTriggers = publishWorkflow.slice(0, triggerBoundary);
    assert.doesNotMatch(
      publishTriggers,
      /^\s*workflow_dispatch:/m,
      "the package-writer must not be manually dispatchable on an arbitrary ref",
    );
    assert.doesNotMatch(
      publishTriggers,
      /^\s*push:/m,
      "a tag push must not reach the credentialed image publisher",
    );
    assert.doesNotMatch(
      publishWorkflow,
      /github\.event_name == 'push'/,
      "the publisher must not accept an unconditional push event",
    );
    assert.doesNotMatch(
      publishWorkflow,
      /type=semver/,
      "version tags require a separately reviewed release path",
    );
    for (const requiredTrustPredicate of [
      "github.event.workflow_run.conclusion == 'success'",
      "github.event.workflow_run.event == 'push'",
      "github.event.workflow_run.head_branch == 'main'",
      "github.event.workflow_run.head_repository.full_name == github.repository",
    ]) {
      assert.match(
        publishWorkflow,
        new RegExp(requiredTrustPredicate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
        `trusted publisher predicate missing: ${requiredTrustPredicate}`,
      );
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});
