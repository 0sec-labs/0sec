import assert from "node:assert/strict";
import { access, mkdtemp, rm } from "node:fs/promises";
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
      ".github/workflows/public-pr.yml",
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
      ".github/workflows/docker-publish.yml",
      ".github/workflows/docker-kali-publish.yml",
    ]) {
      assert.equal(await exists(join(outputDir, forbidden)), false, `${forbidden} leaked`);
    }
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
});
