import { access, cp, mkdir } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const outputArg = process.argv[2];

function fail(message) {
  console.error(`public source export: ${message}`);
  process.exit(1);
}

async function exists(path) {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

if (!outputArg) {
  fail("usage: node scripts/create-public-source-export.mjs <empty-output-directory>");
}

const outputDir = resolve(process.cwd(), outputArg);
if (outputDir === repoRoot || outputDir.startsWith(`${repoRoot}${sep}`)) {
  fail("output directory must be outside the private checkout");
}
if (await exists(outputDir)) {
  fail(`output directory already exists: ${outputDir}`);
}

const publicRoots = [
  ".dockerignore",
  ".gitignore",
  ".npmignore",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "scripts/create-public-source-export.mjs",
  "scripts/create-public-source-export.test.mjs",
  "Dockerfile",
  "Dockerfile.prebuilt",
  "LICENSE",
  "LICENSE-MIT",
  "NOTICE",
  "README.md",
  "SECURITY.md",
  "assets/pwnkit-icon.gif",
  "package.json",
  "packages",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "scripts/assert-sqlite-wasm.mjs",
  "scripts/bundle-cli.mjs",
  "scripts/dist-package-lock.json",
  "scripts/docker-contract.test.mjs",
  "scripts/runtime-lock.test.mjs",
  "scripts/npm-launcher",
  "scripts/ci-runner-bootstrap.sh",
  "scripts/smoke-cli.sh",
  "test-targets",
  "tsconfig.base.json",
  "vitest.workspace-aliases.ts",
  ".github/workflows/public-pr.yml",
  ".github/workflows/main.yml",
  ".github/workflows/docker-publish.yml",
];

const excludedPaths = [
  "AGENTS.md",
  "CLAUDE.md",
  "docs",
  "packages/core/src/bench/corpus-v1.json",
  "release-staging",
  "research",
  "packages/benchmark/results",
  ".github/workflows/ci.yml",
  ".github/workflows/docker-kali-publish.yml",
];

function slashPath(path) {
  return path.split(sep).join("/");
}

function isExcluded(sourcePath) {
  const sourceRelative = slashPath(relative(repoRoot, sourcePath));
  return excludedPaths.some(
    (excluded) => sourceRelative === excluded || sourceRelative.startsWith(`${excluded}/`),
  );
}

await mkdir(outputDir, { recursive: false });

for (const root of publicRoots) {
  const source = join(repoRoot, root);
  if (!(await exists(source))) {
    fail(`required source path is missing: ${root}`);
  }

  await cp(source, join(outputDir, root), {
    recursive: true,
    filter: (sourcePath) => !isExcluded(sourcePath),
  });
}

for (const excluded of excludedPaths) {
  if (await exists(join(outputDir, excluded))) {
    fail(`forbidden path reached export: ${excluded}`);
  }
}

console.log(`public source export ready: ${outputDir}`);
