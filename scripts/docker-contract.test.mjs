// Structural checks for Docker build contract consistency.
//
// Verifies that:
//   - Both Dockerfiles reference the Node major version matching
//     package.json engines.node (>=24)
//   - Dockerfile.prebuilt uses COPY . (verified-dist context) not COPY dist/
//   - .dockerignore still excludes dist/ (source-build path not weakened)
//
// Run with: node --test scripts/docker-contract.test.mjs

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..");

function readFile(path) {
  return readFileSync(join(repoRoot, path), "utf-8");
}

test("Dockerfile uses node:24 (matching engines.node >=24)", () => {
  const dockerfile = readFile("Dockerfile");
  assert.ok(
    /^FROM node:24-/m.test(dockerfile),
    "Dockerfile must use node:24 base image"
  );
});

test("Dockerfile.prebuilt uses node:24 (matching engines.node >=24)", () => {
  const prebuilt = readFile("Dockerfile.prebuilt");
  assert.ok(
    /^FROM node:24-/m.test(prebuilt),
    "Dockerfile.prebuilt must use node:24 base image"
  );
});

test("package.json engines.node requires >=24", () => {
  const pkg = JSON.parse(readFile("package.json"));
  assert.ok(
    pkg.engines?.node?.includes(">=24"),
    `package.json engines.node must require >=24, got: ${pkg.engines?.node}`
  );
});

test("Dockerfile.prebuilt copies from context root (dist directory as context)", () => {
  const prebuilt = readFile("Dockerfile.prebuilt");
  assert.ok(
    /^COPY \.\s+\/app\/dist/m.test(prebuilt),
    "Dockerfile.prebuilt must COPY . (dist context root) to /app/dist"
  );
  assert.ok(
    !/^COPY dist\/?\s+\/app\/dist/m.test(prebuilt),
    "Dockerfile.prebuilt must not COPY dist/ (context is already ./dist/)"
  );
});

test(".dockerignore still excludes dist/ for source-build path", () => {
  const ignore = readFile(".dockerignore");
  const lines = ignore.split("\n").map((l) => l.trim());
  assert.ok(
    lines.includes("dist"),
    ".dockerignore must exclude dist/"
  );
});