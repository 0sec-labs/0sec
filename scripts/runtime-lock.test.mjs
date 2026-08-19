import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function read(path) {
  return readFileSync(join(repoRoot, path), "utf8");
}

test("dist runtime lock matches the generated package identity", () => {
  const lock = JSON.parse(read("scripts/dist-package-lock.json"));
  assert.equal(lock.name, "pwnkit-cli");
  assert.equal(lock.packages[""].name, "pwnkit-cli");
  assert.ok(lock.packages[""].dependencies["node-sqlite3-wasm"]);
  assert.ok(lock.packages[""].dependencies["tree-sitter"]);
});

test("bundle generator copies the immutable runtime lock", () => {
  assert.match(
    read("scripts/bundle-cli.mjs"),
    /copyFileSync\("scripts\/dist-package-lock\.json", `\$\{outdir\}\/package-lock\.json`\)/,
  );
});

for (const dockerfile of ["Dockerfile", "Dockerfile.prebuilt"]) {
  test(`${dockerfile} installs locked runtime dependencies`, () => {
    const source = read(dockerfile);
    assert.match(source, /npm ci --omit=dev --ignore-scripts/);
    assert.doesNotMatch(source, /npm install --omit=dev/);
    assert.doesNotMatch(source, /npm install -g playwright/);
  });
}
