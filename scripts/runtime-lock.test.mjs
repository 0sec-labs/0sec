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
  const rootPackage = JSON.parse(read("package.json"));
  const cliPackage = JSON.parse(read("packages/cli/package.json"));

  assert.equal(lock.name, rootPackage.name);
  assert.equal(lock.packages[""].name, rootPackage.name);
  assert.equal(lock.packages[""].version, rootPackage.version);
  assert.equal(lock.packages[""].dependencies["node-sqlite3-wasm"], rootPackage.dependencies["node-sqlite3-wasm"]);
  assert.equal(lock.packages[""].dependencies["tree-sitter"], rootPackage.dependencies["tree-sitter"]);
  assert.equal(lock.packages[""].dependencies["@opentui/core"], cliPackage.dependencies["@opentui/core"]);
  assert.equal(lock.packages[""].dependencies["@opentui/react"], cliPackage.dependencies["@opentui/react"]);
  assert.equal(lock.packages[""].dependencies.react, cliPackage.dependencies.react);
});

test("bundle generator copies the immutable runtime lock", () => {
  assert.match(
    read("scripts/bundle-cli.mjs"),
    /copyFileSync\("scripts\/dist-package-lock\.json", `\$\{outdir\}\/package-lock\.json`\)/,
  );
  assert.match(
    read("scripts/bundle-cli.mjs"),
    /"@opentui\/core": cliPkg\.dependencies\["@opentui\/core"\]/,
  );
  assert.match(read("scripts/bundle-cli.mjs"), /"react",\s*"react\/\*"/);
});

for (const dockerfile of ["Dockerfile", "Dockerfile.prebuilt"]) {
  test(`${dockerfile} installs locked runtime dependencies`, () => {
    const source = read(dockerfile);
    assert.match(source, /npm ci --omit=dev --ignore-scripts/);
    assert.doesNotMatch(source, /npm install --omit=dev/);
    assert.doesNotMatch(source, /npm install -g playwright/);
  });
}
