/**
 * build-npm-shim.test.mjs — validates the npm launcher package the release
 * pipeline publishes. Runs the real builder into dist-npm/ and asserts the
 * generated package.json + launcher are shaped so that a global install lands
 * the operator on the documented `0` command.
 *
 * Run with: pnpm test:npm-shim  (root package.json)
 */

import { after, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, statSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const OUT = join(ROOT, "dist-npm");

// Build once for the whole suite.
execFileSync("node", [join(__dirname, "build-npm-shim.mjs")], { cwd: ROOT });

const rootPkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const pkg = JSON.parse(readFileSync(join(OUT, "package.json"), "utf8"));

after(() => {
  rmSync(OUT, { recursive: true, force: true });
});

test("package.json version tracks the root package", () => {
  assert.equal(pkg.version, rootPkg.version);
});

test("exposes the documented `0`, `0sec`, and `0sec-cli` commands", () => {
  assert.deepEqual(Object.keys(pkg.bin).sort(), ["0", "0sec", "0sec-cli"]);
  // All three commands back onto one launcher file.
  const targets = new Set(Object.values(pkg.bin));
  assert.equal(targets.size, 1);
  const [launcherRel] = [...targets];
  assert.equal(launcherRel, "bin/0sec.cjs");
});

test("the launcher file exists, is executable, and has the version baked in", () => {
  const launcher = join(OUT, "bin", "0sec.cjs");
  assert.ok(existsSync(launcher), "bin/0sec.cjs should be emitted");
  const mode = statSync(launcher).mode & 0o777;
  assert.ok(mode & 0o100, `launcher should be owner-executable (got ${mode.toString(8)})`);
  const src = readFileSync(launcher, "utf8");
  assert.ok(src.startsWith("#!/usr/bin/env node"), "launcher needs a node shebang");
  assert.ok(!src.includes("__0SEC_VERSION__"), "version placeholder must be substituted");
  assert.ok(src.includes(`"${rootPkg.version}"`), "concrete version must be baked in");
});

test("publishable file list is present and self-contained", () => {
  assert.deepEqual(pkg.files, ["bin", "README.md", "LICENSE"]);
  for (const f of ["README.md", "LICENSE"]) {
    assert.ok(existsSync(join(OUT, f)), `${f} should be copied into dist-npm/`);
  }
});
