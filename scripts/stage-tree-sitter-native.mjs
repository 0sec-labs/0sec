#!/usr/bin/env node

import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const [target, destination] = process.argv.slice(2);
if (!target || !destination) {
  throw new Error("Usage: stage-tree-sitter-native.mjs <platform-arch> <destination>");
}

const require = createRequire(import.meta.url);

function packageDirectory(name) {
  return dirname(require.resolve(`${name}/package.json`));
}

function addonPath(packageDir, prebuiltName, buildName) {
  const prebuilt = join(packageDir, "prebuilds", target, prebuiltName);
  if (existsSync(prebuilt)) return prebuilt;

  const built = join(packageDir, "build", "Release", buildName);
  if (existsSync(built)) return built;

  throw new Error(
    `No native addon for ${target}: expected ${prebuilt} or ${built}. ` +
      "Install dependencies with lifecycle scripts before compiling.",
  );
}

const parserPackage = packageDirectory("tree-sitter");
const grammarPackage = packageDirectory("tree-sitter-c");
const parser = addonPath(parserPackage, "tree-sitter.node", "tree_sitter_runtime_binding.node");
const grammar = addonPath(grammarPackage, "tree-sitter-c.node", "tree_sitter_c_binding.node");
const parserDestination = join(destination, "tree-sitter.node");
const grammarDestination = join(destination, "tree-sitter-c.node");
const wrapperDestination = join(destination, "tree-sitter-runtime.cjs");
const wrapper = readFileSync(join(parserPackage, "index.js"), "utf8");
const patchedWrapper = wrapper.replace(
  "require('node-gyp-build')(__dirname)",
  "require('./tree-sitter.node')",
);
if (patchedWrapper === wrapper) {
  throw new Error("tree-sitter wrapper no longer has the expected node-gyp-build loader.");
}

rmSync(destination, { recursive: true, force: true });
mkdirSync(destination, { recursive: true });
copyFileSync(parser, parserDestination);
copyFileSync(grammar, grammarDestination);
writeFileSync(wrapperDestination, patchedWrapper);

console.log(`Staged tree-sitter native addons for ${target}`);
