#!/usr/bin/env node

import { copyFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
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

const parser = addonPath(
  packageDirectory("tree-sitter"),
  "tree-sitter.node",
  "tree_sitter_runtime_binding.node",
);
const grammar = addonPath(
  packageDirectory("tree-sitter-c"),
  "tree-sitter-c.node",
  "tree_sitter_c_binding.node",
);
const parserDestination = join(destination, "tree-sitter", "prebuilds", "bundled-native", "tree-sitter.node");
const grammarDestination = join(destination, "tree-sitter-c", "prebuilds", "bundled-native", "tree-sitter-c.node");

rmSync(destination, { recursive: true, force: true });
mkdirSync(dirname(parserDestination), { recursive: true });
mkdirSync(dirname(grammarDestination), { recursive: true });
copyFileSync(parser, parserDestination);
copyFileSync(grammar, grammarDestination);

console.log(`Staged tree-sitter native addons for ${target}`);
