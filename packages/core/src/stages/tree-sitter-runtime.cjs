/*
 * `node-gyp-build` discovers native addons through runtime filesystem probing,
 * which Bun's compiler cannot see. The release script stages one parser/grammar
 * pair at these fixed paths; the direct requires make Bun embed them.
 */
const path = require("node:path");

const compiled = typeof __0SEC_COMPILED_TARGET__ === "string";
if (!compiled) {
  module.exports = {
    Parser: require("tree-sitter"),
    language: require("tree-sitter-c"),
  };
} else {
  const assetRoot = path.join(__dirname, "tree-sitter-compiled");
  const keys = ["TREE_SITTER_PREBUILD", "TREE_SITTER_C_PREBUILD", "npm_config_platform", "npm_config_arch"];
  const saved = new Map(keys.map((key) => [key, process.env[key]]));
  process.env.TREE_SITTER_PREBUILD = path.join(assetRoot, "tree-sitter");
  process.env.TREE_SITTER_C_PREBUILD = path.join(assetRoot, "tree-sitter-c");
  process.env.npm_config_platform = "bundled";
  process.env.npm_config_arch = "native";
  try {
    require("./tree-sitter-compiled/tree-sitter/prebuilds/bundled-native/tree-sitter.node");
    require("./tree-sitter-compiled/tree-sitter-c/prebuilds/bundled-native/tree-sitter-c.node");
    module.exports = {
      Parser: require("tree-sitter"),
      language: require("tree-sitter-c"),
    };
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}
