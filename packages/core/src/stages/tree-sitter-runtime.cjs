/*
 * `node-gyp-build` discovers native addons through runtime filesystem probing,
 * which Bun's compiler cannot see. The release script stages one parser/grammar
 * pair at these fixed paths; the direct requires make Bun embed them.
 */

const compiled = typeof __0SEC_COMPILED_TARGET__ === "string";
if (!compiled) {
  module.exports = {
    Parser: require("tree-sitter"),
    language: require("tree-sitter-c"),
  };
} else {
  const parserBinding = require("./tree-sitter-compiled/tree-sitter/prebuilds/bundled-native/tree-sitter.node");
  const language = require("./tree-sitter-compiled/tree-sitter-c/prebuilds/bundled-native/tree-sitter-c.node");
  // tree-sitter's JavaScript wrapper is useful (it wires Parser's prototypes),
  // but it calls node-gyp-build dynamically. Give that one wrapper the addon
  // Bun embedded above instead of letting it probe a nonexistent filesystem.
  const loaderPath = require.resolve("node-gyp-build");
  const hadLoader = Object.prototype.hasOwnProperty.call(require.cache, loaderPath);
  const previousLoader = require.cache[loaderPath];
  require.cache[loaderPath] = { exports: () => parserBinding };
  try {
    module.exports = {
      Parser: require("tree-sitter"),
      language,
    };
  } finally {
    if (hadLoader) require.cache[loaderPath] = previousLoader;
    else delete require.cache[loaderPath];
  }
}
