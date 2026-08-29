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
  // The staged wrapper is tree-sitter's own JavaScript API with only its
  // node-gyp-build line replaced by a direct embedded-addon require.
  module.exports = {
    Parser: require("./tree-sitter-compiled/tree-sitter-runtime.cjs"),
    language: require("./tree-sitter-compiled/tree-sitter-c.node"),
  };
}
