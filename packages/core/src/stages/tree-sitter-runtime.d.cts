import type Parser from "tree-sitter";

declare const runtime: {
  readonly Parser: new () => Parser;
  readonly language: Parameters<Parser["setLanguage"]>[0];
};

export default runtime;
