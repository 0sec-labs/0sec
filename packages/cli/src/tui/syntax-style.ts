/**
 * Syntax highlighting for fenced code blocks in the chat transcript.
 *
 * This module answers two questions and nothing else:
 *
 *   1. Given one already-sanitised, already-width-fit line of code and its
 *      language, what are its coloured tokens? — `highlightCode`.
 *   2. Given the active theme, what colour and weight does each token kind
 *      get? — `codeTokenStyle`.
 *
 * Both are pure: no React, no opentui, no I/O, no native handles. That is a
 * deliberate choice, not a limitation. @opentui/core 0.5.4 ships a native
 * `<code filetype syntaxStyle>` renderable backed by a tree-sitter worker, and
 * it does highlight JavaScript and TypeScript well. We do NOT use it here, for
 * reasons documented at the bottom of this file (`toSyntaxStyleDefs`): the
 * languages an offensive-security console shows most — bash, http, json — have
 * no parser bundled in this version and fail to load offline, its highlighting
 * is asynchronous (so it paints unstyled first and can't be captured
 * deterministically), and it manages its own sizing and native lifecycle,
 * which fights this project's pure, pre-wrapped, no-overflow markdown pipeline.
 *
 * A hand-written lexer, by contrast, is synchronous, total, covers every
 * language the same way, and drops straight into the existing block renderer as
 * styled spans. The token-kind names below mirror tree-sitter's capture names
 * on purpose, so the theme mapping is forward-compatible with the native path
 * if a later @opentui version bundles the parsers we need.
 *
 * The lexers are hand-rolled character scanners rather than regex-driven, for
 * the same reason `markdown.ts` is: every scan advances at least one character,
 * so a pathological line stays linear and can never hang the render loop.
 */

import type { Theme } from "./theme-context.js";

/**
 * A highlighted token. `text` is verbatim source (never a marker or an
 * escape — the input has already been through `markdown.ts`'s sanitiser), so
 * the concatenation of a line's token texts is exactly the input line. That
 * identity is what lets the renderer trust these for indentation and padding.
 */
export interface CodeToken {
  text: string;
  kind: CodeTokenKind;
}

/**
 * Token kinds, named to match tree-sitter's highlight captures so
 * `toSyntaxStyleDefs` can hand the same palette to the native renderable.
 * `plain` is uncoloured source — whitespace, ordinary identifiers, and every
 * character of an unrecognised language.
 */
export type CodeTokenKind =
  | "plain"
  | "keyword"
  | "string"
  | "comment"
  | "number"
  | "function"
  | "type"
  | "constant"
  | "variable"
  | "operator"
  | "punctuation"
  | "property";

/** How a token kind paints: a theme colour plus optional real attributes. */
export interface CodeTokenStyle {
  fg: string;
  bold?: boolean;
  italic?: boolean;
  dim?: boolean;
}

/** Language families the lexer knows. Everything else renders as `plain`. */
export type CodeLang = "bash" | "js" | "ts" | "json" | "plain";

// ---------------------------------------------------------------------------
// Theme mapping
// ---------------------------------------------------------------------------

/**
 * Map a token kind onto the active theme.
 *
 * `ERROR` (red) is never used: red means an error everywhere else in the TUI,
 * and a red keyword would read as a failure. Every colour here is a swept text
 * token, so each has adequate contrast on the code surface.
 */
export function codeTokenStyle(kind: CodeTokenKind, theme: Theme): CodeTokenStyle {
  switch (kind) {
    case "keyword":
      return { fg: theme.PRIMARY, bold: true };
    case "string":
      return { fg: theme.SUCCESS };
    case "comment":
      return { fg: theme.MUTED, dim: true, italic: true };
    case "number":
      return { fg: theme.WARNING };
    case "function":
      return { fg: theme.INFO };
    case "type":
      return { fg: theme.BRAND };
    case "constant":
      return { fg: theme.ACCENT };
    case "property":
      return { fg: theme.INFO };
    case "operator":
    case "punctuation":
      return { fg: theme.MUTED };
    case "variable":
    case "plain":
    default:
      return { fg: theme.TEXT };
  }
}

// ---------------------------------------------------------------------------
// Language normalisation
// ---------------------------------------------------------------------------

const LANG_ALIASES: Record<string, CodeLang> = {
  sh: "bash",
  bash: "bash",
  shell: "bash",
  zsh: "bash",
  console: "bash",
  shellsession: "bash",
  js: "js",
  javascript: "js",
  jsx: "js",
  mjs: "js",
  cjs: "js",
  node: "js",
  ts: "ts",
  typescript: "ts",
  tsx: "ts",
  json: "json",
  jsonc: "json",
  json5: "json",
};

/** Fold a fence's info string onto a known family, or `plain`. */
export function normalizeCodeLang(language?: string): CodeLang {
  if (!language) return "plain";
  return LANG_ALIASES[language.trim().toLowerCase()] ?? "plain";
}

// ---------------------------------------------------------------------------
// Lexers
// ---------------------------------------------------------------------------

const JS_KEYWORDS = new Set([
  "const", "let", "var", "function", "return", "if", "else", "for", "while",
  "do", "switch", "case", "break", "continue", "new", "class", "extends",
  "super", "this", "typeof", "instanceof", "in", "of", "try", "catch",
  "finally", "throw", "async", "await", "yield", "import", "from", "export",
  "default", "delete", "void", "static", "get", "set",
]);

const TS_KEYWORDS = new Set([
  ...JS_KEYWORDS,
  "interface", "type", "enum", "namespace", "declare", "implements", "public",
  "private", "protected", "readonly", "abstract", "as", "satisfies", "keyof",
  "infer", "is", "unknown", "never", "any",
]);

const JS_CONSTANTS = new Set(["true", "false", "null", "undefined", "NaN", "Infinity"]);

const BASH_KEYWORDS = new Set([
  "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done",
  "case", "esac", "function", "in", "select", "time", "return", "local",
  "export", "readonly", "declare", "set", "unset", "shift", "eval", "exec",
  "source", "alias", "trap", "test",
]);

function isDigit(ch: string): boolean {
  return ch >= "0" && ch <= "9";
}

function isIdentStart(ch: string): boolean {
  return /[A-Za-z_$]/.test(ch);
}

function isIdentChar(ch: string): boolean {
  return /[A-Za-z0-9_$]/.test(ch);
}

const JS_OP_CHARS = "+-*/%=<>!&|^~?:";

function push(out: CodeToken[], text: string, kind: CodeTokenKind): void {
  if (!text) return;
  const last = out[out.length - 1];
  if (last && last.kind === kind) {
    last.text += text;
    return;
  }
  out.push({ text, kind });
}

/** Consume a quoted string starting at `i`; returns the index past the close. */
function scanString(line: string, i: number, quote: string, out: CodeToken[]): number {
  let j = i + 1;
  while (j < line.length) {
    if (line[j] === "\\") {
      j += 2;
      continue;
    }
    if (line[j] === quote) {
      j += 1;
      break;
    }
    j += 1;
  }
  push(out, line.slice(i, Math.min(j, line.length)), "string");
  return Math.min(j, line.length);
}

/** Consume a numeric literal starting at `i`; returns the index past it. */
function scanNumber(line: string, i: number, out: CodeToken[]): number {
  let j = i;
  if (line[j] === "0" && (line[j + 1] === "x" || line[j + 1] === "X")) {
    j += 2;
    while (j < line.length && /[0-9a-fA-F]/.test(line[j] as string)) j += 1;
  } else {
    while (j < line.length && (isDigit(line[j] as string) || line[j] === "." || line[j] === "_")) j += 1;
    if (line[j] === "e" || line[j] === "E") {
      j += 1;
      if (line[j] === "+" || line[j] === "-") j += 1;
      while (j < line.length && isDigit(line[j] as string)) j += 1;
    }
  }
  push(out, line.slice(i, j), "number");
  return j;
}

function lexJsLike(line: string, keywords: Set<string>): CodeToken[] {
  const out: CodeToken[] = [];
  let i = 0;
  while (i < line.length) {
    const ch = line[i] as string;
    // Line comment.
    if (ch === "/" && line[i + 1] === "/") {
      push(out, line.slice(i), "comment");
      break;
    }
    // Block comment — within this one line only.
    if (ch === "/" && line[i + 1] === "*") {
      const end = line.indexOf("*/", i + 2);
      const stop = end < 0 ? line.length : end + 2;
      push(out, line.slice(i, stop), "comment");
      i = stop;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      i = scanString(line, i, ch, out);
      continue;
    }
    if (isDigit(ch) || (ch === "." && isDigit(line[i + 1] ?? ""))) {
      i = scanNumber(line, i, out);
      continue;
    }
    if (isIdentStart(ch)) {
      let j = i + 1;
      while (j < line.length && isIdentChar(line[j] as string)) j += 1;
      const word = line.slice(i, j);
      let k = j;
      while (k < line.length && line[k] === " ") k += 1;
      if (keywords.has(word)) push(out, word, "keyword");
      else if (JS_CONSTANTS.has(word)) push(out, word, "constant");
      else if (line[k] === "(") push(out, word, "function");
      else push(out, word, "plain");
      i = j;
      continue;
    }
    if (JS_OP_CHARS.includes(ch)) {
      let j = i + 1;
      while (j < line.length && JS_OP_CHARS.includes(line[j] as string)) j += 1;
      push(out, line.slice(i, j), "operator");
      i = j;
      continue;
    }
    if ("()[]{},;.".includes(ch)) {
      push(out, ch, "punctuation");
      i += 1;
      continue;
    }
    push(out, ch, "plain");
    i += 1;
  }
  return out;
}

function lexBash(line: string): CodeToken[] {
  const out: CodeToken[] = [];
  let i = 0;
  while (i < line.length) {
    const ch = line[i] as string;
    // A comment: an unquoted # at line start or after whitespace.
    if (ch === "#" && (i === 0 || line[i - 1] === " " || line[i - 1] === "\t")) {
      push(out, line.slice(i), "comment");
      break;
    }
    if (ch === '"' || ch === "'") {
      i = scanString(line, i, ch, out);
      continue;
    }
    // A variable reference: $NAME, ${...}, $?, $#, $1 …
    if (ch === "$") {
      let j = i + 1;
      if (line[j] === "{") {
        const end = line.indexOf("}", j + 1);
        j = end < 0 ? line.length : end + 1;
      } else if (line[j] !== undefined && /[A-Za-z_?#@*!$0-9]/.test(line[j] as string)) {
        j += 1;
        while (j < line.length && isIdentChar(line[j] as string)) j += 1;
      }
      push(out, line.slice(i, j), "variable");
      i = j;
      continue;
    }
    if (isDigit(ch)) {
      i = scanNumber(line, i, out);
      continue;
    }
    if (isIdentStart(ch)) {
      let j = i + 1;
      while (j < line.length && isIdentChar(line[j] as string)) j += 1;
      const word = line.slice(i, j);
      push(out, word, BASH_KEYWORDS.has(word) ? "keyword" : "plain");
      i = j;
      continue;
    }
    if ("|&;<>()".includes(ch)) {
      push(out, ch, "operator");
      i += 1;
      continue;
    }
    push(out, ch, "plain");
    i += 1;
  }
  return out;
}

function lexJson(line: string): CodeToken[] {
  const out: CodeToken[] = [];
  let i = 0;
  while (i < line.length) {
    const ch = line[i] as string;
    if (ch === '"') {
      const start = i;
      i = scanString(line, i, '"', out);
      // A string that is followed (past spaces) by a colon is an object key.
      let k = i;
      while (k < line.length && line[k] === " ") k += 1;
      if (line[k] === ":") {
        // Re-tag the string token we just pushed as a property.
        const tok = out[out.length - 1];
        if (tok && tok.text === line.slice(start, i)) tok.kind = "property";
      }
      continue;
    }
    if (isDigit(ch) || (ch === "-" && isDigit(line[i + 1] ?? ""))) {
      const start = ch === "-" ? i + 1 : i;
      const next = scanNumber(line, start, out);
      if (ch === "-") {
        // Fold the leading minus into the number token.
        const tok = out[out.length - 1];
        if (tok && tok.kind === "number") tok.text = "-" + tok.text;
      }
      i = next;
      continue;
    }
    if (isIdentStart(ch)) {
      let j = i + 1;
      while (j < line.length && isIdentChar(line[j] as string)) j += 1;
      const word = line.slice(i, j);
      push(out, word, JS_CONSTANTS.has(word) ? "constant" : "plain");
      i = j;
      continue;
    }
    if ("{}[],:".includes(ch)) {
      push(out, ch, "punctuation");
      i += 1;
      continue;
    }
    push(out, ch, "plain");
    i += 1;
  }
  return out;
}

/**
 * Tokenise one line of code for highlighting.
 *
 * The input must be a single physical line, already sanitised and width-fit by
 * `markdown.ts` (this module never sees an escape or a control byte). The sum
 * of the returned tokens' `text` is exactly the input line, so the renderer can
 * rely on it for indentation and surface padding. An unknown or absent language
 * yields a single `plain` token — the code still renders on the code surface,
 * just uncoloured, which is always safe.
 *
 * Multi-line constructs (a `/* *\/` block comment or a heredoc that spans rows)
 * are highlighted per line: each line is treated independently. This is the one
 * deliberate imprecision of a lightweight highlighter and it never produces a
 * wrong character, only an occasionally under-coloured one.
 */
export function highlightCode(line: string, language?: string): CodeToken[] {
  const text = String(line ?? "");
  if (text.length === 0) return [];
  const lang = normalizeCodeLang(language);
  switch (lang) {
    case "bash":
      return lexBash(text);
    case "js":
      return lexJsLike(text, JS_KEYWORDS);
    case "ts":
      return lexJsLike(text, TS_KEYWORDS);
    case "json":
      return lexJson(text);
    case "plain":
    default:
      return [{ text, kind: "plain" }];
  }
}

// ---------------------------------------------------------------------------
// Native forward-compatibility
// ---------------------------------------------------------------------------

/**
 * The same theme palette expressed as @opentui/core `SyntaxStyle` style
 * definitions, keyed by tree-sitter capture name.
 *
 * We do not consume this today (see the module header for why the native
 * `<code>` renderable is not used in 0.5.4), but it is the bridge if a later
 * version bundles bash/json parsers and resolves the tree-sitter worker
 * offline. At that point:
 *
 *   import { SyntaxStyle } from "@opentui/core";
 *   const style = SyntaxStyle.fromStyles(toSyntaxStyleDefs(theme));
 *   // then <code content={src} filetype={lang} syntaxStyle={style} />
 *
 * `SyntaxStyle` is a native handle that must be created from the render lib and
 * destroyed, so a real integration memoises one per theme and disposes it on
 * theme change — which is exactly the native-lifecycle cost that keeps it out
 * of this otherwise-pure module. Kept pure here so it is unit-testable.
 */
export function toSyntaxStyleDefs(
  theme: Theme,
): Record<string, { fg: string; bold?: boolean; italic?: boolean; dim?: boolean }> {
  const kinds: CodeTokenKind[] = [
    "keyword", "string", "comment", "number", "function", "type",
    "constant", "variable", "operator", "punctuation", "property",
  ];
  const defs: Record<string, { fg: string; bold?: boolean; italic?: boolean; dim?: boolean }> = {
    default: { fg: theme.TEXT },
  };
  for (const kind of kinds) {
    const style = codeTokenStyle(kind, theme);
    defs[kind] = { fg: style.fg, bold: style.bold, italic: style.italic, dim: style.dim };
  }
  return defs;
}
