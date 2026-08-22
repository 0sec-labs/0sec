/**
 * Markdown -> styled spans, for the chat transcript.
 *
 * Models emit markdown whether or not anyone asked them to. Rendering their
 * replies as raw text is why the console shows `**A repository / local code
 * scope**` with the asterisks painted on screen. This module turns a model
 * message into a block/span tree that a terminal component can paint with one
 * colour per span, and does the line-breaking itself so the component never
 * has to guess how many cells a styled run occupies.
 *
 * Everything here is pure: no React, no opentui, no I/O, no clock, no
 * randomness. `renderMarkdown(source, width)` is a total function — every
 * input, including hostile ones, produces a value.
 *
 * Three invariants matter more than fidelity to CommonMark:
 *
 *   1. Nothing model-authored reaches the terminal with an escape sequence in
 *      it. Every string that leaves this module has been through the same
 *      stripping `sanitizeTuiText` applies, so a model cannot move the cursor,
 *      repaint the header, or set the window title by emitting `\x1b[...`.
 *   2. No input can hang the render loop. The inline scanner is hand-written
 *      rather than regex-driven, and every "look ahead for a closing marker"
 *      search is memoised so a line of 5000 unmatched `*` stays linear.
 *   3. A marker either styles something or is shown literally. A stray `*` is
 *      text; it is never silently swallowed.
 */

import { sanitizeTuiText } from "./text.js";

export type SpanStyle = "text" | "bold" | "italic" | "code" | "link" | "muted" | "strike";

export interface MdSpan {
  text: string;
  style: SpanStyle;
}

/**
 * A wrapped block.
 *
 * `lines` is always post-wrap: each entry is one physical terminal row, and
 * the spans in it are guaranteed to fit the cells the block was given.
 * Headings carry `lines` rather than a single `spans` array for the same
 * reason paragraphs do — a model heading regularly exceeds a narrow pane, and
 * silently truncating it loses content the user asked for.
 */
export type MdBlock =
  | { kind: "paragraph"; lines: MdSpan[][] }
  | { kind: "heading"; level: number; lines: MdSpan[][] }
  | { kind: "listItem"; marker: string; indent: number; lines: MdSpan[][] }
  | { kind: "code"; language?: string; lines: string[] }
  | { kind: "quote"; lines: MdSpan[][] }
  | { kind: "rule" };

export type MdListItemBlock = Extract<MdBlock, { kind: "listItem" }>;

/** Cells the renderer must reserve left of a `quote` block's lines. */
export const QUOTE_GUTTER_WIDTH = 2;

/** Cells one level of list nesting adds, regardless of the source indent. */
export const LIST_INDENT_WIDTH = 2;

/** Deepest list nesting that still earns indentation; beyond this it flattens. */
const MAX_LIST_DEPTH = 6;

/** Appended to a code line that did not fit. One cell, unlike `fitTuiText`'s "...". */
const CODE_TRUNCATION_MARK = "…";

/** Markdown treats a tab as advancing to the next multiple of four. */
const TAB_WIDTH = 4;

/** Emphasis may not nest deeper than this; past it the markers stay literal. */
const MAX_INLINE_DEPTH = 6;

/**
 * Cells the renderer must reserve left of a list item's lines: the nesting
 * indent, the marker itself, and one space after it. The first row gets the
 * marker; continuation rows get this many spaces so the text stays aligned.
 */
export function listItemGutterWidth(block: Pick<MdListItemBlock, "marker" | "indent">): number {
  return block.indent + cellCount(block.marker) + 1;
}

// ---------------------------------------------------------------------------
// Sanitising
// ---------------------------------------------------------------------------

/**
 * Strip escapes and control characters without destroying layout whitespace.
 *
 * `sanitizeTuiText` is the project's stripping rule and we do not want a
 * second, subtly different copy of it — but it also collapses every whitespace
 * run to one space and trims, which would erase the leading indentation that
 * decides list nesting and the interior indentation that makes a code block
 * readable. So we hand it only the non-whitespace runs and stitch the gaps
 * back in ourselves.
 *
 * Splitting on whitespace cannot smuggle an escape past it: `sanitizeTuiText`
 * removes every 0x1b byte unconditionally, not only the ones that parse as a
 * complete CSI/OSC sequence. A sequence broken across a space therefore loses
 * its ESC and degrades to inert literal text.
 */
function stripControl(value: string): string {
  return value.replace(/\S+/g, (chunk) => (needsSanitize(chunk) ? sanitizeTuiText(chunk) : chunk));
}

/** Cheapest possible probe for any control byte, ESC included. Linear, no backtracking. */
const CONTROL_PROBE = /[\x00-\x1f\x7f]/;

/**
 * `sanitizeTuiText` compiles a RegExp on every call, so a long message would
 * pay for one per word. Short chunks with no control bytes cannot be changed
 * by it — 32 is the floor its encoded-payload guard will ever use — so they
 * skip the call entirely.
 */
function needsSanitize(chunk: string): boolean {
  return chunk.length >= 32 || CONTROL_PROBE.test(chunk);
}

/** Expand tabs by column: a raw tab in a terminal jumps the cursor. */
function expandTabs(line: string): string {
  if (!line.includes("\t")) return line;
  let out = "";
  let col = 0;
  for (const ch of line) {
    if (ch === "\t") {
      const advance = TAB_WIDTH - (col % TAB_WIDTH);
      out += " ".repeat(advance);
      col += advance;
    } else {
      out += ch;
      col += 1;
    }
  }
  return out;
}

function normalizeSource(source: string): string[] {
  return String(source ?? "")
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((line) => stripControl(expandTabs(line)));
}

// ---------------------------------------------------------------------------
// Width helpers
// ---------------------------------------------------------------------------

/**
 * Width in cells.
 *
 * Counted in code points rather than UTF-16 units so an emoji is never split
 * down the middle into two lone surrogates — a half surrogate is what puts a
 * replacement glyph in the middle of a word. This deliberately does not
 * implement full wcwidth: East Asian wide characters still count as one cell,
 * the same assumption the rest of the TUI's budgeting makes.
 */
function cellCount(text: string): number {
  let count = 0;
  for (const _ of text) count += 1;
  return count;
}

function normalizeWidth(width: number): number {
  if (!Number.isFinite(width)) return 0;
  return Math.max(0, Math.trunc(width));
}

// ---------------------------------------------------------------------------
// Inline parsing
// ---------------------------------------------------------------------------

const ESCAPABLE = new Set([
  "\\", "`", "*", "_", "~", "[", "]", "(", ")", "#", "+", "-", ".", "!", ">", "|",
]);

function isWordChar(ch: string): boolean {
  return ch.length > 0 && /[A-Za-z0-9]/.test(ch);
}

function pushSpan(out: MdSpan[], text: string, style: SpanStyle): void {
  if (!text) return;
  const last = out[out.length - 1];
  if (last && last.style === style) {
    last.text += text;
    return;
  }
  out.push({ text, style });
}

/**
 * Find a run of exactly `n` backticks at or after `from`.
 *
 * "Exactly" is what lets `` `a ` b` `` behave: a longer run is not a closer,
 * it is content. Runs are skipped whole, so this is linear in the line.
 */
function findBacktickRun(text: string, from: number, n: number): number {
  let j = from;
  while (j < text.length) {
    if (text[j] !== "`") {
      j += 1;
      continue;
    }
    let runLen = 1;
    while (text[j + runLen] === "`") runLen += 1;
    if (runLen === n) return j;
    j += runLen;
  }
  return -1;
}

/**
 * Find the closing emphasis run for a delimiter opened before `from`.
 *
 * A closer must (a) be a run of the same character at least as long as the
 * opener, (b) leave non-empty content, (c) not be preceded by a space, so
 * `a * b * c` stays literal arithmetic rather than becoming italic, and (d)
 * for `_`, not sit inside a word, so `snake_case_name` survives intact.
 *
 * Every one of those conditions depends only on the candidate's own position,
 * never on where the opener was. That is what makes the caller's "this
 * delimiter has no closer anywhere left in the line" memo sound: a later
 * opener can only ever see a subset of the candidates this search rejected.
 */
function findEmphasisClose(text: string, from: number, ch: string, delimLen: number): number {
  let j = from;
  while (j < text.length) {
    if (text[j] !== ch) {
      j += 1;
      continue;
    }
    let runLen = 1;
    while (text[j + runLen] === ch) runLen += 1;
    const closesWord = ch !== "_" || !isWordChar(text[j + runLen] ?? "");
    if (runLen >= delimLen && j > from && text[j - 1] !== " " && closesWord) return j;
    j += runLen;
  }
  return -1;
}

/** Balanced `]` for a link label, or -1. Bails immediately when there is none. */
function findLabelEnd(text: string, open: number): number {
  if (text.indexOf("]", open + 1) < 0) return -1;
  let depth = 0;
  for (let j = open; j < text.length; j += 1) {
    const ch = text[j];
    if (ch === "\\") {
      j += 1;
      continue;
    }
    if (ch === "[") depth += 1;
    else if (ch === "]") {
      depth -= 1;
      if (depth === 0) return j;
    }
  }
  return -1;
}

/** Balanced `)` for a link destination, or -1. */
function findParenEnd(text: string, open: number): number {
  if (text.indexOf(")", open + 1) < 0) return -1;
  let depth = 0;
  for (let j = open; j < text.length; j += 1) {
    const ch = text[j];
    if (ch === "\\") {
      j += 1;
      continue;
    }
    if (ch === "(") depth += 1;
    else if (ch === ")") {
      depth -= 1;
      if (depth === 0) return j;
    }
  }
  return -1;
}

/** CommonMark strips one padding space from each end of a code span. */
function normalizeCodeContent(content: string): string {
  if (content.length >= 2 && content.startsWith(" ") && content.endsWith(" ") && content.trim() !== "") {
    return content.slice(1, -1);
  }
  return content;
}

function parseInlineInto(text: string, style: SpanStyle, depth: number, out: MdSpan[]): void {
  if (!text) return;
  if (depth >= MAX_INLINE_DEPTH) {
    pushSpan(out, text, style);
    return;
  }

  // Delimiters proven to have no closer left in this line. See
  // findEmphasisClose for why one failure settles it for every later opener —
  // without this, a line of 5000 `*` is quadratic.
  const dead = new Set<string>();

  let literalStart = 0;
  let i = 0;

  const flushLiteral = (end: number): void => {
    if (end > literalStart) pushSpan(out, text.slice(literalStart, end), style);
  };

  while (i < text.length) {
    const ch = text[i] as string;

    if (ch === "\\") {
      const next = text[i + 1];
      if (next !== undefined && ESCAPABLE.has(next)) {
        flushLiteral(i);
        pushSpan(out, next, style);
        i += 2;
        literalStart = i;
        continue;
      }
      i += 1;
      continue;
    }

    if (ch === "`") {
      let n = 1;
      while (text[i + n] === "`") n += 1;
      const close = findBacktickRun(text, i + n, n);
      if (close >= 0) {
        flushLiteral(i);
        // Code span content is literal by definition: no recursion, so
        // `**not bold**` inside backticks keeps its asterisks.
        pushSpan(out, normalizeCodeContent(text.slice(i + n, close)), "code");
        i = close + n;
        literalStart = i;
        continue;
      }
      i += n;
      continue;
    }

    if (ch === "*" || ch === "_" || ch === "~") {
      let runLen = 1;
      while (text[i + runLen] === ch) runLen += 1;

      let delimLen: number;
      let nested: SpanStyle;
      if (ch === "~") {
        if (runLen < 2) {
          i += runLen;
          continue;
        }
        delimLen = 2;
        nested = "strike";
      } else if (runLen >= 3) {
        // Bold-italic collapses to bold: SpanStyle is one attribute per span,
        // and bold is the half a terminal reader actually notices.
        delimLen = 3;
        nested = "bold";
      } else if (runLen === 2) {
        delimLen = 2;
        nested = "bold";
      } else {
        delimLen = 1;
        nested = "italic";
      }

      const after = text[i + delimLen];
      const openerOk =
        after !== undefined &&
        after !== " " &&
        (ch !== "_" || i === 0 || !isWordChar(text[i - 1] ?? ""));
      const key = `${ch}${delimLen}`;

      if (openerOk && !dead.has(key)) {
        const from = i + delimLen;
        const close = findEmphasisClose(text, from, ch, delimLen);
        if (close >= 0) {
          flushLiteral(i);
          parseInlineInto(text.slice(from, close), nested, depth + 1, out);
          i = close + delimLen;
          literalStart = i;
          continue;
        }
        dead.add(key);
      }
      i += runLen;
      continue;
    }

    if (ch === "[") {
      const labelEnd = findLabelEnd(text, i);
      if (labelEnd > i && text[labelEnd + 1] === "(") {
        const parenEnd = findParenEnd(text, labelEnd + 1);
        if (parenEnd > labelEnd + 1) {
          const label = text.slice(i + 1, labelEnd);
          const url = text.slice(labelEnd + 2, parenEnd).trim();
          flushLiteral(i);
          if (label) parseInlineInto(label, "link", depth + 1, out);
          else pushSpan(out, url, "link");
          // A terminal cannot follow a link, so the destination is shown
          // rather than hidden behind the label — muted, so it reads as
          // chrome. Skipped when it would just repeat the label.
          if (url && url !== label) pushSpan(out, ` (${url})`, "muted");
          i = parenEnd + 1;
          literalStart = i;
          continue;
        }
      }
      i += 1;
      continue;
    }

    i += 1;
  }

  flushLiteral(text.length);
}

/** Parse inline markup within a single logical line. */
export function parseInline(line: string): MdSpan[] {
  const out: MdSpan[] = [];
  parseInlineInto(stripControl(String(line ?? "")), "text", 0, out);
  return out.filter((span) => span.text.length > 0);
}

/** Flatten spans back to plain text. Useful for measurement and assertions. */
export function spansToText(spans: readonly MdSpan[]): string {
  let out = "";
  for (const span of spans) out += span.text;
  return out;
}

// ---------------------------------------------------------------------------
// Wrapping
// ---------------------------------------------------------------------------

interface WrapToken {
  text: string;
  style: SpanStyle;
  space: boolean;
}

function tokenize(spans: readonly MdSpan[]): WrapToken[] {
  const tokens: WrapToken[] = [];
  for (const span of spans) {
    const text = span.text;
    let i = 0;
    while (i < text.length) {
      const space = text[i] === " ";
      let j = i + 1;
      while (j < text.length && (text[j] === " ") === space) j += 1;
      tokens.push({ text: text.slice(i, j), style: span.style, space });
      i = j;
    }
  }
  return tokens;
}

/**
 * Greedy word wrap that preserves span identity.
 *
 * Span continuity across a break is not something that has to be tracked: the
 * wrapper works on tokens that each still carry the style of the span they
 * came from, so when a bold run straddles a break, the fragment left on row N
 * and the fragment starting row N+1 are both emitted as bold spans. Adjacent
 * fragments of the same style are merged back together, so a row never
 * contains two consecutive spans with equal styles, and `**a b**` stays one
 * span rather than three.
 *
 * A word wider than the whole column is hard-broken across rows instead of
 * overflowing — an overflowing row in this TUI does not clip, it paints over
 * its neighbours.
 */
export function wrapSpans(spans: readonly MdSpan[], width: number): MdSpan[][] {
  const w = normalizeWidth(width);
  // Zero columns can hold nothing. Returning no rows is the honest answer and
  // keeps every loop below guarded against a zero/negative budget.
  if (w <= 0) return [];

  const lines: MdSpan[][] = [];
  let line: MdSpan[] = [];
  let lineWidth = 0;
  let pendingSpace = false;

  const flush = (): void => {
    if (line.length > 0) lines.push(line);
    line = [];
    lineWidth = 0;
    pendingSpace = false;
  };

  const emit = (text: string, style: SpanStyle): void => {
    pushSpan(line, text, style);
    lineWidth += cellCount(text);
  };

  for (const token of tokenize(spans)) {
    if (token.space) {
      // Leading whitespace on a row is dropped, and a run of spaces collapses
      // to one: reflowed prose should not carry the source's line padding.
      if (lineWidth > 0) pendingSpace = true;
      continue;
    }

    let chars = Array.from(token.text);
    while (chars.length > 0) {
      const gap = pendingSpace && lineWidth > 0 ? 1 : 0;
      const avail = w - lineWidth - gap;

      if (chars.length <= avail) {
        if (gap > 0) emitGap(line, emit, token.style);
        emit(chars.join(""), token.style);
        pendingSpace = false;
        break;
      }

      if (chars.length <= w) {
        // Fits on a row of its own: move it down whole rather than splitting.
        // `line` is non-empty here (otherwise avail would be w), so this makes
        // progress and cannot loop.
        flush();
        continue;
      }

      // Longer than the column itself: hard break. `avail <= 0` implies the
      // row already has content, so flushing always advances.
      if (avail <= 0) {
        flush();
        continue;
      }
      if (gap > 0) emitGap(line, emit, token.style);
      const take = w - lineWidth;
      emit(chars.slice(0, take).join(""), token.style);
      chars = chars.slice(take);
      pendingSpace = false;
      flush();
    }
  }

  flush();
  return lines;
}

/**
 * The separating space belongs to whichever side it can join without changing
 * how it looks. Styles like `strike` and `link` paint a space visibly, so a
 * space between two differently-styled runs is neutral text.
 */
function emitGap(
  line: readonly MdSpan[],
  emit: (text: string, style: SpanStyle) => void,
  nextStyle: SpanStyle,
): void {
  const last = line[line.length - 1];
  emit(" ", last && last.style === nextStyle ? nextStyle : "text");
}

/** Join logical lines into one span run, so re-wrapping never fuses words. */
function joinLines(lines: readonly MdSpan[][]): MdSpan[] {
  const out: MdSpan[] = [];
  for (const line of lines) {
    if (out.length > 0) out.push({ text: " ", style: "text" });
    for (const span of line) out.push({ text: span.text, style: span.style });
  }
  return out;
}

/**
 * Code is truncated, never wrapped.
 *
 * Reflowing code changes what it means: a wrapped shell command looks like two
 * commands, a wrapped string literal looks like a different string, and a
 * wrapped diff line looks like it touches a line it does not. A user who needs
 * the tail of a long code line widens the pane or copies from the log; a user
 * shown silently reflowed code has been given something false.
 */
function truncateCodeLine(line: string, width: number): string {
  const chars = Array.from(line);
  if (chars.length <= width) return chars.join("");
  if (width <= 1) return chars.slice(0, width).join("");
  return chars.slice(0, width - 1).join("") + CODE_TRUNCATION_MARK;
}

// ---------------------------------------------------------------------------
// Block parsing
// ---------------------------------------------------------------------------

function leadingSpaces(line: string): number {
  let n = 0;
  while (line[n] === " ") n += 1;
  return n;
}

function isBlank(line: string): boolean {
  return line.trim().length === 0;
}

interface FenceMatch {
  char: string;
  len: number;
  info: string;
}

function matchFence(line: string): FenceMatch | null {
  const indent = leadingSpaces(line);
  if (indent > 3) return null;
  const rest = line.slice(indent);
  const char = rest[0];
  if (char !== "`" && char !== "~") return null;
  let len = 0;
  while (rest[len] === char) len += 1;
  if (len < 3) return null;
  const info = rest.slice(len).trim();
  // A backtick fence's info string may not itself contain a backtick,
  // otherwise `` ```a`b `` would eat the rest of the message as code.
  if (char === "`" && info.includes("`")) return null;
  return { char, len, info };
}

function isRule(line: string): boolean {
  const indent = leadingSpaces(line);
  if (indent > 3) return false;
  const rest = line.slice(indent).trimEnd();
  if (rest.length < 3) return false;
  const char = rest[0];
  if (char !== "-" && char !== "*" && char !== "_") return false;
  let count = 0;
  for (const ch of rest) {
    if (ch === char) count += 1;
    else if (ch !== " ") return false;
  }
  return count >= 3;
}

function matchHeading(line: string): { level: number; text: string } | null {
  const indent = leadingSpaces(line);
  if (indent > 3) return null;
  const rest = line.slice(indent);
  let level = 0;
  while (rest[level] === "#") level += 1;
  if (level === 0 || level > 6) return null;
  const after = rest.slice(level);
  if (after.length > 0 && after[0] !== " ") return null;
  const text = after.trim().replace(/\s+#+$/, "").trim();
  return { level, text };
}

function matchQuote(line: string): string | null {
  const indent = leadingSpaces(line);
  if (indent > 3) return null;
  const rest = line.slice(indent);
  if (rest[0] !== ">") return null;
  const body = rest.slice(1);
  return body.startsWith(" ") ? body.slice(1) : body;
}

interface ListMatch {
  sourceIndent: number;
  marker: string;
  body: string;
}

function matchListItem(line: string): ListMatch | null {
  const sourceIndent = leadingSpaces(line);
  const rest = line.slice(sourceIndent);
  const char = rest[0];
  if (char === "-" || char === "*" || char === "+") {
    if (rest[1] !== " ") return null;
    return { sourceIndent, marker: char, body: rest.slice(2).replace(/^ +/, "") };
  }
  let digits = 0;
  while (digits < 9 && rest[digits] !== undefined && rest[digits]! >= "0" && rest[digits]! <= "9") {
    digits += 1;
  }
  if (digits === 0) return null;
  const delim = rest[digits];
  if (delim !== "." && delim !== ")") return null;
  if (rest[digits + 1] !== " ") return null;
  return {
    sourceIndent,
    marker: rest.slice(0, digits + 1),
    body: rest.slice(digits + 2).replace(/^ +/, ""),
  };
}

/** True when a line would open a block of its own, ending any paragraph run. */
function startsBlock(line: string): boolean {
  return (
    isBlank(line) ||
    matchFence(line) !== null ||
    isRule(line) ||
    matchHeading(line) !== null ||
    matchQuote(line) !== null ||
    matchListItem(line) !== null
  );
}

/**
 * Parse into unwrapped blocks: every `lines` entry is one *logical* line, not
 * a terminal row. `renderMarkdown` is the wrapping pass on top of this.
 */
export function parseMarkdownBlocks(source: string): MdBlock[] {
  const lines = normalizeSource(source);
  const blocks: MdBlock[] = [];

  // Source indents of the currently open list levels, outermost first. Models
  // are wildly inconsistent about whether a nested item is indented by 2, 3 or
  // 4 spaces, so nesting is derived from this stack and re-emitted at a fixed
  // width rather than echoing whatever the model happened to type.
  let listStack: number[] = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i] as string;

    if (isBlank(line)) {
      i += 1;
      continue;
    }

    const fence = matchFence(line);
    if (fence) {
      listStack = [];
      const body: string[] = [];
      i += 1;
      while (i < lines.length) {
        const candidate = lines[i] as string;
        const closing = matchFence(candidate);
        if (closing && closing.char === fence.char && closing.len >= fence.len && closing.info === "") {
          i += 1;
          break;
        }
        body.push(candidate);
        i += 1;
      }
      const language = fence.info.split(/\s+/)[0] ?? "";
      // Content is verbatim: markdown inside a fence is text, not markup.
      blocks.push(language ? { kind: "code", language, lines: body } : { kind: "code", lines: body });
      continue;
    }

    if (isRule(line)) {
      listStack = [];
      blocks.push({ kind: "rule" });
      i += 1;
      continue;
    }

    const heading = matchHeading(line);
    if (heading) {
      listStack = [];
      blocks.push({ kind: "heading", level: heading.level, lines: [parseInline(heading.text)] });
      i += 1;
      continue;
    }

    const quote = matchQuote(line);
    if (quote !== null) {
      listStack = [];
      const parts: string[] = [quote];
      i += 1;
      while (i < lines.length) {
        const next = matchQuote(lines[i] as string);
        if (next === null || isBlank(next)) break;
        parts.push(next);
        i += 1;
      }
      blocks.push({ kind: "quote", lines: [parseInline(parts.join(" "))] });
      continue;
    }

    const item = matchListItem(line);
    if (item) {
      while (listStack.length > 0 && item.sourceIndent < (listStack[listStack.length - 1] as number)) {
        listStack.pop();
      }
      if (listStack.length === 0 || item.sourceIndent > (listStack[listStack.length - 1] as number)) {
        listStack.push(item.sourceIndent);
      }
      const level = Math.min(listStack.length - 1, MAX_LIST_DEPTH);

      const parts: string[] = [item.body];
      i += 1;
      // Lazy continuation: an unindented follow-on line still belongs to the
      // item, because models wrap list bodies without re-indenting them.
      while (i < lines.length && !startsBlock(lines[i] as string)) {
        parts.push((lines[i] as string).trim());
        i += 1;
      }
      blocks.push({
        kind: "listItem",
        marker: item.marker,
        indent: level * LIST_INDENT_WIDTH,
        lines: [parseInline(parts.join(" ").trim())],
      });
      continue;
    }

    listStack = [];
    const parts: string[] = [line.trim()];
    i += 1;
    while (i < lines.length && !startsBlock(lines[i] as string)) {
      parts.push((lines[i] as string).trim());
      i += 1;
    }
    blocks.push({ kind: "paragraph", lines: [parseInline(parts.join(" "))] });
  }

  return blocks;
}

function wrapBlock(block: MdBlock, width: number): MdBlock {
  switch (block.kind) {
    case "rule":
      return block;
    case "code": {
      const lines = block.lines.map((line) => truncateCodeLine(line, width));
      return block.language
        ? { kind: "code", language: block.language, lines }
        : { kind: "code", lines };
    }
    case "heading":
      return { kind: "heading", level: block.level, lines: wrapSpans(joinLines(block.lines), width) };
    case "quote":
      return {
        kind: "quote",
        lines: wrapSpans(joinLines(block.lines), Math.max(1, width - QUOTE_GUTTER_WIDTH)),
      };
    case "listItem":
      return {
        kind: "listItem",
        marker: block.marker,
        indent: block.indent,
        lines: wrapSpans(joinLines(block.lines), Math.max(1, width - listItemGutterWidth(block))),
      };
    case "paragraph":
      return { kind: "paragraph", lines: wrapSpans(joinLines(block.lines), width) };
  }
}

/**
 * Parse markdown into blocks, then wrap every block to `width` cells.
 *
 * `width` is the full content column. Blocks that need a gutter (list markers,
 * the quote bar) subtract it themselves, so the renderer can paint
 * `gutter + line` and stay inside the column. `width <= 0` yields no blocks.
 */
export function renderMarkdown(source: string, width: number): MdBlock[] {
  const w = normalizeWidth(width);
  if (w <= 0) return [];
  return parseMarkdownBlocks(source).map((block) => wrapBlock(block, w));
}
