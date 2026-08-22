import { describe, expect, it } from "vitest";

import {
  LIST_INDENT_WIDTH,
  QUOTE_GUTTER_WIDTH,
  listItemGutterWidth,
  parseInline,
  parseMarkdownBlocks,
  renderMarkdown,
  spansToText,
  wrapSpans,
  type MdBlock,
  type MdSpan,
} from "./markdown.js";

const ESC = "\u001b";

function styled(spans: readonly MdSpan[]): Array<[string, string]> {
  return spans.map((span) => [span.text, span.style]);
}

function allSpans(blocks: readonly MdBlock[]): MdSpan[] {
  const out: MdSpan[] = [];
  for (const block of blocks) {
    if (block.kind === "rule" || block.kind === "code" || block.kind === "table") continue;
    for (const line of block.lines) out.push(...line);
  }
  return out;
}

function lineTexts(lines: readonly MdSpan[][]): string[] {
  return lines.map((line) => spansToText(line));
}

describe("parseInline", () => {
  it("styles bold and drops the markers", () => {
    expect(styled(parseInline("a **bee** c"))).toEqual([
      ["a ", "text"],
      ["bee", "bold"],
      [" c", "text"],
    ]);
  });

  it("styles italic with either marker", () => {
    expect(styled(parseInline("*one*"))).toEqual([["one", "italic"]]);
    expect(styled(parseInline("_two_"))).toEqual([["two", "italic"]]);
  });

  it("styles inline code", () => {
    expect(styled(parseInline("run `0sec scan` now"))).toEqual([
      ["run ", "text"],
      ["0sec scan", "code"],
      [" now", "text"],
    ]);
  });

  it("keeps markdown inside a code span literal", () => {
    expect(styled(parseInline("`**not bold**`"))).toEqual([["**not bold**", "code"]]);
  });

  it("styles strikethrough", () => {
    expect(styled(parseInline("~~gone~~"))).toEqual([["gone", "strike"]]);
  });

  it("renders a link label plus a muted destination", () => {
    expect(styled(parseInline("see [docs](https://0sec.dev)"))).toEqual([
      ["see ", "text"],
      ["docs", "link"],
      [" (https://0sec.dev)", "muted"],
    ]);
  });

  it("does not repeat the destination when it equals the label", () => {
    expect(styled(parseInline("[https://0sec.dev](https://0sec.dev)"))).toEqual([
      ["https://0sec.dev", "link"],
    ]);
  });

  it("keeps the innermost style when markup nests", () => {
    expect(styled(parseInline("**bold with `code` inside**"))).toEqual([
      ["bold with ", "bold"],
      ["code", "code"],
      [" inside", "bold"],
    ]);
  });

  it("collapses bold-italic to bold", () => {
    expect(styled(parseInline("***loud***"))).toEqual([["loud", "bold"]]);
  });

  it("leaves unmatched markers as literal text", () => {
    expect(styled(parseInline("a lone * star"))).toEqual([["a lone * star", "text"]]);
    expect(styled(parseInline("**unclosed bold"))).toEqual([["**unclosed bold", "text"]]);
    expect(styled(parseInline("an `unclosed code"))).toEqual([["an `unclosed code", "text"]]);
    expect(styled(parseInline("5 * 3 * 2"))).toEqual([["5 * 3 * 2", "text"]]);
  });

  it("leaves an unterminated link literal", () => {
    expect(styled(parseInline("[label](broken"))).toEqual([["[label](broken", "text"]]);
    expect(styled(parseInline("[just brackets]"))).toEqual([["[just brackets]", "text"]]);
  });

  it("does not treat intraword underscores as emphasis", () => {
    expect(styled(parseInline("snake_case_name"))).toEqual([["snake_case_name", "text"]]);
  });

  it("honours backslash escapes and drops the backslash", () => {
    expect(styled(parseInline("literal \\*stars\\*"))).toEqual([["literal *stars*", "text"]]);
  });

  it("never leaves a marker in a span's text", () => {
    const spans = parseInline("**a** *b* `c` ~~d~~ [e](f)");
    for (const span of spans) {
      if (span.style === "code") continue;
      expect(span.text).not.toContain("**");
      expect(span.text).not.toContain("~~");
    }
  });
});

describe("the real-world console reply", () => {
  const REPLY =
    "I can do that, but I don't have a scoped code directory/target loaded yet. " +
    "Please provide one of the following: 1. **A repository / local code scope** to scan, " +
    "or 2. **A target URL/API host** if you want live testing";

  it("renders the repository scope as a bold span with no markers anywhere", () => {
    const blocks = renderMarkdown(REPLY, 80);
    const spans = allSpans(blocks);

    const bold = spans.filter((span) => span.style === "bold");
    expect(bold.map((span) => span.text)).toEqual([
      "A repository / local code scope",
      "A target URL/API host",
    ]);

    for (const span of spans) expect(span.text).not.toContain("*");
    // Wrapping must not have lost a word of the prose. Rows are rejoined with
    // a space because that is the break the wrapper consumed.
    const paragraph = blocks[0] as Extract<MdBlock, { kind: "paragraph" }>;
    expect(lineTexts(paragraph.lines).join(" ")).toBe(REPLY.replace(/\*\*/g, ""));
    for (const line of paragraph.lines) expect(spansToText(line).length).toBeLessThanOrEqual(80);
  });
});

describe("blocks", () => {
  it("parses ATX headings at every level", () => {
    for (let level = 1; level <= 6; level += 1) {
      const [block] = parseMarkdownBlocks(`${"#".repeat(level)} Title`);
      expect(block).toEqual({ kind: "heading", level, lines: [[{ text: "Title", style: "text" }]] });
    }
  });

  it("does not treat a hashtag as a heading", () => {
    expect(parseMarkdownBlocks("#hashtag")[0]?.kind).toBe("paragraph");
    expect(parseMarkdownBlocks("####### seven")[0]?.kind).toBe("paragraph");
  });

  it("strips a closing hash sequence", () => {
    const [block] = parseMarkdownBlocks("## Findings ##");
    expect(block).toMatchObject({ kind: "heading", level: 2 });
    expect(spansToText((block as { lines: MdSpan[][] }).lines[0]!)).toBe("Findings");
  });

  it("parses fenced code with a language and keeps the body literal", () => {
    const blocks = parseMarkdownBlocks("```ts\nconst a = **1**;\n# not a heading\n```");
    expect(blocks).toEqual([
      { kind: "code", language: "ts", lines: ["const a = **1**;", "# not a heading"] },
    ]);
  });

  it("parses tilde fences and omits an absent language", () => {
    expect(parseMarkdownBlocks("~~~\nplain\n~~~")).toEqual([{ kind: "code", lines: ["plain"] }]);
  });

  it("closes an unterminated fence at end of input", () => {
    expect(parseMarkdownBlocks("```\nstill code")).toEqual([{ kind: "code", lines: ["still code"] }]);
  });

  it("does not let a shorter fence close a longer one", () => {
    const blocks = parseMarkdownBlocks("````\n```\ninner\n````");
    expect(blocks).toEqual([{ kind: "code", lines: ["```", "inner"] }]);
  });

  it("parses blockquotes and joins their lines", () => {
    const [block] = parseMarkdownBlocks("> first\n> **second**");
    expect(block?.kind).toBe("quote");
    expect(styled((block as { lines: MdSpan[][] }).lines[0]!)).toEqual([
      ["first ", "text"],
      ["second", "bold"],
    ]);
  });

  it("parses horizontal rules but not list items that look like them", () => {
    expect(parseMarkdownBlocks("---")).toEqual([{ kind: "rule" }]);
    expect(parseMarkdownBlocks("***")).toEqual([{ kind: "rule" }]);
    expect(parseMarkdownBlocks("___")).toEqual([{ kind: "rule" }]);
    expect(parseMarkdownBlocks("- - -")).toEqual([{ kind: "rule" }]);
    expect(parseMarkdownBlocks("-- ")[0]?.kind).toBe("paragraph");
  });

  it("joins soft-wrapped paragraph lines and splits on a blank line", () => {
    const blocks = parseMarkdownBlocks("one\ntwo\n\nthree");
    expect(blocks).toHaveLength(2);
    expect(spansToText((blocks[0] as { lines: MdSpan[][] }).lines[0]!)).toBe("one two");
    expect(spansToText((blocks[1] as { lines: MdSpan[][] }).lines[0]!)).toBe("three");
  });

  it("ignores blank input", () => {
    expect(parseMarkdownBlocks("")).toEqual([]);
    expect(parseMarkdownBlocks("\n\n   \n")).toEqual([]);
  });
});

describe("lists", () => {
  it("retains unordered markers", () => {
    const blocks = parseMarkdownBlocks("- alpha\n* beta\n+ gamma");
    expect(blocks.map((b) => (b as { marker: string }).marker)).toEqual(["-", "*", "+"]);
    expect(blocks.every((b) => b.kind === "listItem")).toBe(true);
  });

  it("retains ordered markers including the delimiter", () => {
    const blocks = parseMarkdownBlocks("1. one\n2) two\n10. ten");
    expect(blocks.map((b) => (b as { marker: string }).marker)).toEqual(["1.", "2)", "10."]);
    expect(
      blocks.map((b) => spansToText((b as { lines: MdSpan[][] }).lines[0]!)),
    ).toEqual(["one", "two", "ten"]);
  });

  it("derives nesting from indentation and normalises the indent", () => {
    const blocks = parseMarkdownBlocks("- top\n    - nested\n        - deeper\n- back");
    expect(blocks.map((b) => (b as { indent: number }).indent)).toEqual([
      0,
      LIST_INDENT_WIDTH,
      LIST_INDENT_WIDTH * 2,
      0,
    ]);
  });

  it("treats a three-space nested item the same as a four-space one", () => {
    const three = parseMarkdownBlocks("- top\n   - nested");
    const four = parseMarkdownBlocks("- top\n    - nested");
    expect(three.map((b) => (b as { indent: number }).indent)).toEqual(
      four.map((b) => (b as { indent: number }).indent),
    );
  });

  it("parses inline markup inside a list body", () => {
    const [block] = parseMarkdownBlocks("- run `0sec` on **the repo**");
    expect(styled((block as { lines: MdSpan[][] }).lines[0]!)).toEqual([
      ["run ", "text"],
      ["0sec", "code"],
      [" on ", "text"],
      ["the repo", "bold"],
    ]);
  });

  it("absorbs a lazy continuation line into the item", () => {
    const blocks = parseMarkdownBlocks("- first line\ncontinued here\n- second");
    expect(blocks).toHaveLength(2);
    expect(spansToText((blocks[0] as { lines: MdSpan[][] }).lines[0]!)).toBe(
      "first line continued here",
    );
  });

  it("reserves marker cells when wrapping the body", () => {
    const [block] = renderMarkdown("1. alpha beta gamma delta", 12);
    expect(block?.kind).toBe("listItem");
    const item = block as Extract<MdBlock, { kind: "listItem" }>;
    expect(listItemGutterWidth(item)).toBe(3);
    for (const line of item.lines) {
      expect(spansToText(line).length).toBeLessThanOrEqual(12 - 3);
    }
    expect(lineTexts(item.lines).join(" ")).toBe("alpha beta gamma delta");
  });
});

describe("wrapping", () => {
  it("breaks on word boundaries", () => {
    const lines = wrapSpans(parseInline("the quick brown fox jumps"), 10);
    expect(lineTexts(lines)).toEqual(["the quick", "brown fox", "jumps"]);
  });

  it("never emits a row wider than the width", () => {
    const source = "the quick brown fox jumps over the lazy dog again and again";
    for (const width of [1, 2, 3, 7, 13, 40]) {
      for (const line of wrapSpans(parseInline(source), width)) {
        expect(spansToText(line).length).toBeLessThanOrEqual(width);
      }
    }
  });

  it("keeps a bold run bold on both sides of a break", () => {
    const lines = wrapSpans(parseInline("**alpha beta**"), 6);
    expect(lineTexts(lines)).toEqual(["alpha", "beta"]);
    for (const line of lines) {
      expect(line).toHaveLength(1);
      expect(line[0]!.style).toBe("bold");
    }
  });

  it("keeps a split code span styled as code on every row", () => {
    const lines = wrapSpans(parseInline("`aaaa bbbb cccc`"), 5);
    expect(lines.every((line) => line.every((span) => span.style === "code"))).toBe(true);
    expect(lineTexts(lines)).toEqual(["aaaa", "bbbb", "cccc"]);
  });

  it("merges adjacent same-styled fragments into one span per row", () => {
    const lines = wrapSpans(parseInline("**a b** c"), 40);
    expect(styled(lines[0]!)).toEqual([
      ["a b", "bold"],
      [" c", "text"],
    ]);
  });

  it("hard-breaks a word longer than the width", () => {
    const lines = wrapSpans(parseInline("supercalifragilistic"), 6);
    expect(lineTexts(lines)).toEqual(["superc", "alifra", "gilist", "ic"]);
  });

  it("hard-breaks a styled over-long word without losing the style", () => {
    const lines = wrapSpans(parseInline("**supercalifragilistic**"), 6);
    expect(lineTexts(lines).join("")).toBe("supercalifragilistic");
    expect(lines.every((line) => line.every((span) => span.style === "bold"))).toBe(true);
  });

  it("does not split a surrogate pair when hard-breaking", () => {
    const lines = wrapSpans([{ text: "🔥🔥🔥🔥", style: "text" }], 2);
    expect(lineTexts(lines)).toEqual(["🔥🔥", "🔥🔥"]);
    const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
    for (const line of lines) expect(LONE_SURROGATE.test(line[0]!.text)).toBe(false);
  });

  it("returns no rows at width 0 and never throws on a bad width", () => {
    expect(wrapSpans(parseInline("hello"), 0)).toEqual([]);
    expect(wrapSpans(parseInline("hello"), -5)).toEqual([]);
    expect(wrapSpans(parseInline("hello"), Number.NaN)).toEqual([]);
    expect(renderMarkdown("# hello\n\n- a\n\n> b\n\n```\nc\n```", 0)).toEqual([]);
    expect(renderMarkdown("# hello", -1)).toEqual([]);
    expect(renderMarkdown("# hello", Number.NaN)).toEqual([]);
  });

  it("wraps to a single column at width 1", () => {
    expect(lineTexts(wrapSpans(parseInline("ab cd"), 1))).toEqual(["a", "b", "c", "d"]);
  });

  it("wraps to two columns at width 2", () => {
    expect(lineTexts(wrapSpans(parseInline("ab cd"), 2))).toEqual(["ab", "cd"]);
  });

  it("drops the source's leading and repeated whitespace", () => {
    expect(lineTexts(wrapSpans([{ text: "  a    b  ", style: "text" }], 20))).toEqual(["a b"]);
  });

  it("subtracts the quote gutter from the quote body width", () => {
    const [block] = renderMarkdown("> alpha beta gamma delta epsilon", 12);
    expect(block?.kind).toBe("quote");
    for (const line of (block as { lines: MdSpan[][] }).lines) {
      expect(spansToText(line).length).toBeLessThanOrEqual(12 - QUOTE_GUTTER_WIDTH);
    }
  });
});

describe("code blocks", () => {
  it("truncates rather than reflowing, and marks the truncation", () => {
    const [block] = renderMarkdown("```\nconst message = 'a very long line indeed';\n```", 20);
    expect(block?.kind).toBe("code");
    const lines = (block as { lines: string[] }).lines;
    expect(lines).toHaveLength(1);
    // Exactly the leading 19 cells of the source line plus a one-cell mark:
    // the prefix is verbatim, never re-flowed.
    expect(lines[0]).toBe("const message = 'a …");
    expect(lines[0]!.length).toBe(20);
  });

  it("leaves a short code line untouched", () => {
    const [block] = renderMarkdown("```sh\n0sec scan\n```", 40);
    expect(block).toEqual({ kind: "code", language: "sh", lines: ["0sec scan"] });
  });

  it("preserves interior indentation", () => {
    const [block] = renderMarkdown("```py\ndef f():\n    return 1\n```", 40);
    expect((block as { lines: string[] }).lines).toEqual(["def f():", "    return 1"]);
  });

  it("expands tabs instead of emitting a cursor-moving tab", () => {
    const [block] = renderMarkdown("```\n\tindented\n```", 40);
    expect((block as { lines: string[] }).lines).toEqual(["    indented"]);
  });
});

describe("terminal safety", () => {
  const HOSTILE = [
    `${ESC}[31mred${ESC}[0m`,
    `${ESC}[2J${ESC}[H wiped`,
    `${ESC}]0;window title${String.fromCharCode(7)}`,
    `bell${String.fromCharCode(7)}and${String.fromCharCode(0)}nul`,
    `carriage\rreturn`,
  ].join("\n");

  it("strips every escape and control character from span text", () => {
    const blocks = renderMarkdown(HOSTILE, 60);
    for (const span of allSpans(blocks)) {
      expect(span.text).not.toContain(ESC);
      expect(span.text).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f]/);
    }
  });

  it("strips escapes inside fenced code, where nothing else is transformed", () => {
    const [block] = renderMarkdown("```\n" + `${ESC}[2Jwiped` + "\n```", 60);
    const lines = (block as { lines: string[] }).lines;
    expect(lines[0]).not.toContain(ESC);
    // The whole CSI sequence goes, not just its ESC byte.
    expect(lines[0]).toBe("wiped");
  });

  it("strips escapes from headings, list markers' bodies, quotes and links", () => {
    const source = [
      `# head${ESC}[31m`,
      "",
      `- item${ESC}[1m`,
      "",
      `> quoted${ESC}[7m`,
      "",
      `[lab${ESC}[4mel](http://x${ESC}[0m/y)`,
    ].join("\n");
    const blocks = renderMarkdown(source, 60);
    const text = allSpans(blocks)
      .map((span) => span.text)
      .join("");
    expect(text).not.toContain(ESC);
  });

  it("cannot smuggle an escape through a whitespace split", () => {
    // The CSI intermediate byte range includes SPACE, so a sequence can
    // legitimately contain one. Splitting on whitespace must still not let it
    // through: sanitizeTuiText removes the ESC byte itself unconditionally.
    const blocks = renderMarkdown(`before ${ESC}[0 m after`, 60);
    const text = allSpans(blocks)
      .map((span) => span.text)
      .join("");
    expect(text).not.toContain(ESC);
    expect(text).toContain("before");
    expect(text).toContain("after");
  });

  it("keeps benign unicode intact", () => {
    const blocks = renderMarkdown("café — naïve … 中文", 60);
    expect(spansToText(allSpans(blocks))).toBe("café — naïve … 中文");
  });
});

describe("performance guards", () => {
  function timed(fn: () => void): number {
    const start = Date.now();
    fn();
    return Date.now() - start;
  }

  it("handles 5000 unmatched asterisks quickly", () => {
    const source = "*".repeat(5000);
    let blocks: MdBlock[] = [];
    const ms = timed(() => {
      blocks = renderMarkdown(source, 80);
    });
    expect(blocks.length).toBeGreaterThan(0);
    expect(ms).toBeLessThan(1000);
  });

  it("handles pathological runs of every inline marker quickly", () => {
    const cases = [
      "*".repeat(5000),
      "_".repeat(5000),
      "~".repeat(5000),
      "`".repeat(5000),
      "[".repeat(5000),
      "](".repeat(2500),
      "*a ".repeat(1600),
      "[a](".repeat(1200),
      "**".repeat(2500),
      `${"*".repeat(2500)}x`,
    ];
    const ms = timed(() => {
      for (const source of cases) renderMarkdown(source, 80);
    });
    expect(ms).toBeLessThan(2000);
  });

  it("handles a long realistic document quickly", () => {
    const source = Array.from({ length: 400 }, (_, i) =>
      `## Section ${i}\n\nSome **bold** and \`code\` and a [link](https://example.com/${i}).\n\n- item one\n  - nested\n\n\`\`\`ts\nconst x = ${i};\n\`\`\`\n`,
    ).join("\n");
    let blocks: MdBlock[] = [];
    const ms = timed(() => {
      blocks = renderMarkdown(source, 80);
    });
    expect(blocks.length).toBeGreaterThan(400);
    expect(ms).toBeLessThan(2000);
  });
});

describe("renderMarkdown end to end", () => {
  it("renders a mixed document into wrapped blocks", () => {
    const source = [
      "# Report",
      "",
      "Found **two** issues in `auth.ts`.",
      "",
      "1. Missing check",
      "2. Weak hash",
      "",
      "---",
      "",
      "> Fix before release.",
      "",
      "```ts",
      "if (!user) return;",
      "```",
    ].join("\n");

    const blocks = renderMarkdown(source, 40);
    expect(blocks.map((block) => block.kind)).toEqual([
      "heading",
      "paragraph",
      "listItem",
      "listItem",
      "rule",
      "quote",
      "code",
    ]);
    expect(blocks[0]).toEqual({
      kind: "heading",
      level: 1,
      lines: [[{ text: "Report", style: "text" }]],
    });
    expect(blocks[6]).toEqual({ kind: "code", language: "ts", lines: ["if (!user) return;"] });
  });
});

describe("tables", () => {
  const TABLE = ["| Color | Meaning |", "|---|---|", "| Red | Error |", "| Green | Success |"].join("\n");

  it("parses a GFM pipe table into a table block", () => {
    const [block] = renderMarkdown(TABLE, 80);
    expect(block?.kind).toBe("table");
    if (block?.kind !== "table") throw new Error("expected a table");
    expect(block.header.map(spansToText)).toEqual(["Color", "Meaning"]);
    expect(block.rows.map((row) => row.map(spansToText))).toEqual([
      ["Red", "Error"],
      ["Green", "Success"],
    ]);
  });

  it("reads per-column alignment from the delimiter colons", () => {
    const src = ["| a | b | c |", "|:--|:-:|--:|", "| 1 | 2 | 3 |"].join("\n");
    const [block] = renderMarkdown(src, 80);
    if (block?.kind !== "table") throw new Error("expected a table");
    expect(block.align).toEqual(["left", "center", "right"]);
  });

  it("parses inline markup inside cells and measures the DISPLAY width", () => {
    const src = ["| Sev | Note |", "|---|---|", "| **High** | `x` |"].join("\n");
    const [block] = renderMarkdown(src, 80);
    if (block?.kind !== "table") throw new Error("expected a table");
    // The bold marker is stripped: the cell is a bold span reading "High".
    expect(block.rows[0]![0]).toEqual([{ text: "High", style: "bold" }]);
    expect(block.rows[0]![1]).toEqual([{ text: "x", style: "code" }]);
    // Column 0 is 4 cells wide ("High"), not 8 ("**High**").
    expect(block.widths[0]).toBe(4);
  });

  it("normalises rows to the header's column count", () => {
    const src = ["| a | b | c |", "|---|---|---|", "| 1 | 2 |", "| 1 | 2 | 3 | 4 |"].join("\n");
    const [block] = renderMarkdown(src, 80);
    if (block?.kind !== "table") throw new Error("expected a table");
    expect(block.rows[0]!.length).toBe(3);
    expect(block.rows[1]!.length).toBe(3);
    expect(spansToText(block.rows[0]![2]!)).toBe("");
  });

  it("keeps the whole row within the content width when a cell overflows", () => {
    const src = ["| k | v |", "|---|---|", "| id | " + "x".repeat(100) + " |"].join("\n");
    const [block] = renderMarkdown(src, 20);
    if (block?.kind !== "table") throw new Error("expected a table");
    const gap = 3; // " │ " between the two columns
    expect(block.widths[0]! + block.widths[1]! + gap).toBeLessThanOrEqual(20);
    // The overflowing cell was truncated with an ellipsis.
    expect(spansToText(block.rows[0]![1]!).endsWith("…")).toBe(true);
  });

  it("does not treat a lone pipe line as a table", () => {
    const [block] = renderMarkdown("a | b without a delimiter row", 80);
    expect(block?.kind).toBe("paragraph");
  });
});
