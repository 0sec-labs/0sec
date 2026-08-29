/** @jsxImportSource @opentui/react */
import React from "react";
import { TextAttributes } from "@opentui/core";
import {
  listItemGutterWidth,
  type MdBlock,
  type MdSpan,
} from "../markdown.js";
import type { Theme } from "../theme-context.js";
import { codeTokenStyle, highlightCode, type CodeTokenStyle } from "../syntax-style.js";

/** Combine a token's weight flags into a single TextAttributes bitmask. */
function codeTokenAttributes(style: CodeTokenStyle): number | undefined {
  let attributes = 0;
  if (style.bold) attributes |= TextAttributes.BOLD;
  if (style.italic) attributes |= TextAttributes.ITALIC;
  if (style.dim) attributes |= TextAttributes.DIM;
  return attributes === 0 ? undefined : attributes;
}

/** Display width of a string in cells (code points), matching markdown.ts. */
function codeLineWidth(line: string): number {
  let n = 0;
  for (const _ of line) n += 1;
  return n;
}

/**
 * Terminal text ATTRIBUTES for a markdown span — the real weight, not just a
 * colour. A bold run gets TextAttributes.BOLD so it renders visibly heavier;
 * italic gets ITALIC, strike gets STRIKETHROUGH, a link is UNDERLINEd so it
 * reads as a link even in themes where ACCENT sits close to body text, and a
 * muted run is dimmed. Applied by every inline renderer (paragraphs, list
 * items, table cells) so `**bold**` looks bold wherever it appears.
 */
export function spanAttributes(style: MdSpan["style"]): number | undefined {
  switch (style) {
    case "bold":
      return TextAttributes.BOLD;
    case "italic":
      return TextAttributes.ITALIC;
    case "strike":
      return TextAttributes.STRIKETHROUGH;
    case "link":
      return TextAttributes.UNDERLINE;
    case "muted":
      return TextAttributes.DIM;
    default:
      return undefined;
  }
}

/** Map a markdown span style onto the theme. */
export function spanColor(style: MdSpan["style"], theme: Theme, tone?: string): string {
  const { ACCENT, MUTED, TEXT } = theme;
  // A tone override keeps a whole block in one voice (e.g. reasoning stays
  // muted) while still honouring structure like code and links.
  if (tone && style !== "code" && style !== "link") return tone;
  // Inline code and links both carry the accent hue — code as coloured text on
  // a subtle chip (see spanBackground), a link as underlined accent text.
  if (style === "code" || style === "link") return ACCENT;
  if (style === "muted" || style === "strike") return MUTED;
  return TEXT;
}

/**
 * Optional background for a span. Only inline `code` gets one: a subtle tinted
 * chip (the same offset surface a fenced block uses) so `` `code` `` reads as a
 * distinct token mid-sentence rather than as differently-coloured prose. A tone
 * override (e.g. a wholly muted reasoning block) drops the chip so the run stays
 * one flat voice.
 */
export function spanBackground(style: MdSpan["style"], theme: Theme, tone?: string): string | undefined {
  if (tone) return undefined;
  return style === "code" ? theme.surfaceAlt : undefined;
}

/**
 * Colour a heading by its level so the outline reads at a glance: H1 is the
 * loudest (PRIMARY), H2 carries the brand hue, H3 the accent, and H4+ step down
 * to a muted-but-bold label. A tone override (a block pinned to one voice) wins
 * over the level colour. Every level is rendered BOLD by the caller.
 */
export function headingColor(level: number, theme: Theme, tone?: string): string {
  if (tone) return tone;
  if (level <= 1) return theme.PRIMARY;
  if (level === 2) return theme.BRAND;
  if (level === 3) return theme.ACCENT;
  return theme.MUTED;
}

/**
 * Render parsed markdown blocks.
 *
 * Models emit markdown constantly, and showing `**bold**` literally is the
 * single most visible way a terminal agent looks unfinished. Every line is
 * pre-wrapped to an exact width by `renderMarkdown`, so nothing here needs
 * to guess at widths — which is also what keeps a long span from
 * overflowing its row.
 */
export function renderMarkdownBlocks(blocks: readonly MdBlock[], key: string, theme: Theme, tone?: string) {
  const { ACCENT, BORDER, MUTED, PRIMARY } = theme;
  return blocks.map((block, index) => {
    const id = `${key}-b${index}`;
    if (block.kind === "rule") {
      return <text key={id} fg={tone ?? MUTED}>{"─".repeat(8)}</text>;
    }
    if (block.kind === "table") {
      // Rendered as a real BORDERED GRID: an outer box-drawing frame, a heavier
      // rule under the emphasised header, and a `│` between every column. Each
      // column is a fixed-width box padded per its parsed alignment, so the bars
      // line up regardless of cell content. Every border segment spans the
      // column's width PLUS the one pad cell on each side of it, so the `┬`/`┼`/
      // `┴` junctions sit exactly over the `│` bars. Widths were chosen by
      // `renderMarkdown` with TABLE_FRAME_WIDTH reserved for this frame, so the
      // whole grid — bars and all — stays inside the content column.
      const { widths } = block;
      // A horizontal rule: `<lc>` + one segment per column joined by `<mc>` +
      // `<rc>`. A segment covers the cell width and its two pad cells.
      const rule = (lc: string, mc: string, rc: string): string =>
        lc + widths.map((w) => "─".repeat(Math.max(1, w) + 2)).join(mc) + rc;
      const renderRow = (cells: readonly MdSpan[][], rowKey: string, header: boolean) => (
        <box key={rowKey} flexDirection="row" flexShrink={0} minWidth={0}>
          <text flexShrink={0} fg={BORDER}>{"│ "}</text>
          {cells.map((cell, c) => {
            const w = widths[c] ?? 1;
            const disp = cell.reduce((n, s) => n + Array.from(s.text).length, 0);
            const pad = Math.max(0, w - disp);
            const align = block.align[c] ?? "left";
            const lead = align === "right" ? pad : align === "center" ? Math.floor(pad / 2) : 0;
            const trail = pad - lead;
            return (
              <React.Fragment key={`${rowKey}-c${c}`}>
                {c > 0 ? <text flexShrink={0} fg={BORDER}>{" │ "}</text> : null}
                <box width={w} flexShrink={0} minWidth={0} flexDirection="row">
                  {lead > 0 ? <text flexShrink={0} fg={MUTED}>{" ".repeat(lead)}</text> : null}
                  {cell.map((span, j) => (
                    <text key={`${rowKey}-c${c}-s${j}`} flexShrink={0} fg={spanColor(span.style, theme, header ? (tone ?? PRIMARY) : tone)} bg={spanBackground(span.style, theme, tone)} attributes={spanAttributes(span.style) ?? (header ? TextAttributes.BOLD : undefined)}>{span.text}</text>
                  ))}
                  {trail > 0 ? <text flexShrink={0} fg={MUTED}>{" ".repeat(trail)}</text> : null}
                </box>
              </React.Fragment>
            );
          })}
          <text flexShrink={0} fg={BORDER}>{" │"}</text>
        </box>
      );
      return (
        <box key={id} flexDirection="column" flexShrink={0} minWidth={0}>
          <text flexShrink={0} fg={BORDER}>{rule("┌", "┬", "┐")}</text>
          {renderRow(block.header, `${id}-h`, true)}
          <text flexShrink={0} fg={BORDER}>{rule("├", "┼", "┤")}</text>
          {block.rows.map((row, i) => renderRow(row, `${id}-r${i}`, false))}
          <text flexShrink={0} fg={BORDER}>{rule("└", "┴", "┘")}</text>
        </box>
      );
    }
    if (block.kind === "code") {
      // A fenced block renders as a DISTINCT surface — a subtle tinted
      // background with a one-cell gutter on each side (reserved by
      // CODE_BLOCK_PAD when the lines were truncated, so it never overflows the
      // content column) — not as indented prose. Each line is tokenised and
      // painted per token, so keywords/strings/comments/numbers carry theme
      // colour and real weight. Every row is padded to the block's widest line
      // so the tinted surface reads as a clean rectangle regardless of how the
      // parent sizes the box, and whitespace/indentation is preserved verbatim
      // because a line's token texts concatenate back to the source line.
      //
      // The language is shown as a small CHIP — a bracketed `[bash]` in the
      // accent hue, right-aligned on the surface's first row — not a bare word
      // on its own line, so it reads as a label on the block rather than as
      // stray code.
      const { surfaceAlt } = theme;
      const lang = block.language;
      // Only label a REAL language. Unlabeled fences and generic "text"/"plain"
      // blocks (which a model emits constantly for paths, output, prose) don't
      // earn a "[text]" chip — it just adds noise over the block.
      const GENERIC_FENCE_LANGS = new Set(["text", "txt", "plain", "plaintext", "none", "output"]);
      const chip = lang && !GENERIC_FENCE_LANGS.has(lang.toLowerCase()) ? `[${lang}]` : "";
      const chipWidth = codeLineWidth(chip);
      const maxWidth = block.lines.reduce((w, line) => Math.max(w, codeLineWidth(line)), chipWidth);
      const chipLead = Math.max(0, maxWidth - chipWidth);
      return (
        <box key={id} flexDirection="column" flexShrink={0} minWidth={0} paddingX={1} backgroundColor={surfaceAlt}>
          {chip ? (
            <box flexDirection="row" flexShrink={0} minWidth={0}>
              {chipLead > 0 ? <text flexShrink={0} fg={MUTED}>{" ".repeat(chipLead)}</text> : null}
              <text flexShrink={0} fg={ACCENT} attributes={TextAttributes.BOLD}>{chip}</text>
            </box>
          ) : null}
          {block.lines.map((line, i) => {
            const tokens = highlightCode(line, lang);
            const pad = Math.max(0, maxWidth - codeLineWidth(line));
            return (
              <box key={`${id}-${i}`} flexDirection="row" flexShrink={0} minWidth={0}>
                {tokens.map((token, j) => {
                  const style = codeTokenStyle(token.kind, theme);
                  return (
                    <text key={`${id}-${i}-${j}`} flexShrink={0} fg={style.fg} attributes={codeTokenAttributes(style)}>{token.text}</text>
                  );
                })}
                {pad > 0 ? <text flexShrink={0} fg={theme.TEXT}>{" ".repeat(pad)}</text> : null}
              </box>
            );
          })}
        </box>
      );
    }
    if (block.kind === "heading") {
      // Coloured by level (see headingColor) and always bold, so the outline
      // stands out from body text. Wrapping/width were already handled upstream.
      const fg = headingColor(block.level, theme, tone);
      return (
        <box key={id} flexDirection="column" minWidth={0}>
          {block.lines.map((line, i) => (
            <text key={`${id}-${i}`} fg={fg} attributes={TextAttributes.BOLD}>{line.map((span) => span.text).join("")}</text>
          ))}
        </box>
      );
    }
    if (block.kind === "listItem") {
      // The marker is coloured (accent) and bold so it separates cleanly from
      // the body; unordered bullets render as `•` regardless of the source glyph
      // (`-`/`*`/`+`, all one cell, so the gutter arithmetic is unchanged).
      // Continuation rows sit in the body column, aligning under the text.
      const gutter = listItemGutterWidth(block);
      const ordered = /\d/.test(block.marker);
      const marker = ordered ? block.marker : "•";
      return (
        <box key={id} flexDirection="row" minWidth={0}>
          <box width={gutter} flexShrink={0} minWidth={0} flexDirection="row">
            {block.indent > 0 ? <text flexShrink={0} fg={MUTED}>{" ".repeat(block.indent)}</text> : null}
            <text flexShrink={0} fg={tone ?? ACCENT} attributes={TextAttributes.BOLD}>{marker}</text>
          </box>
          <box flexDirection="column" flexGrow={1} minWidth={0}>
            {block.lines.map((line, i) => (
              <box key={`${id}-${i}`} flexDirection="row" minWidth={0}>
                {line.map((span, j) => (
                  <text key={`${id}-${i}-${j}`} fg={spanColor(span.style, theme, tone)} bg={spanBackground(span.style, theme, tone)} attributes={spanAttributes(span.style)}>{span.text}</text>
                ))}
              </box>
            ))}
          </box>
        </box>
      );
    }
    // paragraph | quote — a quote is always muted, otherwise inherit the
    // caller's tone override (if any).
    const blockTone = block.kind === "quote" ? MUTED : tone;
    return (
      <box key={id} flexDirection="column" minWidth={0} marginLeft={block.kind === "quote" ? 2 : 0}>
        {block.lines.map((line, i) => (
          <box key={`${id}-${i}`} flexDirection="row" minWidth={0}>
            {line.map((span, j) => (
              <text key={`${id}-${i}-${j}`} fg={spanColor(span.style, theme, blockTone)} bg={spanBackground(span.style, theme, blockTone)} attributes={spanAttributes(span.style)}>{span.text}</text>
            ))}
          </box>
        ))}
      </box>
    );
  });
}
