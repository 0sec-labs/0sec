/** @jsxImportSource @opentui/react */
import React from "react";
import { TextAttributes } from "@opentui/core";
import {
  listItemGutterWidth,
  TABLE_COLUMN_GAP,
  TABLE_JOIN_GLYPH,
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
 * italic gets ITALIC, strike gets STRIKETHROUGH, and a muted run is dimmed.
 * Applied by every inline renderer (paragraphs, list items, table cells) so
 * `**bold**` looks bold wherever it appears.
 */
export function spanAttributes(style: MdSpan["style"]): number | undefined {
  switch (style) {
    case "bold":
      return TextAttributes.BOLD;
    case "italic":
      return TextAttributes.ITALIC;
    case "strike":
      return TextAttributes.STRIKETHROUGH;
    case "muted":
      return TextAttributes.DIM;
    default:
      return undefined;
  }
}

/** Map a markdown span style onto the theme. */
export function spanColor(style: MdSpan["style"], theme: Theme, tone?: string): string {
  const { ACCENT, INFO, MUTED, TEXT } = theme;
  // A tone override keeps a whole block in one voice (e.g. reasoning stays
  // muted) while still honouring structure like code and links.
  if (tone && style !== "code" && style !== "link") return tone;
  if (style === "code") return ACCENT;
  if (style === "link") return INFO;
  if (style === "muted" || style === "strike") return MUTED;
  return TEXT;
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
  const { MUTED, PRIMARY, TEXT } = theme;
  return blocks.map((block, index) => {
    const id = `${key}-b${index}`;
    if (block.kind === "rule") {
      return <text key={id} fg={tone ?? MUTED}>{"─".repeat(8)}</text>;
    }
    if (block.kind === "table") {
      // Each cell is a styled inline-span run (bold/italic/code render just as
      // they do in a paragraph). Every column is a fixed-width box, so the
      // separators line up regardless of the cell content, and alignment inside
      // a column is done with leading/trailing padding spans. Widths were chosen
      // by `renderMarkdown` from the marker-stripped display text, so the whole
      // row fits the content column.
      const { widths } = block;
      const renderRow = (cells: readonly MdSpan[][], rowKey: string, header: boolean) => (
        <box key={rowKey} flexDirection="row" minWidth={0}>
          {cells.map((cell, c) => {
            const w = widths[c] ?? 1;
            const disp = cell.reduce((n, s) => n + Array.from(s.text).length, 0);
            const pad = Math.max(0, w - disp);
            const align = block.align[c] ?? "left";
            const lead = align === "right" ? pad : align === "center" ? Math.floor(pad / 2) : 0;
            const trail = pad - lead;
            return (
              <React.Fragment key={`${rowKey}-c${c}`}>
                {c > 0 ? <text flexShrink={0} fg={MUTED}>{TABLE_COLUMN_GAP}</text> : null}
                <box width={w} flexShrink={0} minWidth={0} flexDirection="row">
                  {lead > 0 ? <text flexShrink={0} fg={MUTED}>{" ".repeat(lead)}</text> : null}
                  {cell.map((span, j) => (
                    <text key={`${rowKey}-c${c}-s${j}`} flexShrink={0} fg={spanColor(span.style, theme, header ? (tone ?? PRIMARY) : tone)} attributes={spanAttributes(span.style) ?? (header ? TextAttributes.BOLD : undefined)}>{span.text}</text>
                  ))}
                  {trail > 0 ? <text flexShrink={0} fg={MUTED}>{" ".repeat(trail)}</text> : null}
                </box>
              </React.Fragment>
            );
          })}
        </box>
      );
      const separatorLine = widths.map((w) => "─".repeat(Math.max(1, w))).join(TABLE_JOIN_GLYPH);
      return (
        <box key={id} flexDirection="column" minWidth={0}>
          {renderRow(block.header, `${id}-h`, true)}
          <text fg={MUTED}>{separatorLine}</text>
          {block.rows.map((row, i) => renderRow(row, `${id}-r${i}`, false))}
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
      // The language is shown as a small dim CHIP — a bracketed `[bash]`
      // right-aligned on the surface's first row — not a bare word on its own
      // line, so it reads as a label on the block rather than as stray code.
      const { surfaceAlt } = theme;
      const lang = block.language;
      const chip = lang ? `[${lang}]` : "";
      const chipWidth = codeLineWidth(chip);
      const maxWidth = block.lines.reduce((w, line) => Math.max(w, codeLineWidth(line)), chipWidth);
      const chipLead = Math.max(0, maxWidth - chipWidth);
      return (
        <box key={id} flexDirection="column" flexShrink={0} minWidth={0} paddingX={1} backgroundColor={surfaceAlt}>
          {chip ? (
            <box flexDirection="row" flexShrink={0} minWidth={0}>
              {chipLead > 0 ? <text flexShrink={0} fg={MUTED} attributes={TextAttributes.DIM}>{" ".repeat(chipLead)}</text> : null}
              <text flexShrink={0} fg={MUTED} attributes={TextAttributes.DIM}>{chip}</text>
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
      return (
        <box key={id} flexDirection="column" minWidth={0}>
          {block.lines.map((line, i) => (
            <text key={`${id}-${i}`} fg={tone ?? PRIMARY} attributes={TextAttributes.BOLD}>{line.map((span) => span.text).join("")}</text>
          ))}
        </box>
      );
    }
    if (block.kind === "listItem") {
      const gutter = listItemGutterWidth(block);
      return (
        <box key={id} flexDirection="row" minWidth={0}>
          <box width={gutter} flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{`${" ".repeat(block.indent)}${block.marker}`}</text>
          </box>
          <box flexDirection="column" flexGrow={1} minWidth={0}>
            {block.lines.map((line, i) => (
              <box key={`${id}-${i}`} flexDirection="row" minWidth={0}>
                {line.map((span, j) => (
                  <text key={`${id}-${i}-${j}`} fg={spanColor(span.style, theme, tone)} attributes={spanAttributes(span.style)}>{span.text}</text>
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
              <text key={`${id}-${i}-${j}`} fg={spanColor(span.style, theme, blockTone)} attributes={spanAttributes(span.style)}>{span.text}</text>
            ))}
          </box>
        ))}
      </box>
    );
  });
}
