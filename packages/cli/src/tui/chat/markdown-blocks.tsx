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
  const { MUTED, ACCENT, PRIMARY, TEXT } = theme;
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
      return (
        <box key={id} flexDirection="column" marginLeft={2}>
          {block.lines.map((line, i) => (
            <text key={`${id}-${i}`} fg={ACCENT}>{line}</text>
          ))}
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
