/** @jsxImportSource @opentui/react */
import React from "react";
import type { Theme } from "../theme-context.js";
import type { KeyHint } from "./types.js";

/** Plain rendered length of a key-hint row, for a fits-the-column guard. */
export function keyHintsLength(pairs: readonly KeyHint[], sep: string): number {
  let n = 0;
  pairs.forEach((p, i) => {
    if (i > 0) n += sep.length;
    n += p.key.length + 1 + p.label.length;
  });
  return n;
}

/**
 * A keybind hint row: the KEY glyphs render in TEXT (white) and the labels in
 * MUTED, so `shift+tab mode · ctrl+p palette` reads as chords, not prose. Each
 * segment is flexShrink={0}, so the caller must only render this where it fits
 * (see keyHintsLength); a squeezed row of siblings overpaints in this TUI.
 */
export function KeyHints({
  pairs,
  theme,
  sep = " · ",
}: {
  pairs: readonly KeyHint[];
  theme: Theme;
  sep?: string;
}) {
  const { TEXT, MUTED } = theme;
  const nodes: React.ReactNode[] = [];
  pairs.forEach((p, i) => {
    if (i > 0) nodes.push(<text key={`sep-${i}`} flexShrink={0} fg={MUTED}>{sep}</text>);
    nodes.push(<text key={`key-${i}`} flexShrink={0} fg={TEXT}>{p.key}</text>);
    nodes.push(<text key={`lbl-${i}`} flexShrink={0} fg={MUTED}>{` ${p.label}`}</text>);
  });
  return <box flexDirection="row" minWidth={0} flexShrink={0}>{nodes}</box>;
}
