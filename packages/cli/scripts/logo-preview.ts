#!/usr/bin/env bun
/**
 * Standalone logo preview: renders the three slashed-zero "0SEC" options
 * with real 24-bit colour so you can pick one in your own terminal.
 *
 * This is NOT rendered inside the TUI framebuffer — it writes plain ANSI to
 * stdout on purpose, which is only safe because it runs on its own, not
 * under the differential renderer.
 *
 *   bun run packages/cli/scripts/logo-preview.ts
 */

const WHITE = "\x1b[38;2;235;235;235m";
const RED = "\x1b[38;2;220;38;38m";
const DIM = "\x1b[38;2;120;114;108m";
const RESET = "\x1b[0m";

// Glyph alphabet. '#' = white cell, '/' = red cell, ' ' = empty.
const SEC = [
  ["#####", " ##### ", "##### "].map(() => ""), // placeholder, replaced below
];

// S E C as 5-row block letters (single stroke, 5 cells wide each).
const LETTERS: Record<string, string[]> = {
  S: ["#####", "#    ", "#####", "    #", "#####"],
  E: ["#####", "#    ", "#### ", "#    ", "#####"],
  C: ["#####", "#    ", "#    ", "#    ", "#####"],
};

// The three zero options, 5 rows each. '/' cells render red.
const ZEROS: Record<string, string[]> = {
  "Bold slash · 8 wide": [
    " ###### ",
    "##  //##",
    "## // ##",
    "##//  ##",
    " ###### ",
  ],
  "Thin slash · 7 wide": [
    " ##### ",
    "##  /##",
    "## / ##",
    "##/  ##",
    " ##### ",
  ],
  "Long slash · 9 wide": [
    " ####### ",
    "##    /##",
    "##  /  ##",
    "##/    ##",
    " ####### ",
  ],
};

function paintCell(ch: string): string {
  if (ch === "#") return `${WHITE}█${RESET}`;
  if (ch === "/") return `${RED}█${RESET}`;
  return " ";
}

function renderWord(zero: string[]): string[] {
  const word = ["S", "E", "C"].map((c) => LETTERS[c]);
  const rows: string[] = [];
  for (let r = 0; r < 5; r++) {
    let line = "";
    for (const ch of zero[r]) line += paintCell(ch);
    line += "  "; // gap between 0 and SEC
    for (const glyph of word) {
      for (const ch of glyph[r]) line += paintCell(ch);
      line += " "; // gap between letters
    }
    rows.push(line);
  }
  return rows;
}

const out: string[] = ["", ""];
for (const [label, zero] of Object.entries(ZEROS)) {
  out.push(`${DIM}  ${label}${RESET}`);
  out.push("");
  for (const row of renderWord(zero)) out.push("  " + row);
  out.push("");
  out.push("");
}
process.stdout.write(out.join("\n") + "\n");
