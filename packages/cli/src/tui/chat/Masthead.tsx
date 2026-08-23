/** @jsxImportSource @opentui/react */
import React from "react";
import { fitTuiText } from "../text.js";
import { computeLogoFrame, logoRowRuns } from "../logo-animation.js";
import { TERMINAL_BLOCK_LOGO_WIDTH, logoRunStyle } from "./logo.js";
import type { Theme } from "../theme-context.js";

/**
 * The centered empty-state hero: a muted EYEBROW (the lab name) above the 0sec
 * block mark, then the tagline. Extracted verbatim from ChatScreen's hero so
 * placement and every width/flex invariant is unchanged; the caller still gates
 * the whole unit behind `showMasthead`.
 */
export function Masthead({
  showTerminalMark,
  showTagline,
  contentWidth,
  logoFrameGrid,
  theme,
}: {
  showTerminalMark: boolean;
  showTagline: boolean;
  contentWidth: number;
  logoFrameGrid: ReturnType<typeof computeLogoFrame>;
  theme: Theme;
}) {
  const { MUTED, TEXT } = theme;
  return (
    <>
      {showTerminalMark ? (
        <text fg={MUTED} marginBottom={1}>{fitTuiText("Swiss Applied AI Cybersecurity Research Lab", contentWidth, { mode: "middle" })}</text>
      ) : null}
      {showTerminalMark ? (
        <box flexDirection="column" width={TERMINAL_BLOCK_LOGO_WIDTH} minWidth={TERMINAL_BLOCK_LOGO_WIDTH} flexShrink={0}>
          {/*
            * 0sec brand mark: a slashed zero — a white "0" outline with a
            * red diagonal slash through its hollow — then white "SEC".
            * The per-cell frame comes from computeLogoFrame (the intro
            * animation, or the settled final frame under reduceMotion/"off");
            * logoRowRuns coalesces each row into (tone,visible) runs whose
            * widths sum to TERMINAL_BLOCK_LOGO_WIDTH, so no run overflows and
            * each tone keeps its own token. Rendered verbatim — the row
            * widths are exact, so no fitTuiText/trim is needed.
            */}
          {logoFrameGrid.map((row, index) => (
            <box key={`logo-${index}`} flexDirection="row" width={TERMINAL_BLOCK_LOGO_WIDTH} flexShrink={0} minWidth={0}>
              {logoRowRuns(row).map((run, runIndex) => {
                const style = logoRunStyle(run.tone, theme);
                const glyph = run.visible ? "█" : " ";
                return (
                  <text
                    key={`logo-${index}-${runIndex}`}
                    width={run.length}
                    flexShrink={0}
                    fg={style.fg}
                    attributes={style.attributes}
                  >{glyph.repeat(run.length)}</text>
                );
              })}
            </box>
          ))}
        </box>
      ) : (
        <box flexDirection="row" flexShrink={0}>
          <text fg={TEXT}>0SEC · OPERATOR CONSOLE</text>
        </box>
      )}
      {showTagline ? (
        <text fg={TEXT} marginTop={1}>{fitTuiText("The open, extensible & self-evolving cybersecurity harness", contentWidth, { mode: "middle" })}</text>
      ) : null}
    </>
  );
}
