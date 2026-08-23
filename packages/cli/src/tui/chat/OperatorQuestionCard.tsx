/** @jsxImportSource @opentui/react */
import React from "react";
import { TextAttributes } from "@opentui/core";
import type { ScrollBoxRenderable } from "@opentui/core";
import { fitTuiText } from "../text.js";
import type { OperatorDisplayRow } from "../operator-question.js";
import type { Theme } from "../theme-context.js";
import type { KeyHint } from "./types.js";
import { KeyHints, keyHintsLength } from "./KeyHints.js";

/**
 * The `ask_operator` question modal.
 *
 * The model paused mid-turn to put a STRUCTURED question to the operator. This
 * renders each question's header + prose and its answerable rows — options
 * (with a `(Recommended)` badge, a radio for single-select and a checkbox for
 * multi-select) and, when the question allows it, a small free-text field — and
 * lets the operator move/toggle/type. It AUTHORIZES NOTHING; it only collects an
 * answer, so its voice is the brand purple (never the red/amber of a gate).
 *
 * The body lives in a fixed-height `<scrollbox>` so any number of questions fits
 * the reserved rows without overflow; the caller scrolls the active row into
 * view. Every child carries an explicit cell width so no row reaches the border.
 */
export function OperatorQuestionCard({
  rows,
  cursor,
  hintPairs,
  bodyViewportRows,
  scrollRef,
  contentWidth,
  height,
  theme,
}: {
  rows: OperatorDisplayRow[];
  cursor: number;
  hintPairs: KeyHint[];
  bodyViewportRows: number;
  scrollRef: React.RefObject<ScrollBoxRenderable | null>;
  contentWidth: number;
  height: number;
  theme: Theme;
}) {
  const { PANEL_ALT, MUTED, TEXT, PRIMARY, ACCENT, INFO, BRAND } = theme;
  const innerWidth = Math.max(1, contentWidth - 4);
  const hintLen = keyHintsLength(hintPairs, " · ");
  return (
    <box flexDirection="column" width="100%" minWidth={0} height={height} flexShrink={0} marginTop={1} border borderColor={BRAND} backgroundColor={PANEL_ALT} paddingX={1}>
      <box width={innerWidth} flexShrink={0} minWidth={0}>
        <text fg={BRAND} attributes={TextAttributes.BOLD}>{fitTuiText("0sec has a question for you", innerWidth)}</text>
      </box>
      <scrollbox
        ref={scrollRef}
        focusable={false}
        scrollX={false}
        width={innerWidth}
        height={bodyViewportRows}
        flexShrink={0}
        scrollbarOptions={{ visible: false }}
      >
        <box flexDirection="column" width={innerWidth} minWidth={0}>
          {rows.map((row, index) => {
            const key = `oq-${row.questionIndex}-${row.type}-${index}`;
            if (row.type === "header") {
              return (
                <box key={key} width={innerWidth} flexShrink={0} minWidth={0}>
                  <text fg={ACCENT} attributes={TextAttributes.BOLD}>{fitTuiText(row.text ?? "", innerWidth)}</text>
                </box>
              );
            }
            if (row.type === "prose") {
              return (
                <box key={key} width={innerWidth} flexShrink={0} minWidth={0}>
                  <text fg={MUTED}>{fitTuiText(row.text ?? "", innerWidth, { mode: "middle" })}</text>
                </box>
              );
            }
            const active = row.navIndex === cursor;
            const marker = active ? "›" : " ";
            if (row.type === "custom") {
              const fieldWidth = Math.max(1, innerWidth - 2);
              const value = row.customText ?? "";
              const isEmpty = value.length === 0 && !active;
              // Keep the tail (where the cursor sits) visible as the field grows.
              const full = `${value}${active ? "█" : ""}`;
              const body = isEmpty
                ? "type a free-text answer…"
                : full.length > fieldWidth ? full.slice(full.length - fieldWidth) : full;
              const bodyColor = isEmpty ? MUTED : TEXT;
              return (
                <box key={key} flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
                  <text width={1} flexShrink={0} fg={active ? PRIMARY : MUTED}>{marker}</text>
                  <box width={fieldWidth} flexShrink={0} minWidth={0} marginLeft={1}>
                    <text fg={bodyColor}>{fitTuiText(body, fieldWidth)}</text>
                  </box>
                </box>
              );
            }
            // option
            const boxGlyph = row.multiSelect
              ? row.selected ? "[x]" : "[ ]"
              : row.selected ? "(•)" : "( )";
            const indicatorCells = 1 /* marker */ + 1 /* gap */ + 3 /* box */ + 1 /* gap */;
            const badge = "(Recommended)";
            const badgeWidth = row.recommended
              ? Math.min(badge.length, Math.max(0, innerWidth - indicatorCells - 8))
              : 0;
            const badgeGap = badgeWidth > 0 ? 1 : 0;
            const labelWidth = Math.max(1, innerWidth - indicatorCells - badgeWidth - badgeGap);
            return (
              <box key={key} flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
                <text width={1} flexShrink={0} fg={active ? PRIMARY : MUTED}>{marker}</text>
                <box width={3} flexShrink={0} minWidth={0} marginLeft={1}>
                  <text fg={row.selected ? ACCENT : MUTED}>{boxGlyph}</text>
                </box>
                <box width={labelWidth} flexShrink={0} minWidth={0} marginLeft={1}>
                  <text fg={active ? PRIMARY : TEXT}>{fitTuiText(row.label ?? "", labelWidth)}</text>
                </box>
                {badgeWidth > 0 ? (
                  <box width={badgeWidth} flexShrink={0} minWidth={0} marginLeft={badgeGap}>
                    <text fg={INFO}>{fitTuiText(badge, badgeWidth)}</text>
                  </box>
                ) : null}
              </box>
            );
          })}
        </box>
      </scrollbox>
      <box width={innerWidth} flexShrink={0} minWidth={0}>
        {hintLen <= innerWidth ? (
          <KeyHints pairs={hintPairs} theme={theme} />
        ) : (
          <text fg={MUTED}>{fitTuiText(hintPairs.map((p) => `${p.key} ${p.label}`).join(" · "), innerWidth)}</text>
        )}
      </box>
    </box>
  );
}
