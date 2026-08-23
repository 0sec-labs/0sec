/** @jsxImportSource @opentui/react */
import React from "react";
import { fitTuiText } from "../text.js";
import { commandMenuBoxHeight } from "../chat-layout.js";
import type { SelectorItem } from "../selector.js";
import type { Theme } from "../theme-context.js";

/**
 * How many rows a selector panel may spend, and on what.
 *
 * The panel is a bordered box stacked above the composer with an EXPLICIT
 * height, so whatever it claims here is exactly what it paints. `budget` is
 * the number of content rows the column can spare (from
 * `computeCommandMenuHeight`, which already reserves the composer, the
 * header and a minimum transcript).
 *
 * The optional lines are bought in priority order out of that budget rather
 * than added on top of it: at least one item row always survives, then the
 * context line (which says WHAT is being decided), then the detail line for
 * the highlighted item. A panel that cannot afford them drops them instead
 * of growing past its budget and over-subscribing the column — which is the
 * exact failure that painted four `<text>` children onto one another and
 * through the box border.
 */
export function selectorPanelBudget({
  budget,
  hasContext,
  hasDetail,
}: {
  budget: number;
  hasContext: boolean;
  hasDetail: boolean;
}): { maxItemRows: number; showContext: boolean; showDetail: boolean } {
  const total = Math.max(1, budget);
  let remaining = total - 1; // one item row is non-negotiable
  const showContext = hasContext && remaining > 0;
  if (showContext) remaining -= 1;
  const showDetail = hasDetail && remaining > 0;
  if (showDetail) remaining -= 1;
  return { maxItemRows: 1 + remaining, showContext, showDetail };
}

/**
 * Total rows a selector panel occupies for the rows it actually renders.
 * `commandMenuBoxHeight` covers the two border rows, the header and the
 * hint footer; the optional lines are added explicitly.
 */
export function selectorPanelHeight(itemRows: number, showContext: boolean, showDetail: boolean): number {
  return commandMenuBoxHeight(Math.max(itemRows, 1), 1)
    + (showContext ? 1 : 0)
    + (showDetail ? 1 : 0);
}

/**
 * THE decision surface.
 *
 * `/model`, `/mode`, `/settings`, `/providers`, `/resume` and every
 * authorization prompt render through this one component, driven by the same
 * `SelectorState` reducer and the same key bindings. Approvals used to be
 * four bespoke bordered boxes of loose `<text>` children; opentui defaults
 * `flexShrink` to 1 for any box without a numeric width/height, so under
 * column pressure Yoga collapsed those boxes while their children kept their
 * intrinsic size — every line, and the border, painted onto one row.
 *
 * Two properties prevent that here and are the reason approvals were moved
 * onto this component rather than patched in place:
 *   - an explicit `height` plus `flexShrink={0}`, so the box is clipped by
 *     the layout rather than squeezed under its own contents;
 *   - every child given an explicit cell width, so no row can overspend the
 *     panel's inner width and paint into the border.
 */
export function SelectorPanel({
  title,
  subtitle,
  context,
  contextColor,
  rows,
  windowStart,
  activeIndex,
  detail,
  hint,
  emptyText,
  borderColor,
  titleColor,
  contentWidth,
  height,
  theme,
}: {
  title: string;
  subtitle: string;
  context?: string;
  contextColor?: string;
  rows: SelectorItem[];
  windowStart: number;
  activeIndex: number;
  detail?: string;
  hint: string;
  emptyText: string;
  borderColor: string;
  titleColor: string;
  contentWidth: number;
  height: number;
  theme: Theme;
}) {
  const { PANEL_ALT, MUTED, TEXT, PRIMARY, ACCENT, ERROR } = theme;
  // Deliberately conservative: the real inner width is 2 (compact) to 4
  // (wide) cells more than this, so every explicit allocation below fits
  // with room to spare and can never reach the border.
  const innerWidth = Math.max(1, contentWidth - 4);
  const headerGap = innerWidth > 12 ? 1 : 0;
  const headerTitleWidth = Math.max(1, Math.min(innerWidth - headerGap, Math.floor(innerWidth * 0.55)));
  const headerSubtitleWidth = Math.max(0, innerWidth - headerTitleWidth - headerGap);
  // Marker cell + its gap, then label, then whatever is left for the meta
  // column. Widths and margins sum to exactly `innerWidth`; the old picker
  // used `gap={1}` on top of widths that already spent the full row, which
  // overspent it by two cells.
  const labelWidth = Math.max(1, Math.min(Math.max(1, innerWidth - 2), Math.floor(innerWidth * 0.45)));
  const afterLabel = innerWidth - 2 - labelWidth;
  const metaGap = afterLabel > 1 ? 1 : 0;
  const metaWidth = Math.max(0, afterLabel - metaGap);

  return (
    <box flexDirection="column" width="100%" minWidth={0} height={height} flexShrink={0} marginTop={1} border borderColor={borderColor} backgroundColor={PANEL_ALT} paddingX={1}>
      <box flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
        <box width={headerTitleWidth} flexShrink={0} minWidth={0}>
          <text fg={titleColor}>{fitTuiText(title, headerTitleWidth)}</text>
        </box>
        {headerSubtitleWidth > 0 ? (
          <box width={headerSubtitleWidth} flexShrink={0} minWidth={0} marginLeft={headerGap}>
            <text fg={MUTED}>{fitTuiText(subtitle, headerSubtitleWidth, { mode: "middle" })}</text>
          </box>
        ) : null}
      </box>
      {context ? (
        <box width={innerWidth} flexShrink={0} minWidth={0}>
          {/* Truncated, never wrapped: a wrapping line has an unpredictable
              height, and an unpredictable height is what over-subscribes the
              column in the first place. */}
          <text fg={contextColor ?? TEXT}>{fitTuiText(context, innerWidth, { mode: "middle" })}</text>
        </box>
      ) : null}
      {rows.length > 0 ? rows.map((item, offset) => {
        const index = windowStart + offset;
        const active = index === activeIndex;
        return (
          <box key={item.id} flexDirection="row" width={innerWidth} flexShrink={0} minWidth={0}>
            <text width={1} flexShrink={0} fg={active ? PRIMARY : MUTED}>{active ? "›" : " "}</text>
            <box width={labelWidth} flexShrink={0} minWidth={0} marginLeft={1}>
              <text fg={item.disabled ? MUTED : active ? TEXT : MUTED}>{fitTuiText(`${item.current ? "● " : "  "}${item.label}`, labelWidth)}</text>
            </box>
            {metaWidth > 0 ? (
              <box width={metaWidth} flexShrink={0} minWidth={0} marginLeft={metaGap}>
                <text fg={active ? ACCENT : MUTED}>{fitTuiText(item.meta ?? "", metaWidth, { mode: "middle" })}</text>
              </box>
            ) : null}
          </box>
        );
      }) : (
        <box width={innerWidth} flexShrink={0} minWidth={0}>
          <text fg={ERROR}>{fitTuiText(emptyText, innerWidth)}</text>
        </box>
      )}
      {detail ? (
        <box width={innerWidth} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText(detail, innerWidth, { mode: "middle" })}</text>
        </box>
      ) : null}
      <box width={innerWidth} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{fitTuiText(hint, innerWidth)}</text>
      </box>
    </box>
  );
}
