/** @jsxImportSource @opentui/react */
import React from "react";
import type { Theme } from "../theme-context.js";
import type { TuiSettings } from "../settings.js";

/**
 * Composer chrome, selected by the `composerStyle` setting.
 *
 * Deliberately three distinct elements instead of one box with toggled
 * props: opentui renders a frame whenever `border` is present at all, so a
 * falsy value does not remove it.
 */
export function ComposerFrame({
  style,
  active,
  theme,
  padY = 0,
  children,
}: {
  style: TuiSettings["composerStyle"];
  active: boolean;
  theme: Theme;
  /**
   * Extra rows of vertical padding inside the frame. Used ONLY by the centered
   * hero composer, so the start-screen input reads as a comfortable card rather
   * than a thin sliver; the pinned chat composer leaves it at 0 so its height
   * matches the COMPOSER_ROWS the column reserves.
   */
  padY?: number;
  children: React.ReactNode;
}) {
  const { PRIMARY, MUTED, BORDER, PANEL_ALT } = theme;
  if (style === "border") {
    return (
      <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} border borderColor={active ? PRIMARY : BORDER} backgroundColor={PANEL_ALT} paddingX={1} paddingTop={padY} paddingBottom={padY}>
        {children}
      </box>
    );
  }
  if (style === "rail") {
    return (
      <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} marginLeft={1} backgroundColor={PANEL_ALT} paddingTop={padY} paddingBottom={padY}>
        {children}
      </box>
    );
  }
  return (
    <box flexDirection="column" flexGrow={1} minWidth={0} flexShrink={0} paddingTop={padY} paddingBottom={padY}>
      {children}
    </box>
  );
}
