/** @jsxImportSource @opentui/react */
import React from "react";
import type { ScrollBoxRenderable } from "@opentui/core";
import { fitTuiText } from "../text.js";
import type { CommandMenuLayout } from "../chat-layout.js";
import type { SlashCommand } from "../slash-commands.js";
import type { Theme } from "../theme-context.js";

/**
 * The slash-command menu, a bordered box stacked directly above the composer.
 * Extracted verbatim from ChatScreen's `buildCommandMenu`; every width, the
 * fixed-height scrollbox and the no-overflow contract are unchanged — the caller
 * still owns navigation (the module keyboard handler) and scroll positioning.
 * One builder, two call sites: the full-width `layout` for the pinned chat
 * composer and a narrower one aligned to the centered hero card.
 */
export function CommandMenu({
  layout,
  boxWidth,
  height,
  scrollRef,
  commands,
  selectedIndex,
  visibleRows,
  rowsPerCommand,
  query,
  compact,
  theme,
}: {
  layout: CommandMenuLayout;
  boxWidth: number | "100%";
  height: number;
  scrollRef: React.RefObject<ScrollBoxRenderable | null>;
  commands: SlashCommand[];
  selectedIndex: number;
  visibleRows: number;
  rowsPerCommand: number;
  query: string;
  compact: boolean;
  theme: Theme;
}) {
  const { BORDER, PANEL_ALT, MUTED, PRIMARY, TEXT, ERROR } = theme;
  return (
    <box flexDirection="column" width={boxWidth} minWidth={0} height={height} flexShrink={0} marginTop={1} border borderColor={BORDER} backgroundColor={PANEL_ALT} paddingX={1}>
      <box flexDirection="row" width={layout.innerWidth} minWidth={0} gap={layout.headerGap}>
        <box width={layout.headerTitleWidth} flexShrink={0} minWidth={0}>
          <text fg={MUTED}>{fitTuiText("COMMANDS", layout.headerTitleWidth)}</text>
        </box>
        {layout.headerQueryWidth > 0 ? (
          <box width={layout.headerQueryWidth} flexShrink={0} minWidth={0}>
            <text fg={MUTED}>{fitTuiText(query ? `/${query}` : "all commands", layout.headerQueryWidth, { mode: "middle" })}</text>
          </box>
        ) : null}
      </box>
      {commands.length > 0 ? (
        // The rows live in a fixed-height scrollbox: the box shows a window of
        // `visibleRows` entries and the selection is scrolled into view
        // (the effect below drives scrollTop), so every match is reachable while
        // the box height, budget and no-overflow contract are unchanged. The
        // scrollbar is hidden and the box is not focusable — navigation stays
        // with the module keyboard handler.
        <scrollbox
          ref={scrollRef}
          focusable={false}
          scrollX={false}
          width={layout.innerWidth}
          height={visibleRows * rowsPerCommand}
          flexShrink={0}
          scrollbarOptions={{ visible: false }}
        >
          <box flexDirection="column" width={layout.innerWidth} minWidth={0}>
            {commands.map((command, index) => {
              const active = index === selectedIndex;
              const meta = command.aliases.length > 0
                ? command.aliases.map((alias) => `/${alias}`).join(" ")
                : command.category;
              return (
                <box key={command.name} flexDirection="row" width={layout.innerWidth} flexShrink={0} minWidth={0}>
                  <text width={1} flexShrink={0} fg={active ? PRIMARY : MUTED}>{active ? "›" : " "}</text>
                  <box flexDirection="column" width={layout.rowWidth} flexGrow={0} flexShrink={0} minWidth={0} marginLeft={1}>
                    <box flexDirection="row" width={layout.rowWidth} minWidth={0} gap={1}>
                      <box width={layout.nameWidth} flexShrink={0} minWidth={0}>
                        <text fg={active ? PRIMARY : TEXT}>{fitTuiText(`/${command.name}`, layout.nameWidth)}</text>
                      </box>
                      {layout.metaWidth > 0 ? (
                        <box width={layout.metaWidth} flexShrink={0} minWidth={0}>
                          <text fg={MUTED}>{fitTuiText(meta, layout.metaWidth)}</text>
                        </box>
                      ) : null}
                    </box>
                    {!compact ? (
                      <box width={layout.rowWidth} minWidth={0}>
                        <text fg={MUTED} wrapMode="word">{fitTuiText(command.description, layout.rowWidth)}</text>
                      </box>
                    ) : null}
                  </box>
                </box>
              );
            })}
          </box>
        </scrollbox>
      ) : (
        <box width={layout.innerWidth} flexShrink={0} minWidth={0}>
          <text fg={ERROR}>{fitTuiText(`No command matches /${query}`, Math.max(1, layout.innerWidth))}</text>
        </box>
      )}
      <box width={layout.innerWidth} flexShrink={0} minWidth={0}>
        <text fg={MUTED}>{fitTuiText("↑↓ select · tab complete · enter run · esc close", Math.max(1, layout.innerWidth))}</text>
      </box>
    </box>  );
}
