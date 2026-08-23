/** @jsxImportSource @opentui/react */
/**
 * The full-screen provider connect / login screen (`/connect`, alias `/login`).
 *
 * `/providers` reports which vendors this machine can already reach; this
 * screen is the write side, letting the operator connect one without leaving
 * the console. It mirrors `model-screen.tsx` in shape — a grouped list on the
 * left, the highlighted provider's detail on the right, stacked when the
 * terminal is too narrow to hold both — and, like it, does no arithmetic of
 * its own: every width, row count and window boundary comes off
 * `connect-layout.ts`, which is swept across widths 0..200 and heights 0..80.
 *
 * Two properties are load-bearing:
 *
 * 1. **A credential leaves this screen only through the credential store.** The
 *    input sub-step writes the pasted secret with `saveCredentials`, which
 *    persists it owner-only to `~/.0sec/credentials.json`. Nothing is sent
 *    anywhere else, and the raw value is never rendered — the input echoes a
 *    fixed, length-capped dot run, never the secret.
 *
 * 2. **The green check is verified, never optimistic.** A provider reads as
 *    connected only when `providerStates` finds an env credential or the store
 *    on disk holds one. There is no sticky "connecting…" state; the check
 *    appears after a save because the store now holds the value, not because
 *    the screen assumed the save worked.
 *
 * The subscription / OAuth path is honest about the absence of an in-tool
 * network dance: for a subscription provider the detail pane names the real
 * sign-in (e.g. `codex login`) and the sub-step accepts the token the operator
 * pastes back, storing it the same way an API key is stored. It never fakes a
 * completed OAuth handshake.
 */

import React, { useEffect, useMemo, useState } from "react";
import { TextAttributes } from "@opentui/core";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";

import { useTheme, type Theme } from "./theme-context.js";
import { Cells } from "./primitives.js";
import { providerStates } from "./provider-status.js";
import {
  loadCredentials,
  saveCredentials,
  type StoredCredentials,
} from "./credential-store.js";
import {
  authHintLabel,
  buildConnectRows,
  clampSelection,
  clipConnectDetailLines,
  computeConnectLayout,
  computeConnectTitleLayout,
  computeConnectWindow,
  connectDetailLines,
  connectDetailTitleLabel,
  connectDetailTitleMeta,
  connectFooterHint,
  connectInputMask,
  connectListMeta,
  connectListTitleLabel,
  connectStatusLine,
  firstSelectableIndex,
  hasAnyConnection,
  isFilterKey,
  moveSelection,
  pastableChars,
  type ConnectDetailTone,
  type ConnectMode,
  type ConnectPane,
  type ConnectProvider,
} from "./connect-layout.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;

/**
 * True when at least one provider holds a real credential — in the environment
 * or in the on-disk store. Drives a later onboarding nudge; reads once per
 * environment change, since credentials are process-level and a file read on
 * every render would be wasted work.
 */
export function useConnected(env: Record<string, string | undefined> = process.env): boolean {
  return useMemo(() => {
    const states = providerStates(env);
    const stored = loadCredentials();
    return hasAnyConnection({ states, stored: Object.keys(stored) });
  }, [env]);
}

export interface ConnectFrameInput {
  body: React.ReactNode;
  hint: string;
}

export interface ConnectScreenProps {
  /** Wraps the body in the console shell (injected so this file need not import run.tsx). */
  frame: (input: ConnectFrameInput) => React.ReactNode;
  /** Leave the screen — Esc once any filter is cleared. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
  /** Environment to read credentials from. Defaults to the real one; injected for tests. */
  env?: Record<string, string | undefined>;
  /**
   * The credential store home dir. Defaults to the real one; injected so a test
   * can point the store at a temp dir without touching the operator's file.
   */
  homeDir?: string;
}

function toneColor(theme: Theme, tone: ConnectDetailTone): string | undefined {
  switch (tone) {
    case "title":
      return theme.PRIMARY;
    case "accent":
      return theme.ACCENT;
    case "ok":
      return theme.SUCCESS;
    case "warn":
      return theme.WARNING;
    case "muted":
    case "blank":
      return theme.MUTED;
    default:
      return theme.TEXT;
  }
}

/** A pane that states its own height; renders nothing when the layout gave it none. */
function Pane({
  pane,
  bordered,
  title,
  children,
}: {
  pane: ConnectPane;
  bordered: boolean;
  /** The header row node, already fitted to the pane's inner width. */
  title: React.ReactNode;
  children: React.ReactNode;
}) {
  const theme = useTheme();
  if (pane.width <= 0 || pane.height <= 0) return null;
  const titleRow = pane.hasTitle ? title : null;
  return (
    <box
      flexDirection="column"
      width={pane.width}
      height={pane.height}
      flexShrink={0}
      flexGrow={0}
      minWidth={0}
      border={bordered || undefined}
      borderColor={bordered ? theme.BORDER : undefined}
      backgroundColor={bordered ? theme.PANEL : undefined}
      paddingX={bordered ? 1 : undefined}
    >
      {titleRow}
      {children}
    </box>
  );
}

/**
 * A pane header: a bold, primary-toned title on the left and a right-aligned
 * summary meta on the right. Widths come off `computeConnectTitleLayout`, so the
 * row claims exactly the pane's inner width and the title survives when the
 * header is too narrow for both. `metaFg` lets the caller colour the meta (the
 * detail header greens a connected provider).
 */
function TitleRow({
  innerWidth,
  title,
  meta,
  metaFg,
}: {
  innerWidth: number;
  title: string;
  meta: string;
  metaFg: string;
}) {
  const theme = useTheme();
  const columns = computeConnectTitleLayout(innerWidth, meta.length);
  if (columns.width <= 0) return null;
  return (
    <box flexDirection="row" width={columns.width} flexShrink={0} minWidth={0}>
      <Cells width={columns.titleWidth} fg={theme.PRIMARY} attributes={TextAttributes.BOLD}>
        {title}
      </Cells>
      {columns.metaWidth > 0 ? (
        <>
          <Cells width={columns.gap}>{""}</Cells>
          <Cells width={columns.metaWidth} align="right" fg={metaFg}>
            {meta}
          </Cells>
        </>
      ) : null}
    </box>
  );
}

export function ConnectScreen({ frame, onBack, onExit, env, homeDir }: ConnectScreenProps) {
  const theme = useTheme();
  const { width, height } = useTerminalDimensions();

  const [filter, setFilter] = useState("");
  const [filtering, setFiltering] = useState(false);
  const [anchor, setAnchor] = useState(0);

  // The store is component state so a save is reflected immediately: the row's
  // check turns green because the store now holds the value, not because the
  // screen assumed the write succeeded.
  const [stored, setStored] = useState<StoredCredentials>(() => loadCredentials(homeDir));

  // Input sub-step state. `inputProviderId` doubles as the "are we in the input
  // sub-step" flag; the raw secret lives here and nowhere else, and is dropped
  // the moment the step ends.
  const [inputProviderId, setInputProviderId] = useState<string | undefined>(undefined);
  const [inputValue, setInputValue] = useState("");
  const [notice, setNotice] = useState<string | undefined>(undefined);

  // Credentials are process-level; re-read env only when the injected env changes.
  const states = useMemo(() => providerStates(env ?? process.env), [env]);
  const storedIds = useMemo(() => new Set(Object.keys(stored)), [stored]);

  const rows = useMemo(
    () => buildConnectRows({ states, stored: storedIds, filter }),
    [states, storedIds, filter],
  );

  const [selected, setSelected] = useState(() => {
    const at = firstSelectableIndex(buildConnectRows({ states, stored: storedIds }));
    return at >= 0 ? at : 0;
  });

  const cursor = clampSelection(rows, selected);
  const activeRow = cursor >= 0 ? rows[cursor] : undefined;
  const activeProvider: ConnectProvider | undefined =
    activeRow?.kind === "provider" ? activeRow.provider : undefined;

  const layout = computeConnectLayout({ width, height, noticeRows: 1 });
  const window = computeConnectWindow({ rows, selected: cursor, visible: layout.visibleRows, anchor });

  const inInput = inputProviderId !== undefined;
  const mode: ConnectMode = inInput ? "input" : filtering ? "filter" : "browse";

  // Keep the stored anchor in step with the window the list is actually
  // showing, so the list scrolls rather than jumps — but leave it frozen while
  // the input sub-step is up, since the cursor cannot move there.
  useEffect(() => {
    if (!inInput && window.start !== anchor) setAnchor(window.start);
  }, [inInput, window.start, anchor]);
  useEffect(() => {
    if (cursor >= 0 && cursor !== selected) setSelected(cursor);
  }, [cursor, selected]);

  const move = (delta: number) => {
    const next = moveSelection(rows, cursor, delta);
    if (next >= 0) {
      setSelected(next);
      setNotice(undefined);
    }
  };

  const setQuery = (next: string) => {
    setFilter(next);
    setSelected(0);
    setAnchor(0);
  };

  const beginConnect = (provider: ConnectProvider) => {
    setInputProviderId(provider.id);
    setInputValue("");
    setNotice(undefined);
  };

  const cancelInput = () => {
    setInputProviderId(undefined);
    setInputValue("");
  };

  const commitInput = () => {
    const id = inputProviderId;
    const secret = inputValue.trim();
    setInputProviderId(undefined);
    setInputValue("");
    if (!id) return;
    if (secret.length === 0) {
      setNotice("nothing pasted; provider unchanged");
      return;
    }
    const next: StoredCredentials = { ...stored, [id]: secret };
    const ok = saveCredentials(next, homeDir);
    if (!ok) {
      setNotice("could not write credentials (is HOME writable?)");
      return;
    }
    // Re-read so the row reflects exactly what the store normalised and kept.
    const reloaded = loadCredentials(homeDir);
    setStored(reloaded);
    const label = states.find((s) => s.id === id)?.label ?? id;
    setNotice(reloaded[id] ? `connected ${label}` : `${label} not stored`);
  };

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";

    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }

    // ── input sub-step ──
    if (inInput) {
      if (key.name === "escape") {
        cancelInput();
        return;
      }
      if (key.name === "return") {
        commitInput();
        return;
      }
      if (key.name === "backspace") {
        setInputValue((current) => current.slice(0, -1));
        return;
      }
      const chunk = pastableChars(seq);
      if (chunk) setInputValue((current) => current + chunk);
      return;
    }

    // ── movement (browse and filter) ──
    if (key.name === "up") return move(-1);
    if (key.name === "down") return move(1);
    if (key.name === "pageup") return move(-PAGE_STEP);
    if (key.name === "pagedown") return move(PAGE_STEP);
    if (key.name === "return") {
      if (activeProvider) beginConnect(activeProvider);
      return;
    }

    // ── filter mode ──
    if (filtering) {
      if (key.name === "escape") {
        setFiltering(false);
        return;
      }
      if (key.name === "backspace") {
        setQuery(filter.slice(0, -1));
        return;
      }
      if (isFilterKey(seq)) setQuery(filter + seq);
      return;
    }

    // ── browse mode ──
    if (key.name === "escape") {
      if (filter) {
        setQuery("");
        return;
      }
      onBack();
      return;
    }
    if (key.name === "backspace") {
      if (filter) setQuery(filter.slice(0, -1));
      return;
    }
    if (seq === "/") {
      setFiltering(true);
      setQuery("");
      return;
    }
    if (isFilterKey(seq)) {
      setFiltering(true);
      setQuery(seq);
    }
  });

  const row = layout.row;
  const heading = layout.heading;
  const visible = rows.slice(window.start, window.end);

  const listBody = visible.map((entry, offset) => {
    const index = window.start + offset;

    if (entry.kind === "heading") {
      return (
        <box
          key={`heading-${entry.group.id}`}
          flexDirection="row"
          width={heading.width}
          flexShrink={0}
          minWidth={0}
        >
          <Cells width={heading.labelWidth} fg={theme.MUTED} attributes={TextAttributes.BOLD}>
            {entry.group.label.toUpperCase()}
          </Cells>
          <Cells width={heading.gap}>{""}</Cells>
          <Cells width={heading.stateWidth} align="right" fg={theme.MUTED}>
            {""}
          </Cells>
        </box>
      );
    }

    if (entry.kind === "subtitle") {
      return (
        <box
          key={`subtitle-${index}`}
          flexDirection="row"
          width={row.width}
          flexShrink={0}
          minWidth={0}
        >
          <Cells width={row.markerWidth + row.markerGap}>{""}</Cells>
          <Cells width={Math.max(0, row.width - row.markerWidth - row.markerGap)} fg={theme.MUTED}>
            {entry.text}
          </Cells>
        </box>
      );
    }

    const selectedRow = index === cursor;
    const background = selectedRow ? theme.PANEL_ALT : undefined;
    const provider = entry.provider;
    return (
      <box
        key={`provider-${provider.id}`}
        flexDirection="row"
        width={row.width}
        flexShrink={0}
        minWidth={0}
      >
        <Cells width={row.markerWidth} fg={theme.ACCENT} bg={background}>
          {selectedRow ? "▸" : ""}
        </Cells>
        <Cells width={row.markerGap} bg={background}>
          {""}
        </Cells>
        <Cells width={row.checkWidth} fg={theme.SUCCESS} bg={background}>
          {provider.connected ? "✓" : ""}
        </Cells>
        <Cells width={row.checkGap} bg={background}>
          {""}
        </Cells>
        <Cells
          width={row.labelWidth}
          fg={provider.connected ? theme.SUCCESS : selectedRow ? theme.ACCENT : theme.MUTED}
          bg={background}
        >
          {provider.label}
        </Cells>
        <Cells width={row.authGap} bg={background}>
          {""}
        </Cells>
        <Cells width={row.authWidth} align="right" fg={theme.MUTED} bg={background}>
          {provider.connected ? "connected" : authHintLabel(provider.auth)}
        </Cells>
      </box>
    );
  });

  const detailBody = clipConnectDetailLines(
    connectDetailLines({ row: activeRow, compact: layout.detailCompact }, layout.detail.innerWidth),
    layout.detail.bodyRows,
    layout.detail.innerWidth,
  ).map((line, index) => (
    <Cells key={`detail-${index}`} width={layout.detail.innerWidth} fg={toneColor(theme, line.tone)}>
      {line.text}
    </Cells>
  ));

  const statusText = inInput
    ? `${activeProvider?.auth === "subscription" ? "paste sign-in token" : "paste API key"} for ${
        activeProvider?.label ?? inputProviderId
      }: ${connectInputMask(inputValue.length)}`
    : filtering
      ? `filter: ${filter}_`
      : notice
        ? notice
        : filter
          ? `filter: ${filter} · ${connectStatusLine(rows)}`
          : connectStatusLine(rows);

  const statusFg = inInput ? theme.ACCENT : notice ? theme.SUCCESS : theme.MUTED;

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <box
        flexDirection={layout.stacked ? "column" : "row"}
        gap={layout.paneGap}
        flexShrink={0}
        minWidth={0}
      >
        <Pane
          pane={layout.list}
          bordered={layout.bordered}
          title={
            <TitleRow
              innerWidth={layout.list.innerWidth}
              title={connectListTitleLabel()}
              meta={connectListMeta(window)}
              metaFg={theme.MUTED}
            />
          }
        >
          {rows.length === 0 ? (
            <Cells width={row.width} fg={theme.MUTED}>
              no providers match this filter
            </Cells>
          ) : (
            listBody
          )}
        </Pane>
        <Pane
          pane={layout.detail}
          bordered={layout.bordered}
          title={
            <TitleRow
              innerWidth={layout.detail.innerWidth}
              title={connectDetailTitleLabel()}
              meta={connectDetailTitleMeta(activeRow)}
              metaFg={activeProvider?.connected ? theme.SUCCESS : theme.MUTED}
            />
          }
        >
          {detailBody}
        </Pane>
      </box>
      <box flexDirection="row" width="100%" flexShrink={0} minWidth={0}>
        <Cells width={layout.contentWidth} fg={statusFg}>
          {statusText}
        </Cells>
      </box>
    </box>
  );

  return <>{frame({ body, hint: connectFooterHint(mode, filter.length > 0) })}</>;
}
