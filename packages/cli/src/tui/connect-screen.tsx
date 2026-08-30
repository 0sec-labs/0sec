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
 * The ChatGPT Codex path runs the official `codex login --device-auth` flow
 * under this OpenTUI pane. It never asks for an API key or pasted OAuth token:
 * Codex owns the browser/device protocol and writes its auth file; completion
 * reloads that file into this process only after a successful device login.
 */

import React, { useEffect, useMemo, useRef, useState } from "react";
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
import type { ConnectionRecovery } from "./connection-recovery.js";
import {
  startCodexDeviceAuth,
  type CodexDeviceAuthSession,
  type CodexDeviceAuthUpdate,
} from "./codex-device-auth.js";
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
  /** Provider/authentication failure that opened this screen, if any. */
  recovery?: ConnectionRecovery;
  /** Called after a provider is persisted so the chat can rebuild in place. */
  onConnected?: (providerId: string) => void;
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

/**
 * Local equivalent of the shell's RailBar. It is a painted one-cell spine, not
 * a text glyph, so it remains a continuous rule across the section's height.
 */
function RailBar({ tone }: { tone: string }) {
  return <box width={1} flexShrink={0} alignSelf="stretch" backgroundColor={tone} />;
}

/**
 * The connect flow uses the same sparse rail treatment as chat: one primary
 * selection rail, then a flat selected-provider context. `connect-layout`
 * already reserves four cells of wide-screen pane chrome; this spends them as
 * rail + breathing room instead of drawing a second all-sided console box.
 */
function RailPane({
  pane,
  railTone,
  title,
  children,
}: {
  pane: ConnectPane;
  /** Omit for the quieter selected-provider context pane. */
  railTone?: string;
  /** The header row node, already fitted to the pane's inner width. */
  title: React.ReactNode;
  children: React.ReactNode;
}) {
  if (pane.width <= 0 || pane.height <= 0 || pane.innerWidth <= 0) return null;
  const titleRow = pane.hasTitle ? title : null;
  const hasWideChrome = pane.width > pane.innerWidth;
  const body = (
    <>
      {titleRow}
      {children}
    </>
  );

  if (railTone && hasWideChrome) {
    return (
      <box
        flexDirection="row"
        width={pane.width}
        height={pane.height}
        flexShrink={0}
        flexGrow={0}
        minWidth={0}
      >
        <RailBar tone={railTone} />
        <box
          flexDirection="column"
          width={pane.innerWidth}
          height={pane.height}
          flexShrink={0}
          flexGrow={0}
          minWidth={0}
          marginLeft={1}
        >
          {body}
        </box>
      </box>
    );
  }

  return (
    <box
      flexDirection="column"
      width={pane.width}
      height={pane.height}
      flexShrink={0}
      flexGrow={0}
      minWidth={0}
    >
      <box
        flexDirection="column"
        width={pane.innerWidth}
        height={pane.height}
        flexShrink={0}
        flexGrow={0}
        minWidth={0}
        marginLeft={hasWideChrome ? 2 : undefined}
      >
        {body}
      </box>
    </box>
  );
}

/** A compact rail treatment for an OAuth or connection-recovery message. */
function DetailRail({
  showRail,
  tone,
  children,
}: {
  showRail: boolean;
  tone: string;
  children: React.ReactNode;
}) {
  if (!showRail) {
    return <box flexDirection="column" width="100%" minWidth={0}>{children}</box>;
  }
  return (
    <box flexDirection="row" width="100%" minWidth={0}>
      <RailBar tone={tone} />
      <box flexDirection="column" flexGrow={1} minWidth={0} paddingLeft={1}>
        {children}
      </box>
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

function oauthStateTone(theme: Theme, phase: CodexDeviceAuthUpdate["phase"]): string {
  switch (phase) {
    case "failed":
      return theme.ERROR;
    case "connected":
      return theme.SUCCESS;
    case "running":
      return theme.ACCENT;
    default:
      return theme.MUTED;
  }
}

function oauthStateTitle(
  phase: CodexDeviceAuthUpdate["phase"],
  standalone: boolean,
): string {
  switch (phase) {
    case "connected":
      return standalone ? "ChatGPT Codex connected" : "connected";
    case "failed":
      return standalone ? "ChatGPT Codex sign-in failed" : "sign-in failed";
    case "cancelled":
      return standalone ? "ChatGPT Codex sign-in cancelled" : "sign-in cancelled";
    default:
      return standalone ? "ChatGPT Codex device sign-in" : "device sign-in";
  }
}

function oauthStateMeta(phase: CodexDeviceAuthUpdate["phase"]): string {
  switch (phase) {
    case "running":
      return "sign-in";
    case "connected":
      return "connected";
    case "failed":
      return "failed";
    default:
      return "cancelled";
  }
}

function oauthRecoveryHint(phase: CodexDeviceAuthUpdate["phase"]): string {
  switch (phase) {
    case "running":
      return "Complete the sign-in in your browser. Keep this pane open; Esc cancels.";
    case "failed":
      return "Review the Codex output, then press Enter to try again or use ↑/↓ to choose another provider.";
    case "connected":
      return "The subscription credential is loaded for this session.";
    default:
      return "Press Enter to try again or use ↑/↓ to choose another provider.";
  }
}

export function ConnectScreen({ frame, onBack, onExit, recovery, onConnected, env, homeDir }: ConnectScreenProps) {
  const theme = useTheme();
  const { width, height } = useTerminalDimensions();

  const [filter, setFilter] = useState("");
  const [filtering, setFiltering] = useState(false);
  const [anchor, setAnchor] = useState(0);

  // The store is component state so a save is reflected immediately: the row's
  // check turns green because the store now holds the value, not because the
  // screen assumed the write succeeded.
  const [stored, setStored] = useState<StoredCredentials>(() => loadCredentials(homeDir));

  // API-key input state. The raw secret lives here and nowhere else, and is
  // dropped the moment the sub-step ends.
  const [inputProviderId, setInputProviderId] = useState<string | undefined>(undefined);
  const [inputValue, setInputValue] = useState("");
  const [notice, setNotice] = useState<string | undefined>(undefined);
  const oauthSessionRef = useRef<CodexDeviceAuthSession | undefined>(undefined);
  const [oauth, setOauth] = useState<
    (CodexDeviceAuthUpdate & { providerId: string }) | undefined
  >(undefined);
  const [authEpoch, setAuthEpoch] = useState(0);

  // OAuth completion updates process env, so authEpoch is the explicit redraw
  // boundary for providerStates rather than a hidden file-read side effect.
  const states = useMemo(() => providerStates(env ?? process.env), [env, authEpoch]);
  const storedIds = useMemo(() => new Set(Object.keys(stored)), [stored]);

  const rows = useMemo(
    () => buildConnectRows({ states, stored: storedIds, filter }),
    [states, storedIds, filter],
  );

  const recoveredProviderRef = useRef<string | undefined>(undefined);
  const [selected, setSelected] = useState(() => {
    const at = firstSelectableIndex(buildConnectRows({ states, stored: storedIds }));
    return at >= 0 ? at : 0;
  });

  const cursor = clampSelection(rows, selected);
  const activeRow = cursor >= 0 ? rows[cursor] : undefined;
  const activeProvider: ConnectProvider | undefined =
    activeRow?.kind === "provider" ? activeRow.provider : undefined;
  const detailRow =
    activeRow?.kind === "provider" && recovery?.providerId === activeRow.provider.id
      ? {
          ...activeRow,
          provider: {
            ...activeRow.provider,
            connected: false,
            source: undefined,
            via: undefined,
          },
        }
      : activeRow;
  const detailProvider: ConnectProvider | undefined =
    detailRow?.kind === "provider" ? detailRow.provider : undefined;

  const layout = computeConnectLayout({ width, height, noticeRows: 1 });
  const window = computeConnectWindow({ rows, selected: cursor, visible: layout.visibleRows, anchor });

  const inInput = inputProviderId !== undefined;
  const oauthVisible = oauth?.providerId === activeProvider?.id;
  const inOAuth = oauthVisible && oauth?.phase === "running";
  const mode: ConnectMode = inInput ? "input" : inOAuth ? "oauth" : filtering ? "filter" : "browse";

  // Keep the stored anchor in step with the window the list is actually
  // showing, so the list scrolls rather than jumps — but leave it frozen while
  // an authentication sub-step is active.
  useEffect(() => {
    if (!inInput && !inOAuth && window.start !== anchor) setAnchor(window.start);
  }, [inInput, inOAuth, window.start, anchor]);
  useEffect(() => {
    if (cursor >= 0 && cursor !== selected) setSelected(cursor);
  }, [cursor, selected]);
  useEffect(() => {
    const providerId = recovery?.providerId;
    if (!providerId || recoveredProviderRef.current === providerId) return;
    const recoveryIndex = rows.findIndex(
      (entry) => entry.kind === "provider" && entry.provider.id === providerId,
    );
    recoveredProviderRef.current = providerId;
    if (recoveryIndex >= 0) {
      setSelected(recoveryIndex);
      setAnchor(Math.max(0, recoveryIndex - 1));
    }
  }, [recovery?.providerId, rows]);

  useEffect(() => () => {
    oauthSessionRef.current?.cancel();
  }, []);

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

  const beginOauth = (provider: ConnectProvider) => {
    oauthSessionRef.current?.cancel();
    setInputProviderId(undefined);
    setInputValue("");
    setNotice(undefined);
    setOauth({
      providerId: provider.id,
      phase: "running",
      lines: [],
      message: "Starting ChatGPT Codex device sign-in…",
    });
    oauthSessionRef.current = startCodexDeviceAuth({
      homeDir,
      onUpdate: (update) => {
        setOauth({ ...update, providerId: provider.id });
        if (update.phase === "failed") setNotice(update.message);
      },
      onConnected: () => {
        oauthSessionRef.current = undefined;
        setAuthEpoch((current) => current + 1);
        setStored(loadCredentials(homeDir));
        setNotice(`connected ${provider.label} through device OAuth`);
        onConnected?.(provider.id);
      },
    });
  };

  const beginConnect = (provider: ConnectProvider) => {
    if (provider.auth === "oauth") {
      beginOauth(provider);
      return;
    }
    setOauth(undefined);
    setInputProviderId(provider.id);
    setInputValue("");
    setNotice(undefined);
  };

  const cancelInput = () => {
    setInputProviderId(undefined);
    setInputValue("");
  };

  const cancelOauth = () => {
    oauthSessionRef.current?.cancel();
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
    const reloaded = loadCredentials(homeDir);
    setStored(reloaded);
    const label = states.find((state) => state.id === id)?.label ?? id;
    setNotice(reloaded[id] ? `connected ${label}` : `${label} not stored`);
    onConnected?.(id);
  };

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";

    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }

    if (inOAuth) {
      if (key.name === "escape") cancelOauth();
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
    const recovering = recovery?.providerId === provider.id;
    const connected = provider.connected && !recovering;
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
          {connected ? "✓" : ""}
        </Cells>
        <Cells width={row.checkGap} bg={background}>
          {""}
        </Cells>
        <Cells
          width={row.labelWidth}
          fg={connected ? theme.SUCCESS : selectedRow ? theme.ACCENT : theme.MUTED}
          bg={background}
        >
          {provider.label}
        </Cells>
        <Cells width={row.authGap} bg={background}>
          {""}
        </Cells>
        <Cells width={row.authWidth} align="right" fg={recovering ? theme.ERROR : theme.MUTED} bg={background}>
          {recovering ? "reconnect" : connected ? "connected" : authHintLabel(provider.auth)}
        </Cells>
      </box>
    );
  });

  const rawDetailLines = connectDetailLines(
    { row: detailRow, compact: layout.detailCompact },
    layout.detail.innerWidth,
  );
  // A wide detail pane gets the selected provider in its title row. Remove that
  // repeated lead label (and its spacer) before spending the body-row budget;
  // stacked/narrow panes retain the original self-contained detail lines.
  let detailBodyStart = 0;
  if (layout.detail.hasTitle) {
    while (detailBodyStart < rawDetailLines.length) {
      const tone = rawDetailLines[detailBodyStart]?.tone;
      if (tone !== "title" && tone !== "blank") break;
      detailBodyStart += 1;
    }
  }
  const detailLines = detailBodyStart === 0
    ? rawDetailLines
    : rawDetailLines.slice(detailBodyStart);
  const detailBody = clipConnectDetailLines(
    detailLines,
    layout.detail.bodyRows,
    layout.detail.innerWidth,
  ).map((line, index) => (
    <Cells key={`detail-${index}`} width={layout.detail.innerWidth} fg={toneColor(theme, line.tone)}>
      {line.text}
    </Cells>
  ));
  const oauthTone = oauthVisible && oauth ? oauthStateTone(theme, oauth.phase) : theme.MUTED;
  const oauthContent = oauthVisible && oauth ? (
    <scrollbox
      width={layout.detail.innerWidth}
      height={Math.max(1, layout.detail.bodyRows)}
      flexShrink={0}
      minWidth={0}
      minHeight={0}
    >
      <DetailRail showRail={layout.bordered} tone={oauthTone}>
        <text fg={oauthTone} attributes={TextAttributes.BOLD} wrapMode="word">
          {oauthStateTitle(oauth.phase, !layout.detail.hasTitle)}
        </text>
        <text
          fg={oauth.phase === "failed" ? theme.TEXT : theme.MUTED}
          marginTop={1}
          wrapMode="word"
        >
          {oauth.message}
        </text>
        {oauth.lines.length > 0 ? (
          <box flexDirection="column" marginTop={1} minWidth={0}>
            <text fg={theme.MUTED}>CODEX</text>
            {oauth.lines.map((line, index) => (
              <text key={`oauth-${index}`} fg={theme.TEXT} wrapMode="word">{line}</text>
            ))}
          </box>
        ) : null}
        <text fg={theme.MUTED} marginTop={1} wrapMode="word">
          {oauthRecoveryHint(oauth.phase)}
        </text>
      </DetailRail>
    </scrollbox>
  ) : null;
  const codexRecovery = recovery?.providerId === "chatgpt-codex";
  const recoveryTitle = codexRecovery
    ? "ChatGPT Codex needs device sign-in"
    : recovery?.title;
  const recoveryDetail = codexRecovery
    ? "The previous ChatGPT Codex subscription credential is no longer valid. Start device OAuth to refresh it; do not enter an OpenAI API key here."
    : recovery?.detail;
  const detailContent = oauthContent ?? (recovery ? (
    <scrollbox
      width={layout.detail.innerWidth}
      height={Math.max(1, layout.detail.bodyRows)}
      flexShrink={0}
      minWidth={0}
      minHeight={0}
    >
      <DetailRail showRail={layout.bordered} tone={theme.ERROR}>
        <text fg={theme.ERROR} attributes={TextAttributes.BOLD} wrapMode="word">{recoveryTitle}</text>
        <text fg={theme.TEXT} marginTop={1} wrapMode="word">{recoveryDetail}</text>
        <text fg={theme.ACCENT} marginTop={1} wrapMode="word">
          Press Enter to start {codexRecovery ? "ChatGPT Codex device OAuth" : `reconnect ${activeProvider?.label ?? "the selected provider"}`}. Esc returns to chat.
        </text>
        {detailBody.length > 0 ? (
          <box flexDirection="column" marginTop={1} minWidth={0}>{detailBody}</box>
        ) : null}
      </DetailRail>
    </scrollbox>
  ) : detailBody);
  const detailContextMeta = oauthVisible && oauth
    ? oauthStateMeta(oauth.phase)
    : recovery?.providerId === detailProvider?.id
      ? "reconnect"
      : connectDetailTitleMeta(detailRow);
  const detailContextMetaFg = oauthVisible && oauth
    ? oauthTone
    : recovery?.providerId === detailProvider?.id
      ? theme.ERROR
      : detailProvider?.connected ? theme.SUCCESS : theme.MUTED;

  const statusText = oauthVisible && oauth
    ? oauth.message
    : recovery
      ? recoveryTitle ?? "provider needs to reconnect"
      : inInput
        ? `paste API key for ${activeProvider?.label ?? inputProviderId}: ${connectInputMask(inputValue.length)}`
        : filtering
          ? `filter: ${filter}_`
          : notice
            ? notice
            : filter
              ? `filter: ${filter} · ${connectStatusLine(rows)}`
              : connectStatusLine(rows);
  const statusFg = oauthVisible && oauth
    ? oauth.phase === "failed" ? theme.ERROR : oauth.phase === "connected" ? theme.SUCCESS : theme.ACCENT
    : recovery ? theme.ERROR : inInput ? theme.ACCENT : notice ? theme.SUCCESS : theme.MUTED;

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <box
        flexDirection={layout.stacked ? "column" : "row"}
        gap={layout.paneGap}
        flexShrink={0}
        minWidth={0}
      >
        <RailPane
          pane={layout.list}
          railTone={layout.bordered ? theme.ACCENT : undefined}
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
        </RailPane>
        <RailPane
          pane={layout.detail}
          title={
            <TitleRow
              innerWidth={layout.detail.innerWidth}
              title={detailProvider?.label ?? connectDetailTitleLabel()}
              meta={detailContextMeta}
              metaFg={detailContextMetaFg}
            />
          }
        >
          {detailContent}
        </RailPane>
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
