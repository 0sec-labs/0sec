/** @jsxImportSource @opentui/react */
/**
 * The agent-herd overview surface.
 *
 * A roster of every 0sec peer — sessions and subagents — working this project
 * directory, grouped by live status, with a detail pane for the selected peer
 * and its recent inbox activity. Modelled on the settings screen: a grouped
 * list on the left, a detail pane on the right, stacked when the terminal is
 * too narrow to hold both.
 *
 * Two properties are load-bearing, both inherited from `settings-screen.tsx`:
 *
 * 1. **This component does no arithmetic.** Every width, height, row count and
 *    window boundary comes off `herd-layout.ts`, swept across widths 0..200 and
 *    heights 0..80 by a test, because Yoga shrinks siblings rather than clipping
 *    them (see `PRIMITIVES.md`).
 *
 * 2. **It never fabricates a herd.** The hub roster has no producer wired yet
 *    (see `herd-layout.ts` and `packages/core/src/hub/registry.ts`), so the
 *    roster is empty by default and this screen says so — "no other agents in
 *    this project" — rather than rendering placeholder agents. It reads its
 *    roster from an INJECTED provider (`readRoster`), defaulting to one that
 *    returns nothing; the day a producer persists the roster, the provider is
 *    swapped for a real reader and this screen lights up unchanged.
 *
 * The roster is a *view*, so it refreshes on a timer. The interval is cleared
 * on unmount, and a cheap signature guard skips the state update (and therefore
 * the repaint) when nothing observable changed between two polls.
 */

import React, { useEffect, useMemo, useRef, useState } from "react";
import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { peekInbox } from "@0sec/core";

import { useTheme, type Theme } from "./theme-context.js";
import { Cells } from "./primitives.js";
import {
  HERD_EMPTY_TEXT,
  buildHerdRows,
  clampHerdSelection,
  clipDetailLines,
  computeHerdLayout,
  computeHerdWindow,
  herdDetailLines,
  herdFooterHint,
  herdListTitle,
  herdRowLabelText,
  herdRowStatusText,
  herdStatusLabel,
  moveHerdSelection,
  type HerdDetailTone,
  type HerdInboxMessage,
  type HerdPane,
  type HerdPeer,
} from "./herd-layout.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;
/** How often the roster view refreshes, in ms. */
const REFRESH_MS = 1500;

export interface HerdFrameInput {
  body: React.ReactNode;
  hint: string;
}

export interface HerdScreenProps {
  /**
   * Wraps the body in the console shell. Injected rather than imported so this
   * module does not depend on `run.tsx` — which owns `ShellFrame` and pulls in
   * every other screen with it.
   */
  frame: (input: HerdFrameInput) => React.ReactNode;
  /** Leave the screen — Esc. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
  /**
   * Reads the current peer roster as of `now`. Defaults to an empty roster,
   * because the hub has no producer wired yet — the screen must not invent one.
   * A real reader is injected once the roster transport lands.
   */
  readRoster?: (now: number) => HerdPeer[];
  /**
   * Reads (peeks, never drains) a peer's inbox. Defaults to the hub mailbox's
   * `peekInbox` against `projectPath`. Peeking leaves the mail in place so a
   * concurrent drain by the real reader is not starved.
   */
  peekInboxFor?: (peerId: string) => HerdInboxMessage[];
  /** Project directory the hub is keyed by. Defaults to `process.cwd()`. */
  projectPath?: string;
  /** Home dir for `~` path abbreviation. Defaults to `$HOME`. */
  homeDir?: string;
  /** Injected clock, tests only. Defaults to `Date.now`. */
  now?: () => number;
}

function toneColor(theme: Theme, tone: HerdDetailTone): string | undefined {
  switch (tone) {
    case "title":
      return theme.PRIMARY;
    case "accent":
      return theme.ACCENT;
    case "warn":
      return theme.WARNING;
    case "muted":
    case "blank":
      return theme.MUTED;
    default:
      return theme.TEXT;
  }
}

/** The colour a status heading and its rows render in. */
function statusColor(theme: Theme, status: string): string {
  switch (status) {
    case "working":
      return theme.ACCENT;
    case "blocked":
    case "stale":
      return theme.WARNING;
    default:
      return theme.MUTED;
  }
}

/**
 * A pane that states its own height. `height` includes the borders and
 * `flexShrink={0}` stops the column squeezing the box behind its content's
 * back. A pane the layout could not find room for reports zero and renders
 * nothing at all — the correct degradation.
 */
function Pane({
  pane,
  bordered,
  title,
  titleFg,
  children,
}: {
  pane: HerdPane;
  bordered: boolean;
  title: string;
  titleFg: string;
  children: React.ReactNode;
}) {
  const theme = useTheme();
  if (pane.width <= 0 || pane.height <= 0) return null;
  const titleRow = pane.hasTitle ? (
    <Cells width={pane.innerWidth} fg={titleFg}>
      {title}
    </Cells>
  ) : null;
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

/** A single value that changes exactly when the rendered roster does. */
function rosterSignature(peers: readonly HerdPeer[], now: number): string {
  // Bucket `now` to the refresh cadence so relative-age labels still tick
  // without a repaint every millisecond.
  const bucket = Math.floor(now / REFRESH_MS);
  const parts = peers.map((p) => {
    const a = p.activity;
    return `${p.id}|${p.kind}|${p.pid}|${p.lastSeen}|${p.label ?? ""}|${a?.phase ?? ""}|${a?.turn ?? ""}|${a?.tool ?? ""}|${a?.note ?? ""}`;
  });
  return `${bucket}#${parts.join("~")}`;
}

export function HerdScreen({
  frame,
  onBack,
  onExit,
  readRoster,
  peekInboxFor,
  projectPath,
  homeDir,
  now: nowFn,
}: HerdScreenProps) {
  const theme = useTheme();
  const { width, height } = useTerminalDimensions();
  const clock = nowFn ?? Date.now;
  const cwd = projectPath ?? process.cwd();
  const home = homeDir ?? process.env["HOME"] ?? undefined;

  // The roster provider defaults to empty: the hub has no producer, so there is
  // genuinely nothing to read, and the screen must show that honestly.
  const readRosterRef = useRef(readRoster);
  readRosterRef.current = readRoster;
  const peekRef = useRef(peekInboxFor);
  peekRef.current = peekInboxFor;

  const peekOne = React.useCallback(
    (peerId: string): HerdInboxMessage[] => {
      if (peekRef.current) return peekRef.current(peerId);
      try {
        return peekInbox(cwd, peerId, home).map((m) => ({ from: m.from, body: m.body, ts: m.ts }));
      } catch {
        return [];
      }
    },
    [cwd, home],
  );

  const [tick, setTick] = useState(0);
  const [now, setNow] = useState(() => clock());
  const [peers, setPeers] = useState<HerdPeer[]>(() => readRoster?.(clock()) ?? []);
  const [selected, setSelected] = useState(0);
  const [anchor, setAnchor] = useState(0);

  const signatureRef = useRef<string>("");

  // Poll the roster on a timer, repainting only when the signature changes.
  useEffect(() => {
    const poll = () => {
      const at = clock();
      const next = readRosterRef.current?.(at) ?? [];
      const signature = rosterSignature(next, at);
      if (signature !== signatureRef.current) {
        signatureRef.current = signature;
        setPeers(next);
        setNow(at);
        setTick((t) => t + 1);
      }
    };
    poll();
    const handle = setInterval(poll, REFRESH_MS);
    return () => clearInterval(handle);
    // `clock` is stable (Date.now or an injected function); the refs carry the
    // latest providers so the interval never needs re-creating.
  }, [clock]);

  const rows = useMemo(() => buildHerdRows(peers, now), [peers, now]);
  const cursor = clampHerdSelection(rows, selected);
  const activeRow = cursor >= 0 ? rows[cursor] : undefined;
  const activePeer = activeRow?.kind === "peer" ? activeRow.peer : undefined;

  const layout = computeHerdLayout({ width, height });
  const window = computeHerdWindow({
    rows,
    selected: cursor,
    visible: layout.visibleRows,
    anchor,
  });

  useEffect(() => {
    if (window.start !== anchor) setAnchor(window.start);
  }, [window.start, anchor]);
  useEffect(() => {
    if (cursor >= 0 && cursor !== selected) setSelected(cursor);
  }, [cursor, selected]);

  // Peek the selected peer's inbox. Re-peeked when the selection or the poll
  // tick changes; never drained, so a real reader's mail is left intact.
  const inbox = useMemo<HerdInboxMessage[]>(() => {
    if (!activePeer) return [];
    return peekOne(activePeer.id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activePeer?.id, peekOne, tick]);

  const move = (delta: number) => {
    const next = moveHerdSelection(rows, cursor, delta);
    if (next >= 0) setSelected(next);
  };

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";
    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }
    if (key.name === "escape") {
      onBack();
      return;
    }
    if (key.name === "up") {
      move(-1);
      return;
    }
    if (key.name === "down") {
      move(1);
      return;
    }
    if (key.name === "pageup") {
      move(-PAGE_STEP);
      return;
    }
    if (key.name === "pagedown") {
      move(PAGE_STEP);
      return;
    }
    // Enter focuses the selected peer; with a single detail pane that is the
    // current selection already, so it is a no-op that still consumes the key
    // rather than letting it fall through. `seq` guards against a stray return.
    if (key.name === "return" && seq !== "") {
      /* selection is the focus; nothing further to do */
    }
  });

  const row = layout.row;
  const visible = rows.slice(window.start, window.end);

  const listBody =
    rows.length === 0 ? (
      <Cells width={row.width || layout.list.innerWidth} fg={theme.MUTED}>
        {HERD_EMPTY_TEXT}
      </Cells>
    ) : (
      visible.map((entry, offset) => {
        const index = window.start + offset;
        if (entry.kind === "heading") {
          return (
            <box
              key={`heading-${entry.status}`}
              flexDirection="row"
              width={row.width}
              flexShrink={0}
              minWidth={0}
            >
              <Cells width={row.width} fg={statusColor(theme, entry.status)}>
                {`${herdStatusLabel(entry.status)} ${entry.count}`}
              </Cells>
            </box>
          );
        }

        const active = index === cursor;
        const background = active ? theme.PANEL_ALT : undefined;
        return (
          <box
            key={`peer-${entry.peer.id}`}
            flexDirection="row"
            width={row.width}
            flexShrink={0}
            minWidth={0}
            onMouseDown={() => setSelected(index)}
          >
            <Cells width={row.markerWidth} fg={theme.PRIMARY} bg={background}>
              {active ? ">" : ""}
            </Cells>
            <Cells width={row.markerGap} bg={background}>
              {""}
            </Cells>
            <Cells width={row.labelWidth} fg={active ? theme.TEXT : theme.MUTED} bg={background}>
              {herdRowLabelText(entry.peer)}
            </Cells>
            <Cells width={row.statusGap} bg={background}>
              {""}
            </Cells>
            <Cells
              width={row.statusWidth}
              align="right"
              fg={statusColor(theme, entry.status)}
              bg={background}
            >
              {herdRowStatusText(entry.peer, entry.status)}
            </Cells>
          </box>
        );
      })
    );

  const detailBody = activePeer
    ? clipDetailLines(
        herdDetailLines(activePeer, inbox, layout.detail.innerWidth, now, {
          compact: layout.detailCompact,
          homeDir: home,
        }),
        layout.detail.bodyRows,
        layout.detail.innerWidth,
      ).map((line, index) => (
        <Cells key={`detail-${index}`} width={layout.detail.innerWidth} fg={toneColor(theme, line.tone)}>
          {line.text}
        </Cells>
      ))
    : (
        <Cells width={layout.detail.innerWidth} fg={theme.MUTED}>
          {rows.length === 0 ? "waiting for the roster" : "select a peer"}
        </Cells>
      );

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <box
        flexDirection={layout.stacked ? "column" : "row"}
        gap={layout.paneGap}
        flexShrink={0}
        minWidth={0}
      >
        <Pane pane={layout.list} bordered={layout.bordered} title={herdListTitle(window)} titleFg={theme.MUTED}>
          {listBody}
        </Pane>
        <Pane
          pane={layout.detail}
          bordered={layout.bordered}
          title={activePeer ? "DETAIL" : "DETAIL -"}
          titleFg={theme.MUTED}
        >
          {detailBody}
        </Pane>
      </box>
    </box>
  );

  return <>{frame({ body, hint: herdFooterHint() })}</>;
}
