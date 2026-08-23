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
import { TextAttributes } from "@opentui/core";
import { eventBus, peekInbox, sendOperatorMessage, type MessagingRuntime } from "@0sec/core";

import { useTheme, type Theme } from "./theme-context.js";
import { Cells } from "./primitives.js";
import {
  HERD_COMPOSER_CURSOR,
  HERD_COMPOSER_PROMPT,
  HERD_EMPTY_TEXT,
  HERD_FOCUS_EMPTY_TEXT,
  applySubagentLifecycle,
  applySubagentProgress,
  buildHerdRows,
  clampHerdSelection,
  clipDetailLines,
  computeHerdFocusLayout,
  computeHerdLayout,
  computeHerdWindow,
  focusHeaderLines,
  herdComposerFooterHint,
  herdComposerVisibleDraft,
  herdDetailLines,
  herdFocusFooterHint,
  herdFocusTranscriptTitle,
  herdFooterHint,
  herdListHeading,
  herdRowLabelText,
  paneTitleColumns,
  herdRowStatusText,
  herdStatusLabel,
  mergeSubagentRoster,
  moveHerdSelection,
  renderFocusActivity,
  subagentPeers,
  subagentStatusLabel,
  windowFocusTail,
  type HerdDetailTone,
  type HerdInboxMessage,
  type HerdPane,
  type HerdPeer,
  type HerdSubagentMap,
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
  /**
   * The OPERATOR's own peer id — the `from` on a steering message. Without it
   * the console cannot name itself, so the compose affordance still opens but a
   * send fails cleanly ("operator identity not wired"). Supplied once the
   * roster producer lands; left unset today, consistent with the empty roster.
   */
  selfId?: string;
  /**
   * The operator↔child channel toggle, mirrored onto the steering runtime.
   * Defaults to `true` — steering a running subagent is on by default, and the
   * pure {@link import("@0sec/core").decideAddressing} still re-checks it.
   */
  operatorChannelEnabled?: boolean;
  /**
   * Sends a steering message to `to`, returning the delivery outcome. Injected
   * for tests; the default authorizes with `decideAddressing` and delivers via
   * the hub mailbox (`sendOperatorMessage`) using an `operator` runtime built
   * from {@link selfId}, the live roster, and the project/home paths.
   */
  sendSteer?: (input: { to: string; body: string }) => {
    ok: boolean;
    reason?: string;
    truncated?: boolean;
  };
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
  meta,
  children,
}: {
  pane: HerdPane;
  bordered: boolean;
  title: string;
  /** Right-aligned muted summary on the title row (count/window). */
  meta?: string;
  children: React.ReactNode;
}) {
  const theme = useTheme();
  if (pane.width <= 0 || pane.height <= 0) return null;
  // Title row: bold primary title left, right-aligned muted meta — the OMP
  // header the console reuses. The columns sum to the inner width so the two
  // can never fuse under pressure.
  const cols = paneTitleColumns(pane.innerWidth, (meta ?? "").length);
  const titleRow = pane.hasTitle ? (
    <box flexDirection="row" width={pane.innerWidth} flexShrink={0} minWidth={0}>
      <Cells width={cols.titleWidth} fg={theme.PRIMARY} attributes={TextAttributes.BOLD}>
        {title}
      </Cells>
      <Cells width={cols.gap}>{""}</Cells>
      <Cells width={cols.metaWidth} align="right" fg={theme.MUTED}>
        {meta ?? ""}
      </Cells>
    </box>
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
  selfId,
  operatorChannelEnabled,
  sendSteer,
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

  // Live subagents seen on this process's event bus. Keyed by `agent_id`, the
  // same id a roster subagent peer carries, so the two join. Built additively
  // from `subagent_lifecycle` / `subagent_progress` — the herd screen carries
  // only a snapshot roster otherwise, so this is the live half the focus view
  // renders. Fail-soft: a malformed payload folds to the same map (no repaint).
  const [subagents, setSubagents] = useState<HerdSubagentMap>({});

  // Focus mode: the id of the subagent the operator drilled into, or null in
  // list mode. `scrollOffset` scrolls the live transcript back from its tail.
  const [focusId, setFocusId] = useState<string | null>(null);
  const [scrollOffset, setScrollOffset] = useState(0);

  // Steering composer. `composing`/`draft` are mirrored onto refs so the
  // keyboard handler reads the latest value synchronously between keystrokes
  // (the chat composer relies on the same pattern). `notice` is the one-row
  // delivery confirmation or error shown after a send.
  const [composing, setComposing] = useState(false);
  const composingRef = useRef(false);
  const [draft, setDraft] = useState("");
  const draftRef = useRef("");
  const [notice, setNotice] = useState<{ text: string; tone: "ok" | "error" } | null>(null);

  const setComposingBoth = (value: boolean) => {
    composingRef.current = value;
    setComposing(value);
  };
  const setDraftBoth = (value: string) => {
    draftRef.current = value;
    setDraft(value);
  };

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

  // Subscribe to the core event bus for per-subagent activity, additively. The
  // reducers are pure; the subscription is unsubscribed on unmount. Unlike the
  // chat screen this view is NOT scoped to one session's scanId — the herd is
  // the cross-cutting roster, so every subagent emitting on this process's bus
  // is surfaced. (The bus is process-local: a subagent in another process is
  // out of reach until the roster transport lands — see the report.)
  useEffect(() => {
    const unsub = eventBus.subscribe({
      emit: (type, payload) => {
        const at = clock();
        if (type === "subagent_lifecycle") {
          setSubagents((prev) => applySubagentLifecycle(prev, payload, at));
        } else if (type === "subagent_progress") {
          setSubagents((prev) => applySubagentProgress(prev, payload, at));
        }
      },
    });
    return unsub;
  }, [clock]);

  // The roster the list renders is the injected provider's peers merged with
  // the live subagents (provider wins on an id collision). These are real
  // agents emitting real events, not fabricated placeholders.
  const livePeers = useMemo(() => subagentPeers(subagents, now), [subagents, now]);
  const mergedPeers = useMemo(
    () => mergeSubagentRoster(peers, livePeers),
    [peers, livePeers],
  );

  const rows = useMemo(() => buildHerdRows(mergedPeers, now), [mergedPeers, now]);
  const cursor = clampHerdSelection(rows, selected);
  const activeRow = cursor >= 0 ? rows[cursor] : undefined;
  const activePeer = activeRow?.kind === "peer" ? activeRow.peer : undefined;

  // Focus mode: the peer being drilled into and its live record. The peer is
  // looked up in the merged roster so a focused subagent survives list
  // reshuffles; `focused` gates the whole alternate view and its keymap. A
  // focused peer that leaves the roster (a session that vanished) drops focus.
  const focusedPeer = focusId ? mergedPeers.find((peer) => peer.id === focusId) : undefined;
  const focusRecord = focusId ? subagents[focusId] : undefined;
  const focused = focusId != null && focusedPeer != null;

  // Whichever peer a steering message is addressed to: the focused agent while
  // drilled in, otherwise the highlighted list row.
  const steerTarget = focused ? focusedPeer : activePeer;

  useEffect(() => {
    if (focusId != null && !focusedPeer) {
      setFocusId(null);
      setScrollOffset(0);
    }
  }, [focusId, focusedPeer]);

  // A composer or a delivery notice claims one row above the footer; reserve it
  // through the layout's own `noticeRows` budget so the panes shrink by exactly
  // that row and nothing overlaps.
  const overlayRow = composing || notice !== null;
  const layout = computeHerdLayout({ width, height, noticeRows: overlayRow ? 1 : 0 });
  const focusLayout = computeHerdFocusLayout({ width, height, noticeRows: overlayRow ? 1 : 0 });
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
    setNotice(null);
    const next = moveHerdSelection(rows, cursor, delta);
    if (next >= 0) setSelected(next);
  };

  /**
   * Authorize and deliver a steering message to `to`. Uses the injected
   * `sendSteer` when present (tests); otherwise builds an `operator` messaging
   * runtime — pinned to the live roster so a dead id is refused — and hands it
   * to `sendOperatorMessage`, which re-runs `decideAddressing` before it spools.
   */
  const deliver = (to: string, body: string): { ok: boolean; reason?: string; truncated?: boolean } => {
    if (sendSteer) return sendSteer({ to, body });
    if (!selfId) return { ok: false, reason: "operator identity not wired" };
    const runtime: MessagingRuntime = {
      selfId,
      selfRole: "operator",
      siblingChannelEnabled: false,
      operatorChannelEnabled: operatorChannelEnabled ?? true,
      projectPath: cwd,
      homeDir: home,
      knownPeerIds: mergedPeers.map((peer) => peer.id),
    };
    const result = sendOperatorMessage(runtime, to, body, clock());
    return { ok: result.ok, reason: result.reason, truncated: result.truncated };
  };

  useKeyboard((key) => {
    // Ctrl+C always exits — a modal composer must never trap the operator.
    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }

    // ── Compose mode: the composer is modal, owning typing, Enter and Esc ──
    if (composingRef.current) {
      if (key.name === "escape") {
        setComposingBoth(false);
        setDraftBoth("");
        return;
      }
      if (key.name === "return") {
        const body = draftRef.current.trim();
        setComposingBoth(false);
        setDraftBoth("");
        if (body.length === 0) return; // empty draft: just close, deliver nothing
        if (!steerTarget) {
          setNotice({ text: "no agent selected", tone: "error" });
          return;
        }
        const result = deliver(steerTarget.id, body);
        setNotice(
          result.ok
            ? {
                text: `sent to ${steerTarget.id}${result.truncated ? " (truncated)" : ""}`,
                tone: "ok",
              }
            : { text: result.reason ?? "message could not be delivered", tone: "error" },
        );
        return;
      }
      if (key.name === "backspace") {
        setDraftBoth(draftRef.current.slice(0, -1));
        return;
      }
      if (
        typeof key.sequence === "string" &&
        key.sequence.length === 1 &&
        !key.ctrl &&
        !key.meta &&
        key.sequence.charCodeAt(0) >= 32
      ) {
        setDraftBoth(`${draftRef.current}${key.sequence}`);
      }
      return;
    }

    // ── Focus mode: one subagent, its live transcript, a steer composer ──
    // Esc returns to the LIST (it does not leave the herd screen); up/down
    // scroll the transcript back from its tail; `m`/Enter open the steer
    // composer bound to the focused agent.
    if (focused) {
      if (key.name === "escape") {
        setFocusId(null);
        setScrollOffset(0);
        setNotice(null);
        return;
      }
      if (key.name === "up") {
        setScrollOffset((offset) => offset + 1);
        return;
      }
      if (key.name === "down") {
        setScrollOffset((offset) => Math.max(0, offset - 1));
        return;
      }
      if (key.name === "pageup") {
        setScrollOffset((offset) => offset + PAGE_STEP);
        return;
      }
      if (key.name === "pagedown") {
        setScrollOffset((offset) => Math.max(0, offset - PAGE_STEP));
        return;
      }
      if (
        key.name === "return" ||
        (!key.ctrl && !key.meta && (key.sequence === "m" || key.sequence === "M"))
      ) {
        setNotice(null);
        setDraftBoth("");
        setComposingBoth(true);
        return;
      }
      return;
    }

    // ── Navigation mode ──
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
    // Enter drills into the highlighted peer — focus mode. A no-op with nothing
    // highlighted, so it can never enter focus with no subject.
    if (key.name === "return") {
      if (activePeer) {
        setNotice(null);
        setScrollOffset(0);
        setFocusId(activePeer.id);
      }
      return;
    }
    // `m` opens the steering composer bound to the highlighted peer. A no-op
    // when the roster is empty, so it can never open a composer with no target.
    if (!key.ctrl && !key.meta && (key.sequence === "m" || key.sequence === "M")) {
      if (activePeer) {
        setNotice(null);
        setDraftBoth("");
        setComposingBoth(true);
      }
      return;
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
          // Status group header: a small status-coloured, bold label left with
          // the group count right-aligned in muted — a section header, not a
          // wall of text. The columns sum to the row width.
          const count = String(entry.count);
          const cols = paneTitleColumns(row.width, count.length);
          return (
            <box
              key={`heading-${entry.status}`}
              flexDirection="row"
              width={row.width}
              flexShrink={0}
              minWidth={0}
            >
              <Cells
                width={cols.titleWidth}
                fg={statusColor(theme, entry.status)}
                attributes={TextAttributes.BOLD}
              >
                {herdStatusLabel(entry.status)}
              </Cells>
              <Cells width={cols.gap}>{""}</Cells>
              <Cells width={cols.metaWidth} align="right" fg={theme.MUTED}>
                {count}
              </Cells>
            </box>
          );
        }

        const active = index === cursor;
        const background = active ? theme.PANEL_ALT : undefined;
        // The marker column doubles as a selection caret and a live-status dot,
        // exactly like the shared agent row: a selected row shows an accent "▸",
        // otherwise a status-coloured "●". The highlighted row's label is accent
        // + bold; other rows are muted.
        const markerGlyph = active ? "▸" : "●";
        const markerFg = active ? theme.ACCENT : statusColor(theme, entry.status);
        return (
          <box
            key={`peer-${entry.peer.id}`}
            flexDirection="row"
            width={row.width}
            flexShrink={0}
            minWidth={0}
            onMouseDown={() => setSelected(index)}
          >
            <Cells width={row.markerWidth} fg={markerFg} bg={background}>
              {row.markerWidth > 0 ? markerGlyph : ""}
            </Cells>
            <Cells width={row.markerGap} bg={background}>
              {""}
            </Cells>
            <Cells
              width={row.labelWidth}
              fg={active ? theme.ACCENT : theme.TEXT}
              bg={background}
              attributes={active ? TextAttributes.BOLD : undefined}
            >
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

  // The single reserved overlay row: the composer while composing, otherwise the
  // most recent delivery notice. Both are budgeted to `contentWidth` by `Cells`,
  // so neither can overrun the row `noticeRows` reserved for it.
  const overlayBody = composing ? (
    <box flexDirection="row" width={layout.contentWidth} flexShrink={0} minWidth={0}>
      <Cells width={layout.contentWidth} fg={theme.TEXT}>
        {`${HERD_COMPOSER_PROMPT}${herdComposerVisibleDraft(draft, layout.contentWidth)}${HERD_COMPOSER_CURSOR}`}
      </Cells>
    </box>
  ) : notice ? (
    <box flexDirection="row" width={layout.contentWidth} flexShrink={0} minWidth={0}>
      <Cells width={layout.contentWidth} fg={notice.tone === "ok" ? theme.SUCCESS : theme.ERROR}>
        {notice.text}
      </Cells>
    </box>
  ) : null;

  const listView = (
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
          title={herdListHeading(window).title}
          meta={herdListHeading(window).meta}
        >
          {listBody}
        </Pane>
        <Pane
          pane={layout.detail}
          bordered={layout.bordered}
          title="DETAIL"
          meta={activeRow?.kind === "peer" ? herdStatusLabel(activeRow.status) : "—"}
        >
          {detailBody}
        </Pane>
      </box>
      {overlayBody}
    </box>
  );

  // ── Focus view: one subagent's meta stacked over its live transcript ──
  // Every number comes off `focusLayout`; the two panes are the full content
  // width (a single column) so they can only fail vertically, which the
  // allocator has already fitted. The transcript renders a tail window over
  // the agent's activity ring, scrolled back by `scrollOffset`.
  const focusMetaLines = focused
    ? clipDetailLines(
        focusHeaderLines(focusedPeer, focusRecord, focusLayout.meta.innerWidth, now, {
          compact: !focusLayout.bordered,
        }),
        focusLayout.meta.bodyRows,
        focusLayout.meta.innerWidth,
      )
    : [];
  const focusActivityLines =
    focused && focusRecord
      ? renderFocusActivity(focusRecord.activity, focusLayout.transcript.innerWidth)
      : [];
  const focusTail = windowFocusTail(
    focusActivityLines.length,
    focusLayout.transcript.bodyRows,
    scrollOffset,
  );
  const focusVisibleActivity = focusActivityLines.slice(focusTail.start, focusTail.end);

  const focusView = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0}>
      <box flexDirection="column" flexShrink={0} minWidth={0}>
        <Pane
          pane={focusLayout.meta}
          bordered={focusLayout.bordered}
          title="FOCUS"
          meta={focusRecord ? subagentStatusLabel(focusRecord.status) : undefined}
        >
          {focusMetaLines.map((line, index) => (
            <Cells
              key={`meta-${index}`}
              width={focusLayout.meta.innerWidth}
              fg={toneColor(theme, line.tone)}
            >
              {line.text}
            </Cells>
          ))}
        </Pane>
        <Pane
          pane={focusLayout.transcript}
          bordered={focusLayout.bordered}
          title={herdFocusTranscriptTitle(focusActivityLines.length)}
        >
          {focusVisibleActivity.length === 0 ? (
            <Cells width={focusLayout.transcript.innerWidth} fg={theme.MUTED}>
              {HERD_FOCUS_EMPTY_TEXT}
            </Cells>
          ) : (
            focusVisibleActivity.map((line, index) => (
              <Cells
                key={`live-${focusTail.start + index}`}
                width={focusLayout.transcript.innerWidth}
                fg={toneColor(theme, line.tone)}
              >
                {line.text}
              </Cells>
            ))
          )}
        </Pane>
      </box>
      {overlayBody}
    </box>
  );

  const body = focused ? focusView : listView;

  // While composing, the footer names the bound steer target; in focus mode the
  // focus keymap; otherwise the list navigation hint.
  const hint = composing
    ? `to ${steerTarget?.id ?? "?"} · ${herdComposerFooterHint()}`
    : focused
      ? herdFocusFooterHint()
      : herdFooterHint();

  return <>{frame({ body, hint })}</>;
}
