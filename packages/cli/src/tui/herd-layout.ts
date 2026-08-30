/**
 * Layout, grouping, navigation and windowing arithmetic for the agent-herd
 * overview screen.
 *
 * This is `herd-screen.tsx`'s pure half, following the precedent
 * `settings-layout.ts` set: every number the screen renders with is computed
 * here, where a property sweep can hammer it across widths 0..200 and heights
 * 0..80. The reason is spelled out in `PRIMITIVES.md` and `settings-layout.ts`
 * — OpenTUI lays rows out with Yoga, and Yoga *shrinks* siblings rather than
 * clipping them, so a row that claims one cell too many paints two strings on
 * top of each other and a bordered box one row short of its content paints its
 * own border through that content. Both are invisible until someone resizes a
 * terminal, which is why the arithmetic lives somewhere a sweep can reach.
 *
 * ## What this screen is a view over
 *
 * The hub peer roster (`packages/core/src/hub/registry.ts`): the set of 0sec
 * peers — sessions and subagents — working the same project directory. That
 * module is a PURE data model; the filesystem/socket transport that persists
 * and gossips the roster is a later increment and **is not wired yet**. There
 * is therefore no way to read a live roster today, and this screen degrades
 * honestly to an empty state rather than fabricating agents. The screen takes
 * its roster from an injected provider (see `herd-screen.tsx`), so the day the
 * producer lands it plugs straight in.
 *
 * ## Reuse note (registry symbols are not exported)
 *
 * `registry.ts`'s `PeerRecord` / `statusOf` / `DEFAULT_PEER_TTL_MS` are NOT
 * re-exported from `@0sec/core` (only the mailbox's `peekInbox` / `hubDir` are),
 * and this package may not edit core to add the export. So the peer SHAPE and
 * the TTL/status derivation are mirrored here: {@link HerdPeer} is structurally
 * a `PeerRecord` (a real record assigns to it with no cast), {@link isPeerStale}
 * reproduces `registry.isStale` byte-for-byte — same default TTL, same
 * INCLUSIVE-ALIVE boundary (stale only once strictly older than the TTL) — and
 * a unit test pins that boundary. When core grows a public export, this mirror
 * should be replaced by the import.
 */

import { borderChrome, computeListWindow, computePaneSplit, makePane } from "./pane-layout.js";
import { fitTuiText, sanitizeTuiText, wrapText } from "./text.js";

// ---------------------------------------------------------------------------
// Untrusted text
// ---------------------------------------------------------------------------

/**
 * Zero-width and bidi formatting characters — the "trojan source" spoofing
 * range. `sanitizeTuiText` strips ANSI, C0/C1 and DEL but NOT these, whereas
 * the mailbox's `stripUnsafeText` does. Peer `label` / `cwd` reach this screen
 * from a roster provider that may not have sanitized them (the registry only
 * sanitizes `id`, and only to `[A-Za-z0-9._-]`), so this screen closes the gap
 * itself before any peer-authored string reaches the frame.
 */
const RE_INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g;

/**
 * Sanitize an untrusted, peer-authored display string: everything
 * `sanitizeTuiText` removes, plus the bidi/zero-width range above. Every value
 * that may have come from another process passes through here.
 */
export function sanitizeHerdText(value: unknown): string {
  return sanitizeTuiText(value).replace(RE_INVISIBLE, "");
}

// ---------------------------------------------------------------------------
// Numeric hygiene (mirrors settings-layout.ts / primitives.ts)
// ---------------------------------------------------------------------------

/**
 * Cell and row counts are non-negative integers. Terminal geometry arrives
 * from `useTerminalDimensions`, which reports 0 on a detached tty and can
 * report a fractional or `NaN` size mid-resize; Yoga accepts all of those and
 * lays out sub-cell boxes that round inconsistently between siblings, which is
 * itself an overlap. Everything entering the allocator is normalised here.
 */
function cells(value: unknown, fallback = 0): number {
  const raw = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  const truncated = Math.trunc(raw);
  return truncated > 0 ? truncated : 0;
}

function clamp(value: number, low: number, high: number): number {
  if (high < low) return low;
  return Math.min(Math.max(value, low), high);
}

// ---------------------------------------------------------------------------
// Peer model — a structural mirror of registry.PeerRecord
// ---------------------------------------------------------------------------

/** What a roster entry represents. Mirrors `registry.PeerKind`. */
export type HerdPeerKind = "session" | "subagent";

/**
 * The status buckets the herd groups by, in the fixed order they render.
 *
 * `stale` is the only one {@link isPeerStale} decides on its own; the other
 * four are live-activity phases carried on {@link HerdActivity}. An active peer
 * with no live signal is `idle` — the honest default, since a bare roster entry
 * tells us the peer is alive but not what it is doing.
 */
export type HerdStatus = "working" | "idle" | "blocked" | "done" | "stale";

/** The four phases a NON-stale peer can be in. */
export type HerdPhase = Exclude<HerdStatus, "stale">;

/** Stable group order. Empty groups are omitted from the row model. */
export const HERD_STATUS_ORDER: readonly HerdStatus[] = [
  "working",
  "idle",
  "blocked",
  "done",
  "stale",
];

/**
 * Optional live enrichment for one peer, keyed elsewhere by the peer's id.
 *
 * The natural producer is the event bus — `subagent_progress` carries
 * `turn` / `max_turns` / `tool` / `note`, and `subagent_lifecycle` carries the
 * terminal `done` transition — joined to a roster row by `agent_id`. Everything
 * here is DISPLAY data: a note may have come from another process and is
 * control-stripped on the way to the screen.
 */
export interface HerdActivity {
  /** Overrides the default `idle` phase for an active peer. */
  phase?: HerdPhase;
  /** 1-based turn the child last completed. */
  turn?: number;
  /** The child's effective turn budget. */
  maxTurns?: number;
  /** Name of the most recent tool the child ran. Never a path or payload. */
  tool?: string;
  /** Short single-line status the child authored. */
  note?: string;
}

/**
 * One roster entry, structurally identical to `registry.PeerRecord` plus an
 * optional {@link HerdActivity}. A real `PeerRecord` assigns to this with no
 * cast; the extra field is ignored by anything that only knows the record.
 */
export interface HerdPeer {
  /** Stable roster id. Already sanitized by the registry to `[A-Za-z0-9._-]`. */
  id: string;
  kind: HerdPeerKind;
  /** OS process id. Opaque data. */
  pid: number;
  /** Project directory. Opaque, possibly authored by another process. */
  cwd: string;
  /** Epoch ms of the peer's last heartbeat. */
  lastSeen: number;
  /** Optional human label, e.g. the engagement target. Untrusted for display. */
  label?: string;
  /** Optional live enrichment. */
  activity?: HerdActivity;
}

/** The inbox fields the detail pane renders. A subset of `HubMessage`. */
export interface HerdInboxMessage {
  from: string;
  body: string;
  ts: number;
}

// ---------------------------------------------------------------------------
// Status derivation — mirrors registry.isStale / statusOf exactly
// ---------------------------------------------------------------------------

/**
 * Default heartbeat time-to-live, mirroring `registry.DEFAULT_PEER_TTL_MS`.
 * See the module header for why it is copied rather than imported.
 */
export const HERD_PEER_TTL_MS = 90_000;

/**
 * Is `peer` stale as of `now`? A byte-for-byte mirror of `registry.isStale`:
 * the boundary is INCLUSIVE-ALIVE (age exactly equal to the TTL is still
 * active; stale only once strictly older), and a non-positive or non-finite
 * `ttlMs` falls back to the default so a caller cannot mark everything stale.
 */
export function isPeerStale(peer: HerdPeer, now: number, ttlMs: number = HERD_PEER_TTL_MS): boolean {
  const ttl = Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : HERD_PEER_TTL_MS;
  return now - peer.lastSeen > ttl;
}

/**
 * Derive a peer's {@link HerdStatus}. Stale wins over everything (a peer whose
 * heartbeat has lapsed is stale even if its last activity said "working"); an
 * active peer takes its {@link HerdActivity.phase}, defaulting to `idle`.
 */
export function herdStatusOf(peer: HerdPeer, now: number, ttlMs?: number): HerdStatus {
  if (isPeerStale(peer, now, ttlMs)) return "stale";
  return peer.activity?.phase ?? "idle";
}

/** Human heading for a status group. */
export function herdStatusLabel(status: HerdStatus): string {
  switch (status) {
    case "working":
      return "WORKING";
    case "idle":
      return "IDLE";
    case "blocked":
      return "BLOCKED";
    case "done":
      return "DONE";
    default:
      return "STALE";
  }
}

// ---------------------------------------------------------------------------
// Row model
// ---------------------------------------------------------------------------

export type HerdRow =
  | { readonly kind: "heading"; readonly status: HerdStatus; readonly count: number }
  | { readonly kind: "peer"; readonly status: HerdStatus; readonly peer: HerdPeer };

/**
 * Flattens a roster into a renderable list of status headings and peer rows.
 *
 * Peers are bucketed by {@link herdStatusOf} and emitted group-by-group in the
 * fixed {@link HERD_STATUS_ORDER}. A heading is emitted only for a group with
 * at least one peer — an empty group is a row of noise. Within a group, peers
 * keep the order the provider handed them (the registry preserves entry order
 * across heartbeats), so the list does not reshuffle on every poll.
 */
export function buildHerdRows(
  peers: readonly HerdPeer[],
  now: number,
  ttlMs?: number,
): HerdRow[] {
  const byStatus = new Map<HerdStatus, HerdPeer[]>();
  for (const peer of peers) {
    if (!peer || typeof peer.id !== "string") continue;
    const status = herdStatusOf(peer, now, ttlMs);
    if (!byStatus.has(status)) byStatus.set(status, []);
    byStatus.get(status)?.push(peer);
  }

  const rows: HerdRow[] = [];
  for (const status of HERD_STATUS_ORDER) {
    const group = byStatus.get(status);
    if (!group || group.length === 0) continue;
    rows.push({ kind: "heading", status, count: group.length });
    for (const peer of group) rows.push({ kind: "peer", status, peer });
  }
  return rows;
}

/** Index of the first selectable (peer) row, or -1 when there are none. */
export function firstSelectableIndex(rows: readonly HerdRow[]): number {
  for (let index = 0; index < rows.length; index++) {
    if (rows[index]?.kind === "peer") return index;
  }
  return -1;
}

/** Index of the last selectable (peer) row, or -1 when there are none. */
export function lastSelectableIndex(rows: readonly HerdRow[]): number {
  for (let index = rows.length - 1; index >= 0; index--) {
    if (rows[index]?.kind === "peer") return index;
  }
  return -1;
}

/**
 * Pulls an arbitrary index onto a selectable row. The highlighted row can
 * vanish between two polls (a peer went stale into a different group, or left),
 * so the selection has to land on a peer rather than a heading or past the end.
 * Searching forward first keeps the cursor near where the list was.
 */
export function clampHerdSelection(rows: readonly HerdRow[], current: number): number {
  if (rows.length === 0) return -1;
  const start = clamp(Math.trunc(Number.isFinite(current) ? current : 0), 0, rows.length - 1);
  for (let index = start; index < rows.length; index++) {
    if (rows[index]?.kind === "peer") return index;
  }
  for (let index = start - 1; index >= 0; index--) {
    if (rows[index]?.kind === "peer") return index;
  }
  return -1;
}

/**
 * Moves the selection by `delta` rows, skipping headings and wrapping. The
 * inner guard loop is bounded by the list length so a list of nothing but
 * headings terminates instead of spinning.
 */
export function moveHerdSelection(rows: readonly HerdRow[], current: number, delta: number): number {
  const total = rows.length;
  if (total === 0) return -1;
  const anchor = clampHerdSelection(rows, current);
  if (anchor < 0) return -1;

  const step = delta >= 0 ? 1 : -1;
  const truncated = Math.trunc(Number.isFinite(delta) ? delta : 0);
  const count = Math.max(1, Math.abs(truncated) || 1);

  let index = anchor;
  for (let moved = 0; moved < count; moved++) {
    let probe = index;
    for (let guard = 0; guard < total; guard++) {
      probe = (probe + step + total) % total;
      if (rows[probe]?.kind === "peer") break;
    }
    if (rows[probe]?.kind !== "peer") return anchor;
    index = probe;
  }
  return index;
}

// ---------------------------------------------------------------------------
// Windowing (mirrors settings-layout.computeSettingsWindow)
// ---------------------------------------------------------------------------

export interface HerdWindowInput {
  rows: readonly HerdRow[];
  /** Highlighted row index, or -1 when the roster is empty. */
  selected: number;
  /** Rows the list body can actually paint. */
  visible: number;
  /** Previous window start, so the list scrolls instead of re-centring. */
  anchor?: number;
}

export interface HerdWindow {
  start: number;
  /** Exclusive. `rows.slice(start, end)` is exactly what may be rendered. */
  end: number;
  count: number;
  total: number;
  hasAbove: boolean;
  hasBelow: boolean;
}

/**
 * Scroll-into-view windowing, stateless apart from the caller's last start.
 * Taking the previous start as an anchor rather than re-centring is the
 * difference between a list that scrolls and one that jumps. When the cursor
 * lands on the first peer of a group, the window is pulled up one extra row so
 * that group's heading comes with it — a list scrolled past its own heading has
 * stopped saying which status you are looking at.
 */
export function computeHerdWindow(input: HerdWindowInput): HerdWindow {
  return computeListWindow(input);
}

// ---------------------------------------------------------------------------
// Shell chrome (mirrors settings-layout.shellChromeRows)
// ---------------------------------------------------------------------------

const SHELL_HORIZONTAL_PADDING = 2;
const PANEL_HORIZONTAL_CHROME = 4;
const HEADER_COMPACT_WIDTH = 88;
const FOOTER_INLINE_WIDTH = 64;

/**
 * Rows the shell spends before and after a screen's own content. Mirrors
 * `getShellChromeHeight` in `run.tsx` and the copy in `settings-layout.ts`,
 * for the same reason: importing the `.tsx` original would pull the whole
 * OpenTUI renderer into this module and its sweep. Verified against the real
 * frame by the render captures, not by a shared import.
 */
export function shellChromeRows(width: number): number {
  const total = cells(width);
  const headerContentWidth = total - SHELL_HORIZONTAL_PADDING * 2 - PANEL_HORIZONTAL_CHROME;
  const headerContentRows = headerContentWidth < HEADER_COMPACT_WIDTH ? 3 : 2;
  const contentWidth = Math.max(1, total - SHELL_HORIZONTAL_PADDING * 2);
  const footerRows = contentWidth >= FOOTER_INLINE_WIDTH ? 1 : 3;
  return 1 + (headerContentRows + 3) + footerRows;
}

// ---------------------------------------------------------------------------
// Geometry (mirrors settings-layout.computeSettingsLayout)
// ---------------------------------------------------------------------------

const TWO_PANE_MIN_WIDTH = 76;
const DETAIL_MIN_WIDTH = 30;
const DETAIL_MAX_WIDTH = 52;
const DETAIL_WIDTH_SHARE = 0.44;
const LIST_MIN_WIDTH = 34;
const STATUS_MAX_WIDTH = 8;
const STATUS_WIDTH_SHARE = 0.35;
const BORDERED_MIN_ROWS = 12;
const STACKED_DETAIL_SHARE = 0.4;
const STACKED_DETAIL_MAX_ROWS = 10;

export interface HerdPane {
  /** Outer cells, borders included. 0 when the pane is not rendered. */
  width: number;
  /** Cells available to text inside the pane. */
  innerWidth: number;
  /** Outer rows, borders included. 0 when the pane is not rendered. */
  height: number;
  /** Rows available to content, below the title row when there is one. */
  bodyRows: number;
  /** The pane spends a row on a title. */
  hasTitle: boolean;
}

export interface HerdRowLayout {
  /** Total cells a list row occupies; equals the list pane's inner width. */
  width: number;
  /** Selection marker column. 0 when the row is too narrow to spare it. */
  markerWidth: number;
  markerGap: number;
  /** Id / label column. Takes what the status column leaves. */
  labelWidth: number;
  statusGap: number;
  /** Status / activity column. 0 when the row can only afford a label. */
  statusWidth: number;
}

export interface HerdLayoutInput {
  width: number;
  height: number;
  /** 1 when a notice occupies a row above the footer. */
  noticeRows?: number;
}

export interface HerdLayout {
  stacked: boolean;
  bordered: boolean;
  contentWidth: number;
  bodyRows: number;
  paneGap: number;
  list: HerdPane;
  detail: HerdPane;
  row: HerdRowLayout;
  visibleRows: number;
  /** The detail pane drops blank separator lines when rows are scarce. */
  detailCompact: boolean;
}

/**
 * Splits a list row into marker, label and status columns. Both separators are
 * real Yoga gaps, never padded literals — `fitTuiText` routes through
 * `sanitizeTuiText`, which trims, so a label carrying its own trailing space
 * comes back without one and fuses onto its status. The status gives way before
 * the label: a row reading `Main` with no status still names the peer, while a
 * bare `working` does not. The columns sum to EXACTLY `innerWidth`.
 */
function computeRowLayout(innerWidth: number): HerdRowLayout {
  const width = cells(innerWidth);
  if (width <= 0) {
    return { width: 0, markerWidth: 0, markerGap: 0, labelWidth: 0, statusGap: 0, statusWidth: 0 };
  }

  const markerWidth = width >= 6 ? 1 : 0;
  const markerGap = markerWidth > 0 && width > markerWidth ? 1 : 0;
  const afterMarker = Math.max(0, width - markerWidth - markerGap);

  const statusWidth =
    afterMarker >= 14 ? Math.min(STATUS_MAX_WIDTH, Math.floor(afterMarker * STATUS_WIDTH_SHARE)) : 0;
  const statusGap = statusWidth > 0 && afterMarker > statusWidth ? 1 : 0;
  const labelWidth = Math.max(0, afterMarker - statusWidth - statusGap);

  return { width, markerWidth, markerGap, labelWidth, statusGap, statusWidth };
}

/**
 * The full geometry of the herd screen. Horizontally, the detail pane takes a
 * bounded share of the content column when the terminal is wide enough to hold
 * both and stacks underneath otherwise. Vertically, the panes give up their
 * borders before they give up rows of content, and the detail pane is dropped
 * entirely rather than rendered at a height that would push its border through
 * its own text.
 */
export function computeHerdLayout({ width, height, noticeRows = 0 }: HerdLayoutInput): HerdLayout {
  const terminalWidth = cells(width);
  const contentWidth = Math.max(0, terminalWidth - SHELL_HORIZONTAL_PADDING * 2);
  const bodyRows = Math.max(
    0,
    cells(height) - shellChromeRows(terminalWidth) - Math.min(1, cells(noticeRows)),
  );

  const split = computePaneSplit(contentWidth, bodyRows, {
    twoPaneMinWidth: TWO_PANE_MIN_WIDTH,
    detailMinWidth: DETAIL_MIN_WIDTH,
    detailMaxWidth: DETAIL_MAX_WIDTH,
    detailWidthShare: DETAIL_WIDTH_SHARE,
    listMinWidth: LIST_MIN_WIDTH,
    borderedMinRows: BORDERED_MIN_ROWS,
    stackedDetailShare: STACKED_DETAIL_SHARE,
    stackedDetailMaxRows: STACKED_DETAIL_MAX_ROWS,
  });

  return {
    ...split,
    row: computeRowLayout(split.list.innerWidth),
    visibleRows: split.list.bodyRows,
    detailCompact: !split.bordered,
  };
}

// ---------------------------------------------------------------------------
// Text: relative age, path abbreviation, wrapping
// ---------------------------------------------------------------------------

/**
 * A peer's heartbeat age as an operator-facing relative string. Pure — `now`
 * and `lastSeen` are both injected. A negative age (clock skew between peers)
 * reads as "just now" rather than a nonsense future.
 */
export function formatRelativeAge(lastSeen: number, now: number): string {
  const ageMs = now - lastSeen;
  if (!Number.isFinite(ageMs) || ageMs < 1000) return "just now";
  const seconds = Math.floor(ageMs / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/**
 * Abbreviate a project directory with `~` when it sits under `homeDir`, then
 * sanitize it. The cwd is opaque data that may have been written by another
 * process, so it is control-stripped before it can reach the frame.
 */
export function abbreviateHomePath(cwd: unknown, homeDir?: string): string {
  const raw = typeof cwd === "string" ? cwd : "";
  let shown = raw;
  if (homeDir && homeDir.length > 0 && raw === homeDir) {
    shown = "~";
  } else if (homeDir && homeDir.length > 0 && raw.startsWith(`${homeDir}/`)) {
    shown = `~${raw.slice(homeDir.length)}`;
  }
  return sanitizeHerdText(shown);
}

/**
 * Greedy word wrap onto `width`-cell lines. The input is sanitised first, so a
 * label or note from another process cannot smuggle a cursor move into the
 * frame, and a token longer than the line is hard-broken rather than allowed to
 * overhang.
 */
export function wrapCells(value: unknown, width: number): string[] {
  return wrapText(sanitizeHerdText(value), width);
}

// ---------------------------------------------------------------------------
// List row rendering data
// ---------------------------------------------------------------------------

/**
 * How a peer's status column reads in the list. Prefers the activity's tool or
 * turn counter when it carries one, since "read_file" or "3/8" says more than
 * "working"; falls back to the status word. Bounded to the column later.
 */
export function herdRowStatusText(peer: HerdPeer, status: HerdStatus): string {
  if (status !== "stale" && peer.activity) {
    const { tool, turn, maxTurns } = peer.activity;
    if (typeof tool === "string" && tool.length > 0) return sanitizeHerdText(tool);
    if (typeof turn === "number" && Number.isFinite(turn)) {
      if (typeof maxTurns === "number" && Number.isFinite(maxTurns) && maxTurns > 0) {
        return `${Math.trunc(turn)}/${Math.trunc(maxTurns)}`;
      }
      return `t${Math.trunc(turn)}`;
    }
  }
  return herdStatusLabel(status).toLowerCase();
}

/** How a peer reads in the list's label column: its label, or its id. */
export function herdRowLabelText(peer: HerdPeer): string {
  const label = typeof peer.label === "string" ? sanitizeHerdText(peer.label) : "";
  if (label.length > 0) return label;
  return sanitizeHerdText(peer.id);
}

// ---------------------------------------------------------------------------
// Detail pane
// ---------------------------------------------------------------------------

export type HerdDetailTone = "title" | "text" | "muted" | "accent" | "warn" | "blank";

export interface HerdDetailLine {
  readonly text: string;
  readonly tone: HerdDetailTone;
}

export interface HerdDetailOptions {
  /** Omit the blank separator rows. Set when the pane is short of rows. */
  compact?: boolean;
  /** Home dir for `~` abbreviation. */
  homeDir?: string;
  /** How many recent inbox messages to show. */
  maxInbox?: number;
}

function statusTone(status: HerdStatus): HerdDetailTone {
  switch (status) {
    case "working":
      return "accent";
    case "blocked":
    case "stale":
      return "warn";
    default:
      return "muted";
  }
}

/**
 * The detail pane's body for one peer, as flat tone-tagged lines. Content is
 * decided here and colour by the component, so the pane can be asserted on
 * without a renderer. Every value is a `label: value` pair rather than an
 * alignment column, because `sanitizeTuiText` collapses whitespace and a padded
 * literal would be trimmed away.
 *
 * Every peer-authored field (id, label, cwd, inbox `from` / `body`) is
 * sanitized — the mailbox already strips message bodies, and registry ids are
 * already sanitized, but this pane re-strips defensively since a row may arrive
 * from an injected provider that did neither.
 */
export function herdDetailLines(
  peer: HerdPeer | undefined,
  inbox: readonly HerdInboxMessage[],
  width: number,
  now: number,
  { compact = false, homeDir, maxInbox = 4 }: HerdDetailOptions = {},
): HerdDetailLine[] {
  const limit = cells(width);
  if (!peer || limit <= 0) return [];

  const status = herdStatusOf(peer, now);
  const lines: HerdDetailLine[] = [];
  const separate = () => {
    if (!compact) lines.push({ text: "", tone: "blank" });
  };
  const push = (value: string, tone: HerdDetailTone) => {
    for (const text of wrapCells(value, limit)) lines.push({ text, tone });
  };

  push(peer.id, "title");
  separate();

  push(`Status: ${herdStatusLabel(status).toLowerCase()}`, statusTone(status));
  push(`Kind: ${peer.kind === "subagent" ? "subagent" : "session"}`, "muted");
  const pid = Number.isFinite(peer.pid) ? Math.trunc(peer.pid) : 0;
  push(`PID: ${pid}`, "muted");
  push(`Last seen: ${formatRelativeAge(peer.lastSeen, now)}`, status === "stale" ? "warn" : "muted");
  if (typeof peer.label === "string" && sanitizeHerdText(peer.label).length > 0) {
    push(`Label: ${peer.label}`, "text");
  }
  push(`Dir: ${abbreviateHomePath(peer.cwd, homeDir)}`, "muted");

  if (peer.activity) {
    const { turn, maxTurns, tool, note } = peer.activity;
    if (typeof turn === "number" && Number.isFinite(turn)) {
      const budget =
        typeof maxTurns === "number" && Number.isFinite(maxTurns) && maxTurns > 0
          ? `/${Math.trunc(maxTurns)}`
          : "";
      push(`Turn: ${Math.trunc(turn)}${budget}`, "text");
    }
    if (typeof tool === "string" && sanitizeHerdText(tool).length > 0) push(`Tool: ${tool}`, "text");
    if (typeof note === "string" && sanitizeHerdText(note).length > 0) push(`Note: ${note}`, "text");
  }

  separate();
  const recent = inbox.slice(-Math.max(0, Math.trunc(maxInbox)));
  if (recent.length === 0) {
    push("Inbox: empty", "muted");
  } else {
    push(`Inbox (${inbox.length})`, "muted");
    for (const message of recent) {
      const from = sanitizeHerdText(message.from) || "?";
      const body = sanitizeHerdText(message.body);
      push(`${from}: ${body}`, "text");
    }
  }

  return lines;
}

/**
 * Trims detail lines to the rows the pane actually has, marking the cut rather
 * than making it silently. Given a width, the marker is appended to the last
 * surviving line instead of taking a row of its own — on the short terminals
 * where clipping happens, a lone `...` throws away a line to say a line was
 * thrown away.
 */
export function clipDetailLines(
  lines: readonly HerdDetailLine[],
  rows: number,
  width = 0,
): HerdDetailLine[] {
  const limit = cells(rows);
  if (limit <= 0) return [];
  if (lines.length <= limit) return [...lines];

  const kept = lines.slice(0, limit);
  const last = kept[limit - 1];
  const room = cells(width);
  if (room >= 8 && last && last.text.length > 0) {
    const head = last.text.slice(0, Math.max(0, room - 4)).trimEnd();
    kept[limit - 1] = { text: `${head} ...`, tone: last.tone };
  } else {
    kept[limit - 1] = { text: "...", tone: "muted" };
  }
  return kept;
}

// ---------------------------------------------------------------------------
// Titles, hints, empty state
// ---------------------------------------------------------------------------

/** `HERD 4-15/18`, `HERD 18`, or `HERD 0` when the roster is empty. */
export function herdListTitle(window: HerdWindow): string {
  if (window.total === 0) return "HERD 0";
  if (!window.hasAbove && !window.hasBelow) return `HERD ${window.total}`;
  return `HERD ${window.start + 1}-${window.end}/${window.total}`;
}

/**
 * The list pane's header, split into a bold title and a right-aligned summary
 * meta — the OMP-style "AGENTS … N" header the console reuses. The title is a
 * stable label; the meta counts the roster (peers, not headings) or names the
 * visible window when the list is scrolled, so an operator always knows how
 * many agents there are and how much is off-screen.
 */
export function herdListHeading(window: HerdWindow): { title: string; meta: string } {
  if (window.total === 0) return { title: "HERD", meta: "empty" };
  if (!window.hasAbove && !window.hasBelow) {
    return { title: "HERD", meta: `${window.total}` };
  }
  return { title: "HERD", meta: `${window.start + 1}-${window.end} / ${window.total}` };
}

export { paneTitleColumns, type PaneTitleColumns } from "./pane-layout.js";

/**
 * The honest empty-state line. The roster has no producer yet, so an empty
 * roster is the NORMAL state today — this says so plainly rather than implying
 * something is broken.
 */
export const HERD_EMPTY_TEXT = "no other agents in this project";

export function herdFooterHint(): string {
  return ["↑/↓ move", "enter focus", "m message", "esc back", "ctrl+c exit"].join(" · ");
}

/** The footer hint while the steering composer is open. */
export function herdComposerFooterHint(): string {
  return ["enter send", "esc cancel", "ctrl+c exit"].join(" · ");
}

/**
 * The footer hint shown while drilled into a subagent from the chat screen, so
 * the operator always sees how to get back to the main agent and that they can
 * type to message the focused subagent.
 */
export function chatFocusFooterHint(): string {
  return ["type to message", "esc/← back to main", "↑/↓ scroll", "ctrl+c exit"].join(" · ");
}

/**
 * The prompt shown before the steering draft, e.g. `› `. A real prefix rather
 * than a padded literal, so its width is accounted for in
 * {@link herdComposerTextWidth} and it cannot fuse onto the draft.
 */
export const HERD_COMPOSER_PROMPT = "› ";

/** A single cursor cell painted at the tail of the steering draft. */
export const HERD_COMPOSER_CURSOR = "▏";

/**
 * Cells available to the steering draft text on the reserved composer row.
 *
 * The row is the prompt ({@link HERD_COMPOSER_PROMPT}, 2 cells) + the draft +
 * a one-cell cursor block, budgeted against the screen's content width exactly
 * as `chat-layout.ts` budgets its own composer. Floored at one cell so a very
 * narrow terminal still shows a caret rather than nothing. Pure.
 */
export function herdComposerTextWidth(contentWidth: number): number {
  return Math.max(1, cells(contentWidth) - HERD_COMPOSER_PROMPT.length - HERD_COMPOSER_CURSOR.length);
}

/**
 * The tail of `draft` that fits the composer text column, so the newest
 * characters an operator types stay visible (end-truncation would hide them).
 * Sanitized so a pasted control sequence cannot reach the frame. Pure.
 */
export function herdComposerVisibleDraft(draft: unknown, contentWidth: number): string {
  const width = herdComposerTextWidth(contentWidth);
  const text = sanitizeHerdText(draft);
  return text.length > width ? text.slice(text.length - width) : text;
}

/** Budget the empty-state text to the pane and clip it if the pane is tiny. */
export function fitHerdEmptyText(width: number): string {
  return fitTuiText(HERD_EMPTY_TEXT, cells(width));
}

// ===========================================================================
// FOCUS MODE — drill into ONE subagent, watch its live activity, steer it.
// ===========================================================================
//
// The list is a roster overview; focus mode is the operator "going into" a
// single running subagent. The list pane feeds it a peer; the event bus feeds
// it that peer's LIVE activity. Both halves are pure and swept here, for the
// same Yoga-shrinks-not-clips reason the list layout is:
//
//   1. {@link computeHerdFocusLayout} splits the body into a fixed meta pane
//      (identity + status + turns + findings) stacked over a transcript pane
//      (the scrolling mini-transcript of the child's per-turn activity). Both
//      are the full content width — a single column — so the only failure mode
//      is vertical, and the allocator gives the transcript every row the meta
//      does not need while guaranteeing the meta keeps at least its title.
//   2. {@link applySubagentLifecycle} / {@link applySubagentProgress} are pure
//      reducers over the `subagent_lifecycle` / `subagent_progress` bus events
//      (mirrored structurally here — the payload arrives as a bare record and
//      core's `SubagentProgressPayload` is not exported). They build a bounded
//      per-agent record: latest snapshot + a ring of activity entries.
//   3. {@link focusHeaderLines} / {@link renderFocusActivity} turn a record
//      into tone-tagged, width-wrapped lines the component paints without any
//      arithmetic of its own — every peer-authored field is sanitized on the
//      way, exactly as the detail pane sanitizes.

// ---------------------------------------------------------------------------
// Live subagent model — a structural mirror of the bus payloads
// ---------------------------------------------------------------------------

/** The four lifecycle states a subagent moves through. Mirrors the bus. */
export type SubagentStatus = "queued" | "running" | "completed" | "failed";

/** How many activity entries a single agent's ring buffer retains. */
export const HERD_ACTIVITY_MAX = 200;

/**
 * One entry in a subagent's live activity ring. A `lifecycle` entry marks a
 * state transition (queued → running → completed|failed); a `progress` entry
 * is one completed child turn carrying the tool that ran and any note the
 * child authored. Everything here is DISPLAY data — sanitized when rendered.
 */
export interface SubagentActivityEntry {
  readonly kind: "lifecycle" | "progress";
  /** Epoch ms the entry was recorded (the event arrival clock). */
  readonly ts: number;
  readonly status?: SubagentStatus;
  readonly turn?: number;
  readonly maxTurns?: number;
  readonly tool?: string;
  readonly note?: string;
  readonly findings?: number;
  readonly turns?: number;
  readonly error?: string;
}

/**
 * The live record the focus view is a view over: the latest snapshot for one
 * subagent joined to its bounded activity ring. Keyed elsewhere by `agentId`,
 * which is the SAME id a roster subagent peer carries, so a peer and its live
 * record join on the id.
 */
export interface HerdSubagentRecord {
  readonly agentId: string;
  /** Human-friendly AdjectiveNoun name from the lifecycle event (display). */
  readonly name?: string;
  readonly parentScanId: string;
  readonly task: string;
  readonly status: SubagentStatus;
  readonly maxTurns: number;
  readonly turn?: number;
  readonly turns?: number;
  readonly findings?: number;
  readonly summary?: string;
  readonly error?: string;
  /** Latest tool the child ran, mirrored onto the roster row's activity. */
  readonly tool?: string;
  /** Latest note the child authored. */
  readonly note?: string;
  /** Epoch ms of the last event for this agent — drives age/staleness. */
  readonly lastSeen: number;
  readonly activity: readonly SubagentActivityEntry[];
}

/** A live subagent map, keyed by `agentId`. */
export type HerdSubagentMap = Record<string, HerdSubagentRecord>;

// -- Defensive coercion of bus payload fields (payloads arrive as records) --

function pickString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function pickFiniteInt(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? Math.trunc(value) : undefined;
}

function pickStatus(value: unknown): SubagentStatus | undefined {
  return value === "queued" || value === "running" || value === "completed" || value === "failed"
    ? value
    : undefined;
}

function boundActivity(
  prev: readonly SubagentActivityEntry[],
  entry: SubagentActivityEntry,
  maxLines: number,
): SubagentActivityEntry[] {
  const cap = Math.max(1, cells(maxLines) || HERD_ACTIVITY_MAX);
  const next = [...prev, entry];
  return next.length > cap ? next.slice(next.length - cap) : next;
}

/**
 * Fold one `subagent_lifecycle` bus payload into the map. Pure: the arrival
 * clock is injected. Returns the SAME map when the payload is unusable (no
 * `agent_id`), so a malformed event never forces a repaint; otherwise a new
 * map with the agent's record upserted and a lifecycle entry appended.
 *
 * Terminal states (completed|failed) are KEPT, not dropped — unlike the chat
 * card's active-set reducer, the focus view wants the final summary/error to
 * stay readable after the child finishes.
 */
export function applySubagentLifecycle(
  map: HerdSubagentMap,
  payload: Record<string, unknown>,
  now: number,
  maxLines: number = HERD_ACTIVITY_MAX,
): HerdSubagentMap {
  const agentId = pickString(payload["agent_id"]);
  if (!agentId) return map;
  const ts = Number.isFinite(now) ? now : 0;
  const prev = map[agentId];
  const status = pickStatus(payload["status"]) ?? prev?.status ?? "queued";
  const task = pickString(payload["task"]) ?? prev?.task ?? "";
  const maxTurns = pickFiniteInt(payload["max_turns"]) ?? prev?.maxTurns ?? 0;
  const turns = pickFiniteInt(payload["turns"]) ?? prev?.turns;
  const findings = pickFiniteInt(payload["findings"]) ?? prev?.findings;
  const summary = pickString(payload["summary"]) ?? prev?.summary;
  const error = pickString(payload["error"]) ?? prev?.error;

  const entry: SubagentActivityEntry = {
    kind: "lifecycle",
    ts,
    status,
    turns,
    findings,
    error,
  };

  const record: HerdSubagentRecord = {
    agentId,
    name: pickString(payload["name"]) ?? prev?.name,
    parentScanId: pickString(payload["parent_scan_id"]) ?? prev?.parentScanId ?? "",
    task,
    status,
    maxTurns,
    turn: prev?.turn,
    turns,
    findings,
    summary,
    error,
    tool: prev?.tool,
    note: prev?.note,
    lastSeen: ts,
    activity: boundActivity(prev?.activity ?? [], entry, maxLines),
  };
  return { ...map, [agentId]: record };
}

/**
 * Fold one `subagent_progress` bus payload into the map. Pure. A progress
 * event only lands for a running child, so if no record exists yet one is
 * seeded in `running` — the roster/lifecycle event may simply not have been
 * observed by this process first. Appends a progress entry and refreshes the
 * latest turn / tool / note mirrored onto the roster row.
 */
export function applySubagentProgress(
  map: HerdSubagentMap,
  payload: Record<string, unknown>,
  now: number,
  maxLines: number = HERD_ACTIVITY_MAX,
): HerdSubagentMap {
  const agentId = pickString(payload["agent_id"]);
  if (!agentId) return map;
  const ts = Number.isFinite(now) ? now : 0;
  const prev = map[agentId];
  const turn = pickFiniteInt(payload["turn"]);
  const maxTurns = pickFiniteInt(payload["max_turns"]) ?? prev?.maxTurns ?? 0;
  const tool = pickString(payload["tool"]);
  const note = pickString(payload["note"]);

  const entry: SubagentActivityEntry = { kind: "progress", ts, turn, maxTurns, tool, note };

  const record: HerdSubagentRecord = {
    agentId,
    parentScanId: pickString(payload["parent_scan_id"]) ?? prev?.parentScanId ?? "",
    task: prev?.task ?? "",
    // A child still emitting turns is running, unless it already reached a
    // terminal state we recorded (a late progress event never resurrects it).
    status: prev?.status === "completed" || prev?.status === "failed" ? prev.status : "running",
    maxTurns,
    turn: turn ?? prev?.turn,
    turns: prev?.turns,
    findings: prev?.findings,
    summary: prev?.summary,
    error: prev?.error,
    tool: tool ?? prev?.tool,
    note: note ?? prev?.note,
    lastSeen: ts,
    activity: boundActivity(prev?.activity ?? [], entry, maxLines),
  };
  return { ...map, [agentId]: record };
}

/** Map a lifecycle status to the roster's live phase bucket. */
function statusPhase(status: SubagentStatus): HerdPhase {
  switch (status) {
    case "running":
      return "working";
    case "queued":
      return "idle";
    default:
      // completed AND failed are both terminal → "done"; a failed child keeps
      // its error visible in the note rather than masquerading as "blocked".
      return "done";
  }
}

/** Human label for a subagent's own lifecycle status (focus header). */
export function subagentStatusLabel(status: SubagentStatus): string {
  switch (status) {
    case "queued":
      return "queued";
    case "running":
      return "running";
    case "completed":
      return "completed";
    default:
      return "failed";
  }
}

/**
 * Project the live subagent map onto roster peers, so a subagent actually
 * running in this process shows in the list even before the (unwired) roster
 * producer lands. These are REAL agents emitting REAL events — not fabricated
 * placeholders — so surfacing them does not violate the screen's no-invented-
 * herd rule. Insertion order is preserved (JS keeps string-key order).
 */
export function subagentPeers(map: HerdSubagentMap, _now: number): HerdPeer[] {
  const peers: HerdPeer[] = [];
  for (const record of Object.values(map)) {
    if (!record || typeof record.agentId !== "string") continue;
    peers.push({
      id: record.agentId,
      kind: "subagent",
      pid: 0,
      cwd: "",
      lastSeen: record.lastSeen,
      label: record.task || undefined,
      activity: {
        phase: statusPhase(record.status),
        turn: record.turn,
        maxTurns: record.maxTurns > 0 ? record.maxTurns : undefined,
        tool: record.tool,
        note: record.note,
      },
    });
  }
  return peers;
}

/**
 * Merge a provider roster with the live subagent peers, provider winning on an
 * id collision (the injected reader is authoritative once it lands). Additive:
 * with no provider peers this is just the live subagents; with no live
 * subagents it is just the provider roster.
 */
export function mergeSubagentRoster(
  providerPeers: readonly HerdPeer[],
  livePeers: readonly HerdPeer[],
): HerdPeer[] {
  const seen = new Set(providerPeers.map((p) => p.id));
  const merged: HerdPeer[] = [...providerPeers];
  for (const peer of livePeers) {
    if (!seen.has(peer.id)) {
      merged.push(peer);
      seen.add(peer.id);
    }
  }
  return merged;
}

// ---------------------------------------------------------------------------
// Focus content — header lines + activity transcript
// ---------------------------------------------------------------------------

function focusStatusTone(status: SubagentStatus): HerdDetailTone {
  switch (status) {
    case "running":
      return "accent";
    case "failed":
      return "warn";
    default:
      return "muted";
  }
}

/**
 * The focus header: identity + live status counters for one subagent, as flat
 * tone-tagged lines wrapped to `width`. Prefers the live record when present
 * (its lifecycle status/findings/summary are richer than the roster row), and
 * falls back to the peer's own roster fields otherwise, so focusing a peer
 * with no live record still reads.
 */
export function focusHeaderLines(
  peer: HerdPeer | undefined,
  record: HerdSubagentRecord | undefined,
  width: number,
  now: number,
  { compact = false }: { compact?: boolean } = {},
): HerdDetailLine[] {
  const limit = cells(width);
  if (!peer || limit <= 0) return [];
  const lines: HerdDetailLine[] = [];
  const push = (value: string, tone: HerdDetailTone) => {
    for (const text of wrapCells(value, limit)) lines.push({ text, tone });
  };
  const separate = () => {
    if (!compact) lines.push({ text: "", tone: "blank" });
  };

  const task = record?.task || peer.label || "";
  push(sanitizeHerdText(task).length > 0 ? task : peer.id, "title");
  if (sanitizeHerdText(task).length > 0) push(peer.id, "muted");
  separate();

  if (record) {
    push(`Status: ${subagentStatusLabel(record.status)}`, focusStatusTone(record.status));
    // Show turn progress as a plain count, not `turn/maxTurns` — the budget cap
    // is an internal guardrail, and surfacing it here reads as an arbitrary
    // "limit" on the subagent rather than useful progress.
    const turnValue =
      typeof record.turn === "number"
        ? record.turn
        : typeof record.turns === "number"
          ? record.turns
          : undefined;
    if (typeof turnValue === "number") push(`Turns: ${turnValue}`, "text");
    if (typeof record.findings === "number") push(`Findings: ${record.findings}`, "text");
    if (record.tool) push(`Tool: ${record.tool}`, "text");
    if (record.note) push(`Note: ${record.note}`, "text");
    push(`Last seen: ${formatRelativeAge(record.lastSeen, now)}`, "muted");
    if (record.status === "completed" && record.summary) {
      separate();
      push(`Summary: ${record.summary}`, "text");
    }
    if (record.status === "failed" && record.error) {
      separate();
      push(`Error: ${record.error}`, "warn");
    }
  } else {
    const status = herdStatusOf(peer, now);
    push(`Status: ${herdStatusLabel(status).toLowerCase()}`, statusTone(status));
    push(`Kind: ${peer.kind === "subagent" ? "subagent" : "session"}`, "muted");
    const a = peer.activity;
    if (a && typeof a.turn === "number") {
      push(`Turns: ${Math.trunc(a.turn)}`, "text");
    }
    if (a?.tool) push(`Tool: ${a.tool}`, "text");
    if (a?.note) push(`Note: ${a.note}`, "text");
    push(`Last seen: ${formatRelativeAge(peer.lastSeen, now)}`, "muted");
  }

  return lines;
}

/**
 * The live activity transcript for one subagent: its ring of entries rendered
 * oldest-first as tone-tagged, width-wrapped lines. A progress turn reads
 * `t3/8 · read_file` with any note on a continuation line; a lifecycle entry
 * marks the transition. Every child-authored value is sanitized. Newest lines
 * are last, so a tail window shows the most recent activity.
 */
export function renderFocusActivity(
  entries: readonly SubagentActivityEntry[],
  width: number,
): HerdDetailLine[] {
  const limit = cells(width);
  if (limit <= 0) return [];
  const lines: HerdDetailLine[] = [];
  const push = (value: string, tone: HerdDetailTone) => {
    for (const text of wrapCells(value, limit)) lines.push({ text, tone });
  };

  for (const entry of entries) {
    if (entry.kind === "lifecycle") {
      const status = entry.status ?? "queued";
      let text = `• ${subagentStatusLabel(status)}`;
      if (status === "completed" || status === "failed") {
        const bits: string[] = [];
        if (typeof entry.turns === "number") bits.push(`${entry.turns} turns`);
        if (typeof entry.findings === "number") bits.push(`${entry.findings} findings`);
        if (bits.length > 0) text += ` · ${bits.join(" · ")}`;
      }
      push(text, status === "failed" ? "warn" : status === "running" ? "accent" : "muted");
      if (status === "failed" && entry.error) push(`  ↳ ${entry.error}`, "warn");
    } else {
      const budget =
        typeof entry.maxTurns === "number" && entry.maxTurns > 0 ? `/${entry.maxTurns}` : "";
      const turn = typeof entry.turn === "number" ? `t${entry.turn}${budget}` : "turn";
      const tool = entry.tool ? ` · ${entry.tool}` : "";
      push(`${turn}${tool}`, "text");
      if (entry.note) push(`  ↳ ${entry.note}`, "muted");
    }
  }
  return lines;
}

/**
 * A tail window over `total` lines showing `capacity` of them, scrolled back
 * `offsetFromBottom` lines. Offset 0 is the newest (the natural follow-tail);
 * a larger offset scrolls toward older lines and is clamped so the window
 * never runs off either end. Pure — the mirror of {@link computeHerdWindow}
 * for a bottom-anchored transcript.
 */
export function windowFocusTail(
  total: number,
  capacity: number,
  offsetFromBottom: number,
): { start: number; end: number; count: number; hasAbove: boolean; hasBelow: boolean } {
  const rows = cells(total);
  const cap = cells(capacity);
  if (cap <= 0 || rows <= 0) {
    return { start: 0, end: 0, count: 0, hasAbove: rows > 0, hasBelow: false };
  }
  if (rows <= cap) return { start: 0, end: rows, count: rows, hasAbove: false, hasBelow: false };
  const maxOffset = rows - cap;
  const off = clamp(cells(offsetFromBottom), 0, maxOffset);
  const end = rows - off;
  const start = end - cap;
  return { start, end, count: cap, hasAbove: start > 0, hasBelow: end < rows };
}

// ---------------------------------------------------------------------------
// Focus geometry — a meta pane stacked over a transcript pane
// ---------------------------------------------------------------------------

/** Rows of meta CONTENT the focus header wants before the transcript. */
const FOCUS_META_ROWS = 6;

export interface HerdFocusLayout {
  bordered: boolean;
  contentWidth: number;
  bodyRows: number;
  /** Identity + status counters. Zero-height when the body is too short. */
  meta: HerdPane;
  /** The scrolling live-activity transcript. Takes what the meta leaves. */
  transcript: HerdPane;
}

/**
 * The focus view's geometry: two full-width panes stacked vertically, the meta
 * header over the live transcript. Because both are the content width, the only
 * failure mode is vertical — the allocator hands the transcript every row the
 * meta does not need, guaranteeing the meta keeps at least its title row and
 * the transcript keeps at least one content row, and dropping the meta entirely
 * before it would squeeze the transcript below a single line.
 */
export function computeHerdFocusLayout({
  width,
  height,
  noticeRows = 0,
}: HerdLayoutInput): HerdFocusLayout {
  const terminalWidth = cells(width);
  const contentWidth = Math.max(0, terminalWidth - SHELL_HORIZONTAL_PADDING * 2);
  const bodyRows = Math.max(
    0,
    cells(height) - shellChromeRows(terminalWidth) - Math.min(1, cells(noticeRows)),
  );

  const bordered = bodyRows >= BORDERED_MIN_ROWS && contentWidth >= DETAIL_MIN_WIDTH + 4;
  const chrome = borderChrome(bordered);
  // Minimum outer height for a pane that keeps a title + one content row.
  const paneMin = chrome.vertical + 1 + 1;

  let metaHeight = 0;
  let transcriptHeight = 0;
  if (bodyRows >= paneMin * 2) {
    // Both panes fit: give the meta what it wants, capped so the transcript
    // keeps at least its minimum, and hand the transcript the remainder.
    const wantMeta = chrome.vertical + 1 + FOCUS_META_ROWS;
    metaHeight = clamp(wantMeta, paneMin, bodyRows - paneMin);
    transcriptHeight = bodyRows - metaHeight;
  } else if (bodyRows >= paneMin) {
    // Only room for one pane — the transcript is the point of focus mode.
    transcriptHeight = bodyRows;
  }

  const meta = makePane(contentWidth, metaHeight, chrome.horizontal, chrome.vertical, true);
  const transcript = makePane(
    contentWidth,
    transcriptHeight,
    chrome.horizontal,
    chrome.vertical,
    true,
  );

  return { bordered, contentWidth, bodyRows, meta, transcript };
}

/** Footer hint while a subagent is focused (navigation, not composing). */
export function herdFocusFooterHint(): string {
  return ["↑/↓ scroll", "m steer", "esc back to list", "ctrl+c exit"].join(" · ");
}

/** Title for the transcript pane: `LIVE 12` (entry count) or `LIVE`. */
export function herdFocusTranscriptTitle(count: number): string {
  const n = cells(count);
  return n > 0 ? `LIVE ${n}` : "LIVE";
}

/** Shown in the transcript pane when the focused agent has no activity yet. */
export const HERD_FOCUS_EMPTY_TEXT = "no live activity yet";
