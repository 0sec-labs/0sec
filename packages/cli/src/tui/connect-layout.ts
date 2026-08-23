/**
 * Layout, navigation and windowing arithmetic for the full-screen provider
 * connect / login screen (`/connect`, alias `/login`).
 *
 * This is `model-layout.ts` for provider authentication, and it exists for the
 * same reason spelled out in `PRIMITIVES.md`: OpenTUI lays rows out with Yoga,
 * and Yoga *shrinks* siblings rather than clipping them. Two `<text>` nodes
 * that together want more cells than their row has are both painted in full
 * into boxes that are now too small, and the terminal shows the two strings
 * interleaved character by character. The same failure on the vertical axis
 * makes a bordered box paint its own bottom border through its last content
 * row. So the component reads widths and row counts off a `ConnectLayout` and
 * never computes one, and a sweep hammers every number in here across widths
 * 0..200 and heights 0..80.
 *
 * ## What the screen is for
 *
 * `/providers` is read-only: it says which vendors this machine can already
 * reach. This screen is the write side — it lets the operator connect one. The
 * providers, their env vars and their setup hints are all taken from
 * `provider-status.ts` (itself transcribed from the runtime's detection), so a
 * provider added there appears here without this module changing. This module
 * only adds two things the runtime table does not carry: which auth *method*
 * each provider uses (an API key versus an OAuth/subscription sign-in) and
 * which providers are worth surfacing first for someone connecting their very
 * first one.
 *
 * ## The honesty rule
 *
 * A provider reads as connected — the green check — only when a credential
 * actually exists for it: an env var holds one, or the credential store on
 * disk does. The store is written by the screen's input sub-step. Nothing here
 * ever reports a connection that was not verified against one of those two
 * sources; there is no optimistic "connecting…" state that sticks.
 *
 * ## Reuse
 *
 * `shellChromeRows` and `wrapCells` are imported from `settings-layout.ts`
 * rather than copied, exactly as `model-layout.ts` does — the honest long-term
 * home for both is a shared `shell-geometry.ts`, and this import is the marker
 * for that move.
 */

import { PROVIDERS, providerStates, type ProviderState } from "./provider-status.js";
import { shellChromeRows, wrapCells } from "./settings-layout.js";
import { sanitizeTuiText } from "./text.js";

export { shellChromeRows, wrapCells };

// ---------------------------------------------------------------------------
// Numeric hygiene (mirrors model-layout.ts)
// ---------------------------------------------------------------------------

/** Cell and row counts are non-negative integers; garbage geometry degrades to 0. */
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
// Provider model
// ---------------------------------------------------------------------------

/**
 * How a provider is authenticated.
 *
 * - `api-key`      — paste a secret; the input sub-step writes it to the
 *                    credential store, which the runtime reads back via env.
 * - `subscription` — an OAuth / device-code sign-in. The real network dance
 *                    lives outside the tool (e.g. `codex login`); the screen
 *                    presents the honest "sign in, then paste the token" path
 *                    and stores whatever the operator actually pastes back.
 */
export type AuthKind = "api-key" | "subscription";

/**
 * Providers surfaced in the "Popular" group, in the order shown. The first is
 * 0sec's recommended subscription option. Membership is a curation decision,
 * not a runtime fact, so it lives here and nowhere else; every id must exist in
 * `PROVIDERS` or it is silently ignored (a test guards that).
 */
export const RECOMMENDED_IDS: readonly string[] = ["chatgpt-codex", "anthropic", "openai"];

/** Providers whose auth is a subscription / OAuth sign-in rather than a key. */
const SUBSCRIPTION_IDS = new Set<string>(["chatgpt-codex"]);

/**
 * Plain-language subtitles for the recommended group. Kept short enough to sit
 * as a single dimmed row under the provider it describes; wrapping is handled
 * by the list row budget, not here.
 */
const PROVIDER_SUBTITLE: Record<string, string> = {
  "chatgpt-codex": "Sign in with your ChatGPT subscription - no API key, no per-token billing.",
  anthropic: "Paste an Anthropic API key from console.anthropic.com.",
  openai: "Paste an OpenAI API key from platform.openai.com.",
};

/** The auth method for a provider id. Everything that is not a subscription is a key. */
export function authKindFor(id: string): AuthKind {
  return SUBSCRIPTION_IDS.has(id) ? "subscription" : "api-key";
}

/** The short, right-aligned auth hint on a provider row. */
export function authHintLabel(auth: AuthKind): string {
  return auth === "subscription" ? "subscription" : "API key";
}

export interface ConnectGroup {
  /** Stable group id, e.g. "popular" or "all". */
  readonly id: string;
  /** Heading label, e.g. "Popular". */
  readonly label: string;
}

const POPULAR_GROUP: ConnectGroup = { id: "popular", label: "Popular" };
const ALL_GROUP: ConnectGroup = { id: "all", label: "All providers" };

export interface ConnectProvider {
  readonly id: string;
  readonly label: string;
  readonly auth: AuthKind;
  /** True when an env var OR the credential store holds a credential. */
  readonly connected: boolean;
  /** Where the connection was verified: "env" or "stored". Undefined when dark. */
  readonly source?: "env" | "stored";
  /** The env var that actually held the credential, when connected via env. */
  readonly via?: string;
  /** One-line setup instruction from `PROVIDERS`. */
  readonly hint: string;
  /** Plain-language subtitle, for recommended providers. */
  readonly subtitle?: string;
  /** On-disk credential location, for providers that have one. */
  readonly fileSource?: string;
  readonly envVars: readonly string[];
}

export interface ConnectSources {
  /** Provider states over the environment (from `providerStates`). */
  states: readonly ProviderState[];
  /** Provider ids that have a value in the on-disk credential store. */
  stored?: ReadonlySet<string> | readonly string[];
}

/** Does any provider hold a real credential? Drives the onboarding nudge. */
export function hasAnyConnection({ states, stored }: ConnectSources): boolean {
  if (states.some((state) => state.configured)) return true;
  const storedSet = stored instanceof Set ? stored : new Set(stored ?? []);
  return storedSet.size > 0;
}

/** Everything sayable about one provider, folding env and stored credentials. */
function connectProviderFor(
  info: ProviderState,
  storedSet: ReadonlySet<string>,
): ConnectProvider {
  // Env wins: an explicit export is the credential the runtime will actually
  // use, so it is the one the screen must report as the live source.
  const source: ConnectProvider["source"] = info.configured
    ? "env"
    : storedSet.has(info.id)
      ? "stored"
      : undefined;
  return {
    id: info.id,
    label: info.label,
    auth: authKindFor(info.id),
    connected: source !== undefined,
    source,
    via: info.via,
    hint: info.hint,
    subtitle: PROVIDER_SUBTITLE[info.id],
    fileSource: info.fileSource,
    envVars: info.envVars,
  };
}

// ---------------------------------------------------------------------------
// Row model
// ---------------------------------------------------------------------------

export type ConnectRow =
  | { readonly kind: "heading"; readonly group: ConnectGroup }
  | { readonly kind: "subtitle"; readonly group: ConnectGroup; readonly text: string }
  | {
      readonly kind: "provider";
      readonly group: ConnectGroup;
      readonly provider: ConnectProvider;
    };

export interface ConnectRowsInput extends Partial<ConnectSources> {
  filter?: string;
}

/** Byte-order compare: locale-independent so the order never shifts. */
function compareStrings(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/**
 * Flattens the provider table into a "Popular" group followed by "All
 * providers", each a heading then its provider rows. A recommended provider
 * with a subtitle emits a non-selectable subtitle row beneath it.
 *
 * A heading is only emitted when at least one provider under it survives the
 * filter, and the two groups are disjoint: a provider in the popular group is
 * not repeated under "all". The filter is AND-over-terms across the provider
 * id, its label and its auth hint.
 */
export function buildConnectRows({
  states = providerStates({}),
  stored,
  filter = "",
}: ConnectRowsInput = {}): ConnectRow[] {
  const storedSet = stored instanceof Set ? stored : new Set(stored ?? []);
  const terms = sanitizeTuiText(filter).toLowerCase().split(" ").filter(Boolean);

  const byId = new Map<string, ConnectProvider>();
  for (const state of states) {
    if (!state || typeof state.id !== "string" || state.id.length === 0) continue;
    byId.set(state.id, connectProviderFor(state, storedSet));
  }

  const matches = (provider: ConnectProvider): boolean => {
    if (terms.length === 0) return true;
    const haystack =
      `${provider.id} ${provider.label} ${authHintLabel(provider.auth)}`.toLowerCase();
    return terms.every((term) => haystack.includes(term));
  };

  const recommended = RECOMMENDED_IDS.map((id) => byId.get(id)).filter(
    (provider): provider is ConnectProvider => provider !== undefined,
  );
  const recommendedIds = new Set(recommended.map((provider) => provider.id));
  const rest = [...byId.values()]
    .filter((provider) => !recommendedIds.has(provider.id))
    .sort((a, b) => compareStrings(a.id, b.id));

  const rows: ConnectRow[] = [];
  const pushGroup = (group: ConnectGroup, providers: readonly ConnectProvider[]) => {
    const shown = providers.filter(matches);
    if (shown.length === 0) return;
    rows.push({ kind: "heading", group });
    for (const provider of shown) {
      rows.push({ kind: "provider", group, provider });
      if (group.id === "popular" && provider.subtitle) {
        rows.push({ kind: "subtitle", group, text: provider.subtitle });
      }
    }
  };

  pushGroup(POPULAR_GROUP, recommended);
  pushGroup(ALL_GROUP, rest);
  return rows;
}

/** A provider row is selectable; headings and subtitles are not. */
function isSelectable(row: ConnectRow | undefined): boolean {
  return row?.kind === "provider";
}

/** Index of the first selectable row, or -1. */
export function firstSelectableIndex(rows: readonly ConnectRow[]): number {
  for (let index = 0; index < rows.length; index++) {
    if (isSelectable(rows[index])) return index;
  }
  return -1;
}

/** Index of the last selectable row, or -1. */
export function lastSelectableIndex(rows: readonly ConnectRow[]): number {
  for (let index = rows.length - 1; index >= 0; index--) {
    if (isSelectable(rows[index])) return index;
  }
  return -1;
}

/** Index of a provider by id, or -1. */
export function indexOfProvider(rows: readonly ConnectRow[], id: string | undefined): number {
  if (!id) return -1;
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index];
    if (row?.kind === "provider" && row.provider.id === id) return index;
  }
  return -1;
}

/**
 * Pulls an arbitrary index onto a selectable row: forward first so the cursor
 * stays near where the list was, then backward, then -1 when nothing selects.
 */
export function clampSelection(rows: readonly ConnectRow[], current: number): number {
  if (rows.length === 0) return -1;
  const start = clamp(Math.trunc(Number.isFinite(current) ? current : 0), 0, rows.length - 1);
  for (let index = start; index < rows.length; index++) {
    if (isSelectable(rows[index])) return index;
  }
  for (let index = start - 1; index >= 0; index--) {
    if (isSelectable(rows[index])) return index;
  }
  return -1;
}

/** Moves the selection by `delta` rows, skipping headings/subtitles and wrapping. */
export function moveSelection(rows: readonly ConnectRow[], current: number, delta: number): number {
  const total = rows.length;
  if (total === 0) return -1;
  const anchor = clampSelection(rows, current);
  if (anchor < 0) return -1;

  const step = delta >= 0 ? 1 : -1;
  const truncated = Math.trunc(Number.isFinite(delta) ? delta : 0);
  const count = Math.max(1, Math.abs(truncated) || 1);

  let index = anchor;
  for (let moved = 0; moved < count; moved++) {
    let probe = index;
    for (let guard = 0; guard < total; guard++) {
      probe = (probe + step + total) % total;
      if (isSelectable(rows[probe])) break;
    }
    if (!isSelectable(rows[probe])) return anchor;
    index = probe;
  }
  return index;
}

// ---------------------------------------------------------------------------
// Windowing (mirrors computeModelWindow)
// ---------------------------------------------------------------------------

export interface ConnectWindowInput {
  rows: readonly ConnectRow[];
  selected: number;
  visible: number;
  anchor?: number;
}

export interface ConnectWindow {
  start: number;
  end: number;
  count: number;
  total: number;
  hasAbove: boolean;
  hasBelow: boolean;
}

/**
 * Scroll-into-view windowing, anchored on the caller's last start so the list
 * scrolls rather than re-centres. When the cursor is the first provider of a
 * group, the window is pulled up to keep that group's heading on screen — the
 * heading is where the group's identity lives.
 */
export function computeConnectWindow({
  rows,
  selected,
  visible,
  anchor = 0,
}: ConnectWindowInput): ConnectWindow {
  const total = rows.length;
  const capacity = Math.min(cells(visible), total);
  if (capacity <= 0) {
    return { start: 0, end: 0, count: 0, total, hasAbove: total > 0, hasBelow: false };
  }

  const maxStart = Math.max(0, total - capacity);
  let start = clamp(cells(anchor), 0, maxStart);

  const cursor = Math.trunc(Number.isFinite(selected) ? selected : -1);
  if (cursor >= 0 && cursor < total) {
    const wanted = capacity >= 2 && rows[cursor - 1]?.kind === "heading" ? cursor - 1 : cursor;
    if (cursor > start + capacity - 1) start = cursor - capacity + 1;
    if (wanted < start) start = wanted;
    start = clamp(start, 0, maxStart);
  }

  const end = Math.min(total, start + capacity);
  return {
    start,
    end,
    count: end - start,
    total,
    hasAbove: start > 0,
    hasBelow: end < total,
  };
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

/** Below this the detail pane cannot sit beside the list and stacks under it. */
const TWO_PANE_MIN_WIDTH = 76;
const DETAIL_MIN_WIDTH = 30;
const DETAIL_MAX_WIDTH = 56;
const DETAIL_WIDTH_SHARE = 0.44;
const LIST_MIN_WIDTH = 34;
/** Widest the auth hint column gets; "subscription" is 12 cells. */
const AUTH_MAX_WIDTH = 12;
const AUTH_WIDTH_SHARE = 0.42;
/** Below this a row cannot afford an auth column at all. */
const AUTH_MIN_ROOM = 26;
/** Widest a heading's state column gets; "3 connected" is 11 cells. */
const STATE_MAX_WIDTH = 12;
const HEADING_LABEL_MIN = 8;
const HEADING_STATE_MIN_ROOM = 22;
const BORDERED_MIN_ROWS = 12;
const STACKED_DETAIL_SHARE = 0.4;
const STACKED_DETAIL_MAX_ROWS = 10;

export interface ConnectPane {
  width: number;
  innerWidth: number;
  height: number;
  bodyRows: number;
  hasTitle: boolean;
}

export interface ConnectRowLayout {
  /** Total cells a list row occupies; equals the list pane's inner width. */
  width: number;
  markerWidth: number;
  markerGap: number;
  /** Connected-state check column. 0 when the row cannot spare it. */
  checkWidth: number;
  checkGap: number;
  /** The provider label. */
  labelWidth: number;
  authGap: number;
  /** Right-aligned auth hint. 0 when the row can only afford a label. */
  authWidth: number;
}

export interface ConnectHeadingLayout {
  width: number;
  labelWidth: number;
  gap: number;
  stateWidth: number;
}

export interface ConnectLayoutInput {
  width: number;
  height: number;
  /** 1 when the status line under the panes is rendered. */
  noticeRows?: number;
}

export interface ConnectLayout {
  stacked: boolean;
  bordered: boolean;
  contentWidth: number;
  bodyRows: number;
  paneGap: number;
  list: ConnectPane;
  detail: ConnectPane;
  row: ConnectRowLayout;
  heading: ConnectHeadingLayout;
  visibleRows: number;
  detailCompact: boolean;
}

function borderChrome(bordered: boolean): { horizontal: number; vertical: number } {
  return bordered ? { horizontal: 4, vertical: 2 } : { horizontal: 0, vertical: 0 };
}

function makePane(
  width: number,
  height: number,
  chromeH: number,
  chromeV: number,
  hasTitle: boolean,
): ConnectPane {
  const outerWidth = cells(width);
  const outerHeight = cells(height);
  const verticalChrome = chromeV + (hasTitle ? 1 : 0);
  if (outerWidth <= chromeH || outerHeight <= verticalChrome) {
    return { width: 0, innerWidth: 0, height: 0, bodyRows: 0, hasTitle };
  }
  return {
    width: outerWidth,
    innerWidth: outerWidth - chromeH,
    height: outerHeight,
    bodyRows: outerHeight - verticalChrome,
    hasTitle,
  };
}

/**
 * Splits a list row into cursor, check, label and auth columns. The auth hint
 * gives way first, then the check, then the cursor; the label always survives.
 * Every separator is a real gap, never a padded literal — `sanitizeTuiText`
 * trims, so a literal space would collapse and fuse two columns.
 */
function computeRowLayout(innerWidth: number): ConnectRowLayout {
  const width = cells(innerWidth);
  if (width <= 0) {
    return {
      width: 0,
      markerWidth: 0,
      markerGap: 0,
      checkWidth: 0,
      checkGap: 0,
      labelWidth: 0,
      authGap: 0,
      authWidth: 0,
    };
  }

  const markerWidth = width >= 8 ? 1 : 0;
  const markerGap = markerWidth > 0 && width > markerWidth ? 1 : 0;
  const afterMarker = Math.max(0, width - markerWidth - markerGap);

  const checkWidth = afterMarker >= 10 ? 1 : 0;
  const checkGap = checkWidth > 0 && afterMarker > checkWidth ? 1 : 0;
  const afterCheck = Math.max(0, afterMarker - checkWidth - checkGap);

  const authWidth =
    afterCheck >= AUTH_MIN_ROOM
      ? Math.min(AUTH_MAX_WIDTH, Math.floor(afterCheck * AUTH_WIDTH_SHARE))
      : 0;
  const authGap = authWidth > 0 && afterCheck > authWidth ? 1 : 0;
  const labelWidth = Math.max(0, afterCheck - authWidth - authGap);

  return { width, markerWidth, markerGap, checkWidth, checkGap, labelWidth, authGap, authWidth };
}

/** Splits a heading into its label and its right-aligned state column. */
function computeHeadingLayout(innerWidth: number): ConnectHeadingLayout {
  const width = cells(innerWidth);
  if (width <= 0) return { width: 0, labelWidth: 0, gap: 0, stateWidth: 0 };
  if (width < HEADING_STATE_MIN_ROOM) {
    return { width, labelWidth: width, gap: 0, stateWidth: 0 };
  }
  const stateWidth = clamp(
    Math.min(STATE_MAX_WIDTH, Math.floor(width * 0.4)),
    0,
    Math.max(0, width - HEADING_LABEL_MIN - 1),
  );
  const gap = stateWidth > 0 ? 1 : 0;
  return { width, labelWidth: Math.max(0, width - stateWidth - gap), gap, stateWidth };
}

/** The full geometry of the connect screen. Mirrors `computeModelLayout`. */
export function computeConnectLayout({
  width,
  height,
  noticeRows = 0,
}: ConnectLayoutInput): ConnectLayout {
  const terminalWidth = cells(width);
  const contentWidth = Math.max(0, terminalWidth - 4);
  const bodyRows = Math.max(
    0,
    cells(height) - shellChromeRows(terminalWidth) - Math.min(1, cells(noticeRows)),
  );

  const bordered = bodyRows >= BORDERED_MIN_ROWS && contentWidth >= DETAIL_MIN_WIDTH + 4;
  const chrome = borderChrome(bordered);
  const listMinHeight = chrome.vertical + 1 + 1;
  const detailMinHeight = chrome.vertical + 1;

  // -- horizontal split --
  const canSplit = contentWidth >= TWO_PANE_MIN_WIDTH;
  const paneGap = canSplit ? 1 : 0;
  let detailWidth = 0;
  let listWidth = contentWidth;
  if (canSplit) {
    const available = contentWidth - paneGap;
    const wanted = clamp(
      Math.floor(available * DETAIL_WIDTH_SHARE),
      DETAIL_MIN_WIDTH,
      DETAIL_MAX_WIDTH,
    );
    detailWidth = clamp(wanted, 0, Math.max(0, available - LIST_MIN_WIDTH));
    listWidth = available - detailWidth;
  }
  const stacked = detailWidth <= 0;
  if (stacked) {
    detailWidth = contentWidth;
    listWidth = contentWidth;
  }

  // -- vertical split --
  let listHeight = 0;
  let detailHeight = 0;
  if (bodyRows >= listMinHeight) {
    if (stacked) {
      const wanted = Math.min(Math.floor(bodyRows * STACKED_DETAIL_SHARE), STACKED_DETAIL_MAX_ROWS);
      detailHeight = wanted >= detailMinHeight + 1 && bodyRows - wanted >= listMinHeight ? wanted : 0;
      listHeight = bodyRows - detailHeight;
    } else {
      listHeight = bodyRows;
      detailHeight = bodyRows >= detailMinHeight ? bodyRows : 0;
    }
  }

  const list = makePane(listWidth, listHeight, chrome.horizontal, chrome.vertical, true);
  const detail = makePane(detailWidth, detailHeight, chrome.horizontal, chrome.vertical, !stacked);

  return {
    stacked,
    bordered,
    contentWidth,
    bodyRows,
    paneGap: list.width > 0 && detail.width > 0 && !stacked ? paneGap : 0,
    list,
    detail,
    row: computeRowLayout(list.innerWidth),
    heading: computeHeadingLayout(list.innerWidth),
    visibleRows: list.bodyRows,
    detailCompact: !bordered,
  };
}

// ---------------------------------------------------------------------------
// Detail pane
// ---------------------------------------------------------------------------

export type ConnectDetailTone = "title" | "text" | "muted" | "accent" | "ok" | "warn" | "blank";

export interface ConnectDetailLine {
  readonly text: string;
  readonly tone: ConnectDetailTone;
}

export interface ConnectDetailInput {
  row?: ConnectRow;
  compact?: boolean;
}

/**
 * The detail pane body for the highlighted provider, as tone-tagged lines.
 * Content is decided here and colour by the component, so the pane is testable
 * without a renderer. Every field uses a `": "` separator rather than
 * alignment columns, because `sanitizeTuiText` would trim padded literals.
 */
export function connectDetailLines(
  { row, compact = false }: ConnectDetailInput,
  width: number,
): ConnectDetailLine[] {
  const limit = cells(width);
  if (!row || row.kind !== "provider" || limit <= 0) return [];

  const provider = row.provider;
  const lines: ConnectDetailLine[] = [];
  const push = (value: string, tone: ConnectDetailTone) => {
    for (const text of wrapCells(value, limit)) lines.push({ text, tone });
  };
  const separate = () => {
    if (!compact) lines.push({ text: "", tone: "blank" });
  };

  push(provider.label, "title");
  if (provider.subtitle) {
    separate();
    push(provider.subtitle, "accent");
  }
  separate();

  push(
    provider.auth === "subscription" ? "Auth: subscription sign-in" : "Auth: API key",
    "text",
  );

  separate();
  if (provider.connected) {
    if (provider.source === "env") {
      push(`Connected: credential found in ${provider.via ?? "the environment"}`, "ok");
    } else {
      push("Connected: credential stored on this machine", "ok");
      if (provider.envVars.length > 0) {
        push(`Exported to the runtime as ${provider.envVars[0]}`, "muted");
      }
    }
  } else {
    push("Not connected in this environment", "warn");
    if (provider.envVars.length > 0) push(`Reads: ${provider.envVars.join(", ")}`, "muted");
    if (provider.hint) push(`Setup: ${provider.hint}`, "muted");
    if (provider.fileSource) {
      push(`Also read from ${provider.fileSource}, which is not checked here.`, "muted");
    }
  }

  separate();
  push(
    provider.auth === "subscription"
      ? "Enter: start the subscription sign-in and paste your token."
      : "Enter: paste an API key. It is stored owner-only on this machine.",
    "muted",
  );

  return lines;
}

/** Trims detail lines to the rows the pane holds, marking the cut. */
export function clipConnectDetailLines(
  lines: readonly ConnectDetailLine[],
  rows: number,
  width = 0,
): ConnectDetailLine[] {
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
// Status line, titles, hints and keys
// ---------------------------------------------------------------------------

/** The always-on status line under the panes: how many providers are connected. */
export function connectStatusLine(rows: readonly ConnectRow[]): string {
  const seen = new Set<string>();
  let connected = 0;
  for (const row of rows) {
    if (row.kind !== "provider") continue;
    if (seen.has(row.provider.id)) continue;
    seen.add(row.provider.id);
    if (row.provider.connected) connected++;
  }
  if (seen.size === 0) return "no providers to connect";
  if (connected === 0) return "no providers connected yet - select one to connect";
  return `connected: ${connected} of ${seen.size} provider${seen.size === 1 ? "" : "s"}`;
}

/** `PROVIDERS 4-15/20`, or `PROVIDERS 20` when the whole list is on screen. */
export function connectListTitle(window: ConnectWindow): string {
  if (window.total === 0) return "PROVIDERS 0";
  if (!window.hasAbove && !window.hasBelow) return `PROVIDERS ${window.total}`;
  return `PROVIDERS ${window.start + 1}-${window.end}/${window.total}`;
}

export type ConnectMode = "browse" | "filter" | "input";

/**
 * The prompt shown while the operator is pasting a credential. The secret is
 * NEVER echoed: only a fixed dot run capped at 8 cells signals that something
 * was typed, so neither the value nor its exact length reaches the screen.
 */
export function connectInputMask(secretLength: number): string {
  const length = cells(secretLength);
  if (length === 0) return "";
  const dots = "•".repeat(Math.min(length, 8));
  return length > 8 ? `${dots}…` : dots;
}

/** The footer hint, per mode. Names the real bindings. */
export function connectFooterHint(mode: ConnectMode, hasFilter = false): string {
  if (mode === "input") return "paste credential · enter save · esc cancel";
  if (mode === "filter") return "type to filter · enter connect · esc done · backspace delete";
  return [
    "up/down move",
    "enter connect",
    "/ filter",
    hasFilter ? "esc clear filter" : "esc back",
    "ctrl+c exit",
  ].join(" · ");
}

/** Every printable single character reaches the filter. */
export function isFilterKey(sequence: unknown): boolean {
  if (typeof sequence !== "string" || sequence.length !== 1) return false;
  const code = sequence.charCodeAt(0);
  return code >= 0x20 && code !== 0x7f;
}

/**
 * Whether a single keystroke should be appended to the credential input.
 *
 * Broader than `isFilterKey` in intent (a pasted key can contain any printable
 * character), but the same test: one printable, non-control character.
 */
export function isInputKey(sequence: unknown): boolean {
  return isFilterKey(sequence);
}

/**
 * The printable characters of a key sequence, control characters stripped.
 *
 * A pasted credential can arrive as one key event whose sequence is the whole
 * paste, so the input sub-step appends `pastableChars(seq)` rather than a
 * single character — this keeps a pasted key intact while dropping any stray
 * control bytes (a trailing newline from the paste, an escape) that would
 * otherwise corrupt the stored secret.
 */
export function pastableChars(sequence: unknown): string {
  if (typeof sequence !== "string") return "";
  let out = "";
  for (const ch of sequence) {
    const code = ch.codePointAt(0) ?? 0;
    if (code >= 0x20 && code !== 0x7f) out += ch;
  }
  return out;
}

/** All providers, for callers that want the raw list (e.g. a test guard). */
export { PROVIDERS };
