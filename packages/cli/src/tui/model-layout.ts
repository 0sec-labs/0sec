/**
 * Layout, navigation and windowing arithmetic for the full-screen model
 * picker.
 *
 * This is `settings-layout.ts` for `/model`, and it exists for the same reason
 * spelled out in `PRIMITIVES.md`: OpenTUI lays rows out with Yoga, and Yoga
 * *shrinks* siblings rather than clipping them. Two `<text>` nodes that
 * together want more cells than their row has are both painted in full into
 * boxes that are now too small, and the terminal shows the two strings
 * interleaved character by character — `runs12`, `target:cnone`. The same
 * failure on the vertical axis makes a bordered box paint its own bottom
 * border through its last content row. So the component reads widths and row
 * counts off a `ModelLayout` and never computes one, and a sweep hammers every
 * number in here across widths 0..200 and heights 0..80.
 *
 * ## Why the screen exists at all
 *
 * `/model` used to open a compact picker floating above the composer: a flat
 * list of 43 ids with a `provider · price` caption each. That shape has no
 * room for the one thing an operator actually needs before switching model,
 * which is whether this machine holds credentials for the vendor at all. A
 * turn started against a dark provider dies with zero tokens and a message
 * about a key nobody knew they needed.
 *
 * ## The accuracy rule this module is built around
 *
 * Credential state is reported **per provider**, never per model.
 *
 * A previous attempt annotated each row "no credentials" using the provider
 * that `model-catalog.ts` carries. That was wrong and was reverted. The
 * catalogue's provider comes from the pricing table (`modelProvider`, a
 * prefix match on the id), while the runtime resolves a model's provider
 * through its own detection and failover order — `providerForModel` in
 * `packages/core/src/runtime/llm-api.ts`, which core does not export. Those
 * two disagree in practice: an OpenAI-named model can in fact be served by the
 * ChatGPT/Codex backend, so a per-row verdict flags working models as broken,
 * which is the worst possible failure for a screen whose whole selling point
 * is telling the truth about reachability.
 *
 * What is verifiable from here is which *providers* hold credentials in the
 * environment, and that is all this module claims: a state on each provider
 * heading, the full env-var and setup detail in the detail pane, and — when
 * the highlighted model's nominal provider is dark while some other provider
 * is lit — a line naming the lit ones, so the operator can judge. There is no
 * "you cannot use this model" anywhere, by design.
 *
 * ## Reuse
 *
 * `shellChromeRows` and `wrapCells` are imported from `settings-layout.ts`
 * rather than copied. `shellChromeRows` in particular is the *corrected*
 * mirror of `run.tsx`'s `getShellChromeHeight`: the original assumes a
 * one-row footer, but `FooterBar` stacks to three rows below 64 content
 * cells, and a screen that fills its column — as this one does — overflows by
 * two rows on every narrow terminal if it believes the original. Neither
 * helper is settings-specific; the honest long-term home for both is a shared
 * `shell-geometry.ts`, and this import is the marker for that move.
 */

import { buildModelCatalog, type CatalogModel } from "./model-catalog.js";
import { PROVIDERS, providerStates, type ProviderState } from "./provider-status.js";
import { shellChromeRows, wrapCells } from "./settings-layout.js";
import { sanitizeTuiText } from "./text.js";

export { shellChromeRows, wrapCells };

// ---------------------------------------------------------------------------
// Numeric hygiene
// ---------------------------------------------------------------------------

/**
 * Cell and row counts are non-negative integers.
 *
 * Terminal geometry arrives from `useTerminalDimensions`, which reports 0 on a
 * detached tty and can report a fractional or `NaN` size mid-resize. Yoga
 * accepts all of those and lays out sub-cell boxes that round inconsistently
 * between siblings, which is itself an overlap.
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
// Providers
// ---------------------------------------------------------------------------

/**
 * What can be said about a provider without lying.
 *
 * - `ready`   — an env var listed in `PROVIDERS` holds a credential.
 * - `missing` — the runtime knows how to reach this provider, but nothing in
 *               the environment authenticates it. Note that `providerStates`
 *               never stats the filesystem, so a provider with a `fileSource`
 *               can read `missing` here while the runtime still finds an
 *               on-disk token; the detail pane says so rather than pretending.
 * - `unmapped` — the pricing table names a vendor the runtime has no direct
 *               env path for at all (`google`, `meta`, `mistral`, `unknown`).
 *               These are reachable, if at all, through an aggregator such as
 *               OpenRouter, which is a routing question this module cannot
 *               answer.
 */
export type ProviderCredential = "ready" | "missing" | "unmapped";

export interface ModelProviderGroup {
  /** Provider id exactly as the catalogue reports it, e.g. "z-ai". */
  readonly id: string;
  /** Human label from `PROVIDERS`, or the id title-cased when unmapped. */
  readonly label: string;
  readonly credential: ProviderCredential;
  /** The env var that actually held the credential, when `ready`. */
  readonly via?: string;
  /** One-line setup instruction from `PROVIDERS`, when the runtime knows one. */
  readonly hint?: string;
  /** On-disk credential location, for providers that have one. */
  readonly fileSource?: string;
  readonly envVars: readonly string[];
}

/** `z-ai` -> `Z Ai`. Only ever reached for providers `PROVIDERS` omits. */
function titleCase(id: string): string {
  return sanitizeTuiText(id)
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

/** Everything sayable about the provider behind a catalogue entry. */
export function providerGroupFor(
  id: string,
  states: readonly ProviderState[],
): ModelProviderGroup {
  const state = states.find((candidate) => candidate.id === id);
  if (!state) {
    return {
      id,
      label: titleCase(id) || id,
      credential: "unmapped",
      envVars: [],
    };
  }
  return {
    id: state.id,
    label: state.label,
    credential: state.configured ? "ready" : "missing",
    via: state.via,
    hint: state.hint,
    fileSource: state.fileSource,
    envVars: state.envVars,
  };
}

/** How a provider's credential state reads on its group heading. */
export function credentialLabel(credential: ProviderCredential): string {
  switch (credential) {
    case "ready":
      return "ready";
    case "missing":
      return "no credentials";
    default:
      return "no setup path";
  }
}

/** Labels of every provider that currently holds a credential. */
export function configuredProviderLabels(states: readonly ProviderState[]): string[] {
  return states.filter((state) => state.configured).map((state) => state.label);
}

/**
 * The always-on status line under the panes.
 *
 * This is the screen's one unconditional statement of fact, and it is a
 * provider-level one. It matters most for the operator whose only credential
 * is ChatGPT Codex: every group heading on this screen will read "no
 * credentials", because the catalogue has no chatgpt-codex models to group
 * under, and without this line that reads as "nothing works".
 */
export function credentialSummary(states: readonly ProviderState[]): string {
  const labels = configuredProviderLabels(states);
  if (labels.length === 0) {
    return "credentials: none detected in this environment - see /doctor";
  }
  return `credentials: ${labels.join(", ")}`;
}

// ---------------------------------------------------------------------------
// Row model
// ---------------------------------------------------------------------------

export type ModelRow =
  | { readonly kind: "heading"; readonly group: ModelProviderGroup; readonly count: number }
  | {
      readonly kind: "model";
      readonly group: ModelProviderGroup;
      readonly model: CatalogModel;
      readonly active: boolean;
    };

export interface ModelRowsInput {
  /** Defaults to the live catalogue; a test may pass its own. */
  catalog?: readonly CatalogModel[];
  /** Defaults to an empty environment, i.e. nothing configured. */
  states?: readonly ProviderState[];
  filter?: string;
  /** The model the session is currently running. */
  activeModel?: string;
}

/** Byte-order compare: locale-independent so the order never shifts. */
function compareStrings(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

const PROVIDER_ORDER = new Map(PROVIDERS.map((info, index) => [info.id, index]));

/**
 * Group ordering: the active model's provider, then the providers that hold
 * credentials, then the ones the runtime could reach if configured, then the
 * vendors it has no direct path to.
 *
 * This is a statement about providers, not about models — the ordering says
 * "these vendors are authenticated", which is verifiable, and never "this
 * model will not run", which is not. Within each band the order is the
 * `PROVIDERS` table's own priority (which mirrors the runtime's env-priority
 * chain), with unmapped vendors falling to the end alphabetically, so the list
 * is stable across renders and across sessions.
 */
function groupRank(group: ModelProviderGroup, activeProvider: string | undefined): number {
  if (activeProvider !== undefined && group.id === activeProvider) return 0;
  switch (group.credential) {
    case "ready":
      return 1;
    case "missing":
      return 2;
    default:
      return 3;
  }
}

/**
 * Flattens the catalogue into provider headings and model rows, honouring an
 * optional filter.
 *
 * A heading is only emitted when at least one model under it survived the
 * filter: a heading with nothing beneath it is a row of noise, and on this
 * screen it would also be a credential claim about a vendor the operator did
 * not ask about.
 *
 * The filter is AND-over-terms across the model id, the provider id, the
 * provider label and the formatted price. Matching the provider label is what
 * makes "anthropic" and "Moonshot" both work, and matching the price is what
 * makes "free" a usable query.
 */
export function buildModelRows({
  catalog = buildModelCatalog(),
  states = providerStates({}),
  filter = "",
  activeModel,
}: ModelRowsInput = {}): ModelRow[] {
  const terms = sanitizeTuiText(filter).toLowerCase().split(" ").filter(Boolean);
  const groups = new Map<string, ModelProviderGroup>();
  const byProvider = new Map<string, CatalogModel[]>();

  for (const model of catalog) {
    if (!model || typeof model.id !== "string" || model.id.length === 0) continue;
    const providerId = typeof model.provider === "string" && model.provider.length > 0
      ? model.provider
      : "unknown";
    let group = groups.get(providerId);
    if (!group) {
      group = providerGroupFor(providerId, states);
      groups.set(providerId, group);
    }
    const haystack = `${model.id} ${group.id} ${group.label} ${model.price}`.toLowerCase();
    if (terms.length > 0 && !terms.every((term) => haystack.includes(term))) continue;
    const bucket = byProvider.get(providerId);
    if (bucket) bucket.push(model);
    else byProvider.set(providerId, [model]);
  }

  const activeProvider = [...byProvider.entries()].find(([, models]) =>
    models.some((model) => model.id === activeModel),
  )?.[0];

  const order = [...byProvider.keys()].sort((a, b) => {
    const left = groups.get(a);
    const right = groups.get(b);
    if (!left || !right) return compareStrings(a, b);
    return (
      groupRank(left, activeProvider) - groupRank(right, activeProvider) ||
      (PROVIDER_ORDER.get(a) ?? Number.MAX_SAFE_INTEGER) -
        (PROVIDER_ORDER.get(b) ?? Number.MAX_SAFE_INTEGER) ||
      compareStrings(a, b)
    );
  });

  const rows: ModelRow[] = [];
  for (const providerId of order) {
    const group = groups.get(providerId);
    const models = byProvider.get(providerId);
    if (!group || !models || models.length === 0) continue;
    // The active model floats to the top of its own group: it is the row the
    // operator most often opened the screen to confirm, and it doubles as the
    // initial highlight.
    const sorted = [...models].sort((a, b) => {
      if (a.id === activeModel) return b.id === activeModel ? 0 : -1;
      if (b.id === activeModel) return 1;
      return compareStrings(a.id, b.id);
    });
    rows.push({ kind: "heading", group, count: sorted.length });
    for (const model of sorted) {
      rows.push({ kind: "model", group, model, active: model.id === activeModel });
    }
  }
  return rows;
}

/** Index of the first selectable row, or -1 when the list has none. */
export function firstSelectableIndex(rows: readonly ModelRow[]): number {
  for (let index = 0; index < rows.length; index++) {
    if (rows[index]?.kind === "model") return index;
  }
  return -1;
}

/** Index of the last selectable row, or -1 when the list has none. */
export function lastSelectableIndex(rows: readonly ModelRow[]): number {
  for (let index = rows.length - 1; index >= 0; index--) {
    if (rows[index]?.kind === "model") return index;
  }
  return -1;
}

/** Index of a model by id, or -1. Used to open the screen on the active row. */
export function indexOfModel(rows: readonly ModelRow[], id: string | undefined): number {
  if (!id) return -1;
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index];
    if (row?.kind === "model" && row.model.id === id) return index;
  }
  return -1;
}

/**
 * Pulls an arbitrary index onto a selectable row.
 *
 * Filtering is the reason this exists: the highlighted row can vanish from
 * under the cursor between two keystrokes, and the selection then has to land
 * somewhere sane rather than on a heading or past the end. Searching forward
 * first keeps the cursor near where the list was, which reads better than
 * snapping back to the top on every keystroke.
 */
export function clampSelection(rows: readonly ModelRow[], current: number): number {
  if (rows.length === 0) return -1;
  const start = clamp(Math.trunc(Number.isFinite(current) ? current : 0), 0, rows.length - 1);
  for (let index = start; index < rows.length; index++) {
    if (rows[index]?.kind === "model") return index;
  }
  for (let index = start - 1; index >= 0; index--) {
    if (rows[index]?.kind === "model") return index;
  }
  return -1;
}

/**
 * Moves the selection by `delta` rows, skipping provider headings and
 * wrapping.
 *
 * Wrapping matters more here than on the settings screen: the catalogue is 43
 * models under ten headings, and the vendor an operator wants is as often at
 * the bottom as the top. The inner guard loop is bounded by the list length so
 * a list of nothing but headings terminates instead of spinning.
 */
export function moveSelection(rows: readonly ModelRow[], current: number, delta: number): number {
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
      if (rows[probe]?.kind === "model") break;
    }
    if (rows[probe]?.kind !== "model") return anchor;
    index = probe;
  }
  return index;
}

// ---------------------------------------------------------------------------
// Windowing
// ---------------------------------------------------------------------------

export interface ModelWindowInput {
  rows: readonly ModelRow[];
  /** Highlighted row index, or -1 when the filter matched nothing. */
  selected: number;
  /** Rows the list body can actually paint. */
  visible: number;
  /** Previous window start, so the list scrolls instead of re-centring. */
  anchor?: number;
}

export interface ModelWindow {
  start: number;
  /** Exclusive. `rows.slice(start, end)` is exactly what may be rendered. */
  end: number;
  /** `end - start`; never exceeds `visible` and never exceeds `rows.length`. */
  count: number;
  total: number;
  hasAbove: boolean;
  hasBelow: boolean;
}

/**
 * Scroll-into-view windowing, stateless apart from the caller's last start.
 *
 * Taking the previous start as an anchor rather than re-centring on every move
 * is the difference between a list that scrolls and a list that jumps: with
 * centring, a single down-arrow shifts every visible row by one even when the
 * cursor was comfortably mid-pane.
 *
 * The heading rule is load-bearing on this screen. When the cursor lands on
 * the first model of a provider, the window is pulled up one extra row so that
 * provider's heading comes with it — and that heading is where the credential
 * state is written. A model list scrolled past its own headings is a list that
 * has stopped saying which vendor you are looking at, which is the entire
 * reason this screen replaced the picker.
 */
export function computeModelWindow({
  rows,
  selected,
  visible,
  anchor = 0,
}: ModelWindowInput): ModelWindow {
  const total = rows.length;
  const capacity = Math.min(cells(visible), total);
  if (capacity <= 0) {
    return { start: 0, end: 0, count: 0, total, hasAbove: total > 0, hasBelow: false };
  }

  const maxStart = Math.max(0, total - capacity);
  let start = clamp(cells(anchor), 0, maxStart);

  const cursor = Math.trunc(Number.isFinite(selected) ? selected : -1);
  if (cursor >= 0 && cursor < total) {
    // Reserve the provider heading directly above the cursor, when there is
    // one — but only when the pane has a second row to spend on it. At a
    // capacity of one, pulling the heading in would push the cursor itself
    // out, and a window that does not contain the highlighted row is worse
    // than a window that does not name its provider.
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
/** A detail pane narrower than this wraps a setup hint into confetti. */
const DETAIL_MIN_WIDTH = 30;
/** Past this the detail pane is just whitespace; give the cells to the list. */
const DETAIL_MAX_WIDTH = 56;
/** Share of the content column the detail pane asks for when it fits beside. */
const DETAIL_WIDTH_SHARE = 0.44;
/** A list narrower than this cannot show an id and a price side by side. */
const LIST_MIN_WIDTH = 34;
/** Widest the price column ever gets; "$0.19/0.51 per M" is 16 cells. */
const PRICE_MAX_WIDTH = 16;
/** Share of a list row the price column may take on a narrow screen. */
const PRICE_WIDTH_SHARE = 0.42;
/** Below this a row cannot afford a price column at all. */
const PRICE_MIN_ROOM = 26;
/** Widest a heading's credential state gets; "no credentials" is 14 cells. */
const STATE_MAX_WIDTH = 14;
/** A heading keeps at least this much of the provider name. */
const HEADING_LABEL_MIN = 8;
/** Below this a heading drops its state column and keeps the provider name. */
const HEADING_STATE_MIN_ROOM = 22;
/** Below this the panes drop their borders rather than their content. */
const BORDERED_MIN_ROWS = 12;
/** Share of a stacked column the detail pane takes. */
const STACKED_DETAIL_SHARE = 0.4;
/** Cap on the stacked detail pane; past this the list is the better use. */
const STACKED_DETAIL_MAX_ROWS = 10;

export interface ModelPane {
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

export interface ModelRowLayout {
  /** Total cells a list row occupies; equals the list pane's inner width. */
  width: number;
  /** Cursor marker column. 0 when the row is too narrow to spare it. */
  markerWidth: number;
  markerGap: number;
  /** Active-model marker column. 0 when the row cannot spare it. */
  activeWidth: number;
  activeGap: number;
  /** The model id. */
  labelWidth: number;
  priceGap: number;
  /** Price per million. 0 when the row can only afford an id. */
  priceWidth: number;
}

export interface ModelHeadingLayout {
  /** Total cells a heading row occupies; equals the list pane's inner width. */
  width: number;
  labelWidth: number;
  gap: number;
  /** Credential state. 0 when the heading can only afford a provider name. */
  stateWidth: number;
}

export interface ModelLayoutInput {
  width: number;
  height: number;
  /** 1 when the status line under the panes is rendered. */
  noticeRows?: number;
}

export interface ModelLayout {
  /** The detail pane sits under the list rather than beside it. */
  stacked: boolean;
  /** The panes draw borders. False on a short terminal, where rows cost more. */
  bordered: boolean;
  /** Usable cells across, inside the shell's padding. */
  contentWidth: number;
  /** Rows the two panes may share. */
  bodyRows: number;
  /** Cells between the panes when side by side, else 0. */
  paneGap: number;
  list: ModelPane;
  detail: ModelPane;
  row: ModelRowLayout;
  heading: ModelHeadingLayout;
  /** List rows that fit in the list pane's body. */
  visibleRows: number;
  /**
   * The detail pane drops the blank separator lines between its sections.
   *
   * Whitespace is the first thing to cut when rows are scarce: on a short
   * terminal the detail pane gets three of them, and spending one on a blank
   * means the setup hint is a single line.
   */
  detailCompact: boolean;
}

/** A bordered pane spends four columns and two rows on its border and padding. */
function borderChrome(bordered: boolean): { horizontal: number; vertical: number } {
  return bordered ? { horizontal: 4, vertical: 2 } : { horizontal: 0, vertical: 0 };
}

function makePane(
  width: number,
  height: number,
  chromeH: number,
  chromeV: number,
  hasTitle: boolean,
): ModelPane {
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
 * Splits a list row into cursor, active-marker, id and price columns.
 *
 * Every separator is a real Yoga gap rather than a padded literal, because
 * `fitTuiText` routes through `sanitizeTuiText`, which trims — an id carrying
 * its own trailing space comes back without one and fuses onto its price even
 * when the row had cells to spare. That is the `runs12` defect, and it is
 * invisible at review time.
 *
 * The degradation ladder, widest to narrowest:
 *
 *   1. cursor + active marker + id + price   (>= 34 cells)
 *   2. cursor + active marker + id           (>= 12 after the cursor)
 *   3. cursor + id                           (>= 8)
 *   4. id alone                              (anything above zero)
 *
 * The price gives way before the active marker, and the active marker before
 * the id. A row reading `> * gpt-5.5` still says which model you are on and
 * whether it is the running one; a row reading `$5/30 per M` says neither.
 */
function computeRowLayout(innerWidth: number): ModelRowLayout {
  const width = cells(innerWidth);
  if (width <= 0) {
    return {
      width: 0,
      markerWidth: 0,
      markerGap: 0,
      activeWidth: 0,
      activeGap: 0,
      labelWidth: 0,
      priceGap: 0,
      priceWidth: 0,
    };
  }

  const markerWidth = width >= 8 ? 1 : 0;
  const markerGap = markerWidth > 0 && width > markerWidth ? 1 : 0;
  const afterMarker = Math.max(0, width - markerWidth - markerGap);

  const activeWidth = afterMarker >= 12 ? 1 : 0;
  const activeGap = activeWidth > 0 && afterMarker > activeWidth ? 1 : 0;
  const afterActive = Math.max(0, afterMarker - activeWidth - activeGap);

  const priceWidth =
    afterActive >= PRICE_MIN_ROOM
      ? Math.min(PRICE_MAX_WIDTH, Math.floor(afterActive * PRICE_WIDTH_SHARE))
      : 0;
  const priceGap = priceWidth > 0 && afterActive > priceWidth ? 1 : 0;
  const labelWidth = Math.max(0, afterActive - priceWidth - priceGap);

  return { width, markerWidth, markerGap, activeWidth, activeGap, labelWidth, priceGap, priceWidth };
}

/**
 * Splits a provider heading into its name and its credential state.
 *
 * The state column is the screen's headline claim, so it is the last thing
 * dropped — but it *is* dropped below 22 cells, because a truncated `no cre...`
 * beside a truncated provider name is worse than an honest bare name with the
 * full story one pane over.
 */
function computeHeadingLayout(innerWidth: number): ModelHeadingLayout {
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

/**
 * The full geometry of the model screen.
 *
 * Horizontally: the detail pane takes a bounded share of the content column
 * when the terminal is wide enough to hold both, and stacks underneath the
 * list otherwise. Vertically: the panes give up their borders before they give
 * up rows of content, and the detail pane is dropped entirely rather than
 * rendered at a height that would push its own border through its text.
 */
export function computeModelLayout({
  width,
  height,
  noticeRows = 0,
}: ModelLayoutInput): ModelLayout {
  const terminalWidth = cells(width);
  // `ShellFrame` pads two cells either side of every screen.
  const contentWidth = Math.max(0, terminalWidth - 4);
  const bodyRows = Math.max(
    0,
    cells(height) - shellChromeRows(terminalWidth) - Math.min(1, cells(noticeRows)),
  );

  const bordered = bodyRows >= BORDERED_MIN_ROWS && contentWidth >= DETAIL_MIN_WIDTH + 4;
  const chrome = borderChrome(bordered);
  // The list always titles itself, because the title is where the scroll
  // position lives and a windowed list that does not say "1-12/53" is a list
  // that looks like the whole list. The detail pane titles itself only when it
  // sits beside the list; stacked underneath, its first line is already the
  // model id and a "MODEL" caption above it is a wasted row.
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
    // The list is the pane that must survive; the detail pane only ever gets
    // what is left after the list has been kept above its own minimum.
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
      // A pane below its minimum is not a small pane, it is a corrupt one —
      // Yoga paints its border through its own last row. Drop it instead.
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

/**
 * `ok` is the one tone this screen needs that the settings detail pane does
 * not: a configured provider is worth saying in green rather than in the
 * accent colour used for "changed from the default".
 */
export type ModelDetailTone = "title" | "text" | "muted" | "accent" | "ok" | "warn" | "blank";

export interface ModelDetailLine {
  readonly text: string;
  readonly tone: ModelDetailTone;
}

export interface ModelDetailInput {
  row?: ModelRow;
  /**
   * Labels of every provider that does hold credentials.
   *
   * Rendered only when the highlighted model's own provider is dark. This is
   * the honest substitute for the per-row verdict this module refuses to make:
   * the runtime may well serve this model through one of these instead, and
   * naming them lets the operator judge rather than being told "no".
   */
  configured?: readonly string[];
  /** Omit the blank separator rows. Set when the pane is short of rows. */
  compact?: boolean;
}

/**
 * The detail pane's body, as flat tone-tagged lines.
 *
 * Content is decided here and colour is decided by the component, so the pane
 * can be asserted on without a renderer. Every field uses a `": "` separator
 * rather than alignment columns: `sanitizeTuiText` collapses runs of
 * whitespace, so a padded literal would be trimmed away and the label would
 * fuse to its value.
 */
export function modelDetailLines(
  { row, configured = [], compact = false }: ModelDetailInput,
  width: number,
): ModelDetailLine[] {
  const limit = cells(width);
  if (!row || limit <= 0) return [];

  const lines: ModelDetailLine[] = [];
  const push = (value: string, tone: ModelDetailTone) => {
    for (const text of wrapCells(value, limit)) lines.push({ text, tone });
  };
  const separate = () => {
    if (!compact) lines.push({ text: "", tone: "blank" });
  };

  const group = row.group;

  if (row.kind === "heading") {
    push(group.label, "title");
    separate();
    push(`${row.count} model${row.count === 1 ? "" : "s"} priced under this provider`, "text");
  } else {
    push(row.model.id, "title");
    separate();
    push(`Provider: ${group.label}`, "text");
    push(`Price: ${row.model.price}`, "text");
    if (row.active) push("Currently active", "accent");
  }

  separate();

  switch (group.credential) {
    case "ready":
      push(`Credentials: found in ${group.via ?? "the environment"}`, "ok");
      break;
    case "missing":
      push("Credentials: not found in this environment", "warn");
      if (group.envVars.length > 0) push(`Reads: ${group.envVars.join(", ")}`, "muted");
      if (group.hint) push(`Setup: ${group.hint}`, "muted");
      if (group.fileSource) {
        // `providerStates` is pure over env and never stats the filesystem, so
        // this provider can read as unconfigured while the runtime still finds
        // an on-disk token. Say that rather than let the pane assert a
        // reachability it did not check.
        push(`Also read from ${group.fileSource}, which is not checked here.`, "muted");
      }
      if (configured.length > 0) {
        push(`Providers with credentials: ${configured.join(", ")}`, "muted");
      }
      break;
    default:
      push("Credentials: no direct provider path", "muted");
      push(
        `The pricing table knows ${group.label}, but the runtime has no env var for it — reach it through an aggregator such as OpenRouter.`,
        "muted",
      );
      if (configured.length > 0) {
        push(`Providers with credentials: ${configured.join(", ")}`, "muted");
      }
      break;
  }

  separate();
  // The caveat that keeps every line above honest. The provider shown is the
  // pricing table's, and the runtime resolves the backend independently
  // (`providerForModel`), so the two can legitimately disagree.
  push(
    "Provider is from the pricing table. The runtime picks a backend at call time and may route this model elsewhere.",
    "muted",
  );

  return lines;
}

/**
 * Trims detail lines to the rows the pane actually has.
 *
 * Rendering more rows than the box holds is what pushes a border through the
 * content, so the overflow has to be cut — but it is marked rather than cut
 * silently, because a hint that stops mid-sentence with no sign it was
 * truncated reads as a bug in the hint.
 *
 * Given a width, the marker is appended to the last surviving line instead of
 * taking a row of its own. On the terminals where clipping actually happens
 * the pane has three rows, and spending one of them on a lone `...` throws
 * away a third of the text to say the text was thrown away.
 *
 * This is `clipDetailLines` from `settings-layout.ts` re-implemented rather
 * than imported: that one is typed to its own tone union, which has no `ok`,
 * and widening a module this change does not own to save fifteen lines is the
 * wrong trade.
 */
export function clipModelDetailLines(
  lines: readonly ModelDetailLine[],
  rows: number,
  width = 0,
): ModelDetailLine[] {
  const limit = cells(rows);
  if (limit <= 0) return [];
  if (lines.length <= limit) return [...lines];

  const kept = lines.slice(0, limit);
  const last = kept[limit - 1];
  const room = cells(width);
  // Four cells: a space and the three dots. Below eight there is nothing left
  // of the line once the marker is paid for, so it takes the row instead.
  if (room >= 8 && last && last.text.length > 0) {
    const head = last.text.slice(0, Math.max(0, room - 4)).trimEnd();
    kept[limit - 1] = { text: `${head} ...`, tone: last.tone };
  } else {
    kept[limit - 1] = { text: "...", tone: "muted" };
  }
  return kept;
}

// ---------------------------------------------------------------------------
// Titles, hints and keys
// ---------------------------------------------------------------------------

/** `MODELS 4-15/53`, or `MODELS 53` when the whole list is on screen. */
export function modelListTitle(window: ModelWindow): string {
  if (window.total === 0) return "MODELS 0";
  if (!window.hasAbove && !window.hasBelow) return `MODELS ${window.total}`;
  return `MODELS ${window.start + 1}-${window.end}/${window.total}`;
}

export type ModelMode = "browse" | "filter";

/**
 * The footer hint, per mode.
 *
 * These are the real bindings. Unlike the settings screen there is no
 * destructive key to reserve, so browse mode gives every printable character
 * to the filter — with 43 models across ten vendors, type-to-filter is the
 * primary way anyone reaches a row.
 */
export function modelFooterHint(mode: ModelMode, hasFilter = false): string {
  if (mode === "filter") return "type to filter · enter/esc done · backspace delete";
  return [
    "up/down move",
    "enter select",
    "/ filter",
    hasFilter ? "esc clear filter" : "esc back",
    "ctrl+c exit",
  ].join(" · ");
}

/**
 * Every printable character starts a filter.
 *
 * `settings-layout.ts` has to carve `r` and `R` out of this path because that
 * screen binds them to reset. This screen has no destructive key, so nothing
 * is reserved and the whole alphabet reaches the filter.
 */
export function isFilterKey(sequence: unknown): boolean {
  if (typeof sequence !== "string" || sequence.length !== 1) return false;
  const code = sequence.charCodeAt(0);
  return code >= 0x20 && code !== 0x7f;
}
