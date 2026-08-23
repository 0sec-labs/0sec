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

/** Index of a model by id, or -1. Used to open the screen on the active row. */
export function indexOfModel(rows: readonly ModelRow[], id: string | undefined): number {
  if (!id) return -1;
  for (let index = 0; index < rows.length; index++) {
    const row = rows[index];
    if (row?.kind === "model" && row.model.id === id) return index;
  }
  return -1;
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
// Hints and keys
// ---------------------------------------------------------------------------

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
