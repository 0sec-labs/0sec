/** @jsxImportSource @opentui/react */
/**
 * The `/model` pop-up dialog.
 *
 * The screen is a dialog *body*: an icon+title row, the target / policy
 * context rows, the shared grouped/searchable picker (`DialogSelectBody`) with
 * a detail column beside it, and a status line. The scrim, the rounded panel
 * and the footer hints are the host's — the surface is read through
 * `useSurfaceDimensions`, which reports the panel's inner box when the screen
 * is mounted inside a `DialogSurface` and the terminal otherwise, and the
 * footer text still goes out through the injected `frame`.
 *
 * `/model` used to open a compact selector floating above the composer: a flat
 * list of every priced model, each with a `provider · price` caption. That
 * shape competed with the transcript for the only scarce resource a TUI has —
 * rows — and it had nowhere to put the one thing an operator needs before
 * switching model, which is whether this machine can reach the vendor at all.
 * A turn started against a dark provider dies with zero tokens and a message
 * about a key nobody knew they needed.
 *
 * This screen is the replacement, and it is now a projection of the one shared
 * picker body, `DialogSelectBody`: the grouped, windowed list on the left and
 * the highlighted model's detail on the right, driven inline (no scrim, no
 * floating panel) inside the console shell. The same body serves the modal
 * `DialogSelect` overlay and the settings screen; this file supplies only the
 * domain — which models exist, how they group, what their detail says — and its
 * own keyboard.
 *
 * ## Two catalogues, never mixed
 *
 * A hosted runtime (`providerId === "hosted"`) is served by the account's own
 * catalogue, read live through `loadHostedModelCatalog` and projected by
 * `buildHostedModelCatalog`. A hosted id names a route on that account, so this
 * path has no cache, no bundled floor and no BYOK fallback: when the live read
 * fails the screen says so and offers a reload, because a Models.dev row of the
 * same name describes a different thing — the public model — and showing its
 * numbers under this account's route would be a fabrication. Every other
 * runtime keeps the existing BYOK catalogue (`buildFullModelCatalog`, the
 * pricing table plus the Models.dev sync).
 *
 * ## What this screen may say about a model
 *
 * Only what the authoritative catalogue reported. Every id on screen comes out
 * of `buildFullModelCatalog` (BYOK) or `buildHostedModelCatalog` (hosted) —
 * there is no hand-written model list anywhere in this file. Price comes from
 * the pricing table or the hosted catalogue's own `pricing` block and reads
 * "not published" / "unknown" when neither carried one. The BYOK context
 * window comes from the synced Models.dev cache (`contextTokens`), keyed on
 * provider AND id together, and the hosted one from the service's own
 * `context_length`; both read "unknown" when absent. Nothing is derived from a
 * sibling model, a vendor default, or the model's name, and there is no "free"
 * or "optimized" claim this file authors: `free` is a catalogue stating both
 * rates are zero.
 *
 * The hosted catalogue carries no availability, readiness or entitlement
 * signal — canonical `InferenceModel` has none — so this screen makes no such
 * claim either. Listed rows are OFFERED for explicit operator selection; no row
 * is labelled qualified, ready, healthy or funded, and no row is drawn as
 * disabled on a fact nobody reported.
 *
 * Every write is an explicit operator action staged for the next audit: the
 * base model, one role's assignment, or the single-model policy. Loading,
 * highlighting, filtering and background refreshing never call those callbacks,
 * and no model is ever selected for the operator.
 *
 * Three further properties are load-bearing:
 *
 * 1. **Nothing here knows the models.** The row model is derived from
 *    `model-catalog.ts` — itself derived from the pricing table or the account's
 *    own catalogue — and the provider facts from `provider-status.ts`. There is
 *    no list, no vendor order and no row count written down, so a model added
 *    to the pricing table appears here with its group, its price and its
 *    credential state without this file changing.
 *
 * 2. **This component does no arithmetic.** Every width, height, row count and
 *    window boundary comes off `model-layout.ts` via
 *    `computeModelDialogLayout` (and `dialog-select-layout.ts` beneath it),
 *    where it is swept across widths and heights by a test. The reason is in
 *    `PRIMITIVES.md`: Yoga shrinks siblings rather than clipping them, so a
 *    row that claims one cell too many paints two strings on top of each
 *    other, and a bordered box one row short of its content paints its own
 *    border through that content.
 *
 * 3. **Credential state is reported per provider, never per model.** A
 *    previous attempt annotated each row "no credentials" using the provider
 *    the catalogue carries. That was wrong and was reverted: the catalogue's
 *    provider comes from the pricing table, while the runtime resolves a
 *    model's provider through its own detection and failover order
 *    (`providerForModel` in `core/src/runtime/llm-api.ts`, which core does not
 *    export). Those disagree — an OpenAI-named model can in fact be served by
 *    the ChatGPT/Codex backend — so a per-row verdict flags working models as
 *    broken. What this screen states is what it can verify: which providers
 *    hold credentials, in the status line and in the detail pane. The operator
 *    judges.
 *
 * ## Only live bindings are advertised
 *
 * The role-assignment and single-model controls exist only when the router
 * actually wired their callbacks. When it did not, the key is not bound, its
 * row is not drawn and the footer does not name it — a control that cannot
 * function is absent, never rendered-and-dead.
 */

import React, { useEffect, useMemo, useRef, useState, type SetStateAction } from "react";
import { useKeyboard, usePaste } from "@opentui/react";
import { decodePasteBytes, TextAttributes } from "@opentui/core";

import { useTheme, type Theme } from "./theme-context.js";
import { useSymbols } from "./symbol-context.js";
import { useDialogSurface, useSurfaceDimensions } from "./dialog-surface.js";
import { Cells, textCells } from "./primitives.js";
import { DialogSelectBody, type DialogItem } from "./dialog-select.js";
import {
  clampDialogSelection,
  moveDialogSelection,
} from "./dialog-select-layout.js";
import {
  buildContextWindowIndex,
  clipModelDetailLines,
  computeModelDialogLayout,
  contextWindowFor,
  configuredProviderLabels,
  credentialSummary,
  hostedDetailLines,
  isFilterKey,
  modelDetailLines,
  modelDialogCount,
  modelDialogHint,
  modelDialogTitle,
  modelFooterHint,
  modelTargetLine,
  singleModelLine,
  buildModelRows,
  type ModelCatalogScope,
  type ModelDetailLine,
  type ModelDetailTone,
  type ModelMode,
  type ModelRow,
} from "./model-layout.js";
import {
  buildFullModelCatalog,
  buildHostedModelCatalog,
  hostedModelDetails,
  preferredHostedModel,
} from "./model-catalog.js";
import {
  syncModelCatalog,
  loadCatalogModels,
  loadHostedModelCatalog,
  type HostedCatalogSnapshot,
} from "./model-catalog-sync.js";
import { OFFLINE_MODEL_CATALOG } from "./model-catalog.offline.js";
import { providerStates } from "./provider-status.js";
import { sanitizeTuiText } from "./text.js";

/** How many rows page-up and page-down move. */
const PAGE_STEP = 5;
/**
 * The runtime discriminator for the hosted service. It is the runtime's own
 * `providerId`, not an upstream vendor name: a hosted route's upstream
 * ("anthropic", "openai", …) lives in the catalogue row's `provider`, and
 * comparing the two is a category error.
 */
const HOSTED_PROVIDER_ID = "hosted";
/**
 * The roles an audit can assign a model to. The list is the union of these and
 * whatever keys the caller's map already carries, so a role the caller knows
 * about is targetable even when it is not named here.
 */
const MODEL_ROLES = ["discovery", "attack", "verify", "report", "audit", "review"] as const;
const CURATED_MODEL_IDS: Readonly<Record<string, true>> = Object.fromEntries(
  OFFLINE_MODEL_CATALOG.map((model) => [model.id, true]),
);

export interface ModelFrameInput {
  /** The screen body, already sized to the rows the frame left it. */
  body: React.ReactNode;
  /** Footer text for the current mode, naming the bindings that actually work. */
  hint: string;
}

export interface ModelScreenProps {
  /**
   * Wraps the body in the console shell.
   *
   * Injected rather than imported so this module does not depend on `run.tsx`
   * — which owns `ShellFrame` and pulls in every other screen with it. The
   * screen states what it needs (a frame, and a footer line whose text changes
   * with the mode) and the router supplies it.
   */
  frame: (input: ModelFrameInput) => React.ReactNode;
  /** The model the session is currently running, when there is one. */
  currentModel?: string;
  /**
   * The runtime this picker is choosing for: `"hosted"` selects the account's
   * own catalogue, anything else (including nothing) keeps the BYOK catalogue.
   * Never invented — the router reports what the runtime says.
   */
  providerId?: string;
  /** Per-role model assignments already staged for the next audit. */
  agentModels?: Readonly<Record<string, string>>;
  /** Whether the next audit is pinned to one model for every role. */
  singleModel?: boolean;
  /**
   * Stage the full merged role map for the next audit. Optional: when the
   * router does not supply it there is no role targeting at all — no Ctrl+←/→,
   * no Ctrl+Backspace, no target row and no footer mention of either.
   */
  onAgentModelsChange?: (models: Readonly<Record<string, string>>) => void;
  /** Stage the single-model policy. Optional on the same terms as above. */
  onSingleModelChange?: (enabled: boolean) => void;
  /** Enter on a model row. The router decides what "select" means. */
  onSelect: (id: string) => void;
  /** Leave the screen — Esc, once any filter has been cleared. */
  onBack: () => void;
  /** Leave the console entirely — ctrl+c. */
  onExit: () => void;
  /**
   * Environment to read credentials from. Defaults to the real one; injected
   * so the screen can be driven under a synthetic environment without the
   * test mutating `process.env`.
   */
  env?: Record<string, string | undefined>;
}

function toneColor(theme: Theme, tone: ModelDetailTone): string | undefined {
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

function modelDialogItems(rows: ModelRow[]): DialogItem[] {
  return rows
    .filter((row): row is Extract<ModelRow, { kind: "model" }> => row.kind === "model")
    .map((row) => ({
      id: row.model.id,
      label: row.model.id,
      meta: row.model.price,
      category: row.group.label,
      current: row.active,
    }));
}

export function ModelScreen({
  frame,
  currentModel,
  providerId,
  agentModels,
  singleModel = false,
  onAgentModelsChange,
  onSingleModelChange,
  onSelect,
  onBack,
  onExit,
  env,
}: ModelScreenProps) {
  const theme = useTheme();
  const symbols = useSymbols();
  const { width, height } = useSurfaceDimensions();
  const inDialog = useDialogSurface();

  // A hosted runtime is the only thing that switches catalogues. Everything
  // else — a named BYOK provider, or a router that did not say — keeps the
  // BYOK catalogue this screen has always drawn.
  const isHosted = providerId === HOSTED_PROVIDER_ID;
  const isByok = !isHosted;
  const scope: ModelCatalogScope = isHosted ? "hosted" : "byok";
  // A control exists only when its callback does. These two flags gate the
  // key, the row and the footer text together, so a binding is never named
  // where it would do nothing.
  const rolesLive = onAgentModelsChange !== undefined;
  const singleModelLive = onSingleModelChange !== undefined;

  const [role, setRole] = useState<string | null>(null);
  const roles = useMemo(
    () => [null, ...new Set<string>([...MODEL_ROLES, ...Object.keys(agentModels ?? {})])],
    [agentModels],
  );
  // The model the picker is choosing FOR: the parent model, or the role's own
  // assignment when it has one. A role with no assignment inherits, and the
  // target row says so rather than showing the inherited id as an assignment.
  const activeModel = role === null ? currentModel : (agentModels?.[role] ?? currentModel);
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);

  const [filter, setFilter] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [refreshing, setRefreshing] = useState(true);
  const filterRef = useRef("");
  const showAllRef = useRef(false);

  // Read once per mount. Credentials are process-level and cannot change
  // under a screen that has no way to set them; re-deriving them on every
  // keystroke would only make the filter slower.
  const states = useMemo(() => providerStates(env ?? process.env), [env]);
  const configured = useMemo(() => configuredProviderLabels(states), [states]);

  // The identity of the connection this load belongs to. A hosted snapshot is
  // only ever shown while it still matches — rows fetched for one account must
  // never paint under another, and Ctrl+R bumps `reload` to force a re-read.
  const source = useMemo(() => ({ providerId, env, reload }), [providerId, env, reload]);
  const [hostedState, setHostedState] = useState<{
    source: typeof source;
    snapshot: HostedCatalogSnapshot | null;
    error: string | null;
  } | null>(null);
  const hostedSnapshot = hostedState?.source === source ? hostedState.snapshot : null;
  const hostedError = hostedState?.source === source ? hostedState.error : null;

  // BYOK: refresh the Models.dev catalog cache in the background whenever the
  // picker opens. Fire-and-forget: it never throws, no-ops when the cache is
  // still fresh, and only affects the *next* open — this render reads whatever
  // cache (or the bundled offline floor) is already on disk, so the list is
  // instant. `catalogNonce` bumps once the refresh lands so an operator who
  // leaves the picker open sees newly-synced models without reopening it.
  //
  // Hosted: read the account's own catalogue live. There is nothing to cache
  // and nothing to fall back to, so a failure is reported as a failure.
  const [catalogNonce, setCatalogNonce] = useState(0);
  useEffect(() => {
    let alive = true;
    setRefreshing(true);
    if (isHosted) {
      void loadHostedModelCatalog({ env })
        .then((snapshot) => {
          // Project before publishing: a malformed catalogue (an id-less or
          // duplicated row) throws here and stays an error rather than being
          // half-drawn.
          buildHostedModelCatalog(snapshot.models, snapshot.account);
          if (alive) setHostedState({ source, snapshot, error: null });
        })
        .catch((error: unknown) => {
          if (alive) {
            setHostedState({
              source,
              snapshot: null,
              error: sanitizeTuiText(
                error instanceof Error ? error.message : "Hosted catalog failed",
              ),
            });
          }
        })
        .finally(() => {
          if (alive) setRefreshing(false);
        });
    } else {
      void syncModelCatalog().then((updated) => {
        if (!alive) return;
        if (updated) setCatalogNonce((n) => n + 1);
        setRefreshing(false);
      });
    }
    return () => {
      alive = false;
    };
  }, [source, isHosted, env]);

  const hostedCatalog = useMemo(
    () => (hostedSnapshot ? buildHostedModelCatalog(hostedSnapshot.models, hostedSnapshot.account) : []),
    [hostedSnapshot],
  );
  const catalog = useMemo(
    () => (isByok ? buildFullModelCatalog(activeModel) : []),
    // catalogNonce forces a re-read after a background sync writes the cache.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [isByok, activeModel, catalogNonce],
  );
  // BYOK context windows come straight off the synced Models.dev cache (or its
  // bundled offline floor). `CatalogModel` does not carry the field, and
  // `model-catalog.ts` is not this lane's to widen, so the lookup is built
  // here from the same rows the catalogue itself was built from.
  //
  // The index is keyed on **provider and id together**: the same id exists
  // under more than one provider with different windows, so an id-only lookup
  // would report another provider's number as this model's. A pair the feed
  // never described, or one it described inconsistently, is simply not in the
  // index and renders "unknown" — never inferred from a sibling row. The
  // hosted path never consults it: a hosted route's window is the service's
  // own `context_length` or nothing.
  const contextIndex = useMemo(
    () => (isByok ? buildContextWindowIndex(loadCatalogModels().models) : new Map<string, number>()),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [isByok, catalogNonce],
  );
  const scopedCatalog = useMemo(
    () => showAll ? catalog : catalog.filter((model) => Object.hasOwn(CURATED_MODEL_IDS, model.id) || model.id === activeModel),
    [catalog, activeModel, showAll],
  );

  // `buildModelRows` does all the domain work — grouping by provider, credential
  // lookup, credential-band ordering, floating the active model first, and the
  // AND-over-terms filter. The screen keeps only its selectable model rows and
  // projects them onto `DialogItem`s: the provider label is the category (so the
  // shared body draws a heading per provider), the price is the right-aligned
  // meta, and the running model carries the current-value dot.
  const modelRows = useMemo(
    () => buildModelRows({ catalog: scopedCatalog, states, filter, activeModel }),
    [scopedCatalog, states, filter, activeModel],
  );
  // The hosted list has no provider-credential story to group by — the account
  // holds the keys — so it groups by upstream vendor and filters over the
  // fields the service actually published.
  const hostedItems = (query: string): DialogItem[] => {
    const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
    return hostedCatalog
      .filter((model) =>
        terms.every((term) =>
          `${model.id} ${model.provider} ${model.catalog.upstream_model}`
            .toLowerCase()
            .includes(term),
        ),
      )
      .map((model) => ({
        id: model.id,
        label: model.id,
        meta: model.selectable ? `${model.recommended ? "Recommended · " : ""}${model.price}` : "Unavailable",
        category: `Hosted · ${model.provider}`,
        current: model.id === activeModel,
        disabled: !model.selectable,
      }));
  };
  const items = isHosted ? hostedItems(filter) : modelDialogItems(modelRows);
  const hostedById = useMemo(
    () => new Map(hostedCatalog.map((model) => [model.id, model])),
    [hostedCatalog],
  );
  // id -> ModelRow, so the detail renderer can reach the full provider/credential
  // facts the flat `DialogItem` does not carry.
  const rowById = useMemo(() => {
    const map = new Map<string, ModelRow>();
    for (const row of modelRows) if (row.kind === "model") map.set(row.model.id, row);
    return map;
  }, [modelRows]);
  // Display rows (headings interleaved) drive the panel's scroll/height math.
  const totalRows = useMemo(() => {
    let count = 0;
    let group = "";
    for (const item of items) {
      if (item.category && item.category !== group) {
        group = item.category;
        count += 1;
      }
      count += 1;
    }
    return count;
  }, [items]);

  // Keep the highlight on the same model when the background catalog refreshes.
  const [selectedId, setSelectedId] = useState(currentModel);
  const selectedIdRef = useRef(selectedId);
  // Preserve the operator's pin; otherwise offer the server recommendation.
  // An unavailable pin is not silently replaced by another model.
  const offeredId = preferredHostedModel(hostedCatalog, selectedId ?? activeModel)?.id;
  const highlightId = isHosted ? offeredId : (selectedId ?? activeModel);
  const cursor = clampDialogSelection(items, items.findIndex((item) => item.id === highlightId));

  // Every width and row count comes off the layout module, from the surface
  // box the dialog handed down — never from `useTerminalDimensions` and never
  // computed here (PRIMITIVES.md: Yoga shrinks siblings rather than clipping).
  const layout = computeModelDialogLayout({ width, height, totalRows, inDialog });
  const { contentWidth, panel, stackedRows } = layout;
  const listRows = layout.bodyRows - stackedRows;

  const mode: ModelMode = filter ? "filter" : "browse";
  // The always-on status line carries the one statement this screen can always
  // make. On BYOK it matters most for the operator whose only credential is
  // ChatGPT Codex: the catalogue has no chatgpt-codex models to group under, so
  // no heading names them, and without this line that reads as "nothing works".
  // On hosted it names the host the rows came from and how many were listed —
  // a count of rows, not a verdict on any of them.
  const statusText = hostedError
    ? `${symbols.warning} Hosted catalog error: ${hostedError} · Ctrl+R reload`
    : isHosted && !hostedSnapshot
      ? "Loading the account's hosted model catalog…"
      : isHosted && hostedSnapshot
        ? `${hostedSnapshot.host} · ${hostedCatalog.length} model${hostedCatalog.length === 1 ? "" : "s"} listed for this account`
        : credentialSummary(states);
  // When there is no list to draw, the reason takes the list's place. It is the
  // whole explanation, so it is wrapped and scrolled rather than clipped.
  const connectionMessage = hostedError
    ? `${statusText}. No cached, offline or BYOK models are substituted for a hosted route.`
    : isHosted && hostedSnapshot && hostedCatalog.length === 0
      ? "The hosted service listed no models for this account. Check the connection, then Ctrl+R to reload. No fallback model will be substituted."
      : null;

  const currentItems = () => isHosted
    ? hostedItems(filterRef.current)
    : filterRef.current === filter && showAllRef.current === showAll
      ? items
      : modelDialogItems(buildModelRows({
        catalog: showAllRef.current
          ? catalog
          : catalog.filter((model) => Object.hasOwn(CURATED_MODEL_IDS, model.id) || model.id === activeModel),
        states,
        filter: filterRef.current,
        activeModel,
      }));
  const highlight = (id: string | undefined) => {
    selectedIdRef.current = id;
    setSelectedId(id);
  };

  const move = (delta: number) => {
    const visible = currentItems();
    if (visible.length === 0) return;
    const dir: 1 | -1 = delta >= 0 ? 1 : -1;
    let next = clampDialogSelection(
      visible,
      visible.findIndex((item) => item.id === (selectedIdRef.current ?? activeModel ?? offeredId)),
    );
    for (let i = 0; i < Math.abs(delta); i += 1) next = moveDialogSelection(visible, next, dir);
    highlight(visible[next]?.id);
  };

  const setQuery = (next: SetStateAction<string>) => {
    filterRef.current = typeof next === "function" ? next(filterRef.current) : next;
    setFilter(filterRef.current);
    highlight(undefined);
  };

  usePaste((event) => {
    const text = sanitizeTuiText(decodePasteBytes(event.bytes));
    if (text) setQuery((current) => current + text);
  });

  useKeyboard((key) => {
    const seq = typeof key.sequence === "string" ? key.sequence : "";

    if (key.ctrl && key.name === "c") {
      onExit();
      return;
    }

    if (key.ctrl && key.name === "u") return setQuery("");
    // Role targeting, single-model policy and inheritance exist only while
    // their callbacks do; without them these keys are not bound at all.
    if (rolesLive && key.ctrl && (key.name === "left" || key.name === "right")) {
      const index = roles.indexOf(role);
      const next = roles[(index + (key.name === "right" ? 1 : -1) + roles.length) % roles.length] ?? null;
      setRole(next);
      setNotice("");
      highlight(next === null ? currentModel : (agentModels?.[next] ?? currentModel));
      return;
    }
    if (singleModelLive && key.ctrl && key.name === "s") {
      onSingleModelChange?.(!singleModel);
      setNotice("Single-model policy staged for the next audit; the running audit is unchanged.");
      return;
    }
    if (isHosted && key.ctrl && key.name === "r") {
      setReload((value) => value + 1);
      return;
    }
    if (rolesLive && key.ctrl && key.name === "backspace" && role !== null) {
      const next = { ...agentModels };
      delete next[role];
      onAgentModelsChange?.(next);
      setNotice(`${role} will inherit the parent model in the next audit.`);
      return;
    }
    if (key.ctrl || key.meta || key.option) return;
    if (key.name === "up") return move(-1);
    if (key.name === "down") return move(1);
    if (key.name === "pageup") return move(-PAGE_STEP);
    if (key.name === "pagedown") return move(PAGE_STEP);
    if (key.name === "home") return highlight(currentItems()[0]?.id);
    if (key.name === "end") return highlight(currentItems().at(-1)?.id);
    if (key.name === "tab") {
      // Curated/all is a property of the BYOK superset; the hosted catalogue is
      // whatever the account listed, so there is nothing to widen.
      if (isHosted) return;
      showAllRef.current = !showAllRef.current;
      setShowAll(showAllRef.current);
      return;
    }
    if (key.name === "return") {
      const visible = currentItems();
      const activeItem = visible[clampDialogSelection(
        visible,
        visible.findIndex((item) => item.id === (selectedIdRef.current ?? activeModel ?? offeredId)),
      )];
      if (!activeItem || activeItem.disabled) return;
      if (role !== null && rolesLive) {
        onAgentModelsChange?.({ ...agentModels, [role]: activeItem.id });
        setNotice(
          `${role}: ${activeItem.id} staged for the next audit${singleModel ? "; single-model mode still takes precedence" : ""}.`,
        );
        return;
      }
      onSelect(activeItem.id);
      return;
    }
    if (key.name === "escape") {
      if (filterRef.current) setQuery("");
      else onBack();
      return;
    }
    if (key.name === "backspace") {
      setQuery((current) => Array.from(current).slice(0, -1).join(""));
      return;
    }
    if (isFilterKey(seq)) {
      // Functional updates preserve every character in a paste/fast key burst.
      // A leading slash still opens search; slashes within model IDs are text.
      setQuery((current) => current === "" && seq === "/" ? "" : current + seq);
    }
  });

  // The detail pane shows the highlighted model's full story — what the
  // catalogue reported and nothing else — fitted to the exact box the shared
  // body hands it. Both branches end in a bounded box, so the pane physically
  // cannot paint more rows than it was given.
  const renderDetail = (item: DialogItem, pane: { width: number; height: number }) => {
    const compact = pane.height < 12;

    if (isHosted) {
      const hosted = hostedById.get(item.id);
      if (!hosted) return null;
      // Every string below is the hosted service's own report of this model.
      const details = hostedModelDetails(hosted);
      if (role !== null && rolesLive) {
        details.splice(
          1,
          0,
          `Role advice: ${role} inherits the parent unless you explicitly assign a model.`,
          `Enter stages this exact model for ${role}; Ctrl+Backspace restores inheritance. The running audit is unchanged.`,
        );
      }
      // The hosted report is the account's own description of the route, and
      // all of it was reachable before this dialog existed. Clipping it away
      // would delete catalogue metadata rather than fit it, so the pane keeps
      // its scrollbox: the box is still bounded to `pane`, but the overflow
      // scrolls instead of vanishing. The inner column gives up one cell for
      // the scrollbar.
      const inner = Math.max(1, pane.width - 1);
      const lines = hostedDetailLines(details, inner, compact);
      return (
        <scrollbox
          key={item.id}
          width={pane.width}
          height={pane.height}
          flexShrink={0}
          scrollX={false}
          verticalScrollbarOptions={{
            trackOptions: {
              backgroundColor: theme.PANEL,
              foregroundColor: theme.MUTED,
            },
            arrowOptions: {
              foregroundColor: theme.MUTED,
              backgroundColor: theme.PANEL,
            },
          }}
        >
          <box width={inner} flexDirection="column" flexShrink={0} minWidth={0}>
            {lines.map((line, index) => (
              <Cells
                key={`detail-${index}`}
                width={inner}
                fg={toneColor(theme, line.tone)}
                attributes={line.tone === "title" ? TextAttributes.BOLD : undefined}
              >
                {line.text}
              </Cells>
            ))}
          </box>
        </scrollbox>
      );
    }

    // The BYOK pane is short and bounded — id, provider, price, context, the
    // credential story — and is clipped with a visible marker rather than
    // scrolled. Nothing that was reachable before is dropped.
    const row = rowById.get(item.id);
    const contextTokens = row?.kind === "model"
      ? contextWindowFor(contextIndex, row.model.provider, row.model.id)
      : null;
    const lines: ModelDetailLine[] = clipModelDetailLines(
      modelDetailLines({ row, configured, compact, contextTokens }, pane.width, symbols),
      pane.height,
      pane.width,
    );
    return (
      <>
        {lines.map((line, index) => (
          <Cells
            key={`detail-${index}`}
            width={pane.width}
            fg={toneColor(theme, line.tone)}
            attributes={line.tone === "title" ? TextAttributes.BOLD : undefined}
          >
            {line.text}
          </Cells>
        ))}
      </>
    );
  };

  // ── Title row: glyph + label on the left, the live row count on the right.
  // Split explicitly so the two leaves can never be handed overlapping cells.
  const titleText = modelDialogTitle({ scope, providerId, showAll });
  const countText = modelDialogCount(items.length, refreshing);
  const countWidth = Math.min(contentWidth, textCells(countText));
  const titleWidth = Math.max(0, contentWidth - countWidth - (countWidth > 0 ? 1 : 0));

  // The footer names bindings, so it is composed from what is actually bound.
  // `modelDialogHint` names Ctrl+←/→ and Ctrl+S unconditionally, so it is used
  // only when both of those callbacks exist; `modelFooterHint` names Tab, so it
  // is used only on the BYOK path. The hosted path without a role layer is
  // neither, and is listed explicitly rather than borrowing a line that
  // advertises a key it does not implement.
  const hint = rolesLive && singleModelLive
    ? modelDialogHint({ scope, role, hasFilter: filter.length > 0 })
    : isByok
      ? modelFooterHint(mode, filter.length > 0)
      : [
        "↑↓ model",
        role !== null && rolesLive ? "enter stage" : "enter select",
        rolesLive ? "ctrl+←/→ target" : undefined,
        rolesLive && role !== null ? "ctrl+backspace inherit" : undefined,
        singleModelLive ? "ctrl+s single" : undefined,
        "ctrl+r reload",
        filter.length > 0 ? "ctrl+u clear" : "type to filter",
        filter.length > 0 ? "esc clear" : "esc back",
      ]
        .filter((part): part is string => part !== undefined)
        .join(" · ");

  // The meta rows, in priority order: what the next Enter will change, then
  // the policy that governs it, then which slice of the BYOK superset is on
  // show. `computeModelDialogLayout` hands out 0, 1 or 2 of them, and each row
  // that names a key is only present when that key is bound.
  const metaLines: { text: string; fg: string }[] = [];
  if (rolesLive) {
    metaLines.push({
      text: `${modelTargetLine(role, activeModel, role !== null && agentModels?.[role] !== undefined, symbols)} · Ctrl+←/→ target`,
      fg: theme.ACCENT,
    });
  }
  if (singleModelLive) {
    metaLines.push({ text: `${singleModelLine(singleModel)} · Ctrl+S toggle`, fg: theme.MUTED });
  }
  if (isByok) {
    metaLines.push({
      text: `${showAll ? "All models" : "Curated models"} · ${items.length} of ${scopedCatalog.length} · Tab ${showAll ? "curated" : "all models"}${refreshing ? " · refreshing…" : ""}`,
      fg: theme.ACCENT,
    });
  }
  const visibleMetaLines = metaLines.slice(0, layout.metaRows);

  // The connection/failure notice is wrapped, not clipped: it is the whole
  // explanation of why there is no list. One cell goes to the scrollbar.
  const messageWidth = Math.max(1, contentWidth - 1);
  const messageLines = connectionMessage && contentWidth > 0
    ? hostedDetailLines([sanitizeTuiText(connectionMessage)], messageWidth, true)
    : [];

  const body = (
    <box flexDirection="column" width="100%" flexGrow={1} minWidth={0} overflow="hidden">
      {layout.titleRows > 0 && contentWidth > 0 ? (
        <box flexDirection="row" width={contentWidth} height={1} flexShrink={0} minWidth={0}>
          <Cells width={titleWidth} fg={theme.PRIMARY} attributes={TextAttributes.BOLD}>
            {titleText}
          </Cells>
          {countWidth > 0 ? (
            <>
              {titleWidth > 0 ? <Cells width={1}>{""}</Cells> : null}
              <Cells width={countWidth} align="right" fg={theme.MUTED}>
                {countText}
              </Cells>
            </>
          ) : null}
        </box>
      ) : null}

      {contentWidth > 0
        ? visibleMetaLines.map((line, index) => (
          <Cells key={`meta-${index}`} width={contentWidth} fg={line.fg}>
            {line.text}
          </Cells>
        ))
        : null}

      {listRows < 2 || contentWidth < 1 ? null : connectionMessage ? (
        <scrollbox
          width={contentWidth}
          height={listRows}
          flexShrink={0}
          scrollX={false}
          verticalScrollbarOptions={{
            trackOptions: {
              backgroundColor: theme.PANEL,
              foregroundColor: theme.MUTED,
            },
            arrowOptions: {
              foregroundColor: theme.MUTED,
              backgroundColor: theme.PANEL,
            },
          }}
        >
          <box width={messageWidth} flexDirection="column" flexShrink={0} minWidth={0}>
            {messageLines.map((line, index) => (
              <Cells key={`msg-${index}`} width={messageWidth} fg={hostedError ? theme.ERROR : theme.MUTED}>
                {line.text}
              </Cells>
            ))}
          </box>
        </scrollbox>
      ) : (
        <DialogSelectBody
          items={items}
          cursor={cursor}
          panel={panel}
          query={filter}
          placeholder={`${symbols.fieldSearch} Find a model or provider`}
          gutter
          isCurrent={(item) => item.current === true}
          renderDetail={renderDetail}
          onActivateRow={(index) => highlight(items[index]?.id)}
          onScroll={move}
          emptyText={isHosted
            ? refreshing
              ? "Loading the hosted catalog"
              : "No hosted models matched; no fallback catalog is used"
            : showAll
              ? "No matches. Ctrl+U clears search."
              : "No matches. Tab searches all models; Ctrl+U clears."}
        />
      )}

      {stackedRows > 0 && !connectionMessage && items[cursor] ? (
        <box width={contentWidth} height={stackedRows} flexDirection="column" flexShrink={0} minWidth={0}>
          {renderDetail(items[cursor]!, { width: contentWidth, height: stackedRows })}
        </box>
      ) : null}

      {layout.statusRows > 0 && contentWidth > 0 ? (
        <Cells width={contentWidth} fg={hostedError ? theme.ERROR : theme.MUTED}>
          {hostedError ? statusText : notice || statusText}
        </Cells>
      ) : null}
    </box>
  );

  return <>{frame({ body, hint })}</>;
}
