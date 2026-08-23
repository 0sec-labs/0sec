/**
 * Shell-level plugin-host lifecycle for the live console (0sec plugin system).
 *
 * This is the missing link between "a plugin is enabled in the marketplace" and
 * "its tools reach the running console". `plugin-service.ts` writes the on-disk
 * enablement record; the turn engine reads a `PluginHost` off
 * `ConsoleSessionConfig.pluginHost` at each turn boundary. Something has to own
 * the host object across the chat↔market screen swap, keep it in step with the
 * on-disk enabled set, and hand the CURRENT host to each new console session.
 * That is this module, and it is deliberately self-contained so `run.tsx` can
 * drop it in as one object.
 *
 * ── Why a MANAGER and not just a host ────────────────────────────────────────
 *
 * `PluginHost.enabled` is READONLY: the loader treats the enabled set as the
 * operator's frozen approval for the life of that host, so "enable one more
 * plugin" cannot mutate a host — it must construct a NEW one with the wider set.
 * The manager therefore holds the current host, and {@link refresh} reconstructs
 * it when the on-disk enabled set changed, loads the enabled plugins into the
 * fresh host, swaps it in, disposes the old one, and notifies subscribers so the
 * shell can re-hand the new host to the next `createConsoleSession` build.
 *
 * ── The turn-boundary contract (load-bearing) ────────────────────────────────
 *
 * A reconstruct is a genuine host swap and a load mutates the gate maps, so both
 * are only safe BETWEEN turns — the loader's contract, which it cannot enforce
 * itself because it cannot see turns. The manager does not guess: {@link refresh}
 * is the explicit call the shell invokes at a chat turn boundary, and the market
 * bridge only triggers it while no turn is in flight (deferring past a live turn
 * exactly as it already defers a run). Nothing here reconstructs mid-turn.
 *
 * ── What is NOT weakened ──────────────────────────────────────────────────────
 *
 *   - install ≠ enable ≠ run: the manager loads ONLY the ids `loadableIds`
 *     reports (reconcile of the on-disk record against the current manifests),
 *     and it hands `PluginHost` the same set as its `enabled` — so a non-enabled
 *     id is refused by the loader, the single enablement authority, unchanged.
 *   - `reservedToolNames` and `coreVersion` ARE passed to every host it builds
 *     (and to `readInstalledPlugin` when it reconciles), so the loader's on-load
 *     re-validation against built-in shadowing and its `minCoreVersion` check
 *     run for a session-loaded plugin exactly as for an overlay-loaded one.
 *   - fail-soft: one plugin that fails to load never aborts the others and never
 *     throws out of `refresh`; a failed build degrades to "no plugin host".
 */

import type { PluginHost } from "@0sec/core";

import type { CoreLoadResult, CorePluginApi, PluginHostLike } from "./plugin-service.js";

/** A subscriber notified after the live host is REPLACED (a reconstruct). */
export type SessionPluginHostListener = (host: PluginHost) => void;

export interface SessionPluginHostManager {
  /**
   * The host to hand to `createConsoleSession({ pluginHost })`. Stable between
   * reconstructs; a reconstruct replaces it and fires {@link onChanged}.
   */
  current(): PluginHost;
  /**
   * Reconcile the on-disk enabled set into the live host. Reconstructs (new host
   * + load enabled plugins + swap + dispose old + notify) when that set changed;
   * otherwise loads any still-unloaded enabled plugin into the current host.
   * Returns after loads settle. Safe ONLY at a turn boundary — the caller owns
   * that. Fail-soft per plugin.
   */
  refresh(): Promise<void>;
  /**
   * Ensure one enabled plugin is loaded into the live host (the market RUN
   * path): refresh first so a just-enabled id is loadable, then report whether
   * it is now loaded. Never loads a non-loadable id — the loader still refuses.
   */
  runPlugin(pluginId: string): Promise<CoreLoadResult>;
  /**
   * Subscribe to host REPLACEMENTS. The shell re-hands the new host to the next
   * console session build. Returns an unsubscribe function.
   */
  onChanged(listener: SessionPluginHostListener): () => void;
  /** Tear the current host down. Idempotent. */
  dispose(): void;
}

export interface SessionPluginHostDeps {
  /** Per-user state dir override, forwarded to every core path helper + host. */
  homeDir?: string;
  /** Project the enablement record is keyed to. Defaults to `process.cwd()`. */
  projectPath?: string;
  /**
   * Built-in tool names a plugin may not shadow. Passed to every host built AND
   * to `readInstalledPlugin` during reconcile, so a plugin that shadows a
   * built-in is rejected on both the reconcile and the load path.
   */
  reservedToolNames?: readonly string[];
  /** Running @0sec/core version, for the loader's `minCoreVersion` check. */
  coreVersion?: string;
  /** Injected @0sec/core. Defaults to a lazy `import("@0sec/core")`. */
  core?: CorePluginApi | (() => Promise<CorePluginApi>);
  /** Injected host factory (tests). Defaults to `new core.PluginHost(...)`. */
  hostFactory?: (opts: {
    homeDir?: string;
    enabled: readonly string[];
    reservedToolNames?: readonly string[];
    coreVersion?: string;
  }) => PluginHostLike;
}

/** Lazily resolve @0sec/core once, honouring an injected override. */
function coreLoader(injected: SessionPluginHostDeps["core"]): () => Promise<CorePluginApi> {
  if (typeof injected === "function") return injected as () => Promise<CorePluginApi>;
  if (injected) return async () => injected;
  let cached: Promise<CorePluginApi> | undefined;
  return () => {
    if (!cached) cached = import("@0sec/core") as unknown as Promise<CorePluginApi>;
    return cached;
  };
}

/**
 * Build + prime a manager. ASYNC because the initial host must load its enabled
 * plugins (a subprocess spawn) before {@link SessionPluginHostManager.current}
 * can return a fully-populated host. The shell awaits this once during bootstrap,
 * then `current()` / `refresh()` are synchronous-to-call from render/handlers.
 */
export async function createSessionPluginHostManager(
  deps: SessionPluginHostDeps = {},
): Promise<SessionPluginHostManager> {
  const getCore = coreLoader(deps.core);
  const homeDir = deps.homeDir;
  const projectPath = deps.projectPath ?? process.cwd();
  const reservedToolNames = deps.reservedToolNames;
  const coreVersion = deps.coreVersion;

  const listeners = new Set<SessionPluginHostListener>();
  let host: PluginHostLike | undefined;
  /** id → tool names, for the ids successfully loaded into the current host. */
  let loaded = new Map<string, string[]>();
  /** Sorted enabled ids backing the current host; the reconstruct trigger. */
  let enabledKey = "";

  /** The ids safe to load right now: the on-disk approvals that still reconcile. */
  function computeLoadable(c: CorePluginApi): string[] {
    const root = c.pluginsRootDir(homeDir);
    const ids = c.listInstalledPluginIds(root);
    const views = [];
    for (const id of ids) {
      let disc;
      try {
        disc = c.readInstalledPlugin(
          root,
          id,
          reservedToolNames ? { reservedToolNames } : undefined,
        );
      } catch {
        continue;
      }
      if (!disc.ok || !disc.plugin) continue;
      views.push({
        id,
        version: disc.plugin.manifest.version,
        capabilities: c.aggregateCapabilities(disc.plugin.manifest),
      });
    }
    const record = c.readEnablement(projectPath, homeDir);
    return c.loadableIds(c.reconcile(record, views)).slice().sort();
  }

  function buildHost(c: CorePluginApi, enabled: readonly string[]): PluginHostLike {
    return deps.hostFactory
      ? deps.hostFactory({ homeDir, enabled, reservedToolNames, coreVersion })
      : new c.PluginHost({ homeDir, enabled, reservedToolNames, coreVersion });
  }

  /** Load each enabled id into `into`, fail-soft, recording tool names. */
  async function loadAll(
    into: PluginHostLike,
    enabled: readonly string[],
    into_loaded: Map<string, string[]>,
  ): Promise<void> {
    for (const id of enabled) {
      try {
        const r = await into.load(id);
        if (r.ok) into_loaded.set(id, r.tools ?? []);
      } catch {
        // Fail-soft: one bad plugin never aborts the rest.
      }
    }
  }

  /** Build a fresh host for `enabled`, load it, swap it in, dispose the old. */
  async function reconstruct(
    c: CorePluginApi,
    enabled: readonly string[],
    emit: boolean,
  ): Promise<void> {
    const next = buildHost(c, enabled);
    const nextLoaded = new Map<string, string[]>();
    await loadAll(next, enabled, nextLoaded);

    const old = host;
    host = next;
    loaded = nextLoaded;
    enabledKey = enabled.slice().sort().join("\n");

    if (old) {
      try {
        old.shutdown?.();
      } catch {
        // Best-effort dispose; a throwing shutdown never breaks the swap.
      }
    }
    if (emit) {
      const swapped = host as unknown as PluginHost;
      for (const listener of [...listeners]) {
        try {
          listener(swapped);
        } catch {
          // An observer must never affect host lifecycle.
        }
      }
    }
  }

  async function refresh(): Promise<void> {
    const c = await getCore();
    const enabled = computeLoadable(c);
    const key = enabled.join("\n");

    if (host && key === enabledKey) {
      // Same approved set: no swap. Load any enabled plugin not yet live (e.g. a
      // prior load that failed soft), so a repeated run can recover it.
      for (const id of enabled) {
        if (loaded.has(id)) continue;
        try {
          const r = await host.load(id);
          if (r.ok) loaded.set(id, r.tools ?? []);
        } catch {
          // Fail-soft.
        }
      }
      return;
    }
    // First build (host === undefined) or the set changed: reconstruct. Emit only
    // on a genuine replacement, so the initial build (no subscribers) is quiet.
    await reconstruct(c, enabled, /* emit */ host !== undefined);
  }

  async function runPlugin(pluginId: string): Promise<CoreLoadResult> {
    // Refresh first so a just-enabled id is present in the host's enabled set
    // (enablement is readonly — a stale host would refuse it as "not enabled").
    await refresh();
    const tools = loaded.get(pluginId);
    if (tools) return { ok: true, pluginId, tools };
    return {
      ok: false,
      pluginId,
      errors: [
        `plugin "${pluginId}" is not loaded; it may be uninstalled, not enabled, ` +
          "or its capabilities changed since approval",
      ],
    };
  }

  function onChanged(listener: SessionPluginHostListener): () => void {
    listeners.add(listener);
    return () => listeners.delete(listener);
  }

  function current(): PluginHost {
    return host as unknown as PluginHost;
  }

  function dispose(): void {
    const old = host;
    host = undefined;
    loaded = new Map();
    enabledKey = "";
    if (old) {
      try {
        old.shutdown?.();
      } catch {
        // Best-effort.
      }
    }
  }

  // Prime the initial host from the on-disk enabled set before returning, so the
  // first `current()` hands the console a populated host.
  {
    const c = await getCore();
    await reconstruct(c, computeLoadable(c), /* emit */ false);
  }

  return { current, refresh, runPlugin, onChanged, dispose };
}
