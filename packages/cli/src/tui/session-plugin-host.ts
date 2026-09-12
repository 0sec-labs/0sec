/**
 * Marketplace host ownership. New sessions lease the current approved tool set;
 * refresh builds the next host without changing or stopping a leased live host.
 * A retired host shuts down only after its last session finishes cleanup.
 * The core loader remains the only registry and enablement authority.
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
  /** Pin the current host for a session; release only after that session drains. */
  acquire(): { host: PluginHost; release: () => void };
  /**
   * Reconcile approvals for future sessions. Replaced hosts remain alive while
   * leased, so a marketplace change cannot interrupt a running chat.
   */
  refresh(): Promise<void>;
  /**
   * Ensure one enabled plugin is loaded into the live host (the market RUN
   * path): refresh first so a just-enabled id is loadable, then report whether
   * it is now loaded. Never loads a non-loadable id — the loader still refuses.
   */
  runPlugin(pluginId: string): Promise<CoreLoadResult>;
  /**
   * Subscribe to future-session host replacements, without rebuilding live sessions.
   */
  onChanged(listener: SessionPluginHostListener): () => void;
  /** Stop admitting work; leased hosts drain when their owners release them. */
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
  const leases = new Map<PluginHostLike, number>();
  let disposed = false;
  let refreshTail: Promise<void> = Promise.resolve();

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

  /** Publish a new approved host; retire the old host without breaking its leases. */
  async function reconstruct(
    c: CorePluginApi,
    enabled: readonly string[],
    emit: boolean,
  ): Promise<void> {
    const next = buildHost(c, enabled);
    const nextLoaded = new Map<string, string[]>();
    await loadAll(next, enabled, nextLoaded);
    if (disposed) {
      next.shutdown?.();
      throw new Error("Marketplace host manager is closed");
    }

    const old = host;
    host = next;
    loaded = nextLoaded;
    enabledKey = enabled.slice().sort().join("\n");

    if (old && !leases.has(old)) {
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
    if (disposed) throw new Error("Marketplace host manager is closed");
    const operation = refreshTail.then(async () => {
    if (disposed) throw new Error("Marketplace host manager is closed");
    const c = await getCore();
    if (disposed) throw new Error("Marketplace host manager is closed");
    const enabled = computeLoadable(c);
    const key = enabled.join("\n");

    if (host && key === enabledKey && (!leases.has(host) || enabled.every((id) => loaded.has(id)))) {
      // Never load into a leased host: even a retry changes its tool/gate maps.
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
    });
    refreshTail = operation.catch(() => {});
    return operation;
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
    if (disposed || !host) throw new Error("Marketplace host manager is closed");
    return host as unknown as PluginHost;
  }

  function acquire(): { host: PluginHost; release: () => void } {
    const owned = current();
    const pinned = host!;
    leases.set(pinned, (leases.get(pinned) ?? 0) + 1);
    let released = false;
    return {
      host: owned,
      release() {
        if (released) return;
        released = true;
        const count = (leases.get(pinned) ?? 1) - 1;
        if (count > 0) {
          leases.set(pinned, count);
          return;
        }
        leases.delete(pinned);
        if (pinned !== host || disposed) pinned.shutdown?.();
      },
    };
  }

  function dispose(): void {
    if (disposed) return;
    disposed = true;
    listeners.clear();
    const old = host;
    host = undefined;
    loaded = new Map();
    enabledKey = "";
    if (old && !leases.has(old)) {
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

  return { current, acquire, refresh, runPlugin, onChanged, dispose };
}
