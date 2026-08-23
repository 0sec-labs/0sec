import { describe, expect, it, vi } from "vitest";

import { createPluginService, type CorePluginApi } from "./plugin-service.js";
import type { MarketItem } from "./market-layout.js";
import {
  createSessionPluginHostManager,
  type SessionPluginHostDeps,
} from "./session-plugin-host.js";

// ---------------------------------------------------------------------------
// A fake host: records loads/shutdowns, mimics the loader's enablement refusal.
// No subprocess is ever spawned.
// ---------------------------------------------------------------------------

interface FakeHostOpts {
  failIds?: Set<string>;
  throwIds?: Set<string>;
}

class FakeHost {
  loadedIds = new Set<string>();
  shutdownCalled = false;
  constructor(
    readonly enabled: readonly string[],
    readonly reservedToolNames: readonly string[] | undefined,
    readonly coreVersion: string | undefined,
    private readonly opts: FakeHostOpts,
  ) {}
  async load(id: string): Promise<{ ok: boolean; pluginId: string; tools?: string[]; errors?: string[] }> {
    if (this.opts.throwIds?.has(id)) throw new Error("boom");
    // The loader is the enablement authority: a non-enabled id never loads.
    if (!this.enabled.includes(id)) return { ok: false, pluginId: id, errors: ["not enabled"] };
    if (this.opts.failIds?.has(id)) return { ok: false, pluginId: id, errors: ["load failed"] };
    this.loadedIds.add(id);
    return { ok: true, pluginId: id, tools: [`${id}.t`] };
  }
  shutdown(): void {
    this.shutdownCalled = true;
  }
}

function makeHostFactory(opts: FakeHostOpts = {}): {
  factory: NonNullable<SessionPluginHostDeps["hostFactory"]>;
  built: FakeHost[];
} {
  const built: FakeHost[] = [];
  const factory: NonNullable<SessionPluginHostDeps["hostFactory"]> = (o) => {
    const h = new FakeHost(o.enabled, o.reservedToolNames, o.coreVersion, opts);
    built.push(h);
    return h;
  };
  return { factory, built };
}

// ---------------------------------------------------------------------------
// A fake @0sec/core whose "on disk" enabled/installed set is mutable, so a test
// can change what enablement.ts would report between refreshes.
// ---------------------------------------------------------------------------

function makeCore(onDisk: { ids: string[] }): CorePluginApi {
  return {
    fetchRegistryIndex: async () => ({ ok: true, result: { entries: [], artifacts: [] } }),
    unconfiguredVerifier: {},
    isSafePluginId: (v) => typeof v === "string" && /^[a-z][a-z0-9]*([._-][a-z0-9]+)*$/.test(v),
    pluginsRootDir: () => "/tmp/does-not-exist-root",
    ensurePluginsRoot: () => true,
    listInstalledPluginIds: () => [...onDisk.ids],
    readInstalledPlugin: (_root, id) => ({
      ok: true,
      plugin: { manifest: { id, name: id, version: "1.0.0", tools: [] } },
    }),
    aggregateCapabilities: () => [],
    PLUGIN_MANIFEST_FILE: "plugin.json",
    PLUGIN_ENTRY_FILE: "plugin.js",
    PLUGIN_DIR_MODE: 0o700,
    PLUGIN_FILE_MODE: 0o600,
    // Every installed id counts as enabled/loadable in these fakes; the disk set
    // itself is what a test mutates.
    readEnablement: () => ({ enabled: Object.fromEntries(onDisk.ids.map((id) => [id, {}])) }),
    writeEnablement: () => true,
    enable: (record, pluginId, opts) => ({
      ok: true,
      record: {
        enabled: { ...record.enabled, [pluginId]: { version: opts.version, capabilities: opts.capabilities } },
      },
    }),
    reconcile: (record) =>
      Object.keys(record.enabled).map((pluginId) => ({ pluginId, status: "enabled" })),
    loadableIds: (reconciled) => reconciled.filter((r) => r.status === "enabled").map((r) => r.pluginId),
    PluginHost: class {
      async load(pluginId: string) {
        return { ok: true, pluginId, tools: ["t"] };
      }
    },
  };
}

function pluginItem(id: string): MarketItem {
  return {
    kind: "plugin",
    id,
    name: id,
    version: "1.0.0",
    description: "",
    capabilities: [],
    signature: "unverified",
    raw: { id, version: "1.0.0", manifest: { id, name: id, version: "1.0.0", tools: [] } },
  };
}

// ---------------------------------------------------------------------------

describe("SessionPluginHostManager — initial build", () => {
  it("primes a host from the on-disk enabled set and loads those plugins", async () => {
    const onDisk = { ids: ["a.one", "a.two"] };
    const { factory, built } = makeHostFactory();
    const mgr = await createSessionPluginHostManager({
      core: makeCore(onDisk),
      hostFactory: factory,
    });
    expect(built).toHaveLength(1);
    expect([...built[0].loadedIds].sort()).toEqual(["a.one", "a.two"]);
    // current() hands back the live host object.
    expect(mgr.current() as unknown as FakeHost).toBe(built[0]);
  });

  it("passes reservedToolNames + coreVersion to every host it builds", async () => {
    const { factory, built } = makeHostFactory();
    await createSessionPluginHostManager({
      core: makeCore({ ids: ["a.one"] }),
      hostFactory: factory,
      reservedToolNames: ["http_request", "run_command"],
      coreVersion: "9.9.9",
    });
    expect(built[0].reservedToolNames).toEqual(["http_request", "run_command"]);
    expect(built[0].coreVersion).toBe("9.9.9");
  });

  it("is fail-soft: one plugin that throws on load never aborts the rest", async () => {
    const { factory, built } = makeHostFactory({ throwIds: new Set(["a.bad"]) });
    await createSessionPluginHostManager({
      core: makeCore({ ids: ["a.bad", "a.good"] }),
      hostFactory: factory,
    });
    expect([...built[0].loadedIds]).toEqual(["a.good"]);
  });
});

describe("SessionPluginHostManager — refresh + reconstruction", () => {
  it("reconstructs, swaps, disposes the old host, and notifies when the set changes", async () => {
    const onDisk = { ids: ["a.one"] };
    const { factory, built } = makeHostFactory();
    const mgr = await createSessionPluginHostManager({
      core: makeCore(onDisk),
      hostFactory: factory,
    });
    const changed = vi.fn();
    mgr.onChanged(changed);

    // An operator enables a second plugin: the on-disk set widens.
    onDisk.ids.push("a.two");
    await mgr.refresh();

    expect(built).toHaveLength(2);
    // Old host disposed, new host carries the widened set fully loaded.
    expect(built[0].shutdownCalled).toBe(true);
    expect([...built[1].loadedIds].sort()).toEqual(["a.one", "a.two"]);
    // The subscriber was handed the NEW host so the shell can re-hand it.
    expect(changed).toHaveBeenCalledTimes(1);
    expect(changed.mock.calls[0][0] as unknown as FakeHost).toBe(built[1]);
    expect(mgr.current() as unknown as FakeHost).toBe(built[1]);
  });

  it("does NOT reconstruct when the enabled set is unchanged", async () => {
    const { factory, built } = makeHostFactory();
    const mgr = await createSessionPluginHostManager({
      core: makeCore({ ids: ["a.one"] }),
      hostFactory: factory,
    });
    const changed = vi.fn();
    mgr.onChanged(changed);
    await mgr.refresh();
    expect(built).toHaveLength(1);
    expect(changed).not.toHaveBeenCalled();
  });

  it("recovers a soft-failed plugin on a same-set refresh without a swap", async () => {
    const failIds = new Set<string>(["a.one"]);
    const built: FakeHost[] = [];
    const factory: NonNullable<SessionPluginHostDeps["hostFactory"]> = (o) => {
      const h = new FakeHost(o.enabled, o.reservedToolNames, o.coreVersion, { failIds });
      built.push(h);
      return h;
    };
    const mgr = await createSessionPluginHostManager({
      core: makeCore({ ids: ["a.one"] }),
      hostFactory: factory,
    });
    // Initial load failed soft.
    expect([...built[0].loadedIds]).toEqual([]);
    // The failure clears; a same-set refresh retries the load into the SAME host.
    failIds.delete("a.one");
    await mgr.refresh();
    expect(built).toHaveLength(1);
    expect([...built[0].loadedIds]).toEqual(["a.one"]);
  });
});

describe("SessionPluginHostManager — runPlugin (the market RUN path)", () => {
  it("loads an enabled plugin and reports its tools", async () => {
    const onDisk = { ids: [] as string[] };
    const { factory } = makeHostFactory();
    const mgr = await createSessionPluginHostManager({ core: makeCore(onDisk), hostFactory: factory });
    // The plugin becomes enabled on disk, then run.
    onDisk.ids.push("a.one");
    const res = await mgr.runPlugin("a.one");
    expect(res.ok).toBe(true);
    expect(res.tools).toEqual(["a.one.t"]);
  });

  it("refuses a plugin that is not loadable (never bypasses the loader)", async () => {
    const { factory } = makeHostFactory();
    const mgr = await createSessionPluginHostManager({ core: makeCore({ ids: [] }), hostFactory: factory });
    const res = await mgr.runPlugin("a.absent");
    expect(res.ok).toBe(false);
    expect(res.errors?.join(" ")).toContain("not loaded");
  });
});

describe("SessionPluginHostManager — dispose", () => {
  it("shuts the live host down and is idempotent", async () => {
    const { factory, built } = makeHostFactory();
    const mgr = await createSessionPluginHostManager({ core: makeCore({ ids: ["a.one"] }), hostFactory: factory });
    mgr.dispose();
    mgr.dispose();
    expect(built[0].shutdownCalled).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Integration: plugin-service ENABLE + RUN route through an injected manager.
// ---------------------------------------------------------------------------

describe("PluginService ↔ SessionPluginHostManager integration", () => {
  it("run loads through the manager's host, not the bridge's own", async () => {
    const onDisk = { ids: ["a.one"] };
    const core = makeCore(onDisk);
    const { factory, built } = makeHostFactory();
    const manager = await createSessionPluginHostManager({ core, hostFactory: factory });

    const svc = createPluginService({ core, pluginHostManager: manager, isTurnActive: () => false });
    const res = await svc.run(pluginItem("a.one"));
    expect(res.ok).toBe(true);
    expect(res.message).toContain("a.one.t");
    // The manager's host did the load; only the manager ever built a host.
    expect(built).toHaveLength(1);
    expect(built[0].loadedIds.has("a.one")).toBe(true);
  });

  it("enable triggers a manager refresh at a turn boundary", async () => {
    const core = makeCore({ ids: ["a.one"] });
    const { factory } = makeHostFactory();
    const manager = await createSessionPluginHostManager({ core, hostFactory: factory });
    const spy = vi.spyOn(manager, "refresh");

    const svc = createPluginService({ core, pluginHostManager: manager, isTurnActive: () => false });
    const res = await svc.enable(pluginItem("a.one"));
    expect(res.ok).toBe(true);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("enable does NOT refresh while a turn is in flight", async () => {
    const core = makeCore({ ids: ["a.one"] });
    const { factory } = makeHostFactory();
    const manager = await createSessionPluginHostManager({ core, hostFactory: factory });
    const spy = vi.spyOn(manager, "refresh");

    const svc = createPluginService({ core, pluginHostManager: manager, isTurnActive: () => true });
    await svc.enable(pluginItem("a.one"));
    expect(spy).not.toHaveBeenCalled();
  });

  it("run defers past a live turn, then loads through the manager on flush", async () => {
    let turnActive = true;
    const onDisk = { ids: ["a.one"] };
    const core = makeCore(onDisk);
    const { factory, built } = makeHostFactory();
    const manager = await createSessionPluginHostManager({ core, hostFactory: factory });

    const svc = createPluginService({ core, pluginHostManager: manager, isTurnActive: () => turnActive });
    const deferred = await svc.run(pluginItem("a.one"));
    expect(deferred.deferred).toBe(true);
    expect(built[0].loadedIds.has("a.one")).toBe(true); // loaded at initial build

    turnActive = false;
    const flushed = await svc.flushDeferred();
    expect(flushed).toHaveLength(1);
    expect(flushed[0].ok).toBe(true);
  });
});
