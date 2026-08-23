import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createPluginService, type CorePluginApi } from "./plugin-service.js";
import type { MarketItem } from "./market-layout.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function pluginItem(id: string, capabilities: string[] = [], files?: Record<string, string>): MarketItem {
  return {
    kind: "plugin",
    id,
    name: id,
    version: "1.0.0",
    description: "",
    capabilities,
    signature: "unverified",
    raw: {
      id,
      version: "1.0.0",
      manifest: { id, name: id, version: "1.0.0", tools: [{ name: "t", capabilities }] },
      files,
    },
  };
}

function themeItem(id: string): MarketItem {
  return {
    kind: "theme",
    id,
    name: id,
    version: "1.0.0",
    description: "",
    capabilities: [],
    signature: "unverified",
    raw: { manifest: { theme: { palette: { CANVAS: "#000000" } } } },
  };
}

/** A fake @0sec/core: every method has a benign default, overridable per test. */
function fakeCore(overrides: Partial<CorePluginApi> = {}): CorePluginApi {
  const base: CorePluginApi = {
    fetchRegistryIndex: async () => ({ ok: true, result: { entries: [], artifacts: [] } }),
    unconfiguredVerifier: {},
    isSafePluginId: (v) => typeof v === "string" && /^[a-z][a-z0-9]*([._-][a-z0-9]+)*$/.test(v),
    pluginsRootDir: () => "/tmp/does-not-exist-root",
    ensurePluginsRoot: () => true,
    listInstalledPluginIds: () => [],
    readInstalledPlugin: (_root, id) => ({
      ok: true,
      plugin: { manifest: { id, name: id, version: "1.0.0", tools: [] } },
    }),
    aggregateCapabilities: (m) => {
      const set = new Set<string>();
      for (const tool of m.tools ?? []) for (const c of tool.capabilities ?? []) set.add(c);
      return [...set];
    },
    PLUGIN_MANIFEST_FILE: "plugin.json",
    PLUGIN_ENTRY_FILE: "plugin.js",
    PLUGIN_DIR_MODE: 0o700,
    PLUGIN_FILE_MODE: 0o600,
    readEnablement: () => ({ enabled: {} }),
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
  return { ...base, ...overrides };
}

// ---------------------------------------------------------------------------

describe("PluginService.fetchRegistry", () => {
  it("passes a validated index straight through", async () => {
    const svc = createPluginService({
      core: fakeCore({
        fetchRegistryIndex: async () => ({ ok: true, result: { entries: [{ id: "a.b", version: "1.0.0" }] } }),
      }),
    });
    const res = await svc.fetchRegistry();
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.result.entries?.[0]?.id).toBe("a.b");
  });

  it("surfaces a registry error without throwing", async () => {
    const svc = createPluginService({
      core: fakeCore({ fetchRegistryIndex: async () => ({ ok: false, error: "no endpoint" }) }),
    });
    const res = await svc.fetchRegistry();
    expect(res).toEqual({ ok: false, error: "no endpoint" });
  });

  it("degrades a thrown core error to a message, never a crash", async () => {
    const svc = createPluginService({
      core: fakeCore({
        fetchRegistryIndex: async () => {
          throw new Error("boom");
        },
      }),
    });
    const res = await svc.fetchRegistry();
    expect(res.ok).toBe(false);
  });
});

describe("PluginService.list", () => {
  it("reports a plugin `enabled` only when its approval still reconciles", async () => {
    const svc = createPluginService({
      core: fakeCore({
        listInstalledPluginIds: () => ["a.ok", "a.stale", "a.plain"],
        readEnablement: () => ({ enabled: { "a.ok": {}, "a.stale": {} } }),
        reconcile: () => [
          { pluginId: "a.ok", status: "enabled" },
          { pluginId: "a.stale", status: "stale-capabilities" },
        ],
        loadableIds: (r) => r.filter((x) => x.status === "enabled").map((x) => x.pluginId),
      }),
    });
    const index = await svc.list("dark");
    expect(index.activeTheme).toBe("dark");
    expect(index.plugins.get("a.ok")).toBe("enabled");
    // Approved once but capabilities widened → not loadable → back to installed.
    expect(index.plugins.get("a.stale")).toBe("installed");
    expect(index.plugins.get("a.plain")).toBe("installed");
  });

  it("fails soft to an empty plugin map when core throws", async () => {
    const svc = createPluginService({
      core: fakeCore({
        listInstalledPluginIds: () => {
          throw new Error("unreadable");
        },
      }),
    });
    const index = await svc.list("dark");
    expect(index.plugins.size).toBe(0);
  });
});

describe("PluginService.enable — the explicit, separate approval", () => {
  it("records the ON-DISK capability set and persists it", async () => {
    let persisted: unknown;
    const svc = createPluginService({
      core: fakeCore({
        readInstalledPlugin: (_r, id) => ({
          ok: true,
          plugin: { manifest: { id, name: id, version: "2.0.0", tools: [{ capabilities: ["network"] }] } },
        }),
        writeEnablement: (_p, record) => {
          persisted = record;
          return true;
        },
      }),
    });
    const res = await svc.enable(pluginItem("a.net", ["network"]));
    expect(res.ok).toBe(true);
    expect(res.state).toBe("enabled");
    expect(res.capabilities).toEqual(["network"]);
    expect(res.message).toContain("network");
    expect(persisted).toBeDefined();
  });

  it("refuses to enable a plugin that is not installed", async () => {
    const svc = createPluginService({
      core: fakeCore({
        readInstalledPlugin: () => ({ ok: false, errors: ["no readable plugin.json"] }),
      }),
    });
    const res = await svc.enable(pluginItem("a.missing"));
    expect(res.ok).toBe(false);
    expect(res.message).toContain("Install it first");
  });

  it("refuses to persist without an approval record (fail-soft on write failure)", async () => {
    const svc = createPluginService({ core: fakeCore({ writeEnablement: () => false }) });
    const res = await svc.enable(pluginItem("a.x"));
    expect(res.ok).toBe(false);
    expect(res.message).toContain("Could not persist");
  });

  it("refuses to enable a theme", async () => {
    const svc = createPluginService({ core: fakeCore() });
    const res = await svc.enable(themeItem("midnight"));
    expect(res.ok).toBe(false);
  });
});

describe("PluginService.run — only enabled, only at a turn boundary", () => {
  it("refuses to run a plugin that is not loadable", async () => {
    const svc = createPluginService({
      core: fakeCore({ readEnablement: () => ({ enabled: {} }), reconcile: () => [], loadableIds: () => [] }),
    });
    const res = await svc.run(pluginItem("a.x"));
    expect(res.ok).toBe(false);
    expect(res.message).toContain("enable it first");
  });

  it("loads an enabled plugin through the host at a turn boundary", async () => {
    let loaded = "";
    const svc = createPluginService({
      isTurnActive: () => false,
      hostFactory: () => ({
        load: async (id: string) => {
          loaded = id;
          return { ok: true, pluginId: id, tools: ["scan"] };
        },
      }),
      core: fakeCore({
        readEnablement: () => ({ enabled: { "a.x": {} } }),
        reconcile: () => [{ pluginId: "a.x", status: "enabled" }],
        loadableIds: (r) => r.map((x) => x.pluginId),
      }),
    });
    const res = await svc.run(pluginItem("a.x"));
    expect(res.ok).toBe(true);
    expect(loaded).toBe("a.x");
    expect(res.message).toContain("scan");
  });

  it("DEFERS a load while a turn is in flight, then flushes it at the boundary", async () => {
    let turnActive = true;
    const loads: string[] = [];
    const svc = createPluginService({
      isTurnActive: () => turnActive,
      hostFactory: () => ({
        load: async (id: string) => {
          loads.push(id);
          return { ok: true, pluginId: id, tools: [] };
        },
      }),
      core: fakeCore({
        readEnablement: () => ({ enabled: { "a.x": {} } }),
        reconcile: () => [{ pluginId: "a.x", status: "enabled" }],
        loadableIds: (r) => r.map((x) => x.pluginId),
      }),
    });
    const deferredRes = await svc.run(pluginItem("a.x"));
    expect(deferredRes.ok).toBe(false);
    expect(deferredRes.deferred).toBe(true);
    expect(loads).toEqual([]); // nothing loaded mid-turn

    turnActive = false;
    const flushed = await svc.flushDeferred();
    expect(loads).toEqual(["a.x"]); // loaded once the turn ended
    expect(flushed[0]?.ok).toBe(true);
  });

  it("surfaces a host load failure as a message", async () => {
    const svc = createPluginService({
      hostFactory: () => ({ load: async (id: string) => ({ ok: false, pluginId: id, errors: ["not enabled"] }) }),
      core: fakeCore({
        readEnablement: () => ({ enabled: { "a.x": {} } }),
        reconcile: () => [{ pluginId: "a.x", status: "enabled" }],
        loadableIds: (r) => r.map((x) => x.pluginId),
      }),
    });
    const res = await svc.run(pluginItem("a.x"));
    expect(res.ok).toBe(false);
    expect(res.message).toContain("not enabled");
  });
});

describe("PluginService.activateTheme — hands off to the theme setting", () => {
  it("applies an installed theme via the injected setting", async () => {
    let appliedTo = "";
    const svc = createPluginService({
      core: fakeCore(),
      applyTheme: (id) => {
        appliedTo = id;
        return true;
      },
    });
    const res = await svc.activateTheme(themeItem("midnight"));
    expect(res.ok).toBe(true);
    expect(res.state).toBe("active");
    expect(appliedTo).toBe("midnight");
  });

  it("reports a failed apply without throwing", async () => {
    const svc = createPluginService({ core: fakeCore(), applyTheme: () => false });
    const res = await svc.activateTheme(themeItem("midnight"));
    expect(res.ok).toBe(false);
  });

  it("refuses to activate a plugin", async () => {
    const svc = createPluginService({ core: fakeCore() });
    const res = await svc.activateTheme(pluginItem("a.x"));
    expect(res.ok).toBe(false);
  });
});

describe("PluginService.install — writes bytes, never enables, never runs", () => {
  let root: string;
  afterEach(() => {
    if (root) rmSync(root, { recursive: true, force: true });
  });

  it("copies a plugin's validated files to disk and enables nothing", async () => {
    root = mkdtempSync(join(tmpdir(), "0sec-plugin-svc-"));
    let enableWritten = false;
    let hostBuilt = false;
    const svc = createPluginService({
      hostFactory: () => {
        hostBuilt = true;
        return { load: async (id: string) => ({ ok: true, pluginId: id, tools: [] }) };
      },
      core: fakeCore({
        pluginsRootDir: () => root,
        writeEnablement: () => {
          enableWritten = true;
          return true;
        },
      }),
    });
    const item = pluginItem("a.tool", ["network"], {
      "plugin.js": "module.exports = {};\n",
    });
    const res = await svc.install(item);
    expect(res.ok).toBe(true);
    expect(res.state).toBe("installed");
    expect(existsSync(join(root, "a.tool", "plugin.js"))).toBe(true);
    expect(existsSync(join(root, "a.tool", "plugin.json"))).toBe(true);
    const manifest = JSON.parse(readFileSync(join(root, "a.tool", "plugin.json"), "utf-8"));
    expect(manifest.id).toBe("a.tool");
    // The security contract: install neither enabled nor ran anything.
    expect(enableWritten).toBe(false);
    expect(hostBuilt).toBe(false);
    expect(res.message).toContain("NOT enabled");
  });

  it("refuses a plugin entry missing its entrypoint", async () => {
    root = mkdtempSync(join(tmpdir(), "0sec-plugin-svc-"));
    const svc = createPluginService({ core: fakeCore({ pluginsRootDir: () => root }) });
    const res = await svc.install(pluginItem("a.tool", [], {}));
    expect(res.ok).toBe(false);
    expect(res.message).toContain("plugin.js");
  });
});
