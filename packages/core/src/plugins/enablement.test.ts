import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { PluginManifest } from "./manifest.js";
import {
  aggregateCapabilities,
  coerceEnablementRecord,
  disable,
  emptyEnablement,
  enable,
  enablementFilePath,
  ENABLEMENT_DIR_MODE,
  ENABLEMENT_FILE_MODE,
  isEnabled,
  loadableIds,
  readEnablement,
  reconcile,
  writeEnablement,
  type InstalledPluginView,
} from "./enablement.js";

// ── fixtures ─────────────────────────────────────────────────────────────────

function manifest(overrides: Partial<PluginManifest> = {}): PluginManifest {
  return {
    id: "acme.recon",
    name: "Acme Recon",
    version: "1.0.0",
    tools: [
      { name: "acme_probe", description: "probe", parameters: {}, capabilities: ["network"] },
      { name: "acme_read", description: "read", parameters: {}, capabilities: ["filesystem-read"] },
    ],
    ...overrides,
  };
}

function installed(overrides: Partial<InstalledPluginView> = {}): InstalledPluginView {
  return { id: "acme.recon", version: "1.0.0", capabilities: ["network", "filesystem-read"], ...overrides };
}

let home: string;
let project: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "0sec-enable-home-"));
  project = mkdtempSync(join(tmpdir(), "0sec-enable-proj-"));
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(project, { recursive: true, force: true });
});

// ── aggregateCapabilities ────────────────────────────────────────────────────

describe("aggregateCapabilities", () => {
  it("unions tool capabilities, de-dupes, and returns stable order", () => {
    const m = manifest({
      tools: [
        { name: "a", description: "a", parameters: {}, capabilities: ["findings-write", "network"] },
        { name: "b", description: "b", parameters: {}, capabilities: ["network", "filesystem-read"] },
      ],
    });
    // Stable order is the PLUGIN_CAPABILITIES order: network, filesystem-read, …, findings-write.
    expect(aggregateCapabilities(m)).toEqual(["network", "filesystem-read", "findings-write"]);
  });

  it("ignores unknown capabilities defensively", () => {
    const m = manifest({
      tools: [
        { name: "a", description: "a", parameters: {}, capabilities: ["network", "bogus" as never] },
      ],
    });
    expect(aggregateCapabilities(m)).toEqual(["network"]);
  });
});

// ── pure decisions ───────────────────────────────────────────────────────────

describe("enable / disable / isEnabled", () => {
  it("records an approval with the normalized capability set", () => {
    const r = enable(emptyEnablement(), "acme.recon", {
      version: "1.0.0",
      capabilities: ["filesystem-read", "network"],
      now: 111,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(isEnabled(r.record, "acme.recon")).toBe(true);
    // Normalized to PLUGIN_CAPABILITIES order.
    expect(r.record.enabled["acme.recon"]).toEqual({
      version: "1.0.0",
      capabilities: ["network", "filesystem-read"],
      enabledAt: 111,
    });
  });

  it("is pure — does not mutate the input record", () => {
    const base = emptyEnablement();
    const r = enable(base, "acme.recon", { version: "1.0.0", capabilities: ["network"], now: 1 });
    expect(r.ok).toBe(true);
    expect(isEnabled(base, "acme.recon")).toBe(false);
  });

  it("rejects a path-traversal plugin id before it becomes a key", () => {
    for (const bad of ["../evil", "a/b", "..", ".", "A", "foo\0bar", "/abs"]) {
      const r = enable(emptyEnablement(), bad, { version: "1.0.0", capabilities: ["network"], now: 1 });
      expect(r.ok).toBe(false);
    }
  });

  it("disable removes an approval and is a no-op when absent", () => {
    const enabled = enable(emptyEnablement(), "acme.recon", {
      version: "1.0.0",
      capabilities: ["network"],
      now: 1,
    });
    expect(enabled.ok).toBe(true);
    if (!enabled.ok) return;
    const off = disable(enabled.record, "acme.recon");
    expect(isEnabled(off, "acme.recon")).toBe(false);
    // no-op path returns the same record
    expect(disable(off, "acme.recon")).toBe(off);
  });
});

// ── reconcile: the re-approval rule ──────────────────────────────────────────

describe("reconcile", () => {
  function enabledFor(caps: PluginManifest["tools"][number]["capabilities"], version = "1.0.0") {
    const r = enable(emptyEnablement(), "acme.recon", { version, capabilities: caps, now: 1 });
    if (!r.ok) throw new Error("enable failed in fixture");
    return r.record;
  }

  it("reports a matching approval as enabled and loadable", () => {
    const rec = enabledFor(["network", "filesystem-read"]);
    const [out] = reconcile(rec, [installed()]);
    expect(out.status).toBe("enabled");
    expect(loadableIds(reconcile(rec, [installed()]))).toEqual(["acme.recon"]);
  });

  it("reports a WIDENED capability set as stale, not loadable", () => {
    // Approved for filesystem-read only; the plugin now also declares network.
    const rec = enabledFor(["filesystem-read"]);
    const now = installed({ capabilities: ["network", "filesystem-read"] });
    const [out] = reconcile(rec, [now]);
    expect(out.status).toBe("stale-capabilities");
    expect(out.approvedCapabilities).toEqual(["filesystem-read"]);
    expect(out.currentCapabilities).toEqual(["network", "filesystem-read"]);
    expect(loadableIds(reconcile(rec, [now]))).toEqual([]);
  });

  it("reports ANY capability change (even a narrowing) as stale", () => {
    const rec = enabledFor(["network", "filesystem-read"]);
    const now = installed({ capabilities: ["network"] });
    expect(reconcile(rec, [now])[0].status).toBe("stale-capabilities");
  });

  it("reports a vanished plugin as missing, not loadable", () => {
    const rec = enabledFor(["network"]);
    const [out] = reconcile(rec, []);
    expect(out.status).toBe("missing");
    expect(out.currentCapabilities).toBeNull();
    expect(loadableIds(reconcile(rec, []))).toEqual([]);
  });

  it("a version bump with an unchanged capability set stays loadable", () => {
    const rec = enabledFor(["network", "filesystem-read"], "1.0.0");
    const now = installed({ version: "2.0.0" });
    expect(reconcile(rec, [now])[0].status).toBe("enabled");
  });
});

// ── fs layer: totality + permissions + round-trip ────────────────────────────

describe("fs layer", () => {
  it("readEnablement returns empty for a missing store, never throwing", () => {
    const rec = readEnablement(project, home);
    expect(rec.enabled).toEqual({});
  });

  it("round-trips through disk with 0600/0700 perms", () => {
    const r = enable(emptyEnablement(), "acme.recon", {
      version: "1.0.0",
      capabilities: ["network"],
      now: 7,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(writeEnablement(project, r.record, home)).toBe(true);

    const back = readEnablement(project, home);
    expect(isEnabled(back, "acme.recon")).toBe(true);
    expect(back.enabled["acme.recon"].capabilities).toEqual(["network"]);

    const path = enablementFilePath(project, home);
    expect(statSync(path).mode & 0o777).toBe(ENABLEMENT_FILE_MODE);
    expect(statSync(join(home, ".0sec", "plugin-enablement")).mode & 0o777).toBe(
      ENABLEMENT_DIR_MODE,
    );
  });

  it("readEnablement degrades to empty on corrupt / non-JSON files", () => {
    const path = enablementFilePath(project, home);
    mkdirSync(join(home, ".0sec", "plugin-enablement"), { recursive: true });
    writeFileSync(path, "this is not json {{{");
    expect(readEnablement(project, home).enabled).toEqual({});
  });

  it("coerce drops unsafe keys and unknown capabilities without throwing", () => {
    const rec = coerceEnablementRecord(
      {
        enabled: {
          "acme.recon": { version: "1.0.0", capabilities: ["network", "bogus"], enabledAt: 1 },
          "../evil": { version: "1.0.0", capabilities: ["network"], enabledAt: 1 },
          __proto__: { version: "1.0.0", capabilities: ["network"], enabledAt: 1 },
          "not.an.object": 42,
        },
      },
      "/p",
    );
    expect(Object.keys(rec.enabled)).toEqual(["acme.recon"]);
    expect(rec.enabled["acme.recon"].capabilities).toEqual(["network"]);
  });

  it("coerce is total for arbitrary garbage", () => {
    for (const g of [null, 42, "x", [], { enabled: 7 }, { enabled: [] }]) {
      expect(() => coerceEnablementRecord(g, "/p")).not.toThrow();
      expect(coerceEnablementRecord(g, "/p").enabled).toEqual({});
    }
  });

  it("writeEnablement writes a distinct file per project realpath", () => {
    const other = mkdtempSync(join(tmpdir(), "0sec-enable-proj2-"));
    try {
      expect(enablementFilePath(project, home)).not.toBe(enablementFilePath(other, home));
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });
});
