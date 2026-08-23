import { describe, expect, it, vi } from "vitest";

import type { PluginManifest } from "./manifest.js";
import {
  canonicalEntryPayload,
  createStubSignatureVerifier,
  DEFAULT_REGISTRY_URL,
  evaluateSignature,
  fetchRegistryIndex,
  findInstallable,
  installableFromEntry,
  MAX_REGISTRY_ENTRIES,
  parseRegistryIndex,
  searchInstallable,
  unconfiguredVerifier,
  type RawRegistryEntry,
  type SignatureVerifier,
} from "./registry-client.js";

// ── fixtures ─────────────────────────────────────────────────────────────────

function manifest(overrides: Partial<PluginManifest> = {}): PluginManifest {
  return {
    id: "acme.recon",
    name: "Acme Recon",
    version: "1.0.0",
    tools: [
      { name: "acme_probe", description: "probe", parameters: {}, capabilities: ["network"] },
    ],
    ...overrides,
  };
}

function entry(overrides: Partial<RawRegistryEntry> = {}): RawRegistryEntry {
  const m = (overrides.manifest as PluginManifest) ?? manifest();
  return {
    id: m.id,
    version: m.version,
    manifest: m,
    source: { kind: "inline", files: { "plugin.json": "{}", "plugin.js": "// noop" } },
    ...overrides,
  };
}

/** A fetch that returns a JSON body without any network. */
function fakeFetch(body: unknown, init: { ok?: boolean; status?: number } = {}): typeof fetch {
  return vi.fn(async () => ({
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: async () => body,
  })) as unknown as typeof fetch;
}

// ── DEFAULT_REGISTRY_URL ─────────────────────────────────────────────────────

describe("DEFAULT_REGISTRY_URL", () => {
  it("ships empty — no marketplace host is invented", () => {
    expect(DEFAULT_REGISTRY_URL).toBe("");
  });
});

// ── fetch policy ─────────────────────────────────────────────────────────────

describe("fetchRegistryIndex", () => {
  it("empty URL is a clear no-op and never fetches", async () => {
    const f = fakeFetch({ entries: [] });
    const res = await fetchRegistryIndex("", { fetchImpl: f });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toMatch(/no registry endpoint is configured/);
    expect(f).not.toHaveBeenCalled();
  });

  it("refuses http and never fetches", async () => {
    const f = fakeFetch({ entries: [] });
    const res = await fetchRegistryIndex("http://plugins.example/index.json", { fetchImpl: f });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toMatch(/must be https/);
    expect(f).not.toHaveBeenCalled();
  });

  it("fetches https and parses valid entries", async () => {
    const f = fakeFetch({ entries: [entry()] });
    const res = await fetchRegistryIndex("https://plugins.example/index.json", { fetchImpl: f });
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.result.entries.map((e) => e.id)).toEqual(["acme.recon"]);
    expect(f).toHaveBeenCalledOnce();
  });

  it("reports a non-2xx as a failure, not a throw", async () => {
    const f = fakeFetch({}, { ok: false, status: 503 });
    const res = await fetchRegistryIndex("https://plugins.example/index.json", { fetchImpl: f });
    expect(res.ok).toBe(false);
  });

  it("reports a thrown fetch / bad JSON as a failure", async () => {
    const f = vi.fn(async () => {
      throw new Error("network down");
    }) as unknown as typeof fetch;
    const res = await fetchRegistryIndex("https://plugins.example/index.json", { fetchImpl: f });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toMatch(/network down/);
  });

  it("refuses a redirect instead of following it (no http downgrade / SSRF)", async () => {
    const f = vi.fn(async () => ({
      ok: false,
      status: 302,
      json: async () => ({ entries: [] }),
    })) as unknown as typeof fetch;
    const res = await fetchRegistryIndex("https://plugins.example/index.json", { fetchImpl: f });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toMatch(/redirect/i);
  });

  it("rejects an index whose Content-Length exceeds the cap", async () => {
    const f = vi.fn(async () => ({
      ok: true,
      status: 200,
      headers: { get: (k: string) => (k.toLowerCase() === "content-length" ? "999999999" : null) },
      json: async () => ({ entries: [] }),
    })) as unknown as typeof fetch;
    const res = await fetchRegistryIndex("https://plugins.example/index.json", {
      fetchImpl: f,
      maxIndexBytes: 1024,
    });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toMatch(/too large/);
  });

  it("aborts a hung fetch after the timeout", async () => {
    vi.useFakeTimers();
    const f = vi.fn(
      (_url: unknown, init: { signal: AbortSignal }) =>
        new Promise((_resolve, reject) => {
          init.signal.addEventListener("abort", () =>
            reject(Object.assign(new Error("aborted"), { name: "AbortError" })),
          );
        }),
    ) as unknown as typeof fetch;
    const pending = fetchRegistryIndex("https://plugins.example/index.json", {
      fetchImpl: f,
      timeoutMs: 1000,
    });
    await vi.advanceTimersByTimeAsync(1001);
    const res = await pending;
    vi.useRealTimers();
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toMatch(/timed out/);
  });
});

// ── manifest validation on parse ─────────────────────────────────────────────

describe("parseRegistryIndex", () => {
  it("truncates an index past MAX_REGISTRY_ENTRIES (memory-amplification bound)", () => {
    const many = Array.from({ length: MAX_REGISTRY_ENTRIES + 2 }, () => ({}));
    const result = parseRegistryIndex(many);
    const total = result.entries.length + result.artifacts.length + result.dropped.length;
    expect(total).toBeLessThanOrEqual(MAX_REGISTRY_ENTRIES + 1);
    expect(result.dropped.some((d) => /truncated/.test(d.reason))).toBe(true);
  });

  it("drops a malformed manifest with a reason and never surfaces it as installable", () => {
    const bad = entry({ id: "acme.bad", version: "1.0.0", manifest: { id: "acme.bad" } });
    const result = parseRegistryIndex({ entries: [entry(), bad] });
    expect(result.entries.map((e) => e.id)).toEqual(["acme.recon"]);
    expect(result.dropped).toHaveLength(1);
    expect(result.dropped[0].reason).toMatch(/invalid manifest/);
  });

  it("drops an entry whose index id disagrees with its manifest id", () => {
    const mismatched = entry({ id: "acme.other" });
    const result = parseRegistryIndex({ entries: [mismatched] });
    expect(result.entries).toHaveLength(0);
    expect(result.dropped[0].reason).toMatch(/does not match manifest id/);
  });

  it("accepts a bare array as well as { entries }", () => {
    expect(parseRegistryIndex([entry()]).entries).toHaveLength(1);
  });

  it("is total for garbage index shapes", () => {
    for (const g of [null, 42, "x", { entries: 7 }]) {
      expect(() => parseRegistryIndex(g)).not.toThrow();
      expect(parseRegistryIndex(g).entries).toHaveLength(0);
    }
  });

  it("surfaces an aggregated capability summary per installable", () => {
    const m = manifest({
      tools: [
        { name: "a", description: "a", parameters: {}, capabilities: ["network"] },
        { name: "b", description: "b", parameters: {}, capabilities: ["filesystem-read"] },
      ],
    });
    const [e] = parseRegistryIndex([entry({ manifest: m })]).entries;
    expect(e.capabilities).toEqual(["network", "filesystem-read"]);
  });
});

// ── signature policy (crypto stubbed) ────────────────────────────────────────

describe("signature policy", () => {
  it("no configured key ⇒ unsigned entry is allowed as unverified", () => {
    const [e] = parseRegistryIndex([entry()], { verifier: unconfiguredVerifier }).entries;
    expect(e.signatureState).toBe("unverified");
  });

  it("configured key + unsigned entry ⇒ refused", () => {
    const verifier: SignatureVerifier = { keyConfigured: true, verify: () => true };
    const result = parseRegistryIndex([entry()], { verifier });
    expect(result.entries).toHaveLength(0);
    expect(result.dropped[0].reason).toMatch(/signature required/);
  });

  it("configured key + bad signature ⇒ refused", () => {
    const verifier: SignatureVerifier = { keyConfigured: true, verify: () => false };
    const result = parseRegistryIndex([entry({ signature: "deadbeef" })], { verifier });
    expect(result.entries).toHaveLength(0);
    expect(result.dropped[0].reason).toMatch(/verification failed/);
  });

  it("configured key + good signature ⇒ verified installable", () => {
    const verifier: SignatureVerifier = { keyConfigured: true, verify: () => true };
    const [e] = parseRegistryIndex([entry({ signature: "goodsig" })], { verifier }).entries;
    expect(e.signatureState).toBe("verified");
  });

  it("the SHIPPED stub verifier refuses everything (fail-closed, no real crypto)", () => {
    const stub = createStubSignatureVerifier();
    expect(stub.keyConfigured).toBe(true);
    expect(stub.verify(canonicalEntryPayload({ id: "x", version: "1.0.0", manifest: {}, source: {} }), "sig")).toBe(false);
    // With the stub installed, even a signed entry is refused.
    expect(parseRegistryIndex([entry({ signature: "sig" })], { verifier: stub }).entries).toHaveLength(0);
  });

  it("evaluateSignature honours the policy table", () => {
    const e = { id: "x", version: "1.0.0", manifest: {}, source: {} };
    expect(evaluateSignature(e, unconfiguredVerifier)).toBe("unverified");
    expect(evaluateSignature(e, { keyConfigured: true, verify: () => true })).toBe("refused-unsigned");
    expect(evaluateSignature({ ...e, signature: "s" }, { keyConfigured: true, verify: () => false })).toBe("refused-bad-signature");
    expect(evaluateSignature({ ...e, signature: "s" }, { keyConfigured: true, verify: () => true })).toBe("verified");
  });

  it("canonical payload is stable regardless of key order", () => {
    const a = canonicalEntryPayload({ id: "x", version: "1", manifest: { a: 1, b: 2 }, source: {} });
    const b = canonicalEntryPayload({ id: "x", version: "1", manifest: { b: 2, a: 1 }, source: {} });
    expect(a).toBe(b);
  });
});

// ── the index is data, never code ────────────────────────────────────────────

describe("index is inert data", () => {
  it("parsing an entry never executes its source files", () => {
    // A source file whose body would throw if evaluated is treated as an opaque
    // string — proof that installableFromEntry does not eval/import/run it.
    const evil = entry({
      source: { kind: "inline", files: { "plugin.js": "throw new Error('executed!')" } },
    });
    const result = installableFromEntry(evil);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.entry.files["plugin.js"]).toBe("throw new Error('executed!')");
  });

  it("drops a source that is not inline files", () => {
    const bad = installableFromEntry(entry({ source: { kind: "tarball", url: "https://x/y.tgz" } }));
    expect(bad.ok).toBe(false);
  });
});

// ── queries ──────────────────────────────────────────────────────────────────

describe("searchInstallable / findInstallable", () => {
  const entries = parseRegistryIndex([
    entry(),
    entry({ manifest: manifest({ id: "beta.scan", name: "Beta Scanner", tools: [
      { name: "beta_crawl", description: "c", parameters: {}, capabilities: ["network"] },
    ] }) }),
  ]).entries;

  it("matches on id, name, and tool name, case-insensitively", () => {
    expect(searchInstallable(entries, "ACME").map((e) => e.id)).toEqual(["acme.recon"]);
    expect(searchInstallable(entries, "scanner").map((e) => e.id)).toEqual(["beta.scan"]);
    expect(searchInstallable(entries, "crawl").map((e) => e.id)).toEqual(["beta.scan"]);
    expect(searchInstallable(entries, "").map((e) => e.id)).toEqual(["acme.recon", "beta.scan"]);
  });

  it("finds by exact id", () => {
    expect(findInstallable(entries, "beta.scan")?.id).toBe("beta.scan");
    expect(findInstallable(entries, "nope")).toBeUndefined();
  });
});

// ── Theme / config artifacts in the index (data, never code) ──────────────────

import {
  artifactFromEntry,
  findArtifact,
  searchArtifacts,
} from "./registry-client.js";

function themeEntry(overrides: Record<string, unknown> = {}): unknown {
  return {
    id: "acme.midnight",
    version: "1.0.0",
    manifest: {
      kind: "theme",
      id: "acme.midnight",
      name: "Acme Midnight",
      version: "1.0.0",
      theme: { label: "Midnight", mode: "dark", palette: { CANVAS: "#0A0E14", TEXT: "#E8ECF2" } },
    },
    ...overrides,
  };
}

function configEntry(overrides: Record<string, unknown> = {}): unknown {
  return {
    id: "acme.quiet",
    version: "1.0.0",
    manifest: {
      kind: "config",
      id: "acme.quiet",
      name: "Acme Quiet",
      version: "1.0.0",
      config: { showLogo: false },
    },
    ...overrides,
  };
}

describe("registry carries theme/config artifacts alongside tools", () => {
  it("routes tool, theme and config entries to their buckets", () => {
    const result = parseRegistryIndex([entry(), themeEntry(), configEntry()]);
    expect(result.entries.map((e) => e.id)).toEqual(["acme.recon"]);
    expect(result.artifacts.map((a) => `${a.kind}:${a.id}`)).toEqual([
      "theme:acme.midnight",
      "config:acme.quiet",
    ]);
    expect(result.dropped).toHaveLength(0);
  });

  it("drops an invalid theme manifest with a reason", () => {
    const bad = themeEntry({ manifest: { kind: "theme", id: "acme.midnight" } });
    const result = parseRegistryIndex([bad]);
    expect(result.artifacts).toHaveLength(0);
    expect(result.dropped[0].reason).toMatch(/invalid theme manifest/);
  });

  it("drops a theme entry that carries a source (data has none)", () => {
    const bad = themeEntry({ source: { kind: "inline", files: {} } });
    const res = artifactFromEntry(bad);
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.dropped.reason).toMatch(/must not carry a `source`/);
  });

  it("applies the signature policy to artifacts too (fail-closed)", () => {
    const verifier: SignatureVerifier = { keyConfigured: true, verify: () => false };
    const result = parseRegistryIndex([themeEntry()], { verifier });
    expect(result.artifacts).toHaveLength(0);
    expect(result.dropped[0].reason).toMatch(/signature required/);
  });

  it("marks an artifact verified with a good signature", () => {
    const verifier: SignatureVerifier = { keyConfigured: true, verify: () => true };
    const [a] = parseRegistryIndex([themeEntry({ signature: "ok" })], { verifier }).artifacts;
    expect(a.signatureState).toBe("verified");
  });

  it("finds and searches artifacts", () => {
    const { artifacts } = parseRegistryIndex([themeEntry(), configEntry()]);
    expect(findArtifact(artifacts, "acme.midnight")?.kind).toBe("theme");
    expect(searchArtifacts(artifacts, "quiet").map((a) => a.id)).toEqual(["acme.quiet"]);
  });

  it("still returns an artifacts array for a tool-only index", () => {
    expect(parseRegistryIndex([entry()]).artifacts).toEqual([]);
  });
});
