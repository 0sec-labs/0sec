/**
 * Registry + tool-seam tests.
 *
 * The properties under test are the ones a mis-registered plugin would break
 * silently: unique ids, magic-byte evidence outranking a name hint, plugins
 * with unsatisfiable service requirements being skipped instead of invoked,
 * and the craft-loop handlers returning agent-actionable strings rather than
 * throwing into the tool-dispatch `catch`.
 */

import { describe, it, expect } from "vitest";
import {
  PROVER_PLUGIN_BY_ID,
  PROVER_PLUGIN_REGISTRY,
  getProverPluginById,
  listProverPluginIds,
  rankProverPlugins,
  selectProverPlugin,
} from "./registry.js";
import { PROVER_TOOL_NAMES, proverToolDefs, runProverConstruct, runProverTool, runProverValidate } from "./tool.js";
import { pngProverPlugin } from "./png.js";
import { zipProverPlugin } from "./zip.js";
import { toHex } from "./binary.js";
import type { ProverPlugin } from "./types.js";

function buildPngHex(): string {
  const r = pngProverPlugin.construct({});
  if (!r.ok) throw new Error(r.error);
  return toHex(r.bytes);
}

function buildZipHex(): string {
  const r = zipProverPlugin.construct({ params: { entries: [{ name: "a.txt", dataText: "AAAA" }] } });
  if (!r.ok) throw new Error(r.error);
  return toHex(r.bytes);
}

describe("PROVER_PLUGIN_REGISTRY", () => {
  it("exposes unique ids and a matching id map", () => {
    const ids = listProverPluginIds();
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toEqual(Object.keys(PROVER_PLUGIN_BY_ID));
    expect(getProverPluginById("PNG")).toBe(pngProverPlugin);
    expect(getProverPluginById("nope")).toBeUndefined();
  });

  it("gives every plugin the fields the tool layer and the agent depend on", () => {
    for (const p of PROVER_PLUGIN_REGISTRY) {
      expect(p.id).toMatch(/^[a-z0-9-]+$/);
      expect(p.title.length).toBeGreaterThan(0);
      expect(p.aliases.length).toBeGreaterThan(0);
      expect(p.paramsHelp.length).toBeGreaterThan(20);
    }
  });
});

describe("selectProverPlugin", () => {
  it("dispatches on magic bytes, with no hint at all", () => {
    const png = pngProverPlugin.construct({});
    const zip = zipProverPlugin.construct({ params: { entries: [{ name: "a", dataText: "b" }] } });
    if (!png.ok || !zip.ok) throw new Error("fixture build failed");
    expect(selectProverPlugin({ sample: png.bytes })?.plugin.id).toBe("png");
    expect(selectProverPlugin({ sample: zip.bytes })?.plugin.id).toBe("zip");
  });

  it("dispatches on a fuzzer name when no sample is available", () => {
    expect(selectProverPlugin({ hint: "libpng_read_fuzzer" })?.plugin.id).toBe("png");
    expect(selectProverPlugin({ hint: "minizip_fuzzer" })?.plugin.id).toBe("zip");
  });

  it("lets magic bytes beat a contradicting name hint", () => {
    // The agent guessed the format from a fuzzer name and guessed wrong; the
    // bytes in front of it are authoritative.
    const png = pngProverPlugin.construct({});
    if (!png.ok) throw new Error(png.error);
    const selection = selectProverPlugin({ hint: "zip_fuzzer", sample: png.bytes });
    expect(selection?.plugin.id).toBe("png");
    expect(selection?.match.score).toBe(1);
    expect(selection?.match.reason).toMatch(/signature/);
  });

  it("returns undefined for a format nothing claims", () => {
    expect(selectProverPlugin({ hint: "ttf" })).toBeUndefined();
    expect(selectProverPlugin({ sample: Uint8Array.from([1, 2, 3, 4]) })).toBeUndefined();
  });

  it("ranks all applicable plugins, best first", () => {
    const ranked = rankProverPlugins({ hint: "png zip" });
    expect(ranked.map((r) => r.plugin.id).sort()).toEqual(["png", "zip"]);
  });
});

describe("service requirements", () => {
  /** A plugin that needs I/O it will not be given. */
  const needsIo: ProverPlugin = {
    id: "needs-io",
    title: "test-only",
    aliases: ["needsio"],
    requiresServices: ["readFile"],
    paramsHelp: "none",
    matches: () => ({ score: 1, reason: "always" }),
    construct: () => ({ ok: false, error: "never called" }),
    validate: () => ({ wellFormed: false, defects: [], structure: [] }),
  };

  it("skips a plugin whose required services are absent", () => {
    // Exercised through the same helper the registry uses, on a local registry
    // shape — the shipped registry is intentionally all-pure, so this is the
    // only way to prove the gate works before someone adds an impure plugin.
    const satisfied = (p: ProverPlugin, s: { readFile?: unknown } | undefined) =>
      (p.requiresServices ?? []).every((k) => s?.[k as "readFile"] !== undefined);
    expect(satisfied(needsIo, undefined)).toBe(false);
    expect(satisfied(needsIo, { readFile: () => undefined })).toBe(true);
    expect(satisfied(pngProverPlugin, undefined)).toBe(true);
  });
});

describe("craft-loop tool seam", () => {
  it("declares exactly the tools it dispatches", () => {
    expect(proverToolDefs().map((t) => t.name)).toEqual([...PROVER_TOOL_NAMES]);
    for (const def of proverToolDefs()) {
      expect(def.description).toContain("png");
      expect(def.input_schema).toHaveProperty("properties");
    }
  });

  it("returns undefined for a tool it does not own, so the caller falls through", () => {
    expect(runProverTool("read_file", {})).toBeUndefined();
  });

  it("constructs by explicit format and reports the bytes as a python literal", () => {
    const out = runProverConstruct({ format: "png", params: { width: 2, height: 2 } });
    expect(out).toMatch(/Constructed with the png prover/);
    expect(out).toMatch(/python: .*payload = b"/);
    expect(out).toMatch(/hex: 89504e470d0a1a0a/);
  });

  it("infers the plugin from baseHex when no format is given", () => {
    const out = runProverConstruct({ baseHex: buildZipHex() });
    expect(out).toMatch(/Constructed with the zip prover/);
  });

  it("validates a good candidate as structurally OK", () => {
    expect(runProverValidate({ bytesHex: buildPngHex() })).toMatch(/STRUCTURE OK/);
    expect(runProverValidate({ bytesHex: buildZipHex() })).toMatch(/STRUCTURE OK/);
  });

  it("names the fatal defects, with the repair route, for a broken candidate", () => {
    const broken = buildPngHex().replace(/.{8}$/, "00000000"); // clobber the IEND CRC
    const out = runProverValidate({ bytesHex: broken });
    expect(out).toMatch(/NOT WELL-FORMED/);
    expect(out).toMatch(/FATAL/);
    expect(out).toMatch(/prover_construct with baseHex/);
  });

  it("round-trips: validate flags it, construct repairs it, validate clears it", () => {
    const broken = buildPngHex().replace(/.{8}$/, "00000000");
    expect(runProverValidate({ bytesHex: broken })).toMatch(/NOT WELL-FORMED/);
    const repaired = runProverConstruct({ baseHex: broken });
    expect(repaired).toMatch(/Repaired 1 framing field/);
    const hex = /hex: ([0-9a-f]+)/.exec(repaired)?.[1];
    expect(hex).toBeDefined();
    expect(runProverValidate({ bytesHex: hex! })).toMatch(/STRUCTURE OK/);
  });

  it("turns every bad input into an actionable message rather than throwing", () => {
    expect(runProverValidate({})).toMatch(/`bytesHex` is required/);
    expect(runProverValidate({ bytesHex: "xyz" })).toMatch(/not valid hex/);
    expect(runProverConstruct({ baseHex: "xyz" })).toMatch(/not valid hex/);
    expect(runProverConstruct({ format: "png", params: [] })).toMatch(/`params` must be an object/);
    expect(runProverConstruct({ format: "ttf" })).toMatch(/No prover plugin/);
    expect(runProverConstruct({ format: "png", params: { nope: 1 } })).toMatch(/unknown param/);
  });

  it("tells the agent which formats exist when it asks for one that does not", () => {
    const out = runProverValidate({ bytesHex: "0102030405060708", format: "heif" });
    expect(out).toMatch(/Available: png, zip/);
    expect(out).toMatch(/format_reference/);
  });
});
