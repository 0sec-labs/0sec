/**
 * PNG prover-plugin tests.
 *
 * The assertions are made against INDEPENDENT ground truth wherever a shortcut
 * was available: node's `zlib.crc32` recomputes every chunk checksum, and
 * node's `zlib.inflateSync` decompresses the IDAT we emit. If the plugin's CRC
 * arithmetic or its zlib framing were wrong, these fail — they cannot pass by
 * agreeing with the plugin's own helpers.
 *
 * The other half of the file is the property the whole module exists for: that
 * `validate` REJECTS a candidate a parser would reject, and that it does NOT
 * reject one that is merely malformed in an attacker-controlled field.
 */

import { describe, it, expect } from "vitest";
import { crc32 as nodeCrc32, inflateSync } from "node:zlib";
import { pngProverPlugin } from "./png.js";
import { toHex, fromHex } from "./binary.js";

const SIG = "89504e470d0a1a0a";

/** Independent chunk walker for the tests — deliberately not the plugin's. */
function chunksOf(bytes: Uint8Array): Array<{ offset: number; type: string; data: Uint8Array; crc: number }> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out: Array<{ offset: number; type: string; data: Uint8Array; crc: number }> = [];
  let at = 8;
  while (at + 12 <= bytes.length) {
    const len = view.getUint32(at);
    const type = String.fromCharCode(...bytes.subarray(at + 4, at + 8));
    const data = bytes.subarray(at + 8, at + 8 + len);
    const crc = view.getUint32(at + 8 + len);
    out.push({ offset: at, type, data, crc });
    at += 12 + len;
  }
  return out;
}

function buildOk(params?: Record<string, unknown>): Uint8Array {
  const r = pngProverPlugin.construct(params ? { params } : {});
  if (!r.ok) throw new Error(`construct failed: ${r.error}`);
  return r.bytes;
}

describe("pngProverPlugin.construct — from scratch", () => {
  it("emits a signature, IHDR, IDAT and IEND with CRCs node's zlib agrees with", () => {
    const bytes = buildOk();
    expect(toHex(bytes.subarray(0, 8))).toBe(SIG);

    const chunks = chunksOf(bytes);
    expect(chunks.map((c) => c.type)).toEqual(["IHDR", "IDAT", "IEND"]);

    for (const c of chunks) {
      const overType = Buffer.concat([Buffer.from(c.type, "ascii"), Buffer.from(c.data)]);
      expect(c.crc >>> 0).toBe(nodeCrc32(overType) >>> 0);
    }
  });

  it("writes a 13-byte IHDR whose fields match the requested geometry", () => {
    const bytes = buildOk({ width: 7, height: 3, bitDepth: 8, colorType: 2 });
    const ihdr = chunksOf(bytes).find((c) => c.type === "IHDR")!;
    expect(ihdr.data.length).toBe(13);
    const view = new DataView(ihdr.data.buffer, ihdr.data.byteOffset, ihdr.data.byteLength);
    expect(view.getUint32(0)).toBe(7);
    expect(view.getUint32(4)).toBe(3);
    expect(ihdr.data[8]).toBe(8);
    expect(ihdr.data[9]).toBe(2);
  });

  it("emits an IDAT that node's inflate decodes to exactly the scanline bytes the geometry implies", () => {
    // 7x3 truecolour 8-bit → 3 channels → 7*3 = 21 bytes/row + 1 filter byte.
    const bytes = buildOk({ width: 7, height: 3, bitDepth: 8, colorType: 2 });
    const idat = chunksOf(bytes).find((c) => c.type === "IDAT")!;
    const raw = inflateSync(Buffer.from(idat.data));
    expect(raw.length).toBe(3 * (7 * 3 + 1));
  });

  it("zlib-wraps caller-supplied raw scanline bytes verbatim", () => {
    const bytes = buildOk({ width: 1, height: 1, idatRawHex: "00ff" });
    const idat = chunksOf(bytes).find((c) => c.type === "IDAT")!;
    expect(Uint8Array.from(inflateSync(Buffer.from(idat.data)))).toEqual(Uint8Array.from([0x00, 0xff]));
  });

  it("frames an attacker-supplied ancillary chunk with a correct length and CRC while leaving its payload alone", () => {
    const payload = "41424344deadbeef";
    const bytes = buildOk({ chunks: [{ type: "tEXt", dataHex: payload }] });
    const text = chunksOf(bytes).find((c) => c.type === "tEXt")!;
    expect(toHex(text.data)).toBe(payload);
    expect(text.crc >>> 0).toBe(nodeCrc32(Buffer.concat([Buffer.from("tEXt"), Buffer.from(fromHex(payload)!)])) >>> 0);
  });

  it("adds the PLTE that colour type 3 requires, and says so", () => {
    const r = pngProverPlugin.construct({ params: { colorType: 3, bitDepth: 8 } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(chunksOf(r.bytes).map((c) => c.type)).toEqual(["IHDR", "PLTE", "IDAT", "IEND"]);
    expect(r.notes.join(" ")).toMatch(/PLTE/);
  });

  it("passes a verbatim IHDR payload through untouched — the header is a semantic field", () => {
    // A 13-byte IHDR declaring a 0x10000x0x10000 image with an illegal colour
    // type. A prover that "helpfully" corrected any of this would delete the PoC.
    const ihdr = "00010000" + "00010000" + "08" + "07" + "00" + "00" + "00";
    const r = pngProverPlugin.construct({ params: { ihdrDataHex: ihdr } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const written = chunksOf(r.bytes).find((c) => c.type === "IHDR")!;
    expect(toHex(written.data)).toBe(ihdr);
  });

  it("rejects an unknown param instead of silently defaulting it", () => {
    const r = pngProverPlugin.construct({ params: { widht: 4 } });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toMatch(/unknown param `widht`/);
  });

  it("refuses when both idatRawHex and idatZlibHex are given", () => {
    const r = pngProverPlugin.construct({ params: { idatRawHex: "00", idatZlibHex: "789c" } });
    expect(r.ok).toBe(false);
  });

  it("refuses an absurd synthesised image rather than allocating it", () => {
    const r = pngProverPlugin.construct({ params: { width: 100000, height: 100000 } });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toMatch(/idatRawHex/);
  });
});

describe("pngProverPlugin.validate", () => {
  it("accepts what construct produced", () => {
    const report = pngProverPlugin.validate(buildOk());
    expect(report.wellFormed).toBe(true);
    expect(report.defects.filter((d) => d.severity === "fatal")).toEqual([]);
    expect(report.structure.some((s) => s.startsWith("IHDR:"))).toBe(true);
  });

  it("rejects a corrupted CRITICAL chunk CRC as fatal — libpng quits there", () => {
    const bytes = buildOk();
    const ihdr = chunksOf(bytes).find((c) => c.type === "IHDR")!;
    const crcAt = ihdr.offset + 8 + ihdr.data.length;
    const broken = Uint8Array.from(bytes);
    broken[crcAt] = broken[crcAt]! ^ 0xff;

    const report = pngProverPlugin.validate(broken);
    expect(report.wellFormed).toBe(false);
    const defect = report.defects.find((d) => d.field === "IHDR.crc");
    expect(defect?.severity).toBe("fatal");
    expect(defect?.repairable).toBe(true);
  });

  it("downgrades a corrupted ANCILLARY chunk CRC to a warning — libpng warns and uses the chunk", () => {
    const bytes = buildOk({ chunks: [{ type: "tEXt", dataHex: "41" }] });
    const text = chunksOf(bytes).find((c) => c.type === "tEXt")!;
    const crcAt = text.offset + 8 + text.data.length;
    const broken = Uint8Array.from(bytes);
    broken[crcAt] = broken[crcAt]! ^ 0xff;

    const report = pngProverPlugin.validate(broken);
    expect(report.defects.find((d) => d.field === "tEXt.crc")?.severity).toBe("warning");
    expect(report.wellFormed).toBe(true);
  });

  it("rejects a missing signature", () => {
    const report = pngProverPlugin.validate(buildOk().subarray(8));
    expect(report.wellFormed).toBe(false);
    expect(report.defects[0]?.field).toBe("signature");
  });

  it("rejects an illegal bit-depth / colour-type pair — libpng errors in png_handle_IHDR", () => {
    // Colour type 2 (truecolour) with bit depth 4 is not in the spec's table.
    const r = pngProverPlugin.construct({ params: { ihdrDataHex: "0000000100000001" + "04" + "02" + "000000" } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const report = pngProverPlugin.validate(r.bytes);
    expect(report.wellFormed).toBe(false);
    expect(report.defects.some((d) => d.field === "IHDR.bitDepth")).toBe(true);
  });

  it("rejects colour type 3 with no PLTE", () => {
    const r = pngProverPlugin.construct({ params: { ihdrDataHex: "0000000100000001" + "08" + "03" + "000000" } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const report = pngProverPlugin.validate(r.bytes);
    expect(report.defects.some((d) => d.field === "PLTE" && d.severity === "fatal")).toBe(true);
  });

  it("reports a chunk whose declared length overruns the buffer as fatal and NOT repairable", () => {
    // Truncate INSIDE the IDAT payload so its 4-byte declared length promises
    // more bytes than the file holds — the shape a generator produces when it
    // computes a length before deciding how much data to emit.
    const bytes = buildOk({ iend: false });
    const truncated = bytes.subarray(0, bytes.length - 10);
    const report = pngProverPlugin.validate(truncated);
    expect(report.wellFormed).toBe(false);
    const overrun = report.defects.find((d) => d.message.includes("only"));
    expect(overrun?.severity).toBe("fatal");
    expect(overrun?.repairable).toBe(false);
  });

  it("treats a missing IEND as a warning, not a fatal — most bugs fire before it", () => {
    const r = pngProverPlugin.construct({ params: { iend: false } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const report = pngProverPlugin.validate(r.bytes);
    expect(report.wellFormed).toBe(true);
    expect(report.defects.find((d) => d.field === "IEND")?.severity).toBe("warning");
  });
});

describe("pngProverPlugin.construct — repair mode", () => {
  it("restores every wrong CRC, reports what it changed, and reproduces the original bytes", () => {
    const good = buildOk({ chunks: [{ type: "tEXt", dataHex: "4142" }] });
    const broken = Uint8Array.from(good);
    for (const c of chunksOf(good)) {
      const crcAt = c.offset + 8 + c.data.length;
      broken[crcAt] = broken[crcAt]! ^ 0xff;
    }

    const r = pngProverPlugin.construct({ base: broken });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.bytes).toEqual(good);
    expect(r.repairs.map((x) => x.field).sort()).toEqual(["IDAT.crc", "IEND.crc", "IHDR.crc", "tEXt.crc"]);
    // Every repair explains itself — the craft loop is a learning loop.
    for (const rec of r.repairs) expect(rec.why.length).toBeGreaterThan(20);
    expect(pngProverPlugin.validate(r.bytes).wellFormed).toBe(true);
  });

  it("restores a damaged signature", () => {
    const good = buildOk();
    const broken = Uint8Array.from(good);
    broken[3] = 0x00;
    const r = pngProverPlugin.construct({ base: broken });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.bytes).toEqual(good);
    expect(r.repairs.some((x) => x.field === "signature")).toBe(true);
  });

  it("leaves CRCs alone when fixCrc is false — the mismatch may BE the bug", () => {
    const good = buildOk();
    const broken = Uint8Array.from(good);
    const ihdr = chunksOf(good).find((c) => c.type === "IHDR")!;
    broken[ihdr.offset + 8 + ihdr.data.length] ^= 0xff;

    const r = pngProverPlugin.construct({ base: broken, params: { fixCrc: false } });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.bytes).toEqual(broken);
    expect(r.repairs).toEqual([]);
  });

  it("REFUSES to repair an over-long declared length rather than clamping away the PoC", () => {
    const good = buildOk({ iend: false });
    const r = pngProverPlugin.construct({ base: good.subarray(0, good.length - 10) });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toMatch(/NOT repairable/);
  });

  it("appends the fixed IEND terminator when it is missing", () => {
    const without = buildOk({ iend: false });
    const r = pngProverPlugin.construct({ base: without });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(chunksOf(r.bytes).map((c) => c.type)).toContain("IEND");
    expect(r.repairs.some((x) => x.field === "IEND")).toBe(true);
  });
});

describe("pngProverPlugin.matches", () => {
  it("scores 1.0 on the signature and 0.75 on a name hint", () => {
    expect(pngProverPlugin.matches({ sample: buildOk() }).score).toBe(1);
    expect(pngProverPlugin.matches({ hint: "libpng_read_fuzzer" }).score).toBe(0.75);
    expect(pngProverPlugin.matches({ hint: "png_read_fuzzer" }).score).toBe(0.75);
    expect(pngProverPlugin.matches({ hint: "zip" }).score).toBe(0);
  });
});
