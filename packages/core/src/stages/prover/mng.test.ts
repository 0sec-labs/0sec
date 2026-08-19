import { describe, expect, it } from "vitest";
import { mngProverPlugin } from "./mng.js";
import type { ConstructResult } from "./types.js";

function requireBytes(result: ConstructResult): Uint8Array {
  if (!result.ok) throw new Error(result.error);
  return result.bytes;
}

describe("mngProverPlugin", () => {
  it("constructs a framed MNG with a computed CRC for an arbitrary animation chunk", () => {
    const bytes = requireBytes(mngProverPlugin.construct({
      params: { chunks: [{ type: "LOOP", dataHex: "00" }] },
    }));

    expect([...bytes.subarray(0, 8)]).toEqual([0x8a, 0x4d, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    const report = mngProverPlugin.validate(bytes);
    expect(report.wellFormed).toBe(true);
    expect(report.structure.join("\n")).toContain("LOOP declared=1 payload=1");
    expect(report.structure.join("\n")).toContain("MEND declared=0 payload=0");
    expect(report.defects).toEqual([]);
  });

  it("keeps an intentionally short LOOP payload and noncanonical MHDR as semantic warnings", () => {
    const bytes = requireBytes(mngProverPlugin.construct({
      params: {
        mhdrDataHex: "000000010000000100000001000000000000000000000000",
        chunks: [{ type: "LOOP", dataHex: "00" }],
        mend: false,
      },
    }));

    expect(bytes.length).toBe(57);
    const report = mngProverPlugin.validate(bytes);
    expect(report.wellFormed).toBe(true);
    expect(report.defects).toEqual(expect.arrayContaining([
      expect.objectContaining({ field: "MHDR.length", severity: "warning" }),
      expect.objectContaining({ field: "MEND", severity: "warning" }),
    ]));
  });

  it("repairs only a damaged chunk CRC without altering payload bytes", () => {
    const original = requireBytes(mngProverPlugin.construct({
      params: { chunks: [{ type: "LOOP", dataHex: "00" }] },
    }));
    const corrupted = Uint8Array.from(original);
    corrupted[corrupted.length - 1] ^= 0xff;

    expect(mngProverPlugin.validate(corrupted).wellFormed).toBe(true);
    expect(mngProverPlugin.validate(corrupted).defects).toContainEqual(
      expect.objectContaining({ field: "MEND.crc", severity: "warning", repairable: true }),
    );

    const repaired = mngProverPlugin.construct({ base: corrupted });
    const bytes = requireBytes(repaired);
    expect(repaired.ok && repaired.repairs).toHaveLength(1);
    expect(mngProverPlugin.validate(bytes).defects).toEqual([]);
  });

  it("prefers signature evidence and accepts MNG aliases", () => {
    const sample = requireBytes(mngProverPlugin.construct({}));
    expect(mngProverPlugin.matches({ sample }).score).toBe(1);
    expect(mngProverPlugin.matches({ hint: "coder_MNG_fuzzer" }).score).toBeGreaterThan(0);
    expect(mngProverPlugin.matches({ hint: "libpng" }).score).toBe(0);
  });
});
