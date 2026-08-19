import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  parseNestedName,
  isDispatchTableSymbol,
  parseSelectorMapText,
  enumerateTargetModel,
  type R2Backend,
} from "./enumerate.js";
import { DISPATCH2022, VARIABLE_SIZE } from "./types.js";

const FIX = resolve(__dirname, "__fixtures__");

function loadHex(name: string): Uint8Array {
  const hex = readFileSync(resolve(FIX, name), "utf8").replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

describe("parseNestedName", () => {
  it("decodes a two-component dispatch-table symbol", () => {
    expect(parseNestedName("__ZN23IOSurfaceRootUserClient12sMethodDescsE")).toEqual([
      "IOSurfaceRootUserClient",
      "sMethodDescs",
    ]);
  });
  it("decodes the Restricted table symbol", () => {
    expect(parseNestedName("__ZN23IOSurfaceRootUserClient22sMethodDescsRestrictedE")).toEqual([
      "IOSurfaceRootUserClient",
      "sMethodDescsRestricted",
    ]);
  });
  it("returns null for non-nested symbols", () => {
    expect(parseNestedName("_main")).toBeNull();
  });
});

describe("isDispatchTableSymbol", () => {
  it("matches sMethodDescs / sMethods / Restricted", () => {
    expect(isDispatchTableSymbol("IOSurfaceRootUserClient::sMethodDescs")).toBe(true);
    expect(isDispatchTableSymbol("__ZN3Foo8sMethodsE")).toBe(true);
    expect(isDispatchTableSymbol("Foo::sMethodDescsRestricted")).toBe(true);
    expect(isDispatchTableSymbol("Foo::externalMethod")).toBe(false);
  });
});

describe("parseSelectorMapText", () => {
  it("parses the ground-truth IOSurface map (63 rows, VAR → sentinel)", () => {
    const map = parseSelectorMapText(readFileSync(resolve(FIX, "iosurface-selector-map.txt"), "utf8"));
    expect(map).toHaveLength(63);
    expect(map[0]).toMatchObject({ sel: 0, scalarInCnt: 1, structInSize: VARIABLE_SIZE, structOutSize: 3176 });
    expect(map[5]).toMatchObject({ sel: 5, scalarInCnt: 2, structInSize: 0, structOutSize: 0 });
  });
});

describe("enumerateTargetModel — full assembly via a fake R2Backend over real bytes", () => {
  // Lay the real 63-entry table at a known vaddr, place a delimiting symbol
  // exactly 63*0x28 later so the count derivation reproduces 63, and bound it
  // in a __DATA_CONST.__const section.
  const tableVaddr = 0xfffffe0008759b00n;
  const bytes = loadHex("iosurface-smethoddescs.hex");
  const nextSym = tableVaddr + BigInt(63 * DISPATCH2022.STRIDE);

  const backend: R2Backend = {
    symbols: () => [
      { name: "__ZN23IOSurfaceRootUserClient12sMethodDescsE", vaddr: tableVaddr },
      // a following symbol that bounds the table to exactly 63 entries
      { name: "__ZN23IOSurfaceRootUserClient22sMethodDescsRestrictedE", vaddr: nextSym },
      { name: "_unrelated", vaddr: nextSym + 0x40n },
    ],
    sections: () => [
      { name: "12.__DATA_CONST.__const", vaddr: 0xfffffe0008755eb8n, vsize: 0x68d0n },
    ],
    // serve the real table for the primary symbol; serve a tiny stub for the
    // Restricted symbol (1 zeroed entry) so the second table is small but valid.
    readBytes: (vaddr: bigint, len: number) => {
      if (vaddr === tableVaddr) return bytes.subarray(0, len);
      return new Uint8Array(len);
    },
  };

  it("derives 63 selectors for IOSurfaceRootUserClient and matches ground truth", () => {
    const model = enumerateTargetModel(backend, {
      kext: "com.apple.iokit.IOSurface",
      source: "fixture",
    });
    expect(model.kext).toBe("com.apple.iokit.IOSurface");
    expect(model.abi).toBe("IOExternalMethodDispatch2022");

    const primary = model.userClients.find((u) => u.table === "sMethodDescs");
    expect(primary).toBeDefined();
    expect(primary!.class).toBe("IOSurfaceRootUserClient");
    expect(primary!.selectorCount).toBe(63);

    const gt = parseSelectorMapText(readFileSync(resolve(FIX, "iosurface-selector-map.txt"), "utf8"));
    for (let i = 0; i < 63; i++) {
      expect(primary!.selectors[i]).toMatchObject({
        sel: gt[i]!.sel,
        scalarInCnt: gt[i]!.scalarInCnt,
        structInSize: gt[i]!.structInSize,
        scalarOutCnt: gt[i]!.scalarOutCnt,
        structOutSize: gt[i]!.structOutSize,
      });
    }
  });

  it("surfaces the Restricted table as a second user-client entry", () => {
    const model = enumerateTargetModel(backend, { kext: "com.apple.iokit.IOSurface", source: "fixture" });
    expect(model.userClients.some((u) => u.table === "sMethodDescsRestricted")).toBe(true);
  });
});
