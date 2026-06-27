import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  parseDispatchTable,
  dispatchTableByteLength,
  tableMetrics,
  selectorModelToLine,
} from "./dispatch-table.js";
import { parseSelectorMapText } from "./enumerate.js";
import { DISPATCH2022, VARIABLE_SIZE } from "./types.js";

const FIX = resolve(__dirname, "__fixtures__");

function loadHex(name: string): Uint8Array {
  const hex = readFileSync(resolve(FIX, name), "utf8").replace(/[^0-9a-fA-F]/g, "");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Build one synthetic IOExternalMethodDispatch2022 entry. */
function entry(opts: {
  fn?: bigint;
  scIn: number;
  stIn: number;
  scOut: number;
  stOut: number;
  allowAsync?: boolean;
  entitlement?: bigint;
}): Uint8Array {
  const b = new Uint8Array(DISPATCH2022.STRIDE);
  const v = new DataView(b.buffer);
  v.setBigUint64(DISPATCH2022.OFF_FUNCTION, opts.fn ?? 0n, true);
  v.setUint32(DISPATCH2022.OFF_SCALAR_IN_CNT, opts.scIn, true);
  v.setUint32(DISPATCH2022.OFF_STRUCT_IN_SIZE, opts.stIn, true);
  v.setUint32(DISPATCH2022.OFF_SCALAR_OUT_CNT, opts.scOut, true);
  v.setUint32(DISPATCH2022.OFF_STRUCT_OUT_SIZE, opts.stOut, true);
  b[DISPATCH2022.OFF_ALLOW_ASYNC] = opts.allowAsync ? 1 : 0;
  v.setBigUint64(DISPATCH2022.OFF_CHECK_ENTITLEMENT, opts.entitlement ?? 0n, true);
  return b;
}

describe("parseDispatchTable — synthetic", () => {
  it("decodes the four check fields, allowAsync and entitlement", () => {
    const buf = new Uint8Array([
      ...entry({ fn: 0xfffffe0001234560n, scIn: 1, stIn: VARIABLE_SIZE, scOut: 0, stOut: 3176 }),
      ...entry({ scIn: 2, stIn: 0, scOut: 1, stOut: 0, allowAsync: true, entitlement: 0xdeadbeefn }),
    ]);
    const sels = parseDispatchTable(buf, { count: 2 });
    expect(sels).toHaveLength(2);
    expect(sels[0]).toMatchObject({
      sel: 0,
      scalarInCnt: 1,
      structInSize: VARIABLE_SIZE,
      scalarOutCnt: 0,
      structOutSize: 3176,
      allowAsync: false,
      hasEntitlementCheck: false,
    });
    expect(sels[0]!.handlerRaw).toBe("0xfffffe0001234560");
    expect(sels[1]).toMatchObject({
      sel: 1,
      scalarInCnt: 2,
      scalarOutCnt: 1,
      allowAsync: true,
      hasEntitlementCheck: true,
    });
  });

  it("invokes resolveHandler and prefers its result", () => {
    const buf = entry({ fn: 0x1111n, scIn: 0, stIn: 0, scOut: 0, stOut: 0 });
    const sels = parseDispatchTable(buf, { count: 1, resolveHandler: () => "0xCAFE" });
    expect(sels[0]!.handler).toBe("0xCAFE");
  });

  it("throws when the buffer is too small for the declared count", () => {
    expect(() => parseDispatchTable(new Uint8Array(10), { count: 1 })).toThrow(/too small/);
  });

  it("dispatchTableByteLength is count * stride", () => {
    expect(dispatchTableByteLength(63)).toBe(63 * 0x28);
  });
});

describe("parseDispatchTable — real IOSurfaceRootUserClient::sMethodDescs bytes", () => {
  const bytes = loadHex("iosurface-smethoddescs.hex");
  const groundTruth = parseSelectorMapText(
    readFileSync(resolve(FIX, "iosurface-selector-map.txt"), "utf8"),
  );

  it("the fixture is exactly 63 entries", () => {
    expect(bytes.byteLength).toBe(63 * DISPATCH2022.STRIDE);
    expect(groundTruth).toHaveLength(63);
  });

  it("decodes byte-for-byte to the ground-truth selector map", () => {
    const decoded = parseDispatchTable(bytes, { count: 63 });
    expect(decoded).toHaveLength(63);
    for (let i = 0; i < 63; i++) {
      expect({
        sel: decoded[i]!.sel,
        scalarInCnt: decoded[i]!.scalarInCnt,
        structInSize: decoded[i]!.structInSize,
        scalarOutCnt: decoded[i]!.scalarOutCnt,
        structOutSize: decoded[i]!.structOutSize,
      }).toEqual({
        sel: groundTruth[i]!.sel,
        scalarInCnt: groundTruth[i]!.scalarInCnt,
        structInSize: groundTruth[i]!.structInSize,
        scalarOutCnt: groundTruth[i]!.scalarOutCnt,
        structOutSize: groundTruth[i]!.structOutSize,
      });
    }
  });

  it("matches the known sel 0 / sel 9 / sel 17 spot-checks from the design doc & map", () => {
    const d = parseDispatchTable(bytes, { count: 63 });
    // sel 0: scIn=1 stIn=VAR scOut=0 stOut=3176
    expect(d[0]).toMatchObject({ scalarInCnt: 1, structInSize: VARIABLE_SIZE, structOutSize: 3176 });
    // sel 9: scIn=0 stIn=VAR scOut=0 stOut=4
    expect(d[9]).toMatchObject({ scalarInCnt: 0, structInSize: VARIABLE_SIZE, structOutSize: 4 });
    // sel 17: scIn=0 stIn=24 scOut=0 stOut=0
    expect(d[17]).toMatchObject({ scalarInCnt: 0, structInSize: 24, scalarOutCnt: 0, structOutSize: 0 });
  });

  it("computes the §6 variable-size sentinel density (17 VAR selectors)", () => {
    const d = parseDispatchTable(bytes, { count: 63 });
    const m = tableMetrics(d);
    expect(m.selectorCount).toBe(63);
    // Count VAR rows directly from the ground-truth text for an independent check.
    const varRows = groundTruth.filter(
      (s) => s.structInSize === VARIABLE_SIZE || s.structOutSize === VARIABLE_SIZE,
    ).length;
    expect(m.varSizeSelectorCount).toBe(varRows);
  });
});

describe("selectorModelToLine", () => {
  it("renders VAR and a vaddr in the human format", () => {
    const line = selectorModelToLine({
      sel: 0,
      handler: "0xfffffe000abe9d28",
      scalarInCnt: 1,
      structInSize: VARIABLE_SIZE,
      scalarOutCnt: 0,
      structOutSize: 3176,
    });
    expect(line).toContain("sel  0");
    expect(line).toContain("scIn=1 stIn=VAR");
    expect(line).toContain("stOut=3176");
    expect(line).toContain("VAR-SIZE");
  });
});
