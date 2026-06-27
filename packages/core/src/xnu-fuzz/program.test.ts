import { describe, expect, it } from "vitest";
import { encodeProgram, decodeProgram, PROGRAM_MAGIC, type ProgramCall } from "./program.js";

describe("program wire format", () => {
  it("round-trips a multi-call program", () => {
    const calls: ProgramCall[] = [
      {
        selector: 0,
        scalarInput: [1n, 0xdeadbeefn],
        structureInput: new Uint8Array([1, 2, 3, 4]),
        scalarOutCnt: 1,
        structOutSize: 3176,
      },
      {
        selector: 9,
        scalarInput: [],
        structureInput: new Uint8Array(0),
        scalarOutCnt: 0,
        structOutSize: 4,
      },
    ];
    const decoded = decodeProgram(encodeProgram(calls));
    expect(decoded).toHaveLength(2);
    expect(decoded[0]).toMatchObject({ selector: 0, scalarOutCnt: 1, structOutSize: 3176 });
    expect(decoded[0]!.scalarInput).toEqual([1n, 0xdeadbeefn]);
    expect(Array.from(decoded[0]!.structureInput)).toEqual([1, 2, 3, 4]);
    expect(decoded[1]).toMatchObject({ selector: 9, structOutSize: 4 });
    expect(decoded[1]!.scalarInput).toEqual([]);
  });

  it("starts with the PKXF magic", () => {
    const buf = encodeProgram([
      { selector: 1, scalarInput: [], structureInput: new Uint8Array(0), scalarOutCnt: 0, structOutSize: 0 },
    ]);
    const magic = new DataView(buf.buffer).getUint32(0, true);
    expect(magic).toBe(PROGRAM_MAGIC);
  });

  it("rejects a bad magic", () => {
    expect(() => decodeProgram(new Uint8Array(12))).toThrow(/magic/);
  });

  it("accepts FuzzInput-shaped calls directly (lengthLabel ignored)", () => {
    const decoded = decodeProgram(
      encodeProgram([
        {
          selector: 50,
          scalarInput: [7n],
          structureInput: new Uint8Array([0xaa]),
          scalarOutCnt: 0,
          structOutSize: 0,
          lengthLabel: "len-1",
        },
      ]),
    );
    expect(decoded[0]).toMatchObject({ selector: 50, structOutSize: 0 });
    expect(Array.from(decoded[0]!.structureInput)).toEqual([0xaa]);
  });
});
