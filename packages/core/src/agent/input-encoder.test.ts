import { describe, it, expect } from "vitest";
import {
  encodeFdp,
  decodeFdp,
  FdpReader,
  runFdpEncode,
  fdpEncodeToolDef,
  type FdpSpec,
} from "./input-encoder.js";

function bytesOf(r: ReturnType<typeof encodeFdp>): Uint8Array {
  if (!r.ok) throw new Error(`expected ok, got error: ${r.error}`);
  return r.bytes;
}

describe("input-encoder — FuzzedDataProvider encoding", () => {
  it("round-trips every supported field kind through the reference decoder", () => {
    const spec: FdpSpec = {
      fields: [
        { kind: "bytes", name: "magic", value: "deadbeef" },
        { kind: "intInRange", name: "len", value: 65535, min: 0, max: 65535, bits: 16 },
        { kind: "bool", name: "flag", value: true },
        { kind: "string", name: "label", value: "AB" },
        { kind: "int", name: "tag", value: 0x11223344, bits: 32 },
        { kind: "remainingBytes", name: "rest", value: "cafe" },
      ],
    };
    const bytes = bytesOf(encodeFdp(spec));
    const decoded = decodeFdp(spec, bytes);

    expect(Array.from(decoded[0] as Uint8Array)).toEqual([0xde, 0xad, 0xbe, 0xef]);
    expect(decoded[1]).toBe(65535n);
    expect(decoded[2]).toBe(true);
    expect(decoded[3]).toEqual([0x41, 0x42]);
    expect(decoded[4]).toBe(0x11223344n);
    expect(Array.from(decoded[5] as Uint8Array)).toEqual([0xca, 0xfe]);
  });

  it("consumes integrals from the BACK and bytes from the FRONT", () => {
    // uint16 = 0xAABB. Front bytes 'XY' (0x58,0x59). FDP pulls the u16 off the
    // tail reading the VERY LAST byte first as the MSB, so the last byte is
    // 0xAA and the one before it is 0xBB.
    const spec: FdpSpec = {
      fields: [
        { kind: "bytes", value: [0x58, 0x59] },
        { kind: "int", value: 0xaabb, bits: 16 },
      ],
    };
    const bytes = bytesOf(encodeFdp(spec));
    expect(Array.from(bytes)).toEqual([0x58, 0x59, 0xbb, 0xaa]);
    // Sanity: a hand-driven reader decodes it the same way.
    const r = new FdpReader(bytes);
    expect(Array.from(r.consumeBytes(2))).toEqual([0x58, 0x59]);
    expect(r.consumeIntegral(16, false)).toBe(0xaabbn);
  });

  it("orders multiple back-consumed fields so the FIRST consumed sits at the very end", () => {
    // a = u16 (first, back), b = u8 (second, back). a pops the last 2 bytes,
    // b pops the byte before them.
    const spec: FdpSpec = {
      fields: [
        { kind: "int", name: "a", value: 0x1234, bits: 16 },
        { kind: "int", name: "b", value: 0x77, bits: 8 },
      ],
    };
    const bytes = bytesOf(encodeFdp(spec));
    // `a` pops the last two bytes MSB-first (last=0x12 hi, prev=0x34 lo);
    // `b` pops the byte before them (0x77). buffer = [0x77, 0x34, 0x12].
    expect(Array.from(bytes)).toEqual([0x77, 0x34, 0x12]);
    expect(decodeFdp(spec, bytes)).toEqual([0x1234n, 0x77n]);
  });

  it("interleaves front and back consumption correctly", () => {
    const spec: FdpSpec = {
      fields: [
        { kind: "bytes", name: "b0", value: [0x01, 0x02] },
        { kind: "int", name: "i", value: 0xbeef, bits: 16 },
        { kind: "bytes", name: "b1", value: [0x03] },
        { kind: "int", name: "j", value: 0x5a, bits: 8 },
      ],
    };
    const bytes = bytesOf(encodeFdp(spec));
    // front: 01 02 03 ; back region (buffer order) = reverse of pop [ef? ] ...
    // pop order: i.hi(0xbe), i.lo(0xef), j(0x5a) -> reverse -> 5a ef be ... wait
    // careful: back region = reverse(popOrder). popOrder = [0xbe,0xef,0x5a].
    // reverse => [0x5a,0xef,0xbe]; buffer = front ++ that.
    expect(Array.from(bytes)).toEqual([0x01, 0x02, 0x03, 0x5a, 0xef, 0xbe]);
    expect(decodeFdp(spec, bytes)).toEqual([
      Uint8Array.from([0x01, 0x02]),
      0xbeefn,
      Uint8Array.from([0x03]),
      0x5an,
    ]);
  });

  it("encodes ConsumeIntegralInRange with the correct byte count and modulo fold", () => {
    // range 0..999 needs 2 bytes (999 >> 8 = 3 > 0). value 500 -> r = 500.
    const spec: FdpSpec = { fields: [{ kind: "intInRange", value: 500, min: 0, max: 999, bits: 32 }] };
    const bytes = bytesOf(encodeFdp(spec));
    expect(bytes.length).toBe(2);
    expect(decodeFdp(spec, bytes)[0]).toBe(500n);
  });

  it("handles non-zero min ranges", () => {
    const spec: FdpSpec = { fields: [{ kind: "intInRange", value: 105, min: 100, max: 200, bits: 32 }] };
    const bytes = bytesOf(encodeFdp(spec));
    expect(bytes.length).toBe(1); // range 100 fits in 1 byte
    expect(decodeFdp(spec, bytes)[0]).toBe(105n);
  });

  it("round-trips signed integers (two's complement)", () => {
    const spec: FdpSpec = {
      fields: [
        { kind: "int", name: "neg", value: -1, bits: 32, signed: true },
        { kind: "int", name: "min", value: -128, bits: 8, signed: true },
      ],
    };
    const bytes = bytesOf(encodeFdp(spec));
    expect(decodeFdp(spec, bytes)).toEqual([-1n, -128n]);
  });

  it("round-trips a full-width unsigned 64-bit value", () => {
    const spec: FdpSpec = { fields: [{ kind: "int", value: 0xdeadbeefcafef00dn, bits: 64 }] };
    const bytes = bytesOf(encodeFdp(spec));
    expect(bytes.length).toBe(8);
    expect(decodeFdp(spec, bytes)[0]).toBe(0xdeadbeefcafef00dn);
  });

  it("escapes backslashes and terminates random-length strings", () => {
    const spec: FdpSpec = {
      fields: [
        { kind: "string", name: "s", value: "a\\b" },
        { kind: "bytes", name: "after", value: [0x99] },
      ],
    };
    const bytes = bytesOf(encodeFdp(spec));
    const decoded = decodeFdp(spec, bytes);
    expect(decoded[0]).toEqual([0x61, 0x5c, 0x62]); // "a\b"
    expect(Array.from(decoded[1] as Uint8Array)).toEqual([0x99]); // terminator did not swallow it
  });

  it("bool reads the low bit of one back byte", () => {
    const t = bytesOf(encodeFdp({ fields: [{ kind: "bool", value: true }] }));
    const f = bytesOf(encodeFdp({ fields: [{ kind: "bool", value: false }] }));
    expect(new FdpReader(t).consumeBool()).toBe(true);
    expect(new FdpReader(f).consumeBool()).toBe(false);
  });

  it("is deterministic — identical spec yields identical bytes", () => {
    const spec: FdpSpec = {
      fields: [
        { kind: "bytes", value: "0011" },
        { kind: "intInRange", value: 7, min: 0, max: 15, bits: 8 },
      ],
    };
    expect(Array.from(bytesOf(encodeFdp(spec)))).toEqual(Array.from(bytesOf(encodeFdp(spec))));
  });
});

describe("input-encoder — error reporting (fed back to the agent)", () => {
  it("rejects an out-of-range value with an actionable message", () => {
    const res = encodeFdp({ fields: [{ kind: "intInRange", name: "len", value: 1000, min: 0, max: 999, bits: 32 }] });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toMatch(/out of range/);
      expect(res.error).toMatch(/len/);
      expect(res.fieldIndex).toBe(0);
    }
  });

  it("rejects remainingBytes that is not the last field", () => {
    const res = encodeFdp({
      fields: [
        { kind: "remainingBytes", value: "00" },
        { kind: "int", value: 1, bits: 8 },
      ],
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/must be the last field/);
  });

  it("rejects malformed hex", () => {
    const res = encodeFdp({ fields: [{ kind: "bytes", value: "xyz" }] });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.error).toMatch(/not valid hex/);
  });
});

describe("input-encoder — craft-tool glue", () => {
  it("exposes a tool def named fdp_encode with a fields schema", () => {
    const def = fdpEncodeToolDef();
    expect(def.name).toBe("fdp_encode");
    expect((def.input_schema as { required: string[] }).required).toContain("fields");
  });

  it("runFdpEncode returns a python literal on success", () => {
    const out = runFdpEncode({ fields: [{ kind: "int", value: 0xab, bits: 8 }] });
    expect(out).toMatch(/python: sys\.stdout\.buffer\.write\(b"/);
    expect(out).toMatch(/hex: ab/);
  });

  it("runFdpEncode returns a fixable error string on bad input", () => {
    expect(runFdpEncode({})).toMatch(/`fields` must be an array/);
    expect(runFdpEncode({ fields: [{ kind: "intInRange", value: 5, min: 10, max: 20 }] })).toMatch(/error:/);
  });
});
