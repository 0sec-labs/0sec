/**
 * Byte-level tests for the shared prover primitives.
 *
 * These assert against values that are independently checkable — the CRC-32 of
 * "123456789" is the algorithm's published check value, and node's own `zlib`
 * inflates our stored-block streams — so a regression here is caught against
 * ground truth rather than against a snapshot of our own behaviour.
 */

import { describe, it, expect } from "vitest";
import { inflateSync } from "node:zlib";
import { adler32, ascii, crc32, fromHex, pythonLiteral, toHex, u32be, u32le, zlibStored } from "./binary.js";

describe("crc32", () => {
  it("matches the published CRC-32/ISO-HDLC check value for '123456789'", () => {
    expect(crc32(ascii("123456789"))).toBe(0xcbf43926);
  });

  it("is 0 for the empty input", () => {
    expect(crc32(new Uint8Array(0))).toBe(0);
  });

  it("produces the well-known CRC for a PNG IEND chunk (type bytes only)", () => {
    // The IEND chunk is empty, so its CRC is the CRC of the four type bytes.
    // Every PNG in existence ends with ...49454e44 ae426082.
    expect(crc32(ascii("IEND"))).toBe(0xae426082);
  });
});

describe("adler32", () => {
  it("matches the reference value for 'Wikipedia'", () => {
    expect(adler32(ascii("Wikipedia"))).toBe(0x11e60398);
  });

  it("is 1 for the empty input", () => {
    expect(adler32(new Uint8Array(0))).toBe(1);
  });
});

describe("zlibStored", () => {
  it("produces a stream node's zlib can inflate back to the original bytes", () => {
    const raw = Uint8Array.from([0x00, 0x11, 0x22, 0x33, 0x44]);
    const out = inflateSync(Buffer.from(zlibStored(raw)));
    expect(Uint8Array.from(out)).toEqual(raw);
  });

  it("round-trips a payload larger than one 65535-byte stored block", () => {
    const raw = new Uint8Array(70_000);
    for (let i = 0; i < raw.length; i++) raw[i] = i & 0xff;
    const out = inflateSync(Buffer.from(zlibStored(raw)));
    expect(Uint8Array.from(out)).toEqual(raw);
  });

  it("round-trips an empty payload", () => {
    expect(inflateSync(Buffer.from(zlibStored(new Uint8Array(0)))).length).toBe(0);
  });
});

describe("integer encoding", () => {
  it("writes big-endian and little-endian u32 in the expected byte order", () => {
    expect(Array.from(u32be(0x01020304))).toEqual([0x01, 0x02, 0x03, 0x04]);
    expect(Array.from(u32le(0x01020304))).toEqual([0x04, 0x03, 0x02, 0x01]);
  });
});

describe("hex + python literal", () => {
  it("round-trips through toHex/fromHex and tolerates separators", () => {
    const bytes = Uint8Array.from([0x89, 0x50, 0x4e, 0x47]);
    expect(toHex(bytes)).toBe("89504e47");
    expect(fromHex("89 50:4e-47")).toEqual(bytes);
    expect(fromHex("0x89504E47")).toEqual(bytes);
  });

  it("rejects odd-length and non-hex input rather than guessing", () => {
    expect(fromHex("abc")).toBeUndefined();
    expect(fromHex("zz")).toBeUndefined();
  });

  it("escapes quotes, backslashes and non-printables in the python literal", () => {
    expect(pythonLiteral(Uint8Array.from([0x22, 0x5c, 0x00, 0x41]))).toBe('b"\\"\\\\\\x00A"');
  });
});
