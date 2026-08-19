import { describe, it, expect } from "vitest";
import {
  forgeObjectId,
  parseObjectId,
  forgeObjectIdSequence,
} from "./objectid-forge.js";

describe("forgeObjectId", () => {
  it("produces the canonical hand-computed value for a known input", () => {
    // timestamp 0x60000000 BE = "60000000"
    // machineId "0000000000"
    // counter 0 BE          = "000000"
    // → "600000000000000000000000"
    const oid = forgeObjectId({
      timestamp: 0x60000000,
      machineId: "0000000000",
      counter: 0,
    });
    expect(oid).toBe("600000000000000000000000");
    expect(oid).toHaveLength(24);
  });

  it("produces a 24-char lowercase hex string for a non-trivial input", () => {
    const oid = forgeObjectId({
      timestamp: 1_700_000_000,
      machineId: "abcd1234ef",
      counter: 42,
    });
    expect(oid).toHaveLength(24);
    expect(oid).toMatch(/^[0-9a-f]{24}$/);
    // 1700000000 = 0x6553f100
    expect(oid.slice(0, 8)).toBe("6553f100");
    expect(oid.slice(8, 18)).toBe("abcd1234ef");
    expect(oid.slice(18, 24)).toBe("00002a");
  });

  it("lowercases an uppercase machineId", () => {
    const oid = forgeObjectId({
      timestamp: 0x12345678,
      machineId: "ABCDEFABCD",
      counter: 0,
    });
    expect(oid).toBe("12345678abcdefabcd000000");
  });

  it("handles counter = 0 (the 'first user' case)", () => {
    const oid = forgeObjectId({ timestamp: 1, machineId: "1111111111", counter: 0 });
    expect(oid).toBe("000000011111111111000000");
  });

  it("handles counter = 16777215 (max 3-byte value)", () => {
    const oid = forgeObjectId({ timestamp: 1, machineId: "1111111111", counter: 0xffffff });
    expect(oid.slice(18, 24)).toBe("ffffff");
  });

  it("handles machineId all zeros", () => {
    const oid = forgeObjectId({ timestamp: 1, machineId: "0000000000", counter: 1 });
    expect(oid).toBe("000000010000000000000001");
  });

  it("handles machineId all f's", () => {
    const oid = forgeObjectId({ timestamp: 1, machineId: "ffffffffff", counter: 1 });
    expect(oid).toBe("00000001ffffffffff000001");
  });

  it("rejects an out-of-range timestamp", () => {
    expect(() =>
      forgeObjectId({ timestamp: -1, machineId: "0000000000", counter: 0 }),
    ).toThrow(/timestamp/);
    expect(() =>
      forgeObjectId({ timestamp: 0x100000000, machineId: "0000000000", counter: 0 }),
    ).toThrow(/timestamp/);
  });

  it("rejects an out-of-range counter", () => {
    expect(() =>
      forgeObjectId({ timestamp: 1, machineId: "0000000000", counter: -1 }),
    ).toThrow(/counter/);
    expect(() =>
      forgeObjectId({ timestamp: 1, machineId: "0000000000", counter: 0x1000000 }),
    ).toThrow(/counter/);
  });

  it("rejects a malformed machineId", () => {
    expect(() =>
      forgeObjectId({ timestamp: 1, machineId: "tooshort", counter: 0 }),
    ).toThrow(/machineId/);
    expect(() =>
      forgeObjectId({ timestamp: 1, machineId: "zzzzzzzzzz", counter: 0 }),
    ).toThrow(/machineId/);
  });
});

describe("parseObjectId", () => {
  it("round-trips with forgeObjectId for several inputs", () => {
    const cases = [
      { timestamp: 0x60000000, machineId: "0000000000", counter: 0 },
      { timestamp: 1_700_000_000, machineId: "abcd1234ef", counter: 42 },
      { timestamp: 1, machineId: "ffffffffff", counter: 0xffffff },
      { timestamp: 0xffffffff, machineId: "1234567890", counter: 1 },
      { timestamp: 0, machineId: "0a0b0c0d0e", counter: 0 },
    ];
    for (const c of cases) {
      const oid = forgeObjectId(c);
      const parsed = parseObjectId(oid);
      expect(parsed).toEqual(c);
    }
  });

  it("parses a real-looking ObjectId", () => {
    const parsed = parseObjectId("6553f100abcd1234ef00002a");
    expect(parsed.timestamp).toBe(1_700_000_000);
    expect(parsed.machineId).toBe("abcd1234ef");
    expect(parsed.counter).toBe(42);
  });

  it("accepts uppercase hex and returns lowercase machine ID", () => {
    const parsed = parseObjectId("6553F100ABCD1234EF00002A");
    expect(parsed.machineId).toBe("abcd1234ef");
    expect(parsed.counter).toBe(42);
  });

  it("throws on wrong length", () => {
    expect(() => parseObjectId("deadbeef")).toThrow(/24 hex chars/);
    expect(() => parseObjectId("6553f100abcd1234ef00002a00")).toThrow(/24 hex chars/);
  });

  it("throws on non-hex chars", () => {
    expect(() => parseObjectId("zzzzzzzzzzzzzzzzzzzzzzzz")).toThrow(/hex/);
  });

  it("throws on non-string input", () => {
    // @ts-expect-error testing runtime guard
    expect(() => parseObjectId(12345)).toThrow();
  });
});

describe("forgeObjectIdSequence", () => {
  it("returns count ObjectIds with monotonically increasing counters", () => {
    const seq = forgeObjectIdSequence({
      timestamp: 0x60000000,
      machineId: "0000000000",
      counterStart: 0,
      count: 5,
    });
    expect(seq).toHaveLength(5);
    expect(seq[0]).toBe("600000000000000000000000");
    expect(seq[1]).toBe("600000000000000000000001");
    expect(seq[2]).toBe("600000000000000000000002");
    expect(seq[3]).toBe("600000000000000000000003");
    expect(seq[4]).toBe("600000000000000000000004");
  });

  it("supports a non-zero counterStart", () => {
    const seq = forgeObjectIdSequence({
      timestamp: 1,
      machineId: "abcdef0123",
      counterStart: 1000,
      count: 3,
    });
    expect(seq).toHaveLength(3);
    expect(parseObjectId(seq[0]).counter).toBe(1000);
    expect(parseObjectId(seq[1]).counter).toBe(1001);
    expect(parseObjectId(seq[2]).counter).toBe(1002);
  });

  it("returns an empty array for count = 0", () => {
    const seq = forgeObjectIdSequence({
      timestamp: 1,
      machineId: "0000000000",
      counterStart: 0,
      count: 0,
    });
    expect(seq).toEqual([]);
  });

  it("throws when counterStart + count would overflow the 3-byte counter", () => {
    expect(() =>
      forgeObjectIdSequence({
        timestamp: 1,
        machineId: "0000000000",
        counterStart: 0xfffffe,
        count: 5,
      }),
    ).toThrow(/overflow/);
  });

  it("throws if count exceeds the entire counter space", () => {
    expect(() =>
      forgeObjectIdSequence({
        timestamp: 1,
        machineId: "0000000000",
        counterStart: 0,
        count: 0x1000001,
      }),
    ).toThrow();
  });

  it("throws on negative count", () => {
    expect(() =>
      forgeObjectIdSequence({
        timestamp: 1,
        machineId: "0000000000",
        counterStart: 0,
        count: -1,
      }),
    ).toThrow(/non-negative/);
  });
});
