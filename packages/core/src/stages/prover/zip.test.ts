/**
 * ZIP prover-plugin tests.
 *
 * Two layers of ground truth:
 *
 *  1. A small independent parser written here in the test file, plus node's
 *     `zlib.crc32` for entry checksums. These assertions cannot pass by
 *     agreeing with the plugin's own helpers.
 *  2. Python's `zipfile` module as an external oracle — it is the same
 *     reference implementation the craft stage already depends on (`python3`
 *     runs every generated PoC), and it enumerates and extracts exactly the way
 *     a real parser does. Those cases are gated on `python3` being present so
 *     the suite stays green on a machine without it; the structural
 *     assertions in layer 1 cover the same properties unconditionally.
 */

import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32 as nodeCrc32 } from "node:zlib";
import { zipProverPlugin } from "./zip.js";
import { concat, toHex } from "./binary.js";

const hasPython = spawnSync("python3", ["-c", "import zipfile"], { stdio: "ignore" }).status === 0;

// ── independent mini-parser ──────────────────────────────────────────────────

interface TestEocd {
  offset: number;
  entries: number;
  cdSize: number;
  cdOffset: number;
}

function parseEocd(b: Uint8Array): TestEocd {
  for (let at = b.length - 22; at >= 0; at--) {
    if (b[at] === 0x50 && b[at + 1] === 0x4b && b[at + 2] === 0x05 && b[at + 3] === 0x06) {
      const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
      return { offset: at, entries: v.getUint16(at + 10, true), cdSize: v.getUint32(at + 12, true), cdOffset: v.getUint32(at + 16, true) };
    }
  }
  throw new Error("no EOCD");
}

interface TestRecord {
  name: string;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  localOffset: number;
  size: number;
}

function parseCentralDirectory(b: Uint8Array, eocd: TestEocd): TestRecord[] {
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out: TestRecord[] = [];
  let at = eocd.cdOffset;
  for (let i = 0; i < eocd.entries; i++) {
    expect(toHex(b.subarray(at, at + 4))).toBe("504b0102");
    const nameLen = v.getUint16(at + 28, true);
    const extraLen = v.getUint16(at + 30, true);
    const commentLen = v.getUint16(at + 32, true);
    out.push({
      crc: v.getUint32(at + 16, true),
      compressedSize: v.getUint32(at + 20, true),
      uncompressedSize: v.getUint32(at + 24, true),
      localOffset: v.getUint32(at + 42, true),
      name: String.fromCharCode(...b.subarray(at + 46, at + 46 + nameLen)),
      size: 46 + nameLen + extraLen + commentLen,
    });
    at += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/** Payload bytes of the entry whose local header sits at `offset`. */
function entryData(b: Uint8Array, offset: number, compressedSize: number): Uint8Array {
  expect(toHex(b.subarray(offset, offset + 4))).toBe("504b0304");
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const nameLen = v.getUint16(offset + 26, true);
  const extraLen = v.getUint16(offset + 28, true);
  const start = offset + 30 + nameLen + extraLen;
  return b.subarray(start, start + compressedSize);
}

function buildOk(params: Record<string, unknown>): Uint8Array {
  const r = zipProverPlugin.construct({ params });
  if (!r.ok) throw new Error(`construct failed: ${r.error}`);
  return r.bytes;
}

const TWO_ENTRIES = {
  entries: [
    { name: "a.txt", dataText: "hello prover" },
    { name: "dir/b.bin", dataHex: "00010203deadbeef" },
  ],
};

// ── construction ─────────────────────────────────────────────────────────────

describe("zipProverPlugin.construct — from scratch", () => {
  it("writes an EOCD whose central-directory offset really points at PK\\x01\\x02", () => {
    const bytes = buildOk(TWO_ENTRIES);
    const eocd = parseEocd(bytes);
    expect(eocd.entries).toBe(2);
    expect(toHex(bytes.subarray(eocd.cdOffset, eocd.cdOffset + 4))).toBe("504b0102");
    expect(eocd.cdOffset + eocd.cdSize).toBe(eocd.offset);
  });

  it("points every directory record at a real local file header with the same name", () => {
    const bytes = buildOk(TWO_ENTRIES);
    const records = parseCentralDirectory(bytes, parseEocd(bytes));
    expect(records.map((r) => r.name)).toEqual(["a.txt", "dir/b.bin"]);
    const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (const r of records) {
      expect(toHex(bytes.subarray(r.localOffset, r.localOffset + 4))).toBe("504b0304");
      const nameLen = v.getUint16(r.localOffset + 26, true);
      expect(String.fromCharCode(...bytes.subarray(r.localOffset + 30, r.localOffset + 30 + nameLen))).toBe(r.name);
    }
  });

  it("computes each entry's CRC-32 to the value node's zlib computes over the payload", () => {
    const bytes = buildOk(TWO_ENTRIES);
    const records = parseCentralDirectory(bytes, parseEocd(bytes));
    for (const r of records) {
      const data = entryData(bytes, r.localOffset, r.compressedSize);
      expect(r.crc >>> 0).toBe(nodeCrc32(Buffer.from(data)) >>> 0);
      expect(r.uncompressedSize).toBe(data.length);
    }
  });

  it("writes a planted CRC verbatim — a deliberately wrong checksum is the PoC, not a mistake", () => {
    const r = zipProverPlugin.construct({
      params: { entries: [{ name: "a.txt", dataText: "AAAA", crc: 0xdeadbeef, uncompressedSize: 0x41414141 }] },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const rec = parseCentralDirectory(r.bytes, parseEocd(r.bytes))[0]!;
    expect(rec.crc >>> 0).toBe(0xdeadbeef);
    expect(rec.uncompressedSize).toBe(0x41414141);
    expect(r.notes.join(" ")).toMatch(/planted/);
  });

  it("keeps the archive comment and still lets the EOCD be found behind it", () => {
    const bytes = buildOk({ ...TWO_ENTRIES, comment: "x".repeat(300) });
    const eocd = parseEocd(bytes);
    expect(bytes.length - eocd.offset - 22).toBe(300);
    expect(zipProverPlugin.validate(bytes).wellFormed).toBe(true);
  });

  it("rejects an unknown entry key rather than silently defaulting it", () => {
    const r = zipProverPlugin.construct({ params: { entries: [{ name: "a", dataTxt: "oops" }] } });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toMatch(/unknown param `dataTxt`/);
  });

  it("refuses an empty entry list with a usable example", () => {
    const r = zipProverPlugin.construct({ params: { entries: [] } });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.error).toMatch(/entries/);
  });
});

// ── validation ───────────────────────────────────────────────────────────────

describe("zipProverPlugin.validate", () => {
  it("accepts what construct produced and lists the entries", () => {
    const report = zipProverPlugin.validate(buildOk(TWO_ENTRIES));
    expect(report.wellFormed).toBe(true);
    expect(report.defects.filter((d) => d.severity === "fatal")).toEqual([]);
    expect(report.structure.join("\n")).toMatch(/'a\.txt'/);
  });

  it("rejects a buffer with no EOCD at all", () => {
    const report = zipProverPlugin.validate(Uint8Array.from([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]));
    expect(report.wellFormed).toBe(false);
    expect(report.defects[0]?.field).toBe("eocd");
  });

  it("rejects a central-directory offset that lands on nothing and is not a uniform prefix shift", () => {
    // Move the offset AND keep cdSize, so `eocdOffset - cdSize - cdOffset` does
    // not explain it either. This is the unrecoverable case.
    const bytes = Uint8Array.from(buildOk(TWO_ENTRIES));
    const eocd = parseEocd(bytes);
    new DataView(bytes.buffer).setUint32(eocd.offset + 16, eocd.cdOffset + 3, true);
    new DataView(bytes.buffer).setUint32(eocd.offset + 12, eocd.cdSize - 3, true);
    const report = zipProverPlugin.validate(bytes);
    expect(report.wellFormed).toBe(false);
    const defect = report.defects.find((d) => d.field === "eocd.centralDirectoryOffset");
    expect(defect?.severity).toBe("fatal");
    expect(defect?.repairable).toBe(true);
  });

  it("treats a UNIFORM prepended-data shift as a warning, because minizip and python's zipfile compensate for it", () => {
    // Every offset is short by 16. python's `_handle_prepended_data` and
    // minizip's `byte_before_the_zipfile` both infer exactly this delta, so the
    // archive is still reachable and flagging it fatal would send the agent
    // chasing a non-problem.
    const shifted = concat([new Uint8Array(16), buildOk(TWO_ENTRIES)]);
    const report = zipProverPlugin.validate(shifted);
    expect(report.wellFormed).toBe(true);
    const defect = report.defects.find((d) => d.field === "eocd.centralDirectoryOffset");
    expect(defect?.severity).toBe("warning");
    expect(defect?.message).toMatch(/prepended data/);
    // …and the entry table is still walked, through the inferred prefix.
    expect(report.structure.join("\n")).toMatch(/'dir\/b\.bin'/);
  });

  it("rejects a directory record pointing at a non-existent local header", () => {
    const bytes = Uint8Array.from(buildOk(TWO_ENTRIES));
    const eocd = parseEocd(bytes);
    const records = parseCentralDirectory(bytes, eocd);
    // The first record's local-header-offset field lives at cdOffset + 42.
    new DataView(bytes.buffer).setUint32(eocd.cdOffset + 42, records[0]!.localOffset + 5, true);
    const report = zipProverPlugin.validate(bytes);
    expect(report.wellFormed).toBe(false);
    expect(report.defects.some((d) => d.field.includes("localHeaderOffset"))).toBe(true);
  });

  it("rejects an entry count the directory does not actually contain", () => {
    const bytes = Uint8Array.from(buildOk(TWO_ENTRIES));
    const eocd = parseEocd(bytes);
    new DataView(bytes.buffer).setUint16(eocd.offset + 10, 7, true);
    const report = zipProverPlugin.validate(bytes);
    expect(report.defects.find((d) => d.field === "eocd.totalEntries")?.severity).toBe("fatal");
  });

  it("reports a wrong entry CRC as a WARNING — it is checked at extraction, after enumeration succeeded", () => {
    const bytes = buildOk({ entries: [{ name: "a.txt", dataText: "AAAA", crc: 0x11223344 }] });
    const report = zipProverPlugin.validate(bytes);
    expect(report.wellFormed).toBe(true);
    expect(report.defects.find((d) => d.field.includes("crc32"))?.severity).toBe("warning");
  });

  it("reports a stored entry whose declared sizes disagree as a WARNING — a classic ZIP bug lever", () => {
    const bytes = buildOk({ entries: [{ name: "a.txt", dataText: "AAAA", uncompressedSize: 0xffff }] });
    const report = zipProverPlugin.validate(bytes);
    expect(report.wellFormed).toBe(true);
    expect(report.defects.find((d) => d.field.includes("uncompressedSize"))?.severity).toBe("warning");
  });
});

// ── repair ───────────────────────────────────────────────────────────────────

describe("zipProverPlugin.construct — repair mode", () => {
  it("rewrites prefixed offsets absolutely, so even a non-SFX-aware parser can navigate", () => {
    const good = buildOk(TWO_ENTRIES);
    // A python generator that writes a header before the archive shifts every
    // absolute offset in the file. Tolerant parsers infer the prefix; repairing
    // removes the dependency on that tolerance entirely.
    const shifted = concat([new Uint8Array(16), good]);
    expect(zipProverPlugin.validate(shifted).defects.some((d) => d.severity === "warning")).toBe(true);

    const r = zipProverPlugin.construct({ base: shifted });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.bytes.length).toBe(shifted.length);
    const after = zipProverPlugin.validate(r.bytes);
    expect(after.wellFormed).toBe(true);
    expect(after.defects).toEqual([]);

    const fields = r.repairs.map((x) => x.field);
    expect(fields).toContain("eocd.centralDirectoryOffset");
    expect(fields.some((f) => f.includes("'a.txt'"))).toBe(true);
    for (const rec of r.repairs) expect(rec.why.length).toBeGreaterThan(20);
  });

  it("re-points a SINGLE stale record offset, which no parser compensates for", () => {
    const good = Uint8Array.from(buildOk(TWO_ENTRIES));
    const eocd = parseEocd(good);
    const records = parseCentralDirectory(good, eocd);
    // Corrupt only the second record. There is no uniform delta to infer, so
    // python, minizip and everyone else fails to open that entry.
    const secondRecordAt = eocd.cdOffset + records[0]!.size;
    new DataView(good.buffer).setUint32(secondRecordAt + 42, records[1]!.localOffset + 5, true);
    expect(zipProverPlugin.validate(good).wellFormed).toBe(false);

    const r = zipProverPlugin.construct({ base: good });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.repairs.map((x) => x.field)).toEqual(["centralDirectory['dir/b.bin'].localHeaderOffset"]);
    expect(zipProverPlugin.validate(r.bytes).wellFormed).toBe(true);
  });

  it("preserves the entry payloads byte-for-byte while repairing", () => {
    const good = buildOk(TWO_ENTRIES);
    const shifted = concat([new Uint8Array(16), good]);
    const r = zipProverPlugin.construct({ base: shifted });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const records = parseCentralDirectory(r.bytes, parseEocd(r.bytes));
    const data = entryData(r.bytes, records[0]!.localOffset, records[0]!.compressedSize);
    expect(Buffer.from(data).toString("latin1")).toBe("hello prover");
  });

  it("does not touch a planted CRC while fixing navigation", () => {
    const good = buildOk({ entries: [{ name: "a.txt", dataText: "AAAA", crc: 0xdeadbeef }] });
    const r = zipProverPlugin.construct({ base: concat([new Uint8Array(8), good]) });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(parseCentralDirectory(r.bytes, parseEocd(r.bytes))[0]!.crc >>> 0).toBe(0xdeadbeef);
  });

  it("reports no repairs and returns the bytes unchanged for an already-consistent archive", () => {
    const good = buildOk(TWO_ENTRIES);
    const r = zipProverPlugin.construct({ base: good });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.repairs).toEqual([]);
    expect(r.bytes).toEqual(good);
  });

  it("refuses when there is no EOCD to anchor the repair", () => {
    const r = zipProverPlugin.construct({ base: Uint8Array.from([0x50, 0x4b, 0x03, 0x04]) });
    expect(r.ok).toBe(false);
  });
});

// ── external oracle ──────────────────────────────────────────────────────────

describe.skipIf(!hasPython)("zipProverPlugin against python's zipfile", () => {
  function writeTmp(bytes: Uint8Array, name: string): string {
    const dir = mkdtempSync(join(tmpdir(), "prover-zip-"));
    const path = join(dir, name);
    writeFileSync(path, bytes);
    return path;
  }

  /** Enumerate AND extract every entry — extraction is what follows the offsets. */
  function pythonInspect(path: string): { status: number; stdout: string } {
    const res = spawnSync(
      "python3",
      [
        "-c",
        "import sys,zipfile\n" +
          "z=zipfile.ZipFile(sys.argv[1])\n" +
          "print('|'.join(z.namelist()))\n" +
          "print('|'.join(z.read(n).hex() for n in z.namelist()))\n",
        path,
      ],
      { encoding: "utf8" },
    );
    return { status: res.status ?? -1, stdout: res.stdout };
  }

  it("builds an archive python enumerates and extracts correctly", () => {
    const path = writeTmp(buildOk(TWO_ENTRIES), "built.zip");
    const { status, stdout } = pythonInspect(path);
    expect(status).toBe(0);
    expect(stdout.split("\n")[0]).toBe("a.txt|dir/b.bin");
    expect(stdout.split("\n")[1]).toBe(`${Buffer.from("hello prover").toString("hex")}|00010203deadbeef`);
  });

  it("python REJECTS a single stale record offset and ACCEPTS the repaired archive", () => {
    const broken = Uint8Array.from(buildOk(TWO_ENTRIES));
    const eocd = parseEocd(broken);
    const records = parseCentralDirectory(broken, eocd);
    new DataView(broken.buffer).setUint32(eocd.cdOffset + records[0]!.size + 42, records[1]!.localOffset + 5, true);
    expect(pythonInspect(writeTmp(broken, "broken.zip")).status).not.toBe(0);

    const r = zipProverPlugin.construct({ base: broken });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const after = pythonInspect(writeTmp(r.bytes, "repaired.zip"));
    expect(after.status).toBe(0);
    expect(after.stdout.split("\n")[0]).toBe("a.txt|dir/b.bin");
  });

  it("confirms the tolerance the validator models: python OPENS a uniformly prefixed archive", () => {
    // This is the external check behind downgrading a prepended-data shift from
    // fatal to warning. If a future python version stopped compensating, this
    // test fails and the severity should be revisited.
    const shifted = concat([new Uint8Array(16), buildOk(TWO_ENTRIES)]);
    expect(pythonInspect(writeTmp(shifted, "shifted.zip")).status).toBe(0);
    // …and the repaired form is accepted too, so repairing is never a regression.
    const r = zipProverPlugin.construct({ base: shifted });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(pythonInspect(writeTmp(r.bytes, "shifted-repaired.zip")).status).toBe(0);
  });
});

// ── selection ────────────────────────────────────────────────────────────────

describe("zipProverPlugin.matches", () => {
  it("scores 1.0 on a local file header signature", () => {
    expect(zipProverPlugin.matches({ sample: buildOk(TWO_ENTRIES) }).score).toBe(1);
  });

  it("scores 0.75 on a ZIP-ish fuzzer name", () => {
    expect(zipProverPlugin.matches({ hint: "minizip_fuzzer" }).score).toBe(0.75);
    expect(zipProverPlugin.matches({ hint: "zip_read_fuzzer" }).score).toBe(0.75);
  });

  it("does NOT claim gzip just because the name contains 'zip'", () => {
    expect(zipProverPlugin.matches({ hint: "gzip_decompress_fuzzer" }).score).toBe(0);
  });
});
