/**
 * ZIP prover plugin — central-directory offsets, EOCD framing, entry CRC-32.
 *
 * ## Why ZIP is the second plugin
 *
 * `stages/format-knowledge.ts` states the barrier precisely: *"Parsers read
 * EOCD first (scan from end for PK0506) → central dir offset/count."* That one
 * sentence hides the reason hand-built ZIPs fail. A ZIP is not read
 * front-to-back; it is read **backwards**. The parser finds the end-of-central-
 * directory record, follows its 32-bit offset to the central directory, walks
 * the directory records, and follows each record's own 32-bit offset back to a
 * local file header. Every one of those offsets is an absolute position in the
 * file.
 *
 * Which means: the moment the agent prepends a byte, appends a comment, changes
 * a filename length, or reorders an entry, **every offset downstream is wrong**
 * and the parser enumerates nothing. It does not crash, it does not warn — it
 * reports an empty or corrupt archive and the vulnerable extraction code is
 * never entered. The agent then reads "no crash", assumes its hypothesis about
 * the bug was wrong, and rewrites a hypothesis that was actually correct. This
 * is the exact shape of the 65.4% "Prove" bucket.
 *
 * Recomputing those offsets is mechanical, total, and something a plugin can do
 * perfectly. That is the whole argument for the interface.
 *
 * ## Framing vs. semantics, applied to ZIP
 *
 * Framing (this plugin owns): the EOCD signature and its central-directory
 * size/offset/count fields, and each central-directory record's local-header
 * offset. Get these wrong and enumeration fails at the front door.
 *
 * Semantics (this plugin passes through untouched, and lets the caller plant
 * deliberately): an entry's declared `crc32`, `compressedSize` and
 * `uncompressedSize`. A mismatch between a declared uncompressed size and the
 * bytes actually produced is one of the oldest and most productive ZIP bug
 * classes — a plugin that "helpfully" corrected it would be deleting the PoC.
 * So construction exposes explicit override knobs for all three, and validation
 * reports a mismatch as a `warning`, never a `fatal`: the mismatch is caught at
 * extraction time, long after enumeration has succeeded, so it does not block
 * reachability.
 *
 * ## Scope
 *
 * Store-only (method 0) for construction, because the point is byte-exactness
 * and a stored entry's CRC and sizes are derivable with no compressor in the
 * loop. Deflated entries are fully supported in *repair* and *validation* (the
 * compressed bytes are carried verbatim); they are simply not synthesised.
 * ZIP64 is out of scope and is reported explicitly rather than mis-parsed —
 * see the note at {@link ZIP64_MARKER}.
 */

import {
  ascii,
  concat,
  crc32,
  readU16le,
  readU32le,
  startsWith,
  toHex,
  u16le,
  u32le,
} from "./binary.js";
import { matchAlias } from "./hint.js";
import { ParamError, ParamReader, withParams } from "./params.js";
import type {
  ConstructRequest,
  ConstructResult,
  ProverContext,
  ProverMatch,
  ProverPlugin,
  RepairRecord,
  ValidationDefect,
  ValidationReport,
} from "./types.js";

const LFH_SIG = [0x50, 0x4b, 0x03, 0x04] as const; // "PK\x03\x04"
const CDH_SIG = [0x50, 0x4b, 0x01, 0x02] as const; // "PK\x01\x02"
const EOCD_SIG = [0x50, 0x4b, 0x05, 0x06] as const; // "PK\x05\x06"

/**
 * The sentinel a 32-bit ZIP field carries when the real value lives in a ZIP64
 * extended-information extra field. We detect it and say so rather than
 * silently treating 0xffffffff as a literal offset — a plugin that reports a
 * confidently wrong structure is worse than one that admits a gap.
 */
const ZIP64_MARKER = 0xffffffff;

const LFH_FIXED = 30;
const CDH_FIXED = 46;
const EOCD_FIXED = 22;

/** DOS date for 1980-01-01, the epoch of the MS-DOS date encoding ZIP uses. */
const DOS_DATE_EPOCH = 0x0021;

interface LocalHeader {
  offset: number;
  method: number;
  flags: number;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  name: string;
  /** Offset of the entry's payload (past the fixed header, name and extra). */
  dataOffset: number;
}

interface CentralRecord {
  offset: number;
  method: number;
  flags: number;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  name: string;
  localHeaderOffset: number;
  /** Total on-disk size of this record, including name/extra/comment. */
  totalSize: number;
  /** Offset of the 4-byte local-header-offset field, for precise repair records. */
  localHeaderOffsetField: number;
}

interface Eocd {
  offset: number;
  entriesThisDisk: number;
  totalEntries: number;
  cdSize: number;
  cdOffset: number;
  commentLength: number;
}

/**
 * Find the EOCD the way a real parser does: scan backwards for `PK\x05\x06`.
 * The archive comment can be up to 64 KiB, so the record can sit that far from
 * the end. We take the LAST match, matching the behaviour of info-zip and most
 * hardened parsers (taking the first match from the front is how some parsers
 * get confused by a `PK\x05\x06` byte sequence inside compressed data).
 */
function findEocd(buf: Uint8Array): Eocd | undefined {
  const earliest = Math.max(0, buf.length - EOCD_FIXED - 0xffff);
  for (let at = buf.length - EOCD_FIXED; at >= earliest; at--) {
    if (!startsWith(buf.subarray(at), EOCD_SIG)) continue;
    const entriesThisDisk = readU16le(buf, at + 8);
    const totalEntries = readU16le(buf, at + 10);
    const cdSize = readU32le(buf, at + 12);
    const cdOffset = readU32le(buf, at + 16);
    const commentLength = readU16le(buf, at + 20);
    if (
      entriesThisDisk === undefined ||
      totalEntries === undefined ||
      cdSize === undefined ||
      cdOffset === undefined ||
      commentLength === undefined
    ) {
      continue;
    }
    return { offset: at, entriesThisDisk, totalEntries, cdSize, cdOffset, commentLength };
  }
  return undefined;
}

/** Walk central-directory records starting at `at`, stopping on the first desync. */
function walkCentralDirectory(buf: Uint8Array, at: number, limit: number): CentralRecord[] {
  const out: CentralRecord[] = [];
  let p = at;
  while (p + CDH_FIXED <= limit && startsWith(buf.subarray(p), CDH_SIG)) {
    const flags = readU16le(buf, p + 8) ?? 0;
    const method = readU16le(buf, p + 10) ?? 0;
    const crc = readU32le(buf, p + 16) ?? 0;
    const compressedSize = readU32le(buf, p + 20) ?? 0;
    const uncompressedSize = readU32le(buf, p + 24) ?? 0;
    const nameLen = readU16le(buf, p + 28) ?? 0;
    const extraLen = readU16le(buf, p + 30) ?? 0;
    const commentLen = readU16le(buf, p + 32) ?? 0;
    const localHeaderOffset = readU32le(buf, p + 42) ?? 0;
    const nameEnd = Math.min(p + CDH_FIXED + nameLen, buf.length);
    const name = String.fromCharCode(...buf.subarray(p + CDH_FIXED, nameEnd));
    const totalSize = CDH_FIXED + nameLen + extraLen + commentLen;
    out.push({
      offset: p,
      method,
      flags,
      crc,
      compressedSize,
      uncompressedSize,
      name,
      localHeaderOffset,
      totalSize,
      localHeaderOffsetField: p + 42,
    });
    p += totalSize;
  }
  return out;
}

/** Parse the local file header at `at`, or `undefined` if the signature is absent. */
function readLocalHeader(buf: Uint8Array, at: number): LocalHeader | undefined {
  if (at < 0 || at + LFH_FIXED > buf.length) return undefined;
  if (!startsWith(buf.subarray(at), LFH_SIG)) return undefined;
  const flags = readU16le(buf, at + 6) ?? 0;
  const method = readU16le(buf, at + 8) ?? 0;
  const crc = readU32le(buf, at + 14) ?? 0;
  const compressedSize = readU32le(buf, at + 18) ?? 0;
  const uncompressedSize = readU32le(buf, at + 22) ?? 0;
  const nameLen = readU16le(buf, at + 26) ?? 0;
  const extraLen = readU16le(buf, at + 28) ?? 0;
  const nameEnd = Math.min(at + LFH_FIXED + nameLen, buf.length);
  return {
    offset: at,
    flags,
    method,
    crc,
    compressedSize,
    uncompressedSize,
    name: String.fromCharCode(...buf.subarray(at + LFH_FIXED, nameEnd)),
    dataOffset: at + LFH_FIXED + nameLen + extraLen,
  };
}

/** Every local file header in the buffer, found by signature scan. */
function scanLocalHeaders(buf: Uint8Array): LocalHeader[] {
  const out: LocalHeader[] = [];
  for (let at = 0; at + LFH_FIXED <= buf.length; at++) {
    if (buf[at] !== LFH_SIG[0]) continue;
    const h = readLocalHeader(buf, at);
    if (h) out.push(h);
  }
  return out;
}

const PARAMS_HELP =
  "ZIP params (build): entries — array of {name, dataHex?, dataText?, crc?, compressedSize?, uncompressedSize?, method?}. " +
  "`crc`/`compressedSize`/`uncompressedSize` are SEMANTIC overrides: give them to plant a deliberately inconsistent " +
  "entry (the classic ZIP bug class) and the plugin writes them verbatim while still producing correct directory " +
  "offsets. `method` defaults to 0 (stored); construction cannot deflate, so pass already-deflated bytes in dataHex " +
  "with method: 8 if you need one. Also: comment (archive comment string). " +
  "ZIP params (repair, with `base`): fixOffsets (default true), fixEocd (default true).";

interface BuildEntry {
  name: string;
  data: Uint8Array;
  method: number;
  crc: number;
  compressedSize: number;
  uncompressedSize: number;
  planted: string[];
}

function constructZip(req: ConstructRequest): ConstructResult {
  return req.base ? repair(req.base, req.params) : build(req.params);
}

function build(params: Record<string, unknown> | undefined): ConstructResult {
  const parsed = withParams(() => {
    const p = new ParamReader(params);
    const rawEntries = p.objects("entries");
    const comment = p.str("comment", "");
    p.rejectUnknown(PARAMS_HELP);
    const entries: BuildEntry[] = rawEntries.map((e, i) => {
      const ep = new ParamReader(e);
      const name = ep.str("name", "");
      const dataHex = ep.hex("dataHex", new Uint8Array(0));
      const dataText = ep.str("dataText", "");
      const method = ep.int("method", 0, 0, 0xffff);
      const hasCrc = ep.has("crc");
      const crc = ep.int("crc", 0, 0, 0xffffffff);
      const hasCsize = ep.has("compressedSize");
      const compressedSize = ep.int("compressedSize", 0, 0, 0xffffffff);
      const hasUsize = ep.has("uncompressedSize");
      const uncompressedSize = ep.int("uncompressedSize", 0, 0, 0xffffffff);
      ep.rejectUnknown(`entries[${i}] accepts name, dataHex, dataText, method, crc, compressedSize, uncompressedSize.`);
      if (name === "") throw new ParamError(`entries[${i}].name is required`);
      if (dataHex.length > 0 && dataText !== "") {
        throw new ParamError(`entries[${i}] has both dataHex and dataText — pick one`);
      }
      const data = dataHex.length > 0 ? dataHex : ascii(dataText);
      const planted: string[] = [];
      if (hasCrc) planted.push("crc");
      if (hasCsize) planted.push("compressedSize");
      if (hasUsize) planted.push("uncompressedSize");
      return {
        name,
        data,
        method,
        crc: hasCrc ? crc : crc32(data),
        compressedSize: hasCsize ? compressedSize : data.length,
        uncompressedSize: hasUsize ? uncompressedSize : data.length,
        planted,
      };
    });
    return { entries, comment };
  });
  if (!parsed.ok) return { ok: false, error: `zip construct: ${parsed.error}` };
  const { entries, comment } = parsed.value;

  if (entries.length === 0) {
    return {
      ok: false,
      error:
        "zip construct: `entries` is empty. Pass at least one entry, e.g. " +
        '{"entries":[{"name":"a.txt","dataText":"A"}]}. ' +
        PARAMS_HELP,
    };
  }
  if (entries.length > 0xffff) {
    return {
      ok: false,
      error: `zip construct: ${entries.length} entries exceeds the 16-bit EOCD entry count; ZIP64 is not supported by this plugin.`,
    };
  }

  const notes: string[] = [];
  const parts: Uint8Array[] = [];
  const localOffsets: number[] = [];
  let cursor = 0;

  for (const e of entries) {
    const nameBytes = ascii(e.name);
    localOffsets.push(cursor);
    const lfh = concat([
      Uint8Array.from(LFH_SIG),
      u16le(20), // version needed
      u16le(0), // flags
      u16le(e.method),
      u16le(0), // mod time
      u16le(DOS_DATE_EPOCH),
      u32le(e.crc),
      u32le(e.compressedSize),
      u32le(e.uncompressedSize),
      u16le(nameBytes.length),
      u16le(0), // extra length
      nameBytes,
    ]);
    parts.push(lfh, e.data);
    cursor += lfh.length + e.data.length;
    if (e.planted.length > 0) {
      notes.push(
        `entry '${e.name}': planted ${e.planted.join(", ")} verbatim — the local header and the central directory both carry your value, and the actual payload is ${e.data.length} bytes.`,
      );
    }
    if (e.method !== 0) {
      notes.push(
        `entry '${e.name}': method ${e.method} declared but the payload was written verbatim (no compression performed) — make sure dataHex already holds the compressed stream.`,
      );
    }
  }

  const cdOffset = cursor;
  entries.forEach((e, i) => {
    const nameBytes = ascii(e.name);
    const cdh = concat([
      Uint8Array.from(CDH_SIG),
      u16le(20), // version made by
      u16le(20), // version needed
      u16le(0), // flags
      u16le(e.method),
      u16le(0), // mod time
      u16le(DOS_DATE_EPOCH),
      u32le(e.crc),
      u32le(e.compressedSize),
      u32le(e.uncompressedSize),
      u16le(nameBytes.length),
      u16le(0), // extra length
      u16le(0), // comment length
      u16le(0), // disk number start
      u16le(0), // internal attributes
      u32le(0), // external attributes
      u32le(localOffsets[i]!),
      nameBytes,
    ]);
    parts.push(cdh);
    cursor += cdh.length;
  });
  const cdSize = cursor - cdOffset;

  const commentBytes = ascii(comment);
  parts.push(
    concat([
      Uint8Array.from(EOCD_SIG),
      u16le(0), // this disk
      u16le(0), // disk with CD
      u16le(entries.length),
      u16le(entries.length),
      u32le(cdSize),
      u32le(cdOffset),
      u16le(commentBytes.length),
      commentBytes,
    ]),
  );

  notes.push(
    `central directory at offset ${cdOffset} (${cdSize} bytes, ${entries.length} record(s)); EOCD points at it. ` +
      "If you post-process these bytes in python, any insertion before the directory invalidates every offset — re-run prover_construct with the result as `base` instead of patching by hand.",
  );

  return { ok: true, bytes: concat(parts), repairs: [], notes };
}

/**
 * Repair a ZIP's navigation framing: each central-directory record's
 * local-header offset, and the EOCD's directory size / offset / entry counts.
 * Entry payloads, filenames, methods, CRCs and declared sizes are untouched.
 */
function repair(base: Uint8Array, params: Record<string, unknown> | undefined): ConstructResult {
  const parsed = withParams(() => {
    const p = new ParamReader(params);
    const fixOffsets = p.bool("fixOffsets", true);
    const fixEocd = p.bool("fixEocd", true);
    p.rejectUnknown("Repair mode (with `base`) accepts only `fixOffsets` and `fixEocd`.");
    return { fixOffsets, fixEocd };
  });
  if (!parsed.ok) return { ok: false, error: `zip construct: ${parsed.error}` };
  const { fixOffsets, fixEocd } = parsed.value;

  const eocd = findEocd(base);
  if (!eocd) {
    return {
      ok: false,
      error:
        "zip construct: no end-of-central-directory record (PK\\x05\\x06) found in the last 64 KiB. A ZIP parser " +
        "starts here, so without it nothing is enumerable. Build the archive with `entries` instead of repairing.",
    };
  }

  const locals = scanLocalHeaders(base);
  if (locals.length === 0) {
    return {
      ok: false,
      error:
        "zip construct: no local file headers (PK\\x03\\x04) found, so there is nothing for the central directory to " +
        "point at. Build the archive with `entries` instead of repairing.",
    };
  }

  // The directory is normally located BY the EOCD — which is exactly the field
  // that may be wrong — so we have to find it independently, the way a recovery
  // tool does. Scanning for the first `PK\x01\x02` is not enough on its own:
  // that byte sequence can occur inside stored entry data. We therefore prefer
  // a candidate whose record walk ends exactly at the EOCD, which is true of
  // every well-formed archive and vanishingly unlikely for a coincidental
  // signature, and only fall back to first-signature when no candidate fits.
  const candidates: number[] = [];
  for (let at = 0; at + CDH_FIXED <= eocd.offset; at++) {
    if (startsWith(base.subarray(at), CDH_SIG)) candidates.push(at);
  }
  let cdStart = -1;
  for (const at of candidates) {
    const walked = walkCentralDirectory(base, at, eocd.offset);
    if (walked.length > 0 && at + walked.reduce((n, r) => n + r.totalSize, 0) === eocd.offset) {
      cdStart = at;
      break;
    }
  }
  if (cdStart < 0 && candidates.length > 0) cdStart = candidates[0]!;
  if (cdStart < 0) {
    return {
      ok: false,
      error:
        "zip construct: no central-directory record (PK\\x01\\x02) found before the EOCD. The archive has local " +
        "entries but no directory; build it with `entries` so the directory is generated.",
    };
  }

  const records = walkCentralDirectory(base, cdStart, eocd.offset);
  if (records.length === 0) {
    return {
      ok: false,
      error: `zip construct: found a PK\\x01\\x02 signature at ${cdStart} but could not walk a complete record from it.`,
    };
  }

  const out = new Uint8Array(base);
  const repairs: RepairRecord[] = [];
  const notes: string[] = [];

  if (fixOffsets) {
    // Match directory records to local headers by filename. Name matching (not
    // ordinal) because a repair is usually needed precisely when entries have
    // shifted; ordinal matching would confidently produce a valid-looking
    // archive whose entries point at each other's data.
    const byName = new Map<string, LocalHeader>();
    for (const l of locals) if (!byName.has(l.name)) byName.set(l.name, l);
    for (const r of records) {
      if (r.localHeaderOffset === ZIP64_MARKER) {
        notes.push(
          `entry '${r.name}': local-header offset is the ZIP64 sentinel 0xffffffff; this plugin does not parse ZIP64 extra fields, so the offset was left alone.`,
        );
        continue;
      }
      const local = byName.get(r.name);
      if (!local) {
        notes.push(
          `entry '${r.name}': no local file header with that name — offset left alone (repairing it would require guessing which entry you meant).`,
        );
        continue;
      }
      if (local.offset !== r.localHeaderOffset) {
        out.set(u32le(local.offset), r.localHeaderOffsetField);
        repairs.push({
          offset: r.localHeaderOffsetField,
          field: `centralDirectory['${r.name}'].localHeaderOffset`,
          from: String(r.localHeaderOffset),
          to: String(local.offset),
          why:
            "absolute file offset of this entry's PK\\x03\\x04 header. It is pure navigation: a parser that follows a " +
            "stale offset finds no signature and skips or rejects the entry, so the extraction code never runs.",
        });
      }
    }
  }

  if (fixEocd) {
    const cdSize = records.reduce((n, r) => n + r.totalSize, 0);
    if (eocd.cdOffset !== cdStart) {
      out.set(u32le(cdStart), eocd.offset + 16);
      repairs.push({
        offset: eocd.offset + 16,
        field: "eocd.centralDirectoryOffset",
        from: String(eocd.cdOffset),
        to: String(cdStart),
        why: "the parser's entry point — a wrong value means it reads garbage instead of the directory and enumerates nothing.",
      });
    }
    if (eocd.cdSize !== cdSize) {
      out.set(u32le(cdSize), eocd.offset + 12);
      repairs.push({
        offset: eocd.offset + 12,
        field: "eocd.centralDirectorySize",
        from: String(eocd.cdSize),
        to: String(cdSize),
        why: "byte span of the directory records actually present; bounds the parser's walk.",
      });
    }
    if (eocd.totalEntries !== records.length) {
      out.set(u16le(records.length), eocd.offset + 10);
      repairs.push({
        offset: eocd.offset + 10,
        field: "eocd.totalEntries",
        from: String(eocd.totalEntries),
        to: String(records.length),
        why: "count of directory records actually present; a parser that trusts a larger count reads past the directory.",
      });
    }
    if (eocd.entriesThisDisk !== records.length) {
      out.set(u16le(records.length), eocd.offset + 8);
      repairs.push({
        offset: eocd.offset + 8,
        field: "eocd.entriesThisDisk",
        from: String(eocd.entriesThisDisk),
        to: String(records.length),
        why: "single-disk archive, so this must equal the total entry count.",
      });
    }
  }

  if (repairs.length === 0) notes.push("navigation framing was already consistent; bytes returned unchanged.");
  return { ok: true, bytes: out, repairs, notes };
}

function validateZip(bytes: Uint8Array): ValidationReport {
  const defects: ValidationDefect[] = [];
  const structure: string[] = [];

  const eocd = findEocd(bytes);
  if (!eocd) {
    defects.push({
      severity: "fatal",
      field: "eocd",
      message:
        "no PK\\x05\\x06 end-of-central-directory record in the last 64 KiB. A ZIP parser reads backwards from here, " +
        "so with no EOCD it enumerates nothing and the extraction code is unreachable.",
      repairable: false,
    });
    return { wellFormed: false, defects, structure: ["(no EOCD — not a navigable ZIP)"] };
  }
  structure.push(
    `EOCD @${eocd.offset}: entries=${eocd.totalEntries} cdOffset=${eocd.cdOffset} cdSize=${eocd.cdSize} commentLen=${eocd.commentLength}`,
  );

  if (eocd.offset + EOCD_FIXED + eocd.commentLength !== bytes.length) {
    defects.push({
      severity: "warning",
      offset: eocd.offset + 20,
      field: "eocd.commentLength",
      message:
        `declares ${eocd.commentLength} comment bytes but ${bytes.length - eocd.offset - EOCD_FIXED} follow the record. ` +
        "Most parsers tolerate this; some reject the archive outright.",
      repairable: true,
    });
  }

  if (eocd.cdOffset === ZIP64_MARKER || eocd.cdSize === ZIP64_MARKER || eocd.totalEntries === 0xffff) {
    defects.push({
      severity: "warning",
      offset: eocd.offset,
      field: "eocd",
      message:
        "a field holds the ZIP64 sentinel (0xffffffff / 0xffff); the real value lives in a ZIP64 record this plugin does not parse. " +
        "Structure below may be incomplete — validate manually.",
      repairable: false,
    });
  }

  if (eocd.cdOffset + eocd.cdSize > bytes.length) {
    defects.push({
      severity: "fatal",
      offset: eocd.offset + 16,
      field: "eocd.centralDirectoryOffset",
      message: `directory at ${eocd.cdOffset} + ${eocd.cdSize} bytes runs past the end of the ${bytes.length}-byte file`,
      repairable: true,
    });
    return { wellFormed: false, defects, structure };
  }

  // A hand-built archive that got bytes prepended (a python generator writing a
  // header before the zip, an SFX stub) has every stored offset short by a
  // constant. Real parsers split on this: python's `zipfile`
  // (`_handle_prepended_data`) and minizip both INFER the prefix as
  // `eocdOffset - cdSize - cdOffset` and compensate, while stricter readers do
  // not. So a uniform shift is a WARNING — the archive is very likely still
  // reachable — and only an offset that is wrong even after compensating is
  // fatal. Getting this backwards in either direction is costly: calling it
  // fatal sends the agent chasing a non-problem, calling everything fine sends
  // it to a graded submit with an unreadable archive.
  let delta = 0;
  if (!startsWith(bytes.subarray(eocd.cdOffset), CDH_SIG)) {
    const inferred = eocd.offset - eocd.cdSize - eocd.cdOffset;
    const adjusted = eocd.cdOffset + inferred;
    if (inferred !== 0 && adjusted >= 0 && adjusted + CDH_FIXED <= bytes.length && startsWith(bytes.subarray(adjusted), CDH_SIG)) {
      delta = inferred;
      defects.push({
        severity: "warning",
        offset: eocd.offset + 16,
        field: "eocd.centralDirectoryOffset",
        message:
          `every stored offset is short by ${inferred} byte(s) — the archive has ${inferred} byte(s) of prepended data. ` +
          "SFX-aware parsers (python zipfile, minizip, info-zip) infer this prefix and compensate; stricter readers do not. " +
          "Run prover_construct with baseHex to rewrite the offsets absolutely and remove the ambiguity.",
        repairable: true,
      });
    } else {
      defects.push({
        severity: "fatal",
        offset: eocd.cdOffset,
        field: "eocd.centralDirectoryOffset",
        message:
          `offset ${eocd.cdOffset} does not begin with PK\\x01\\x02 (found ${toHex(bytes.subarray(eocd.cdOffset, eocd.cdOffset + 4))}), ` +
          "and it is not explained by a uniform prepended-data prefix either. The parser follows this offset first, so " +
          "nothing downstream is reachable.",
        repairable: true,
      });
      return { wellFormed: false, defects, structure };
    }
  }

  const records = walkCentralDirectory(bytes, eocd.cdOffset + delta, eocd.offset);
  if (records.length !== eocd.totalEntries) {
    defects.push({
      severity: "fatal",
      offset: eocd.offset + 10,
      field: "eocd.totalEntries",
      message: `EOCD declares ${eocd.totalEntries} entries but ${records.length} complete directory record(s) are present`,
      repairable: true,
    });
  }

  for (const r of records) {
    structure.push(
      `CDH @${r.offset} '${r.name}' method=${r.method} crc=0x${r.crc.toString(16).padStart(8, "0")} ` +
        `csize=${r.compressedSize} usize=${r.uncompressedSize} → local @${r.localHeaderOffset}`,
    );
    const local = readLocalHeader(bytes, r.localHeaderOffset + delta);
    if (!local) {
      defects.push({
        severity: "fatal",
        offset: r.localHeaderOffsetField,
        field: `centralDirectory['${r.name}'].localHeaderOffset`,
        message:
          `points at ${r.localHeaderOffset}${delta !== 0 ? ` (${r.localHeaderOffset + delta} after the ${delta}-byte prefix)` : ""}, ` +
          "where there is no PK\\x03\\x04 signature. The entry cannot be opened, so its payload never reaches the decompressor.",
        repairable: true,
      });
      continue;
    }
    if (local.name !== r.name) {
      defects.push({
        severity: "warning",
        offset: local.offset + LFH_FIXED,
        field: "localHeader.name",
        message: `local header names '${local.name}' but the directory record names '${r.name}' — parsers disagree on which wins`,
        repairable: false,
      });
    }
    if (r.method !== 0 && r.method !== 8) {
      defects.push({
        severity: "warning",
        offset: r.offset + 10,
        field: `centralDirectory['${r.name}'].method`,
        message: `compression method ${r.method} is neither stored (0) nor deflate (8); most parsers refuse to extract but still enumerate`,
        repairable: false,
      });
    }
    // Only a STORED entry lets us check the CRC and sizes without a decompressor.
    // A mismatch is reported as a warning on purpose: it is detected at extraction,
    // after enumeration has already succeeded, and it is frequently the PoC's point.
    if (r.method === 0 && (local.flags & 0x08) === 0) {
      const dataEnd = local.dataOffset + r.compressedSize;
      if (dataEnd > bytes.length) {
        defects.push({
          severity: "fatal",
          offset: r.offset + 20,
          field: `centralDirectory['${r.name}'].compressedSize`,
          message: `entry data would span ${local.dataOffset}..${dataEnd} in a ${bytes.length}-byte file`,
          repairable: false,
        });
      } else {
        const data = bytes.subarray(local.dataOffset, dataEnd);
        const actual = crc32(data);
        if (actual !== r.crc) {
          defects.push({
            severity: "warning",
            offset: r.offset + 16,
            field: `centralDirectory['${r.name}'].crc32`,
            message:
              `declares 0x${r.crc.toString(16).padStart(8, "0")}, payload computes 0x${actual.toString(16).padStart(8, "0")}. ` +
              "Checked at extraction, not enumeration — deliberate if you are proving a CRC-handling bug.",
            repairable: false,
          });
        }
        if (r.uncompressedSize !== r.compressedSize) {
          defects.push({
            severity: "warning",
            offset: r.offset + 24,
            field: `centralDirectory['${r.name}'].uncompressedSize`,
            message:
              `stored entry declares compressed=${r.compressedSize} but uncompressed=${r.uncompressedSize}; for method 0 they must be equal. ` +
              "This inconsistency is a classic ZIP bug lever, so it is not treated as an error.",
            repairable: false,
          });
        }
      }
    }
  }

  return { wellFormed: !defects.some((d) => d.severity === "fatal"), defects, structure };
}

export const zipProverPlugin: ProverPlugin = {
  id: "zip",
  title: "ZIP — central-directory offsets, EOCD framing, entry CRC-32",
  aliases: ["zip", "minizip", "libzip", "jar", "apk", "epub", "docx", "unzip", "zipfile", "zlibzip"],
  paramsHelp: PARAMS_HELP,

  matches(ctx: ProverContext): ProverMatch {
    if (ctx.sample) {
      if (startsWith(ctx.sample, LFH_SIG)) return { score: 1, reason: "sample begins with a PK\\x03\\x04 local file header" };
      if (startsWith(ctx.sample, EOCD_SIG)) return { score: 1, reason: "sample begins with a PK\\x05\\x06 EOCD (empty archive)" };
      if (startsWith(ctx.sample, CDH_SIG)) return { score: 0.9, reason: "sample begins with a PK\\x01\\x02 central directory record" };
    }
    const alias = matchAlias(`${ctx.hint ?? ""} ${ctx.harness ?? ""}`, zipProverPlugin.aliases);
    if (alias) return { score: 0.75, reason: `hint mentions '${alias}'` };
    return { score: 0, reason: "no PK signature and no ZIP-ish hint" };
  },

  construct: constructZip,
  validate: validateZip,
};
