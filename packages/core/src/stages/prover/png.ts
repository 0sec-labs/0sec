/**
 * PNG prover plugin — chunk framing, CRC-32, and the IHDR legality rules.
 *
 * ## Why PNG is a good first plugin
 *
 * `stages/format-knowledge.ts` already documents PNG, and its primer ends with
 * the sentence that motivates this whole module: *"Many readers validate CRC —
 * compute it (zlib.crc32 over type+data)."* That instruction is correct and
 * almost useless. The agent has to compute a CRC-32 over the concatenation of
 * the four type bytes and the payload — **not** including the length field,
 * which is the part everyone gets wrong — for every chunk, and get four bytes
 * exactly right each time, inside a python generator it also has to get right.
 * libpng's default `png_set_crc_action` is `PNG_CRC_ERROR_QUIT` for critical
 * chunks, so one wrong CRC ends the parse at the front door and the graded
 * submit is gone.
 *
 * The other PNG-specific front-door rejections this plugin knows about:
 *
 *   - the 8-byte signature `89 50 4E 47 0D 0A 1A 0A`, whose non-ASCII bytes are
 *     a routine transcription casualty;
 *   - IHDR must be the first chunk and exactly 13 bytes;
 *   - the bit-depth / colour-type combination table (libpng rejects e.g. a
 *     4-bit truecolour image immediately — the spec allows only specific pairs);
 *   - colour type 3 (palette) requires a PLTE chunk before IDAT;
 *   - IDAT is a zlib stream, so a payload with a bad Adler-32 fails inflation
 *     and the row-processing code — where most libpng bugs live — is never
 *     entered.
 *
 * ## What this plugin will NOT do
 *
 * It never edits a semantic field. Width, height, bit depth, colour type, the
 * contents of an ancillary chunk, and the declared chunk lengths are the
 * attacker's levers, and repairing them would delete the bug being proved (see
 * the framing/semantics discussion in `types.ts`). Concretely: a chunk whose
 * declared length runs past the end of the buffer is reported as a **fatal,
 * non-repairable** defect rather than being clamped, because clamping it is
 * indistinguishable from removing the vulnerability.
 */

import {
  ascii,
  concat,
  crc32,
  readU32be,
  startsWith,
  toHex,
  u32be,
  zlibStored,
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

const SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;

/**
 * The PNG spec's legal (colour type → bit depth) table. libpng checks this in
 * `png_handle_IHDR` and calls `png_error` on a violation, so an illegal pair is
 * a hard front-door rejection, not a warning.
 */
const LEGAL_BIT_DEPTHS: Readonly<Record<number, readonly number[]>> = Object.freeze({
  0: [1, 2, 4, 8, 16], // greyscale
  2: [8, 16], // truecolour
  3: [1, 2, 4, 8], // indexed
  4: [8, 16], // greyscale + alpha
  6: [8, 16], // truecolour + alpha
});

/** Samples per pixel for each colour type — drives the scanline size. */
const CHANNELS: Readonly<Record<number, number>> = Object.freeze({ 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 });

/** Cap on synthesised image data, so a 65535×65535 request errors instead of hanging. */
const MAX_SYNTH_RAW = 8 * 1024 * 1024;

interface PngChunk {
  /** Offset of the 4-byte length field. */
  offset: number;
  /** Declared length (NOT necessarily the bytes actually present). */
  declaredLength: number;
  type: string;
  /** Payload as present in the buffer; shorter than `declaredLength` if truncated. */
  data: Uint8Array;
  /** CRC as stored, or `undefined` when the buffer ends first. */
  storedCrc?: number;
  /** CRC recomputed over type+data. */
  actualCrc: number;
  /** The declared length runs past the end of the buffer. */
  overruns: boolean;
}

/** A chunk is critical iff bit 5 of its first type byte is clear (uppercase). */
function isCritical(type: string): boolean {
  return (type.charCodeAt(0) & 0x20) === 0;
}

/** Chunk types are four ASCII letters; anything else means the walk has desynced. */
function isValidTypeName(type: string): boolean {
  return /^[A-Za-z]{4}$/.test(type);
}

/**
 * Walk the chunk stream from `start`. Stops at the first structural desync
 * rather than trying to resynchronise: a desynced walk produces confident
 * nonsense, and the agent is better served by "the walk stopped at offset N"
 * than by an invented chunk list.
 */
function walkChunks(buf: Uint8Array, start: number): { chunks: PngChunk[]; stoppedAt?: number } {
  const chunks: PngChunk[] = [];
  let at = start;
  while (at < buf.length) {
    const declaredLength = readU32be(buf, at);
    if (declaredLength === undefined) return { chunks, stoppedAt: at };
    if (at + 8 > buf.length) return { chunks, stoppedAt: at };
    const typeBytes = buf.subarray(at + 4, at + 8);
    const type = String.fromCharCode(...typeBytes);
    const dataStart = at + 8;
    const dataEnd = dataStart + declaredLength;
    const overruns = dataEnd + 4 > buf.length;
    const data = buf.subarray(dataStart, Math.min(dataEnd, buf.length));
    const storedCrc = overruns ? undefined : readU32be(buf, dataEnd);
    chunks.push({
      offset: at,
      declaredLength,
      type,
      data,
      ...(storedCrc !== undefined ? { storedCrc } : {}),
      actualCrc: crc32(concat([typeBytes, data])),
      overruns,
    });
    if (overruns) return { chunks, stoppedAt: dataStart };
    at = dataEnd + 4;
    if (!isValidTypeName(type)) return { chunks, stoppedAt: at };
  }
  return { chunks };
}

/** Serialise one chunk with a correct length and CRC. */
function emitChunk(type: string, data: Uint8Array): Uint8Array {
  const typeBytes = ascii(type);
  return concat([u32be(data.length), typeBytes, data, u32be(crc32(concat([typeBytes, data])))]);
}

const PARAMS_HELP =
  "PNG params: width, height (ints, default 1), bitDepth (default 8), colorType (0|2|3|4|6, default 0), " +
  "compressionMethod, filterMethod, interlace (default 0), ihdrDataHex (verbatim 13-byte IHDR payload — " +
  "overrides the field knobs, use it to plant a deliberately illegal header), idatRawHex (raw pre-filter " +
  "scanline bytes; the plugin zlib-wraps them), idatZlibHex (verbatim IDAT payload, no wrapping — for zlib-level " +
  "bugs), chunks (array of {type, dataHex} inserted between IHDR and IDAT — this is where your malformed " +
  "ancillary chunk goes), iend (default true), fixCrc (repair mode only, default true).";

function constructPng(req: ConstructRequest): ConstructResult {
  return req.base ? repair(req.base, req.params) : build(req.params);
}

/** Build a minimal, genuinely decodable PNG parameterised by `params`. */
function build(params: Record<string, unknown> | undefined): ConstructResult {
  const parsed = withParams(() => {
    const p = new ParamReader(params);
    const width = p.int("width", 1, 0, 0x7fffffff);
    const height = p.int("height", 1, 0, 0x7fffffff);
    const bitDepth = p.int("bitDepth", 8, 0, 255);
    const colorType = p.int("colorType", 0, 0, 255);
    const compressionMethod = p.int("compressionMethod", 0, 0, 255);
    const filterMethod = p.int("filterMethod", 0, 0, 255);
    const interlace = p.int("interlace", 0, 0, 255);
    const ihdrDataHex = p.hex("ihdrDataHex", new Uint8Array(0));
    const hasIhdrOverride = ihdrDataHex.length > 0;
    const idatRawHex = p.hex("idatRawHex", new Uint8Array(0));
    const hasRaw = idatRawHex.length > 0;
    const idatZlibHex = p.hex("idatZlibHex", new Uint8Array(0));
    const hasZlib = idatZlibHex.length > 0;
    const extra = p.objects("chunks").map((c, i) => {
      const cp = new ParamReader(c);
      const type = cp.str("type", "");
      const dataHex = cp.hex("dataHex", new Uint8Array(0));
      cp.rejectUnknown(`chunks[${i}] accepts only \`type\` and \`dataHex\`.`);
      if (!isValidTypeName(type)) {
        throw new ParamError(`chunks[${i}].type must be four ASCII letters (got ${JSON.stringify(type)})`);
      }
      return { type, data: dataHex };
    });
    const iend = p.bool("iend", true);
    p.rejectUnknown(PARAMS_HELP);
    return {
      width, height, bitDepth, colorType, compressionMethod, filterMethod, interlace,
      ihdrDataHex, hasIhdrOverride, idatRawHex, hasRaw, idatZlibHex, hasZlib, extra, iend,
    };
  });
  if (!parsed.ok) return { ok: false, error: `png construct: ${parsed.error}. ${PARAMS_HELP}` };
  const v = parsed.value;

  const notes: string[] = [];
  if (v.hasRaw && v.hasZlib) {
    return {
      ok: false,
      error:
        "png construct: pass `idatRawHex` OR `idatZlibHex`, not both — the first is zlib-wrapped for you, the second is copied verbatim.",
    };
  }

  // ── IHDR ──
  // The override path exists so a PoC can plant an illegal header (a zero
  // width, a bogus colour type, a short payload) and still get correct framing
  // around it. That is precisely the framing/semantics split: we compute the
  // length and CRC, we do not second-guess the 13 bytes.
  let ihdrData: Uint8Array;
  if (v.hasIhdrOverride) {
    ihdrData = v.ihdrDataHex;
    notes.push(
      `IHDR payload taken verbatim from ihdrDataHex (${ihdrData.length} bytes) — field knobs ignored, length + CRC still computed.`,
    );
  } else {
    ihdrData = concat([
      u32be(v.width),
      u32be(v.height),
      Uint8Array.from([v.bitDepth, v.colorType, v.compressionMethod, v.filterMethod, v.interlace]),
    ]);
  }

  // ── chunks between IHDR and IDAT ──
  const between = [...v.extra];
  if (!v.hasIhdrOverride && v.colorType === 3 && !between.some((c) => c.type === "PLTE")) {
    // Colour type 3 without PLTE is a libpng hard error before any row data is
    // touched, so a caller who asked for an indexed image without supplying a
    // palette gets one rather than an unusable file. Recorded as a note because
    // it is a structural addition the caller did not ask for.
    between.unshift({ type: "PLTE", data: Uint8Array.from([0, 0, 0]) });
    notes.push("added a 1-entry PLTE — colour type 3 requires a palette before IDAT or libpng errors out.");
  }

  // ── IDAT ──
  let idatPayload: Uint8Array;
  if (v.hasZlib) {
    idatPayload = v.idatZlibHex;
    notes.push(`IDAT payload copied verbatim from idatZlibHex (${idatPayload.length} bytes) — no zlib wrapping applied.`);
  } else if (v.hasRaw) {
    idatPayload = zlibStored(v.idatRawHex);
    notes.push(`wrapped ${v.idatRawHex.length} raw bytes in a zlib stored-block stream (Adler-32 computed).`);
  } else if (v.hasIhdrOverride) {
    idatPayload = zlibStored(new Uint8Array(0));
    notes.push("IHDR was overridden so scanline geometry is unknown — emitted an empty zlib stream for IDAT.");
  } else {
    const channels = CHANNELS[v.colorType];
    if (channels === undefined) {
      return {
        ok: false,
        error:
          `png construct: colorType ${v.colorType} has no defined channel count, so scanline size cannot be derived. ` +
          "Supply idatRawHex or idatZlibHex, or use ihdrDataHex if an invalid colour type is the point of the PoC.",
      };
    }
    const bitsPerPixel = channels * v.bitDepth;
    const scanline = Math.ceil((v.width * bitsPerPixel) / 8) + 1; // +1 filter byte per row
    const total = scanline * v.height;
    if (total > MAX_SYNTH_RAW) {
      return {
        ok: false,
        error:
          `png construct: ${v.width}x${v.height} at ${v.bitDepth}bpp/${channels}ch needs ${total} bytes of scanline data ` +
          `(cap ${MAX_SYNTH_RAW}). Large declared dimensions with a SMALL IDAT is usually what you want for an overflow PoC — ` +
          "pass idatRawHex explicitly to decouple the declared geometry from the actual data.",
      };
    }
    idatPayload = zlibStored(new Uint8Array(total));
    notes.push(`synthesised ${total} zero bytes of scanline data (${v.height} rows x ${scanline} bytes incl. filter byte).`);
  }

  const parts: Uint8Array[] = [Uint8Array.from(SIGNATURE), emitChunk("IHDR", ihdrData)];
  for (const c of between) parts.push(emitChunk(c.type, c.data));
  parts.push(emitChunk("IDAT", idatPayload));
  if (v.iend) parts.push(emitChunk("IEND", new Uint8Array(0)));

  return { ok: true, bytes: concat(parts), repairs: [], notes };
}

/** Repair the framing of an existing PNG, leaving every semantic field alone. */
function repair(base: Uint8Array, params: Record<string, unknown> | undefined): ConstructResult {
  const parsed = withParams(() => {
    const p = new ParamReader(params);
    const fixCrc = p.bool("fixCrc", true);
    const iend = p.bool("iend", true);
    p.rejectUnknown("Repair mode (with `base`) accepts only `fixCrc` and `iend`.");
    return { fixCrc, iend };
  });
  if (!parsed.ok) return { ok: false, error: `png construct: ${parsed.error}` };
  const { fixCrc, iend } = parsed.value;

  const repairs: RepairRecord[] = [];
  const notes: string[] = [];

  let body = base;
  if (startsWith(base, SIGNATURE)) {
    body = base.subarray(SIGNATURE.length);
  } else {
    // Either the signature is corrupt or the caller handed us a bare chunk
    // stream. Both are fixed by prepending the canonical eight bytes; we only
    // drop leading bytes when they are a damaged 8-byte signature (first byte
    // 0x89 or the ASCII "PNG" tail present) rather than guessing.
    const looksLikeDamagedSig =
      base.length >= 8 && (base[0] === 0x89 || String.fromCharCode(base[1] ?? 0, base[2] ?? 0, base[3] ?? 0) === "PNG");
    if (looksLikeDamagedSig) {
      repairs.push({
        offset: 0,
        field: "signature",
        from: toHex(base.subarray(0, 8)),
        to: toHex(Uint8Array.from(SIGNATURE)),
        why: "the 8-byte PNG signature is a fixed constant; no parser reads past a wrong one, and it carries no attacker-controlled information.",
      });
      body = base.subarray(8);
    } else {
      repairs.push({
        offset: 0,
        field: "signature",
        from: "(absent)",
        to: toHex(Uint8Array.from(SIGNATURE)),
        why: "input began at the chunk stream; prepended the fixed 8-byte signature.",
      });
    }
  }

  const { chunks, stoppedAt } = walkChunks(body, 0);
  const overrunning = chunks.find((c) => c.overruns);
  if (overrunning) {
    return {
      ok: false,
      error:
        `png construct: chunk '${overrunning.type}' at offset ${overrunning.offset + SIGNATURE.length} declares ` +
        `${overrunning.declaredLength} bytes but only ${overrunning.data.length} are present. This is NOT repairable: ` +
        "shrinking the declared length would silently delete the very condition an over-long length is usually planted to " +
        "exercise. Either append the missing payload bytes, or rebuild the file with `chunks` so the length is derived.",
    };
  }
  if (stoppedAt !== undefined && chunks.length > 0 && !isValidTypeName(chunks[chunks.length - 1]!.type)) {
    return {
      ok: false,
      error:
        `png construct: chunk walk desynced at offset ${stoppedAt + SIGNATURE.length} — type ` +
        `${JSON.stringify(chunks[chunks.length - 1]!.type)} is not four ASCII letters. A preceding length field is wrong; ` +
        "rebuild rather than repair, since resynchronising would require guessing which length to change.",
    };
  }

  const parts: Uint8Array[] = [Uint8Array.from(SIGNATURE)];
  for (const c of chunks) {
    const absolute = c.offset + SIGNATURE.length;
    let crc = c.storedCrc ?? c.actualCrc;
    if (c.storedCrc === undefined) {
      repairs.push({
        offset: absolute + 8 + c.declaredLength,
        field: `${c.type}.crc`,
        from: "(truncated)",
        to: "0x" + c.actualCrc.toString(16).padStart(8, "0"),
        why: "the trailing CRC-32 was missing; it is derived entirely from the type + payload already present.",
      });
      crc = c.actualCrc;
    } else if (fixCrc && c.storedCrc !== c.actualCrc) {
      repairs.push({
        offset: absolute + 8 + c.declaredLength,
        field: `${c.type}.crc`,
        from: "0x" + c.storedCrc.toString(16).padStart(8, "0"),
        to: "0x" + c.actualCrc.toString(16).padStart(8, "0"),
        why:
          "CRC-32 over the 4 type bytes + payload (NOT the length field). libpng's default crc_action quits on a " +
          `${isCritical(c.type) ? "critical" : "ancillary"} chunk mismatch, so a wrong CRC ends the parse before the bug.`,
      });
      crc = c.actualCrc;
    }
    parts.push(u32be(c.declaredLength), ascii(c.type), c.data, u32be(crc));
  }

  if (iend && !chunks.some((c) => c.type === "IEND")) {
    parts.push(emitChunk("IEND", new Uint8Array(0)));
    repairs.push({
      offset: -1,
      field: "IEND",
      from: "(absent)",
      to: "0000000049454e44ae426082",
      why: "IEND is a fixed, empty terminator chunk; appending it cannot change any attacker-controlled value.",
    });
  }
  if (!fixCrc) notes.push("fixCrc=false — stored CRCs left as-is (use this when the CRC mismatch IS the bug).");

  return { ok: true, bytes: concat(parts), repairs, notes };
}

function validatePng(bytes: Uint8Array): ValidationReport {
  const defects: ValidationDefect[] = [];
  const structure: string[] = [];

  if (!startsWith(bytes, SIGNATURE)) {
    defects.push({
      severity: "fatal",
      offset: 0,
      field: "signature",
      message: `expected 89504e470d0a1a0a, got ${toHex(bytes.subarray(0, Math.min(8, bytes.length)))}`,
      repairable: true,
    });
    return { wellFormed: false, defects, structure: ["(not a PNG stream)"] };
  }

  const { chunks, stoppedAt } = walkChunks(bytes, SIGNATURE.length);
  if (chunks.length === 0) {
    defects.push({
      severity: "fatal",
      offset: SIGNATURE.length,
      field: "chunks",
      message: "signature present but no chunk follows",
      repairable: false,
    });
    return { wellFormed: false, defects, structure: ["(signature only)"] };
  }

  for (const c of chunks) {
    structure.push(
      `@${c.offset} ${isValidTypeName(c.type) ? c.type : JSON.stringify(c.type)} len=${c.declaredLength}` +
        (c.overruns ? ` OVERRUNS (${c.data.length} present)` : "") +
        (c.storedCrc !== undefined && c.storedCrc !== c.actualCrc
          ? ` crc=0x${c.storedCrc.toString(16).padStart(8, "0")} (want 0x${c.actualCrc.toString(16).padStart(8, "0")})`
          : ""),
    );

    if (!isValidTypeName(c.type)) {
      defects.push({
        severity: "fatal",
        offset: c.offset + 4,
        field: "chunk.type",
        message: `chunk type ${JSON.stringify(c.type)} is not four ASCII letters — the chunk walk has desynced, which means a preceding length field is wrong`,
        repairable: false,
      });
      continue;
    }
    if (c.overruns) {
      defects.push({
        severity: "fatal",
        offset: c.offset,
        field: `${c.type}.length`,
        message: `declares ${c.declaredLength} bytes but only ${c.data.length} are present (plus no room for the CRC) — the parser reads past the end of the file and bails`,
        repairable: false,
      });
      continue;
    }
    if (c.storedCrc !== undefined && c.storedCrc !== c.actualCrc) {
      // libpng: critical-chunk CRC failure is PNG_CRC_ERROR_QUIT by default and
      // ends the parse; ancillary-chunk failure is PNG_CRC_WARN_USE, so the
      // chunk is still processed. That difference is exactly the fatal/warning
      // line this report draws.
      defects.push({
        severity: isCritical(c.type) ? "fatal" : "warning",
        offset: c.offset + 8 + c.declaredLength,
        field: `${c.type}.crc`,
        message:
          `stored 0x${c.storedCrc.toString(16).padStart(8, "0")}, computed 0x${c.actualCrc.toString(16).padStart(8, "0")} ` +
          `(CRC-32 over the type bytes + payload, excluding the length). ` +
          (isCritical(c.type)
            ? "Critical chunk: libpng quits here."
            : "Ancillary chunk: libpng warns and still uses it, so this may be harmless."),
        repairable: true,
      });
    }
  }

  if (stoppedAt !== undefined && !chunks.some((c) => c.overruns) && chunks.every((c) => isValidTypeName(c.type))) {
    defects.push({
      severity: "warning",
      offset: stoppedAt,
      field: "chunks",
      message: `${bytes.length - stoppedAt - SIGNATURE.length} trailing byte(s) after the last complete chunk`,
      repairable: false,
    });
  }

  const first = chunks[0]!;
  if (first.type !== "IHDR") {
    defects.push({
      severity: "fatal",
      offset: first.offset,
      field: "IHDR",
      message: `first chunk is '${first.type}'; PNG requires IHDR first and libpng errors immediately otherwise`,
      repairable: false,
    });
  } else if (first.declaredLength !== 13) {
    defects.push({
      severity: "fatal",
      offset: first.offset,
      field: "IHDR.length",
      message: `IHDR is ${first.declaredLength} bytes; the spec fixes it at 13 and libpng errors on any other size`,
      repairable: false,
    });
  } else {
    const width = readU32be(first.data, 0) ?? 0;
    const height = readU32be(first.data, 4) ?? 0;
    const bitDepth = first.data[8]!;
    const colorType = first.data[9]!;
    const interlace = first.data[12]!;
    structure.push(
      `IHDR: ${width}x${height} bitDepth=${bitDepth} colorType=${colorType} interlace=${interlace}`,
    );
    const legal = LEGAL_BIT_DEPTHS[colorType];
    if (!legal) {
      defects.push({
        severity: "fatal",
        offset: first.offset + 8 + 9,
        field: "IHDR.colorType",
        message: `colour type ${colorType} is not one of 0, 2, 3, 4, 6 — libpng errors in png_handle_IHDR before any chunk after IHDR is seen`,
        repairable: false,
      });
    } else if (!legal.includes(bitDepth)) {
      defects.push({
        severity: "fatal",
        offset: first.offset + 8 + 8,
        field: "IHDR.bitDepth",
        message: `bit depth ${bitDepth} is illegal for colour type ${colorType} (legal: ${legal.join(", ")}) — libpng errors in png_handle_IHDR`,
        repairable: false,
      });
    }
    if (colorType === 3 && !chunks.some((c) => c.type === "PLTE")) {
      defects.push({
        severity: "fatal",
        field: "PLTE",
        message: "colour type 3 (indexed) requires a PLTE chunk before IDAT; libpng errors with 'Missing PLTE before IDAT'",
        repairable: false,
      });
    }
    if (width === 0 || height === 0) {
      defects.push({
        severity: "fatal",
        offset: first.offset + 8,
        field: "IHDR.dimensions",
        message: `zero ${width === 0 ? "width" : "height"}; libpng rejects it in png_check_IHDR before decoding`,
        repairable: false,
      });
    }
  }

  const idatIndices = chunks.map((c, i) => (c.type === "IDAT" ? i : -1)).filter((i) => i >= 0);
  if (idatIndices.length === 0) {
    defects.push({
      severity: "warning",
      field: "IDAT",
      message: "no IDAT chunk — fine if the bug is in header/ancillary-chunk handling, fatal if it is in row decoding",
      repairable: false,
    });
  } else if (idatIndices[idatIndices.length - 1]! - idatIndices[0]! !== idatIndices.length - 1) {
    defects.push({
      severity: "warning",
      field: "IDAT",
      message: "IDAT chunks are not consecutive; libpng rejects a second IDAT run with 'Too many IDATs found'",
      repairable: false,
    });
  }
  if (!chunks.some((c) => c.type === "IEND")) {
    defects.push({
      severity: "warning",
      field: "IEND",
      message: "no IEND terminator — most bugs fire before it, but a decoder that reads to completion will report a truncated file",
      repairable: true,
    });
  }

  return { wellFormed: !defects.some((d) => d.severity === "fatal"), defects, structure };
}

export const pngProverPlugin: ProverPlugin = {
  id: "png",
  title: "PNG — chunk framing, CRC-32, IHDR legality, zlib IDAT",
  aliases: ["png", "libpng", "apng", "pngfuzz"],
  paramsHelp: PARAMS_HELP,

  matches(ctx: ProverContext): ProverMatch {
    if (ctx.sample && startsWith(ctx.sample, SIGNATURE)) {
      return { score: 1, reason: "sample begins with the 8-byte PNG signature" };
    }
    const alias = matchAlias(`${ctx.hint ?? ""} ${ctx.harness ?? ""}`, pngProverPlugin.aliases);
    if (alias) return { score: 0.75, reason: `hint mentions '${alias}'` };
    return { score: 0, reason: "no PNG signature and no PNG-ish hint" };
  },

  construct: constructPng,
  validate: validatePng,
};
