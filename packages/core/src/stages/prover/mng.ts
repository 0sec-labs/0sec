/**
 * MNG/JNG prover plugin — chunk framing and CRCs for the GraphicsMagick-style
 * MNG parser family.
 *
 * MNG uses the PNG chunk envelope: an eight-byte signature followed by
 * `[u32be length][four-byte type][payload][u32be CRC(type || payload)]`.
 * That envelope is enough to reach the animation chunks where the CyberGym
 * GraphicsMagick task lives. The plugin intentionally leaves chunk payloads
 * verbatim: a short LOOP payload can be the vulnerability condition, so it is
 * never "repaired" into a different semantic input.
 */

import {
  ascii,
  concat,
  crc32,
  readU32be,
  startsWith,
  toHex,
  u32be,
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

const SIGNATURE = [0x8a, 0x4d, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] as const;
const MHDR_BYTES = 28;
const MAX_CHUNKS = 512;

interface MngChunk {
  offset: number;
  declaredLength: number;
  type: string;
  typeBytes: Uint8Array;
  data: Uint8Array;
  storedCrc?: number;
  actualCrc: number;
  overruns: boolean;
}

function isValidTypeName(type: string): boolean {
  return /^[A-Za-z]{4}$/.test(type);
}

function walkChunks(bytes: Uint8Array, start = SIGNATURE.length): {
  chunks: MngChunk[];
  stoppedAt?: number;
} {
  const chunks: MngChunk[] = [];
  let at = start;
  while (at < bytes.length) {
    if (chunks.length >= MAX_CHUNKS) return { chunks, stoppedAt: at };
    const declaredLength = readU32be(bytes, at);
    if (declaredLength === undefined || at + 8 > bytes.length) return { chunks, stoppedAt: at };
    const typeBytes = bytes.subarray(at + 4, at + 8);
    const type = String.fromCharCode(...typeBytes);
    const dataStart = at + 8;
    const dataEnd = dataStart + declaredLength;
    const overruns = dataEnd + 4 > bytes.length;
    const data = bytes.subarray(dataStart, Math.min(dataEnd, bytes.length));
    const storedCrc = overruns ? undefined : readU32be(bytes, dataEnd);
    chunks.push({
      offset: at,
      declaredLength,
      type,
      typeBytes,
      data,
      ...(storedCrc === undefined ? {} : { storedCrc }),
      actualCrc: crc32(concat([typeBytes, data])),
      overruns,
    });
    if (overruns || !isValidTypeName(type)) return { chunks, stoppedAt: dataStart };
    at = dataEnd + 4;
  }
  return { chunks };
}

function emitChunk(type: string, data: Uint8Array): Uint8Array {
  const typeBytes = ascii(type);
  return concat([u32be(data.length), typeBytes, data, u32be(crc32(concat([typeBytes, data])))]);
}

const PARAMS_HELP =
  "MNG params: width, height, ticksPerSecond (default 1), nominalLayerCount, nominalFrameCount, nominalPlayTime, simplicityProfile (all default 0), mhdrDataHex (verbatim MHDR payload, overrides field knobs), chunks (array of {type, dataHex} after MHDR), mend (default true). Repair mode with base accepts only fixCrc (default true) and appendMend (default false).";

function build(params: Record<string, unknown> | undefined): ConstructResult {
  const parsed = withParams(() => {
    const p = new ParamReader(params);
    const width = p.int("width", 1, 0, 0xffffffff);
    const height = p.int("height", 1, 0, 0xffffffff);
    const ticksPerSecond = p.int("ticksPerSecond", 1, 0, 0xffffffff);
    const nominalLayerCount = p.int("nominalLayerCount", 0, 0, 0xffffffff);
    const nominalFrameCount = p.int("nominalFrameCount", 0, 0, 0xffffffff);
    const nominalPlayTime = p.int("nominalPlayTime", 0, 0, 0xffffffff);
    const simplicityProfile = p.int("simplicityProfile", 0, 0, 0xffffffff);
    const mhdrDataHex = p.hex("mhdrDataHex", new Uint8Array(0));
    const chunks = p.objects("chunks").map((raw, index) => {
      const chunk = new ParamReader(raw);
      const type = chunk.str("type", "");
      const data = chunk.hex("dataHex", new Uint8Array(0));
      chunk.rejectUnknown(`chunks[${index}] accepts only \`type\` and \`dataHex\`.`);
      if (!isValidTypeName(type)) {
        throw new ParamError(`chunks[${index}].type must be four ASCII letters (got ${JSON.stringify(type)})`);
      }
      if (type === "MHDR") throw new ParamError("chunks must not contain MHDR; use mhdrDataHex for its payload");
      return { type, data };
    });
    const mend = p.bool("mend", true);
    p.rejectUnknown(PARAMS_HELP);
    return {
      width,
      height,
      ticksPerSecond,
      nominalLayerCount,
      nominalFrameCount,
      nominalPlayTime,
      simplicityProfile,
      mhdrDataHex,
      chunks,
      mend,
    };
  });
  if (!parsed.ok) return { ok: false, error: `mng construct: ${parsed.error}. ${PARAMS_HELP}` };

  const value = parsed.value;
  const mhdrData = value.mhdrDataHex.length > 0
    ? value.mhdrDataHex
    : concat([
        u32be(value.width),
        u32be(value.height),
        u32be(value.ticksPerSecond),
        u32be(value.nominalLayerCount),
        u32be(value.nominalFrameCount),
        u32be(value.nominalPlayTime),
        u32be(value.simplicityProfile),
      ]);
  const notes = value.mhdrDataHex.length > 0
    ? [`MHDR payload taken verbatim from mhdrDataHex (${mhdrData.length} bytes); enclosing length and CRC were computed.`]
    : ["built canonical 28-byte MHDR with the supplied canvas and timing fields."];
  if (value.mhdrDataHex.length !== 0 && value.mhdrDataHex.length !== MHDR_BYTES) {
    notes.push(
      `MHDR is ${value.mhdrDataHex.length} bytes, not the canonical ${MHDR_BYTES}; kept verbatim because a short MHDR can be an intentional target condition.`,
    );
  }

  const parts: Uint8Array[] = [Uint8Array.from(SIGNATURE), emitChunk("MHDR", mhdrData)];
  for (const chunk of value.chunks) parts.push(emitChunk(chunk.type, chunk.data));
  if (value.mend && !value.chunks.some((chunk) => chunk.type === "MEND")) {
    parts.push(emitChunk("MEND", new Uint8Array(0)));
  }
  return { ok: true, bytes: concat(parts), repairs: [], notes };
}

function repair(base: Uint8Array, params: Record<string, unknown> | undefined): ConstructResult {
  const parsed = withParams(() => {
    const p = new ParamReader(params);
    const fixCrc = p.bool("fixCrc", true);
    const appendMend = p.bool("appendMend", false);
    p.rejectUnknown(PARAMS_HELP);
    return { fixCrc, appendMend };
  });
  if (!parsed.ok) return { ok: false, error: `mng construct: ${parsed.error}` };
  if (!startsWith(base, SIGNATURE)) {
    return {
      ok: false,
      error: "mng construct: repair requires the exact 8-byte MNG signature; refusing to guess where a damaged chunk stream begins.",
    };
  }

  const { chunks, stoppedAt } = walkChunks(base);
  const broken = chunks.find((chunk) => chunk.overruns);
  if (broken) {
    return {
      ok: false,
      error: `mng construct: chunk '${broken.type}' at offset ${broken.offset} declares ${broken.declaredLength} bytes but only ${broken.data.length} are present. Do not shrink its length: that may erase the vulnerability condition.`,
    };
  }
  if (stoppedAt !== undefined || chunks.length === 0) {
    return {
      ok: false,
      error: `mng construct: unable to walk a complete chunk stream${stoppedAt === undefined ? "" : ` (stopped at offset ${stoppedAt})`}.`,
    };
  }

  const repairs: RepairRecord[] = [];
  const parts: Uint8Array[] = [Uint8Array.from(SIGNATURE)];
  for (const chunk of chunks) {
    if (!isValidTypeName(chunk.type)) {
      return { ok: false, error: `mng construct: invalid chunk type at offset ${chunk.offset}` };
    }
    if (parsed.value.fixCrc) {
      if (chunk.storedCrc !== chunk.actualCrc) {
        repairs.push({
          offset: chunk.offset + 8 + chunk.data.length,
          field: `${chunk.type}.crc`,
          from: chunk.storedCrc === undefined ? "(absent)" : chunk.storedCrc.toString(16).padStart(8, "0"),
          to: chunk.actualCrc.toString(16).padStart(8, "0"),
          why: "CRC covers only the fixed framing bytes type || payload; recalculating it preserves the payload verbatim.",
        });
      }
      parts.push(emitChunk(chunk.type, chunk.data));
    } else {
      parts.push(concat([
        u32be(chunk.declaredLength),
        chunk.typeBytes,
        chunk.data,
        u32be(chunk.storedCrc ?? chunk.actualCrc),
      ]));
    }
  }
  if (parsed.value.appendMend && !chunks.some((chunk) => chunk.type === "MEND")) {
    parts.push(emitChunk("MEND", new Uint8Array(0)));
    repairs.push({
      offset: base.length,
      field: "MEND",
      from: "(absent)",
      to: toHex(emitChunk("MEND", new Uint8Array(0))),
      why: "appended the fixed zero-length terminal chunk without changing any existing chunk payload.",
    });
  }
  return { ok: true, bytes: concat(parts), repairs, notes: repairs.length > 0 ? ["repaired MNG framing only; payload bytes were preserved."] : [] };
}

function validate(bytes: Uint8Array): ValidationReport {
  const defects: ValidationDefect[] = [];
  const structure: string[] = [];
  if (!startsWith(bytes, SIGNATURE)) {
    defects.push({
      severity: "fatal",
      offset: 0,
      field: "signature",
      message: "missing the exact 8-byte MNG signature 8a4d4e470d0a1a0a; a reader will reject before any chunk is parsed.",
      repairable: false,
    });
    return { wellFormed: false, defects, structure };
  }
  structure.push("signature: MNG");
  const { chunks, stoppedAt } = walkChunks(bytes);
  for (const chunk of chunks) {
    structure.push(`chunk @${chunk.offset}: ${chunk.type} declared=${chunk.declaredLength} payload=${chunk.data.length}`);
    if (!isValidTypeName(chunk.type)) {
      defects.push({
        severity: "fatal",
        offset: chunk.offset + 4,
        field: "chunk.type",
        message: `chunk type ${JSON.stringify(chunk.type)} is not four ASCII letters; chunk framing has desynchronised.`,
        repairable: false,
      });
    }
    if (chunk.overruns) {
      defects.push({
        severity: "fatal",
        offset: chunk.offset,
        field: `${chunk.type}.length`,
        message: `declares ${chunk.declaredLength} payload bytes but only ${chunk.data.length} remain; the parser cannot safely walk past this chunk.`,
        repairable: false,
      });
    }
    if (!chunk.overruns && chunk.storedCrc !== chunk.actualCrc) {
      defects.push({
        severity: "warning",
        offset: chunk.offset + 8 + chunk.data.length,
        field: `${chunk.type}.crc`,
        message: `stored ${chunk.storedCrc?.toString(16).padStart(8, "0")} differs from computed ${chunk.actualCrc.toString(16).padStart(8, "0")}; some MNG readers ignore this, others reject it before the target chunk.`,
        repairable: true,
      });
    }
  }
  if (stoppedAt !== undefined && !chunks.some((chunk) => chunk.overruns)) {
    defects.push({
      severity: "fatal",
      offset: stoppedAt,
      field: "chunk.stream",
      message: "trailing bytes cannot form a complete MNG chunk header.",
      repairable: false,
    });
  }
  const first = chunks[0];
  if (!first || first.type !== "MHDR") {
    defects.push({
      severity: "fatal",
      offset: SIGNATURE.length,
      field: "MHDR",
      message: "the first MNG chunk must be MHDR to establish the animation header.",
      repairable: false,
    });
  } else if (first.data.length !== MHDR_BYTES) {
    defects.push({
      severity: "warning",
      offset: first.offset + 8,
      field: "MHDR.length",
      message: `MHDR payload is ${first.data.length} bytes; canonical MNG uses ${MHDR_BYTES}. Kept as a warning because short headers can be intentional parser-boundary test cases.`,
      repairable: false,
    });
  }
  if (!chunks.some((chunk) => chunk.type === "MEND")) {
    defects.push({
      severity: "warning",
      field: "MEND",
      message: "no MEND terminal chunk; many readers accept a truncated animation, but add it for a portable baseline.",
      repairable: true,
    });
  }
  return { wellFormed: !defects.some((defect) => defect.severity === "fatal"), defects, structure };
}

export const mngProverPlugin: ProverPlugin = {
  id: "mng",
  title: "MNG/JNG — chunk framing and CRCs for animation containers",
  aliases: ["mng", "jng", "graphicsmagick", "imagemagick"],
  paramsHelp: PARAMS_HELP,

  matches(ctx: ProverContext): ProverMatch {
    if (ctx.sample && startsWith(ctx.sample, SIGNATURE)) {
      return { score: 1, reason: "sample begins with the 8-byte MNG signature" };
    }
    const alias = matchAlias(`${ctx.hint ?? ""} ${ctx.harness ?? ""}`, mngProverPlugin.aliases);
    if (alias) return { score: 0.75, reason: `hint mentions '${alias}'` };
    return { score: 0, reason: "no MNG signature and no MNG/JNG hint" };
  },

  construct(req: ConstructRequest): ConstructResult {
    return req.base ? repair(req.base, req.params) : build(req.params);
  },

  validate,
};
