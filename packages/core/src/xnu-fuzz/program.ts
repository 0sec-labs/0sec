/**
 * `xnu-fuzz` §3.2 host↔guest wire format.
 *
 * Generation lives on the host (so a guest panic never loses fuzzer state);
 * each test program is shipped to the in-guest opener over a length-prefixed
 * channel. This module is the encoder/decoder for that channel — kept in sync
 * with the C opener (`opener/iokit-opener.c`, which parses the identical bytes).
 *
 * Program layout (all integers little-endian):
 *   u32 magic   = 'PKXF' (0x46584b50)
 *   u32 version = 1
 *   u32 callCount
 *   repeat callCount times:
 *     u32       selector
 *     u32       scalarInCount
 *     u64[...]  scalars
 *     u32       structInSize
 *     u8[...]   structIn
 *     u32       scalarOutCount   (requested)
 *     u32       structOutSize    (requested)
 */

import type { FuzzInput } from "./input-gen.js";

export const PROGRAM_MAGIC = 0x46584b50; // 'PKXF'
export const PROGRAM_VERSION = 1;

export interface ProgramCall {
  selector: number;
  scalarInput: bigint[];
  structureInput: Uint8Array;
  scalarOutCnt: number;
  structOutSize: number;
}

/** Encode a sequence of calls (a §2.4 program) into the guest wire format. */
export function encodeProgram(calls: (FuzzInput | ProgramCall)[]): Uint8Array {
  // FuzzInput is a superset of ProgramCall's fields, so read the common shape.
  const norm: ProgramCall[] = calls.map((c) => ({
    selector: c.selector,
    scalarInput: c.scalarInput,
    structureInput: c.structureInput,
    scalarOutCnt: c.scalarOutCnt,
    structOutSize: c.structOutSize,
  }));
  let size = 12;
  for (const c of norm) {
    size += 4 + 4 + c.scalarInput.length * 8 + 4 + c.structureInput.byteLength + 4 + 4;
  }
  const buf = new Uint8Array(size);
  const view = new DataView(buf.buffer);
  let off = 0;
  view.setUint32(off, PROGRAM_MAGIC, true); off += 4;
  view.setUint32(off, PROGRAM_VERSION, true); off += 4;
  view.setUint32(off, norm.length, true); off += 4;
  for (const c of norm) {
    view.setUint32(off, c.selector >>> 0, true); off += 4;
    view.setUint32(off, c.scalarInput.length, true); off += 4;
    for (const s of c.scalarInput) { view.setBigUint64(off, BigInt.asUintN(64, s), true); off += 8; }
    view.setUint32(off, c.structureInput.byteLength, true); off += 4;
    buf.set(c.structureInput, off); off += c.structureInput.byteLength;
    view.setUint32(off, c.scalarOutCnt >>> 0, true); off += 4;
    view.setUint32(off, c.structOutSize >>> 0, true); off += 4;
  }
  return buf;
}

/** Decode a wire-format program (the inverse of `encodeProgram`). */
export function decodeProgram(buf: Uint8Array): ProgramCall[] {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let off = 0;
  const requireBytes = (count: number, label: string): void => {
    if (count > buf.byteLength - off) throw new Error(`truncated program while reading ${label}`);
  };
  const u32 = (label: string): number => {
    requireBytes(4, label);
    const value = view.getUint32(off, true);
    off += 4;
    return value;
  };

  const magic = u32("magic");
  if (magic !== PROGRAM_MAGIC) throw new Error(`bad program magic 0x${magic.toString(16)}`);
  const version = u32("version");
  if (version !== PROGRAM_VERSION) throw new Error(`unsupported program version ${version}`);
  const count = u32("call count");
  const calls: ProgramCall[] = [];
  for (let i = 0; i < count; i++) {
    const selector = u32(`call ${i} selector`);
    const scn = u32(`call ${i} scalar input count`);
    if (scn > Math.floor((buf.byteLength - off) / 8)) throw new Error(`truncated program while reading call ${i} scalars`);
    const scalarInput: bigint[] = [];
    for (let j = 0; j < scn; j++) {
      scalarInput.push(view.getBigUint64(off, true));
      off += 8;
    }
    const sis = u32(`call ${i} structure input size`);
    requireBytes(sis, `call ${i} structure input`);
    const structureInput = buf.slice(off, off + sis); off += sis;
    const scalarOutCnt = u32(`call ${i} scalar output count`);
    const structOutSize = u32(`call ${i} structure output size`);
    calls.push({ selector, scalarInput, structureInput, scalarOutCnt, structOutSize });
  }
  if (off !== buf.byteLength) throw new Error("program has trailing bytes");
  return calls;
}
