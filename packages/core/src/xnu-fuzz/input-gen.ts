/**
 * `xnu-fuzz` §2 input generation.
 *
 *   2.1 Valid-sized base inputs — emit exactly `scalarInCnt` scalars and
 *       `structInSize` struct bytes so every input gets PAST the marshalling
 *       gate into the real handler; for variable-size (`VARIABLE_SIZE`)
 *       selectors, sweep a length schedule that targets off-by-one and
 *       integer-truncation handling around length fields.
 *
 *   2.2 Structure-aware mutation — given a best-effort field grammar lifted
 *       from the decompiled handler (length / magic / handle / unknown), mutate
 *       around the fields that matter (boundary values on lengths, mostly-valid
 *       magics, boundary handles) and havoc the rest. Degrades gracefully: with
 *       no grammar, everything is `unknown` and gets havoc'd.
 *
 * Determinism: all randomness flows through a seeded mulberry32 PRNG so the
 * generators are reproducible (a crash's input bytes must replay exactly).
 */

import { VARIABLE_SIZE, isVariable, type SelectorModel } from "./types.js";

// ── deterministic PRNG ─────────────────────────────────────────────────────

export interface Rng {
  /** next float in [0, 1). */
  next(): number;
  /** next u32. */
  u32(): number;
  /** next byte 0..255. */
  byte(): number;
  /** next u64 as bigint. */
  u64(): bigint;
  /** integer in [0, n). */
  below(n: number): number;
}

/** Seeded mulberry32 — small, fast, reproducible. */
export function makeRng(seed: number): Rng {
  let a = seed >>> 0;
  const u32 = (): number => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return (t ^ (t >>> 14)) >>> 0;
  };
  return {
    u32,
    next: () => u32() / 0x1_0000_0000,
    byte: () => u32() & 0xff,
    u64: () => (BigInt(u32()) << 32n) | BigInt(u32()),
    below: (n: number) => (n <= 0 ? 0 : u32() % n),
  };
}

// ── 2.1 valid-sized base inputs ─────────────────────────────────────────────

export interface FuzzInput {
  selector: number;
  /** Exactly `scalarInCnt` scalars (the IOConnectCallMethod scalarInput). */
  scalarInput: bigint[];
  /** The structureInput bytes (length per the size schedule). */
  structureInput: Uint8Array;
  /** Requested scalarOutput count (mirrors the gate's expectation). */
  scalarOutCnt: number;
  /** Requested structureOutput size (declared, or chosen for VAR). */
  structOutSize: number;
  /** Provenance for a VAR-length sweep entry (e.g. "header-1"). */
  lengthLabel?: string;
}

/**
 * The variable-length sweep schedule (§2.1). Hits 0/1/word, the declared
 * header size and header±1, and page / 64K boundaries (and ±1) where
 * length-field off-by-ones and truncations live.
 */
export function variableLengthSchedule(headerSize = 0x20): number[] {
  const base = [0, 1, 8, headerSize, headerSize - 1, headerSize + 1, 0x1000, 0x1000 - 1, 0x1000 + 1, 0x10000];
  return [...new Set(base.filter((n) => n >= 0))].sort((a, b) => a - b);
}

/** A safe concrete struct size to use when the gate declares VARIABLE_SIZE. */
const VAR_DEFAULT_STRUCT_OUT = 0x1000;

function fillRandom(rng: Rng, len: number): Uint8Array {
  const b = new Uint8Array(len);
  for (let i = 0; i < len; i++) b[i] = rng.byte();
  return b;
}

/** A single gate-passing base input for a fixed-size selector. */
export function generateBaseInput(sel: SelectorModel, rng: Rng): FuzzInput {
  const scalarInput: bigint[] = [];
  for (let i = 0; i < sel.scalarInCnt; i++) scalarInput.push(rng.u64());
  const structLen = isVariable(sel.structInSize) ? 0 : sel.structInSize;
  return {
    selector: sel.sel,
    scalarInput,
    structureInput: fillRandom(rng, structLen),
    scalarOutCnt: sel.scalarOutCnt,
    structOutSize: isVariable(sel.structOutSize) ? VAR_DEFAULT_STRUCT_OUT : sel.structOutSize,
    lengthLabel: isVariable(sel.structInSize) ? "var-0" : undefined,
  };
}

export interface GenerateOptions {
  /** Base inputs per fixed-size selector (default 1). */
  fixedReplicas?: number;
  /** Header size used to seed the VAR length schedule (default 0x20). */
  headerSize?: number;
}

/**
 * Generate the §2.1 gate-passing input set for one selector: a few random
 * fixed-size inputs, or one input per length in the sweep for VAR selectors.
 */
export function generateInputsForSelector(
  sel: SelectorModel,
  rng: Rng,
  opts: GenerateOptions = {},
): FuzzInput[] {
  const inputs: FuzzInput[] = [];
  if (isVariable(sel.structInSize)) {
    for (const len of variableLengthSchedule(opts.headerSize)) {
      const scalarInput: bigint[] = [];
      for (let i = 0; i < sel.scalarInCnt; i++) scalarInput.push(rng.u64());
      inputs.push({
        selector: sel.sel,
        scalarInput,
        structureInput: fillRandom(rng, len),
        scalarOutCnt: sel.scalarOutCnt,
        structOutSize: isVariable(sel.structOutSize) ? VAR_DEFAULT_STRUCT_OUT : sel.structOutSize,
        lengthLabel: `len-${len}`,
      });
    }
  } else {
    const replicas = Math.max(1, opts.fixedReplicas ?? 1);
    for (let i = 0; i < replicas; i++) inputs.push(generateBaseInput(sel, rng));
  }
  return inputs;
}

// ── 2.2 structure-aware mutation ────────────────────────────────────────────

export type FieldKind = "length" | "magic" | "handle" | "unknown";

export interface FieldSpec {
  offset: number;
  size: 1 | 2 | 4 | 8;
  kind: FieldKind;
  /** Valid constant for a `magic` field — pinned most of the time. */
  magic?: bigint;
}

export interface StructGrammar {
  /** Total struct size, when known (for `len`-relative boundary values). */
  totalSize?: number;
  fields: FieldSpec[];
}

function writeUintLE(buf: Uint8Array, offset: number, size: number, value: bigint): void {
  let v = value & ((1n << BigInt(size * 8)) - 1n);
  for (let i = 0; i < size; i++) {
    buf[offset + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

function readUintLE(buf: Uint8Array, offset: number, size: number): bigint {
  let v = 0n;
  for (let i = size - 1; i >= 0; i--) v = (v << 8n) | BigInt(buf[offset + i] ?? 0);
  return v;
}

/**
 * Boundary values for a length/count field of `size` bytes, relative to the
 * struct total. Targets the classic wraps: 0, 1, signed-max, all-ones, and
 * `total ± 1` — the off-by-one and `count * elem` integer-overflow drivers.
 */
export function lengthBoundaryValues(size: number, total?: number): bigint[] {
  const max = (1n << BigInt(size * 8)) - 1n;
  const signedMax = (1n << BigInt(size * 8 - 1)) - 1n;
  const vals = new Set<bigint>([0n, 1n, signedMax, max]);
  if (total !== undefined) {
    const t = BigInt(total);
    for (const d of [-1n, 0n, 1n]) {
      const v = t + d;
      if (v >= 0n) vals.add(v & max);
    }
  }
  // a value that overflows when multiplied by a typical 16-byte element size
  vals.add((max / 16n) + 1n);
  return [...vals];
}

const HANDLE_BOUNDARY_VALUES: bigint[] = [0n, 1n, 0x7fffffffn, 0xffffffffn, 0xffffffffffffffffn];

/**
 * Produce a deterministic set of structure-aware mutants of `base` per the
 * grammar. One mutant per interesting (field, value) pair, plus a havoc'd
 * variant for coverage of the unknown bytes. Empty input or empty grammar
 * still yields havoc variants so the mutator never returns nothing useful.
 */
export function mutateStructured(base: Uint8Array, grammar: StructGrammar, rng: Rng): Uint8Array[] {
  const total = grammar.totalSize ?? base.byteLength;
  const mutants: Uint8Array[] = [];
  const clone = (): Uint8Array => Uint8Array.from(base);

  for (const f of grammar.fields) {
    if (f.offset + f.size > base.byteLength) continue;
    if (f.kind === "length") {
      for (const v of lengthBoundaryValues(f.size, total)) {
        const m = clone();
        writeUintLE(m, f.offset, f.size, v);
        mutants.push(m);
      }
    } else if (f.kind === "handle") {
      for (const v of HANDLE_BOUNDARY_VALUES) {
        const m = clone();
        writeUintLE(m, f.offset, f.size, v);
        mutants.push(m);
      }
    } else if (f.kind === "magic") {
      // mostly pin the valid magic; emit one flipped variant to probe the
      // version-mismatch path.
      if (f.magic !== undefined) {
        const m = clone();
        writeUintLE(m, f.offset, f.size, f.magic);
        mutants.push(m);
      }
      const flip = clone();
      writeUintLE(flip, f.offset, f.size, (f.magic ?? readUintLE(base, f.offset, f.size)) ^ 0x1n);
      mutants.push(flip);
    }
  }

  // structure-preserving havoc on whatever isn't a typed field.
  mutants.push(havoc(base, grammar, rng));
  return mutants;
}

/** One structure-preserving havoc step: bitflip/arith on non-typed bytes. */
export function havoc(base: Uint8Array, grammar: StructGrammar, rng: Rng): Uint8Array {
  const typed = new Set<number>();
  for (const f of grammar.fields) for (let i = 0; i < f.size; i++) typed.add(f.offset + i);
  const m = Uint8Array.from(base);
  if (m.byteLength === 0) return m;
  const flips = 1 + rng.below(Math.max(1, Math.floor(m.byteLength / 8)));
  for (let i = 0; i < flips; i++) {
    let pos = rng.below(m.byteLength);
    // prefer untyped bytes, but don't loop forever on a fully-typed struct
    for (let tries = 0; tries < 4 && typed.has(pos); tries++) pos = rng.below(m.byteLength);
    m[pos] = (m[pos]! ^ (1 << rng.below(8))) & 0xff;
  }
  return m;
}

/** Total count of structure-aware mutants a grammar will produce (for budgeting). */
export function mutantBudget(grammar: StructGrammar, total?: number): number {
  let n = 1; // havoc
  for (const f of grammar.fields) {
    if (f.kind === "length") n += lengthBoundaryValues(f.size, total ?? grammar.totalSize).length;
    else if (f.kind === "handle") n += HANDLE_BOUNDARY_VALUES.length;
    else if (f.kind === "magic") n += f.magic !== undefined ? 2 : 1;
  }
  return n;
}

export { VARIABLE_SIZE };
