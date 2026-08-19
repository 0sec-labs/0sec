// Deterministic Input Encoder — 0sec #1501 item 2.
//
// WHY THIS EXISTS (the failure class it removes):
// A large slice of PoC-generation failures against libFuzzer targets are not
// reasoning failures — they are *byte-layout* failures. The target harness
// wraps its input in an LLVM `FuzzedDataProvider` (FDP), which decodes the raw
// bytes into typed values with a decidedly non-obvious algorithm:
//
//   • `ConsumeBytes` / `ConsumeBytesAsString` / `ConsumeRandomLengthString` /
//     `ConsumeRemainingBytes` pull from the **front** of the buffer;
//   • `ConsumeIntegral` / `ConsumeIntegralInRange` / `ConsumeBool` /
//     `ConsumeEnum` pull from the **back** of the buffer, one byte at a time,
//     most-significant byte first, with a range-dependent byte count and a
//     `result % (range + 1)` fold;
//   • `ConsumeRandomLengthString` uses a `\`-escape scheme where a lone
//     backslash terminates the string.
//
// An LLM can reliably reason about the *triggering value* ("field `len` must be
// 0xffff to overflow the copy") but reliably gets the *encoding* wrong (which
// end of the buffer? how many bytes? what modulo?). Two independent DARPA AIxCC
// finalists converged on the same fix — separate the reasoning from the
// encoding and hand the encoding to a cached, deterministic serializer
// (ATLANTIS's LibFDP, MIT; Theori RoboDuck's Input Encoder). This module is
// that serializer for the pwnkit engine.
//
// The agent describes the values it wants the harness to *decode*, in call
// order; `encodeFdp` emits the exact bytes FDP will decode back into those
// values, or a structured error the agent can act on. It is pure, deterministic
// and dependency-free, and it self-verifies by round-tripping through a
// faithful in-module FDP decoder before returning.
//
// Fidelity reference: llvm/compiler-rt FuzzedDataProvider.h. Semantics are
// covered by a round-trip unit test (input-encoder.test.ts).

// ────────────────────────────────────────────────────────────────────
// Field spec — what the agent says it wants the harness to decode.
// ────────────────────────────────────────────────────────────────────

/** Supported integer widths for the FDP integral consumers. */
export type FdpIntBits = 8 | 16 | 32 | 64;

/** `ConsumeIntegral<T>()` — full-range integer, consumed from the back. */
export interface FdpIntField {
  kind: "int";
  /** Optional label, surfaced in errors so the agent knows which field failed. */
  name?: string;
  /** Target value the harness should decode. `number` or `bigint` (for 64-bit). */
  value: number | bigint;
  /** Integer width in bits. Defaults to 32. */
  bits?: FdpIntBits;
  /** Signed (two's-complement) vs unsigned. Defaults to false (unsigned). */
  signed?: boolean;
}

/** `ConsumeIntegralInRange<T>(min, max)` — bounded integer, consumed from the back. */
export interface FdpIntInRangeField {
  kind: "intInRange";
  name?: string;
  value: number | bigint;
  min: number | bigint;
  max: number | bigint;
  /** Width of the C++ type `T`. Defaults to 32. Bounds the bytes FDP may pull. */
  bits?: FdpIntBits;
  signed?: boolean;
}

/** `ConsumeBool()` — one back byte, LSB. */
export interface FdpBoolField {
  kind: "bool";
  name?: string;
  value: boolean;
}

/** `ConsumeBytes(n)` / `ConsumeData(dst, n)` — `n` verbatim bytes from the front. */
export interface FdpBytesField {
  kind: "bytes";
  name?: string;
  /** Raw bytes, or a hex string ("deadbeef" / "de ad be ef" / "0xdead"). */
  value: Uint8Array | number[] | string;
  /** Interpret a string `value` as hex (default) vs latin1 text. */
  encoding?: "hex" | "latin1";
}

/** `ConsumeRandomLengthString(maxLength)` — front, `\`-escaped, self-terminating. */
export interface FdpStringField {
  kind: "string";
  name?: string;
  /** The exact string the harness should decode (code units must be 0..255). */
  value: string;
  /**
   * The `max_length` the harness passes. Defaults to `Infinity` (FDP's default
   * `size_t` max). If `value.length >= maxLength` the string is length-capped
   * and no terminator is emitted, matching FDP.
   */
  maxLength?: number;
}

/** `ConsumeRemainingBytes()` — grabs every not-yet-consumed byte. MUST be last. */
export interface FdpRemainingBytesField {
  kind: "remainingBytes";
  name?: string;
  value: Uint8Array | number[] | string;
  encoding?: "hex" | "latin1";
}

export type FdpField =
  | FdpIntField
  | FdpIntInRangeField
  | FdpBoolField
  | FdpBytesField
  | FdpStringField
  | FdpRemainingBytesField;

export interface FdpSpec {
  /** Fields in the exact order the harness consumes them. */
  fields: FdpField[];
}

export interface EncodeOk {
  ok: true;
  bytes: Uint8Array;
  /** Lowercase hex, convenient for logs / prompts. */
  hex: string;
  /** `b"\\x.."` python literal for dropping straight into a submit_poc generator. */
  pythonLiteral: string;
  /** Bytes attributed to front- vs back-consumed fields (for explainability). */
  layout: { frontBytes: number; backBytes: number; total: number };
}

export interface EncodeErr {
  ok: false;
  /** Human-readable, actionable message fed straight back to the agent. */
  error: string;
  /** Index of the offending field in `spec.fields`, when applicable. */
  fieldIndex?: number;
}

export type EncodeResult = EncodeOk | EncodeErr;

const U64 = 1n << 64n;

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

function intBounds(bits: number, signed: boolean): { min: bigint; max: bigint } {
  if (signed) {
    const half = 1n << BigInt(bits - 1);
    return { min: -half, max: half - 1n };
  }
  return { min: 0n, max: (1n << BigInt(bits)) - 1n };
}

function toU64(v: bigint): bigint {
  return ((v % U64) + U64) % U64;
}

function parseHex(s: string): Uint8Array | null {
  let h = s.trim().toLowerCase();
  if (h.startsWith("0x")) h = h.slice(2);
  h = h.replace(/[\s_]/g, "");
  if (h.length === 0) return new Uint8Array(0);
  if (h.length % 2 !== 0 || /[^0-9a-f]/.test(h)) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** Coerce a bytes-ish field value to raw bytes, or return an error string. */
function coerceBytes(
  value: Uint8Array | number[] | string,
  encoding: "hex" | "latin1" | undefined,
): { bytes: Uint8Array } | { error: string } {
  if (value instanceof Uint8Array) return { bytes: value };
  if (Array.isArray(value)) {
    for (const b of value) {
      if (!Number.isInteger(b) || b < 0 || b > 255)
        return { error: `byte array element ${b} is not an integer in 0..255` };
    }
    return { bytes: Uint8Array.from(value) };
  }
  // string
  if ((encoding ?? "hex") === "hex") {
    const parsed = parseHex(value);
    if (!parsed) return { error: `value "${value}" is not valid hex (need an even number of [0-9a-f] digits)` };
    return { bytes: parsed };
  }
  const out = new Uint8Array(value.length);
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c > 255) return { error: `latin1 value contains code unit ${c} (>255) at index ${i}` };
    out[i] = c;
  }
  return { bytes: out };
}

/**
 * Number of bytes FDP's integral loop pulls for a given `range`, capped by the
 * type width. Mirrors: `while (offset < sizeof(T)*8 && (range >> offset) > 0)`.
 */
function integralByteCount(range: bigint, bits: number): number {
  let n = 0;
  for (let off = 0; off < bits && range >> BigInt(off) > 0n; off += 8) n++;
  return n;
}

/**
 * Pop-order bytes (most-significant first, i.e. the order FDP reads them off
 * the shrinking tail) that reconstruct raw pre-modulo `result === r`.
 */
function backPopBytes(r: bigint, nbytes: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < nbytes; i++) {
    const shift = BigInt(8 * (nbytes - 1 - i));
    out.push(Number((r >> shift) & 0xffn));
  }
  return out;
}

// ────────────────────────────────────────────────────────────────────
// Encoder
// ────────────────────────────────────────────────────────────────────

/**
 * Encode a typed FDP spec into the exact bytes the target's
 * `FuzzedDataProvider` will decode back into those values.
 *
 * Determinism: identical spec → identical bytes, always. No RNG, no clock.
 *
 * The result self-verifies: before returning `ok`, the encoded bytes are run
 * through {@link decodeFdp} and compared field-by-field. A mismatch is reported
 * as an encoding error rather than emitting a wrong PoC — the whole point is to
 * never silently hand the harness bytes that decode to something else.
 */
export function encodeFdp(spec: FdpSpec): EncodeResult {
  const front: number[] = [];
  // Back-consumed bytes in *pop* order (field order, MSB-first within a field).
  const backPop: number[] = [];

  const fields = spec.fields;
  for (let i = 0; i < fields.length; i++) {
    const f = fields[i];
    const label = f.name ? ` (${f.name})` : "";

    switch (f.kind) {
      case "int":
      case "intInRange": {
        const bits = f.bits ?? 32;
        if (![8, 16, 32, 64].includes(bits))
          return { ok: false, error: `field #${i}${label}: unsupported bits=${bits} (use 8|16|32|64)`, fieldIndex: i };
        const signed = f.signed ?? false;
        const value = BigInt(f.value);

        let min: bigint;
        let max: bigint;
        if (f.kind === "intInRange") {
          min = BigInt(f.min);
          max = BigInt(f.max);
          if (min > max)
            return { ok: false, error: `field #${i}${label}: min ${min} > max ${max}`, fieldIndex: i };
        } else {
          const b = intBounds(bits, signed);
          min = b.min;
          max = b.max;
        }
        if (value < min || value > max)
          return { ok: false, error: `field #${i}${label}: value ${value} out of range [${min}, ${max}]`, fieldIndex: i };

        // FDP: uint64 range = (uint64)max - (uint64)min.
        const range = toU64(max - min);
        const nbytes = integralByteCount(range, bits);
        // r = value - min as unsigned; result % (range+1) is the identity here
        // because 0 <= r <= range, so the raw bytes are just big-endian r.
        const r = toU64(value - min);
        // Guard: r must fit in nbytes (it always does, since r <= range and the
        // loop consumes enough bytes to cover `range` — assert defensively).
        if (nbytes > 0 && r >> BigInt(8 * nbytes) !== 0n)
          return { ok: false, error: `field #${i}${label}: internal encode overflow (r=${r}, nbytes=${nbytes})`, fieldIndex: i };
        for (const b of backPopBytes(r, nbytes)) backPop.push(b);
        break;
      }

      case "bool": {
        // ConsumeBool() == (ConsumeIntegral<uint8_t>() & 1). One back byte.
        backPop.push(f.value ? 1 : 0);
        break;
      }

      case "bytes": {
        const c = coerceBytes(f.value, f.encoding);
        if ("error" in c) return { ok: false, error: `field #${i}${label}: ${c.error}`, fieldIndex: i };
        for (const b of c.bytes) front.push(b);
        break;
      }

      case "string": {
        const maxLength = f.maxLength ?? Infinity;
        if (maxLength < 0)
          return { ok: false, error: `field #${i}${label}: maxLength must be >= 0`, fieldIndex: i };
        let emitted = 0;
        for (let k = 0; k < f.value.length; k++) {
          if (emitted >= maxLength) break; // FDP stops at max_length.
          const c = f.value.charCodeAt(k);
          if (c > 255)
            return { ok: false, error: `field #${i}${label}: code unit ${c} (>255) at index ${k}; strings are byte strings`, fieldIndex: i };
          if (c === 0x5c) {
            // Literal backslash: FDP appends one '\' only for the "\\" escape.
            front.push(0x5c, 0x5c);
          } else {
            front.push(c);
          }
          emitted++;
        }
        // Terminate so following fields are not swallowed — unless the string
        // was length-capped (FDP stops on its own at max_length).
        if (emitted < maxLength) front.push(0x5c, 0x00);
        break;
      }

      case "remainingBytes": {
        if (i !== fields.length - 1)
          return { ok: false, error: `field #${i}${label}: remainingBytes must be the last field (it consumes everything left)`, fieldIndex: i };
        const c = coerceBytes(f.value, f.encoding);
        if ("error" in c) return { ok: false, error: `field #${i}${label}: ${c.error}`, fieldIndex: i };
        for (const b of c.bytes) front.push(b);
        break;
      }

      default: {
        const _exhaustive: never = f;
        return { ok: false, error: `field #${i}: unknown kind ${(f as { kind?: string }).kind}` };
      }
    }
  }

  // Back region in buffer order = reverse of pop order (the last buffer byte is
  // the first byte the first back-consumed field pops).
  const back = backPop.slice().reverse();
  const bytes = Uint8Array.from([...front, ...back]);

  // Self-verify: decode and compare. Never emit bytes that decode wrong.
  const check = verifyRoundTrip(spec, bytes);
  if (check) return { ok: false, error: `self-check failed: ${check}` };

  return {
    ok: true,
    bytes,
    hex: Buffer.from(bytes).toString("hex"),
    pythonLiteral: toPythonLiteral(bytes),
    layout: { frontBytes: front.length, backBytes: back.length, total: bytes.length },
  };
}

function toPythonLiteral(bytes: Uint8Array): string {
  let s = 'b"';
  for (const b of bytes) s += `\\x${b.toString(16).padStart(2, "0")}`;
  return s + '"';
}

// ────────────────────────────────────────────────────────────────────
// Reference decoder — a faithful TS port of FuzzedDataProvider.h.
//
// Used for the encoder's self-check and by the unit test as the oracle. Kept in
// this module (not the test) so the self-check ships with the encoder: a spec
// that encodes then decodes back to the same values is provably harness-safe.
// ────────────────────────────────────────────────────────────────────

/** A minimal, faithful FDP over a byte buffer — front pointer + back pointer. */
export class FdpReader {
  private data: Uint8Array;
  private head = 0; // next front byte
  private remaining: number;

  constructor(bytes: Uint8Array) {
    this.data = bytes;
    this.remaining = bytes.length;
  }

  consumeBytes(n: number): Uint8Array {
    const count = Math.min(n, this.remaining);
    const out = this.data.slice(this.head, this.head + count);
    this.head += count;
    this.remaining -= count;
    return out;
  }

  consumeRemainingBytes(): Uint8Array {
    return this.consumeBytes(this.remaining);
  }

  consumeIntegralInRange(min: bigint, max: bigint, bits: number): bigint {
    if (min > max) throw new Error("min > max");
    const range = toU64(max - min);
    let result = 0n;
    let offset = 0;
    while (offset < bits && range >> BigInt(offset) > 0n && this.remaining !== 0) {
      this.remaining--;
      // Byte off the shrinking tail, relative to the advanced head.
      result = (result << 8n) | BigInt(this.data[this.head + this.remaining]);
      offset += 8;
    }
    if (range !== U64 - 1n) result = result % (range + 1n);
    // FDP: static_cast<T>(static_cast<uint64_t>(min) + result). For signed T
    // this lands on the correct two's-complement value directly.
    return min + result;
  }

  consumeIntegral(bits: number, signed: boolean): bigint {
    const { min, max } = intBounds(bits, signed);
    return this.consumeIntegralInRange(min, max, bits);
  }

  consumeBool(): boolean {
    return (this.consumeIntegral(8, false) & 1n) === 1n;
  }

  consumeRandomLengthString(maxLength = Infinity): number[] {
    const out: number[] = [];
    for (let i = 0; i < maxLength && this.remaining !== 0; i++) {
      let next = this.data[this.head];
      this.head++;
      this.remaining--;
      if (next === 0x5c && this.remaining !== 0) {
        next = this.data[this.head];
        this.head++;
        this.remaining--;
        if (next !== 0x5c) break; // lone backslash terminates
      }
      out.push(next);
    }
    return out;
  }
}

/** Decode a buffer per a spec, returning each field's decoded value. */
export function decodeFdp(spec: FdpSpec, bytes: Uint8Array): unknown[] {
  const r = new FdpReader(bytes);
  const out: unknown[] = [];
  for (const f of spec.fields) {
    switch (f.kind) {
      case "int":
        out.push(r.consumeIntegral(f.bits ?? 32, f.signed ?? false));
        break;
      case "intInRange":
        out.push(r.consumeIntegralInRange(BigInt(f.min), BigInt(f.max), f.bits ?? 32));
        break;
      case "bool":
        out.push(r.consumeBool());
        break;
      case "bytes": {
        const c = coerceBytes(f.value, f.encoding);
        const n = "error" in c ? 0 : c.bytes.length;
        out.push(r.consumeBytes(n));
        break;
      }
      case "string":
        out.push(r.consumeRandomLengthString(f.maxLength ?? Infinity));
        break;
      case "remainingBytes":
        out.push(r.consumeRemainingBytes());
        break;
    }
  }
  return out;
}

/** Returns an error string if `bytes` do not decode back to `spec`, else null. */
function verifyRoundTrip(spec: FdpSpec, bytes: Uint8Array): string | null {
  let decoded: unknown[];
  try {
    decoded = decodeFdp(spec, bytes);
  } catch (e) {
    return `decoder threw: ${String(e)}`;
  }
  for (let i = 0; i < spec.fields.length; i++) {
    const f = spec.fields[i];
    const got = decoded[i];
    const mismatch = fieldMismatch(f, got);
    if (mismatch) return `field #${i}${f.name ? ` (${f.name})` : ""}: ${mismatch}`;
  }
  return null;
}

function fieldMismatch(f: FdpField, got: unknown): string | null {
  switch (f.kind) {
    case "int":
    case "intInRange":
      return BigInt(got as bigint) === BigInt(f.value) ? null : `decoded ${got} != wanted ${f.value}`;
    case "bool":
      return got === f.value ? null : `decoded ${got} != wanted ${f.value}`;
    case "bytes":
    case "remainingBytes": {
      const c = coerceBytes(f.value, f.encoding);
      if ("error" in c) return c.error;
      return bytesEqual(got as Uint8Array, c.bytes) ? null : `decoded bytes differ from wanted`;
    }
    case "string": {
      const wanted: number[] = [];
      for (let k = 0; k < f.value.length; k++) wanted.push(f.value.charCodeAt(k));
      return arrayEqual(got as number[], wanted) ? null : `decoded string differs from wanted`;
    }
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function arrayEqual(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ────────────────────────────────────────────────────────────────────
// Craft-agent tool glue.
//
// Mirrors the `format_reference` tool wiring in stages/craft-scan.ts: a tool
// definition plus a pure string-returning handler. This keeps the integration
// into the craft loop a two-line change and independently unit-testable.
// ────────────────────────────────────────────────────────────────────

/** The tool definition to add to the craft agent's tool list. */
export function fdpEncodeToolDef(): {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
} {
  return {
    name: "fdp_encode",
    description:
      "Deterministically encode typed values into the EXACT bytes a FuzzedDataProvider (FDP) harness will decode. " +
      "Use this whenever LLVMFuzzerTestOneInput wraps `data` in a FuzzedDataProvider instead of reading raw bytes — " +
      "reason about the VALUES you want each Consume* call to return, then let this emit the bytes (you do NOT need to " +
      "work out front/back consumption or the modulo yourself). Pass `fields` in the SAME ORDER the harness consumes " +
      "them. Kinds: int{value,bits?,signed?}, intInRange{value,min,max,bits?}, bool{value}, bytes{value:hex}, " +
      "string{value,maxLength?}, remainingBytes{value:hex, must be last}. Returns the python bytes literal + hex, or a " +
      "precise error to fix.",
    input_schema: {
      type: "object",
      properties: {
        fields: {
          type: "array",
          description: "FDP fields in harness-consumption order.",
          items: { type: "object" },
        },
      },
      required: ["fields"],
    },
  };
}

/**
 * Handler for the `fdp_encode` tool. Accepts the raw tool input, returns a
 * string suitable as a `tool_result` (either the encoded PoC bytes or an
 * actionable encoding error the agent can iterate on).
 */
export function runFdpEncode(input: unknown): string {
  const fields = (input as { fields?: unknown })?.fields;
  if (!Array.isArray(fields))
    return 'fdp_encode error: `fields` must be an array of FDP field specs (e.g. [{"kind":"intInRange","value":65535,"min":0,"max":65535,"bits":16}]).';
  const res = encodeFdp({ fields: fields as FdpField[] });
  if (!res.ok) return `fdp_encode error: ${res.error}. Fix the spec and call again.`;
  return (
    `Encoded ${res.layout.total} bytes ` +
    `(${res.layout.frontBytes} front-consumed, ${res.layout.backBytes} back-consumed).\n` +
    `python: sys.stdout.buffer.write(${res.pythonLiteral})\n` +
    `hex: ${res.hex}`
  );
}
