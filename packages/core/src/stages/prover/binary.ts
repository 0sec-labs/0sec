/**
 * Shared byte primitives for the prover plugins.
 *
 * Nothing here is clever. It exists because every container format that blocks
 * a PoC blocks it with the SAME three mechanics — a checksum, a length field,
 * and an offset field — and each prover plugin would otherwise reimplement them
 * slightly differently. A CRC that is subtly wrong in one plugin and right in
 * another is exactly the class of defect a prover plugin is supposed to remove
 * from the agent's plate, so the arithmetic lives in one audited place with its
 * own round-trip tests.
 *
 * Everything is PURE: no I/O, no globals, no clock, no randomness. A prover
 * plugin built on these helpers is deterministic, which is what lets us assert
 * byte-exact outputs in tests and what lets the craft agent trust that calling
 * `prover_construct` twice with the same params yields the same PoC.
 */

// ── Checksums ────────────────────────────────────────────────────────────────

/**
 * CRC-32/ISO-HDLC (the "IEEE" / zlib CRC-32): reflected, polynomial 0xEDB88320,
 * init 0xFFFFFFFF, final XOR 0xFFFFFFFF.
 *
 * This ONE function covers both shipped plugins, which is not a coincidence:
 * PNG chunk CRCs and ZIP entry CRCs are the same algorithm. It is also the
 * single most common reason a hand-built container is rejected before the
 * parser ever reaches the buggy code — the agent gets the structure right and
 * then writes four bytes of garbage where the checksum goes.
 */
export function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i]!;
    for (let bit = 0; bit < 8; bit++) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Adler-32, the zlib stream checksum. Needed because a PNG's IDAT payload is a
 * zlib stream, and a zlib stream whose trailing Adler-32 is wrong is rejected
 * by the inflater — i.e. the image data never reaches the row-processing code
 * where most libpng bugs live.
 */
export function adler32(data: Uint8Array): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < data.length; i++) {
    a = (a + data[i]!) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

// ── Integer encoding ─────────────────────────────────────────────────────────

/** Big-endian u32 (PNG, ISO-BMFF, most network-order formats). */
export function u32be(value: number): Uint8Array {
  const v = value >>> 0;
  return Uint8Array.from([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
}

/** Little-endian u32 (ZIP, RIFF, most Intel-era formats). */
export function u32le(value: number): Uint8Array {
  const v = value >>> 0;
  return Uint8Array.from([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]);
}

/** Little-endian u16. */
export function u16le(value: number): Uint8Array {
  const v = value & 0xffff;
  return Uint8Array.from([v & 0xff, (v >>> 8) & 0xff]);
}

/** Read a big-endian u32 at `off`, or `undefined` when it would read past the end. */
export function readU32be(buf: Uint8Array, off: number): number | undefined {
  if (off < 0 || off + 4 > buf.length) return undefined;
  return ((buf[off]! << 24) | (buf[off + 1]! << 16) | (buf[off + 2]! << 8) | buf[off + 3]!) >>> 0;
}

/** Read a little-endian u32 at `off`, or `undefined` when out of bounds. */
export function readU32le(buf: Uint8Array, off: number): number | undefined {
  if (off < 0 || off + 4 > buf.length) return undefined;
  return ((buf[off]! | (buf[off + 1]! << 8) | (buf[off + 2]! << 16) | (buf[off + 3]! << 24)) >>> 0);
}

/** Read a little-endian u16 at `off`, or `undefined` when out of bounds. */
export function readU16le(buf: Uint8Array, off: number): number | undefined {
  if (off < 0 || off + 2 > buf.length) return undefined;
  return (buf[off]! | (buf[off + 1]! << 8)) >>> 0;
}

// ── Buffer plumbing ──────────────────────────────────────────────────────────

/** Concatenate byte runs into one buffer. */
export function concat(parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** ASCII → bytes. Throws on any code unit above 0x7f so a typo can't silently truncate. */
export function ascii(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 0x7f) throw new Error(`non-ASCII character ${JSON.stringify(s[i])} at index ${i}`);
    out[i] = c;
  }
  return out;
}

/** Bytes → lowercase hex. */
export function toHex(buf: Uint8Array): string {
  let s = "";
  for (let i = 0; i < buf.length; i++) s += buf[i]!.toString(16).padStart(2, "0");
  return s;
}

/**
 * Hex → bytes. Tolerates `0x` prefixes, whitespace and `:`/`-` separators
 * because the agent pastes hex from a dozen different sources (xxd, python
 * repr, a sanitizer trace) and a strict parser here would just add a round-trip
 * of pointless error feedback.
 */
export function fromHex(s: string): Uint8Array | undefined {
  const cleaned = s
    .trim()
    .replace(/^0x/i, "")
    .replace(/[\s:_-]/g, "");
  if (cleaned.length === 0) return new Uint8Array(0);
  if (cleaned.length % 2 !== 0) return undefined;
  if (!/^[0-9a-fA-F]+$/.test(cleaned)) return undefined;
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Render bytes as a python `b"..."` literal so the agent can paste the result
 * straight into the `submit_poc` generator without a second encoding step.
 * Mirrors `agent/input-encoder.ts`'s `pythonLiteral`, deliberately: the craft
 * agent has already been taught that shape by `fdp_encode`.
 */
export function pythonLiteral(buf: Uint8Array): string {
  let s = 'b"';
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]!;
    if (b === 0x5c) s += "\\\\";
    else if (b === 0x22) s += '\\"';
    else if (b >= 0x20 && b <= 0x7e) s += String.fromCharCode(b);
    else s += "\\x" + b.toString(16).padStart(2, "0");
  }
  return s + '"';
}

/** True when `buf` starts with `prefix`. */
export function startsWith(buf: Uint8Array, prefix: readonly number[]): boolean {
  if (buf.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (buf[i] !== prefix[i]) return false;
  return true;
}

// ── zlib (stored blocks only) ────────────────────────────────────────────────

/**
 * Wrap raw bytes in a valid zlib stream using DEFLATE **stored** (uncompressed)
 * blocks.
 *
 * Why stored blocks and not real compression: the prover's job is to get the
 * container past the parser's front door, not to make it small. A stored-block
 * stream is byte-exactly derivable, has no entropy coder to get wrong, and
 * every inflater accepts it. Bringing in a real deflate implementation would
 * add a dependency and a class of bugs for zero proving benefit. If a task ever
 * needs a genuinely compressed IDAT (e.g. a bug in the Huffman decoder itself),
 * the right move is to let the agent supply the compressed stream verbatim —
 * which is why the PNG plugin exposes an "inject this IDAT payload as-is" knob
 * rather than trying to compress on the agent's behalf.
 *
 * Layout: `78 01` (CMF/FLG for deflate, 32K window, fastest level, FCHECK
 * chosen so the u16 is a multiple of 31), then stored blocks
 * `[BFINAL|BTYPE=00][LEN u16le][~LEN u16le][data]`, then the big-endian
 * Adler-32 of the *uncompressed* data.
 */
export function zlibStored(raw: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [Uint8Array.from([0x78, 0x01])];
  const MAX = 0xffff;
  if (raw.length === 0) {
    parts.push(Uint8Array.from([0x01, 0x00, 0x00, 0xff, 0xff]));
  } else {
    for (let off = 0; off < raw.length; off += MAX) {
      const chunk = raw.subarray(off, Math.min(off + MAX, raw.length));
      const final = off + chunk.length >= raw.length ? 1 : 0;
      parts.push(Uint8Array.from([final]));
      parts.push(u16le(chunk.length));
      parts.push(u16le(~chunk.length & 0xffff));
      parts.push(chunk);
    }
  }
  parts.push(u32be(adler32(raw)));
  return concat(parts);
}
