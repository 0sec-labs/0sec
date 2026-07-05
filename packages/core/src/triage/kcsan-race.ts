/**
 * KCSAN data-race report parser (kernelCTF Pipeline #1, issue #1112).
 *
 * The KASAN fuzz fleet is structurally blind to data races; a KCSAN kernel is
 * where crypto/net concurrency bugs actually surface (the vein others win
 * kernelCTF with). But a raw KCSAN splat is prose — before it can be fed to the
 * hunt-engine gate (skeptic filter → race-widening prover) it has to be turned
 * into structured facts: the two racing access sites (function + file:line +
 * stack) and the raced-on object.
 *
 * This module is JUST the parser + its types. It does no I/O and no LLM/VM work,
 * so it unit-tests offline against a real KCSAN report sample. The triage that
 * consumes a {@link KcsanRace} lives in `kcsan-triage.ts`.
 *
 * A canonical KCSAN report looks like:
 *
 *   ==================================================================
 *   BUG: KCSAN: data-race in ext4_free_inode / ext4_mark_iloc_dirty
 *
 *   write to 0xffff8881033c1a40 of 8 bytes by task 6398 on cpu 0:
 *    ext4_mark_iloc_dirty+0x2d4/0x680 fs/ext4/inode.c:5876
 *    __ext4_mark_inode_dirty+0x1a0/0x4c0 fs/ext4/inode.c:6132
 *    ...
 *
 *   read to 0xffff8881033c1a40 of 8 bytes by task 6403 on cpu 1:
 *    ext4_free_inode+0x33c/0x8d0 fs/ext4/ialloc.c:320
 *    ...
 *
 *   value changed: 0x0000000000000001 -> 0x0000000000000000
 *
 *   Reported by Kernel Concurrency Sanitizer on:
 *   ==================================================================
 */

/** One side of a KCSAN data race: the faulting site + its stack. */
export interface KcsanAccess {
  /** Faulting function name (top stack frame). */
  fn: string;
  /** Source file of the faulting frame, when the report carries `file:line`. */
  file?: string;
  /** Source line of the faulting frame. */
  line?: number;
  /** Access direction KCSAN observed. */
  access?: "read" | "write";
  /** Access width in bytes (from `of N bytes`). */
  size?: number;
  /** The raced-on kernel address (`0x…`), if present on this access. */
  address?: string;
  /** The symbol stack (top frame first), each `func` or `func file:line`. */
  stack: string[];
}

/** A parsed KCSAN `data-race` report reduced to its load-bearing facts. */
export interface KcsanRace {
  /** First racing access (header FUNC1 / first access block). */
  a: KcsanAccess;
  /** Second racing access (header FUNC2 / second access block). A
   *  same-function race (`data-race in foo`) yields `b === a`'s function. */
  b: KcsanAccess;
  /** The raced-on object address, when the report exposes one. */
  object?: string;
  /** `value changed: X -> Y`, when present (evidence the write actually raced). */
  valueChanged?: { from: string; to: string };
  /** The original report text, preserved for the prover's CrashReport.raw. */
  raw: string;
}

const HEADER_RE = /BUG:\s*KCSAN:\s*data-race in\s+(.+?)\s*$/im;
// `write to 0x… of 8 bytes by task 6398 on cpu 0:` — KCSAN uses `to`/`of`.
const ACCESS_RE =
  /^\s*(read|write)\s+(?:to|of)\s+(0x[0-9a-fA-F]+)\s+of\s+(\d+)\s+bytes\s+by\s+task\s+\d+\s+on\s+cpu\s+\d+\s*:\s*$/;
// A stack frame: ` funcname+0x2d4/0x680 fs/ext4/inode.c:5876` (file:line optional).
const FRAME_RE = /^\s+([A-Za-z_][A-Za-z0-9_.]*)\+0x[0-9a-fA-F]+\/0x[0-9a-fA-F]+(?:\s+(\S+):(\d+))?/;
const VALUE_CHANGED_RE = /value changed:\s*(0x[0-9a-fA-F]+)\s*->\s*(0x[0-9a-fA-F]+)/i;

/** Split the header `FUNC1 / FUNC2` (or a single `FUNC`) into its two names. */
function parseHeaderFns(header: string): [string, string] {
  const parts = header.split("/").map((s) => s.trim()).filter(Boolean);
  if (parts.length >= 2) return [parts[0], parts[1]];
  // Same-function race (`data-race in cfg80211_registered_device`): both sides
  // are the same symbol.
  return [parts[0] ?? "", parts[0] ?? ""];
}

/** Pull the top frame's fn/file/line out of a stack-frame line. */
function parseFrame(line: string): { fn: string; file?: string; line?: number } | undefined {
  const m = FRAME_RE.exec(line);
  if (!m) return undefined;
  return {
    fn: m[1],
    ...(m[2] ? { file: m[2] } : {}),
    ...(m[3] ? { line: parseInt(m[3], 10) } : {}),
  };
}

/**
 * Parse a KCSAN `data-race` report into a {@link KcsanRace}.
 *
 * Returns `undefined` when the text is not a KCSAN data-race report (no header),
 * so a caller can fail-soft on unrelated dmesg. Robust to:
 *  - `FUNC1 / FUNC2` and single-`FUNC` (same-function) races,
 *  - `read to`/`write to`/`read of` phrasings,
 *  - missing `file:line` on frames,
 *  - only one access block being present (rare; the second mirrors the header).
 */
export function parseKcsanReport(raw: string): KcsanRace | undefined {
  const header = HEADER_RE.exec(raw);
  if (!header) return undefined;
  const [fnA, fnB] = parseHeaderFns(header[1]);

  const lines = raw.split(/\r?\n/);
  const blocks: KcsanAccess[] = [];
  for (let i = 0; i < lines.length; i++) {
    const am = ACCESS_RE.exec(lines[i]);
    if (!am) continue;
    const access = am[1] as "read" | "write";
    const address = am[2];
    const size = parseInt(am[3], 10);
    const stack: string[] = [];
    let fn = "";
    let file: string | undefined;
    let ln: number | undefined;
    // Consume the indented stack frames that follow, until a blank/de-indented line.
    for (let j = i + 1; j < lines.length; j++) {
      const l = lines[j];
      if (!/^\s+\S/.test(l)) break;
      const frame = parseFrame(l);
      if (!frame) {
        // A non-frame indented line (e.g. an inlined annotation) ends the stack.
        if (stack.length > 0) break;
        continue;
      }
      stack.push(frame.file ? `${frame.fn} ${frame.file}:${frame.line}` : frame.fn);
      if (!fn) {
        fn = frame.fn;
        file = frame.file;
        ln = frame.line;
      }
    }
    blocks.push({
      fn,
      ...(file ? { file } : {}),
      ...(ln !== undefined ? { line: ln } : {}),
      access,
      size,
      address,
      stack,
    });
  }

  // Assign the two sides in REPORT ORDER (side A = the first printed access
  // block, side B = the second) — the intuitive "write then read" as dmesg shows
  // it. KCSAN's header `A / B` is sorted ALPHABETICALLY (kernel/kcsan/report.c),
  // so it does NOT track block order; the header names are used only for the
  // finding title (`fnA`/`fnB`). Fall back to a header-only side when a block is
  // missing (degraded report). Prefer the block's own frame fn when present.
  const a = blocks[0] ?? headerOnlyAccess(fnA);
  const b = blocks[1] ?? headerOnlyAccess(fnB);
  if (!a.fn) a.fn = fnA;
  if (!b.fn) b.fn = fnB;

  const valueChanged = VALUE_CHANGED_RE.exec(raw);
  const object = a.address ?? b.address;

  return {
    a,
    b,
    ...(object ? { object } : {}),
    ...(valueChanged ? { valueChanged: { from: valueChanged[1], to: valueChanged[2] } } : {}),
    raw,
  };
}

/** Degraded fallback: header gave us a name but no access block was parsed. */
function headerOnlyAccess(fn: string): KcsanAccess {
  return { fn, stack: fn ? [fn] : [] };
}
