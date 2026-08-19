/**
 * `xnu-fuzz` §1 enumeration: locate every `IOUserClient` dispatch table in a
 * kext, decode it, and emit the `target-model.json` contract.
 *
 * The decode itself is the pure `parseDispatchTable` (`dispatch-table.ts`).
 * This file is the I/O around it: it drives radare2 to (a) list the
 * `::sMethodDescs` table symbols, (b) bound each table's entry count from the
 * next symbol / section end, and (c) dump the raw struct bytes — all lightweight
 * r2 queries (`is`, `iS`, `p8`), NOT a full `aaa` analysis, so it stays cheap.
 *
 * r2 is abstracted behind `R2Backend` so the assembly logic is unit-testable
 * with a fake backend (no radare2, no kernelcache in CI). The live backend is
 * `createR2Backend`.
 */

import { execFileSync } from "node:child_process";
import { DISPATCH2022, VARIABLE_SIZE, type SelectorModel, type TargetModel, type UserClientModel } from "./types.js";
import { parseDispatchTable, tableMetrics } from "./dispatch-table.js";

// ── C++ symbol handling ──────────────────────────────────────────────────

/**
 * Parse an Itanium nested-name mangling of the shape `__ZN<len><id>…E` into its
 * components. Dispatch-table symbols are simple (`IOSurfaceRootUserClient` +
 * `sMethodDescs`), no templates/substitutions, so this minimal decoder is
 * sufficient and deterministic.
 *
 * `__ZN23IOSurfaceRootUserClient12sMethodDescsE` -> ["IOSurfaceRootUserClient","sMethodDescs"]
 */
export function parseNestedName(mangled: string): string[] | null {
  let s = mangled;
  if (!s.startsWith("__ZN")) return null;
  s = s.slice(4);
  const parts: string[] = [];
  while (s.length > 0 && s[0] !== "E") {
    const m = /^(\d+)/.exec(s);
    if (!m) return null;
    const len = parseInt(m[1]!, 10);
    const start = m[1]!.length;
    const id = s.slice(start, start + len);
    if (id.length !== len) return null;
    parts.push(id);
    s = s.slice(start + len);
  }
  return parts.length ? parts : null;
}

/** True if a mangled/demangled symbol names an IOKit dispatch table. */
export function isDispatchTableSymbol(name: string): boolean {
  // Matches sMethods, sMethodDescs, and sMethodDescsRestricted (also inside an
  // Itanium mangling like `__ZN3Foo8sMethodsE`, where a `\b` would not match).
  return /sMethodDescs|sMethods/.test(name);
}

// ── r2 backend ───────────────────────────────────────────────────────────

export interface R2Symbol {
  name: string;
  vaddr: bigint;
}
export interface R2Section {
  name: string;
  vaddr: bigint;
  vsize: bigint;
}

/** The narrow surface `enumerateTargetModel` needs from radare2. */
export interface R2Backend {
  symbols(): R2Symbol[];
  sections(): R2Section[];
  readBytes(vaddr: bigint, len: number): Uint8Array;
}

function r2(kextPath: string, command: string): string {
  return execFileSync("r2", ["-e", "log.quiet=true", "-e", "scr.color=0", "-qc", command, kextPath], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
}

const HEX = /0x[0-9a-fA-F]+/g;

/**
 * Live radare2 backend. Uses text `is` / `iS` (parsing addresses as hex strings
 * to preserve full 64-bit precision — `isj` emits vaddr as a lossy JS number)
 * and `p8` for raw bytes.
 */
export function createR2Backend(kextPath: string): R2Backend {
  return {
    symbols(): R2Symbol[] {
      const out: R2Symbol[] = [];
      for (const line of r2(kextPath, "is").split("\n")) {
        // columns: <n> <paddr> <vaddr> <bind> <type> <size> <name> [demangled…]
        const cols = line.trim().split(/\s+/);
        if (cols.length < 7) continue;
        const vaddr = cols[2];
        const name = cols[6];
        if (!vaddr?.startsWith("0x") || !name) continue;
        out.push({ name, vaddr: BigInt(vaddr) });
      }
      return out;
    },
    sections(): R2Section[] {
      const out: R2Section[] = [];
      for (const line of r2(kextPath, "iS").split("\n")) {
        if (!/__DATA|__const|__data/.test(line)) continue;
        const hexes = line.match(HEX);
        if (!hexes || hexes.length < 4) continue;
        const big = hexes.map((h) => BigInt(h));
        // vaddr = the kernel-space address (>= 0xffff_0000_0000_0000-ish);
        // vsize = the largest small (< 0x1_0000_0000) hex on the line.
        const vaddr = big.find((b) => b > 0xffff_0000_0000n) ?? big[2]!;
        const name = line.trim().split(/\s+/).pop() ?? "";
        const small = big.filter((b) => b < 0x1_0000_0000n);
        const vsize = small.length ? small.reduce((a, b) => (b > a ? b : a)) : 0n;
        out.push({ name, vaddr, vsize });
      }
      return out;
    },
    readBytes(vaddr: bigint, len: number): Uint8Array {
      const hex = r2(kextPath, `p8 ${len} @ 0x${vaddr.toString(16)}`).replace(/[^0-9a-fA-F]/g, "");
      const n = Math.floor(hex.length / 2);
      const buf = new Uint8Array(Math.min(n, len));
      for (let i = 0; i < buf.length; i++) buf[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      return buf;
    },
  };
}

// ── enumeration ──────────────────────────────────────────────────────────

export interface EnumerateOptions {
  /** Kext bundle id for the model (`com.apple.iokit.IOSurface`). */
  kext: string;
  /** Source path (kext binary or kernelcache) recorded in the model. */
  source: string;
  /** Hard cap on entries per table when no bound can be derived (default 512). */
  maxEntries?: number;
  /** Optional fixup resolver for the handler vaddr (in-place-kernelcache lane). */
  resolveHandler?: (rawFunctionField: bigint, selectorIndex: number) => string | undefined;
}

interface TableLoc {
  symbol: string;
  className: string;
  member: string;
  vaddr: bigint;
}

/**
 * Derive each dispatch table's entry count by the delta to the next symbol
 * (any symbol), capped at the containing section's end. The dispatch struct
 * stride (0x28) divides these spans exactly for real tables, which is the
 * built-in sanity check.
 */
function deriveCounts(
  tables: TableLoc[],
  allSymbolVaddrs: bigint[],
  sections: R2Section[],
  maxEntries: number,
): Map<bigint, number> {
  const sorted = [...new Set(allSymbolVaddrs)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const counts = new Map<bigint, number>();
  for (const t of tables) {
    const next = sorted.find((v) => v > t.vaddr);
    const sec = sections.find((s) => t.vaddr >= s.vaddr && t.vaddr < s.vaddr + s.vsize);
    const secEnd = sec ? sec.vaddr + sec.vsize : undefined;
    let end = next ?? secEnd;
    if (secEnd !== undefined && (end === undefined || end > secEnd)) end = secEnd;
    let count = end !== undefined ? Number((end - t.vaddr) / BigInt(DISPATCH2022.STRIDE)) : maxEntries;
    if (count < 0) count = 0;
    if (count > maxEntries) count = maxEntries;
    counts.set(t.vaddr, count);
  }
  return counts;
}

/**
 * Build the `target-model.json` for one kext from an `R2Backend`. Pure over the
 * backend, so a fake backend exercises the whole assembly path in tests.
 */
export function enumerateTargetModel(backend: R2Backend, opts: EnumerateOptions): TargetModel {
  const maxEntries = opts.maxEntries ?? 512;
  const symbols = backend.symbols();
  const sections = backend.sections();

  const tables: TableLoc[] = [];
  for (const sym of symbols) {
    if (!isDispatchTableSymbol(sym.name)) continue;
    const comps = parseNestedName(sym.name);
    const className = comps && comps.length >= 2 ? comps.slice(0, -1).join("::") : sym.name;
    const member = comps && comps.length >= 1 ? comps[comps.length - 1]! : sym.name;
    tables.push({ symbol: sym.name, className, member: member ?? sym.name, vaddr: sym.vaddr });
  }

  const counts = deriveCounts(
    tables,
    symbols.map((s) => s.vaddr),
    sections,
    maxEntries,
  );

  const byClass = new Map<string, UserClientModel>();
  for (const t of tables) {
    const count = counts.get(t.vaddr) ?? 0;
    if (count === 0) continue;
    const bytes = backend.readBytes(t.vaddr, count * DISPATCH2022.STRIDE);
    const usable = Math.floor(bytes.byteLength / DISPATCH2022.STRIDE);
    const selectors = parseDispatchTable(bytes, {
      count: Math.min(count, usable),
      resolveHandler: opts.resolveHandler,
    });
    const metrics = tableMetrics(selectors);
    const uc: UserClientModel = {
      class: t.className,
      table: t.member,
      selectors,
      varSizeSelectorCount: metrics.varSizeSelectorCount,
      selectorCount: metrics.selectorCount,
    };
    // One class can own multiple tables (sMethodDescs + …Restricted); keep the
    // largest as the primary, expose the rest as siblings via class suffix.
    const key = `${t.className}::${t.member}`;
    byClass.set(key, uc);
  }

  return {
    kext: opts.kext,
    source: opts.source,
    abi: "IOExternalMethodDispatch2022",
    userClients: [...byClass.values()].sort((a, b) => b.selectorCount - a.selectorCount),
  };
}

/** Convenience wrapper: enumerate straight from a kext binary path via live r2. */
export function enumerateTargetModelFromKext(kextPath: string, opts: EnumerateOptions): TargetModel {
  return enumerateTargetModel(createR2Backend(kextPath), opts);
}

// ── ground-truth text cross-check ──────────────────────────────────────────

/**
 * Parse the human selector-map format the prior xnu-re hunt produced
 * (`selector_map_A.txt`): `sel N 0x.. scIn=.. stIn=.. scOut=.. stOut=..`,
 * `VAR` => VARIABLE_SIZE. Used to cross-validate the byte decoder against the
 * known-good map without needing r2 in CI.
 */
export function parseSelectorMapText(text: string): SelectorModel[] {
  const out: SelectorModel[] = [];
  const re =
    /^\s*sel\s+(\d+)\s+(0x[0-9a-fA-F]+)\s+scIn=(\d+)\s+stIn=(VAR|\d+)\s+scOut=(\d+)\s+stOut=(VAR|\d+)/;
  const sz = (v: string) => (v === "VAR" ? VARIABLE_SIZE : parseInt(v, 10));
  for (const line of text.split("\n")) {
    const m = re.exec(line);
    if (!m) continue;
    out.push({
      sel: parseInt(m[1]!, 10),
      handler: m[2],
      scalarInCnt: parseInt(m[3]!, 10),
      structInSize: sz(m[4]!),
      scalarOutCnt: parseInt(m[5]!, 10),
      structOutSize: sz(m[6]!),
    });
  }
  return out;
}
