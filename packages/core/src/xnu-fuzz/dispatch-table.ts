/**
 * `xnu-fuzz` §1 core: the pure `IOExternalMethodDispatch2022` byte decoder.
 *
 * This is deliberately a PURE function over raw bytes — no r2, no I/O — so it
 * is unit-testable with synthetic and real-kext byte slices, and so the noisy
 * part (locating + dumping the table, which needs r2) is isolated in
 * `enumerate.ts`. The layout is grounded in the real IOSurface kext (see the
 * test fixture decoded from `IOSurfaceRootUserClient::sMethodDescs`).
 */

import { DISPATCH2022, VARIABLE_SIZE, type SelectorModel } from "./types.js";

/** Number of bytes a dispatch table of `count` entries occupies. */
export function dispatchTableByteLength(count: number): number {
  return count * DISPATCH2022.STRIDE;
}

export interface ParseDispatchOptions {
  /** Number of `IOExternalMethodDispatch2022` entries to decode. */
  count: number;
  /**
   * Optional resolver for the arm64e chained-fixup function pointer. Inside a
   * cache the +0x00 field is fixup-encoded, not a clean vaddr; only the
   * in-place-kernelcache lane (or ipsw fixup application) can resolve it. When
   * omitted we record `handlerRaw` and leave `handler` undefined — honest about
   * what a standalone-kext decode can and cannot ground.
   */
  resolveHandler?: (rawFunctionField: bigint, selectorIndex: number) => string | undefined;
}

function u32(view: DataView, off: number): number {
  return view.getUint32(off, /* littleEndian */ true);
}

/**
 * Decode a packed array of `IOExternalMethodDispatch2022` structs into the
 * per-selector input model. `buf` must contain at least `count * 0x28` bytes.
 */
export function parseDispatchTable(
  buf: Uint8Array,
  opts: ParseDispatchOptions,
): SelectorModel[] {
  const { count } = opts;
  if (count < 0) throw new RangeError(`dispatch entry count must be >= 0, got ${count}`);
  const need = dispatchTableByteLength(count);
  if (buf.byteLength < need) {
    throw new RangeError(
      `dispatch buffer too small: need ${need} bytes for ${count} entries, got ${buf.byteLength}`,
    );
  }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const out: SelectorModel[] = [];

  for (let sel = 0; sel < count; sel++) {
    const base = sel * DISPATCH2022.STRIDE;
    const rawFn = view.getBigUint64(base + DISPATCH2022.OFF_FUNCTION, true);
    const scalarInCnt = u32(view, base + DISPATCH2022.OFF_SCALAR_IN_CNT);
    const structInSize = u32(view, base + DISPATCH2022.OFF_STRUCT_IN_SIZE);
    const scalarOutCnt = u32(view, base + DISPATCH2022.OFF_SCALAR_OUT_CNT);
    const structOutSize = u32(view, base + DISPATCH2022.OFF_STRUCT_OUT_SIZE);
    const allowAsync = (buf[base + DISPATCH2022.OFF_ALLOW_ASYNC] ?? 0) !== 0;
    const entitlementPtr = view.getBigUint64(base + DISPATCH2022.OFF_CHECK_ENTITLEMENT, true);

    const handler = opts.resolveHandler?.(rawFn, sel);
    const entry: SelectorModel = {
      sel,
      handlerRaw: "0x" + rawFn.toString(16).padStart(16, "0"),
      scalarInCnt,
      structInSize,
      scalarOutCnt,
      structOutSize,
      allowAsync,
      hasEntitlementCheck: entitlementPtr !== 0n,
    };
    if (handler) entry.handler = handler;
    out.push(entry);
  }
  return out;
}

/** §6 prioritization metrics, computed for free from a decoded table. */
export function tableMetrics(selectors: SelectorModel[]): {
  selectorCount: number;
  varSizeSelectorCount: number;
} {
  let varSizeSelectorCount = 0;
  for (const s of selectors) {
    if (s.structInSize === VARIABLE_SIZE || s.structOutSize === VARIABLE_SIZE) {
      varSizeSelectorCount++;
    }
  }
  return { selectorCount: selectors.length, varSizeSelectorCount };
}

/**
 * Render one decoded selector in the human-readable ground-truth format used by
 * the prior xnu-re hunt (`selector_map_A.txt`) — for display and cross-check.
 */
export function selectorModelToLine(s: SelectorModel): string {
  const sz = (n: number) => (n === VARIABLE_SIZE ? "VAR" : String(n));
  const addr = s.handler ?? s.handlerRaw ?? "0x?";
  const tail =
    s.structInSize === VARIABLE_SIZE || s.structOutSize === VARIABLE_SIZE ? "  <== VAR-SIZE" : "";
  return (
    `sel ${String(s.sel).padStart(2)} ${addr} ` +
    `scIn=${s.scalarInCnt} stIn=${sz(s.structInSize)} ` +
    `scOut=${s.scalarOutCnt} stOut=${sz(s.structOutSize)}${tail}`
  );
}
