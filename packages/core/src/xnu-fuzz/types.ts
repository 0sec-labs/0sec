/**
 * `xnu-fuzz` — shared types for the 0sec IOKit user-client fuzzer.
 *
 * Design: docs/0sec-iokit-fuzzer.md. This module is the DYNAMIC sibling to
 * the static `xnu-re` review profile: it consumes the same kernelcache /
 * kext-extraction output and models, per user client, exactly what the
 * post-2022 `IOExternalMethodDispatch2022` marshalling gate will accept — so
 * every generated input lands INSIDE a real handler instead of bouncing off
 * `kIOReturnBadArgument`.
 *
 * The byte layout below is confirmed against the real
 * `com.apple.iokit.IOSurface` kext (`IOSurfaceRootUserClient::sMethodDescs`,
 * 63 selectors). See `dispatch-table.ts`.
 */

/**
 * `0xffffffff` sentinel in a dispatch struct's size/count field = "don't
 * check" = variable-length. Per the design doc (§1.1) this is also the single
 * strongest prioritization signal: variable-size struct inputs are where the
 * length-handling bugs concentrate.
 */
export const VARIABLE_SIZE = 0xffffffff;

/**
 * Packed layout of `IOExternalMethodDispatch2022` (arm64e), one array element
 * of an `sMethods` / `sMethodDescs` table. Stride 0x28 (40 bytes), confirmed
 * empirically against IOSurface:
 *
 *   +0x00  function (8)            — handler pointer, arm64e chained-fixup
 *                                    encoded inside the cache (NOT a clean
 *                                    vaddr until fixups are resolved)
 *   +0x08  checkScalarInputCount   (u32)
 *   +0x0c  checkStructureInputSize (u32)   VARIABLE_SIZE => variable
 *   +0x10  checkScalarOutputCount  (u32)
 *   +0x14  checkStructureOutputSize(u32)   VARIABLE_SIZE => variable
 *   +0x18  allowAsync (u8) + 7 pad
 *   +0x20  checkEntitlement (8)    — pointer to entitlement string, or 0
 */
export const DISPATCH2022 = {
  STRIDE: 0x28,
  OFF_FUNCTION: 0x00,
  OFF_SCALAR_IN_CNT: 0x08,
  OFF_STRUCT_IN_SIZE: 0x0c,
  OFF_SCALAR_OUT_CNT: 0x10,
  OFF_STRUCT_OUT_SIZE: 0x14,
  OFF_ALLOW_ASYNC: 0x18,
  OFF_CHECK_ENTITLEMENT: 0x20,
} as const;

/** True if a dispatch size/count field is the variable-length sentinel. */
export function isVariable(size: number): boolean {
  return size === VARIABLE_SIZE;
}

/**
 * One selector's accepted-input contract, decoded from a dispatch-table entry.
 * This is the per-selector half of the "valid-input model" §1 builds; it is
 * the contract the generator (§2) turns into gate-passing inputs.
 */
export interface SelectorModel {
  /** Selector index = position in the `sMethods` array = the `selector` arg. */
  sel: number;
  /** Resolved handler vaddr (hex) when fixups were applied; else undefined. */
  handler?: string;
  /** Raw 8-byte function field (hex, little-endian) before fixup resolution. */
  handlerRaw?: string;
  /** Exact count of uint64 scalars the gate requires. */
  scalarInCnt: number;
  /** Exact structureInput byte size, or VARIABLE_SIZE for variable-length. */
  structInSize: number;
  scalarOutCnt: number;
  /** structureOutput byte size, or VARIABLE_SIZE for variable-length. */
  structOutSize: number;
  allowAsync?: boolean;
  /** True if the entry carries a non-null entitlement-check pointer. */
  hasEntitlementCheck?: boolean;
  notes?: string[];
}

/** One `IOUserClient` subclass and its decoded selector table. */
export interface UserClientModel {
  /** Demangled C++ class name (the `IOServiceOpen` target). */
  class: string;
  /** Dispatch-table symbol (`sMethodDescs`, `sMethodDescsRestricted`, …). */
  table: string;
  /** Matching service name, when known. */
  matchingService?: string;
  selectors: SelectorModel[];
  /** §6 prioritization: count of variable-size selectors (sentinel density). */
  varSizeSelectorCount: number;
  /** Total selector count (the dispatch COUNT bound). */
  selectorCount: number;
}

/** The `target-model.json` contract between enumeration (§1) and generation (§2). */
export interface TargetModel {
  /** Kext bundle id, e.g. `com.apple.iokit.IOSurface`. */
  kext: string;
  /** Path the model was extracted from (kext binary or kernelcache). */
  source: string;
  abi: "IOExternalMethodDispatch2022";
  userClients: UserClientModel[];
}

/** Immutable reference to an exact byte artifact recorded in an XNU receipt. */
export interface XnuArtifactReference {
  id: string;
  digest: string;
  byteLength: number;
}

/** Immutable reference to the target model a receipt was generated against. */
export interface XnuTargetReference {
  id: string;
  digest: string;
}
