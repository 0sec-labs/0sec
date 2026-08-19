/**
 * `xnu-fuzz` — 0sec IOKit user-client fuzzer (dynamic sibling to `xnu-re`).
 * Public surface. Design: docs/0sec-iokit-fuzzer.md.
 *
 * Pipeline: extract (reused xnu-re-extract.sh) → MODEL (§1, this module) →
 * GENERATE (§2, this module) → run in the macOS-VM lane (§3, this module) →
 * triage (future). The model + generators run statically/locally; the VM lane
 * is built but must run on a beefier Apple-Silicon Mac (see harness.ts).
 */

// §1 — target enumeration / dispatch-table model
export {
  VARIABLE_SIZE,
  DISPATCH2022,
  isVariable,
  type SelectorModel,
  type UserClientModel,
  type TargetModel,
  type XnuArtifactReference,
  type XnuTargetReference,
} from "./types.js";
export {
  parseDispatchTable,
  dispatchTableByteLength,
  tableMetrics,
  selectorModelToLine,
  type ParseDispatchOptions,
} from "./dispatch-table.js";
export {
  enumerateTargetModel,
  enumerateTargetModelFromKext,
  createR2Backend,
  parseSelectorMapText,
  parseNestedName,
  isDispatchTableSymbol,
  type R2Backend,
  type R2Symbol,
  type R2Section,
  type EnumerateOptions,
} from "./enumerate.js";

// §2 — input generation
export {
  makeRng,
  generateBaseInput,
  generateInputsForSelector,
  variableLengthSchedule,
  mutateStructured,
  havoc,
  lengthBoundaryValues,
  mutantBudget,
  type Rng,
  type FuzzInput,
  type GenerateOptions,
  type FieldKind,
  type FieldSpec,
  type StructGrammar,
} from "./input-gen.js";

// §3.2 — host↔guest program wire format
export {
  encodeProgram,
  decodeProgram,
  PROGRAM_MAGIC,
  PROGRAM_VERSION,
  type ProgramCall,
} from "./program.js";

// §3.3 — non-executing artifact receipt, replay, and deduplication
export {
  XNU_RECEIPT_SCHEMA_VERSION,
  xnuArtifactDigest,
  createXnuFuzzReceipt,
  validateXnuFuzzReceipt,
  XnuReceiptReplayer,
  type XnuFuzzReceipt,
  type XnuReceiptReplayOutcome,
  type CreateXnuFuzzReceiptInput,
  type XnuReceiptArtifacts,
} from "./receipt.js";

// §3 — macOS-VM execution lane
export {
  TartVmLane,
  planSingleShardRun,
  type VmLaneConfig,
  type CommandRunner,
  type ShardSpec,
  type ShardRunResult,
  type PanicReport,
} from "./harness.js";
