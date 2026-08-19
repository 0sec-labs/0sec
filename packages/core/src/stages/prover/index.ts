/**
 * Prover plugins — the executable counterpart to `stages/format-knowledge.ts`.
 *
 * `format-knowledge.ts` tells the craft agent what a container looks like.
 * These plugins build one, and tell the agent whether the bytes it produced are
 * well-formed enough for a parser to walk into the vulnerable code. See
 * `types.ts` for the full rationale (MDASH's 65.4% "Prove" failure bucket, and
 * the framing-vs-semantics rule that keeps a repairer from deleting the bug it
 * is supposed to help prove).
 */

export type {
  ConstructErr,
  ConstructOk,
  ConstructRequest,
  ConstructResult,
  ProverContext,
  ProverMatch,
  ProverPlugin,
  ProverServices,
  RepairRecord,
  ValidationDefect,
  ValidationReport,
} from "./types.js";

export {
  PROVER_PLUGIN_BY_ID,
  PROVER_PLUGIN_REGISTRY,
  getProverPluginById,
  listProverPluginIds,
  rankProverPlugins,
  selectProverPlugin,
  type ProverSelection,
} from "./registry.js";

export { pngProverPlugin } from "./png.js";
export { mngProverPlugin } from "./mng.js";
export { zipProverPlugin } from "./zip.js";

export {
  PROVER_TOOL_NAMES,
  proverToolDefs,
  runProverConstruct,
  runProverTool,
  runProverValidate,
} from "./tool.js";
