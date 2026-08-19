/**
 * npm-ecosystem dynamic-discovery detectors — public surface.
 *
 * The extensible detector framework that turns confirmed novel bug classes into
 * ecosystem-scale detectors. See `docs/operations/sspp-dynamic-miner-design.md`
 * (what shipped) and `docs/operations/detector-from-finding.md` (how to add a
 * detector from a confirmed finding + PoC).
 */

export type {
  Detector,
  DetectorCandidate,
  DetectorConfirmation,
  DedupHints,
  DedupVerdict,
  PackageProbe,
  PackageRef,
} from "./types.js";
export {
  DETECTOR_REGISTRY,
  DETECTOR_REGISTRY_BY_ID,
  getDetectorById,
  listDetectorIds,
  resolveDetectors,
  type AnyDetector,
} from "./registry.js";
export {
  runDetectorOnPackage,
  guardPackage,
  type DiscoveryGuards,
  type DetectorLead,
  type DetectorRunOutcome,
  type GuardVerdict,
} from "./base.js";
export { dedupConfirmation, type AdvisoryLookup } from "./dedup.js";
export {
  createOsvAdvisoryLookup,
  deriveForkSiblings,
  OsvLookupError,
  type OsvLookupOptions,
} from "./osv-lookup.js";
export { inProcessProbe, staticProbe } from "./probe.js";
export {
  createSandboxPackageRunner,
  localSandboxProvider,
  type NpmPackageRunner,
  type PackageRunResult,
  type SandboxProvider,
  type SandboxSession,
  type SandboxCommandResult,
  type SandboxRunnerOptions,
} from "./sandbox-probe.js";

export { ssppFuzzDetector, fuzzCandidate, nameMatchesPpSink, pollutionSnapshot, type SsppCandidate } from "./sspp-fuzz.js";
export {
  readUnstableDetector,
  confirmReadUnstable,
  makePhasedField,
  type ReadUnstableCandidate,
  type PhasedField,
} from "./read-unstable.js";
export {
  parserDiffDetector,
  confirmParserDiff,
  scanDivergences,
  inetAton,
  classify,
  isUnsafe,
  PARSER_DIFF_CORPUS,
  type ParserDiffCandidate,
} from "./parser-diff.js";
