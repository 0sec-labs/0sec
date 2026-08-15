import { createHash } from "node:crypto";
import { closeSync, fstatSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { constants as fsConstants } from "node:fs";
import { join, resolve } from "node:path";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

const RESULT_SCHEMA = "0verse.windows-variant/v1";
const PROOF_LIMIT = "Static lexical guard-delta evidence only. This result cannot establish a crash, security impact, exploitability, novelty, or bounty eligibility.";
const SHA256 = /^[a-f0-9]{64}$/;
const ADDRESS = /^(?:|0x[0-9a-f]+)$/;
const MAX_MANIFEST_BYTES = 16 * 1024 * 1024;
const MAX_RESULT_BYTES = 32 * 1024 * 1024;
const MAX_TIMEOUT_MS = 300_000;
const REACHABILITY = new Set(["unknown", "unprivileged-ioctl", "ordinary-child", "root-only", "internal-only"]);
const SINKS = new Set([
  "copy", "fill", "indexed-store",
  // CWE-59 link-following family (privileged path-resolution sinks)
  "file-open", "file-mutate", "registry-hive", "image-load",
]);
const GUARDS = new Set([
  "bounds", "checked-arithmetic", "probe-read", "probe-write", "previous-mode", "privilege", "partition-capability",
  // CWE-59 link-resolution guards
  "no-reparse-open", "reparse-check", "final-path-verify", "client-impersonation",
]);

export interface WindowsVariantArtifactBinding {
  binarySha256: string;
  ghidraExportSha256: string;
  pdbIdentity: string;
  pdbSha256: string;
  analysisReceiptSha256: string;
  ghidraVersion: string;
  cacheKey: string;
  syntheticFixture: boolean;
}

export interface WindowsVariantTargetConfig {
  expectedCampaignSha256: string;
  expectedSeedFunction: string;
  expectedArtifacts: {
    vulnerable: WindowsVariantArtifactBinding;
    fixed: WindowsVariantArtifactBinding;
    current: WindowsVariantArtifactBinding;
  };
  timeoutMs?: number;
}

export type WindowsVariantTarget = ResearchTarget<
  "windows.binary-variant",
  WindowsVariantTargetConfig
>;

export interface WindowsVariantRankRequest {
  manifestPath: string;
  timeoutMs: number;
  signal?: AbortSignal;
}

export interface WindowsVariantRankExecution {
  stdout: Uint8Array;
  stderr?: string;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
}

export type WindowsVariantRankRunner = (
  request: Readonly<WindowsVariantRankRequest>,
) => Promise<Readonly<WindowsVariantRankExecution>>;

interface ArtifactRecord {
  binary_sha256: string;
  ghidra_export_sha256: string;
  pdb_identity: string;
  pdb_sha256: string;
  analysis_receipt_sha256: string;
  ghidra_version: string;
  cache_key: string;
  synthetic_fixture: boolean;
}

interface VariantRow {
  function: string;
  function_address: string;
  status: "candidate";
  score: number;
  matched_sinks: string[];
  missing_seed_guards: string[];
  present_guards: string[];
  lexical_parameter_sink_hint: string[];
  reachability_grade: string;
  reachability_evidence: string;
  required_next_validator: string;
  rank: number;
}

interface WindowsVariantResult {
  schema_version: typeof RESULT_SCHEMA;
  campaign_sha256: string;
  seed: {
    function: string;
    reference: string;
    guard_delta: string[];
    sink_geometry: string[];
    vulnerable: ArtifactRecord;
    fixed: ArtifactRecord;
  };
  current: ArtifactRecord;
  candidate_count: number;
  candidates: VariantRow[];
  proof_limit: typeof PROOF_LIMIT;
  all_results_are_candidates: true;
  weaponization: false;
  automatic_disclosure: false;
}

export type WindowsVariantCandidate = ResearchCandidate<{
  row: VariantRow;
  campaignSha256: string;
  resultSha256: string;
  seed: WindowsVariantResult["seed"];
  current: ArtifactRecord;
}>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exact(value: unknown, fields: readonly string[], label: string): asserts value is Record<string, unknown> {
  if (!isRecord(value) || Object.keys(value).length !== fields.length
    || Object.keys(value).some((field) => !fields.includes(field))) {
    throw new Error(`${label} has unexpected fields`);
  }
}

function sha(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new Error(`${label} must be lowercase SHA-256`);
  return value;
}

function text(value: unknown, label: string, maximum = 1024): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || value.includes("\0")) {
    throw new Error(`${label} must be bounded nonempty text`);
  }
  return value;
}

function symbol(value: unknown, label: string): string {
  const name = text(value, label, 512);
  if ([...name].some((character) => character.charCodeAt(0) < 0x20 || character === "\u007f")) {
    throw new Error(`${label} contains control characters`);
  }
  return name;
}

function sortedUniqueStrings(value: unknown, label: string, nonempty = false): string[] {
  if (!Array.isArray(value) || (nonempty && value.length === 0)
    || value.some((item) => typeof item !== "string" || !item || item.includes("\0"))) {
    throw new Error(`${label} must be an array of bounded strings`);
  }
  const items = value as string[];
  if (new Set(items).size !== items.length
    || items.some((item, index) => index > 0 && items[index - 1]! > item)) {
    throw new Error(`${label} must be sorted and duplicate-free`);
  }
  return items;
}

function parseArtifact(value: unknown, expected: WindowsVariantArtifactBinding, label: string): ArtifactRecord {
  const fields = ["binary_sha256", "ghidra_export_sha256", "pdb_identity", "pdb_sha256", "analysis_receipt_sha256", "ghidra_version", "cache_key", "synthetic_fixture"] as const;
  exact(value, fields, label);
  const record: ArtifactRecord = {
    binary_sha256: sha(value.binary_sha256, `${label}.binary_sha256`),
    ghidra_export_sha256: sha(value.ghidra_export_sha256, `${label}.ghidra_export_sha256`),
    pdb_identity: typeof value.pdb_identity === "string" ? value.pdb_identity : "!",
    pdb_sha256: typeof value.pdb_sha256 === "string" ? value.pdb_sha256 : "",
    analysis_receipt_sha256: sha(value.analysis_receipt_sha256, `${label}.analysis_receipt_sha256`),
    ghidra_version: text(value.ghidra_version, `${label}.ghidra_version`, 128),
    cache_key: text(value.cache_key, `${label}.cache_key`, 128),
    synthetic_fixture: value.synthetic_fixture === true,
  };
  if (typeof value.synthetic_fixture !== "boolean" || record.pdb_identity.length > 512
    || record.pdb_identity.includes("\0") || record.cache_key !== record.binary_sha256.slice(0, 16)
    || (record.synthetic_fixture && (record.pdb_identity !== "" || record.pdb_sha256 !== ""))
    || (!record.synthetic_fixture && (!record.pdb_identity || !SHA256.test(record.pdb_sha256)))) {
    throw new Error(`${label} has invalid PDB or fixture fields`);
  }
  const expectedRecord: ArtifactRecord = {
    binary_sha256: expected.binarySha256,
    ghidra_export_sha256: expected.ghidraExportSha256,
    pdb_identity: expected.pdbIdentity,
    pdb_sha256: expected.pdbSha256,
    analysis_receipt_sha256: expected.analysisReceiptSha256,
    ghidra_version: expected.ghidraVersion,
    cache_key: expected.cacheKey,
    synthetic_fixture: expected.syntheticFixture,
  };
  if (JSON.stringify(record) !== JSON.stringify(expectedRecord)) {
    throw new Error(`${label} differs from the target-config artifact binding`);
  }
  return record;
}

function nextValidator(grade: string): string {
  return grade === "root-only" || grade === "internal-only"
    ? "do not dynamically test unless a supported non-root caller is established"
    : "establish a supported unprivileged or ordinary-child caller before dynamic testing";
}

function parseCandidate(
  value: unknown,
  index: number,
  guardDelta: Set<string>,
  sinkGeometry: Set<string>,
  seedFunction: string,
): VariantRow {
  const fields = ["function", "function_address", "status", "score", "matched_sinks", "missing_seed_guards", "present_guards", "lexical_parameter_sink_hint", "reachability_grade", "reachability_evidence", "required_next_validator", "rank"] as const;
  exact(value, fields, `candidate[${index}]`);
  const functionName = symbol(value.function, `candidate[${index}].function`);
  const address = typeof value.function_address === "string" ? value.function_address : "!";
  const score = value.score;
  const rank = value.rank;
  const grade = value.reachability_grade;
  const evidence = typeof value.reachability_evidence === "string" ? value.reachability_evidence : "";
  if (functionName === seedFunction || !ADDRESS.test(address)
    || value.status !== "candidate" || !Number.isInteger(score) || (score as number) < 0 || (score as number) > 100
    || rank !== index + 1 || typeof grade !== "string" || !REACHABILITY.has(grade)
    || (grade !== "unknown" && !evidence.trim()) || evidence.includes("\0")
    || value.required_next_validator !== nextValidator(String(grade))) {
    throw new Error(`candidate[${index}] has invalid identity, score, rank, or reachability`);
  }
  const matched = sortedUniqueStrings(value.matched_sinks, `candidate[${index}].matched_sinks`, true);
  const missing = sortedUniqueStrings(value.missing_seed_guards, `candidate[${index}].missing_seed_guards`, true);
  const present = sortedUniqueStrings(value.present_guards, `candidate[${index}].present_guards`);
  const hint = sortedUniqueStrings(value.lexical_parameter_sink_hint, `candidate[${index}].lexical_parameter_sink_hint`);
  if (matched.some((item) => !sinkGeometry.has(item)) || missing.some((item) => !guardDelta.has(item))
    || present.some((item) => !GUARDS.has(item))
    || (hint.length !== 0 && (hint.length !== 2
      || !/^parameter:[A-Za-z_][A-Za-z0-9_]*$/.test(hint[0]!)
      || !SINKS.has(hint[1]!.slice("sink:".length)) || !hint[1]!.startsWith("sink:")))) {
    throw new Error(`candidate[${index}] is not a subset of seed geometry or has an invalid lexical hint`);
  }
  return {
    function: functionName,
    function_address: address,
    status: "candidate",
    score: score as number,
    matched_sinks: matched,
    missing_seed_guards: missing,
    present_guards: present,
    lexical_parameter_sink_hint: hint,
    reachability_grade: grade,
    reachability_evidence: evidence,
    required_next_validator: String(value.required_next_validator),
    rank: rank as number,
  };
}

function parseResult(value: unknown, config: WindowsVariantTargetConfig): WindowsVariantResult {
  const topFields = ["schema_version", "campaign_sha256", "seed", "current", "candidate_count", "candidates", "proof_limit", "all_results_are_candidates", "weaponization", "automatic_disclosure"] as const;
  exact(value, topFields, "Windows variant result");
  if (value.schema_version !== RESULT_SCHEMA || value.campaign_sha256 !== config.expectedCampaignSha256
    || value.proof_limit !== PROOF_LIMIT || value.all_results_are_candidates !== true
    || value.weaponization !== false || value.automatic_disclosure !== false) {
    throw new Error("Windows variant result schema, campaign, proof limit, or safety gates mismatch");
  }
  exact(value.seed, ["function", "reference", "guard_delta", "sink_geometry", "vulnerable", "fixed"], "seed");
  const seedFunction = symbol(value.seed.function, "seed.function");
  if (seedFunction !== config.expectedSeedFunction) throw new Error("seed function mismatch");
  const guardDelta = sortedUniqueStrings(value.seed.guard_delta, "seed.guard_delta", true);
  const sinkGeometry = sortedUniqueStrings(value.seed.sink_geometry, "seed.sink_geometry", true);
  if (guardDelta.some((guard) => !GUARDS.has(guard))
    || sinkGeometry.some((sink) => !SINKS.has(sink))) {
    throw new Error("seed guard or sink geometry is outside the v1 vocabulary");
  }
  const seed = {
    function: seedFunction,
    reference: text(value.seed.reference, "seed.reference", 4096),
    guard_delta: guardDelta,
    sink_geometry: sinkGeometry,
    vulnerable: parseArtifact(value.seed.vulnerable, config.expectedArtifacts.vulnerable, "seed.vulnerable"),
    fixed: parseArtifact(value.seed.fixed, config.expectedArtifacts.fixed, "seed.fixed"),
  };
  const current = parseArtifact(value.current, config.expectedArtifacts.current, "current");
  if (seed.vulnerable.binary_sha256 === seed.fixed.binary_sha256
    || seed.vulnerable.ghidra_export_sha256 === seed.fixed.ghidra_export_sha256) {
    throw new Error("vulnerable and fixed seed artifacts must be distinct");
  }
  if (!Array.isArray(value.candidates) || value.candidate_count !== value.candidates.length) {
    throw new Error("candidate_count does not match candidates");
  }
  const candidates = value.candidates.map((row, index) => parseCandidate(
    row, index, new Set(guardDelta), new Set(sinkGeometry), seedFunction,
  ));
  const sites = new Set<string>();
  for (let index = 0; index < candidates.length; index++) {
    const row = candidates[index]!;
    const site = `${row.function}\0${row.function_address}`;
    if (sites.has(site)) throw new Error("duplicate Windows variant candidate site");
    sites.add(site);
    const next = candidates[index + 1];
    if (next && (row.score < next.score || (row.score === next.score && row.function > next.function))) {
      throw new Error("Windows variant candidates are not in deterministic score order");
    }
  }
  return {
    schema_version: RESULT_SCHEMA,
    campaign_sha256: String(value.campaign_sha256),
    seed,
    current,
    candidate_count: candidates.length,
    candidates,
    proof_limit: PROOF_LIMIT,
    all_results_are_candidates: true,
    weaponization: false,
    automatic_disclosure: false,
  };
}

function hashManifest(path: string): string {
  const descriptor = openSync(resolve(path), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_MANIFEST_BYTES) {
      throw new Error("Windows variant manifest must be a bounded regular file");
    }
    return createHash("sha256").update(readFileSync(descriptor)).digest("hex");
  } finally {
    closeSync(descriptor);
  }
}

async function runBounded(
  runner: WindowsVariantRankRunner,
  request: Omit<WindowsVariantRankRequest, "signal">,
  externalSignal?: AbortSignal,
): Promise<Readonly<WindowsVariantRankExecution>> {
  if (externalSignal?.aborted) throw new Error("Windows variant import was aborted");
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let rejectBoundary: ((reason: Error) => void) | undefined;
  const boundary = new Promise<never>((_resolve, reject) => {
    rejectBoundary = reject;
    timer = setTimeout(() => {
      reject(new Error("Windows variant runner timed out"));
      controller.abort(new Error("Windows variant runner timed out"));
    }, request.timeoutMs);
  });
  const onExternalAbort = () => {
    rejectBoundary?.(new Error("Windows variant import was aborted"));
    controller.abort(externalSignal?.reason);
  };
  externalSignal?.addEventListener("abort", onExternalAbort, { once: true });
  try {
    return await Promise.race([
      runner({ ...request, signal: controller.signal }),
      boundary,
    ]);
  } finally {
    if (timer) clearTimeout(timer);
    externalSignal?.removeEventListener("abort", onExternalAbort);
  }
}

export class WindowsVariantResearchAdapter
  implements TargetResearchAdapter<WindowsVariantTarget, WindowsVariantCandidate, never, never>
{
  readonly kind = "windows.binary-variant" as const;

  constructor(private readonly runner: WindowsVariantRankRunner) {}

  async discover(
    target: WindowsVariantTarget,
    ctx: ResearchContext,
  ): Promise<ResearchStageResult<WindowsVariantCandidate>> {
    try {
      sha(target.config.expectedCampaignSha256, "expectedCampaignSha256");
      const timeoutMs = target.config.timeoutMs ?? 120_000;
      if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > MAX_TIMEOUT_MS) {
        throw new Error("Windows variant timeout is outside the bounded range");
      }
      if (hashManifest(target.location) !== target.config.expectedCampaignSha256) {
        throw new Error("Windows variant manifest hash mismatch");
      }
      const execution = await runBounded(this.runner, {
        manifestPath: resolve(target.location),
        timeoutMs,
      }, ctx.signal);
      if (execution.timedOut || execution.signal !== null || execution.exitCode !== 0) {
        throw new Error(`0verse ranker did not exit cleanly (${execution.stderr ?? "no detail"})`);
      }
      const stdout = Buffer.from(execution.stdout);
      if (stdout.length === 0 || stdout.length > MAX_RESULT_BYTES) {
        throw new Error("0verse ranker output is empty or exceeds the size limit");
      }
      const parsed = parseResult(JSON.parse(stdout.toString("utf8")) as unknown, target.config);
      const resultSha256 = createHash("sha256").update(stdout).digest("hex");
      const resultPath = join(ctx.artifactDir, "windows-variant-result.json");
      writeFileSync(resultPath, stdout, { flag: "wx" });
      const items = parsed.candidates.map((row) => ({
        id: `${target.id}:${createHash("sha256").update(`${resultSha256}\0${row.rank}\0${row.function}\0${row.function_address}`).digest("hex")}`,
        title: `Windows binary variant candidate: ${row.function}`,
        location: `${target.location}#${encodeURIComponent(row.function_address || row.function)}`,
        hypothesis: "a current Windows function retains seed sink geometry without the transferred security guard; independent reachability and dynamic proof are required",
        payload: {
          row,
          campaignSha256: parsed.campaign_sha256,
          resultSha256,
          seed: parsed.seed,
          current: parsed.current,
        },
      }));
      return {
        items,
        evidence: [{
          stage: "discover",
          status: "passed",
          summary: `imported ${items.length} hash-bound candidate-only Windows variant(s)`,
          data: {
            schemaVersion: parsed.schema_version,
            campaignSha256: parsed.campaign_sha256,
            resultSha256,
            candidateCount: items.length,
            allResultsAreCandidates: true,
            weaponization: false,
            automaticDisclosure: false,
          },
          artifacts: [resultPath],
        }],
      };
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return {
        items: [],
        evidence: [{ stage: "discover", status: "failed", summary: `Windows variant import rejected: ${detail}` }],
        warnings: [detail],
      };
    }
  }

  async assessReachability(
    _target: WindowsVariantTarget,
    candidates: WindowsVariantCandidate[],
  ): Promise<ResearchStageResult<WindowsVariantCandidate>> {
    return {
      items: candidates,
      evidence: [{
        stage: "reachability",
        status: "inconclusive",
        summary: "0verse reachability annotations are retained as candidate context, not verified reachability",
      }],
    };
  }

  async verify(): Promise<ResearchStageResult<never>> {
    return {
      items: [],
      evidence: [{
        stage: "verify",
        status: "inconclusive",
        summary: "static guard-delta evidence remains candidate-only; independent reachability and dynamic proof are required",
      }],
    };
  }
}
