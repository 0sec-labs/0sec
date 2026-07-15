import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";
import type { Command } from "commander";
import {
  aggregateScorecard,
  digestBenchManifest,
  parseManifest,
  pairwiseDeltas,
  pickChampion,
  projectResearchImprovementResult,
  type BenchScorecard,
  type BenchCaseResult,
  type BenchManifest,
  type ResearchImprovementResult,
  type ResearchTournamentRun,
  type TournamentResult,
} from "@pwnkit/core";

interface CandidateMetadata {
  id: string;
  evaluation: {
    manifestId: string;
    evaluatorDigest: string;
    developmentCorpusDigest: string;
    heldOutCorpusDigest: string;
    negativeControlCorpusDigest: string;
  };
}

interface CiEvidence {
  passed: boolean;
  evidenceRefs: string[];
}

export interface ImprovementProjectionInputs {
  candidate: CandidateMetadata;
  championVariantId: string;
  challengerVariantId: string;
  development: ResearchTournamentRun;
  heldOut: ResearchTournamentRun;
  negativeControls: ResearchTournamentRun;
  evaluatorDigestBefore: string;
  evaluatorDigestAfter: string;
  ciEvidence: CiEvidence;
  evidenceRefs: string[];
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function digest(value: unknown, label: string): string {
  const result = text(value, label);
  if (!/^sha256:[0-9a-f]{64}$/.test(result)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
  return result;
}

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return value;
}

function rate(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${label} must be a finite rate in [0, 1]`);
  }
  return value;
}

function nullableCost(value: unknown, label: string): number | null {
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error(`${label} must be null or a finite non-negative number`);
  }
  return value;
}

function finiteNonNegative(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new Error(`${label} must be a finite non-negative number`);
  }
  return value;
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${label} must be a non-empty string array`);
  }
  const strings = value.map((item, index) => text(item, `${label}[${index}]`));
  if (new Set(strings).size !== strings.length) throw new Error(`${label} contains duplicates`);
  return strings;
}

/** Read a bounded immutable JSON artifact without following symlinks. */
export function readArtifactJson(pathValue: string, label: string): unknown {
  const path = resolve(pathValue);
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-symlink file`);
  }
  if (stat.size > 512 * 1024 * 1024) throw new Error(`${label} exceeds 512 MiB`);
  let fd: number | undefined;
  try {
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const before = fstatSync(fd);
    const content = readFileSync(fd, "utf8");
    const after = fstatSync(fd);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs
    ) {
      throw new Error(`${label} changed while it was being read`);
    }
    return JSON.parse(content);
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON`);
    throw error;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function parseCandidateMetadata(value: unknown): CandidateMetadata {
  const raw = record(value, "candidate");
  if (raw.schemaVersion !== 1) throw new Error("candidate.schemaVersion must be 1");
  const id = text(raw.id, "candidate.id");
  if (!/^[a-z0-9][a-z0-9_-]{2,79}$/.test(id)) {
    throw new Error("candidate.id must be a lowercase filesystem-safe identifier");
  }
  const evaluation = record(raw.evaluation, "candidate.evaluation");
  return {
    id,
    evaluation: {
      manifestId: text(evaluation.manifestId, "candidate.evaluation.manifestId"),
      evaluatorDigest: digest(evaluation.evaluatorDigest, "candidate.evaluation.evaluatorDigest"),
      developmentCorpusDigest: digest(
        evaluation.developmentCorpusDigest,
        "candidate.evaluation.developmentCorpusDigest",
      ),
      heldOutCorpusDigest: digest(
        evaluation.heldOutCorpusDigest,
        "candidate.evaluation.heldOutCorpusDigest",
      ),
      negativeControlCorpusDigest: digest(
        evaluation.negativeControlCorpusDigest,
        "candidate.evaluation.negativeControlCorpusDigest",
      ),
    },
  };
}

export function parseCiEvidence(value: unknown): CiEvidence {
  const raw = record(value, "CI evidence");
  if (raw.schemaVersion !== 1) throw new Error("CI evidence schemaVersion must be 1");
  if (typeof raw.passed !== "boolean") throw new Error("CI evidence passed must be boolean");
  return { passed: raw.passed, evidenceRefs: stringArray(raw.evidenceRefs, "CI evidence refs") };
}

function caseResult(
  value: unknown,
  manifestCase: BenchManifest["cases"][number],
  label: string,
): BenchCaseResult {
  const raw = record(value, label);
  if (text(raw.id, `${label}.id`) !== manifestCase.id) {
    throw new Error(`${label}.id does not match its manifest case`);
  }
  if (text(raw.kind, `${label}.kind`) !== manifestCase.target.kind) {
    throw new Error(`${label}.kind does not match its manifest case`);
  }
  if (text(raw.objective, `${label}.objective`) !== manifestCase.objective.type) {
    throw new Error(`${label}.objective does not match its manifest case`);
  }
  if (raw.knownNegative !== manifestCase.knownNegative) {
    throw new Error(`${label}.knownNegative does not match its manifest case`);
  }
  if (!Array.isArray(raw.tags) || JSON.stringify(raw.tags) !== JSON.stringify(manifestCase.tags)) {
    throw new Error(`${label}.tags do not match its manifest case`);
  }
  positiveInteger(raw.passAtK, `${label}.passAtK`);
  if (!Array.isArray(raw.attempts)) throw new Error(`${label}.attempts must be an array`);
  if (!(["verified", "refuted", "inconclusive"] as unknown[]).includes(raw.verdict)) {
    throw new Error(`${label}.verdict is invalid`);
  }
  if (typeof raw.falsePositive !== "boolean") {
    throw new Error(`${label}.falsePositive must be boolean`);
  }
  if (raw.falsePositive !== (raw.knownNegative === true && raw.verdict === "verified")) {
    throw new Error(`${label}.falsePositive is inconsistent with the verdict`);
  }
  finiteNonNegative(raw.costUsd, `${label}.costUsd`);
  nonNegativeInteger(raw.attackTurns, `${label}.attackTurns`);
  return raw as unknown as BenchCaseResult;
}

function validateScorecard(
  value: unknown,
  manifest: BenchManifest,
  label: string,
): BenchScorecard {
  const raw = record(value, label);
  if (raw.schemaVersion !== 1) throw new Error(`${label}.schemaVersion must be 1`);
  if (text(raw.manifestId, `${label}.manifestId`) !== manifest.id) {
    throw new Error(`${label}.manifestId does not match its manifest`);
  }
  const totals = record(raw.totals, `${label}.totals`);
  const config = record(raw.config, `${label}.config`);
  positiveInteger(config.passAtK, `${label}.config.passAtK`);
  positiveInteger(config.maxTurns, `${label}.config.maxTurns`);
  nullableCost(config.costCeilingUsd, `${label}.config.costCeilingUsd`);
  if (typeof config.ciSubset !== "boolean") throw new Error(`${label}.config.ciSubset must be boolean`);
  const cases = nonNegativeInteger(totals.cases, `${label}.totals.cases`);
  const positives = nonNegativeInteger(totals.positives, `${label}.totals.positives`);
  const negatives = nonNegativeInteger(
    totals.knownNegatives,
    `${label}.totals.knownNegatives`,
  );
  const verified = nonNegativeInteger(totals.verified, `${label}.totals.verified`);
  const refuted = nonNegativeInteger(totals.refuted, `${label}.totals.refuted`);
  const inconclusive = nonNegativeInteger(
    totals.inconclusive,
    `${label}.totals.inconclusive`,
  );
  if (positives + negatives !== cases) throw new Error(`${label}.totals corpus counts disagree`);
  if (verified + refuted + inconclusive !== cases) {
    throw new Error(`${label}.totals verdict counts disagree`);
  }
  const successRate = rate(raw.successRate, `${label}.successRate`);
  rate(raw.fpRate, `${label}.fpRate`);
  const interval = raw.successRateCI95;
  if (!Array.isArray(interval) || interval.length !== 2) {
    throw new Error(`${label}.successRateCI95 must be a two-number interval`);
  }
  const lower = rate(interval[0], `${label}.successRateCI95[0]`);
  const upper = rate(interval[1], `${label}.successRateCI95[1]`);
  if (lower > upper) throw new Error(`${label}.successRateCI95 is reversed`);
  if (successRate < lower || successRate > upper) {
    throw new Error(`${label}.successRate is outside its confidence interval`);
  }
  const falsePositives = nonNegativeInteger(raw.falsePositives, `${label}.falsePositives`);
  if (falsePositives > negatives) throw new Error(`${label}.falsePositives exceeds controls`);
  finiteNonNegative(raw.totalCostUsd, `${label}.totalCostUsd`);
  nullableCost(raw.costPerSuccessUsd, `${label}.costPerSuccessUsd`);
  nonNegativeInteger(raw.totalAttackTurns, `${label}.totalAttackTurns`);
  record(raw.byObjective, `${label}.byObjective`);
  if (!Array.isArray(raw.cases)) throw new Error(`${label}.cases must be an array`);
  const expectedManifestCases = config.ciSubset
    ? manifest.cases.filter((entry) => entry.ci === true)
    : manifest.cases;
  if (raw.cases.length !== expectedManifestCases.length) {
    throw new Error(`${label}.cases do not match the selected manifest corpus`);
  }
  const seen = new Set<string>();
  const manifestById = new Map(expectedManifestCases.map((entry) => [entry.id, entry]));
  const parsedCases = raw.cases.map((entry, index) => {
    const entryRecord = record(entry, `${label}.cases[${index}]`);
    const id = text(entryRecord.id, `${label}.cases[${index}].id`);
    if (seen.has(id)) throw new Error(`${label}.cases contains duplicate id ${id}`);
    seen.add(id);
    const manifestCase = manifestById.get(id);
    if (!manifestCase) throw new Error(`${label}.cases contains unknown id ${id}`);
    return caseResult(entry, manifestCase, `${label}.cases[${index}]`);
  });
  const recomputed = aggregateScorecard({
    manifestId: manifest.id,
    ciSubset: config.ciSubset as boolean,
    passAtK: config.passAtK as number,
    maxTurns: config.maxTurns as number,
    costCeilingUsd: config.costCeilingUsd as number | null,
    cases: parsedCases,
  });
  const suppliedSummary: Record<string, unknown> = { ...raw, cases: parsedCases };
  delete suppliedSummary.generatedAt;
  if (JSON.stringify(canonicalize(suppliedSummary)) !== JSON.stringify(canonicalize(recomputed))) {
    throw new Error(`${label} summary does not match its raw cases`);
  }
  return {
    ...recomputed,
    ...(raw.generatedAt === undefined
      ? {}
      : { generatedAt: text(raw.generatedAt, `${label}.generatedAt`) }),
  };
}

export function parseTournamentPair(value: unknown, label: string): ResearchTournamentRun {
  const raw = record(value, label);
  const manifest = parseManifest(raw.manifest);
  const tournamentRaw = record(raw.tournament, `${label}.tournament`);
  if (text(tournamentRaw.manifestId, `${label}.tournament.manifestId`) !== manifest.id) {
    throw new Error(`${label} tournament manifest does not match its manifest`);
  }
  const config = record(tournamentRaw.config, `${label}.tournament.config`);
  positiveInteger(config.passAtK, `${label}.tournament.config.passAtK`);
  positiveInteger(config.maxTurns, `${label}.tournament.config.maxTurns`);
  nullableCost(config.costCeilingUsd, `${label}.tournament.config.costCeilingUsd`);
  if (typeof config.ciSubset !== "boolean") {
    throw new Error(`${label}.tournament.config.ciSubset must be boolean`);
  }
  const configuredIds = stringArray(config.variantIds, `${label}.tournament.config.variantIds`);
  if (!Array.isArray(tournamentRaw.variants) || tournamentRaw.variants.length === 0) {
    throw new Error(`${label}.tournament.variants must be a non-empty array`);
  }
  const variants = tournamentRaw.variants.map((value, index) => {
    const entry = record(value, `${label}.tournament.variants[${index}]`);
    const variant = record(entry.variant, `${label}.tournament.variants[${index}].variant`);
    const id = text(variant.id, `${label}.tournament.variants[${index}].variant.id`);
    return {
      variant: { ...variant, id },
      scorecard: validateScorecard(
        entry.scorecard,
        manifest,
        `${label}.tournament.variants[${index}].scorecard`,
      ),
    };
  });
  const actualIds = variants.map((entry) => entry.variant.id);
  if (new Set(actualIds).size !== actualIds.length) throw new Error(`${label} has duplicate variants`);
  if (configuredIds.length !== actualIds.length || configuredIds.some((id, i) => id !== actualIds[i])) {
    throw new Error(`${label} configured variant ids do not match tournament variants`);
  }
  const expectedConfig = {
    passAtK: config.passAtK,
    maxTurns: config.maxTurns,
    costCeilingUsd: config.costCeilingUsd,
    ciSubset: config.ciSubset,
  };
  for (const [index, entry] of variants.entries()) {
    if (
      JSON.stringify(canonicalize(entry.scorecard.config)) !==
      JSON.stringify(canonicalize(expectedConfig))
    ) {
      throw new Error(
        `${label}.tournament.variants[${index}] scorecard config does not match tournament config`,
      );
    }
  }
  const championId = text(tournamentRaw.championId, `${label}.tournament.championId`);
  if (championId !== pickChampion(variants)) {
    throw new Error(`${label} champion does not match the recomputed tournament winner`);
  }
  if (!Array.isArray(tournamentRaw.pairwise)) {
    throw new Error(`${label}.tournament.pairwise must be an array`);
  }
  if (
    JSON.stringify(canonicalize(tournamentRaw.pairwise)) !==
    JSON.stringify(canonicalize(pairwiseDeltas(variants)))
  ) {
    throw new Error(`${label} pairwise deltas do not match the recomputed tournament`);
  }
  const tournament: TournamentResult = {
    ...(tournamentRaw as unknown as TournamentResult),
    manifestId: manifest.id,
    variants,
    championId,
  };
  return { manifest, tournament };
}

function requireDigest(actual: string, expected: string, label: string): void {
  if (actual !== expected) throw new Error(`${label} digest does not match candidate metadata`);
}

export function projectImprovementFromArtifacts(
  inputs: ImprovementProjectionInputs,
): ResearchImprovementResult {
  digest(inputs.evaluatorDigestBefore, "evaluator-before digest");
  digest(inputs.evaluatorDigestAfter, "evaluator-after digest");
  if (inputs.evaluatorDigestBefore !== inputs.candidate.evaluation.evaluatorDigest) {
    throw new Error("evaluator-before digest does not match candidate metadata");
  }
  if (inputs.evaluatorDigestAfter !== inputs.evaluatorDigestBefore) {
    throw new Error("evaluator changed between the before and after attestations");
  }
  requireDigest(
    digestBenchManifest(inputs.development.manifest),
    inputs.candidate.evaluation.developmentCorpusDigest,
    "development corpus",
  );
  requireDigest(
    digestBenchManifest(inputs.heldOut.manifest),
    inputs.candidate.evaluation.heldOutCorpusDigest,
    "held-out corpus",
  );
  requireDigest(
    digestBenchManifest(inputs.negativeControls.manifest),
    inputs.candidate.evaluation.negativeControlCorpusDigest,
    "negative-control corpus",
  );
  const evidenceRefs = [...new Set([...inputs.ciEvidence.evidenceRefs, ...inputs.evidenceRefs])];
  return projectResearchImprovementResult({
    candidateId: inputs.candidate.id,
    manifestId: inputs.candidate.evaluation.manifestId,
    championVariantId: inputs.championVariantId,
    challengerVariantId: inputs.challengerVariantId,
    development: inputs.development,
    heldOut: inputs.heldOut,
    negativeControls: inputs.negativeControls,
    evaluatorDigestBefore: inputs.evaluatorDigestBefore,
    evaluatorDigestAfter: inputs.evaluatorDigestAfter,
    ciPassed: inputs.ciEvidence.passed,
    evidenceRefs,
  });
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => [key, canonicalize(item)]),
  );
}

export function canonicalResultJson(result: ResearchImprovementResult): string {
  return `${JSON.stringify(canonicalize(result), null, 2)}\n`;
}

/** Create the destination from a fully written same-directory temporary file. */
export function writeResultAtomic(outputValue: string, result: ResearchImprovementResult): void {
  const output = resolve(outputValue);
  const parent = dirname(output);
  mkdirSync(parent, { recursive: true });
  if (existsSync(output)) throw new Error(`output already exists: ${output}`);
  const temporary = join(parent, `.${basename(output)}.${process.pid}.${randomUUID()}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    writeSync(fd, canonicalResultJson(result), undefined, "utf8");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    try {
      linkSync(temporary, output);
      unlinkSync(temporary);
    } catch (error) {
      if (existsSync(output)) throw new Error(`output already exists: ${output}`);
      throw error;
    }
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

export function registerBenchImprovementCommand(bench: Command): void {
  bench
    .command("improvement-project")
    .description("Offline projection of sealed 0research tournaments into the v1 result contract")
    .requiredOption("--candidate <path>", "schema-v1 ImprovementCandidate JSON")
    .requiredOption("--champion-variant <id>", "champion variant id present in every tournament")
    .requiredOption("--challenger-variant <id>", "challenger variant id present in every tournament")
    .requiredOption("--development <path>", "JSON pair: {manifest, tournament}")
    .requiredOption("--held-out <path>", "JSON pair: {manifest, tournament}")
    .requiredOption("--negative-controls <path>", "JSON pair: {manifest, tournament}")
    .requiredOption("--evaluator-before <digest>", "pre-run evaluator digest")
    .requiredOption("--evaluator-after <digest>", "post-run evaluator digest")
    .requiredOption("--ci-evidence <path>", "JSON: {schemaVersion:1, passed, evidenceRefs}")
    .requiredOption("--output <path>", "canonical v1 ImprovementExperimentResult destination")
    .option("--evidence-ref <ref>", "additional immutable evidence reference (repeatable)", collect, [])
    .action((opts) => {
      const result = projectImprovementFromArtifacts({
        candidate: parseCandidateMetadata(readArtifactJson(String(opts.candidate), "candidate")),
        championVariantId: text(opts.championVariant, "champion variant id"),
        challengerVariantId: text(opts.challengerVariant, "challenger variant id"),
        development: parseTournamentPair(
          readArtifactJson(String(opts.development), "development pair"),
          "development pair",
        ),
        heldOut: parseTournamentPair(
          readArtifactJson(String(opts.heldOut), "held-out pair"),
          "held-out pair",
        ),
        negativeControls: parseTournamentPair(
          readArtifactJson(String(opts.negativeControls), "negative-control pair"),
          "negative-control pair",
        ),
        evaluatorDigestBefore: text(opts.evaluatorBefore, "evaluator-before digest"),
        evaluatorDigestAfter: text(opts.evaluatorAfter, "evaluator-after digest"),
        ciEvidence: parseCiEvidence(readArtifactJson(String(opts.ciEvidence), "CI evidence")),
        evidenceRefs: (opts.evidenceRef as string[]).map((ref, index) =>
          text(ref, `evidence ref ${index}`),
        ),
      });
      writeResultAtomic(String(opts.output), result);
      process.stdout.write(`${String(opts.output)}\n`);
    });
}
