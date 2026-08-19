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
  rmSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";
import type { Command } from "commander";
import {
  aggregateScorecard,
  digestBenchManifest,
  parseManifest,
  pairwiseDeltas,
  pickChampion,
  projectResearchImprovementResult,
  projectResearchExecutionEvidence,
  researchExecutionEvidenceRef,
  snapshotBenchVariant,
  type BenchScorecard,
  type BenchCaseResult,
  type BenchManifest,
  type BenchVariant,
  type BenchEvaluatorAttestation,
  type ResearchImprovementResult,
  type ResearchExecutionEvidence,
  type ResearchTournamentRun,
  type TournamentResult,
} from "@0sec/core";

interface CandidateMetadata {
  id: string;
  project: "0sec";
  calibrationEmptyFindings: boolean;
  change: { kind: string; knobs: Record<string, string | number | boolean> };
  budget: {
    maxRuns: number;
    maxUsd: number;
    maxWallClockMinutes: number;
  };
  evaluation: {
    manifestId: string;
    manifestDigest: string;
    evaluatorDigest: string;
    developmentCorpusDigest: string;
    heldOutCorpusDigest: string;
    negativeControlCorpusDigest: string;
    developmentCaseIds: string[];
    heldOutCaseIds: string[];
    negativeControlCaseIds: string[];
  };
}

interface CiEvidence {
  passed: boolean;
  evidenceRefs: string[];
  producer?: { repository: string; commitSha: string; treeDigest: string };
  provider?: "github-actions";
  candidateId?: string;
  checks?: Array<{ name: string; conclusion: "success" | "failure" | "cancelled" }>;
}

const REQUIRED_0SEC_CHECKS = [
  "build",
  "ecosystem-audit-smoke (cargo)",
  "ecosystem-audit-smoke (npm)",
  "ecosystem-audit-smoke (oci)",
  "ecosystem-audit-smoke (pypi)",
  "install-smoke (bun)",
  "install-smoke (docker)",
  "install-smoke (node 24)",
  "install-smoke (node 25)",
  "test",
] as const;

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
  calibration?: boolean;
}

interface ParsedResearchTournamentRun extends ResearchTournamentRun {
  calibrationMode?: "zero-cost-no-uplift";
}

interface SealedTournamentInput {
  run: ParsedResearchTournamentRun;
  digest: string;
  artifactRef: string;
}

interface EvaluationManifestInput {
  id: string;
  digest: string;
  artifactRef: string;
  developmentCaseIds: string[];
  heldOutCaseIds: string[];
  negativeControlCaseIds: string[];
}

interface EvaluatorInput {
  bundleDigest: string;
  codeDigest: string;
  configDigest: string;
  bundleArtifactRef: string;
  codeArtifactRef: string;
  configArtifactRef: string;
}

export interface ImprovementBundleProjectionInputs {
  candidate: CandidateMetadata;
  championVariantId: string;
  challengerVariantId: string;
  development: SealedTournamentInput;
  heldOut: SealedTournamentInput;
  negativeControls: SealedTournamentInput;
  evaluationManifest: EvaluationManifestInput;
  evaluator: EvaluatorInput;
  ciEvidence: CiEvidence;
  evidenceRefs: string[];
  calibration?: boolean;
}

export interface ResearchImprovementBundle {
  result: ResearchImprovementResult;
  executionEvidence: ResearchExecutionEvidence;
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

/** Read bounded immutable artifact bytes without following symlinks. */
export function readArtifactBytes(pathValue: string, label: string): Buffer {
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
    if (
      stat.dev !== before.dev ||
      stat.ino !== before.ino ||
      stat.size !== before.size ||
      stat.mtimeMs !== before.mtimeMs
    ) {
      throw new Error(`${label} changed before it was opened`);
    }
    const content = readFileSync(fd);
    const after = fstatSync(fd);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs
    ) {
      throw new Error(`${label} changed while it was being read`);
    }
    return content;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function sha256Bytes(content: Uint8Array): string {
  return `sha256:${createHash("sha256").update(content).digest("hex")}`;
}

/** Read a bounded immutable JSON artifact and retain its exact byte digest. */
export function readArtifactJsonWithDigest(
  pathValue: string,
  label: string,
): { value: unknown; digest: string } {
  const content = readArtifactBytes(pathValue, label);
  try {
    return { value: JSON.parse(content.toString("utf8")), digest: sha256Bytes(content) };
  } catch (error) {
    if (error instanceof SyntaxError) throw new Error(`${label} is not valid JSON`);
    throw error;
  }
}

export function readArtifactJson(pathValue: string, label: string): unknown {
  return readArtifactJsonWithDigest(pathValue, label).value;
}

export function parseCandidateMetadata(value: unknown): CandidateMetadata {
  const raw = record(value, "candidate");
  if (raw.schemaVersion !== 1) throw new Error("candidate.schemaVersion must be 1");
  const id = text(raw.id, "candidate.id");
  if (!/^[a-z0-9][a-z0-9_-]{2,79}$/.test(id)) {
    throw new Error("candidate.id must be a lowercase filesystem-safe identifier");
  }
  const evaluation = record(raw.evaluation, "candidate.evaluation");
  if (raw.project !== "0sec") throw new Error("candidate.project must be 0sec");
  const budget = record(raw.budget, "candidate.budget");
  const change = raw.change && typeof raw.change === "object" && !Array.isArray(raw.change)
    ? raw.change as Record<string, unknown>
    : undefined;
  const knobs = change?.knobs && typeof change.knobs === "object" && !Array.isArray(change.knobs)
    ? change.knobs as Record<string, unknown>
    : undefined;
  if (!change || !knobs) throw new Error("candidate.change with knobs is required");
  const parsedKnobs: Record<string, string | number | boolean> = {};
  for (const [key, value] of Object.entries(knobs)) {
    if (!key || !["string", "number", "boolean"].includes(typeof value) || (typeof value === "number" && !Number.isFinite(value))) {
      throw new Error(`candidate.change.knobs.${key} must be a finite scalar`);
    }
    parsedKnobs[key] = value as string | number | boolean;
  }
  return {
    id,
    project: "0sec",
    calibrationEmptyFindings:
      change?.kind === "feature_flag" && knobs?.["calibration.empty_findings"] === true,
    change: { kind: text(change.kind, "candidate.change.kind"), knobs: parsedKnobs },
    budget: {
      maxRuns: positiveInteger(budget.maxRuns, "candidate.budget.maxRuns"),
      maxUsd: finiteNonNegative(budget.maxUsd, "candidate.budget.maxUsd"),
      maxWallClockMinutes: positiveInteger(
        budget.maxWallClockMinutes,
        "candidate.budget.maxWallClockMinutes",
      ),
    },
    evaluation: {
      manifestId: text(evaluation.manifestId, "candidate.evaluation.manifestId"),
      manifestDigest: digest(evaluation.manifestDigest, "candidate.evaluation.manifestDigest"),
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
      developmentCaseIds: stringArray(
        evaluation.developmentCaseIds,
        "candidate.evaluation.developmentCaseIds",
      ),
      heldOutCaseIds: stringArray(
        evaluation.heldOutCaseIds,
        "candidate.evaluation.heldOutCaseIds",
      ),
      negativeControlCaseIds: stringArray(
        evaluation.negativeControlCaseIds,
        "candidate.evaluation.negativeControlCaseIds",
      ),
    },
  };
}

export function parseCiEvidence(value: unknown): CiEvidence {
  const raw = record(value, "CI evidence");
  if (raw.schemaVersion !== 1) throw new Error("CI evidence schemaVersion must be 1");
  if (typeof raw.passed !== "boolean") throw new Error("CI evidence passed must be boolean");
  const evidenceRefs = stringArray(raw.evidenceRefs, "CI evidence refs");
  if (raw.repository === undefined && raw.headSha === undefined && raw.treeDigest === undefined) {
    return { passed: raw.passed, evidenceRefs };
  }
  const expectedKeys = ["candidateId", "checks", "evidenceRefs", "headSha", "passed", "provider", "repository", "schemaVersion", "treeDigest"];
  if (JSON.stringify(Object.keys(raw).sort()) !== JSON.stringify(expectedKeys)) {
    throw new Error("schema-v3 CI evidence has unsupported or missing fields");
  }
  if (evidenceRefs.length !== 1) {
    throw new Error("schema-v3 CI evidence must reference exactly its retained artifact");
  }
  if (raw.provider !== "github-actions") throw new Error("CI evidence provider must be github-actions");
  const candidateId = text(raw.candidateId, "CI evidence candidateId");
  const repository = text(raw.repository, "CI evidence repository");
  const commitSha = text(raw.headSha, "CI evidence headSha");
  const treeDigest = digest(raw.treeDigest, "CI evidence treeDigest");
  if (repository !== "0sec-labs/0sec") throw new Error("CI evidence repository must be 0sec-labs/0sec");
  if (!/^[0-9a-f]{40}$/.test(commitSha)) throw new Error("CI evidence headSha must be a full lowercase SHA");
  if (!Array.isArray(raw.checks)) throw new Error("CI evidence checks must be an array");
  const checks = raw.checks.map((value, index) => {
    const check = record(value, `CI evidence checks[${index}]`);
    if (JSON.stringify(Object.keys(check).sort()) !== JSON.stringify(["conclusion", "name"])) {
      throw new Error(`CI evidence checks[${index}] has unsupported or missing fields`);
    }
    const name = text(check.name, `CI evidence checks[${index}].name`);
    if (!["success", "failure", "cancelled"].includes(String(check.conclusion))) {
      throw new Error(`CI evidence checks[${index}].conclusion is unsupported`);
    }
    return { name, conclusion: check.conclusion as "success" | "failure" | "cancelled" };
  });
  const names = checks.map((check) => check.name);
  if (JSON.stringify(names) !== JSON.stringify(REQUIRED_0SEC_CHECKS)) {
    throw new Error("CI evidence does not contain the controller-required check set");
  }
  const passed = checks.every((check) => check.conclusion === "success");
  if (raw.passed !== passed) throw new Error("CI evidence passed does not match required check conclusions");
  return {
    passed,
    evidenceRefs,
    producer: { repository, commitSha, treeDigest },
    provider: "github-actions",
    candidateId,
    checks,
  };
}

function caseResult(
  value: unknown,
  manifestCase: BenchManifest["cases"][number],
  label: string,
  configuredPassAtK: number,
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
  const passAtK = positiveInteger(raw.passAtK, `${label}.passAtK`);
  if (passAtK !== (manifestCase.passAtK ?? configuredPassAtK)) {
    throw new Error(`${label}.passAtK does not match its manifest or tournament config`);
  }
  if (!Array.isArray(raw.attempts)) throw new Error(`${label}.attempts must be an array`);
  if (raw.attempts.length === 0 || raw.attempts.length > passAtK) {
    throw new Error(`${label}.attempts must contain between 1 and passAtK receipts`);
  }
  const attempts = raw.attempts.map((value, index) => {
    const attempt = record(value, `${label}.attempts[${index}]`);
    if (attempt.attemptIndex !== index) {
      throw new Error(`${label}.attempts must have contiguous zero-based indices`);
    }
    if (!(["verified", "refuted", "inconclusive"] as unknown[]).includes(attempt.status)) {
      throw new Error(`${label}.attempts[${index}].status is invalid`);
    }
    if (
      attempt.confidence !== null &&
      (typeof attempt.confidence !== "number" ||
        !Number.isFinite(attempt.confidence) ||
        attempt.confidence < 0 ||
        attempt.confidence > 1)
    ) {
      throw new Error(`${label}.attempts[${index}].confidence must be null or a rate`);
    }
    if (typeof attempt.notes !== "string") {
      throw new Error(`${label}.attempts[${index}].notes must be a string`);
    }
    finiteNonNegative(attempt.costUsd, `${label}.attempts[${index}].costUsd`);
    nonNegativeInteger(attempt.attackTurns, `${label}.attempts[${index}].attackTurns`);
    nonNegativeInteger(attempt.durationMs, `${label}.attempts[${index}].durationMs`);
    return attempt;
  });
  const firstVerified = attempts.findIndex((attempt) => attempt.status === "verified");
  if (firstVerified >= 0 && firstVerified !== attempts.length - 1) {
    throw new Error(`${label}.attempts continue after the first verified receipt`);
  }
  const derivedVerdict = firstVerified >= 0
    ? "verified"
    : attempts.every((attempt) => attempt.status === "inconclusive")
      ? "inconclusive"
      : "refuted";
  if (raw.verdict !== derivedVerdict) {
    throw new Error(`${label}.verdict does not match its attempt receipts`);
  }
  if (typeof raw.falsePositive !== "boolean") {
    throw new Error(`${label}.falsePositive must be boolean`);
  }
  if (raw.falsePositive !== (raw.knownNegative === true && derivedVerdict === "verified")) {
    throw new Error(`${label}.falsePositive is inconsistent with the verdict`);
  }
  const costUsd = finiteNonNegative(raw.costUsd, `${label}.costUsd`);
  const attackTurns = nonNegativeInteger(raw.attackTurns, `${label}.attackTurns`);
  const attemptCost = attempts.reduce((sum, attempt) => sum + (attempt.costUsd as number), 0);
  const attemptTurns = attempts.reduce((sum, attempt) => sum + (attempt.attackTurns as number), 0);
  if (costUsd !== attemptCost) throw new Error(`${label}.costUsd does not equal attempt costs`);
  if (attackTurns !== attemptTurns) {
    throw new Error(`${label}.attackTurns does not equal attempt turns`);
  }
  return { ...raw, attempts } as unknown as BenchCaseResult;
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
    return caseResult(
      entry,
      manifestCase,
      `${label}.cases[${index}]`,
      config.passAtK as number,
    );
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

export function parseTournamentPair(value: unknown, label: string): ParsedResearchTournamentRun {
  const raw = record(value, label);
  if (raw.schemaVersion !== 1) throw new Error(`${label}.schemaVersion must be 1`);
  let calibrationMode: ParsedResearchTournamentRun["calibrationMode"];
  if (raw.calibration !== undefined) {
    const calibration = record(raw.calibration, `${label}.calibration`);
    const expectedKeys = [
      "expectedOutcome",
      "mode",
      "networkAllowed",
      "providerAllowed",
      "schemaVersion",
    ];
    if (JSON.stringify(Object.keys(calibration).sort()) !== JSON.stringify(expectedKeys)) {
      throw new Error(`${label}.calibration has unsupported fields`);
    }
    if (
      calibration.schemaVersion !== 1 ||
      calibration.mode !== "zero-cost-no-uplift" ||
      calibration.networkAllowed !== false ||
      calibration.providerAllowed !== false ||
      calibration.expectedOutcome !== "reject"
    ) {
      throw new Error(`${label}.calibration is not the trusted zero-cost rejection mode`);
    }
    calibrationMode = "zero-cost-no-uplift";
  }
  const elapsedMs = nonNegativeInteger(raw.elapsedMs, `${label}.elapsedMs`);
  const evaluatorAttestation = (value: unknown, field: string): BenchEvaluatorAttestation => {
    const attestation = record(value, `${label}.${field}`);
    return {
      bundleDigest: digest(attestation.bundleDigest, `${label}.${field}.bundleDigest`),
      codeDigest: digest(attestation.codeDigest, `${label}.${field}.codeDigest`),
      configDigest: digest(attestation.configDigest, `${label}.${field}.configDigest`),
    };
  };
  const evaluatorBefore = evaluatorAttestation(raw.evaluatorBefore, "evaluatorBefore");
  const evaluatorAfter = evaluatorAttestation(raw.evaluatorAfter, "evaluatorAfter");
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
    if (JSON.stringify(Object.keys(entry).sort()) !== JSON.stringify(["scorecard", "variant"])) {
      throw new Error(`${label}.tournament.variants[${index}] has unsupported or missing fields`);
    }
    const variant = record(entry.variant, `${label}.tournament.variants[${index}].variant`);
    const id = text(variant.id, `${label}.tournament.variants[${index}].variant.id`);
    return {
      variant: snapshotBenchVariant({ ...variant, id } as BenchVariant),
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
  return {
    manifest,
    tournament,
    elapsedMs,
    evaluatorBefore,
    evaluatorAfter,
    ...(calibrationMode ? { calibrationMode } : {}),
  };
}

function requireDigest(actual: string, expected: string, label: string): void {
  if (actual !== expected) throw new Error(`${label} digest does not match candidate metadata`);
}

function sameStrings(actual: string[], expected: string[]): boolean {
  return JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

function safeArtifactRef(value: unknown, label: string): string {
  const ref = text(value, label);
  if (!/^[a-z0-9][a-z0-9:._/-]{2,199}$/.test(ref)) {
    throw new Error(`${label} must be a safe artifact reference`);
  }
  return ref;
}

export function parseEvaluationManifest(
  value: unknown,
  manifestDigest: string,
  artifactRef: string,
): EvaluationManifestInput {
  const raw = record(value, "evaluation manifest");
  if (raw.schemaVersion !== 1) throw new Error("evaluation manifest schemaVersion must be 1");
  return {
    id: text(raw.id, "evaluation manifest id"),
    digest: digest(manifestDigest, "evaluation manifest digest"),
    artifactRef: safeArtifactRef(artifactRef, "evaluation manifest ref"),
    developmentCaseIds: stringArray(raw.developmentCaseIds, "evaluation manifest developmentCaseIds"),
    heldOutCaseIds: stringArray(raw.heldOutCaseIds, "evaluation manifest heldOutCaseIds"),
    negativeControlCaseIds: stringArray(
      raw.negativeControlCaseIds,
      "evaluation manifest negativeControlCaseIds",
    ),
  };
}

export function parseEvaluatorBundle(
  value: unknown,
  bundleDigest: string,
  codeDigest: string,
  configDigest: string,
  bundleArtifactRef: string,
  codeArtifactRef: string,
  configArtifactRef: string,
): EvaluatorInput {
  const raw = record(value, "evaluator bundle");
  if (raw.schemaVersion !== 1) throw new Error("evaluator bundle schemaVersion must be 1");
  const declaredCode = digest(raw.codeDigest, "evaluator bundle codeDigest");
  const declaredConfig = digest(raw.configDigest, "evaluator bundle configDigest");
  if (declaredCode !== codeDigest) throw new Error("evaluator code bytes do not match the bundle");
  if (declaredConfig !== configDigest) throw new Error("evaluator config bytes do not match the bundle");
  const parsedBundleDigest = digest(bundleDigest, "evaluator bundle digest");
  const canonicalBundleDigest = sha256Bytes(
    Buffer.from(`${JSON.stringify({ schemaVersion: 1, codeDigest, configDigest })}\n`),
  );
  if (parsedBundleDigest !== canonicalBundleDigest) {
    throw new Error("evaluator bundle bytes are not in the canonical v1 form");
  }
  return {
    bundleDigest: parsedBundleDigest,
    codeDigest,
    configDigest,
    bundleArtifactRef: safeArtifactRef(bundleArtifactRef, "evaluator bundle ref"),
    codeArtifactRef: safeArtifactRef(codeArtifactRef, "evaluator code ref"),
    configArtifactRef: safeArtifactRef(configArtifactRef, "evaluator config ref"),
  };
}

function requireCaseBinding(actual: string[], expected: string[], label: string): void {
  if (!sameStrings(actual, expected)) throw new Error(`${label} case ids do not match candidate metadata`);
}

const CALIBRATION_CHAMPION_ID = "calibration-champion";
const CALIBRATION_CHALLENGER_ID = "calibration-challenger";

function enforceCalibrationProjectionPolicy(inputs: {
  candidate: CandidateMetadata;
  championVariantId: string;
  challengerVariantId: string;
  development: ParsedResearchTournamentRun;
  heldOut: ParsedResearchTournamentRun;
  negativeControls: ParsedResearchTournamentRun;
  ciPassed: boolean;
  calibration?: boolean;
}): void {
  const runs = [inputs.development, inputs.heldOut, inputs.negativeControls];
  const hasCalibrationArtifact = runs.some((run) => run.calibrationMode !== undefined);
  const hasCalibrationVariant = [inputs.championVariantId, inputs.challengerVariantId]
    .some((id) => id === CALIBRATION_CHAMPION_ID || id === CALIBRATION_CHALLENGER_ID);

  if (!inputs.calibration) {
    if (hasCalibrationArtifact || hasCalibrationVariant) {
      throw new Error("calibration evidence requires the explicit rejection-only calibration projector");
    }
    return;
  }
  if (runs.some((run) => run.calibrationMode !== "zero-cost-no-uplift")) {
    throw new Error("calibration projection requires all three lanes to be trusted calibration artifacts");
  }
  if (
    inputs.championVariantId !== CALIBRATION_CHAMPION_ID ||
    inputs.challengerVariantId !== CALIBRATION_CHALLENGER_ID
  ) {
    throw new Error("calibration projection requires the fixed calibration variant ids");
  }
  if (!inputs.candidate.calibrationEmptyFindings || inputs.candidate.budget.maxUsd !== 0) {
    throw new Error("calibration projection requires the empty-findings knob and a zero-dollar budget");
  }
  if (inputs.ciPassed) {
    throw new Error("calibration projection requires non-promotable CI evidence");
  }

  for (const run of runs) {
    if (run.elapsedMs !== 0 || run.tournament.pairwise.length !== 1) {
      throw new Error("calibration projection requires zero elapsed time and one fixed pairwise result");
    }
    const delta = run.tournament.pairwise[0];
    if (
      delta.successRateDelta !== 0 ||
      delta.fpRateDelta !== 0 ||
      delta.costPerSuccessDelta !== null ||
      delta.significant !== false
    ) {
      throw new Error("calibration projection requires a non-significant zero delta");
    }
    for (const variant of run.tournament.variants) {
      const scorecard = variant.scorecard;
      if (
        scorecard.totals.verified !== 0 ||
        scorecard.totals.inconclusive !== 0 ||
        scorecard.falsePositives !== 0 ||
        scorecard.successRate !== 0 ||
        scorecard.fpRate !== 0 ||
        scorecard.costPerSuccessUsd !== null ||
        scorecard.totalCostUsd !== 0 ||
        scorecard.totalAttackTurns !== 0
      ) {
        throw new Error("calibration projection requires refuted-only zero-cost scorecards");
      }
      for (const entry of scorecard.cases) {
        if (
          entry.verdict !== "refuted" ||
          entry.falsePositive ||
          entry.costUsd !== 0 ||
          entry.attackTurns !== 0 ||
          entry.attempts.length !== 1 ||
          entry.attempts[0]?.status !== "refuted" ||
          entry.attempts[0]?.costUsd !== 0 ||
          entry.attempts[0]?.attackTurns !== 0 ||
          entry.attempts[0]?.durationMs !== 0
        ) {
          throw new Error("calibration projection requires one zero-cost refuted receipt per case");
        }
      }
    }
  }
}

export function projectImprovementBundleFromArtifacts(
  inputs: ImprovementBundleProjectionInputs,
): ResearchImprovementBundle {
  enforceCalibrationProjectionPolicy({
    candidate: inputs.candidate,
    championVariantId: inputs.championVariantId,
    challengerVariantId: inputs.challengerVariantId,
    development: inputs.development.run,
    heldOut: inputs.heldOut.run,
    negativeControls: inputs.negativeControls.run,
    ciPassed: inputs.ciEvidence.passed,
    calibration: inputs.calibration,
  });
  if (!inputs.calibration && !inputs.ciEvidence.producer) {
    throw new Error("schema-v3 projection requires producer identity in CI evidence");
  }
  if (!inputs.calibration && inputs.ciEvidence.candidateId !== inputs.candidate.id) {
    throw new Error("schema-v3 CI evidence candidate id does not match candidate metadata");
  }
  const evaluation = inputs.candidate.evaluation;
  if (inputs.evaluationManifest.id !== evaluation.manifestId) {
    throw new Error("evaluation manifest id does not match candidate metadata");
  }
  requireDigest(inputs.evaluationManifest.digest, evaluation.manifestDigest, "evaluation manifest");
  requireDigest(inputs.evaluator.bundleDigest, evaluation.evaluatorDigest, "evaluator bundle");
  const expectedEvaluator = {
    bundleDigest: inputs.evaluator.bundleDigest,
    codeDigest: inputs.evaluator.codeDigest,
    configDigest: inputs.evaluator.configDigest,
  };
  for (const [label, run] of [
    ["development", inputs.development.run],
    ["held-out", inputs.heldOut.run],
    ["negative-control", inputs.negativeControls.run],
  ] as const) {
    if (JSON.stringify(run.evaluatorBefore) !== JSON.stringify(expectedEvaluator)) {
      throw new Error(`${label} evaluator-before attestation does not match retained bytes`);
    }
    if (JSON.stringify(run.evaluatorAfter) !== JSON.stringify(run.evaluatorBefore)) {
      throw new Error(`${label} evaluator changed during tournament execution`);
    }
  }
  requireCaseBinding(
    inputs.evaluationManifest.developmentCaseIds,
    evaluation.developmentCaseIds,
    "development evaluation manifest",
  );
  requireCaseBinding(
    inputs.evaluationManifest.heldOutCaseIds,
    evaluation.heldOutCaseIds,
    "held-out evaluation manifest",
  );
  requireCaseBinding(
    inputs.evaluationManifest.negativeControlCaseIds,
    evaluation.negativeControlCaseIds,
    "negative-control evaluation manifest",
  );

  const elapsedMs =
    (inputs.development.run.elapsedMs ?? -1) +
    (inputs.heldOut.run.elapsedMs ?? -1) +
    (inputs.negativeControls.run.elapsedMs ?? -1);
  const executionEvidence = projectResearchExecutionEvidence({
    candidateId: inputs.candidate.id,
    championVariantId: inputs.championVariantId,
    challengerVariantId: inputs.challengerVariantId,
    manifest: {
      id: inputs.evaluationManifest.id,
      digest: inputs.evaluationManifest.digest,
      artifactRef: inputs.evaluationManifest.artifactRef,
    },
    evaluator: {
      bundleDigest: inputs.evaluator.bundleDigest,
      codeDigest: inputs.evaluator.codeDigest,
      configDigest: inputs.evaluator.configDigest,
      bundleArtifactRef: inputs.evaluator.bundleArtifactRef,
      codeArtifactRef: inputs.evaluator.codeArtifactRef,
      configArtifactRef: inputs.evaluator.configArtifactRef,
    },
    development: {
      run: inputs.development.run,
      artifactRef: inputs.development.artifactRef,
      tournamentDigest: inputs.development.digest,
      corpusDigest: evaluation.developmentCorpusDigest,
      expectedCaseIds: evaluation.developmentCaseIds,
      requireKnownNegative: false,
    },
    heldOut: {
      run: inputs.heldOut.run,
      artifactRef: inputs.heldOut.artifactRef,
      tournamentDigest: inputs.heldOut.digest,
      corpusDigest: evaluation.heldOutCorpusDigest,
      expectedCaseIds: evaluation.heldOutCaseIds,
      requireKnownNegative: false,
    },
    negativeControls: {
      run: inputs.negativeControls.run,
      artifactRef: inputs.negativeControls.artifactRef,
      tournamentDigest: inputs.negativeControls.digest,
      corpusDigest: evaluation.negativeControlCorpusDigest,
      expectedCaseIds: evaluation.negativeControlCaseIds,
      requireKnownNegative: true,
    },
    elapsedMs,
    ...(!inputs.calibration
      ? { candidateChange: inputs.candidate.change, producer: inputs.ciEvidence.producer! }
      : {}),
  });
  const requiredRefs = [
    inputs.evaluationManifest.artifactRef,
    inputs.development.artifactRef,
    inputs.heldOut.artifactRef,
    inputs.negativeControls.artifactRef,
    inputs.evaluator.bundleArtifactRef,
    inputs.evaluator.codeArtifactRef,
    inputs.evaluator.configArtifactRef,
    researchExecutionEvidenceRef(executionEvidence),
  ];
  const allRefs = [
    ...inputs.ciEvidence.evidenceRefs,
    ...inputs.evidenceRefs,
    ...requiredRefs,
  ];
  if (new Set(allRefs).size !== allRefs.length) {
    throw new Error("improvement artifact references must be unique across roles");
  }
  const result = projectImprovementFromArtifacts({
    candidate: inputs.candidate,
    championVariantId: inputs.championVariantId,
    challengerVariantId: inputs.challengerVariantId,
    development: inputs.development.run,
    heldOut: inputs.heldOut.run,
    negativeControls: inputs.negativeControls.run,
    evaluatorDigestBefore: inputs.evaluator.bundleDigest,
    evaluatorDigestAfter: inputs.evaluator.bundleDigest,
    ciEvidence: inputs.ciEvidence,
    evidenceRefs: [...inputs.evidenceRefs, ...requiredRefs],
    calibration: inputs.calibration,
  });
  return { result, executionEvidence };
}

export function projectImprovementFromArtifacts(
  inputs: ImprovementProjectionInputs,
): ResearchImprovementResult {
  enforceCalibrationProjectionPolicy({
    candidate: inputs.candidate,
    championVariantId: inputs.championVariantId,
    challengerVariantId: inputs.challengerVariantId,
    development: inputs.development as ParsedResearchTournamentRun,
    heldOut: inputs.heldOut as ParsedResearchTournamentRun,
    negativeControls: inputs.negativeControls as ParsedResearchTournamentRun,
    ciPassed: inputs.ciEvidence.passed,
    calibration: inputs.calibration,
  });
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

export function canonicalJson(value: unknown): string {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

export function canonicalResultJson(result: ResearchImprovementResult): string {
  return canonicalJson(result);
}

/** Create the destination from a fully written same-directory temporary file. */
export function writeCanonicalJsonAtomic(outputValue: string, value: unknown): void {
  const output = resolve(outputValue);
  const parent = dirname(output);
  mkdirSync(parent, { recursive: true });
  if (existsSync(output)) throw new Error(`output already exists: ${output}`);
  const temporary = join(parent, `.${basename(output)}.${process.pid}.${randomUUID()}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    writeSync(fd, canonicalJson(value), undefined, "utf8");
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

export function writeResultAtomic(outputValue: string, result: ResearchImprovementResult): void {
  writeCanonicalJsonAtomic(outputValue, result);
}

/** Exclusively reserve the directory and publish COMPLETE only after both files exist. */
export function writeImprovementBundleAtomic(
  outputDirectoryValue: string,
  bundle: ResearchImprovementBundle,
): void {
  const outputDirectory = resolve(outputDirectoryValue);
  const parent = dirname(outputDirectory);
  mkdirSync(parent, { recursive: true });
  try {
    mkdirSync(outputDirectory, { mode: 0o700 });
  } catch (error) {
    if (existsSync(outputDirectory)) throw new Error(`output already exists: ${outputDirectory}`);
    throw error;
  }
  try {
    writeCanonicalJsonAtomic(join(outputDirectory, "result.json"), bundle.result);
    writeCanonicalJsonAtomic(
      join(outputDirectory, "execution-evidence.json"),
      bundle.executionEvidence,
    );
    writeCanonicalJsonAtomic(join(outputDirectory, "COMPLETE"), { schemaVersion: 1 });
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    throw error;
  }
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

export function registerBenchImprovementCommand(bench: Command): void {
  bench
    .command("improvement-project")
    .description("Offline projection of sealed tournaments into the v1 result + v3 execution contract")
    .requiredOption("--candidate <path>", "schema-v1 ImprovementCandidate JSON")
    .requiredOption("--champion-variant <id>", "champion variant id present in every tournament")
    .requiredOption("--challenger-variant <id>", "challenger variant id present in every tournament")
    .requiredOption("--development <path>", "JSON pair: {manifest, tournament}")
    .requiredOption("--development-ref <ref>", "immutable development tournament artifact ref")
    .requiredOption("--held-out <path>", "JSON pair: {manifest, tournament}")
    .requiredOption("--held-out-ref <ref>", "immutable held-out tournament artifact ref")
    .requiredOption("--negative-controls <path>", "JSON pair: {manifest, tournament}")
    .requiredOption("--negative-controls-ref <ref>", "immutable negative-control artifact ref")
    .requiredOption("--evaluation-manifest <path>", "precommitted evaluation manifest JSON")
    .requiredOption("--manifest-ref <ref>", "immutable evaluation manifest artifact ref")
    .requiredOption("--evaluator-bundle <path>", "evaluator bundle JSON")
    .requiredOption("--evaluator-bundle-ref <ref>", "immutable evaluator bundle artifact ref")
    .requiredOption("--evaluator-code <path>", "exact evaluator implementation artifact")
    .requiredOption("--evaluator-code-ref <ref>", "immutable evaluator code artifact ref")
    .requiredOption("--evaluator-config <path>", "exact evaluator configuration artifact")
    .requiredOption("--evaluator-config-ref <ref>", "immutable evaluator config artifact ref")
    .requiredOption("--ci-evidence <path>", "retained GitHub Actions receipt with identity, required checks, pass result, and evidenceRefs")
    .requiredOption("--output-dir <path>", "create-once result + execution-evidence directory")
    .option("--calibration", "rejection-only projection of three trusted calibration lanes", false)
    .option("--evidence-ref <ref>", "additional immutable evidence reference (repeatable)", collect, [])
    .action((opts) => {
      const development = readArtifactJsonWithDigest(String(opts.development), "development pair");
      const heldOut = readArtifactJsonWithDigest(String(opts.heldOut), "held-out pair");
      const negativeControls = readArtifactJsonWithDigest(
        String(opts.negativeControls),
        "negative-control pair",
      );
      const manifest = readArtifactJsonWithDigest(
        String(opts.evaluationManifest),
        "evaluation manifest",
      );
      const evaluatorBundle = readArtifactJsonWithDigest(
        String(opts.evaluatorBundle),
        "evaluator bundle",
      );
      const evaluatorCodeDigest = sha256Bytes(
        readArtifactBytes(String(opts.evaluatorCode), "evaluator code"),
      );
      const evaluatorConfigDigest = sha256Bytes(
        readArtifactBytes(String(opts.evaluatorConfig), "evaluator config"),
      );
      const bundle = projectImprovementBundleFromArtifacts({
        candidate: parseCandidateMetadata(readArtifactJson(String(opts.candidate), "candidate")),
        championVariantId: text(opts.championVariant, "champion variant id"),
        challengerVariantId: text(opts.challengerVariant, "challenger variant id"),
        development: {
          run: parseTournamentPair(development.value, "development pair"),
          digest: development.digest,
          artifactRef: safeArtifactRef(opts.developmentRef, "development ref"),
        },
        heldOut: {
          run: parseTournamentPair(heldOut.value, "held-out pair"),
          digest: heldOut.digest,
          artifactRef: safeArtifactRef(opts.heldOutRef, "held-out ref"),
        },
        negativeControls: {
          run: parseTournamentPair(negativeControls.value, "negative-control pair"),
          digest: negativeControls.digest,
          artifactRef: safeArtifactRef(opts.negativeControlsRef, "negative-control ref"),
        },
        evaluationManifest: parseEvaluationManifest(
          manifest.value,
          manifest.digest,
          String(opts.manifestRef),
        ),
        evaluator: parseEvaluatorBundle(
          evaluatorBundle.value,
          evaluatorBundle.digest,
          evaluatorCodeDigest,
          evaluatorConfigDigest,
          String(opts.evaluatorBundleRef),
          String(opts.evaluatorCodeRef),
          String(opts.evaluatorConfigRef),
        ),
        ciEvidence: parseCiEvidence(readArtifactJson(String(opts.ciEvidence), "CI evidence")),
        evidenceRefs: (opts.evidenceRef as string[]).map((ref, index) =>
          text(ref, `evidence ref ${index}`),
        ),
        calibration: Boolean(opts.calibration),
      });
      writeImprovementBundleAtomic(String(opts.outputDir), bundle);
      process.stdout.write(`${String(opts.outputDir)}\n`);
    });
}
