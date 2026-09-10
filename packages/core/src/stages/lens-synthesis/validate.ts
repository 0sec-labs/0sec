import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, mkdtempSync, mkdirSync, openSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, posix, relative, resolve } from "node:path";
import { getRates, MODEL_PRICING, type RuntimeMode } from "@0sec/shared";
import { ScanCostLedger } from "../../agent/cost-ledger.js";
import { aggregateScorecard, pickChampion, type BenchCaseResult, type BenchScorecard } from "../../bench/index.js";
import { canonicalEvolutionJson } from "../../improvement/config.js";
import { loadAppsecFinderLenses } from "../appsec-catalog.js";
import { runHuntScan, type FinderLens } from "../hunt-scan.js";
import type { LensBaselineSnapshot, LensProbe, LensProbeFinding, LensProbeOutcome, LensScorecardSummary, LensTrialSummary, LensValidationReceipt, LensValidationReport, PreparedValidationCorpus, SynthesizedArchetype, ValidationCorpus, ValidationFixture } from "./types.js";

const MAX_CORPUS_BYTES = 64 * 1024 * 1024;
const SHA256 = /^sha256:[a-f0-9]{64}$/;
const hashBytes = (bytes: Buffer): string => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const jsonCopy = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const digest = (value: unknown): string => hashBytes(Buffer.from(canonicalEvolutionJson(jsonCopy(value))));
const finiteNonnegative = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value) && value >= 0;
const lineNumber = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value > 0;
const nonempty = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;

interface FixtureFile { absolute: string; path: string; digest: string; bytes: number }
interface FixtureInspection { directory: boolean; digest: string; files: FixtureFile[] }

function readFixtureFile(path: string): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_CORPUS_BYTES) throw new Error(`unsafe or oversized fixture file: ${path}`);
    const bytes = readFileSync(fd);
    if (bytes.length !== stat.size) throw new Error(`fixture changed while being read: ${path}`);
    return bytes;
  } finally { closeSync(fd); }
}

function inspectFixture(path: string): FixtureInspection {
  const root = resolve(path);
  if (realpathSync(root) !== root) throw new Error(`fixture aliases are not allowed: ${path}`);
  const stat = lstatSync(root);
  if (!stat.isFile() && !stat.isDirectory()) throw new Error(`fixture is not a regular file or directory: ${path}`);
  const files: FixtureFile[] = [];
  let bytes = 0;
  const visit = (absolute: string): void => {
    const entry = lstatSync(absolute);
    if (entry.isSymbolicLink()) throw new Error(`fixture contains a symlink: ${absolute}`);
    if (entry.isDirectory()) {
      for (const name of readdirSync(absolute).sort()) visit(join(absolute, name));
      return;
    }
    const content = readFixtureFile(absolute);
    bytes += content.length;
    if (bytes > MAX_CORPUS_BYTES || files.length >= 10000) throw new Error("fixture exceeds bounded evaluation size");
    files.push({ absolute, path: relative(root, absolute).replace(/\\/g, "/"), digest: hashBytes(content), bytes: content.length });
  };
  visit(root);
  if (files.length === 0) throw new Error(`fixture is empty: ${path}`);
  return { directory: stat.isDirectory(), files, digest: stat.isFile() ? files[0]!.digest : digest(files.map(({ path, digest: fileDigest }) => ({ path, digest: fileDigest }))) };
}

function relativeFindingPath(path: string, sourceRoot: string): string {
  const slashes = path.replace(/\\/g, "/");
  return posix.normalize(isAbsolute(slashes) ? relative(sourceRoot, slashes).replace(/\\/g, "/") : slashes);
}

/** One authoritative corpus check, shared by curation and every evaluation pass. */
export function prepareValidationCorpus(corpus: ValidationCorpus): PreparedValidationCorpus {
  if (!corpus || !Array.isArray(corpus.positives) || corpus.positives.length === 0) throw new Error("no positive fixtures");
  if (!Array.isArray(corpus.negativeControls) || corpus.negativeControls.length === 0) throw new Error("no negative controls");
  if (!Array.isArray(corpus.heldOut) || corpus.heldOut.length === 0) throw new Error("no held-out fixtures");
  if (corpus.baselineDigest !== undefined && !SHA256.test(corpus.baselineDigest)) throw new Error("invalid baseline digest");
  const ids = new Set<string>();
  const physicalFiles = new Set<string>();
  const contents = new Set<string>();
  let bytes = 0;
  const prepare = (fixture: ValidationFixture, negative: boolean): ValidationFixture => {
    if (!fixture || !nonempty(fixture.id) || !nonempty(fixture.path)) throw new Error("fixture id and path are required");
    if (ids.has(fixture.id)) throw new Error(`duplicate fixture id: ${fixture.id}`);
    ids.add(fixture.id);
    if (negative && !nonempty(fixture.cleanProvenance)) throw new Error(`negative control lacks independent cleanProvenance: ${fixture.id}`);
    if (!negative && (!nonempty(fixture.expectedCwe) || !/^CWE-\d+$/i.test(fixture.expectedCwe) || !nonempty(fixture.expectedFile))) {
      throw new Error(`positive fixture requires expected CWE and file identity: ${fixture.id}`);
    }
    if (!negative && fixture.expectedLine === undefined && fixture.expectedRange === undefined) throw new Error(`positive fixture requires an expected line or range: ${fixture.id}`);
    if (fixture.expectedLine !== undefined && !lineNumber(fixture.expectedLine)) throw new Error(`invalid expected line: ${fixture.id}`);
    if (fixture.expectedRange !== undefined && (!Array.isArray(fixture.expectedRange) || fixture.expectedRange.length !== 2
      || !lineNumber(fixture.expectedRange[0]) || !lineNumber(fixture.expectedRange[1]) || fixture.expectedRange[0] > fixture.expectedRange[1]
      || (fixture.expectedLine !== undefined && (fixture.expectedLine < fixture.expectedRange[0] || fixture.expectedLine > fixture.expectedRange[1])))) {
      throw new Error(`invalid expected range: ${fixture.id}`);
    }
    const inspection = inspectFixture(fixture.path);
    if (fixture.contentDigest !== undefined && fixture.contentDigest !== inspection.digest) throw new Error(`fixture content digest mismatch: ${fixture.id}`);
    if (contents.has(inspection.digest)) throw new Error(`duplicate fixture content: ${fixture.id}`);
    contents.add(inspection.digest);
    for (const file of inspection.files) {
      if (physicalFiles.has(file.absolute)) throw new Error(`fixture splits overlap: ${fixture.id}`);
      physicalFiles.add(file.absolute);
      bytes += file.bytes;
    }
    if (bytes > MAX_CORPUS_BYTES) throw new Error("corpus exceeds 64 MiB");
    const copy = structuredClone(fixture);
    copy.path = resolve(fixture.path);
    copy.contentDigest = inspection.digest;
    if (copy.expectedFile !== undefined) {
      const sourceRoot = inspection.directory ? copy.path : dirname(copy.path);
      copy.expectedFile = relativeFindingPath(copy.expectedFile, sourceRoot);
      if (copy.expectedFile === ".." || copy.expectedFile.startsWith("../") || !inspection.files.some((file) =>
        relativeFindingPath(file.absolute, sourceRoot) === copy.expectedFile)) throw new Error(`expected file is outside the fixture: ${fixture.id}`);
    }
    return copy;
  };
  return {
    positives: corpus.positives.map((fixture) => prepare(fixture, false)),
    heldOut: corpus.heldOut.map((fixture) => prepare(fixture, false)),
    negativeControls: corpus.negativeControls.map((fixture) => prepare(fixture, true)),
    ...(corpus.baselineDigest ? { baselineDigest: corpus.baselineDigest } : {}),
  };
}

function copyCorpus(corpus: ValidationCorpus, directory: string): ValidationCorpus {
  let index = 0;
  const copy = (fixture: ValidationFixture): ValidationFixture => {
    const inspection = inspectFixture(fixture.path);
    if (inspection.digest !== fixture.contentDigest) throw new Error(`fixture changed before snapshot: ${fixture.id}`);
    const destination = join(directory, String(index++));
    mkdirSync(destination, { mode: 0o700 });
    const path = inspection.directory ? destination : join(destination, basename(fixture.path));
    for (const file of inspection.files) {
      const target = inspection.directory ? join(destination, file.path) : path;
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
      const content = readFixtureFile(file.absolute);
      if (hashBytes(content) !== file.digest) throw new Error(`fixture changed during snapshot: ${fixture.id}`);
      writeFileSync(target, content, { mode: 0o400, flag: "wx" });
    }
    return { ...structuredClone(fixture), path };
  };
  return { positives: corpus.positives.map(copy), heldOut: corpus.heldOut!.map(copy), negativeControls: corpus.negativeControls.map(copy), ...(corpus.baselineDigest ? { baselineDigest: corpus.baselineDigest } : {}) };
}

const CATEGORY_CWE: Record<string, string> = {
  ssrf: "CWE-918", "command-injection": "CWE-78", "code-injection": "CWE-94", "path-traversal": "CWE-22",
  "sql-injection": "CWE-89", xss: "CWE-79", cors: "CWE-942", "use-after-free": "CWE-416", "double-free": "CWE-415",
  "heap-overflow": "CWE-122", "stack-buffer-overflow": "CWE-121", "out-of-bounds-read": "CWE-125", "out-of-bounds-write": "CWE-787",
  "integer-overflow": "CWE-190", "integer-truncation": "CWE-197", "race-condition": "CWE-362", "type-confusion": "CWE-843",
  "null-pointer-deref": "CWE-476", "null-deref": "CWE-476", "format-string": "CWE-134", "uninitialized-memory": "CWE-908",
  "denial-of-service": "CWE-400", "missing-validation": "CWE-20", "prototype-pollution": "CWE-1321", "unsafe-deserialization": "CWE-502",
  "regex-dos": "CWE-1333", "information-disclosure": "CWE-200", "crypto-misuse": "CWE-327", "security-misconfiguration": "CWE-16",
  "known-vulnerable-package": "CWE-1104", "supply-chain": "CWE-1357", toctou: "CWE-367",
};
const findingCwe = (category?: string): string | undefined => category ? CATEGORY_CWE[category.toLowerCase()] ?? category.toUpperCase() : undefined;

function matches(finding: LensProbeFinding, fixture: ValidationFixture): boolean {
  if (findingCwe(finding.cwe) !== fixture.expectedCwe?.toUpperCase() || !finding.file) return false;
  const sourceRoot = lstatSync(fixture.path).isDirectory() ? fixture.path : dirname(fixture.path);
  if (relativeFindingPath(finding.file, sourceRoot) !== fixture.expectedFile || !lineNumber(finding.line)) return false;
  return fixture.expectedRange
    ? finding.line >= fixture.expectedRange[0] && finding.line <= fixture.expectedRange[1]
    : finding.line === fixture.expectedLine;
}

export interface FinderLensProbeOptions {
  runtime?: RuntimeMode;
  models?: string[];
  depth?: "quick" | "deep";
  concurrency?: number;
  baseLenses?: () => FinderLens[];
  log?: (message: string) => void;
}

/** Real finder discovery only: it neither verifies nor confirms a vulnerability. */
export function makeFinderLensProbe(opts: FinderLensProbeOptions = {}): LensProbe {
  const loader = opts.baseLenses ?? loadAppsecFinderLenses;
  const load = (): FinderLens[] => { const lenses = loader(); return lenses.length ? lenses : [{ id: "", challengeHint: "" }]; };
  const lenses = structuredClone(load());
  const baselineDigest = digest(lenses);
  const models = opts.models ? [...opts.models] : undefined;
  const runtime = opts.runtime ?? "auto";
  const depth = opts.depth ?? "quick";
  const concurrency = opts.concurrency ?? 4;
  const log = opts.log;
  const snapshot = () => {
    if (digest(load()) !== baselineDigest) throw new Error("baseline lens snapshot changed");
    return { lenses: structuredClone(lenses), digest: baselineDigest };
  };
  return Object.assign(async (candidate: FinderLens | null, fixture: ValidationFixture): Promise<LensProbeOutcome> => {
    const ledger = new ScanCostLedger();
    const started = performance.now();
    try {
      snapshot();
      const directory = lstatSync(fixture.path).isDirectory();
      const result = await runHuntScan({
        sourceRoot: directory ? fixture.path : dirname(fixture.path),
        candidates: [{ path: directory ? "." : basename(fixture.path) }],
        runtime, ...(models ? { models: [...models] } : {}), depth, concurrency,
        lenses: candidate ? [...structuredClone(lenses), structuredClone(candidate)] : structuredClone(lenses),
        costLedger: ledger, ...(log ? { log } : {}),
      });
      snapshot();
      const usage = ledger.tokenUsage();
      const cost = ledger.costBreakdown();
      const priced = cost !== null && cost.breakdown.every((entry) => getRates(entry.model) !== MODEL_PRICING.default);
      const attribution = new Map(result.records.map((record) => [record.finding, record]));
      const findings = result.findings.map((finding): LensProbeFinding => {
        const record = attribution.get(finding);
        return {
          cwe: findingCwe(finding.category), file: finding.reviewAnnotation?.path, line: finding.reviewAnnotation?.startLine,
          ...(record?.lensId ? { lensId: record.lensId } : {}),
          ...(record?.lensVersionDigest ? { lensVersionDigest: record.lensVersionDigest } : {}),
          findingDigest: digest(finding), evidence: jsonCopy(finding),
        };
      });
      const incomplete = result.scanned === 0 || result.finderCompleted !== result.scanned || result.finderTimedOut > 0
        || result.finderErrored > 0 || result.costCeilingExceeded || (result.incompleteCoverage?.length ?? 0) > 0;
      return {
        surfaced: findings.length > 0, findings,
        ...(priced ? { costUsd: cost.costUsd } : {}), durationMs: performance.now() - started,
        inputTokens: usage.inputTokens, outputTokens: usage.outputTokens,
        ...(incomplete ? { error: "finder coverage incomplete" } : !priced ? { error: "finder usage or pricing unavailable" } : {}),
      };
    } catch (error) {
      return { surfaced: false, findings: [], durationMs: performance.now() - started, error: error instanceof Error ? error.message : String(error) };
    }
  }, { baselineSnapshot: snapshot });
}

function fixtureCase(fixture: ValidationFixture, negative: boolean, outcome: LensProbeOutcome): BenchCaseResult {
  const complete = !outcome.error && finiteNonnegative(outcome.costUsd) && finiteNonnegative(outcome.durationMs) && Array.isArray(outcome.findings);
  const surfaced = negative ? (outcome.findings?.length ?? 0) > 0 : (outcome.findings ?? []).some((finding) => matches(finding, fixture));
  const verdict = !complete ? "inconclusive" : surfaced ? "verified" : "refuted";
  // Bench numeric totals require numbers; an unknown cost still has an explicit
  // inconclusive verdict and remains absent in the retained probe outcome.
  const costUsd = finiteNonnegative(outcome.costUsd) ? outcome.costUsd : 0;
  const inputTokens = finiteNonnegative(outcome.inputTokens) ? outcome.inputTokens : 0;
  const outputTokens = finiteNonnegative(outcome.outputTokens) ? outcome.outputTokens : 0;
  return {
    id: fixture.id, kind: "source-audit", objective: "finding-match", knownNegative: negative, tags: [], passAtK: 1, attemptPolicy: "pass-at-k",
    attempts: [{ attemptIndex: 0, status: verdict, confidence: null, notes: outcome.error ?? (!complete ? "required probe evidence or metrics unavailable" : "independent fixture identity comparison"),
      costUsd, attackTurns: 0, inputTokens, outputTokens, totalTokens: inputTokens + outputTokens, durationMs: finiteNonnegative(outcome.durationMs) ? outcome.durationMs : 0 }],
    verdict, falsePositive: negative && verdict === "verified", costUsd, attackTurns: 0, inputTokens, outputTokens, totalTokens: inputTokens + outputTokens,
  };
}

function score(cases: BenchCaseResult[]): BenchScorecard {
  return aggregateScorecard({ manifestId: "lens-validation", ciSubset: false, passAtK: 1, attemptPolicy: "pass-at-k", maxTurns: 1, costCeilingUsd: null, cases });
}
function summary(variantId: string, card: BenchScorecard): LensScorecardSummary {
  return { variantId, successRate: card.successRate, fpRate: card.fpRate, verified: card.totals.verified, falsePositives: card.falsePositives };
}

export interface ValidateOptions { probe: LensProbe; trials?: number; log?: (message: string) => void }

/** Immutable inputs, independent expectations, repeated development and held-out gates. */
export async function validateCandidateLens(archetype: SynthesizedArchetype, corpus: ValidationCorpus, opts: ValidateOptions): Promise<LensValidationReport> {
  const lensId = archetype.content.id;
  let baseline = score([]);
  let challenger = score([]);
  const trials: LensTrialSummary[] = [];
  const heldOutTrials: LensTrialSummary[] = [];
  const cases: LensValidationReceipt["cases"] = [];
  const reasons: string[] = [];
  let prepared: ValidationCorpus | undefined;
  let initialBaseline: LensBaselineSnapshot | undefined;
  let candidateDigest: string | undefined;
  let directory: string | undefined;
  let checkDrift: ((fixture?: ValidationFixture) => void) | undefined;
  try {
    const repeats = opts.trials ?? 2;
    if (!Number.isSafeInteger(repeats) || repeats < 2 || repeats > 10) throw new Error("trials must be an integer between 2 and 10");
    prepared = prepareValidationCorpus(corpus);
    const corpusDigest = digest(prepared);
    const inputMetadataDigest = digest(corpus);
    const originals = new Map([...prepared.positives, ...prepared.heldOut!, ...prepared.negativeControls].map((fixture) => [fixture.id, fixture]));
    if (typeof opts.probe.baselineSnapshot !== "function") throw new Error("probe must expose its real baseline snapshot");
    initialBaseline = structuredClone(opts.probe.baselineSnapshot());
    if (!Array.isArray(initialBaseline.lenses) || initialBaseline.lenses.some((lens) => typeof lens.id !== "string" || typeof lens.challengeHint !== "string")
      || initialBaseline.digest !== digest(initialBaseline.lenses)) throw new Error("invalid baseline snapshot digest");
    if (prepared.baselineDigest !== undefined && prepared.baselineDigest !== initialBaseline.digest) throw new Error("baseline digest does not match the requested corpus");
    candidateDigest = digest(archetype);
    const candidate = { id: lensId, challengeHint: archetype.content.challenge_hint };
    directory = mkdtempSync(join(tmpdir(), "0sec-lens-evaluation-"));
    const copied = copyCorpus(prepared, directory);
    const copyDigest = digest(prepareValidationCorpus(copied));
    checkDrift = (fixture) => {
      const current = opts.probe.baselineSnapshot();
      if (current.digest !== initialBaseline!.digest || digest(current.lenses) !== initialBaseline!.digest) throw new Error("baseline lens snapshot changed during validation");
      if (digest(corpus) !== inputMetadataDigest) throw new Error("fixture expectations changed during validation");
      if (fixture) {
        const original = originals.get(fixture.id)!;
        if (inspectFixture(original.path).digest !== original.contentDigest || inspectFixture(fixture.path).digest !== fixture.contentDigest) {
          throw new Error(`fixture content changed during validation: ${fixture.id}`);
        }
      } else if (digest(prepareValidationCorpus(corpus)) !== corpusDigest || digest(prepareValidationCorpus(copied)) !== copyDigest) {
        throw new Error("fixture content or expectations changed during validation");
      }
      if (digest(archetype) !== candidateDigest) throw new Error("candidate changed during validation");
    };
    for (let trialIndex = 0; trialIndex < repeats; trialIndex++) {
      for (const lane of ["development", "held-out"] as const) {
        const cards: Record<"baseline" | "challenger", BenchScorecard> = { baseline: score([]), challenger: score([]) };
        const costs: Record<"baseline" | "challenger", number | null> = { baseline: 0, challenger: 0 };
        const positives = lane === "development" ? copied.positives : copied.heldOut!;
        for (const variant of trialIndex % 2 === 0 ? ["baseline", "challenger"] as const : ["challenger", "baseline"] as const) {
          const results: BenchCaseResult[] = [];
          for (const [fixtures, negative] of [[positives, false], [copied.negativeControls, true]] as const) {
            for (const fixture of fixtures) {
              checkDrift(fixture);
              let outcome: LensProbeOutcome;
              try { outcome = await opts.probe(variant === "baseline" ? null : structuredClone(candidate), structuredClone(fixture)); }
              catch (error) { outcome = { surfaced: false, findings: [], error: error instanceof Error ? error.message : String(error) }; }
              const result = fixtureCase(fixture, negative, outcome);
              results.push(result);
              const previousCost = costs[variant];
              costs[variant] = previousCost !== null && finiteNonnegative(outcome.costUsd) ? previousCost + outcome.costUsd : null;
              const retained = jsonCopy(outcome);
              if (!finiteNonnegative(retained.costUsd)) delete retained.costUsd;
              if (!finiteNonnegative(retained.durationMs)) delete retained.durationMs;
              if (!finiteNonnegative(retained.inputTokens)) delete retained.inputTokens;
              if (!finiteNonnegative(retained.outputTokens)) delete retained.outputTokens;
              cases.push({ trialIndex, lane, variant, fixtureId: fixture.id, negativeControl: negative, outcome: retained });
              checkDrift(fixture);
            }
          }
          cards[variant] = score(results);
        }
        const base = cards.baseline;
        const chal = cards.challenger;
        const complete = [...base.cases, ...chal.cases].every((entry) => entry.verdict !== "inconclusive");
        const caughtMiss = chal.cases.filter((entry) => !entry.knownNegative && entry.verdict === "verified").length === positives.length;
        const noFpRegression = chal.falsePositives <= base.falsePositives && chal.fpRate <= base.fpRate;
        const better = chal.successRate > base.successRate;
        const champion = pickChampion([{ variant: { id: "baseline" }, scorecard: base }, { variant: { id: "challenger" }, scorecard: chal }]) === "challenger";
        if (!complete) reasons.push(`${lane} trial ${trialIndex}: inconclusive probe evidence or metrics`);
        if (!caughtMiss) reasons.push(`${lane} trial ${trialIndex}: missed intended positive finding`);
        if (!noFpRegression) reasons.push(`${lane} trial ${trialIndex}: FP regression`);
        if (!better || !champion) reasons.push(`${lane} trial ${trialIndex}: no improvement over baseline`);
        const trial: LensTrialSummary = { trialIndex, caughtMiss, noFpRegression, challengerSuccessRate: chal.successRate, baselineSuccessRate: base.successRate,
          challengerFpRate: chal.fpRate, baselineFpRate: base.fpRate, challengerCostUsd: costs.challenger, baselineCostUsd: costs.baseline };
        (lane === "development" ? trials : heldOutTrials).push(trial);
        if (lane === "development") { baseline = base; challenger = chal; }
      }
    }
    checkDrift();
  } catch (error) {
    reasons.push(error instanceof Error ? error.message : String(error));
    try { checkDrift?.(); } catch (drift) { reasons.push(drift instanceof Error ? drift.message : String(drift)); }
  } finally {
    if (directory) rmSync(directory, { recursive: true, force: true });
  }
  const passed = reasons.length === 0 && trials.length >= 2 && heldOutTrials.length === trials.length;
  const reason = passed ? `champion across ${trials.length} development and held-out trials` : `rejected: ${reasons.join("; ")}`;
  let receipt: LensValidationReceipt | undefined;
  if (prepared && initialBaseline && candidateDigest) {
    const unsigned = { schemaVersion: 1 as const, candidateDigest, baselineSnapshotDigest: initialBaseline.digest, baselineLenses: initialBaseline.lenses,
      fixtureCorpusDigest: digest(prepared), corpus: prepared, trials, heldOutTrials, cases, passed, rejectionReasons: reasons };
    receipt = { ...unsigned, receiptDigest: digest(unsigned) };
  }
  opts.log?.(`[lens-synth] validate ${lensId}: ${reason}`);
  return { lensId, passed, reason, isChampion: passed, caughtMiss: trials.length > 0 && trials.every((trial) => trial.caughtMiss),
    noFpRegression: trials.length > 0 && trials.every((trial) => trial.noFpRegression), baseline: summary("baseline", baseline), challenger: summary("challenger", challenger),
    ...(receipt ? { receipt } : {}), heldOut: { caught: heldOutTrials.length > 0 && heldOutTrials.every((trial) => trial.caughtMiss), details: reason } };
}
