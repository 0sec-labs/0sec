#!/usr/bin/env node

import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { wilsonIntervalTuple } from "./wilson.js";

export const WINDOWS_ATTEMPT_SCHEMA = "pwnkit.windows-research-attempt/v1" as const;
export const WINDOWS_LEDGER_SCHEMA = "pwnkit.windows-research-ledger/v1" as const;

export type GroundTruth = "positive" | "negative" | "unknown";
export type ProofStatus =
  | "reproduced"
  | "not_reproduced"
  | "inconclusive"
  | "safety_rejected"
  | "not_attempted";

export interface WindowsResearchAttemptInput {
  schemaVersion: typeof WINDOWS_ATTEMPT_SCHEMA;
  mode: "contract" | "live";
  campaignId: string;
  caseId: string;
  attempt: number;
  groundTruth: GroundTruth;
  label: { source: string; sha256: string; sealedAt: string; keyId: string; signature: string };
  repoShas: { zeroverse: string; pwnkit: string; zeroCloud: string };
  windowsBuildLabEx: string;
  campaignManifestSha256: string;
  scopeManifestSha256: string;
  receiptPath?: string;
  importVerdictPath?: string;
  artifactPaths?: string[];
  discovery: {
    candidateEmitted: boolean;
    candidateId?: string;
    model?: string;
    runtime?: string;
    agentRole?: string;
    agentCount: number;
    durationMs: number;
  };
  proof: {
    status: ProofStatus;
    targetTrials: number;
    cleanControls: number;
    confirmations: number;
    crashSignature?: string;
    pwnkitImportPassed: boolean;
    rejectionReason?: string;
  };
  telemetry: {
    startedAt: string;
    completedAt: string;
    proveDurationMs: number;
    importDurationMs: number;
    totalDurationMs: number;
    inputTokens: number | null;
    outputTokens: number | null;
    cachedTokens: number | null;
    workerMinutes: number | null;
    modelCostUsd: number | null;
    computeCostUsd: number | null;
    totalCostUsd: number | null;
    costBasis: string;
  };
  safety: {
    scopeFresh: boolean;
    authorizedProgram: boolean;
    workerBuildBound: boolean;
    triggerAllowlisted: boolean;
    controlFirst: boolean;
    cleanControls: boolean;
    sidecarsRevalidated: boolean;
    artifactsRetained: boolean;
    preExecutionGatePassed: boolean;
    executed: boolean;
    weaponization: false;
    autoDisclosure: false;
    reasons: string[];
  };
}

export interface WindowsResearchLedgerRow
  extends Omit<WindowsResearchAttemptInput, "receiptPath" | "importVerdictPath" | "artifactPaths"> {
  ledgerSchema: typeof WINDOWS_LEDGER_SCHEMA;
  rowId: string;
  receiptSha256: string | null;
  artifacts: Array<{ name: string; sha256: string; bytes: number }>;
  claimEligible: boolean;
  rowSha256: string;
}

interface RateMetric {
  successes: number;
  total: number;
  rate: number | null;
  ci95: [number, number] | null;
}

export interface WindowsResearchSummary {
  schemaVersion: "pwnkit.windows-research-summary/v1";
  rows: number;
  claimEligibleRows: number;
  singleAttempt: {
    confusion: { tp: number; fp: number; tn: number; fn: number };
    precision: RateMetric;
    recall: RateMetric;
    proofYield: RateMetric;
  };
  bestOfN: {
    cases: number;
    confusion: { tp: number; fp: number; tn: number; fn: number };
    precision: RateMetric;
    recall: RateMetric;
    proofYield: RateMetric;
  };
  outcomes: Record<ProofStatus, number>;
  contractValidationOutcomes: Record<ProofStatus, number>;
  telemetry: {
    totalDurationMs: { median: number | null; p95: number | null };
    totalCostUsd: { median: number | null; p95: number | null };
    costPerReproducedUsd: number | null;
  };
  safety: {
    gatePassRate: RateMetric;
    blockedBeforeExecution: number;
    executionsAfterFailedPreExecutionGate: number;
    weaponizationRows: number;
    autoDisclosureRows: number;
  };
}

const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^[a-f0-9]{40}$/;
const IMPORT_VERDICT_SCHEMA = "pwnkit.windows-hyperv-import-verdict/v1";
const FORBIDDEN_KEYS = new Set([
  "trigger_argv",
  "control_argv",
  "exploit_payload",
  "exploit_source",
  "poc_source",
  "shell_command",
]);

function requireText(value: string, name: string): void {
  if (!value.trim()) throw new Error(`${name} must be non-empty`);
}

function requireIso(value: string, name: string): number {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new Error(`${name} must be an ISO-8601 timestamp`);
  return parsed;
}

function requireCount(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`);
}

function requireDuration(value: number, name: string): void {
  if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a non-negative duration`);
}

function requireNullableMeasurement(value: number | null, name: string): void {
  if (value !== null && (!Number.isFinite(value) || value <= 0)) {
    throw new Error(`${name} must be positive or null; placeholder zero is forbidden`);
  }
}

function rejectExecutableMaterial(value: unknown): void {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach(rejectExecutableMaterial);
    return;
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.has(key.toLowerCase())) {
      throw new Error(`Windows research ledger input contains forbidden executable field: ${key}`);
    }
    rejectExecutableMaterial(child);
  }
}

function rejectSecretLikeText(value: unknown, path = "attempt"): void {
  if (typeof value === "string") {
    if (value.length > 1000 || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(value)) {
      throw new Error(`${path} contains oversized or control-character text`);
    }
    if (/(?:github_pat_|gh[pousr]_|authorization\s*:\s*bearer|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i.test(value)) {
      throw new Error(`${path} contains secret-like text`);
    }
    return;
  }
  if (Array.isArray(value)) return value.forEach((child, index) => rejectSecretLikeText(child, `${path}[${index}]`));
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (!["receiptPath", "importVerdictPath", "artifactPaths"].includes(key)) {
        rejectSecretLikeText(child, `${path}.${key}`);
      }
    }
  }
}

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as Record<string, unknown>;
}

function exact(value: unknown, name: string, keys: readonly string[]): Record<string, unknown> {
  const row = record(value, name);
  const allowed = new Set(keys);
  const unknown = Object.keys(row).filter((key) => !allowed.has(key));
  if (unknown.length) throw new Error(`${name} contains unsupported field(s): ${unknown.join(", ")}`);
  return row;
}

function validateInputShape(value: unknown): asserts value is WindowsResearchAttemptInput {
  const top = exact(value, "attempt", [
    "schemaVersion", "mode", "campaignId", "caseId", "attempt", "groundTruth", "label",
    "repoShas", "windowsBuildLabEx", "campaignManifestSha256", "scopeManifestSha256",
    "receiptPath", "importVerdictPath", "artifactPaths", "discovery", "proof", "telemetry", "safety",
  ]);
  const label = exact(top.label, "label", ["source", "sha256", "sealedAt", "keyId", "signature"]);
  const repoShas = exact(top.repoShas, "repoShas", ["zeroverse", "pwnkit", "zeroCloud"]);
  exact(top.discovery, "discovery", [
    "candidateEmitted", "candidateId", "model", "runtime", "agentRole", "agentCount", "durationMs",
  ]);
  exact(top.proof, "proof", [
    "status", "targetTrials", "cleanControls", "confirmations", "crashSignature",
    "pwnkitImportPassed", "rejectionReason",
  ]);
  exact(top.telemetry, "telemetry", [
    "startedAt", "completedAt", "proveDurationMs", "importDurationMs", "totalDurationMs",
    "inputTokens", "outputTokens", "cachedTokens", "workerMinutes", "modelCostUsd",
    "computeCostUsd", "totalCostUsd", "costBasis",
  ]);
  exact(top.safety, "safety", [
    "scopeFresh", "authorizedProgram", "workerBuildBound", "triggerAllowlisted", "controlFirst",
    "cleanControls", "sidecarsRevalidated", "artifactsRetained", "preExecutionGatePassed",
    "executed", "weaponization", "autoDisclosure", "reasons",
  ]);
  if (!Object.values({
    schemaVersion: top.schemaVersion, mode: top.mode, campaignId: top.campaignId, caseId: top.caseId,
    groundTruth: top.groundTruth, windowsBuildLabEx: top.windowsBuildLabEx,
    campaignManifestSha256: top.campaignManifestSha256, scopeManifestSha256: top.scopeManifestSha256,
  }).every((item) => typeof item === "string")) throw new Error("attempt string fields are malformed");
  if (!Object.values(label).every((item) => typeof item === "string")
    || !Object.values(repoShas).every((item) => typeof item === "string")) {
    throw new Error("label and repository identity fields must be strings");
  }
  if (!Array.isArray(top.artifactPaths) && top.artifactPaths !== undefined) throw new Error("artifactPaths must be an array");
  if (Array.isArray(top.artifactPaths) && !top.artifactPaths.every((item) => typeof item === "string")) {
    throw new Error("artifactPaths entries must be strings");
  }
  if (top.receiptPath !== undefined && typeof top.receiptPath !== "string") throw new Error("receiptPath must be a string");
  if (top.importVerdictPath !== undefined && typeof top.importVerdictPath !== "string") {
    throw new Error("importVerdictPath must be a string");
  }
  const discovery = record(top.discovery, "discovery");
  const proof = record(top.proof, "proof");
  const safety = record(top.safety, "safety");
  for (const key of ["candidateEmitted"] as const) if (typeof discovery[key] !== "boolean") throw new Error(`discovery.${key} must be boolean`);
  for (const key of ["pwnkitImportPassed"] as const) if (typeof proof[key] !== "boolean") throw new Error(`proof.${key} must be boolean`);
  for (const key of ["scopeFresh", "authorizedProgram", "workerBuildBound", "triggerAllowlisted", "controlFirst", "cleanControls", "sidecarsRevalidated", "artifactsRetained", "preExecutionGatePassed", "executed", "weaponization", "autoDisclosure"] as const) {
    if (typeof safety[key] !== "boolean") throw new Error(`safety.${key} must be boolean`);
  }
  if (!Array.isArray(safety.reasons) || !safety.reasons.every((item) => typeof item === "string" && item.length <= 500)) {
    throw new Error("safety.reasons must be bounded strings");
  }
  if (!(["contract", "live"] as unknown[]).includes(top.mode)
    || !(["positive", "negative", "unknown"] as unknown[]).includes(top.groundTruth)
    || !(["reproduced", "not_reproduced", "inconclusive", "safety_rejected", "not_attempted"] as unknown[]).includes(proof.status)) {
    throw new Error("attempt enum field is invalid");
  }
}

interface ImportVerdict {
  verdictSchema: typeof IMPORT_VERDICT_SCHEMA;
  campaignId: string;
  buildLabEx: string;
  confirmations: number;
  cleanControls: number;
  distinctDumpArtifacts: number;
  dumpHashBasis: "retained-bundle-bytes";
  receiptSha256: string;
  passed: true;
}

function parseImportVerdict(path: string): ImportVerdict {
  const value = JSON.parse(readOpenedFile(path, 1024 * 1024).toString("utf8")) as unknown;
  const row = exact(value, "import verdict", [
    "verdictSchema", "executionOrigin", "producer", "schemaVersion", "campaignId", "buildLabEx",
    "signature", "confirmations", "requiredConfirmations", "cleanControls", "distinctDumpArtifacts",
    "dumpHashBasis", "receiptSha256", "sidecarsRehashed", "passed",
  ]);
  if (row.verdictSchema !== IMPORT_VERDICT_SCHEMA || row.passed !== true
    || row.dumpHashBasis !== "retained-bundle-bytes" || !SHA256.test(String(row.receiptSha256))
    || typeof row.campaignId !== "string" || typeof row.buildLabEx !== "string"
    || !Number.isSafeInteger(row.confirmations) || !Number.isSafeInteger(row.cleanControls)
    || !Number.isSafeInteger(row.distinctDumpArtifacts)) {
    throw new Error("invalid pwnkit Hyper-V import verdict");
  }
  return row as unknown as ImportVerdict;
}

function sha256Bytes(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function regularFileForLedger(path: string, base?: string): string {
  const absolute = resolve(path);
  if (!lstatSync(absolute, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`Windows research artifact is not a regular file: ${path}`);
  }
  const real = realpathSync(absolute);
  if (base) {
    const escaped = relative(realpathSync(base), real);
    if (escaped === ".." || escaped.startsWith(`..${sep}`) || isAbsolute(escaped)) {
      throw new Error(`Windows research artifact escapes its receipt bundle: ${path}`);
    }
  }
  return real;
}

function readOpenedFile(path: string, maximumBytes = 64 * 1024 * 1024): Buffer {
  const descriptor = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > maximumBytes) throw new Error(`Windows research artifact is too large: ${path}`);
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function hashFile(path: string, base?: string): { name: string; sha256: string; bytes: number } {
  const real = regularFileForLedger(path, base);
  const bytes = readOpenedFile(real);
  return { name: basename(real), sha256: sha256Bytes(bytes), bytes: bytes.byteLength };
}

function stableJson(value: unknown): string {
  if (value === undefined) return "null";
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .filter(([, child]) => child !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => `${JSON.stringify(key)}:${stableJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function verifyLiveLabelSeal(input: WindowsResearchAttemptInput): void {
  const key = process.env.PWNKIT_WINDOWS_LABEL_SEAL_KEY;
  if (!key || Buffer.byteLength(key) < 32) {
    throw new Error("live attempts require PWNKIT_WINDOWS_LABEL_SEAL_KEY with at least 32 bytes");
  }
  if (!input.label.keyId.trim() || !SHA256.test(input.label.signature)) {
    throw new Error("live label seal metadata is invalid");
  }
  const material = stableJson({
    campaignId: input.campaignId,
    caseId: input.caseId,
    groundTruth: input.groundTruth,
    labelSha256: input.label.sha256,
    sealedAt: input.label.sealedAt,
  });
  const expected = createHmac("sha256", key).update(material).digest();
  const actual = Buffer.from(input.label.signature, "hex");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    throw new Error("live ground-truth label seal signature is invalid");
  }
}

export function collectWindowsResearchAttempt(
  input: WindowsResearchAttemptInput,
): WindowsResearchLedgerRow {
  rejectExecutableMaterial(input);
  validateInputShape(input);
  rejectSecretLikeText(input);
  if (input.schemaVersion !== WINDOWS_ATTEMPT_SCHEMA) throw new Error("unsupported Windows attempt schema");
  for (const [name, value] of Object.entries({
    campaignId: input.campaignId,
    caseId: input.caseId,
    windowsBuildLabEx: input.windowsBuildLabEx,
    labelSource: input.label.source,
    costBasis: input.telemetry.costBasis,
  })) requireText(value, name);
  requireCount(input.attempt, "attempt");
  if (input.attempt < 1) throw new Error("attempt must be at least one");
  requireCount(input.discovery.agentCount, "agentCount");
  if (input.discovery.agentCount < 1) throw new Error("agentCount must be at least one");
  requireDuration(input.discovery.durationMs, "discovery.durationMs");
  for (const [name, value] of Object.entries({
    targetTrials: input.proof.targetTrials,
    cleanControls: input.proof.cleanControls,
    confirmations: input.proof.confirmations,
  })) requireCount(value, `proof.${name}`);
  for (const [name, value] of Object.entries({
    proveDurationMs: input.telemetry.proveDurationMs,
    importDurationMs: input.telemetry.importDurationMs,
    totalDurationMs: input.telemetry.totalDurationMs,
  })) requireDuration(value, `telemetry.${name}`);
  for (const [name, value] of Object.entries(input.repoShas)) {
    if (!GIT_SHA.test(value)) throw new Error(`repoShas.${name} must be a full lowercase git SHA`);
  }
  for (const [name, value] of Object.entries({
    label: input.label.sha256,
    campaignManifest: input.campaignManifestSha256,
    scopeManifest: input.scopeManifestSha256,
  })) if (!SHA256.test(value)) throw new Error(`${name} must be a lowercase SHA-256`);
  const started = requireIso(input.telemetry.startedAt, "telemetry.startedAt");
  const completed = requireIso(input.telemetry.completedAt, "telemetry.completedAt");
  const labelSealed = requireIso(input.label.sealedAt, "label.sealedAt");
  if (completed < started) throw new Error("attempt completed before it started");
  if (input.mode === "live" && labelSealed > started) {
    throw new Error("live ground-truth labels must be sealed before the attempt starts");
  }
  if (input.mode === "live") verifyLiveLabelSeal(input);
  for (const name of ["inputTokens", "outputTokens", "cachedTokens"] as const) {
    const value = input.telemetry[name];
    if (value !== null) requireCount(value, `telemetry.${name}`);
  }
  for (const name of ["workerMinutes", "modelCostUsd", "computeCostUsd", "totalCostUsd"] as const) {
    requireNullableMeasurement(input.telemetry[name], `telemetry.${name}`);
  }
  const mandatoryExecutionGates = [
    input.safety.scopeFresh, input.safety.authorizedProgram, input.safety.workerBuildBound,
    input.safety.triggerAllowlisted, input.safety.controlFirst, input.safety.preExecutionGatePassed,
  ];
  if (input.safety.executed && mandatoryExecutionGates.some((passed) => !passed)) {
    throw new Error("execution occurred without every mandatory pre-execution safety gate");
  }
  if (input.safety.weaponization || input.safety.autoDisclosure) {
    throw new Error("benchmark ledger forbids weaponization and automatic disclosure");
  }
  if (input.proof.status === "reproduced" && (!input.proof.pwnkitImportPassed
    || input.proof.confirmations < 2 || input.proof.cleanControls < 2)) {
    throw new Error("reproduced outcome did not clear proof/import thresholds");
  }
  if (!input.discovery.candidateEmitted && input.proof.status === "reproduced") {
    throw new Error("a reproduced outcome requires an emitted candidate");
  }
  if (input.proof.status === "not_attempted" && input.safety.executed) {
    throw new Error("not_attempted outcome cannot claim worker execution");
  }
  const receiptSha256 = input.receiptPath ? hashFile(input.receiptPath).sha256 : null;
  const artifactRoot = input.receiptPath ? dirname(realpathSync(regularFileForLedger(input.receiptPath))) : undefined;
  let importVerdict: ImportVerdict | undefined;
  if (input.mode === "live" && input.proof.status === "reproduced") {
    const gates = [
      input.safety.scopeFresh,
      input.safety.authorizedProgram,
      input.safety.workerBuildBound,
      input.safety.triggerAllowlisted,
      input.safety.controlFirst,
      input.safety.cleanControls,
      input.safety.sidecarsRevalidated,
      input.safety.artifactsRetained,
      input.safety.preExecutionGatePassed,
      input.safety.executed,
    ];
    if (gates.some((passed) => !passed) || !input.receiptPath || !input.importVerdictPath) {
      throw new Error("live reproduced outcome is missing a safety gate, execution, receipt, or import verdict");
    }
    importVerdict = parseImportVerdict(regularFileForLedger(input.importVerdictPath, artifactRoot));
  }

  if (importVerdict && (importVerdict.receiptSha256 !== receiptSha256
    || importVerdict.campaignId !== input.campaignId
    || importVerdict.buildLabEx !== input.windowsBuildLabEx
    || importVerdict.confirmations !== input.proof.confirmations
    || importVerdict.cleanControls !== input.proof.cleanControls
    || importVerdict.distinctDumpArtifacts < input.proof.confirmations)) {
    throw new Error("live proof fields are not bound to the pwnkit import verdict and receipt");
  }
  const artifactPaths = [...new Set([
    ...(input.artifactPaths ?? []),
    ...(input.importVerdictPath ? [input.importVerdictPath] : []),
  ])];
  if (!input.receiptPath && artifactPaths.length > 0) {
    throw new Error("artifact paths require a receipt bundle root");
  }
  const artifacts = artifactPaths
    .map((path) => hashFile(path, artifactRoot))
    .sort((a, b) => a.name.localeCompare(b.name));
  const names = new Set<string>();
  for (const artifact of artifacts) {
    if (names.has(artifact.name)) {
      throw new Error("artifact basenames must be unique within a Windows attempt");
    }
    names.add(artifact.name);
  }
  const rowId = sha256Bytes(`${input.campaignId}\0${input.caseId}\0${input.attempt}`);
  const claimEligible = input.mode === "live";
  const unsigned = {
    schemaVersion: input.schemaVersion,
    mode: input.mode,
    campaignId: input.campaignId,
    caseId: input.caseId,
    attempt: input.attempt,
    groundTruth: input.groundTruth,
    label: { ...input.label },
    repoShas: { ...input.repoShas },
    windowsBuildLabEx: input.windowsBuildLabEx,
    campaignManifestSha256: input.campaignManifestSha256,
    scopeManifestSha256: input.scopeManifestSha256,
    discovery: { ...input.discovery },
    proof: { ...input.proof },
    telemetry: { ...input.telemetry },
    safety: { ...input.safety, reasons: [...input.safety.reasons] },
    ledgerSchema: WINDOWS_LEDGER_SCHEMA,
    rowId,
    receiptSha256,
    artifacts,
    claimEligible,
  };
  return { ...unsigned, rowSha256: sha256Bytes(stableJson(unsigned)) };
}

function rate(successes: number, total: number): RateMetric {
  return {
    successes,
    total,
    rate: total === 0 ? null : successes / total,
    ci95: total === 0 ? null : wilsonIntervalTuple(successes, total),
  };
}

function percentile(values: number[], quantile: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.ceil(quantile * sorted.length) - 1] ?? null;
}

function confusion(rows: WindowsResearchLedgerRow[]) {
  let tp = 0; let fp = 0; let tn = 0; let fn = 0;
  for (const row of rows) {
    if (row.groundTruth === "unknown") continue;
    if (row.groundTruth === "positive") row.discovery.candidateEmitted ? tp++ : fn++;
    else row.discovery.candidateEmitted ? fp++ : tn++;
  }
  return { tp, fp, tn, fn };
}

function bestOfNRows(rows: WindowsResearchLedgerRow[]): WindowsResearchLedgerRow[] {
  const grouped = new Map<string, WindowsResearchLedgerRow[]>();
  for (const row of rows) {
    const key = `${row.campaignId}\0${row.caseId}`;
    grouped.set(key, [...(grouped.get(key) ?? []), row]);
  }
  return [...grouped.values()].map((attempts) => {
    const labels = new Set(attempts.map((row) => stableJson({
      groundTruth: row.groundTruth,
      label: row.label,
    })));
    if (labels.size !== 1) throw new Error("ground-truth label changed across attempts");
    return [...attempts].sort((a, b) => {
      const score = (row: WindowsResearchLedgerRow) => row.proof.status === "reproduced"
        ? 2 : row.discovery.candidateEmitted ? 1 : 0;
      return score(b) - score(a) || a.attempt - b.attempt;
    })[0]!;
  });
}

function view(rows: WindowsResearchLedgerRow[]) {
  const counts = confusion(rows);
  const candidates = rows.filter((row) => row.discovery.candidateEmitted).length;
  const reproduced = rows.filter((row) => row.proof.status === "reproduced").length;
  return {
    confusion: counts,
    precision: rate(counts.tp, counts.tp + counts.fp),
    recall: rate(counts.tp, counts.tp + counts.fn),
    proofYield: rate(reproduced, candidates),
  };
}

export function summarizeWindowsResearch(
  rows: WindowsResearchLedgerRow[],
): WindowsResearchSummary {
  const keys = new Set<string>();
  for (const row of rows) {
    const key = `${row.campaignId}\0${row.caseId}\0${row.attempt}`;
    if (keys.has(key)) throw new Error(`duplicate Windows research attempt: ${key.replaceAll("\0", "/")}`);
    keys.add(key);
    const { rowSha256, ...unsigned } = row;
    if (sha256Bytes(stableJson(unsigned)) !== rowSha256) throw new Error(`row hash mismatch: ${row.rowId}`);
  }
  const claimRows = rows.filter((row) => row.claimEligible);
  const best = bestOfNRows(claimRows);
  const outcomes: Record<ProofStatus, number> = {
    reproduced: 0, not_reproduced: 0, inconclusive: 0, safety_rejected: 0, not_attempted: 0,
  };
  const contractValidationOutcomes: Record<ProofStatus, number> = {
    reproduced: 0, not_reproduced: 0, inconclusive: 0, safety_rejected: 0, not_attempted: 0,
  };
  claimRows.forEach((row) => outcomes[row.proof.status]++);
  rows.filter((row) => !row.claimEligible)
    .forEach((row) => contractValidationOutcomes[row.proof.status]++);
  const costs = claimRows.flatMap((row) => row.telemetry.totalCostUsd === null ? [] : [row.telemetry.totalCostUsd]);
  const durations = claimRows.map((row) => row.telemetry.totalDurationMs);
  const reproducedCost = claimRows
    .filter((row) => row.proof.status === "reproduced")
    .flatMap((row) => row.telemetry.totalCostUsd === null ? [] : [row.telemetry.totalCostUsd]);
  const failedPre = claimRows.filter((row) => !row.safety.preExecutionGatePassed);
  const gatePasses = claimRows.filter((row) => row.safety.preExecutionGatePassed).length;
  return {
    schemaVersion: "pwnkit.windows-research-summary/v1",
    rows: rows.length,
    claimEligibleRows: rows.filter((row) => row.claimEligible).length,
    singleAttempt: view(claimRows),
    bestOfN: { cases: best.length, ...view(best) },
    outcomes,
    contractValidationOutcomes,
    telemetry: {
      totalDurationMs: { median: percentile(durations, 0.5), p95: percentile(durations, 0.95) },
      totalCostUsd: { median: percentile(costs, 0.5), p95: percentile(costs, 0.95) },
      costPerReproducedUsd: reproducedCost.length === 0
        ? null : reproducedCost.reduce((sum, value) => sum + value, 0) / reproducedCost.length,
    },
    safety: {
      gatePassRate: rate(gatePasses, claimRows.length),
      blockedBeforeExecution: failedPre.filter((row) => !row.safety.executed).length,
      executionsAfterFailedPreExecutionGate: failedPre.filter((row) => row.safety.executed).length,
      weaponizationRows: claimRows.filter((row) => row.safety.weaponization).length,
      autoDisclosureRows: claimRows.filter((row) => row.safety.autoDisclosure).length,
    },
  };
}

function parseAttempts(path: string): WindowsResearchAttemptInput[] {
  const text = readFileSync(path, "utf8").trim();
  if (!text) return [];
  if (text.startsWith("[")) return JSON.parse(text) as WindowsResearchAttemptInput[];
  return text.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line) as WindowsResearchAttemptInput);
}

function main(argv = process.argv.slice(2)): void {
  const inputFlag = argv.indexOf("--input");
  const outputFlag = argv.indexOf("--output");
  const summaryFlag = argv.indexOf("--summary");
  const input = inputFlag >= 0 ? argv[inputFlag + 1] : undefined;
  const output = outputFlag >= 0 ? argv[outputFlag + 1] : undefined;
  const summary = summaryFlag >= 0 ? argv[summaryFlag + 1] : undefined;
  if (!input || !output || !summary) {
    throw new Error("usage: windows-research-collector --input attempts.jsonl --output ledger.jsonl --summary summary.json");
  }
  const rows = parseAttempts(input).map(collectWindowsResearchAttempt);
  writeFileSync(output, rows.map((row) => JSON.stringify(row)).join("\n") + (rows.length ? "\n" : ""));
  writeFileSync(summary, `${JSON.stringify(summarizeWindowsResearch(rows), null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
