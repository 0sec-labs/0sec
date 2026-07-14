#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const WINDOWS_LPE_PAIRED_CORPUS_SCHEMA = "pwnkit.windows-lpe-paired-corpus/v2" as const;
export const WINDOWS_LPE_EVALUATOR_LABELS_SCHEMA = "pwnkit.windows-lpe-evaluator-labels/v2" as const;

export type WindowsLpePairedCorpusSplit = "development" | "holdout";
export type WindowsLpeGroundTruth = "positive" | "negative";

export interface WindowsLpePairedCorpusCase {
  caseId: string;
  split: WindowsLpePairedCorpusSplit;
  family: string;
  pairId: string | null;
  advisoryId: string | null;
  target: {
    windowsBuildLabEx: string;
    currentBuildNumber: string;
    updateBuildRevision: number;
    architecture: "x64" | "arm64";
    artifactSha256: string;
    provenance: {
      source: string;
      refs: string[];
      sealedAt: string;
    };
  };
  scope: {
    authorization: "synthetic-fixture" | "public-known-cve-regression";
    dynamicExecutionAllowed: boolean;
    scopeManifestSha256: string;
  };
  policy: {
    noveltyEligible: false;
    bountyClaimEligible: false;
    weaponization: false;
    autoDisclosure: false;
  };
}

export interface WindowsLpePairedCorpusManifest {
  schemaVersion: typeof WINDOWS_LPE_PAIRED_CORPUS_SCHEMA;
  corpusId: string;
  profile: "contract" | "capability";
  createdAt: string;
  labelCommitments: {
    developmentSha256: string;
    holdoutSha256: string;
  };
  evaluation: {
    minimumPositiveGrade: "reproduced";
    requiredConfirmations: number;
    requiredCleanControls: number;
  };
  cases: WindowsLpePairedCorpusCase[];
}

export interface WindowsLpeEvaluatorLabels {
  schemaVersion: typeof WINDOWS_LPE_EVALUATOR_LABELS_SCHEMA;
  corpusId: string;
  split: WindowsLpePairedCorpusSplit;
  inventorySha256: string;
  salt: string;
  labels: Array<{ caseId: string; groundTruth: WindowsLpeGroundTruth }>;
}

export interface ValidatedWindowsLpePairedCorpus {
  manifest: WindowsLpePairedCorpusManifest;
  manifestSha256: string;
  discoveryCounts: {
    cases: number;
    development: number;
    holdout: number;
    families: number;
    pairedFamilies: number;
  };
  evaluationCounts?: {
    positives: number;
    negatives: number;
    publicPositiveFamilies: number;
    holdoutFamilies: number;
    holdoutPublicPositiveFamilies: number;
  };
}

const SHA256 = /^[a-f0-9]{64}$/;
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const SALT = /^[A-Za-z0-9_-]{43}$/;
const CVE = /^CVE-[12][0-9]{3}-[0-9]{4,}$/;
const BUILD_NUMBER = /^[0-9]{4,6}$/;
const FORBIDDEN_KEYS = new Set([
  "groundtruth",
  "kind",
  "label",
  "expectedresult",
  "trigger_argv",
  "control_argv",
  "exploit_payload",
  "exploit_source",
  "poc_source",
  "shell_command",
]);

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as Record<string, unknown>;
}

function exact(value: unknown, name: string, keys: readonly string[]): Record<string, unknown> {
  const result = record(value, name);
  const allowed = new Set(keys);
  const unknown = Object.keys(result).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new Error(`${name} contains unsupported field(s): ${unknown.join(", ")}`);
  for (const key of keys) if (!Object.hasOwn(result, key)) throw new Error(`${name}.${key} is required`);
  return result;
}

function boundedText(value: unknown, name: string, maximum = 500): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.trim() !== value) {
    throw new Error(`${name} must be non-empty, trimmed, and at most ${maximum} characters`);
  }
  if (/[^\t\x20-\x7e]/.test(value)) throw new Error(`${name} must contain bounded printable text only`);
  if (/(?:github_pat_|gh[pousr]_|authorization\s*:\s*bearer|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i.test(value)) {
    throw new Error(`${name} contains secret-like text`);
  }
  return value;
}

function identifier(value: unknown, name: string): string {
  const text = boundedText(value, name, 128);
  if (!ID.test(text)) throw new Error(`${name} must be a stable lowercase identifier`);
  return text;
}

function nonNegativeInteger(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new Error(`${name} must be a non-negative integer`);
  return Number(value);
}

function iso(value: unknown, name: string): string {
  const text = boundedText(value, name, 64);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(text);
  const timestamp = Date.parse(text);
  if (!match || !Number.isFinite(timestamp)) throw new Error(`${name} must be a UTC RFC3339 timestamp`);
  const parsed = new Date(timestamp);
  const parts = match.slice(1, 7).map(Number);
  if (parsed.getUTCFullYear() !== parts[0] || parsed.getUTCMonth() + 1 !== parts[1]
    || parsed.getUTCDate() !== parts[2] || parsed.getUTCHours() !== parts[3]
    || parsed.getUTCMinutes() !== parts[4] || parsed.getUTCSeconds() !== parts[5]) {
    throw new Error(`${name} must be a valid UTC RFC3339 timestamp`);
  }
  return text;
}

function rejectExecutableOrLabelMaterial(value: unknown): void {
  if (Array.isArray(value)) return value.forEach(rejectExecutableOrLabelMaterial);
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.has(key.toLowerCase())) {
      throw new Error(`Windows LPE discovery manifest contains forbidden executable or label field: ${key}`);
    }
    rejectExecutableOrLabelMaterial(child);
  }
}

export function canonicalWindowsLpeJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalWindowsLpeJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => `${JSON.stringify(key)}:${canonicalWindowsLpeJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function windowsLpeLabelsCommitment(value: WindowsLpeEvaluatorLabels): string {
  return createHash("sha256").update(canonicalWindowsLpeJson(value)).digest("hex");
}

/** Evaluators must generate and withhold a fresh 256-bit salt for each label document. */
export function createWindowsLpeLabelsSalt(): string {
  return randomBytes(32).toString("base64url");
}

export function windowsLpeInventoryCommitment(value: WindowsLpePairedCorpusManifest): string {
  const { labelCommitments: _excluded, ...inventory } = value;
  return createHash("sha256").update(canonicalWindowsLpeJson(inventory)).digest("hex");
}

function validateCase(value: unknown, index: number): WindowsLpePairedCorpusCase {
  const name = `cases[${index}]`;
  const row = exact(value, name, ["caseId", "split", "family", "pairId", "advisoryId", "target", "scope", "policy"]);
  const target = exact(row.target, `${name}.target`, ["windowsBuildLabEx", "currentBuildNumber", "updateBuildRevision", "architecture", "artifactSha256", "provenance"]);
  const provenance = exact(target.provenance, `${name}.target.provenance`, ["source", "refs", "sealedAt"]);
  const scope = exact(row.scope, `${name}.scope`, ["authorization", "dynamicExecutionAllowed", "scopeManifestSha256"]);
  const policy = exact(row.policy, `${name}.policy`, ["noveltyEligible", "bountyClaimEligible", "weaponization", "autoDisclosure"]);

  identifier(row.caseId, `${name}.caseId`);
  identifier(row.family, `${name}.family`);
  if (row.pairId !== null) identifier(row.pairId, `${name}.pairId`);
  if (row.advisoryId !== null && (typeof row.advisoryId !== "string" || !CVE.test(row.advisoryId))) {
    throw new Error(`${name}.advisoryId must be a canonical CVE identifier or null`);
  }
  if (!(row.split === "development" || row.split === "holdout")) throw new Error(`${name}.split is invalid`);
  if (!(target.architecture === "x64" || target.architecture === "arm64")) throw new Error(`${name}.target.architecture is invalid`);
  boundedText(target.windowsBuildLabEx, `${name}.target.windowsBuildLabEx`, 256);
  if (typeof target.currentBuildNumber !== "string" || !BUILD_NUMBER.test(target.currentBuildNumber)) {
    throw new Error(`${name}.target.currentBuildNumber must be a decimal Windows build number`);
  }
  if (!String(target.windowsBuildLabEx).startsWith(`${target.currentBuildNumber}.`)) {
    throw new Error(`${name}.target.windowsBuildLabEx must match currentBuildNumber`);
  }
  nonNegativeInteger(target.updateBuildRevision, `${name}.target.updateBuildRevision`);
  if (!SHA256.test(String(target.artifactSha256))) throw new Error(`${name}.target.artifactSha256 must be a lowercase SHA-256`);
  boundedText(provenance.source, `${name}.target.provenance.source`, 500);
  iso(provenance.sealedAt, `${name}.target.provenance.sealedAt`);
  if (!Array.isArray(provenance.refs) || provenance.refs.length < 1 || provenance.refs.length > 20) {
    throw new Error(`${name}.target.provenance.refs must contain 1-20 references`);
  }
  for (const [refIndex, ref] of provenance.refs.entries()) {
    const text = boundedText(ref, `${name}.target.provenance.refs[${refIndex}]`, 500);
    if (!/^(?:https:\/\/|fixture:)[^\s]+$/.test(text)) throw new Error(`${name} provenance references must use HTTPS or fixture:`);
  }
  if (!(scope.authorization === "synthetic-fixture" || scope.authorization === "public-known-cve-regression")) {
    throw new Error(`${name}.scope.authorization is invalid`);
  }
  if (typeof scope.dynamicExecutionAllowed !== "boolean") throw new Error(`${name}.scope.dynamicExecutionAllowed must be boolean`);
  if (!SHA256.test(String(scope.scopeManifestSha256))) throw new Error(`${name}.scope.scopeManifestSha256 must be a lowercase SHA-256`);
  if (scope.authorization === "synthetic-fixture" && row.advisoryId !== null) {
    throw new Error(`${name} synthetic fixtures must not claim a public advisory`);
  }
  if (scope.authorization === "public-known-cve-regression") {
    if (typeof row.advisoryId !== "string" || !CVE.test(row.advisoryId)) {
      throw new Error(`${name} public-known cases require a canonical CVE advisoryId`);
    }
    const hasAuthoritativeReference = provenance.refs.some((ref) => {
      try {
        const url = new URL(String(ref));
        return url.protocol === "https:" && url.hostname === "msrc.microsoft.com"
          && decodeURIComponent(url.pathname).toUpperCase().includes(row.advisoryId as string);
      } catch {
        return false;
      }
    });
    if (!hasAuthoritativeReference) throw new Error(`${name} public-known cases require an advisory-matching HTTPS MSRC reference`);
  }
  if (policy.noveltyEligible !== false || policy.bountyClaimEligible !== false
    || policy.weaponization !== false || policy.autoDisclosure !== false) {
    throw new Error(`${name} must be non-novel, non-claimable, non-weaponizing, and human-gated`);
  }
  return value as WindowsLpePairedCorpusCase;
}

function validateManifest(value: unknown): WindowsLpePairedCorpusManifest {
  rejectExecutableOrLabelMaterial(value);
  const top = exact(value, "manifest", ["schemaVersion", "corpusId", "profile", "createdAt", "labelCommitments", "evaluation", "cases"]);
  if (top.schemaVersion !== WINDOWS_LPE_PAIRED_CORPUS_SCHEMA) throw new Error("unsupported Windows LPE paired corpus schema");
  identifier(top.corpusId, "manifest.corpusId");
  if (!(top.profile === "contract" || top.profile === "capability")) throw new Error("manifest.profile is invalid");
  iso(top.createdAt, "manifest.createdAt");
  const commitments = exact(top.labelCommitments, "manifest.labelCommitments", ["developmentSha256", "holdoutSha256"]);
  if (!SHA256.test(String(commitments.developmentSha256)) || !SHA256.test(String(commitments.holdoutSha256))) {
    throw new Error("manifest label commitments must be lowercase SHA-256 values");
  }
  const evaluation = exact(top.evaluation, "manifest.evaluation", ["minimumPositiveGrade", "requiredConfirmations", "requiredCleanControls"]);
  if (evaluation.minimumPositiveGrade !== "reproduced") throw new Error("manifest.evaluation.minimumPositiveGrade must be reproduced");
  if (nonNegativeInteger(evaluation.requiredConfirmations, "manifest.evaluation.requiredConfirmations") < 2
    || nonNegativeInteger(evaluation.requiredCleanControls, "manifest.evaluation.requiredCleanControls") < 2) {
    throw new Error("positive reproduction requires at least two confirmations and two clean controls");
  }
  if (!Array.isArray(top.cases) || top.cases.length < 4 || top.cases.length > 10_000) {
    throw new Error("manifest.cases must contain 4-10000 cases");
  }
  const cases = top.cases.map(validateCase);
  const caseIds = new Set<string>();
  const familySplits = new Map<string, WindowsLpePairedCorpusSplit>();
  const pairCoordinates = new Map<string, string>();
  const pairSizes = new Map<string, number>();
  const pairAuthorizations = new Map<string, WindowsLpePairedCorpusCase["scope"]["authorization"]>();
  const pairArchitectures = new Map<string, WindowsLpePairedCorpusCase["target"]["architecture"]>();
  const pairAdvisories = new Map<string, string | null>();
  const pairArtifacts = new Map<string, Set<string>>();
  const pairBuildCoordinates = new Map<string, Set<string>>();
  const caseIdentities = new Set<string>();
  const familyAdvisories = new Map<string, string | null>();
  const advisoryFamilies = new Map<string, string>();
  for (const entry of cases) {
    if (caseIds.has(entry.caseId)) throw new Error(`duplicate Windows LPE corpus case: ${entry.caseId}`);
    caseIds.add(entry.caseId);
    const priorSplit = familySplits.get(entry.family);
    if (priorSplit && priorSplit !== entry.split) throw new Error(`family ${entry.family} crosses development and holdout splits`);
    familySplits.set(entry.family, entry.split);
    const caseIdentity = `${entry.target.artifactSha256}\u0000${entry.scope.scopeManifestSha256}`;
    if (caseIdentities.has(caseIdentity)) throw new Error(`duplicate artifact and scope identity at case ${entry.caseId}`);
    caseIdentities.add(caseIdentity);
    const priorFamilyAdvisory = familyAdvisories.get(entry.family);
    if (priorFamilyAdvisory !== undefined && priorFamilyAdvisory !== entry.advisoryId) {
      throw new Error(`family ${entry.family} mixes advisory identities`);
    }
    familyAdvisories.set(entry.family, entry.advisoryId);
    if (entry.advisoryId !== null) {
      const priorFamily = advisoryFamilies.get(entry.advisoryId);
      if (priorFamily && priorFamily !== entry.family) throw new Error(`advisory ${entry.advisoryId} aliases multiple families`);
      advisoryFamilies.set(entry.advisoryId, entry.family);
    }
    if (entry.pairId !== null) {
      const coordinate = `${entry.family}\u0000${entry.split}`;
      const priorCoordinate = pairCoordinates.get(entry.pairId);
      if (priorCoordinate && priorCoordinate !== coordinate) throw new Error(`pair ${entry.pairId} crosses family or split boundaries`);
      pairCoordinates.set(entry.pairId, coordinate);
      pairSizes.set(entry.pairId, (pairSizes.get(entry.pairId) ?? 0) + 1);
      const priorAuthorization = pairAuthorizations.get(entry.pairId);
      if (priorAuthorization && priorAuthorization !== entry.scope.authorization) {
        throw new Error(`pair ${entry.pairId} mixes authorization classes`);
      }
      pairAuthorizations.set(entry.pairId, entry.scope.authorization);
      const priorArchitecture = pairArchitectures.get(entry.pairId);
      if (priorArchitecture && priorArchitecture !== entry.target.architecture) throw new Error(`pair ${entry.pairId} mixes architectures`);
      pairArchitectures.set(entry.pairId, entry.target.architecture);
      if (pairAdvisories.has(entry.pairId) && pairAdvisories.get(entry.pairId) !== entry.advisoryId) {
        throw new Error(`pair ${entry.pairId} mixes advisory identities`);
      }
      pairAdvisories.set(entry.pairId, entry.advisoryId);
      const artifacts = pairArtifacts.get(entry.pairId) ?? new Set<string>();
      if (artifacts.has(entry.target.artifactSha256)) throw new Error(`pair ${entry.pairId} reuses the same target artifact`);
      artifacts.add(entry.target.artifactSha256);
      pairArtifacts.set(entry.pairId, artifacts);
      const builds = pairBuildCoordinates.get(entry.pairId) ?? new Set<string>();
      const buildCoordinate = `${entry.target.windowsBuildLabEx}\u0000${entry.target.currentBuildNumber}\u0000${entry.target.updateBuildRevision}`;
      if (builds.has(buildCoordinate)) throw new Error(`pair ${entry.pairId} reuses the same exact Windows build coordinate`);
      builds.add(buildCoordinate);
      pairBuildCoordinates.set(entry.pairId, builds);
    }
  }
  for (const [pairId, size] of pairSizes) if (size !== 2) throw new Error(`pair ${pairId} must contain exactly two cases`);
  if (!cases.some((entry) => entry.split === "development") || !cases.some((entry) => entry.split === "holdout")) {
    throw new Error("manifest must include development and holdout cases");
  }
  return value as WindowsLpePairedCorpusManifest;
}

function validateLabels(
  value: unknown,
  manifest: WindowsLpePairedCorpusManifest,
): WindowsLpeEvaluatorLabels {
  const top = exact(value, "labels", ["schemaVersion", "corpusId", "split", "inventorySha256", "salt", "labels"]);
  if (top.schemaVersion !== WINDOWS_LPE_EVALUATOR_LABELS_SCHEMA) throw new Error("unsupported Windows LPE evaluator labels schema");
  if (top.corpusId !== manifest.corpusId) throw new Error("label corpusId does not match manifest");
  if (!(top.split === "development" || top.split === "holdout")) throw new Error("labels.split is invalid");
  if (typeof top.inventorySha256 !== "string" || !SHA256.test(top.inventorySha256)) throw new Error("labels.inventorySha256 must be a lowercase SHA-256");
  if (top.inventorySha256 !== windowsLpeInventoryCommitment(manifest)) throw new Error("evaluator labels do not bind the current corpus inventory");
  if (typeof top.salt !== "string" || !SALT.test(top.salt)
    || Buffer.from(top.salt, "base64url").toString("base64url") !== top.salt) {
    throw new Error("labels.salt must be the canonical base64url encoding of a fresh 256-bit random value");
  }
  if (!Array.isArray(top.labels)) throw new Error("labels.labels must be an array");
  const expectedIds = new Set(manifest.cases.filter((entry) => entry.split === top.split).map((entry) => entry.caseId));
  const seen = new Set<string>();
  for (const [index, value] of top.labels.entries()) {
    const row = exact(value, `labels.labels[${index}]`, ["caseId", "groundTruth"]);
    const caseId = identifier(row.caseId, `labels.labels[${index}].caseId`);
    if (!(row.groundTruth === "positive" || row.groundTruth === "negative")) throw new Error(`labels.labels[${index}].groundTruth is invalid`);
    if (!expectedIds.has(caseId)) throw new Error(`labels contain unknown or wrong-split case: ${caseId}`);
    if (seen.has(caseId)) throw new Error(`duplicate evaluator label: ${caseId}`);
    seen.add(caseId);
  }
  const missing = [...expectedIds].filter((caseId) => !seen.has(caseId));
  if (missing.length > 0) throw new Error(`evaluator labels are missing case(s): ${missing.join(", ")}`);
  const labels = value as WindowsLpeEvaluatorLabels;
  const expectedCommitment = top.split === "development"
    ? manifest.labelCommitments.developmentSha256
    : manifest.labelCommitments.holdoutSha256;
  if (windowsLpeLabelsCommitment(labels) !== expectedCommitment) throw new Error(`${top.split} evaluator label commitment mismatch`);
  return labels;
}

function evaluateLabels(
  manifest: WindowsLpePairedCorpusManifest,
  documents: WindowsLpeEvaluatorLabels[],
): ValidatedWindowsLpePairedCorpus["evaluationCounts"] {
  const byCase = new Map(documents.flatMap((document) => document.labels.map((row) => [row.caseId, row.groundTruth] as const)));
  const pairs = new Map<string, WindowsLpeGroundTruth[]>();
  for (const entry of manifest.cases) {
    if (entry.pairId === null || !byCase.has(entry.caseId)) continue;
    const labels = pairs.get(entry.pairId) ?? [];
    labels.push(byCase.get(entry.caseId)!);
    pairs.set(entry.pairId, labels);
  }
  for (const [pairId, labels] of pairs) {
    if (labels.length !== 2 || !labels.includes("positive") || !labels.includes("negative")) {
      throw new Error(`pair ${pairId} must contain one vulnerable positive and one fixed negative`);
    }
  }
  const evaluatedCases = manifest.cases.filter((entry) => byCase.has(entry.caseId));
  const positives = evaluatedCases.filter((entry) => byCase.get(entry.caseId) === "positive");
  const negatives = evaluatedCases.filter((entry) => byCase.get(entry.caseId) === "negative");
  const publicPositiveFamilies = new Set(positives
    .filter((entry) => entry.pairId !== null && entry.scope.authorization === "public-known-cve-regression")
    .map((entry) => entry.family)).size;
  const allFamilies = new Set(manifest.cases.map((entry) => entry.family));
  const holdoutFamilies = new Set(manifest.cases.filter((entry) => entry.split === "holdout").map((entry) => entry.family)).size;
  const holdoutPublicPositiveFamilies = new Set(positives
    .filter((entry) => entry.split === "holdout" && entry.pairId !== null
      && entry.scope.authorization === "public-known-cve-regression")
    .map((entry) => entry.family)).size;
  if (manifest.profile === "capability") {
    if (documents.length !== 2) throw new Error("capability evaluation requires both development and holdout labels");
    if (publicPositiveFamilies < 20) throw new Error("capability corpus requires at least 20 paired public positive CVE families");
    if (negatives.length < 60) throw new Error("capability corpus requires at least 60 negative cases");
    if (holdoutFamilies < Math.ceil(allFamilies.size * 0.25)) throw new Error("holdout must contain at least 25% of corpus families");
    if (holdoutPublicPositiveFamilies < Math.ceil(publicPositiveFamilies * 0.25)) {
      throw new Error("holdout must contain at least 25% of paired public positive CVE families");
    }
  }
  return { positives: positives.length, negatives: negatives.length, publicPositiveFamilies, holdoutFamilies, holdoutPublicPositiveFamilies };
}

export function validateWindowsLpePairedCorpus(
  value: unknown,
  labelValues: unknown[] = [],
): ValidatedWindowsLpePairedCorpus {
  const manifest = validateManifest(value);
  const splits = new Set<WindowsLpePairedCorpusSplit>();
  const labels = labelValues.map((document) => {
    const validated = validateLabels(document, manifest);
    if (splits.has(validated.split)) throw new Error(`duplicate ${validated.split} evaluator label document`);
    splits.add(validated.split);
    return validated;
  });
  const families = new Set(manifest.cases.map((entry) => entry.family));
  const result: ValidatedWindowsLpePairedCorpus = {
    manifest,
    manifestSha256: createHash("sha256").update(canonicalWindowsLpeJson(manifest)).digest("hex"),
    discoveryCounts: {
      cases: manifest.cases.length,
      development: manifest.cases.filter((entry) => entry.split === "development").length,
      holdout: manifest.cases.filter((entry) => entry.split === "holdout").length,
      families: families.size,
      pairedFamilies: new Set(manifest.cases.filter((entry) => entry.pairId !== null).map((entry) => entry.family)).size,
    },
  };
  if (labels.length > 0) result.evaluationCounts = evaluateLabels(manifest, labels);
  return result;
}

function assertNoDuplicateJsonKeys(text: string): void {
  let cursor = 0;
  const whitespace = (): void => { while (/\s/.test(text[cursor] ?? "")) cursor += 1; };
  const string = (): string => {
    if (text[cursor] !== '"') throw new Error("invalid JSON object key");
    const start = cursor;
    cursor += 1;
    while (cursor < text.length) {
      if (text[cursor] === "\\") {
        cursor += 2;
        continue;
      }
      if (text[cursor] === '"') {
        cursor += 1;
        return JSON.parse(text.slice(start, cursor)) as string;
      }
      cursor += 1;
    }
    throw new Error("unterminated JSON string");
  };
  const value = (): void => {
    whitespace();
    if (text[cursor] === "{") {
      cursor += 1;
      whitespace();
      const keys = new Set<string>();
      if (text[cursor] === "}") { cursor += 1; return; }
      while (cursor < text.length) {
        whitespace();
        const key = string();
        if (keys.has(key)) throw new Error(`duplicate JSON key: ${key}`);
        keys.add(key);
        whitespace();
        if (text[cursor] !== ":") throw new Error("invalid JSON object separator");
        cursor += 1;
        value();
        whitespace();
        if (text[cursor] === "}") { cursor += 1; return; }
        if (text[cursor] !== ",") throw new Error("invalid JSON object delimiter");
        cursor += 1;
      }
      throw new Error("unterminated JSON object");
    }
    if (text[cursor] === "[") {
      cursor += 1;
      whitespace();
      if (text[cursor] === "]") { cursor += 1; return; }
      while (cursor < text.length) {
        value();
        whitespace();
        if (text[cursor] === "]") { cursor += 1; return; }
        if (text[cursor] !== ",") throw new Error("invalid JSON array delimiter");
        cursor += 1;
      }
      throw new Error("unterminated JSON array");
    }
    if (text[cursor] === '"') { string(); return; }
    const start = cursor;
    while (cursor < text.length && !/[\s,\]}]/.test(text[cursor]!)) cursor += 1;
    if (cursor === start) throw new Error("invalid JSON value");
  };
  value();
  whitespace();
  if (cursor !== text.length) throw new Error("trailing data after JSON value");
}

function readJson(path: string): unknown {
  const maximum = 8 * 1024 * 1024;
  const descriptor = openSync(resolve(path), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.size > maximum) throw new Error("Windows LPE corpus input must be a regular file no larger than 8 MiB");
    const buffer = Buffer.allocUnsafe(Math.min(maximum + 1, Math.max(1, before.size + 1)));
    let offset = 0;
    while (offset < buffer.length) {
      const count = readSync(descriptor, buffer, offset, buffer.length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    const after = fstatSync(descriptor);
    if (offset > maximum || before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
      || before.ctimeMs !== after.ctimeMs || offset !== after.size) {
      throw new Error("Windows LPE corpus input changed while it was being read");
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, offset));
    assertNoDuplicateJsonKeys(text);
    return JSON.parse(text) as unknown;
  } finally {
    closeSync(descriptor);
  }
}

export function loadWindowsLpePairedCorpus(path: string, labelPaths: string[] = []): ValidatedWindowsLpePairedCorpus {
  return validateWindowsLpePairedCorpus(readJson(path), labelPaths.map(readJson));
}

function option(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : undefined;
}

function main(argv = process.argv.slice(2)): void {
  const input = option(argv, "--input");
  if (!input) throw new Error("usage: windows-lpe-paired-corpus --input corpus.json [--development-labels labels.json] [--holdout-labels labels.json]");
  const labels = [option(argv, "--development-labels"), option(argv, "--holdout-labels")].filter((path): path is string => Boolean(path));
  const result = loadWindowsLpePairedCorpus(input, labels);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: result.manifest.schemaVersion,
    corpusId: result.manifest.corpusId,
    manifestSha256: result.manifestSha256,
    discoveryCounts: result.discoveryCounts,
    evaluationCounts: result.evaluationCounts,
  })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
