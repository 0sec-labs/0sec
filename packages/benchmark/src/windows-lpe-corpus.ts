#!/usr/bin/env node

import { createHash } from "node:crypto";
import { closeSync, constants as fsConstants, fstatSync, openSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const WINDOWS_LPE_CORPUS_SCHEMA = "pwnkit.windows-lpe-corpus/v1" as const;

export type WindowsLpeCorpusKind = "synthetic-positive" | "negative-control" | "public-patched";
export type WindowsLpeCorpusSplit = "development" | "holdout";

export interface WindowsLpeCorpusCase {
  caseId: string;
  kind: WindowsLpeCorpusKind;
  groundTruth: "positive" | "negative";
  split: WindowsLpeCorpusSplit;
  family: string;
  target: {
    windowsBuildLabEx: string;
    architecture: "x64" | "arm64";
    artifactSha256: string;
    provenance: {
      source: string;
      refs: string[];
      sealedAt: string;
    };
  };
  scope: {
    authorization: "synthetic-fixture" | "public-patched-regression";
    dynamicExecutionAllowed: boolean;
    scopeManifestSha256: string;
  };
  evaluation: {
    minimumGrade: "candidate" | "reachable" | "observed" | "reproduced";
    requiredConfirmations: number;
    requiredCleanControls: number;
  };
  policy: {
    noveltyEligible: false;
    bountyClaimEligible: false;
    weaponization: false;
    autoDisclosure: false;
  };
}

export interface WindowsLpeCorpusManifest {
  schemaVersion: typeof WINDOWS_LPE_CORPUS_SCHEMA;
  corpusId: string;
  createdAt: string;
  cases: WindowsLpeCorpusCase[];
}

export interface ValidatedWindowsLpeCorpus {
  manifest: WindowsLpeCorpusManifest;
  manifestSha256: string;
  counts: {
    cases: number;
    positives: number;
    negatives: number;
    development: number;
    holdout: number;
  };
}

const SHA256 = /^[a-f0-9]{64}$/;
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const FORBIDDEN_KEYS = new Set([
  "trigger_argv",
  "control_argv",
  "exploit_payload",
  "exploit_source",
  "poc_source",
  "shell_command",
]);

function record(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exact(value: unknown, name: string, keys: readonly string[]): Record<string, unknown> {
  const result = record(value, name);
  const allowed = new Set(keys);
  const unknown = Object.keys(result).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new Error(`${name} contains unsupported field(s): ${unknown.join(", ")}`);
  for (const key of keys) {
    if (!(key in result)) throw new Error(`${name}.${key} is required`);
  }
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

function count(value: unknown, name: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0) throw new Error(`${name} must be a non-negative integer`);
  return Number(value);
}

function iso(value: unknown, name: string): string {
  const text = boundedText(value, name, 64);
  if (!Number.isFinite(Date.parse(text))) throw new Error(`${name} must be an ISO-8601 timestamp`);
  return text;
}

function rejectExecutableMaterial(value: unknown): void {
  if (Array.isArray(value)) return value.forEach(rejectExecutableMaterial);
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (FORBIDDEN_KEYS.has(key.toLowerCase())) {
      throw new Error(`Windows LPE corpus contains forbidden executable field: ${key}`);
    }
    rejectExecutableMaterial(child);
  }
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => `${JSON.stringify(key)}:${stableJson(child)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function validateCase(value: unknown, index: number): WindowsLpeCorpusCase {
  const name = `cases[${index}]`;
  const row = exact(value, name, ["caseId", "kind", "groundTruth", "split", "family", "target", "scope", "evaluation", "policy"]);
  const target = exact(row.target, `${name}.target`, ["windowsBuildLabEx", "architecture", "artifactSha256", "provenance"]);
  const provenance = exact(target.provenance, `${name}.target.provenance`, ["source", "refs", "sealedAt"]);
  const scope = exact(row.scope, `${name}.scope`, ["authorization", "dynamicExecutionAllowed", "scopeManifestSha256"]);
  const evaluation = exact(row.evaluation, `${name}.evaluation`, ["minimumGrade", "requiredConfirmations", "requiredCleanControls"]);
  const policy = exact(row.policy, `${name}.policy`, ["noveltyEligible", "bountyClaimEligible", "weaponization", "autoDisclosure"]);

  const caseId = boundedText(row.caseId, `${name}.caseId`, 128);
  if (!ID.test(caseId)) throw new Error(`${name}.caseId must be a stable lowercase identifier`);
  const family = boundedText(row.family, `${name}.family`, 128);
  if (!ID.test(family)) throw new Error(`${name}.family must be a stable lowercase identifier`);
  if (!(["synthetic-positive", "negative-control", "public-patched"] as unknown[]).includes(row.kind)) {
    throw new Error(`${name}.kind is invalid`);
  }
  if (!(["positive", "negative"] as unknown[]).includes(row.groundTruth)) throw new Error(`${name}.groundTruth is invalid`);
  if (!(["development", "holdout"] as unknown[]).includes(row.split)) throw new Error(`${name}.split is invalid`);
  if ((row.kind === "negative-control") !== (row.groundTruth === "negative")) {
    throw new Error(`${name} kind and groundTruth disagree`);
  }
  if (!(["x64", "arm64"] as unknown[]).includes(target.architecture)) throw new Error(`${name}.target.architecture is invalid`);
  boundedText(target.windowsBuildLabEx, `${name}.target.windowsBuildLabEx`, 256);
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
  if (!(["synthetic-fixture", "public-patched-regression"] as unknown[]).includes(scope.authorization)) {
    throw new Error(`${name}.scope.authorization is invalid`);
  }
  if (typeof scope.dynamicExecutionAllowed !== "boolean") throw new Error(`${name}.scope.dynamicExecutionAllowed must be boolean`);
  if (!SHA256.test(String(scope.scopeManifestSha256))) throw new Error(`${name}.scope.scopeManifestSha256 must be a lowercase SHA-256`);
  if (row.kind === "public-patched" && scope.authorization !== "public-patched-regression") {
    throw new Error(`${name} public-patched case requires public-patched-regression authorization`);
  }
  if (row.kind !== "public-patched" && scope.authorization !== "synthetic-fixture") {
    throw new Error(`${name} synthetic/control case requires synthetic-fixture authorization`);
  }
  if (!(["candidate", "reachable", "observed", "reproduced"] as unknown[]).includes(evaluation.minimumGrade)) {
    throw new Error(`${name}.evaluation.minimumGrade is invalid`);
  }
  count(evaluation.requiredConfirmations, `${name}.evaluation.requiredConfirmations`);
  count(evaluation.requiredCleanControls, `${name}.evaluation.requiredCleanControls`);
  if (row.groundTruth === "positive" && evaluation.minimumGrade === "reproduced"
    && (Number(evaluation.requiredConfirmations) < 2 || Number(evaluation.requiredCleanControls) < 2)) {
    throw new Error(`${name} reproduced positives require at least two confirmations and clean controls`);
  }
  if (policy.noveltyEligible !== false || policy.bountyClaimEligible !== false
    || policy.weaponization !== false || policy.autoDisclosure !== false) {
    throw new Error(`${name} must be non-novel, non-claimable, non-weaponizing, and human-gated`);
  }
  return value as WindowsLpeCorpusCase;
}

export function validateWindowsLpeCorpus(value: unknown): ValidatedWindowsLpeCorpus {
  rejectExecutableMaterial(value);
  const top = exact(value, "manifest", ["schemaVersion", "corpusId", "createdAt", "cases"]);
  if (top.schemaVersion !== WINDOWS_LPE_CORPUS_SCHEMA) throw new Error("unsupported Windows LPE corpus schema");
  const corpusId = boundedText(top.corpusId, "manifest.corpusId", 128);
  if (!ID.test(corpusId)) throw new Error("manifest.corpusId must be a stable lowercase identifier");
  iso(top.createdAt, "manifest.createdAt");
  if (!Array.isArray(top.cases) || top.cases.length < 2 || top.cases.length > 10_000) {
    throw new Error("manifest.cases must contain 2-10000 cases");
  }
  const cases = top.cases.map(validateCase);
  const caseIds = new Set<string>();
  const familySplits = new Map<string, WindowsLpeCorpusSplit>();
  for (const entry of cases) {
    if (caseIds.has(entry.caseId)) throw new Error(`duplicate Windows LPE corpus case: ${entry.caseId}`);
    caseIds.add(entry.caseId);
    const priorSplit = familySplits.get(entry.family);
    if (priorSplit && priorSplit !== entry.split) {
      throw new Error(`family ${entry.family} crosses development and holdout splits`);
    }
    familySplits.set(entry.family, entry.split);
  }
  if (!cases.some((entry) => entry.groundTruth === "positive") || !cases.some((entry) => entry.groundTruth === "negative")) {
    throw new Error("manifest must include positive and negative-control cases");
  }
  const manifest = value as WindowsLpeCorpusManifest;
  return {
    manifest,
    manifestSha256: createHash("sha256").update(stableJson(manifest)).digest("hex"),
    counts: {
      cases: cases.length,
      positives: cases.filter((entry) => entry.groundTruth === "positive").length,
      negatives: cases.filter((entry) => entry.groundTruth === "negative").length,
      development: cases.filter((entry) => entry.split === "development").length,
      holdout: cases.filter((entry) => entry.split === "holdout").length,
    },
  };
}

function readManifest(path: string): unknown {
  const descriptor = openSync(resolve(path), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.size > 8 * 1024 * 1024) throw new Error("Windows LPE corpus manifest must be a regular file no larger than 8 MiB");
    return JSON.parse(readFileSync(descriptor, "utf8")) as unknown;
  } finally {
    closeSync(descriptor);
  }
}

export function loadWindowsLpeCorpus(path: string): ValidatedWindowsLpeCorpus {
  return validateWindowsLpeCorpus(readManifest(path));
}

function main(argv = process.argv.slice(2)): void {
  const inputIndex = argv.indexOf("--input");
  const input = inputIndex >= 0 ? argv[inputIndex + 1] : undefined;
  if (!input) throw new Error("usage: windows-lpe-corpus --input corpus.json");
  const result = loadWindowsLpeCorpus(input);
  process.stdout.write(`${JSON.stringify({ schemaVersion: result.manifest.schemaVersion, corpusId: result.manifest.corpusId, manifestSha256: result.manifestSha256, counts: result.counts })}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
