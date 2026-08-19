import { createHash } from "node:crypto";
import {
  validateMsrcWindowsLpeTrancheLock,
  type MsrcWindowsLpeInventory,
  type MsrcWindowsLpeInventoryCase,
  type MsrcWindowsLpeTrancheLock,
} from "./msrc-windows-lpe-inventory.js";
import {
  canonicalWindowsLpeJson,
  validateWindowsLpePairedCorpus,
  windowsLpeInventoryCommitment,
  type ValidatedWindowsLpePairedCorpus,
  type WindowsLpeEvaluatorLabels,
  type WindowsLpePairedCorpusCase,
  type WindowsLpePairedCorpusManifest,
  type WindowsLpePairedCorpusSplit,
} from "./windows-lpe-paired-corpus.js";

export const MSRC_WINDOWS_LPE_CAPABILITY_PROMOTION_SCHEMA =
  "pwnkit.msrc-windows-lpe-capability-promotion/v1" as const;

const SHA256 = /^[a-f0-9]{64}$/;
const CVE = /^CVE-[12][0-9]{3}-[0-9]{4,}$/;
const KB = /^[0-9]{7}$/;
const BUILD = /^10\.0\.([0-9]{4,6})\.([0-9]+)$/;
const ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;

type TargetRole = "vulnerable" | "fixed" | "safeNearMiss" | "unreachableSink";

interface MsrcWindowsLpeServicingBinding {
  release: string;
  kb: string;
  build: string;
  catalogUrl: string;
  sourceDocumentSha256: string;
  packageSha256: string;
  componentPath: string;
  extractionReceiptSha256: string;
}

interface MsrcWindowsLpeTargetPromotion {
  caseId: string;
  artifactSha256: string;
  scopeManifestSha256: string;
  windowsBuildLabEx: string;
  currentBuildNumber: string;
  updateBuildRevision: number;
  architecture: "x64" | "arm64";
  servicing: MsrcWindowsLpeServicingBinding;
}

interface MsrcWindowsLpeControlPromotion extends MsrcWindowsLpeTargetPromotion {
  staticSafetyEvidence: {
    analysisReceiptSha256: string;
    siteUniverseSha256: string;
    siteIdSha256: string;
    reason: "guarded-before-sink" | "cfg-unreachable-from-dispatch";
  };
}

export interface MsrcWindowsLpeFamilyPromotion {
  stagingCaseId: string;
  cve: string;
  family: string;
  split: WindowsLpePairedCorpusSplit;
  pairId: string;
  targets: {
    vulnerable: MsrcWindowsLpeTargetPromotion;
    fixed: MsrcWindowsLpeTargetPromotion;
    safeNearMiss: MsrcWindowsLpeControlPromotion;
    unreachableSink: MsrcWindowsLpeControlPromotion;
  };
}

export interface MsrcWindowsLpeCapabilityPromotion {
  schemaVersion: typeof MSRC_WINDOWS_LPE_CAPABILITY_PROMOTION_SCHEMA;
  sourceLockId: string;
  corpusManifestSha256: string;
  corpusInventorySha256: string;
  sealedAt: string;
  families: MsrcWindowsLpeFamilyPromotion[];
  policy: {
    evaluatorPrivate: true;
    agentVisible: false;
    holdoutSealed: true;
    dynamicExecution: false;
    noveltyEligible: false;
    bountyClaimEligible: false;
    weaponization: false;
    autoDisclosure: false;
    humanPromotionGate: true;
  };
}

export interface ValidatedMsrcWindowsLpeCapabilityPromotion {
  manifest: WindowsLpePairedCorpusManifest;
  manifestSha256: string;
  inventorySha256: string;
  promotionSha256: string;
  counts: {
    publicFamilies: number;
    cases: number;
    positives: number;
    negatives: number;
    pairedFixed: number;
    safeNearMisses: number;
    unreachableSinks: number;
    holdoutFamilies: number;
  };
  safety: {
    evaluatorPrivate: true;
    agentVisible: false;
    dynamicExecution: false;
    claimEligible: false;
    weaponization: false;
  };
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, name: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as JsonRecord;
}

function exact(value: unknown, name: string, keys: readonly string[]): JsonRecord {
  const result = record(value, name);
  const actual = Object.keys(result).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${name} has unknown or missing fields`);
  }
  return result;
}

function digest(value: unknown, name: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new Error(`${name} must be a lowercase SHA-256`);
  return value;
}

function identifier(value: unknown, name: string): string {
  if (typeof value !== "string" || !ID.test(value)) throw new Error(`${name} must be a stable lowercase identifier`);
  return value;
}

function boundedText(value: unknown, name: string, maximum = 500): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.trim() !== value
    || /[^\x20-\x7e]/.test(value)) {
    throw new Error(`${name} must be bounded printable text`);
  }
  return value;
}

function timestamp(value: unknown, name: string): string {
  const text = boundedText(value, name, 64);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(text)
    || !Number.isFinite(Date.parse(text))) throw new Error(`${name} must be a canonical UTC timestamp`);
  const canonical = new Date(Date.parse(text)).toISOString();
  if (canonical !== (text.includes(".") ? text : text.replace("Z", ".000Z"))) {
    throw new Error(`${name} must be a valid canonical UTC timestamp`);
  }
  return text;
}

function componentPath(value: unknown, name: string): string {
  const path = boundedText(value, name, 260);
  if (path.startsWith("/") || path.startsWith("\\") || /^[A-Za-z]:/.test(path)
    || path.includes("\\") || path.split("/").some((part) => part === "" || part === "." || part === "..")) {
    throw new Error(`${name} must be a normalized relative component path`);
  }
  return path;
}

function canonicalDigest(value: unknown): string {
  return createHash("sha256").update(canonicalWindowsLpeJson(value)).digest("hex");
}

function sourceForRelease(lock: MsrcWindowsLpeTrancheLock, release: string) {
  const source = lock.sourceDocuments.find((entry) => entry.release === release);
  if (!source) throw new Error(`servicing release ${release} is absent from the source lock`);
  return source;
}

function parseServicing(value: unknown, name: string): MsrcWindowsLpeServicingBinding {
  const row = exact(value, name, [
    "release", "kb", "build", "catalogUrl", "sourceDocumentSha256", "packageSha256",
    "componentPath", "extractionReceiptSha256",
  ]);
  const release = boundedText(row.release, `${name}.release`, 16);
  const kb = boundedText(row.kb, `${name}.kb`, 7);
  const build = boundedText(row.build, `${name}.build`, 32);
  const catalogUrl = boundedText(row.catalogUrl, `${name}.catalogUrl`, 500);
  const url = new URL(catalogUrl);
  if (!KB.test(kb) || !BUILD.test(build) || url.origin !== "https://catalog.update.microsoft.com"
    || url.searchParams.getAll("q").length !== 1 || url.searchParams.get("q")?.toUpperCase() !== `KB${kb}`) {
    throw new Error(`${name} has invalid Windows servicing coordinates`);
  }
  const result: MsrcWindowsLpeServicingBinding = {
    release,
    kb,
    build,
    catalogUrl,
    sourceDocumentSha256: digest(row.sourceDocumentSha256, `${name}.sourceDocumentSha256`),
    packageSha256: digest(row.packageSha256, `${name}.packageSha256`),
    componentPath: componentPath(row.componentPath, `${name}.componentPath`),
    extractionReceiptSha256: digest(row.extractionReceiptSha256, `${name}.extractionReceiptSha256`),
  };
  if (new Set([result.packageSha256, result.extractionReceiptSha256]).size !== 2) {
    throw new Error(`${name} package and extraction receipt digests must not alias`);
  }
  return result;
}

function parseTarget(value: unknown, name: string, control: boolean): MsrcWindowsLpeTargetPromotion | MsrcWindowsLpeControlPromotion {
  const fields = [
    "caseId", "artifactSha256", "scopeManifestSha256", "windowsBuildLabEx", "currentBuildNumber",
    "updateBuildRevision", "architecture", "servicing",
  ];
  if (control) fields.push("staticSafetyEvidence");
  const row = exact(value, name, fields);
  const updateBuildRevision = row.updateBuildRevision;
  if (!Number.isSafeInteger(updateBuildRevision) || Number(updateBuildRevision) < 0) {
    throw new Error(`${name}.updateBuildRevision must be a non-negative integer`);
  }
  if (!(row.architecture === "x64" || row.architecture === "arm64")) throw new Error(`${name}.architecture is invalid`);
  const result: MsrcWindowsLpeTargetPromotion = {
    caseId: identifier(row.caseId, `${name}.caseId`),
    artifactSha256: digest(row.artifactSha256, `${name}.artifactSha256`),
    scopeManifestSha256: digest(row.scopeManifestSha256, `${name}.scopeManifestSha256`),
    windowsBuildLabEx: boundedText(row.windowsBuildLabEx, `${name}.windowsBuildLabEx`, 256),
    currentBuildNumber: boundedText(row.currentBuildNumber, `${name}.currentBuildNumber`, 6),
    updateBuildRevision: Number(updateBuildRevision),
    architecture: row.architecture,
    servicing: parseServicing(row.servicing, `${name}.servicing`),
  };
  if (!/^[0-9]{4,6}$/.test(result.currentBuildNumber)
    || !result.windowsBuildLabEx.startsWith(`${result.currentBuildNumber}.`)
    || result.artifactSha256 === result.scopeManifestSha256
    || [result.artifactSha256, result.scopeManifestSha256].includes(result.servicing.packageSha256)
    || [result.artifactSha256, result.scopeManifestSha256].includes(result.servicing.extractionReceiptSha256)) {
    throw new Error(`${name} has inconsistent or aliased artifact/build/scope evidence`);
  }
  if (!control) return result;
  const evidence = exact(row.staticSafetyEvidence, `${name}.staticSafetyEvidence`, [
    "analysisReceiptSha256", "siteUniverseSha256", "siteIdSha256", "reason",
  ]);
  if (!(evidence.reason === "guarded-before-sink" || evidence.reason === "cfg-unreachable-from-dispatch")) {
    throw new Error(`${name}.staticSafetyEvidence.reason is invalid`);
  }
  const staticSafetyEvidence: MsrcWindowsLpeControlPromotion["staticSafetyEvidence"] = {
    analysisReceiptSha256: digest(evidence.analysisReceiptSha256, `${name}.staticSafetyEvidence.analysisReceiptSha256`),
    siteUniverseSha256: digest(evidence.siteUniverseSha256, `${name}.staticSafetyEvidence.siteUniverseSha256`),
    siteIdSha256: digest(evidence.siteIdSha256, `${name}.staticSafetyEvidence.siteIdSha256`),
    reason: evidence.reason,
  };
  if (new Set(Object.values(staticSafetyEvidence).filter((entry) => entry !== staticSafetyEvidence.reason)).size !== 3) {
    throw new Error(`${name}.staticSafetyEvidence digest roles must not alias`);
  }
  return { ...result, staticSafetyEvidence };
}

function assertTargetMatchesCase(target: MsrcWindowsLpeTargetPromotion, corpusCase: WindowsLpePairedCorpusCase, name: string): void {
  const expected = {
    caseId: corpusCase.caseId,
    artifactSha256: corpusCase.target.artifactSha256,
    scopeManifestSha256: corpusCase.scope.scopeManifestSha256,
    windowsBuildLabEx: corpusCase.target.windowsBuildLabEx,
    currentBuildNumber: corpusCase.target.currentBuildNumber,
    updateBuildRevision: corpusCase.target.updateBuildRevision,
    architecture: corpusCase.target.architecture,
  };
  const actual = {
    caseId: target.caseId,
    artifactSha256: target.artifactSha256,
    scopeManifestSha256: target.scopeManifestSha256,
    windowsBuildLabEx: target.windowsBuildLabEx,
    currentBuildNumber: target.currentBuildNumber,
    updateBuildRevision: target.updateBuildRevision,
    architecture: target.architecture,
  };
  if (canonicalWindowsLpeJson(actual) !== canonicalWindowsLpeJson(expected)) {
    throw new Error(`${name} does not bind the exact paired-corpus target and scope`);
  }
  if (corpusCase.scope.dynamicExecutionAllowed !== false) throw new Error(`${name} must not authorize dynamic execution`);
  const sourceUrl = `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${target.servicing.release}`;
  if (!corpusCase.target.provenance.refs.includes(target.servicing.catalogUrl)
    || !corpusCase.target.provenance.refs.includes(sourceUrl)) {
    throw new Error(`${name} corpus provenance does not bind its catalog and MSRC source references`);
  }
}

function assertBoundary(
  target: MsrcWindowsLpeTargetPromotion,
  boundary: MsrcWindowsLpeInventoryCase["fixedBoundary"] | MsrcWindowsLpeInventoryCase["supersededBoundaryCandidate"],
  lock: MsrcWindowsLpeTrancheLock,
  name: string,
): void {
  const source = sourceForRelease(lock, boundary.release);
  if (target.servicing.release !== boundary.release || target.servicing.kb !== boundary.kb
    || target.servicing.build !== boundary.build || target.servicing.catalogUrl !== boundary.catalogUrl
    || target.servicing.sourceDocumentSha256 !== source.rawBytesSha256
    || target.updateBuildRevision !== boundary.updateBuildRevision
    || target.currentBuildNumber !== BUILD.exec(boundary.build)?.[1]) {
    throw new Error(`${name} does not match the bound MSRC servicing boundary`);
  }
}

function labelMap(labels: readonly WindowsLpeEvaluatorLabels[]): Map<string, "positive" | "negative"> {
  return new Map(labels.flatMap((document) => document.labels.map((entry) => [entry.caseId, entry.groundTruth] as const)));
}

export function validateMsrcWindowsLpeCapabilityPromotion(args: {
  lock: unknown;
  boundInventories: readonly MsrcWindowsLpeInventory[];
  manifest: WindowsLpePairedCorpusManifest;
  developmentLabels: WindowsLpeEvaluatorLabels;
  holdoutLabels: WindowsLpeEvaluatorLabels;
  promotion: unknown;
}): ValidatedMsrcWindowsLpeCapabilityPromotion {
  if (!Array.isArray(args.boundInventories) || args.boundInventories.length !== 2) {
    throw new Error("capability promotion requires both full MSRC inventories that produced the staging lock");
  }
  validateMsrcWindowsLpeTrancheLock(args.lock, args.boundInventories);
  const lock = args.lock;
  const validated: ValidatedWindowsLpePairedCorpus = validateWindowsLpePairedCorpus(
    args.manifest, [args.developmentLabels, args.holdoutLabels],
  );
  if (validated.manifest.profile !== "capability" || !validated.evaluationCounts) {
    throw new Error("promotion requires a fully labeled paired-v2 capability corpus");
  }
  if (validated.manifest.evaluation.requiredConfirmations < 3
    || validated.manifest.evaluation.requiredCleanControls < 3) {
    throw new Error("capability promotion requires at least three confirmations and three clean controls");
  }

  const top = exact(args.promotion, "promotion", [
    "schemaVersion", "sourceLockId", "corpusManifestSha256", "corpusInventorySha256", "sealedAt", "families", "policy",
  ]);
  if (top.schemaVersion !== MSRC_WINDOWS_LPE_CAPABILITY_PROMOTION_SCHEMA) throw new Error("unsupported capability promotion schema");
  if (top.sourceLockId !== lock.lockId) throw new Error("promotion does not bind the exact MSRC staging lock");
  const manifestSha256 = digest(top.corpusManifestSha256, "promotion.corpusManifestSha256");
  const inventorySha256 = digest(top.corpusInventorySha256, "promotion.corpusInventorySha256");
  if (manifestSha256 !== validated.manifestSha256
    || inventorySha256 !== windowsLpeInventoryCommitment(validated.manifest)) {
    throw new Error("promotion does not bind the exact paired-v2 corpus inventory and label commitments");
  }
  const sealedAt = timestamp(top.sealedAt, "promotion.sealedAt");
  const policy = exact(top.policy, "promotion.policy", [
    "evaluatorPrivate", "agentVisible", "holdoutSealed", "dynamicExecution", "noveltyEligible",
    "bountyClaimEligible", "weaponization", "autoDisclosure", "humanPromotionGate",
  ]);
  const requiredPolicy = {
    evaluatorPrivate: true, agentVisible: false, holdoutSealed: true, dynamicExecution: false,
    noveltyEligible: false, bountyClaimEligible: false, weaponization: false, autoDisclosure: false,
    humanPromotionGate: true,
  } as const;
  if (canonicalWindowsLpeJson(policy) !== canonicalWindowsLpeJson(requiredPolicy)) {
    throw new Error("promotion policy must remain evaluator-private, static, nonclaim, nonweaponizing, and human-gated");
  }
  if (!Array.isArray(top.families) || top.families.length !== lock.cases.length || top.families.length < 20) {
    throw new Error("promotion must exactly cover at least 20 staging-lock families");
  }

  const labels = labelMap([args.developmentLabels, args.holdoutLabels]);
  const corpusCases = new Map(validated.manifest.cases.map((entry) => [entry.caseId, entry]));
  const inventoryCases = new Map(args.boundInventories.flatMap((inventory) => inventory.cases)
    .map((entry) => [entry.caseId, entry] as const));
  const lockCases = new Map(lock.cases.map((entry) => [entry.caseId, entry]));
  const seenStaging = new Set<string>();
  const seenFamilies = new Set<string>();
  const consumedCases = new Set<string>();
  let holdoutFamilies = 0;

  const families = top.families.map((value, index): MsrcWindowsLpeFamilyPromotion => {
    const name = `promotion.families[${index}]`;
    const row = exact(value, name, ["stagingCaseId", "cve", "family", "split", "pairId", "targets"]);
    const stagingCaseId = identifier(row.stagingCaseId, `${name}.stagingCaseId`);
    const cve = boundedText(row.cve, `${name}.cve`, 32);
    const family = identifier(row.family, `${name}.family`);
    const pairId = identifier(row.pairId, `${name}.pairId`);
    if (!(row.split === "development" || row.split === "holdout") || !CVE.test(cve)) {
      throw new Error(`${name} has invalid CVE or split`);
    }
    const targets = exact(row.targets, `${name}.targets`, ["vulnerable", "fixed", "safeNearMiss", "unreachableSink"]);
    const parsedTargets = {
      vulnerable: parseTarget(targets.vulnerable, `${name}.targets.vulnerable`, false) as MsrcWindowsLpeTargetPromotion,
      fixed: parseTarget(targets.fixed, `${name}.targets.fixed`, false) as MsrcWindowsLpeTargetPromotion,
      safeNearMiss: parseTarget(targets.safeNearMiss, `${name}.targets.safeNearMiss`, true) as MsrcWindowsLpeControlPromotion,
      unreachableSink: parseTarget(targets.unreachableSink, `${name}.targets.unreachableSink`, true) as MsrcWindowsLpeControlPromotion,
    };
    if (parsedTargets.safeNearMiss.staticSafetyEvidence.reason !== "guarded-before-sink"
      || parsedTargets.unreachableSink.staticSafetyEvidence.reason !== "cfg-unreachable-from-dispatch") {
      throw new Error(`${name} must contain one guarded near-miss and one unreachable-sink control`);
    }
    const lockCase = lockCases.get(stagingCaseId);
    const inventoryCase = inventoryCases.get(stagingCaseId);
    if (!lockCase || !inventoryCase || lockCase.cve !== cve || inventoryCase.cve !== cve) {
      throw new Error(`${name} does not bind one exact staging-lock and inventory case`);
    }
    if (seenStaging.has(stagingCaseId) || seenFamilies.has(family)) throw new Error("promotion families must be a staging-case/family bijection");
    seenStaging.add(stagingCaseId);
    seenFamilies.add(family);

    const roles = Object.entries(parsedTargets) as Array<[TargetRole, MsrcWindowsLpeTargetPromotion]>;
    if (new Set(roles.map(([, target]) => target.caseId)).size !== 4) throw new Error(`${name} target roles must use four distinct cases`);
    for (const [role, target] of roles) {
      const corpusCase = corpusCases.get(target.caseId);
      if (!corpusCase || consumedCases.has(target.caseId)) throw new Error(`${name}.${role} is absent or reused in the paired corpus`);
      consumedCases.add(target.caseId);
      if (corpusCase.family !== family || corpusCase.split !== row.split || corpusCase.advisoryId !== cve
        || corpusCase.scope.authorization !== "public-known-cve-regression"
        || corpusCase.target.provenance.sealedAt !== sealedAt) {
        throw new Error(`${name}.${role} has inconsistent family, split, advisory, authorization, or seal`);
      }
      if ((role === "vulnerable" || role === "fixed") ? corpusCase.pairId !== pairId : corpusCase.pairId !== null) {
        throw new Error(`${name}.${role} has an invalid vulnerable/fixed pair assignment`);
      }
      const expectedLabel = role === "vulnerable" ? "positive" : "negative";
      if (labels.get(target.caseId) !== expectedLabel) throw new Error(`${name}.${role} has an invalid private evaluator label`);
      assertTargetMatchesCase(target, corpusCase, `${name}.${role}`);
    }
    assertBoundary(parsedTargets.vulnerable, inventoryCase.supersededBoundaryCandidate, lock, `${name}.vulnerable`);
    for (const role of ["fixed", "safeNearMiss", "unreachableSink"] as const) {
      assertBoundary(parsedTargets[role], inventoryCase.fixedBoundary, lock, `${name}.${role}`);
    }
    if (row.split === "holdout") holdoutFamilies += 1;
    return { stagingCaseId, cve, family, split: row.split, pairId, targets: parsedTargets };
  });

  const canonicalFamilies = [...families].sort((a, b) => a.stagingCaseId.localeCompare(b.stagingCaseId));
  if (canonicalWindowsLpeJson(families) !== canonicalWindowsLpeJson(canonicalFamilies)
    || seenStaging.size !== lock.cases.length || consumedCases.size !== validated.manifest.cases.length
    || validated.manifest.cases.length !== families.length * 4) {
    throw new Error("promotion must canonically and exclusively cover four cases per staging family");
  }
  if (holdoutFamilies < 5 || holdoutFamilies < Math.ceil(families.length * 0.25)) {
    throw new Error("promotion requires at least five and at least 25% family-disjoint sealed holdout families");
  }
  const counts = {
    publicFamilies: families.length,
    cases: consumedCases.size,
    positives: families.length,
    negatives: families.length * 3,
    pairedFixed: families.length,
    safeNearMisses: families.length,
    unreachableSinks: families.length,
    holdoutFamilies,
  };
  if (counts.negatives < 60 || validated.evaluationCounts.publicPositiveFamilies !== counts.publicFamilies
    || validated.evaluationCounts.positives !== counts.positives
    || validated.evaluationCounts.negatives !== counts.negatives
    || validated.evaluationCounts.holdoutPublicPositiveFamilies !== holdoutFamilies) {
    throw new Error("promotion does not satisfy the exact 1 vulnerable + 3 safe-negative composition per public family");
  }
  return {
    manifest: validated.manifest,
    manifestSha256,
    inventorySha256,
    promotionSha256: canonicalDigest(args.promotion),
    counts,
    safety: {
      evaluatorPrivate: true, agentVisible: false, dynamicExecution: false,
      claimEligible: false, weaponization: false,
    },
  };
}
