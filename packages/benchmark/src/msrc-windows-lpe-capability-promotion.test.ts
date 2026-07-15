import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  MSRC_WINDOWS_LPE_CAPABILITY_PROMOTION_SCHEMA,
  validateMsrcWindowsLpeCapabilityPromotion,
  type MsrcWindowsLpeCapabilityPromotion,
} from "./msrc-windows-lpe-capability-promotion.js";
import {
  buildMsrcWindowsLpeInventory,
  buildMsrcWindowsLpeTrancheLock,
  type MsrcInventorySelection,
  type MsrcWindowsLpeInventory,
} from "./msrc-windows-lpe-inventory.js";
import {
  validateWindowsLpePairedCorpus,
  windowsLpeInventoryCommitment,
  windowsLpeLabelsCommitment,
  type WindowsLpeEvaluatorLabels,
  type WindowsLpePairedCorpusCase,
  type WindowsLpePairedCorpusManifest,
} from "./windows-lpe-paired-corpus.js";

const fixtureDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "../fixtures");
const committedLock = JSON.parse(readFileSync(
  resolve(fixtureDirectory, "msrc-windows-lpe-safe-tranche-lock-v1.json"), "utf8",
)) as unknown;
const SEALED_AT = "2026-07-15T00:00:00.000Z";

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function hex(label: string): string {
  return createHash("sha256").update(label).digest("hex");
}

function remediation(kb: string, build: string, supersededKb: string): Record<string, unknown> {
  return {
    Description: { Value: kb },
    URL: `https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB${kb}`,
    Supercedence: supersededKb,
    ProductID: ["product-x64"],
    Type: 2,
    SubType: "Security Update",
    FixedBuild: build,
  };
}

function vulnerability(cve: string, boundary: Record<string, unknown>): Record<string, unknown> {
  return {
    CVE: cve,
    Title: { Value: "Windows Contract Component Elevation of Privilege Vulnerability" },
    CWE: [{ ID: "CWE-000", Value: "Contract weakness" }],
    ProductStatuses: [{ ProductID: ["product-x64"], Type: 3 }],
    Remediations: [boundary],
    Threats: [
      { Description: { Value: "Elevation of Privilege" }, ProductID: ["product-x64"], Type: 0 },
      { Description: { Value: "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely" }, Type: 1 },
    ],
    CVSSScoreSets: [{
      BaseScore: 7.8,
      Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      ProductID: ["product-x64"],
    }],
  };
}

function document(release: string, build: string, vulnerabilities: unknown[]): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    DocumentTracking: {
      Identification: { ID: { Value: release } },
      Version: "1.0",
      Status: 2,
      RevisionHistory: [{ Number: "1", Date: "2025-01-02T00:00:00", Description: { Value: "contract" } }],
      InitialReleaseDate: "2025-01-01T00:00:00",
      CurrentReleaseDate: "2025-01-02T00:00:00",
    },
    ProductTree: {
      FullProductName: [{
        ProductID: "product-x64",
        CPE: `cpe:2.3:o:microsoft:windows_11_24H2:${build}:*:*:*:*:*:x64:*`,
        Value: "Windows 11 Version 24H2 for x64-based Systems",
      }],
    },
    Vulnerability: vulnerabilities,
  }));
}

function inventories(): [MsrcWindowsLpeInventory, MsrcWindowsLpeInventory] {
  const january = document("2025-Jan", "10.0.26100.2894", [
    { CVE: "CVE-2025-10000", Remediations: [remediation("5048667", "10.0.26100.2894", "5040000")] },
  ]);
  const february = document("2025-Feb", "10.0.26100.3194", Array.from({ length: 11 }, (_, index) =>
    vulnerability(`CVE-2025-${21182 + index}`, remediation("5051987", "10.0.26100.3194", "5048667"))));
  const march = document("2025-Mar", "10.0.26100.3476", Array.from({ length: 9 }, (_, index) =>
    vulnerability(`CVE-2025-${24044 + index}`, remediation("5053598", "10.0.26100.3476", "5051987"))));
  const selection = (previousRelease: string, currentRelease: string): MsrcInventorySelection => ({
    previousRelease,
    currentRelease,
    productName: "Windows 11 Version 24H2 for x64-based Systems",
    architecture: "x64",
    currentBuildNumber: "26100",
  });
  return [
    buildMsrcWindowsLpeInventory(february, january, selection("2025-Jan", "2025-Feb")),
    buildMsrcWindowsLpeInventory(march, february, selection("2025-Feb", "2025-Mar")),
  ];
}

function buildCapability() {
  const boundInventories = inventories();
  const lock = buildMsrcWindowsLpeTrancheLock(boundInventories);
  const manifest: WindowsLpePairedCorpusManifest = {
    schemaVersion: "pwnkit.windows-lpe-paired-corpus/v2",
    corpusId: "msrc-contract-capability",
    profile: "capability",
    createdAt: SEALED_AT,
    labelCommitments: { developmentSha256: "0".repeat(64), holdoutSha256: "0".repeat(64) },
    evaluation: { minimumPositiveGrade: "reproduced", requiredConfirmations: 3, requiredCleanControls: 3 },
    cases: [],
  };
  const labels: [WindowsLpeEvaluatorLabels, WindowsLpeEvaluatorLabels] = [
    {
      schemaVersion: "pwnkit.windows-lpe-evaluator-labels/v2", corpusId: manifest.corpusId,
      split: "development", inventorySha256: "0".repeat(64), salt: "Qx7Nv2Lp9Ds4Hj6Bf1Mt8Yc3Za0Ue5Gi7Ro2Wk9VnAs", labels: [],
    },
    {
      schemaVersion: "pwnkit.windows-lpe-evaluator-labels/v2", corpusId: manifest.corpusId,
      split: "holdout", inventorySha256: "0".repeat(64), salt: "Cv3Mn8Qz1Kp6Xs9Dc2Fh7Jt0Ry4Ua5We3Li8Go1NbEk", labels: [],
    },
  ];
  const inventoryCases = new Map(boundInventories.flatMap((inventory) => inventory.cases)
    .map((entry) => [entry.caseId, entry]));
  const families: MsrcWindowsLpeCapabilityPromotion["families"] = [];

  for (const [index, staged] of lock.cases.entries()) {
    const source = inventoryCases.get(staged.caseId)!;
    const split = index < 15 ? "development" : "holdout";
    const labelDocument = split === "development" ? labels[0] : labels[1];
    const family = `family-${staged.cve.toLowerCase()}`;
    const pairId = `pair-${staged.cve.toLowerCase()}`;
    const roles = ["vulnerable", "fixed", "safeNearMiss", "unreachableSink"] as const;
    const targets = {} as MsrcWindowsLpeCapabilityPromotion["families"][number]["targets"];
    for (const [roleIndex, role] of roles.entries()) {
      const boundary = role === "vulnerable" ? source.supersededBoundaryCandidate : source.fixedBoundary;
      const sourceDocument = lock.sourceDocuments.find((entry) => entry.release === boundary.release)!;
      const caseId = `${family}-${role.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)}`;
      const artifactSha256 = hex(`${caseId}:artifact`);
      const scopeManifestSha256 = hex(`${caseId}:scope`);
      const corpusCase: WindowsLpePairedCorpusCase = {
        caseId,
        split,
        family,
        pairId: role === "vulnerable" || role === "fixed" ? pairId : null,
        advisoryId: staged.cve,
        target: {
          windowsBuildLabEx: `26100.${boundary.updateBuildRevision}.amd64fre.contract`,
          currentBuildNumber: "26100",
          updateBuildRevision: boundary.updateBuildRevision,
          architecture: "x64",
          artifactSha256,
          provenance: {
            source: "evaluator-private artifact extraction contract evidence",
            refs: [
              `https://msrc.microsoft.com/update-guide/vulnerability/${staged.cve}`,
              boundary.catalogUrl,
              sourceDocument.url,
            ],
            sealedAt: SEALED_AT,
          },
        },
        scope: {
          authorization: "public-known-cve-regression",
          dynamicExecutionAllowed: false,
          scopeManifestSha256,
        },
        policy: { noveltyEligible: false, bountyClaimEligible: false, weaponization: false, autoDisclosure: false },
      };
      manifest.cases.push(corpusCase);
      labelDocument.labels.push({ caseId, groundTruth: role === "vulnerable" ? "positive" : "negative" });
      const target = {
        caseId,
        artifactSha256,
        scopeManifestSha256,
        windowsBuildLabEx: corpusCase.target.windowsBuildLabEx,
        currentBuildNumber: "26100",
        updateBuildRevision: boundary.updateBuildRevision,
        architecture: "x64" as const,
        servicing: {
          release: boundary.release,
          kb: boundary.kb,
          build: boundary.build,
          catalogUrl: boundary.catalogUrl,
          sourceDocumentSha256: sourceDocument.rawBytesSha256,
          packageSha256: hex(`${caseId}:package`),
          componentPath: `Windows/System32/drivers/contract-${index}-${roleIndex}.sys`,
          extractionReceiptSha256: hex(`${caseId}:extraction`),
        },
      };
      if (role === "safeNearMiss" || role === "unreachableSink") {
        targets[role] = {
          ...target,
          staticSafetyEvidence: {
            analysisReceiptSha256: hex(`${caseId}:analysis`),
            siteUniverseSha256: hex(`${caseId}:universe`),
            siteIdSha256: hex(`${caseId}:site`),
            reason: role === "safeNearMiss" ? "guarded-before-sink" : "cfg-unreachable-from-dispatch",
          },
        };
      } else {
        targets[role] = target;
      }
    }
    families.push({ stagingCaseId: staged.caseId, cve: staged.cve, family, split, pairId, targets });
  }
  const inventorySha256 = windowsLpeInventoryCommitment(manifest);
  for (const label of labels) label.inventorySha256 = inventorySha256;
  manifest.labelCommitments.developmentSha256 = windowsLpeLabelsCommitment(labels[0]);
  manifest.labelCommitments.holdoutSha256 = windowsLpeLabelsCommitment(labels[1]);
  const promotion: MsrcWindowsLpeCapabilityPromotion = {
    schemaVersion: MSRC_WINDOWS_LPE_CAPABILITY_PROMOTION_SCHEMA,
    sourceLockId: lock.lockId,
    corpusManifestSha256: "0".repeat(64),
    corpusInventorySha256: inventorySha256,
    sealedAt: SEALED_AT,
    families,
    policy: {
      evaluatorPrivate: true, agentVisible: false, holdoutSealed: true, dynamicExecution: false,
      noveltyEligible: false, bountyClaimEligible: false, weaponization: false, autoDisclosure: false,
      humanPromotionGate: true,
    },
  };
  return { lock, boundInventories, manifest, labels, promotion };
}

function bindManifestSha(input: ReturnType<typeof buildCapability>): void {
  input.promotion.corpusManifestSha256 = validateWindowsLpePairedCorpus(
    input.manifest, input.labels,
  ).manifestSha256;
}

function rebindCorpus(input: ReturnType<typeof buildCapability>): void {
  const inventorySha256 = windowsLpeInventoryCommitment(input.manifest);
  for (const label of input.labels) label.inventorySha256 = inventorySha256;
  input.manifest.labelCommitments.developmentSha256 = windowsLpeLabelsCommitment(input.labels[0]);
  input.manifest.labelCommitments.holdoutSha256 = windowsLpeLabelsCommitment(input.labels[1]);
  input.promotion.corpusInventorySha256 = inventorySha256;
  bindManifestSha(input);
}

describe("MSRC paired-v2 capability promotion gate", () => {
  it("promotes only a fully bound evaluator-private 20-family/60-negative corpus", () => {
    const input = buildCapability();
    bindManifestSha(input);
    const result = validateMsrcWindowsLpeCapabilityPromotion({
      lock: input.lock,
      boundInventories: input.boundInventories,
      manifest: input.manifest,
      developmentLabels: input.labels[0],
      holdoutLabels: input.labels[1],
      promotion: input.promotion,
    });
    expect(result.counts).toEqual({
      publicFamilies: 20, cases: 80, positives: 20, negatives: 60, pairedFixed: 20,
      safeNearMisses: 20, unreachableSinks: 20, holdoutFamilies: 5,
    });
    expect(result.promotionSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.safety).toEqual({
      evaluatorPrivate: true, agentVisible: false, dynamicExecution: false,
      claimEligible: false, weaponization: false,
    });
  });

  it("proves the committed 20-row staging lock cannot promote itself", () => {
    const contractManifest = JSON.parse(readFileSync(
      resolve(fixtureDirectory, "windows-lpe-paired-corpus-contract-v2.json"), "utf8",
    )) as WindowsLpePairedCorpusManifest;
    const development = JSON.parse(readFileSync(
      resolve(fixtureDirectory, "windows-lpe-paired-labels-development-contract-v2.json"), "utf8",
    )) as WindowsLpeEvaluatorLabels;
    const holdout = JSON.parse(readFileSync(
      resolve(fixtureDirectory, "windows-lpe-paired-labels-holdout-contract-v2.json"), "utf8",
    )) as WindowsLpeEvaluatorLabels;
    expect(() => validateMsrcWindowsLpeCapabilityPromotion({
      lock: committedLock,
      boundInventories: [],
      manifest: contractManifest,
      developmentLabels: development,
      holdoutLabels: holdout,
      promotion: committedLock,
    })).toThrow(/both full MSRC inventories/);
  });

  it("rejects missing roles, wrong labels, servicing swaps, weak gates, dynamic scope, and policy flips", () => {
    const baseline = buildCapability();
    bindManifestSha(baseline);
    const validate = (input: ReturnType<typeof buildCapability>) => validateMsrcWindowsLpeCapabilityPromotion({
      lock: input.lock,
      boundInventories: input.boundInventories,
      manifest: input.manifest,
      developmentLabels: input.labels[0],
      holdoutLabels: input.labels[1],
      promotion: input.promotion,
    });

    const missingRole = copy(baseline);
    delete (missingRole.promotion.families[0]!.targets as unknown as Record<string, unknown>).unreachableSink;
    expect(() => validate(missingRole)).toThrow(/unknown or missing fields/);

    const wrongLabel = copy(baseline);
    wrongLabel.labels[0].labels.find((entry) => entry.caseId.endsWith("-vulnerable"))!.groundTruth = "negative";
    expect(() => validate(wrongLabel)).toThrow(/commitment mismatch/);

    const servicingSwap = copy(baseline);
    servicingSwap.promotion.families[0]!.targets.vulnerable.servicing.kb =
      servicingSwap.promotion.families[0]!.targets.fixed.servicing.kb;
    servicingSwap.promotion.families[0]!.targets.vulnerable.servicing.catalogUrl =
      servicingSwap.promotion.families[0]!.targets.fixed.servicing.catalogUrl;
    expect(() => validate(servicingSwap)).toThrow(/provenance|servicing boundary/);

    const weakGates = copy(baseline);
    weakGates.manifest.evaluation.requiredConfirmations = 2;
    rebindCorpus(weakGates);
    expect(() => validate(weakGates)).toThrow(/three confirmations/);

    const dynamic = copy(baseline);
    dynamic.manifest.cases[0]!.scope.dynamicExecutionAllowed = true;
    rebindCorpus(dynamic);
    expect(() => validate(dynamic)).toThrow(/must not authorize dynamic execution/);

    const policyFlip = copy(baseline);
    policyFlip.promotion.policy.bountyClaimEligible = true as false;
    expect(() => validate(policyFlip)).toThrow(/nonclaim/);
  });

  it("rejects fewer than five sealed holdout families and noncanonical family order", () => {
    const input = buildCapability();
    for (const family of input.promotion.families.slice(16)) family.split = "development";
    for (const corpusCase of input.manifest.cases.filter((entry) =>
      input.promotion.families.slice(16).some((family) => family.family === entry.family))) {
      corpusCase.split = "development";
      const label = input.labels[1].labels.find((entry) => entry.caseId === corpusCase.caseId)!;
      input.labels[0].labels.push(label);
      input.labels[1].labels = input.labels[1].labels.filter((entry) => entry.caseId !== corpusCase.caseId);
    }
    for (const label of input.labels) label.inventorySha256 = windowsLpeInventoryCommitment(input.manifest);
    input.manifest.labelCommitments.developmentSha256 = windowsLpeLabelsCommitment(input.labels[0]);
    input.manifest.labelCommitments.holdoutSha256 = windowsLpeLabelsCommitment(input.labels[1]);
    input.promotion.corpusInventorySha256 = windowsLpeInventoryCommitment(input.manifest);
    expect(() => validateMsrcWindowsLpeCapabilityPromotion({
      lock: input.lock, boundInventories: input.boundInventories, manifest: input.manifest,
      developmentLabels: input.labels[0], holdoutLabels: input.labels[1], promotion: input.promotion,
    })).toThrow(/25%|five/);

    const unordered = buildCapability();
    bindManifestSha(unordered);
    [unordered.promotion.families[0], unordered.promotion.families[1]] =
      [unordered.promotion.families[1]!, unordered.promotion.families[0]!];
    expect(() => validateMsrcWindowsLpeCapabilityPromotion({
      lock: unordered.lock, boundInventories: unordered.boundInventories, manifest: unordered.manifest,
      developmentLabels: unordered.labels[0], holdoutLabels: unordered.labels[1], promotion: unordered.promotion,
    })).toThrow(/canonically/);
  });
});
