import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  validateWindowsLpePairedCorpus,
  loadWindowsLpePairedCorpus,
  createWindowsLpeLabelsSalt,
  windowsLpeInventoryCommitment,
  windowsLpeLabelsCommitment,
  type WindowsLpeEvaluatorLabels,
  type WindowsLpePairedCorpusCase,
  type WindowsLpePairedCorpusManifest,
} from "./windows-lpe-paired-corpus.js";

const fixtureDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "../fixtures");
const fixture = JSON.parse(readFileSync(resolve(fixtureDirectory, "windows-lpe-paired-corpus-contract-v2.json"), "utf8")) as WindowsLpePairedCorpusManifest;
const development = JSON.parse(readFileSync(resolve(fixtureDirectory, "windows-lpe-paired-labels-development-contract-v2.json"), "utf8")) as WindowsLpeEvaluatorLabels;
const holdout = JSON.parse(readFileSync(resolve(fixtureDirectory, "windows-lpe-paired-labels-holdout-contract-v2.json"), "utf8")) as WindowsLpeEvaluatorLabels;

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function rebind(manifest: WindowsLpePairedCorpusManifest, labels: WindowsLpeEvaluatorLabels): void {
  labels.inventorySha256 = windowsLpeInventoryCommitment(manifest);
  if (labels.split === "development") manifest.labelCommitments.developmentSha256 = windowsLpeLabelsCommitment(labels);
  else manifest.labelCommitments.holdoutSha256 = windowsLpeLabelsCommitment(labels);
}

function capabilityFixture(): {
  manifest: WindowsLpePairedCorpusManifest;
  labels: [WindowsLpeEvaluatorLabels, WindowsLpeEvaluatorLabels];
} {
  const manifest = copy(fixture);
  manifest.profile = "capability";
  manifest.cases = [];
  const documents: [WindowsLpeEvaluatorLabels, WindowsLpeEvaluatorLabels] = [
    { schemaVersion: "0sec.windows-lpe-evaluator-labels/v2", corpusId: manifest.corpusId, split: "development", inventorySha256: "0".repeat(64), salt: "Qx7Nv2Lp9Ds4Hj6Bf1Mt8Yc3Za0Ue5Gi7Ro2Wk9VnAs", labels: [] },
    { schemaVersion: "0sec.windows-lpe-evaluator-labels/v2", corpusId: manifest.corpusId, split: "holdout", inventorySha256: "0".repeat(64), salt: "Cv3Mn8Qz1Kp6Xs9Dc2Fh7Jt0Ry4Ua5We3Li8Go1NbEk", labels: [] },
  ];
  for (let familyIndex = 0; familyIndex < 20; familyIndex += 1) {
    const split = familyIndex < 15 ? "development" : "holdout";
    const labels = split === "development" ? documents[0] : documents[1];
    const family = `public-family-${familyIndex}`;
    const pairId = `public-pair-${familyIndex}`;
    const advisoryId = `CVE-2020-${10000 + familyIndex}`;
    for (const [suffix, groundTruth] of [["a", "positive"], ["b", "negative"]] as const) {
      const caseId = `case-${familyIndex}-${suffix}`;
      manifest.cases.push(contractCase(caseId, family, pairId, split, advisoryId, familyIndex * 4 + (suffix === "a" ? 0 : 1)));
      labels.labels.push({ caseId, groundTruth });
    }
    for (const [offset, suffix] of [[2, "clean-a"], [3, "clean-b"]] as const) {
      const extraCaseId = `case-${familyIndex}-${suffix}`;
      manifest.cases.push(contractCase(extraCaseId, family, null, split, advisoryId, familyIndex * 4 + offset));
      labels.labels.push({ caseId: extraCaseId, groundTruth: "negative" });
    }
  }
  rebind(manifest, documents[0]);
  rebind(manifest, documents[1]);
  return { manifest, labels: documents };
}

function contractCase(
  caseId: string,
  family: string,
  pairId: string | null,
  split: "development" | "holdout",
  advisoryId: string,
  index: number,
): WindowsLpePairedCorpusCase {
  const hex = (index + 1).toString(16).padStart(64, "0");
  return {
    caseId, family, pairId, split, advisoryId,
    target: {
      windowsBuildLabEx: `${26000 + index}.1.amd64fre.contract`, currentBuildNumber: String(26000 + index), updateBuildRevision: index,
      architecture: "x64", artifactSha256: hex,
      provenance: {
        source: "public Microsoft regression metadata; no exploit material",
        refs: [`https://msrc.microsoft.com/update-guide/vulnerability/${advisoryId}`],
        sealedAt: "2026-07-14T00:00:00.000Z",
      },
    },
    scope: { authorization: "public-known-cve-regression", dynamicExecutionAllowed: false, scopeManifestSha256: hex },
    policy: { noveltyEligible: false, bountyClaimEligible: false, weaponization: false, autoDisclosure: false },
  };
}

describe("Windows LPE paired corpus v2", () => {
  it("validates discovery metadata without revealing labels, then evaluates committed labels", () => {
    const discovery = validateWindowsLpePairedCorpus(copy(fixture));
    expect(discovery.discoveryCounts).toEqual({ cases: 4, development: 2, holdout: 2, families: 2, pairedFamilies: 2 });
    expect(discovery.evaluationCounts).toBeUndefined();
    expect(JSON.stringify(fixture)).not.toMatch(/groundTruth|positive|negative/);

    const evaluated = validateWindowsLpePairedCorpus(copy(fixture), [copy(development), copy(holdout)]);
    expect(evaluated.evaluationCounts).toEqual({ positives: 2, negatives: 2, publicPositiveFamilies: 0, holdoutFamilies: 1, holdoutPublicPositiveFamilies: 0 });
    expect(evaluated.manifestSha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("generates canonical 256-bit evaluator salts", () => {
    const salt = createWindowsLpeLabelsSalt();
    expect(salt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(salt, "base64url")).toHaveLength(32);
  });

  it("rejects wrong salts, label swaps across splits, duplicates, missing labels, and unknown labels", () => {
    const wrongSalt = copy(development);
    wrongSalt.salt = createWindowsLpeLabelsSalt();
    expect(() => validateWindowsLpePairedCorpus(copy(fixture), [wrongSalt])).toThrow(/commitment mismatch/);

    const swapped = copy(development);
    swapped.labels[0]!.caseId = "holdout-build-a";
    expect(() => validateWindowsLpePairedCorpus(copy(fixture), [swapped])).toThrow(/unknown or wrong-split/);

    const duplicate = copy(development);
    duplicate.labels[1]!.caseId = duplicate.labels[0]!.caseId;
    expect(() => validateWindowsLpePairedCorpus(copy(fixture), [duplicate])).toThrow(/duplicate evaluator label/);

    const missing = copy(development);
    missing.labels.pop();
    expect(() => validateWindowsLpePairedCorpus(copy(fixture), [missing])).toThrow(/missing case/);

    const unknown = copy(development);
    unknown.labels[0]!.caseId = "not-in-corpus";
    expect(() => validateWindowsLpePairedCorpus(copy(fixture), [unknown])).toThrow(/unknown or wrong-split/);
  });

  it("requires each committed pair to contain one vulnerable and one fixed build", () => {
    const manifest = copy(fixture);
    const labels = copy(development);
    labels.labels[1]!.groundTruth = "positive";
    rebind(manifest, labels);
    expect(() => validateWindowsLpePairedCorpus(manifest, [labels])).toThrow(/one vulnerable positive and one fixed negative/);
  });

  it("binds labels to the full inventory and pairs to distinct same-architecture targets", () => {
    const changedInventory = copy(fixture);
    changedInventory.cases[0]!.scope.scopeManifestSha256 = "9".repeat(64);
    expect(() => validateWindowsLpePairedCorpus(changedInventory, [copy(development)])).toThrow(/bind the current corpus inventory/);

    const sameArtifact = copy(fixture);
    sameArtifact.cases[1]!.target.artifactSha256 = sameArtifact.cases[0]!.target.artifactSha256;
    expect(() => validateWindowsLpePairedCorpus(sameArtifact)).toThrow(/same target artifact/);

    const sameBuild = copy(fixture);
    sameBuild.cases[1]!.target.windowsBuildLabEx = sameBuild.cases[0]!.target.windowsBuildLabEx;
    sameBuild.cases[1]!.target.currentBuildNumber = sameBuild.cases[0]!.target.currentBuildNumber;
    sameBuild.cases[1]!.target.updateBuildRevision = sameBuild.cases[0]!.target.updateBuildRevision;
    expect(() => validateWindowsLpePairedCorpus(sameBuild)).toThrow(/same exact Windows build coordinate/);

    const mixedArchitecture = copy(fixture);
    mixedArchitecture.cases[1]!.target.architecture = "arm64";
    expect(() => validateWindowsLpePairedCorpus(mixedArchitecture)).toThrow(/mixes architectures/);
  });

  it("rejects duplicate IDs, family leakage, incomplete pairs, forbidden fields, and claim-policy flips", () => {
    const duplicate = copy(fixture);
    duplicate.cases[1]!.caseId = duplicate.cases[0]!.caseId;
    expect(() => validateWindowsLpePairedCorpus(duplicate)).toThrow(/duplicate/);

    const leakage = copy(fixture);
    leakage.cases[2]!.family = leakage.cases[0]!.family;
    expect(() => validateWindowsLpePairedCorpus(leakage)).toThrow(/crosses development and holdout/);

    const incomplete = copy(fixture);
    incomplete.cases[1]!.pairId = null;
    expect(() => validateWindowsLpePairedCorpus(incomplete)).toThrow(/exactly two/);

    expect(() => validateWindowsLpePairedCorpus({ ...copy(fixture), exploit_payload: "forbidden" })).toThrow(/forbidden executable or label/);
    const claimable = copy(fixture);
    claimable.cases[0]!.policy.bountyClaimEligible = true as false;
    expect(() => validateWindowsLpePairedCorpus(claimable)).toThrow(/non-claimable/);
  });

  it("enforces capability minimums only with both evaluator-held splits", () => {
    const tooSmall = copy(fixture);
    tooSmall.profile = "capability";
    const tooSmallDevelopment = copy(development);
    const tooSmallHoldout = copy(holdout);
    rebind(tooSmall, tooSmallDevelopment);
    rebind(tooSmall, tooSmallHoldout);
    expect(() => validateWindowsLpePairedCorpus(tooSmall, [tooSmallDevelopment, tooSmallHoldout])).toThrow(/20 paired public positive/);

    const capability = capabilityFixture();
    const result = validateWindowsLpePairedCorpus(capability.manifest, capability.labels);
    expect(result.evaluationCounts).toEqual({ positives: 20, negatives: 60, publicPositiveFamilies: 20, holdoutFamilies: 5, holdoutPublicPositiveFamilies: 5 });

    expect(() => validateWindowsLpePairedCorpus(capability.manifest, [capability.labels[0]])).toThrow(/both development and holdout/);
  });

  it("requires authoritative public CVE provenance and rejects duplicate case identities", () => {
    const capability = capabilityFixture();
    capability.manifest.cases[0]!.target.provenance.refs = ["fixture:not-authoritative"];
    expect(() => validateWindowsLpePairedCorpus(capability.manifest)).toThrow(/MSRC reference/);

    const cloned = copy(fixture);
    cloned.cases[2]!.target.artifactSha256 = cloned.cases[0]!.target.artifactSha256;
    cloned.cases[2]!.scope.scopeManifestSha256 = cloned.cases[0]!.scope.scopeManifestSha256;
    expect(() => validateWindowsLpePairedCorpus(cloned)).toThrow(/duplicate artifact and scope identity/);
  });

  it("rejects duplicate JSON keys in bounded file-loader inputs", () => {
    const directory = mkdtempSync(resolve(tmpdir(), "0sec-paired-corpus-"));
    const path = resolve(directory, "duplicate.json");
    try {
      writeFileSync(path, '{"schemaVersion":"0sec.windows-lpe-paired-corpus/v2","schemaVersion":"shadow"}');
      expect(() => loadWindowsLpePairedCorpus(path)).toThrow(/duplicate JSON key/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
