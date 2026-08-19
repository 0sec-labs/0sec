import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { validateWindowsLpeCorpus, type WindowsLpeCorpusManifest } from "./windows-lpe-corpus.js";

const fixture = JSON.parse(readFileSync(resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../fixtures/windows-lpe-corpus-contract-v1.json",
), "utf8")) as WindowsLpeCorpusManifest;

function copy(): WindowsLpeCorpusManifest {
  return JSON.parse(JSON.stringify(fixture)) as WindowsLpeCorpusManifest;
}

describe("Windows LPE corpus manifest", () => {
  it("accepts the harmless positive and negative contract fixtures", () => {
    const result = validateWindowsLpeCorpus(copy());
    expect(result.counts).toEqual({ cases: 2, positives: 1, negatives: 1, development: 1, holdout: 1 });
    expect(result.manifestSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(validateWindowsLpeCorpus(copy()).manifestSha256).toBe(result.manifestSha256);
  });

  it("keeps every benchmark case out of novelty and bounty claims", () => {
    const input = copy();
    input.cases[0]!.policy.bountyClaimEligible = true as false;
    expect(() => validateWindowsLpeCorpus(input)).toThrow(/non-claimable/);
  });

  it("rejects executable material and unsupported fields", () => {
    expect(() => validateWindowsLpeCorpus({ ...copy(), exploit_payload: "forbidden" })).toThrow(/forbidden executable/);
    expect(() => validateWindowsLpeCorpus({ ...copy(), notes: "unbound" })).toThrow(/unsupported field/);
  });

  it("rejects duplicate cases and family leakage across splits", () => {
    const duplicate = copy();
    duplicate.cases[1]!.caseId = duplicate.cases[0]!.caseId;
    expect(() => validateWindowsLpeCorpus(duplicate)).toThrow(/duplicate/);

    const leakage = copy();
    leakage.cases[1]!.family = leakage.cases[0]!.family;
    expect(() => validateWindowsLpeCorpus(leakage)).toThrow(/crosses development and holdout/);
  });

  it("binds positive reproduction labels to two confirmations and controls", () => {
    const input = copy();
    input.cases[0]!.evaluation.requiredConfirmations = 1;
    expect(() => validateWindowsLpeCorpus(input)).toThrow(/at least two confirmations/);
  });

  it("requires a negative control and matching kind/label semantics", () => {
    const noNegative = copy();
    noNegative.cases[1]!.groundTruth = "positive";
    expect(() => validateWindowsLpeCorpus(noNegative)).toThrow(/kind and groundTruth disagree/);
  });
});
