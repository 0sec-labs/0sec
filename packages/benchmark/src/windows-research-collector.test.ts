import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  collectWindowsResearchAttempt,
  summarizeWindowsResearch,
  type WindowsResearchAttemptInput,
} from "./windows-research-collector.js";
import { loadWindowsLpeCorpus } from "./windows-lpe-corpus.js";

let root: string;
let receiptPath: string;
const labelSealKey = "test-only-label-seal-key-with-at-least-32-bytes";
const contractCorpusPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../fixtures/windows-lpe-corpus-contract-v1.json",
);

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function importVerdict(): string {
  const path = join(root, "import-verdict.json");
  writeFileSync(path, JSON.stringify({
    verdictSchema: "0sec.windows-hyperv-import-verdict/v1",
    executionOrigin: "external",
    producer: "0verse",
    schemaVersion: "0verse.hyperv-evidence/v1",
    campaignId: "windows-contract-v1",
    buildLabEx: "28020.1.amd64fre.rs_prerelease",
    signature: "bugcheck-133:fixture",
    confirmations: 2,
    requiredConfirmations: 2,
    cleanControls: 2,
    distinctDumpArtifacts: 2,
    dumpHashBasis: "retained-bundle-bytes",
    receiptSha256: sha256(receiptPath),
    sidecarsRehashed: 6,
    passed: true,
  }));
  return path;
}

beforeEach(() => {
  process.env["0SEC_WINDOWS_LABEL_SEAL_KEY"] = labelSealKey;
  root = mkdtempSync(join(tmpdir(), "windows-research-ledger-"));
  receiptPath = join(root, "receipt.json");
  writeFileSync(receiptPath, "{}\n");
});

afterEach(() => {
  delete process.env["0SEC_WINDOWS_LABEL_SEAL_KEY"];
  rmSync(root, { recursive: true, force: true });
});

function attempt(
  updates: Partial<WindowsResearchAttemptInput> = {},
): WindowsResearchAttemptInput {
  const result: WindowsResearchAttemptInput = {
    schemaVersion: "0sec.windows-research-attempt/v1",
    mode: "contract",
    campaignId: "windows-contract-v1",
    caseId: "positive-1",
    attempt: 1,
    groundTruth: "positive",
    label: {
      source: "sealed contract labels",
      sha256: "1".repeat(64),
      sealedAt: "2026-07-13T00:00:00.000Z",
      keyId: "test-label-key-v1",
      signature: "0".repeat(64),
    },
    repoShas: {
      zeroverse: "a".repeat(40),
      "0sec": "b".repeat(40),
      zeroCloud: "c".repeat(40),
    },
    windowsBuildLabEx: "28020.1.amd64fre.rs_prerelease",
    campaignManifestSha256: "2".repeat(64),
    scopeManifestSha256: "3".repeat(64),
    receiptPath,
    artifactPaths: [receiptPath],
    discovery: {
      candidateEmitted: true,
      candidateId: "candidate-1",
      model: "fixture-model",
      runtime: "offline-contract",
      agentRole: "finder",
      agentCount: 2,
      durationMs: 10,
    },
    proof: {
      status: "reproduced",
      targetTrials: 2,
      cleanControls: 2,
      confirmations: 2,
      crashSignature: "bugcheck-133:fixture",
      osecImportPassed: true,
    },
    telemetry: {
      startedAt: "2026-07-13T00:00:00.000Z",
      completedAt: "2026-07-13T00:00:01.000Z",
      proveDurationMs: 700,
      importDurationMs: 100,
      totalDurationMs: 1000,
      inputTokens: null,
      outputTokens: null,
      cachedTokens: null,
      workerMinutes: null,
      modelCostUsd: null,
      computeCostUsd: null,
      totalCostUsd: null,
      costBasis: "offline contract fixture; unmetered",
    },
    safety: {
      scopeFresh: true,
      authorizedProgram: true,
      workerBuildBound: true,
      triggerAllowlisted: true,
      controlFirst: true,
      cleanControls: true,
      sidecarsRevalidated: true,
      artifactsRetained: true,
      preExecutionGatePassed: true,
      executed: false,
      weaponization: false,
      autoDisclosure: false,
      reasons: [],
    },
    ...updates,
  };
  result.label.signature = createHmac("sha256", labelSealKey).update(JSON.stringify({
    campaignId: result.campaignId,
    caseId: result.caseId,
    groundTruth: result.groundTruth,
    labelSha256: result.label.sha256,
    sealedAt: result.label.sealedAt,
  })).digest("hex");
  return result;
}

describe("Windows research all-attempts ledger", () => {
  it("hashes artifacts but excludes contract fixtures from capability metrics", () => {
    const row = collectWindowsResearchAttempt(attempt());
    expect(row.claimEligible).toBe(false);
    expect(row.receiptSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(row.artifacts).toHaveLength(1);
    expect(row.rowSha256).toMatch(/^[a-f0-9]{64}$/);
    const summary = summarizeWindowsResearch([row]);
    expect(summary.outcomes.reproduced).toBe(0);
    expect(summary.contractValidationOutcomes.reproduced).toBe(1);
    expect(summary.claimEligibleRows).toBe(0);
    expect(summary.singleAttempt.precision.rate).toBeNull();
  });

  it("cryptographically binds corpus cases and excludes live benchmark rows from claims", () => {
    const corpus = loadWindowsLpeCorpus(contractCorpusPath);
    const row = collectWindowsResearchAttempt(attempt({
      mode: "live",
      caseId: "synthetic-positive-001",
      corpusManifestPath: contractCorpusPath,
      campaignManifestSha256: corpus.manifestSha256,
      windowsBuildLabEx: "fixture.1.amd64fre.contract",
      proof: {
        status: "not_reproduced",
        targetTrials: 0,
        cleanControls: 0,
        confirmations: 0,
        osecImportPassed: false,
      },
    }));
    expect(row.claimEligible).toBe(false);
    expect(summarizeWindowsResearch([row]).claimEligibleRows).toBe(0);

    expect(() => collectWindowsResearchAttempt(attempt({
      mode: "live",
      caseId: "synthetic-positive-001",
      corpusManifestPath: contractCorpusPath,
      campaignManifestSha256: "f".repeat(64),
      windowsBuildLabEx: "fixture.1.amd64fre.contract",
      proof: {
        status: "not_reproduced",
        targetTrials: 0,
        cleanControls: 0,
        confirmations: 0,
        osecImportPassed: false,
      },
    }))).toThrow(/does not bind/);
  });

  it("preserves denominators and reports single-attempt versus best-of-N", () => {
    const miss = collectWindowsResearchAttempt(attempt({
      mode: "live",
      proof: {
        status: "not_attempted",
        targetTrials: 0,
        cleanControls: 0,
        confirmations: 0,
        osecImportPassed: false,
      },
      discovery: { ...attempt().discovery, candidateEmitted: false },
    }));
    const hit = collectWindowsResearchAttempt(attempt({
      mode: "live",
      attempt: 2,
      importVerdictPath: importVerdict(),
      safety: { ...attempt().safety, executed: true },
    }));
    const falsePositive = collectWindowsResearchAttempt(attempt({
      mode: "live",
      caseId: "negative-1",
      groundTruth: "negative",
      proof: {
        status: "not_reproduced",
        targetTrials: 2,
        cleanControls: 2,
        confirmations: 0,
        osecImportPassed: false,
      },
    }));
    const summary = summarizeWindowsResearch([miss, hit, falsePositive]);
    expect(summary.singleAttempt.confusion).toEqual({ tp: 1, fp: 1, tn: 0, fn: 1 });
    expect(summary.singleAttempt.precision.rate).toBe(0.5);
    expect(summary.singleAttempt.recall.rate).toBe(0.5);
    expect(summary.bestOfN.confusion).toEqual({ tp: 1, fp: 1, tn: 0, fn: 0 });
    expect(summary.bestOfN.recall.rate).toBe(1);
    expect(summary.outcomes.not_reproduced).toBe(1);
    expect(summary.outcomes.not_attempted).toBe(1);
  });

  it("records safety rejection without execution and refuses unsafe accounting", () => {
    const rejected = collectWindowsResearchAttempt(attempt({
      mode: "live",
      discovery: { ...attempt().discovery, candidateEmitted: false },
      proof: {
        status: "safety_rejected",
        targetTrials: 0,
        cleanControls: 0,
        confirmations: 0,
        osecImportPassed: false,
        rejectionReason: "scope stale",
      },
      safety: {
        ...attempt().safety,
        scopeFresh: false,
        preExecutionGatePassed: false,
        reasons: ["scope stale"],
      },
    }));
    const summary = summarizeWindowsResearch([rejected]);
    expect(summary.outcomes.safety_rejected).toBe(1);
    expect(summary.safety.blockedBeforeExecution).toBe(1);
    expect(summary.safety.executionsAfterFailedPreExecutionGate).toBe(0);

    expect(() => collectWindowsResearchAttempt(attempt({
      safety: { ...attempt().safety, preExecutionGatePassed: false, executed: true },
    }))).toThrow(/execution occurred/);
    expect(() => collectWindowsResearchAttempt(attempt({
      telemetry: { ...attempt().telemetry, totalCostUsd: 0 },
    }))).toThrow(/placeholder zero/);
    expect(() => collectWindowsResearchAttempt(attempt({
      mode: "live",
      label: { ...attempt().label, sealedAt: "2026-07-13T00:00:00.001Z" },
    }))).toThrow(/sealed before/);
    expect(() => collectWindowsResearchAttempt({
      ...attempt(),
      exploit_payload: "forbidden",
    } as WindowsResearchAttemptInput)).toThrow(/forbidden executable field/);
  });

  it("rejects duplicate attempt keys and post-collection tampering", () => {
    const row = collectWindowsResearchAttempt(attempt({
      mode: "live",
      importVerdictPath: importVerdict(),
      safety: { ...attempt().safety, executed: true },
    }));
    expect(() => summarizeWindowsResearch([row, row])).toThrow(/duplicate/);
    expect(() => summarizeWindowsResearch([{ ...row, windowsBuildLabEx: "tampered" }])).toThrow(/row hash/);
    const serialized = JSON.parse(JSON.stringify(row)) as typeof row;
    expect(() => summarizeWindowsResearch([serialized])).not.toThrow();
  });

  it("binds live reproduced claims to the actual import verdict and rejects unknown fields", () => {
    const verdictPath = importVerdict();
    expect(() => collectWindowsResearchAttempt(attempt({
      mode: "live",
      importVerdictPath: verdictPath,
      safety: { ...attempt().safety, executed: true },
      proof: { ...attempt().proof, confirmations: 3 },
    }))).toThrow(/not bound/);
    expect(() => collectWindowsResearchAttempt({
      ...attempt(),
      password: "should-never-be-published",
    } as WindowsResearchAttemptInput)).toThrow(/unsupported field/);
  });

  it("does not hash files outside the retained receipt bundle", () => {
    const outsideRoot = mkdtempSync(join(tmpdir(), "windows-research-outside-"));
    const outside = join(outsideRoot, "secret.txt");
    writeFileSync(outside, "must not be read");
    try {
      expect(() => collectWindowsResearchAttempt(attempt({ artifactPaths: [outside] }))).toThrow(/escapes/);
    } finally {
      rmSync(outsideRoot, { recursive: true, force: true });
    }
  });
});
