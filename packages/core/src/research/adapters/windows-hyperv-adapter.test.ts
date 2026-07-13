import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { runResearch } from "../research-runner.js";
import {
  WindowsHyperVImportAdapter,
  type WindowsHyperVTarget,
  type ZeroverseHyperVEvidence,
  type ZeroverseHyperVObservation,
} from "./windows-hyperv-adapter.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function setup(status: "REPRODUCED" | "NOT_REPRODUCED" = "REPRODUCED"): {
  target: WindowsHyperVTarget;
  root: string;
  transcript: string;
  analysis: string;
  receiptPath: string;
} {
  const root = mkdtempSync(join(tmpdir(), "pwnkit-hyperv-"));
  roots.push(root);
  mkdirSync(join(root, "sidecars"));
  const observations: ZeroverseHyperVObservation[] = [];
  let firstTranscript = "";
  let firstAnalysis = "";
  for (let trial = 1; trial <= 2; trial++) {
    for (const caseName of ["control", "target"] as const) {
      const transcript = join(root, "sidecars", `${trial}-${caseName}.json`);
      writeFileSync(transcript, JSON.stringify({ trial, case: caseName }));
      if (!firstTranscript) firstTranscript = transcript;
      const crashed = status === "REPRODUCED" && caseName === "target";
      const analysis = crashed ? join(root, "sidecars", `${trial}-target-cdb.txt`) : "";
      const dump = crashed ? join(root, "sidecars", `${trial}-target.dmp`) : "";
      if (analysis) {
        writeFileSync(analysis, "BugCheck 133, {0, 1}\nFAILURE_BUCKET_ID: 0x133_DPC_vmswitch!ParseOid\n");
        if (!firstAnalysis) firstAnalysis = analysis;
      }
      if (dump) writeFileSync(dump, `PAGEDU64sanitized-test-dump-${trial}\n`);
      observations.push({
        case: caseName,
        trial,
        build_lab_ex: "28020.1.amd64fre.rs_prerelease",
        status: crashed ? "CRASH" : "CLEAN",
        crash_signature: crashed ? "bugcheck-133:0x133_dpc_vmswitch!parseoid" : "",
        dump_sha256: dump ? sha256(dump) : "",
        dump_identity: crashed ? `dump-${trial}|artifact-${trial}` : "",
        dump_artifact_path: dump ? `sidecars/${trial}-target.dmp` : "",
        guest_transcript_sha256: sha256(transcript),
        guest_transcript_path: `sidecars/${trial}-${caseName}.json`,
        dump_analysis_path: analysis ? `sidecars/${trial}-target-cdb.txt` : "",
        dump_analysis_sha256: analysis ? sha256(analysis) : "",
        run_nonce: `run-${trial}-${caseName}-`.padEnd(32, "x"),
        argv_sha256: createHash("sha256").update(`${trial}:${caseName}:argv`).digest("hex"),
        error: "",
      });
    }
  }
  const campaignHash = "a".repeat(64);
  const scopeHash = "b".repeat(64);
  const receiptPath = join(root, "receipt.json");
  writeFileSync(receiptPath, JSON.stringify({
    schema_version: "0verse.hyperv-evidence/v1",
    manifest_sha256: campaignHash,
    scope_manifest_sha256: scopeHash,
    campaign_id: "vmswitch-oid-001",
    scope_program: "hyperv-insider",
    worker: "visor-insider",
    status,
    crash_signature: status === "REPRODUCED" ? "bugcheck-133:0x133_dpc_vmswitch!parseoid" : "",
    confirmations: status === "REPRODUCED" ? 2 : 0,
    required_confirmations: 2,
    observations,
    error: status === "REPRODUCED" ? "" : "confirmation threshold was not met",
    claim_eligible: true,
  }));
  const finding = {
    id: "vmswitch-oid",
    templateId: "windows-hyperv",
    title: "vmswitch OID memory corruption",
    description: "candidate imported from an authorized 0verse campaign",
    severity: "high",
    category: "memory-corruption",
    status: "verified",
    evidence: { request: "", response: "" },
    timestamp: 1,
  } as Finding;
  return {
    root,
    transcript: firstTranscript,
    analysis: firstAnalysis,
    receiptPath,
    target: {
      kind: "windows.hyperv-prover-import",
      id: "hyperv-import",
      location: receiptPath,
      version: "hyperv-insider",
      buildId: "28020.1.amd64fre.rs_prerelease",
      configDigest: campaignHash,
      config: {
        finding,
        campaignId: "vmswitch-oid-001",
        worker: "visor-insider",
        campaignManifestSha256: campaignHash,
        scopeManifestSha256: scopeHash,
      },
    },
  };
}

describe("WindowsHyperVImportAdapter", () => {
  it("promotes only after re-hashing paired target-only evidence", async () => {
    const { target, root } = setup();
    const result = await runResearch(new WindowsHyperVImportAdapter(), target, {
      artifactRoot: join(root, "artifacts"),
      runId: "hyperv-run",
    });
    expect(result.envelopes[0]).toMatchObject({
      grade: "reproduced",
      target: { kind: "windows.hyperv-prover-import", buildId: target.buildId },
      executionContext: { sandbox: "hyperv-child-partition", basis: "runtime-attested" },
    });
    expect(result.envelopes[0]?.artifacts).toHaveLength(10);
    expect(result.envelopes[0]?.artifacts.every((artifact) => /^[a-f0-9]{64}$/.test(artifact.sha256))).toBe(true);
    const receiptArtifact = result.envelopes[0]!.artifacts.find((artifact) => basename(artifact.path) === "receipt.json")!;
    const portable = JSON.parse(readFileSync(receiptArtifact.path, "utf8")) as ZeroverseHyperVEvidence;
    for (const row of portable.observations) {
      for (const path of [row.guest_transcript_path, row.dump_analysis_path, row.dump_artifact_path].filter(Boolean)) {
        expect(isAbsolute(path)).toBe(false);
        expect(() => readFileSync(join(dirname(receiptArtifact.path), path))).not.toThrow();
      }
    }
    expect(result.envelopes[0]?.native?.oraclePayload).toEqual(expect.arrayContaining([
      expect.objectContaining({ data: expect.objectContaining({ distinctDumpArtifacts: 2 }) }),
    ]));
  });

  it("rejects a tampered guest transcript", async () => {
    const { target, root, transcript } = setup();
    writeFileSync(transcript, "tampered");
    const result = await runResearch(new WindowsHyperVImportAdapter(), target, {
      artifactRoot: join(root, "artifacts"),
      runId: "tampered",
    });
    expect(result.findings).toHaveLength(0);
    expect(result.evidence.some((item) => item.stage === "discover" && item.status === "failed")).toBe(true);
  });

  it("rejects tampered cdb analysis and reused proof identities", async () => {
    const tampered = setup();
    writeFileSync(tampered.analysis, "BugCheck 133, {0}\nFAILURE_BUCKET_ID: changed\n");
    const tamperedResult = await runResearch(new WindowsHyperVImportAdapter(), tampered.target, {
      artifactRoot: join(tampered.root, "artifacts"),
      runId: "tampered-analysis",
    });
    expect(tamperedResult.findings).toHaveLength(0);

    const reused = setup();
    const receipt = JSON.parse(readFileSync(reused.receiptPath, "utf8")) as ZeroverseHyperVEvidence;
    const crashes = receipt.observations.filter((row) => row.status === "CRASH");
    crashes[1]!.dump_sha256 = crashes[0]!.dump_sha256;
    crashes[1]!.run_nonce = receipt.observations[0]!.run_nonce;
    writeFileSync(reused.receiptPath, JSON.stringify(receipt));
    const reusedResult = await runResearch(new WindowsHyperVImportAdapter(), reused.target, {
      artifactRoot: join(reused.root, "artifacts"),
      runId: "reused-proof",
    });
    expect(reusedResult.findings).toHaveLength(0);
  });

  it("rejects a dump whose retained bytes do not match the receipt", async () => {
    const { target, root, receiptPath } = setup();
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as ZeroverseHyperVEvidence;
    const crash = receipt.observations.find((row) => row.status === "CRASH")!;
    writeFileSync(join(root, crash.dump_artifact_path), "different dump bytes");
    const result = await runResearch(new WindowsHyperVImportAdapter(), target, {
      artifactRoot: join(root, "artifacts"),
      runId: "tampered-dump",
    });
    expect(result.findings).toHaveLength(0);
    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ stage: "discover", status: "failed" }),
    ]));

    const fake = setup();
    const fakeReceipt = JSON.parse(readFileSync(fake.receiptPath, "utf8")) as ZeroverseHyperVEvidence;
    const fakeCrash = fakeReceipt.observations.find((row) => row.status === "CRASH")!;
    const fakeDump = join(fake.root, fakeCrash.dump_artifact_path);
    writeFileSync(fakeDump, "not a Windows crash dump");
    fakeCrash.dump_sha256 = sha256(fakeDump);
    writeFileSync(fake.receiptPath, JSON.stringify(fakeReceipt));
    const fakeResult = await runResearch(new WindowsHyperVImportAdapter(), fake.target, {
      artifactRoot: join(fake.root, "artifacts"),
      runId: "fake-dump",
    });
    expect(fakeResult.findings).toHaveLength(0);
  });

  it("refuses absolute and symlinked sidecars outside the receipt bundle", async () => {
    const absolute = setup();
    const absoluteReceipt = JSON.parse(readFileSync(absolute.receiptPath, "utf8")) as ZeroverseHyperVEvidence;
    absoluteReceipt.observations[0]!.guest_transcript_path = absolute.transcript;
    writeFileSync(absolute.receiptPath, JSON.stringify(absoluteReceipt));
    const absoluteResult = await runResearch(new WindowsHyperVImportAdapter(), absolute.target, {
      artifactRoot: join(absolute.root, "artifacts"),
      runId: "absolute-sidecar",
    });
    expect(absoluteResult.findings).toHaveLength(0);

    const linked = setup();
    const outsideRoot = mkdtempSync(join(tmpdir(), "pwnkit-hyperv-outside-"));
    roots.push(outsideRoot);
    const outside = join(outsideRoot, "outside.json");
    writeFileSync(outside, readFileSync(linked.transcript));
    rmSync(linked.transcript);
    symlinkSync(outside, linked.transcript);
    const linkedResult = await runResearch(new WindowsHyperVImportAdapter(), linked.target, {
      artifactRoot: join(linked.root, "artifacts"),
      runId: "symlink-sidecar",
    });
    expect(linkedResult.findings).toHaveLength(0);
  });

  it("does not promote a well-formed NOT_REPRODUCED receipt", async () => {
    const { target, root } = setup("NOT_REPRODUCED");
    const result = await runResearch(new WindowsHyperVImportAdapter(), target, {
      artifactRoot: join(root, "artifacts"),
      runId: "negative",
    });
    expect(result.findings).toHaveLength(0);
    expect(result.evidence.some((item) => item.stage === "verify" && item.status === "inconclusive")).toBe(true);
  });

  it("validates but never promotes a non-claim contract fixture", async () => {
    const { target, root, receiptPath } = setup();
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as ZeroverseHyperVEvidence;
    receipt.claim_eligible = false;
    receipt.fixture_kind = "sanitized-contract";
    writeFileSync(receiptPath, JSON.stringify(receipt));
    const result = await runResearch(new WindowsHyperVImportAdapter(), target, {
      artifactRoot: join(root, "artifacts"),
      runId: "contract-only",
    });
    expect(result.findings).toHaveLength(0);
    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ status: "passed", summary: expect.stringContaining("no finding") }),
    ]));
  });

  it("fails closed on schema and campaign identity drift", async () => {
    const { target, root, receiptPath } = setup();
    const receipt = JSON.parse(readFileSync(receiptPath, "utf8")) as Record<string, unknown>;
    receipt.schema_version = "0verse.hyperv-evidence/v2";
    receipt.campaign_id = "other-campaign";
    writeFileSync(receiptPath, JSON.stringify(receipt));
    const result = await runResearch(new WindowsHyperVImportAdapter(), target, {
      artifactRoot: join(root, "artifacts"),
      runId: "drift",
    });
    expect(result.candidates).toHaveLength(0);
  });
});
