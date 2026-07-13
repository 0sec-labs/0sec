import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { runResearch } from "../research-runner.js";
import {
  WindowsHyperVImportAdapter,
  type WindowsHyperVTarget,
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
  receiptPath: string;
} {
  const root = mkdtempSync(join(tmpdir(), "pwnkit-hyperv-"));
  roots.push(root);
  mkdirSync(join(root, "sidecars"));
  const observations: ZeroverseHyperVObservation[] = [];
  let firstTranscript = "";
  for (let trial = 1; trial <= 2; trial++) {
    for (const caseName of ["control", "target"] as const) {
      const transcript = join(root, "sidecars", `${trial}-${caseName}.json`);
      writeFileSync(transcript, JSON.stringify({ trial, case: caseName }));
      if (!firstTranscript) firstTranscript = transcript;
      const crashed = status === "REPRODUCED" && caseName === "target";
      const analysis = crashed ? join(root, "sidecars", `${trial}-target-cdb.txt`) : "";
      if (analysis) {
        writeFileSync(analysis, "BugCheck 133, {0, 1}\nFAILURE_BUCKET_ID: 0x133_DPC_vmswitch!ParseOid\n");
      }
      observations.push({
        case: caseName,
        trial,
        build_lab_ex: "28020.1.amd64fre.rs_prerelease",
        status: crashed ? "CRASH" : "CLEAN",
        crash_signature: crashed ? "bugcheck-133:0x133_dpc_vmswitch!parseoid" : "",
        dump_sha256: crashed ? "d".repeat(64) : "",
        guest_transcript_sha256: sha256(transcript),
        guest_transcript_path: transcript,
        dump_analysis_path: analysis,
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
    expect(result.envelopes[0]?.artifacts).toHaveLength(8);
    expect(result.envelopes[0]?.artifacts.every((artifact) => /^[a-f0-9]{64}$/.test(artifact.sha256))).toBe(true);
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

  it("does not promote a well-formed NOT_REPRODUCED receipt", async () => {
    const { target, root } = setup("NOT_REPRODUCED");
    const result = await runResearch(new WindowsHyperVImportAdapter(), target, {
      artifactRoot: join(root, "artifacts"),
      runId: "negative",
    });
    expect(result.findings).toHaveLength(0);
    expect(result.evidence.some((item) => item.stage === "verify" && item.status === "inconclusive")).toBe(true);
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
