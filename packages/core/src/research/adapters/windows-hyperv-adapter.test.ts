import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { runResearch } from "../research-runner.js";
import {
  WindowsHyperVImportAdapter,
  type WindowsHyperVTarget,
  type ZeroverseHyperVEvidence,
  type ZeroverseHyperVObservation,
} from "./windows-hyperv-adapter.js";

const roots: string[] = [];
let signerRoot = "";
let signerKey = "";
let allowedSigners = "";
beforeAll(() => {
  signerRoot = mkdtempSync(join(tmpdir(), "pwnkit-hyperv-signer-"));
  signerKey = join(signerRoot, "acceptance-key");
  allowedSigners = join(signerRoot, "allowed-signers");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", signerKey]);
  writeFileSync(
    allowedSigners,
    `lab-acceptance ${readFileSync(join(signerRoot, "acceptance-key.pub"), "utf8")}`,
  );
  process.env.PWNKIT_HYPERV_ACCEPTANCE_ALLOWED_SIGNERS = allowedSigners;
});
afterAll(() => {
  delete process.env.PWNKIT_HYPERV_ACCEPTANCE_ALLOWED_SIGNERS;
  if (signerRoot) rmSync(signerRoot, { recursive: true, force: true });
});
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
  const now = new Date();
  const common = {
    campaign_sha256: campaignHash,
    scope_manifest_sha256: scopeHash,
    campaign_id: "vmswitch-oid-001",
    worker: "visor-insider",
    guest_worker: "attacker-insider",
    vm_name: "attacker",
    checkpoint_name: "clean",
    dump_path: "C:\\dumps\\MEMORY.DMP",
    build_lab_ex: "28020.1.amd64fre.rs_prerelease",
    checkpoint_identity_sha256: "1".repeat(64),
    debugger_executable_sha256: "2".repeat(64),
    trigger_executable_sha256: "3".repeat(64),
    control_executable_sha256: "3".repeat(64),
  };
  const recoveryArtifacts = {
    benign_dump_sha256: ["recovery-benign.dmp", "PAGEDU64sanitized-benign-dump"],
    benign_dump_analysis_sha256: ["recovery-benign-cdb.txt", "BugCheck 0, benign debugger smoke\n"],
    guest_challenge_sha256: ["recovery-guest-challenge.json", '{"challenge":"nonce-bound","ok":true}'],
  } as const;
  const recoveryHashes: Record<string, string> = {};
  for (const [field, [filename, content]] of Object.entries(recoveryArtifacts)) {
    const artifactPath = join(root, filename);
    writeFileSync(artifactPath, content);
    recoveryHashes[field] = sha256(artifactPath);
  }
  const drillPath = join(root, "recovery-drill.json");
  writeFileSync(drillPath, JSON.stringify({
    schema_version: "0verse.hyperv-recovery-drill/v1",
    ...common,
    worker_machine_id: "worker-guid",
    guest_machine_id: "guest-id",
    worker_ssh_host_key_sha256: "4".repeat(64),
    guest_ssh_host_key_sha256: "5".repeat(64),
    recovery_nonce: "recovery-drill-00000000000000000001",
    pre_host_boot_id: "before",
    post_host_boot_id: "after",
    started_at: new Date(now.getTime() - 6 * 60_000).toISOString(),
    host_unavailable_observed_at: new Date(now.getTime() - 5 * 60_000).toISOString(),
    host_recovered_at: new Date(now.getTime() - 4 * 60_000).toISOString(),
    guest_recovered_at: new Date(now.getTime() - 3 * 60_000).toISOString(),
    completed_at: new Date(now.getTime() - 2 * 60_000).toISOString(),
    ...recoveryHashes,
    out_of_band_controller: "provider-console",
    host_unavailable_observed: true,
    checkpoint_restore_confirmed: true,
    guest_challenge_confirmed: true,
    debugger_smoke_confirmed: true,
  }));
  const acceptance: Record<string, unknown> = {
    schema_version: "0verse.hyperv-worker-acceptance/v1",
    ...common,
    recovery_drill_path: basename(drillPath),
    recovery_drill_sha256: sha256(drillPath),
    execution_grant_sha256: "9".repeat(64),
    execution_grant_nonce: "execution-grant-0000000000000000001",
    issued_at: new Date(now.getTime() - 60_000).toISOString(),
    expires_at: new Date(now.getTime() + 60 * 60_000).toISOString(),
    nonce: "worker-acceptance-0000000000000001",
    accepted_by: "lab-acceptance",
    signature_ssh: "pending",
  };
  const materialPath = join(root, "acceptance-material.json");
  const unsigned = { ...acceptance };
  delete unsigned.signature_ssh;
  writeFileSync(materialPath, JSON.stringify(Object.fromEntries(
    Object.keys(unsigned).sort().map((key) => [key, unsigned[key]]),
  )));
  execFileSync("ssh-keygen", [
    "-q", "-Y", "sign", "-f", signerKey, "-n",
    "0verse-hyperv-worker-acceptance", materialPath,
  ]);
  acceptance.signature_ssh = readFileSync(join(root, "acceptance-material.json.sig"), "utf8");
  const acceptancePath = join(root, "worker-acceptance.json");
  writeFileSync(acceptancePath, JSON.stringify(acceptance));
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
    execution_grant_sha256: acceptance.execution_grant_sha256,
    execution_grant_nonce: acceptance.execution_grant_nonce,
    worker_acceptance_sha256: sha256(acceptancePath),
    worker_acceptance_nonce: acceptance.nonce,
    worker_acceptance_path: basename(acceptancePath),
    worker_recovery_drill_sha256: sha256(drillPath),
    worker_recovery_drill_path: basename(drillPath),
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
    expect(result.envelopes[0]?.artifacts).toHaveLength(15);
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

  it("rejects missing or tampered worker acceptance authority", async () => {
    const missing = setup();
    const receipt = JSON.parse(readFileSync(missing.receiptPath, "utf8")) as Record<string, unknown>;
    delete receipt.worker_acceptance_path;
    writeFileSync(missing.receiptPath, JSON.stringify(receipt));
    const missingResult = await runResearch(new WindowsHyperVImportAdapter(), missing.target, {
      artifactRoot: join(missing.root, "artifacts"), runId: "missing-acceptance",
    });
    expect(missingResult.findings).toHaveLength(0);

    const tampered = setup();
    const acceptancePath = join(tampered.root, "worker-acceptance.json");
    const acceptance = JSON.parse(readFileSync(acceptancePath, "utf8")) as Record<string, unknown>;
    acceptance.build_lab_ex = "attacker-chosen-build";
    writeFileSync(acceptancePath, JSON.stringify(acceptance));
    const tamperedReceipt = JSON.parse(
      readFileSync(tampered.receiptPath, "utf8"),
    ) as Record<string, unknown>;
    tamperedReceipt.worker_acceptance_sha256 = sha256(acceptancePath);
    writeFileSync(tampered.receiptPath, JSON.stringify(tamperedReceipt));
    const tamperedResult = await runResearch(new WindowsHyperVImportAdapter(), tampered.target, {
      artifactRoot: join(tampered.root, "artifacts"), runId: "tampered-acceptance",
    });
    expect(tamperedResult.findings).toHaveLength(0);

    const recoveryTamper = setup();
    writeFileSync(join(recoveryTamper.root, "recovery-guest-challenge.json"), "tampered");
    const recoveryTamperResult = await runResearch(
      new WindowsHyperVImportAdapter(), recoveryTamper.target,
      { artifactRoot: join(recoveryTamper.root, "artifacts"), runId: "tampered-recovery" },
    );
    expect(recoveryTamperResult.findings).toHaveLength(0);
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
