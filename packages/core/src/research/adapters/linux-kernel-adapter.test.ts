import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { researchZeroCapProven, type Finding } from "@0sec/shared";
import { runResearch } from "../research-runner.js";
import { LinuxKernelResearchAdapter, type LinuxKernelTarget } from "./linux-kernel-adapter.js";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function setup(): { target: LinuxKernelTarget; artifactRoot: string } {
  const root = mkdtempSync(join(tmpdir(), "0sec-linux-adapter-"));
  roots.push(root);
  const kernelTree = join(root, "linux");
  mkdirSync(kernelTree);
  const reproducerPath = join(root, "repro.c");
  writeFileSync(reproducerPath, "int main(void){return 0;}");
  const finding: Finding = {
    id: "kernel-f", templateId: "kernel", title: "Kernel UAF", description: "UAF",
    severity: "high", category: "use-after-free", status: "discovered",
    evidence: { request: "", response: "" }, timestamp: 1,
  };
  return {
    artifactRoot: join(root, "artifacts"),
    target: {
      kind: "linux.kernel-reproducer",
      id: "linux-test",
      location: kernelTree,
      config: { finding, verify: { reproducerPath, boots: 3, minHits: 2, expectedSignature: "KASAN: slab-use-after-free" } },
    },
  };
}

function runtimeReceipt(boot: number, reproducerSha256 = "b".repeat(64), observedKernelRelease = "6.12.95-0sec") {
  return { schemaVersion: 2 as const, nonce: String(boot).padStart(32, "a"), reproducerSha256, expectedKernelRelease: "6.12.95-0sec", observedKernelRelease, bootId: `00000000-0000-4000-8000-${String(boot).padStart(12, "0")}`, kernelImageSha256: "e".repeat(64), kernelConfigSha256: "f".repeat(64), realUid: 65534, effectiveUid: 65534, savedUid: 65534, realGid: 65534, effectiveGid: 65534, savedGid: 65534, supplementaryGroups: [], inheritableCapabilities: "0000000000000000", permittedCapabilities: "0000000000000000", effectiveCapabilities: "0000000000000000", ambientCapabilities: "0000000000000000", secureBits: 0, userNamespaceMax: 0, initialUserNamespace: true, noNewPrivileges: true };
}

function serializeReceipt(r: ReturnType<typeof runtimeReceipt>): string {
  return `schema=2\nnonce=${r.nonce}\nreproducer_sha256=${r.reproducerSha256}\nexpected_kernel_release=${r.expectedKernelRelease}\nobserved_kernel_release=${r.observedKernelRelease}\nboot_id=${r.bootId}\nkernel_image_sha256=${r.kernelImageSha256}\nkernel_config_sha256=${r.kernelConfigSha256}\nruid=${r.realUid}\neuid=${r.effectiveUid}\nsuid=${r.savedUid}\nrgid=${r.realGid}\negid=${r.effectiveGid}\nsgid=${r.savedGid}\ngroups=\ncap_inh=${r.inheritableCapabilities}\ncap_prm=${r.permittedCapabilities}\ncap_eff=${r.effectiveCapabilities}\ncap_amb=${r.ambientCapabilities}\nsecurebits=${r.secureBits}\nuserns_max=${r.userNamespaceMax}\ninitial_userns=1\nno_new_privs=1\n`;
}

function materializeEvidence(base: string, reproducerPath: string, observedKernelRelease?: string) {
  const sha = (bytes: string) => createHash("sha256").update(bytes).digest("hex");
  const reproducerSha256 = createHash("sha256").update(readFileSync(reproducerPath)).digest("hex");
  const bootResults = [1, 2].map((n) => {
    const receipt = runtimeReceipt(n, reproducerSha256, observedKernelRelease), receiptRaw = serializeReceipt(receipt), dmesg = "KASAN: uaf\n";
    const receiptPath = `${base}.${n}.receipt`, dmesgPath = `${base}.${n}`;
    writeFileSync(receiptPath, receiptRaw); writeFileSync(dmesgPath, dmesg);
    return { status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: dmesgPath, dmesgSha256: sha(dmesg), build_cache_hit: true, executionIdentity: { uid: 65534, gid: 65534 }, executionAttestation: receipt, executionAttestationPath: receiptPath, executionAttestationSha256: sha(receiptRaw) };
  });
  const first = bootResults[0].executionAttestation;
  const manifest = { schemaVersion: 2, expectedKernelRelease: first.expectedKernelRelease, observedKernelRelease: first.observedKernelRelease, kernelImageSha256: first.kernelImageSha256, kernelConfigSha256: first.kernelConfigSha256, executionIdentity: { uid: 65534, gid: 65534 }, boots: bootResults.map((boot, index) => ({ index: index + 1, bootId: boot.executionAttestation.bootId, receiptSha256: boot.executionAttestationSha256, receiptPath: boot.executionAttestationPath, dmesgSha256: boot.dmesgSha256, dmesgPath: boot.dmesg_path })) };
  const manifestRaw = JSON.stringify(manifest, null, 2) + "\n", manifestPath = `${base}.manifest`;
  writeFileSync(manifestPath, manifestRaw);
  return { bootResults, executionAttestationManifestPath: manifestPath, executionAttestationManifestSha256: sha(manifestRaw) };
}

describe("LinuxKernelResearchAdapter", () => {
  it("promotes only a stable repeated kernel signature", async () => {
    const { target, artifactRoot } = setup();
    const verifier = vi.fn(async (opts) => ({
      status: "reproduced" as const,
      signature: "kasan-uaf",
      dmesg_path: opts.dmesgOutPath!,
      build_cache_hit: true,
      bootHits: 2,
      bootTotal: 3,
      nbootStable: true,
      bootStatuses: ["reproduced", "no_signal", "reproduced"] as const,
      bootResults: [
        { status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: opts.dmesgOutPath!, build_cache_hit: true },
        { status: "no_signal" as const, dmesg_path: opts.dmesgOutPath!, build_cache_hit: true },
        { status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: opts.dmesgOutPath!, build_cache_hit: true },
      ],
    }));
    const emitted: Finding[] = [];
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, {
      artifactRoot,
      runId: "linux-run",
      emitFinding: async (finding) => { emitted.push(finding); },
    });

    expect(result.findings).toHaveLength(1);
    expect(result.envelopes).toHaveLength(1);
    expect(result.envelopes[0]).toMatchObject({ grade: "reproduced", novelty: { state: "unchecked" } });
    expect(result.envelopes[0]).toMatchObject({
      executionContext: { privilege: "privileged", basis: "runner-contract", realUid: 0, effectiveUid: 0 },
    });
    expect(researchZeroCapProven(result.envelopes[0]!)).toBe(false);
    expect(result.findings[0].finding.researchEvidence).toEqual(result.envelopes);
    expect(emitted[0]?.researchEvidence).toEqual(result.envelopes);
    expect(existsSync(result.envelopePath!)).toBe(true);
    expect(result.evidence.some((e) => e.stage === "verify" && e.status === "passed")).toBe(true);
    expect(verifier).toHaveBeenCalledWith(expect.objectContaining({ kernelTree: target.location, boots: 3, minHits: 2 }));
  });

  it("keeps an unstable no-signal run inconclusive", async () => {
    const { target, artifactRoot } = setup();
    const verifier = vi.fn(async (opts) => ({
      status: "no_signal" as const,
      dmesg_path: opts.dmesgOutPath!,
      build_cache_hit: false,
      bootHits: 0,
      bootTotal: 3,
      nbootStable: false,
      bootStatuses: ["no_signal", "no_signal"] as const,
      bootResults: [
        { status: "no_signal" as const, dmesg_path: opts.dmesgOutPath!, build_cache_hit: false },
        { status: "no_signal" as const, dmesg_path: opts.dmesgOutPath!, build_cache_hit: false },
      ],
    }));
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, { artifactRoot, runId: "linux-no" });

    expect(result.findings).toHaveLength(0);
    expect(result.evidence.some((e) => e.stage === "verify" && e.status === "inconclusive")).toBe(true);
  });

  it("promotes zero-cap context only when every reproduced boot is runtime-attested", async () => {
    const { target, artifactRoot } = setup();
    target.config.verify.executionIdentity = { uid: 65534, gid: 65534 };
    const verifier = vi.fn(async (opts) => ({
      status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: opts.dmesgOutPath!, build_cache_hit: true,
      bootHits: 2, bootTotal: 2, nbootStable: true, bootStatuses: ["reproduced", "reproduced"] as const,
      executionIdentity: { uid: 65534, gid: 65534 },
      ...materializeEvidence(opts.dmesgOutPath!, opts.reproducerPath!),
    }));
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, { artifactRoot, runId: "linux-zero-cap" });
    expect(result.envelopes[0]?.executionContext).toMatchObject({ privilege: "zero-cap", basis: "runtime-attested", realUid: 65534, effectiveCapabilities: "0000000000000000", noNewPrivileges: true });
    expect(researchZeroCapProven(result.envelopes[0]!)).toBe(true);
  });

  it("fails zero-cap closed for missing or substituted evidence artifacts", async () => {
    for (const tamper of ["missing-receipt", "substituted-dmesg", "forged-manifest", "symlink-receipt", "outside-receipt"] as const) {
      const { target, artifactRoot } = setup(); target.config.verify.executionIdentity = { uid: 65534, gid: 65534 };
      const verifier = vi.fn(async (opts) => {
        const evidence = materializeEvidence(opts.dmesgOutPath!, opts.reproducerPath!);
        if (tamper === "missing-receipt") unlinkSync(evidence.bootResults[0].executionAttestationPath);
        else if (tamper === "substituted-dmesg") writeFileSync(evidence.bootResults[0].dmesg_path, "substituted bytes\n");
        else if (tamper === "forged-manifest") writeFileSync(evidence.executionAttestationManifestPath, '{"schemaVersion":2,"boots":[]}\n');
        else if (tamper === "symlink-receipt") {
          unlinkSync(evidence.bootResults[0].executionAttestationPath);
          symlinkSync(evidence.bootResults[1].executionAttestationPath, evidence.bootResults[0].executionAttestationPath);
        } else {
          const outside = join(dirname(evidence.executionAttestationManifestPath), "..", "outside.receipt");
          writeFileSync(outside, readFileSync(evidence.bootResults[0].executionAttestationPath));
          evidence.bootResults[0].executionAttestationPath = outside;
          const manifest = JSON.parse(readFileSync(evidence.executionAttestationManifestPath, "utf8"));
          manifest.boots[0].receiptPath = outside;
          const raw = JSON.stringify(manifest, null, 2) + "\n";
          writeFileSync(evidence.executionAttestationManifestPath, raw);
          evidence.executionAttestationManifestSha256 = createHash("sha256").update(raw).digest("hex");
        }
        return { status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: opts.dmesgOutPath!, build_cache_hit: true, bootHits: 2, bootTotal: 2, nbootStable: true, bootStatuses: ["reproduced", "reproduced"] as const, executionIdentity: { uid: 65534, gid: 65534 }, ...evidence };
      });
      const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, { artifactRoot, runId: `linux-${tamper}` });
      expect(result.envelopes[0]?.executionContext).toEqual({ privilege: "privileged", basis: "runner-contract", realUid: 0, effectiveUid: 0 });
      expect(researchZeroCapProven(result.envelopes[0]!)).toBe(false);
    }
  });

  it("fails zero-cap closed for consistently mismatched runtime releases", async () => {
    const { target, artifactRoot } = setup(); target.config.verify.executionIdentity = { uid: 65534, gid: 65534 };
    const verifier = vi.fn(async (opts) => ({ status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: opts.dmesgOutPath!, build_cache_hit: true, bootHits: 2, bootTotal: 2, nbootStable: true, bootStatuses: ["reproduced", "reproduced"] as const, executionIdentity: { uid: 65534, gid: 65534 }, ...materializeEvidence(opts.dmesgOutPath!, opts.reproducerPath!, "6.12.93-0sec") }));
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, { artifactRoot, runId: "linux-release-mismatch" });
    expect(result.envelopes[0]?.executionContext).toMatchObject({ privilege: "privileged", basis: "runtime-attested" });
    expect(researchZeroCapProven(result.envelopes[0]!)).toBe(false);
  });

  it("downgrades instead of throwing when the reproducer disappears after execution", async () => {
    const { target, artifactRoot } = setup(); target.config.verify.executionIdentity = { uid: 65534, gid: 65534 };
    const verifier = vi.fn(async (opts) => {
      const evidence = materializeEvidence(opts.dmesgOutPath!, opts.reproducerPath!);
      unlinkSync(opts.reproducerPath!);
      return { status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: opts.dmesgOutPath!, build_cache_hit: true, bootHits: 2, bootTotal: 2, nbootStable: true, bootStatuses: ["reproduced", "reproduced"] as const, executionIdentity: { uid: 65534, gid: 65534 }, ...evidence };
    });
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, { artifactRoot, runId: "linux-missing-reproducer" });
    expect(result.envelopes[0]?.executionContext).toEqual({ privilege: "privileged", basis: "runner-contract", realUid: 0, effectiveUid: 0 });
    expect(researchZeroCapProven(result.envelopes[0]!)).toBe(false);
  });

  it("never promotes a non-root receipt without an explicit execution contract and all-boot manifest", async () => {
    const { target, artifactRoot } = setup();
    const verifier = vi.fn(async (opts) => ({
      status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: opts.dmesgOutPath!, build_cache_hit: true,
      bootHits: 2, bootTotal: 2, nbootStable: true, bootStatuses: ["reproduced", "reproduced"] as const,
      bootResults: [1, 2].map((n) => ({ status: "reproduced" as const, signature: "kasan-uaf", dmesg_path: `${opts.dmesgOutPath}.${n}`, dmesgSha256: String(n).repeat(64), build_cache_hit: true, executionAttestation: runtimeReceipt(n), executionAttestationPath: `${opts.dmesgOutPath}.${n}.receipt`, executionAttestationSha256: "c".repeat(64) })),
    }));
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, { artifactRoot, runId: "linux-forged-context" });
    expect(result.envelopes[0]?.executionContext).toEqual({ privilege: "privileged", basis: "runner-contract", realUid: 0, effectiveUid: 0 });
    expect(researchZeroCapProven(result.envelopes[0]!)).toBe(false);
  });

  it("fails discovery closed when the claimed signature is not bound", async () => {
    const { target, artifactRoot } = setup();
    delete target.config.verify.expectedSignature;
    const verifier = vi.fn();
    const result = await runResearch(new LinuxKernelResearchAdapter(verifier), target, { artifactRoot, runId: "linux-no-oracle" });
    expect(result.candidates).toHaveLength(0);
    expect(result.findings).toHaveLength(0);
    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ stage: "discover", status: "failed" }),
    ]));
    expect(verifier).not.toHaveBeenCalled();
  });
});
