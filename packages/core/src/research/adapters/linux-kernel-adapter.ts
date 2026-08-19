import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { Finding } from "@0sec/shared";
import type { ResearchExecutionContext } from "@0sec/shared";
import {
  verifyAcrossBoots,
  parseKernelExecutionAttestation,
  type KernelFindingNbootVerification,
  type VerifyAcrossBootsOptions,
} from "../../triage/kernel-vm-runner.js";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchEvidence,
  ResearchFinding,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

type KernelVerifyConfig = Omit<VerifyAcrossBootsOptions, "kernelTree" | "logger" | "dmesgOutPath">;

export interface LinuxKernelTargetConfig {
  finding: Finding;
  verify: KernelVerifyConfig;
}
export type LinuxKernelTarget = ResearchTarget<"linux.kernel-reproducer", LinuxKernelTargetConfig>;
export type LinuxKernelCandidate = ResearchCandidate<{ finding: Finding; verify: KernelVerifyConfig }>;
export interface LinuxKernelHarness { candidateId: string; options: VerifyAcrossBootsOptions }
export interface LinuxKernelExecution { candidateId: string; result: KernelFindingNbootVerification }
type KernelVerifier = typeof verifyAcrossBoots;

function resultArtifacts(result: KernelFindingNbootVerification): string[] {
  return [...new Set([
    ...(result.bootResults.length > 0 ? result.bootResults : [result]).flatMap((boot) => [boot.dmesg_path, boot.executionAttestationPath].filter((path): path is string => Boolean(path))),
    ...(result.executionAttestationManifestPath ? [result.executionAttestationManifestPath] : []),
  ])];
}

function executionContext(result: KernelFindingNbootVerification, reproducerPath?: string): ResearchExecutionContext {
  const reproduced = result.bootResults.filter((boot) => boot.status === "reproduced");
  const receipts = reproduced.map((boot) => boot.executionAttestation).filter((receipt): receipt is NonNullable<typeof receipt> => Boolean(receipt));
  if (receipts.length !== reproduced.length || receipts.length === 0 || !reproducerPath || !result.executionIdentity || !result.executionAttestationManifestPath || !result.executionAttestationManifestSha256 || reproduced.some((boot) => !boot.executionAttestationPath || !boot.executionAttestationSha256 || !boot.dmesgSha256 || boot.executionIdentity?.uid !== result.executionIdentity?.uid || boot.executionIdentity?.gid !== result.executionIdentity?.gid)) return { privilege: "privileged", basis: "runner-contract", realUid: 0, effectiveUid: 0 };
  let validatedReceipts: typeof receipts;
  try {
    const manifestPath = resolve(result.executionAttestationManifestPath);
    const manifestStat = lstatSync(manifestPath);
    if (!manifestStat.isFile() || manifestStat.isSymbolicLink()) throw new Error("manifest must be a regular non-symlink file");
    const artifactDir = dirname(manifestPath);
    const readArtifact = (path: string, encoding?: BufferEncoding): string | Buffer => {
      const resolved = resolve(path);
      if (dirname(resolved) !== artifactDir) throw new Error("evidence path escapes run artifact directory");
      const stat = lstatSync(resolved);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("evidence must be a regular non-symlink file");
      return encoding ? readFileSync(resolved, encoding) : readFileSync(resolved);
    };
    const manifestRaw = readFileSync(manifestPath, "utf8");
    if (createHash("sha256").update(manifestRaw).digest("hex") !== result.executionAttestationManifestSha256) throw new Error("manifest hash mismatch");
    const manifest = JSON.parse(manifestRaw) as Record<string, unknown>;
    const exactKeys = (value: object, keys: string[]) => JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort());
    if (!exactKeys(manifest, ["schemaVersion", "expectedKernelRelease", "observedKernelRelease", "kernelImageSha256", "kernelConfigSha256", "executionIdentity", "boots"]) || manifest.schemaVersion !== 2 || !Array.isArray(manifest.boots) || manifest.boots.length !== reproduced.length || typeof manifest.executionIdentity !== "object" || manifest.executionIdentity === null || !exactKeys(manifest.executionIdentity, ["uid", "gid"])) throw new Error("invalid manifest shape");
    const identity = manifest.executionIdentity as Record<string, unknown>;
    if (identity.uid !== result.executionIdentity.uid || identity.gid !== result.executionIdentity.gid) throw new Error("manifest identity mismatch");
    const manifestBoots = manifest.boots as unknown[];
    validatedReceipts = reproduced.map((boot, index) => {
      const entry = manifestBoots[index] as Record<string, unknown>;
      if (!entry || !exactKeys(entry, ["index", "bootId", "receiptSha256", "receiptPath", "dmesgSha256", "dmesgPath"]) || entry.index !== index + 1 || entry.receiptPath !== boot.executionAttestationPath || entry.receiptSha256 !== boot.executionAttestationSha256 || entry.dmesgPath !== boot.dmesg_path || entry.dmesgSha256 !== boot.dmesgSha256) throw new Error("manifest boot entry mismatch");
      const receiptRaw = readArtifact(boot.executionAttestationPath!, "utf8") as string;
      if (createHash("sha256").update(receiptRaw).digest("hex") !== boot.executionAttestationSha256) throw new Error("receipt hash mismatch");
      const parsed = parseKernelExecutionAttestation(receiptRaw);
      if (JSON.stringify(parsed) !== JSON.stringify(boot.executionAttestation) || entry.bootId !== parsed.bootId) throw new Error("receipt object mismatch");
      const dmesgRaw = readArtifact(boot.dmesg_path) as Buffer;
      if (createHash("sha256").update(dmesgRaw).digest("hex") !== boot.dmesgSha256) throw new Error("dmesg hash mismatch");
      return parsed;
    });
    if (manifestRaw !== JSON.stringify(manifest, null, 2) + "\n") throw new Error("noncanonical manifest");
    const first = validatedReceipts[0]!;
    if (manifest.expectedKernelRelease !== first.expectedKernelRelease || manifest.observedKernelRelease !== first.observedKernelRelease || manifest.kernelImageSha256 !== first.kernelImageSha256 || manifest.kernelConfigSha256 !== first.kernelConfigSha256) throw new Error("manifest provenance mismatch");
  } catch {
    return { privilege: "privileged", basis: "runner-contract", realUid: 0, effectiveUid: 0 };
  }
  const first = validatedReceipts[0]!;
  const bootIds = new Set(validatedReceipts.map((receipt) => receipt.bootId));
  const nonces = new Set(validatedReceipts.map((receipt) => receipt.nonce));
  let reproducerSha256: string;
  try {
    reproducerSha256 = createHash("sha256").update(readFileSync(reproducerPath)).digest("hex");
  } catch {
    return { privilege: "privileged", basis: "runner-contract", realUid: 0, effectiveUid: 0 };
  }
  const zeroCap = validatedReceipts.every((receipt) => receipt.schemaVersion === 2 && receipt.reproducerSha256 === reproducerSha256 && receipt.expectedKernelRelease === receipt.observedKernelRelease && receipt.realUid === result.executionIdentity!.uid && receipt.effectiveUid === result.executionIdentity!.uid && receipt.savedUid === result.executionIdentity!.uid && receipt.realGid === result.executionIdentity!.gid && receipt.effectiveGid === result.executionIdentity!.gid && receipt.savedGid === result.executionIdentity!.gid && receipt.supplementaryGroups.length === 0 && [receipt.inheritableCapabilities, receipt.permittedCapabilities, receipt.effectiveCapabilities, receipt.ambientCapabilities].every((cap) => cap === "0000000000000000") && receipt.noNewPrivileges && receipt.userNamespaceMax === 0 && receipt.initialUserNamespace && receipt.expectedKernelRelease === first.expectedKernelRelease && receipt.observedKernelRelease === first.observedKernelRelease && receipt.kernelImageSha256 === first.kernelImageSha256 && receipt.kernelConfigSha256 === first.kernelConfigSha256) && bootIds.size === validatedReceipts.length && nonces.size === validatedReceipts.length;
  return {
    privilege: zeroCap ? "zero-cap" : "privileged",
    basis: "runtime-attested",
    realUid: first.realUid,
    effectiveUid: first.effectiveUid,
    effectiveCapabilities: first.effectiveCapabilities,
    noNewPrivileges: first.noNewPrivileges,
    attestationArtifact: { ref: result.executionAttestationManifestPath, sha256: result.executionAttestationManifestSha256 },
  };
}

export class LinuxKernelResearchAdapter
  implements TargetResearchAdapter<LinuxKernelTarget, LinuxKernelCandidate, LinuxKernelHarness, LinuxKernelExecution>
{
  readonly kind = "linux.kernel-reproducer" as const;
  constructor(private readonly verifier: KernelVerifier = verifyAcrossBoots) {}

  async discover(target: LinuxKernelTarget): Promise<ResearchStageResult<LinuxKernelCandidate>> {
    const { syzProgramPath, reproducerPath } = target.config.verify;
    if (!target.config.verify.expectedSignature?.trim()) {
      return {
        items: [],
        evidence: [{ stage: "discover", status: "failed", summary: "an expected kernel crash signature is required" }],
        warnings: ["linux kernel research requires expectedSignature to prevent unrelated-crash promotion"],
      };
    }
    const paths = [syzProgramPath, reproducerPath].filter((path): path is string => Boolean(path));
    if (paths.length !== 1) {
      return {
        items: [],
        evidence: [{ stage: "discover", status: "failed", summary: "exactly one syzkaller program or C reproducer is required" }],
        warnings: ["linux kernel research requires exactly one of syzProgramPath or reproducerPath"],
      };
    }
    const missing = [target.location, paths[0]].filter((path) => !existsSync(path));
    if (missing.length > 0) {
      return {
        items: [],
        evidence: [{ stage: "discover", status: "failed", summary: `missing kernel research input(s): ${missing.join(", ")}` }],
        warnings: missing.map((path) => `missing required path: ${path}`),
      };
    }
    return {
      items: [{
        id: `${target.id}:reproducer`,
        title: target.config.finding.title,
        location: paths[0],
        hypothesis: "the supplied reproducer triggers the claimed kernel fault on this exact kernel target",
        payload: { finding: target.config.finding, verify: target.config.verify },
      }],
      evidence: [{ stage: "discover", status: "passed", summary: `validated kernel tree and reproducer inputs (${paths[0]})` }],
    };
  }

  async buildHarness(
    target: LinuxKernelTarget,
    candidates: LinuxKernelCandidate[],
    ctx: ResearchContext,
  ): Promise<ResearchStageResult<LinuxKernelHarness>> {
    const items = candidates.map((candidate) => ({
      candidateId: candidate.id,
      options: {
        ...candidate.payload.verify,
        kernelTree: target.location,
        logger: ctx.log,
        dmesgOutPath: join(ctx.artifactDir, `${candidate.id.replace(/[^a-z0-9_.-]/gi, "-")}.dmesg`),
      },
    }));
    return {
      items,
      evidence: [{ stage: "harness", status: items.length > 0 ? "passed" : "skipped", summary: `prepared ${items.length} N-boot kernel verification plan(s)` }],
    };
  }

  async execute(
    _target: LinuxKernelTarget,
    harnesses: LinuxKernelHarness[],
  ): Promise<ResearchStageResult<LinuxKernelExecution>> {
    const items: LinuxKernelExecution[] = [];
    const evidence: ResearchEvidence[] = [];
    const warnings: string[] = [];
    for (const harness of harnesses) {
      const result = await this.verifier(harness.options);
      items.push({ candidateId: harness.candidateId, result });
      const stable = result.status === "reproduced" && result.nbootStable;
      evidence.push({
        stage: "execute",
        status: stable ? "passed" : "inconclusive",
        summary: stable
          ? `kernel signature reproduced in ${result.bootHits}/${result.bootTotal} fresh boot(s)`
          : `kernel verification ended ${result.status}; hits=${result.bootHits}/${result.bootTotal}`,
        data: result,
        artifacts: resultArtifacts(result),
      });
      if (result.status === "build_failed" || result.status === "run_failed") warnings.push(`kernel verifier ${result.status}`);
    }
    return { items, evidence, warnings };
  }

  async verify(
    _target: LinuxKernelTarget,
    input: { candidates: LinuxKernelCandidate[]; executions?: LinuxKernelExecution[] },
  ): Promise<ResearchStageResult<ResearchFinding>> {
    const items: ResearchFinding[] = [];
    const evidence: ResearchEvidence[] = [];
    for (const execution of input.executions ?? []) {
      const candidate = input.candidates.find((item) => item.id === execution.candidateId);
      const stable = execution.result.status === "reproduced" && execution.result.nbootStable;
      evidence.push({
        stage: "verify",
        status: stable ? "passed" : "inconclusive",
        summary: stable
          ? `N-boot gate passed (${execution.result.bootHits}/${execution.result.bootTotal})`
          : "N-boot reproduction threshold was not met; absence is not proven",
        data: execution.result,
        artifacts: resultArtifacts(execution.result),
      });
      if (!stable || !candidate) continue;
      items.push({
        finding: candidate.payload.finding,
        candidateId: candidate.id,
        grade: "reproduced",
        executionContext: executionContext(execution.result, candidate.payload.verify.syzProgramPath ?? candidate.payload.verify.reproducerPath),
        evidence: [{
          stage: "verify",
          status: "passed",
          summary: `stable kernel signature ${execution.result.signature ?? "unknown"} across fresh boots`,
          data: execution.result,
          artifacts: resultArtifacts(execution.result),
        }],
      });
    }
    return { items, evidence };
  }
}
