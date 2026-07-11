import { existsSync } from "node:fs";
import { join } from "node:path";
import type { Finding } from "@pwnkit/shared";
import {
  verifyAcrossBoots,
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
  return [...new Set((result.bootResults.length > 0 ? result.bootResults : [result]).map((boot) => boot.dmesg_path))];
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
