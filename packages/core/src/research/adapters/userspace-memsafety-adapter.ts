import {
  runMemSafetyScan,
  type MemSafetyScanResult,
} from "../../stages/memsafety-scan.js";
import type { MemSafetyTarget } from "../../triage/memsafety-types.js";
import type { UserspaceFuzzOptions } from "../../triage/userspace-fuzz-runner.js";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchEvidence,
  ResearchFinding,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

type FuzzConfig = Omit<UserspaceFuzzOptions, "target" | "artifactDir" | "logger">;

export interface UserspaceMemSafetyTargetConfig {
  target: MemSafetyTarget;
  fuzz?: FuzzConfig;
}

export type UserspaceMemSafetyTarget = ResearchTarget<"userspace.memsafety", UserspaceMemSafetyTargetConfig>;
export type UserspaceCampaignCandidate = ResearchCandidate<{
  mode: "combined";
  target: MemSafetyTarget;
  fuzz?: FuzzConfig;
}>;
export interface UserspaceHarnessPlan {
  candidateId: string;
  target: MemSafetyTarget;
  fuzz?: FuzzConfig;
}
export interface UserspaceExecution {
  candidateId: string;
  result: MemSafetyScanResult;
}

type MemSafetyScan = typeof runMemSafetyScan;

export class UserspaceMemSafetyResearchAdapter
  implements TargetResearchAdapter<UserspaceMemSafetyTarget, UserspaceCampaignCandidate, UserspaceHarnessPlan, UserspaceExecution>
{
  readonly kind = "userspace.memsafety" as const;

  constructor(private readonly scan: MemSafetyScan = runMemSafetyScan) {}

  async discover(target: UserspaceMemSafetyTarget): Promise<ResearchStageResult<UserspaceCampaignCandidate>> {
    const memTarget = target.config.target;
    const fuzz = target.config.fuzz;
    const executable = memTarget.language === "rust"
      ? Boolean(memTarget.harnessEntry || fuzz?.runMiri)
      : Boolean(fuzz?.tier2Artifact);
    if (!executable) {
      return {
        items: [],
        evidence: [{
          stage: "discover",
          status: "inconclusive",
          summary: "no executable userspace harness or Miri plan is configured",
        }],
        warnings: ["userspace research skipped: configure a Rust harness/Miri or a C/C++ Tier-2 artifact"],
      };
    }
    const id = `${target.id}:campaign`;
    return {
      items: [{
        id,
        title: `Memory-safety campaign for ${memTarget.sourceRoot}`,
        location: memTarget.sourceRoot,
        hypothesis: "sanitizer-backed fuzzing may expose a memory-safety violation",
        payload: { mode: "combined", target: memTarget, ...(fuzz ? { fuzz } : {}) },
      }],
      evidence: [{ stage: "discover", status: "passed", summary: "planned one executable userspace memory-safety campaign" }],
    };
  }

  async buildHarness(
    _target: UserspaceMemSafetyTarget,
    candidates: UserspaceCampaignCandidate[],
  ): Promise<ResearchStageResult<UserspaceHarnessPlan>> {
    const items = candidates.map((candidate) => ({
      candidateId: candidate.id,
      target: candidate.payload.target,
      ...(candidate.payload.fuzz ? { fuzz: candidate.payload.fuzz } : {}),
    }));
    return {
      items,
      evidence: [{
        stage: "harness",
        status: items.length > 0 ? "passed" : "skipped",
        summary: items.length > 0 ? `prepared ${items.length} native fuzz harness plan(s)` : "no campaign candidate to build",
      }],
    };
  }

  async execute(
    _target: UserspaceMemSafetyTarget,
    harnesses: UserspaceHarnessPlan[],
    ctx: ResearchContext,
  ): Promise<ResearchStageResult<UserspaceExecution>> {
    if (harnesses.length === 0) {
      return { items: [], evidence: [{ stage: "execute", status: "skipped", summary: "no harness plan to execute" }] };
    }
    if (ctx.signal?.aborted) {
      return { items: [], evidence: [{ stage: "execute", status: "skipped", summary: "research run was aborted before execution" }] };
    }
    const items: UserspaceExecution[] = [];
    const evidence: ResearchEvidence[] = [];
    const warnings: string[] = [];
    for (const harness of harnesses) {
      const result = await this.scan({
        target: harness.target,
        fuzz: { ...harness.fuzz, artifactDir: ctx.artifactDir },
        logger: ctx.log,
      });
      items.push({ candidateId: harness.candidateId, result });
      const ran = result.loop.iterations > 0;
      evidence.push({
        stage: "execute" as const,
        status: ran ? "passed" as const : "inconclusive" as const,
        summary: ran
          ? `completed ${result.loop.iterations} fuzz iteration(s), observed ${result.loop.crashes.length} unique crash(es)`
          : "userspace campaign produced no executable iterations",
        data: result,
      });
      warnings.push(...result.warnings);
      if (result.toolingMissing.length > 0) warnings.push(`missing tooling: ${result.toolingMissing.join(", ")}`);
    }
    return { items, evidence, warnings };
  }

  async verify(
    _target: UserspaceMemSafetyTarget,
    input: { candidates: UserspaceCampaignCandidate[]; executions?: UserspaceExecution[] },
  ): Promise<ResearchStageResult<ResearchFinding>> {
    const items: ResearchFinding[] = [];
    const evidence: ResearchEvidence[] = [];
    for (const execution of input.executions ?? []) {
      let confirmed = 0;
      for (const detail of execution.result.details) {
        const passed = detail.verdict.verdict === "confirmed";
        evidence.push({
          stage: "verify" as const,
          status: passed ? "passed" as const : "inconclusive" as const,
          summary: detail.verdict.reasoning,
          data: detail,
          ...(detail.crash.inputPath ? { artifacts: [detail.crash.inputPath] } : {}),
        });
        if (!passed) continue;
        confirmed++;
        items.push({
          finding: detail.finding,
          candidateId: execution.candidateId,
          grade: "observed",
          evidence: [{
            stage: "verify",
            status: "passed",
            summary: detail.verdict.reasoning,
            data: { crash: detail.crash, exploitability: detail.exploitability, verdict: detail.verdict },
            ...(detail.crash.inputPath ? { artifacts: [detail.crash.inputPath] } : {}),
          }],
        });
      }
      if (execution.result.details.length === 0) {
        evidence.push({
          stage: "verify",
          status: "inconclusive",
          summary: execution.result.loop.iterations > 0
            ? "no crash observed during the bounded campaign; absence is not proven"
            : "no executable iterations; verification did not run",
          data: { confirmed },
        });
      }
    }
    return { items, evidence };
  }
}
