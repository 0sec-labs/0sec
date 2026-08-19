import {
  runPipeline,
  type PipelineOptions,
  type PipelineReport,
} from "../../unified-pipeline.js";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchFinding,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

export interface UnifiedPipelineTargetConfig { options: Omit<PipelineOptions, "target"> }
export type UnifiedPipelineTarget = ResearchTarget<"pipeline.unified", UnifiedPipelineTargetConfig>;
export type UnifiedPipelineCandidate = ResearchCandidate<PipelineReport["findings"][number]>;
type PipelineRunner = typeof runPipeline;

/** Compatibility adapter covering the existing web/AI/source/package/on-chain pipeline. */
export class UnifiedPipelineResearchAdapter
  implements TargetResearchAdapter<UnifiedPipelineTarget, UnifiedPipelineCandidate, never, never>
{
  readonly kind = "pipeline.unified" as const;
  private readonly reports = new Map<string, Promise<PipelineReport>>();
  constructor(private readonly pipeline: PipelineRunner = runPipeline) {}

  private report(target: UnifiedPipelineTarget, ctx: ResearchContext): Promise<PipelineReport> {
    let report = this.reports.get(ctx.runId);
    if (!report) {
      report = this.pipeline({ ...target.config.options, target: target.location });
      this.reports.set(ctx.runId, report);
    }
    return report;
  }

  async discover(target: UnifiedPipelineTarget, ctx: ResearchContext): Promise<ResearchStageResult<UnifiedPipelineCandidate>> {
    const report = await this.report(target, ctx);
    return {
      items: report.findings.map((finding, index) => ({
        id: `${finding.id}:${index}`,
        title: finding.title,
        location: target.location,
        hypothesis: finding.description,
        payload: finding,
      })),
      evidence: [{
        stage: "discover",
        status: "passed",
        summary: `unified pipeline completed with ${report.findings.length} retained finding(s) and ${report.warnings.length} warning(s)`,
        data: report,
        startedAt: report.startedAt,
        completedAt: report.completedAt,
      }],
      warnings: report.warnings.map((warning) => `${warning.stage}: ${warning.message}`),
    };
  }

  async verify(
    _target: UnifiedPipelineTarget,
    input: { candidates: UnifiedPipelineCandidate[] },
  ): Promise<ResearchStageResult<ResearchFinding>> {
    return {
      items: input.candidates.map((candidate) => {
        const passed = candidate.payload.status !== "discovered"
          && candidate.payload.status !== "false-positive"
          && candidate.payload.publishability !== "needs_verify";
        return {
          finding: candidate.payload,
          candidateId: candidate.id,
          grade: passed ? "observed" : "candidate",
          evidence: [{
          stage: "verify",
          status: passed ? "passed" : "inconclusive",
          summary: passed
            ? "finding was retained with a verified native pipeline status"
            : "native pipeline retained the finding for review without conclusive verification",
          data: candidate.payload,
          }],
        };
      }),
      evidence: input.candidates.map((candidate) => ({
        stage: "verify",
        status: candidate.payload.status !== "discovered"
          && candidate.payload.status !== "false-positive"
          && candidate.payload.publishability !== "needs_verify" ? "passed" : "inconclusive",
        summary: `native unified pipeline retained ${candidate.payload.id}; status=${candidate.payload.status}`,
        data: candidate.payload,
      })),
    };
  }

  async dispose(ctx: ResearchContext): Promise<void> {
    this.reports.delete(ctx.runId);
  }
}
