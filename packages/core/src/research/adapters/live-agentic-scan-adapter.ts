import { agenticScan, type AgenticScanOptions } from "../../agentic-scanner.js";
import type { ScanReport } from "@0sec/shared";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchFinding,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

export interface LiveAgenticScanTargetConfig { options: AgenticScanOptions }
export type LiveAgenticScanTarget = ResearchTarget<"live.agentic-scan", LiveAgenticScanTargetConfig>;
export type LiveAgenticScanCandidate = ResearchCandidate<ScanReport["findings"][number]>;
type AgenticScanner = typeof agenticScan;

/**
 * Compatibility adapter for the live-target agentic scanner (`agenticScan`),
 * the last major entrypoint that bypassed the research registry spine (#1283).
 * It mirrors {@link UnifiedPipelineResearchAdapter}: the native scan runs
 * exactly once per research run, and its findings pass through the shared
 * verify/grade lifecycle without altering the underlying `agenticScan`
 * behavior. `target.location` is the authoritative scan target, so it overrides
 * `config.target` on the wrapped options.
 */
export class LiveAgenticScanResearchAdapter
  implements TargetResearchAdapter<LiveAgenticScanTarget, LiveAgenticScanCandidate, never, never>
{
  readonly kind = "live.agentic-scan" as const;
  private readonly reports = new Map<string, Promise<ScanReport>>();
  constructor(private readonly scan: AgenticScanner = agenticScan) {}

  private report(target: LiveAgenticScanTarget, ctx: ResearchContext): Promise<ScanReport> {
    let report = this.reports.get(ctx.runId);
    if (!report) {
      const { options } = target.config;
      report = this.scan({
        ...options,
        config: { ...options.config, target: target.location },
      });
      this.reports.set(ctx.runId, report);
    }
    return report;
  }

  async discover(target: LiveAgenticScanTarget, ctx: ResearchContext): Promise<ResearchStageResult<LiveAgenticScanCandidate>> {
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
        summary:
          `agentic scan completed with ${report.findings.length} finding(s) and ${report.warnings.length} warning(s)`,
        data: report,
        startedAt: report.startedAt,
        completedAt: report.completedAt,
      }],
      warnings: report.warnings.map((warning) => `${warning.stage}: ${warning.message}`),
    };
  }

  async verify(
    _target: LiveAgenticScanTarget,
    input: { candidates: LiveAgenticScanCandidate[] },
  ): Promise<ResearchStageResult<ResearchFinding>> {
    const isVerified = (finding: ScanReport["findings"][number]): boolean =>
      finding.status !== "discovered"
      && finding.status !== "false-positive"
      && finding.publishability !== "needs_verify";
    return {
      items: input.candidates.map((candidate) => {
        const passed = isVerified(candidate.payload);
        return {
          finding: candidate.payload,
          candidateId: candidate.id,
          grade: passed ? "observed" : "candidate",
          evidence: [{
            stage: "verify",
            status: passed ? "passed" : "inconclusive",
            summary: passed
              ? "finding was retained with a verified agentic-scan status"
              : "agentic scan retained the finding for review without conclusive verification",
            data: candidate.payload,
          }],
        };
      }),
      evidence: input.candidates.map((candidate) => ({
        stage: "verify",
        status: isVerified(candidate.payload) ? "passed" : "inconclusive",
        summary: `native agentic scan retained ${candidate.payload.id}; status=${candidate.payload.status}`,
        data: candidate.payload,
      })),
    };
  }

  async dispose(ctx: ResearchContext): Promise<void> {
    this.reports.delete(ctx.runId);
  }
}
