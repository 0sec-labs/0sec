import {
  runHuntScan,
  type HuntFindingRecord,
  type HuntScanOptions,
  type HuntScanResult,
} from "../../stages/hunt-scan.js";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchEvidence,
  ResearchFinding,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

export interface HuntResearchTargetConfig {
  options: HuntScanOptions;
}

export type HuntResearchTarget = ResearchTarget<"hunt.agentic", HuntResearchTargetConfig>;
export type HuntRecordCandidate = ResearchCandidate<HuntFindingRecord>;
type HuntScan = typeof runHuntScan;

function candidateId(record: HuntFindingRecord, index: number): string {
  return `${record.finding.id}:${index}`;
}

/** Lossless compatibility adapter: the native hunt runs exactly once per research run. */
export class HuntResearchAdapter
  implements TargetResearchAdapter<HuntResearchTarget, HuntRecordCandidate, never, never>
{
  readonly kind = "hunt.agentic" as const;
  private readonly runs = new Map<string, Promise<HuntScanResult>>();

  constructor(private readonly scan: HuntScan = runHuntScan) {}

  private result(target: HuntResearchTarget, ctx: ResearchContext): Promise<HuntScanResult> {
    let result = this.runs.get(ctx.runId);
    if (!result) {
      result = this.scan({ ...target.config.options, log: target.config.options.log ?? ctx.log });
      this.runs.set(ctx.runId, result);
    }
    return result;
  }

  async discover(target: HuntResearchTarget, ctx: ResearchContext): Promise<ResearchStageResult<HuntRecordCandidate>> {
    const result = await this.result(target, ctx);
    const items = result.records.map((record, index) => ({
      id: candidateId(record, index),
      title: record.finding.title,
      location: record.candidatePath,
      hypothesis: record.finding.evidence.analysis,
      payload: record,
    }));
    return {
      items,
      evidence: [{
        stage: "discover",
        status: result.finderCompleted > 0 ? "passed" : "inconclusive",
        summary:
          `${result.finderCompleted}/${result.scanned} finder runs completed; ` +
          `${result.finderTimedOut} timed out; ${result.finderErrored} errored; ${result.records.length} finding record(s)`,
        data: {
          scanned: result.scanned,
          finderCompleted: result.finderCompleted,
          finderTimedOut: result.finderTimedOut,
          finderErrored: result.finderErrored,
          records: result.records,
        },
      }],
      warnings: [...result.warnings],
    };
  }

  async verify(
    target: HuntResearchTarget,
    input: { candidates: HuntRecordCandidate[] },
    ctx: ResearchContext,
  ): Promise<ResearchStageResult<ResearchFinding>> {
    const result = await this.result(target, ctx);
    const preNovel = [...result.confirmed, ...result.duplicates.map((entry) => entry.finding)];
    const items = preNovel.map((finding) => {
      const candidate = input.candidates.find((item) => item.payload.finding === finding)
        ?? input.candidates.find((item) => item.payload.finding.id === finding.id);
      return {
        finding,
        candidateId: candidate?.id ?? `unknown:${finding.id}`,
        grade: "observed" as const,
        evidence: [{
          stage: "verify" as const,
          status: "passed" as const,
          summary: candidate?.payload.skepticReason ?? "native hunt verifier confirmed the finding",
          data: candidate?.payload,
        }],
      };
    });
    const evidence: ResearchEvidence[] = input.candidates.map((candidate) => ({
      stage: "verify",
      status: candidate.payload.skepticConfirmed === true
        ? "passed"
        : candidate.payload.skepticConfirmed === false
          ? "failed"
          : "inconclusive",
      summary: candidate.payload.skepticReason
        ?? (candidate.payload.skepticConfirmed === undefined
          ? "finding was not selected for verification or verification produced no verdict"
          : "native hunt verifier returned no reason"),
      data: candidate.payload,
    }));
    return { items, evidence };
  }

  async checkNovelty(
    target: HuntResearchTarget,
    findings: ResearchFinding[],
    ctx: ResearchContext,
  ): Promise<ResearchStageResult<ResearchFinding>> {
    const result = await this.result(target, ctx);
    const survivors = new Set(result.confirmed);
    const duplicateByFinding = new Map(result.duplicates.map((entry) => [entry.finding, entry.novelty]));
    const items = findings.filter((item) => survivors.has(item.finding));
    const evidence: ResearchEvidence[] = findings.map((item) => {
      const duplicate = duplicateByFinding.get(item.finding);
      if (duplicate) {
        return {
          stage: "novelty",
          status: "failed",
          summary: `native hunt novelty gate matched ${duplicate.duplicates.length} upstream duplicate(s)`,
          data: duplicate,
        };
      }
      return {
        stage: "novelty",
        status: survivors.has(item.finding) ? "passed" : "inconclusive",
        summary: survivors.has(item.finding)
          ? "finding survived the configured native novelty gate"
          : "native hunt did not provide a conclusive novelty disposition",
      };
    });
    return { items, evidence };
  }

  async dispose(ctx: ResearchContext): Promise<void> {
    this.runs.delete(ctx.runId);
  }
}
