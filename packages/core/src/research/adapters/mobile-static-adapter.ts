import {
  runMobileStaticIntake,
  type MobileEndpointIndicator,
  type MobileRiskIndicator,
  type MobileStaticIntakeOptions,
  type MobileStaticIntakeReport,
} from "../../mobile/intake.js";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchHandoff,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

export interface MobileStaticTargetConfig {
  options?: MobileStaticIntakeOptions;
}
export type MobileStaticTarget = ResearchTarget<"mobile.static-intake", MobileStaticTargetConfig>;
export type MobileStaticCandidate = ResearchCandidate<
  | { type: "backend"; indicator: MobileEndpointIndicator }
  | { type: "passive-risk"; indicator: MobileRiskIndicator }
>;
type MobileIntake = typeof runMobileStaticIntake;

export class MobileStaticResearchAdapter
  implements TargetResearchAdapter<MobileStaticTarget, MobileStaticCandidate, never, never>
{
  readonly kind = "mobile.static-intake" as const;
  private readonly reports = new Map<string, MobileStaticIntakeReport>();

  constructor(private readonly intake: MobileIntake = runMobileStaticIntake) {}

  async discover(target: MobileStaticTarget, ctx: ResearchContext): Promise<ResearchStageResult<MobileStaticCandidate>> {
    const report = this.intake(target.location, target.config.options);
    this.reports.set(ctx.runId, report);
    const backends: MobileStaticCandidate[] = report.backendCandidates.map((indicator, index) => ({
      id: `${target.id}:backend:${index}`,
      title: `Mobile backend candidate: ${indicator.value}`,
      location: indicator.value,
      hypothesis: "mobile application references a backend worth scoped downstream testing",
      payload: { type: "backend", indicator },
    }));
    const risks: MobileStaticCandidate[] = report.risks.map((indicator, index) => ({
      id: `${target.id}:risk:${index}`,
      title: indicator.title,
      hypothesis: "passive mobile risk indicator; dynamic verification required",
      payload: { type: "passive-risk", indicator },
    }));
    return {
      items: [...backends, ...risks],
      evidence: [{
        stage: "discover",
        status: report.platform === "unknown" && backends.length + risks.length === 0 ? "inconclusive" : "passed",
        summary: `mobile intake identified ${backends.length} backend target(s) and ${risks.length} passive risk indicator(s)`,
        data: report,
      }],
      warnings: report.warnings,
    };
  }

  async deriveTargets(
    _target: MobileStaticTarget,
    candidates: MobileStaticCandidate[],
  ): Promise<ResearchStageResult<ResearchHandoff>> {
    const items: ResearchHandoff[] = candidates.flatMap((candidate) => {
      if (candidate.payload.type !== "backend" || candidate.payload.indicator.scope?.allowed !== true) return [];
      const indicator = candidate.payload.indicator;
      const scopeReason = indicator.scope!.reason;
      const location = indicator.kind === "url" ? indicator.value : `https://${indicator.value}`;
      return [{
        sourceCandidateId: candidate.id,
        target: { kind: "web.http", id: `mobile-backend:${candidate.id}`, location, config: { source: "mobile-static-intake" } },
        reason: `in-scope backend extracted from mobile application (${scopeReason})`,
        evidence: [{ stage: "handoff", status: "passed", summary: `authorized downstream target: ${location}`, data: indicator }],
      }];
    });
    return {
      items,
      evidence: [{
        stage: "handoff",
        status: items.length > 0 ? "passed" : "inconclusive",
        summary: items.length > 0
          ? `derived ${items.length} authorized downstream web target(s)`
          : "no explicitly in-scope backend target was available for handoff",
      }],
    };
  }

  async verify(): Promise<ResearchStageResult<never>> {
    return {
      items: [],
      evidence: [{
        stage: "verify",
        status: "inconclusive",
        summary: "mobile static indicators are intake hypotheses and cannot be promoted without dynamic verification",
      }],
    };
  }

  async dispose(ctx: ResearchContext): Promise<void> {
    this.reports.delete(ctx.runId);
  }
}
