import type { NativeRuntime } from "../../runtime/types.js";
import {
  runHttpConformanceCheck,
  type ConformanceAttempt,
  type HttpConformanceOptions,
  type HttpConformanceResult,
  type HttpSender,
} from "../../protocol/http-conformance.js";
import type {
  ResearchCandidate,
  ResearchFinding,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

export interface ProtocolHttpTargetConfig {
  specExcerpt: string;
  implExcerpt: string;
  llm: NativeRuntime;
  send: HttpSender;
  protocol: { name: string; version: string; specRef: string };
  options?: HttpConformanceOptions;
}

export type ProtocolHttpTarget = ResearchTarget<"protocol.http-conformance", ProtocolHttpTargetConfig>;
export type ProtocolHttpCandidate = ResearchCandidate<ConformanceAttempt>;

/** Compatibility adapter over the existing monolithic HTTP conformance pass. */
export class ProtocolHttpResearchAdapter
  implements TargetResearchAdapter<ProtocolHttpTarget, ProtocolHttpCandidate, never, never>
{
  readonly kind = "protocol.http-conformance" as const;
  private result?: HttpConformanceResult;

  async discover(target: ProtocolHttpTarget): Promise<ResearchStageResult<ProtocolHttpCandidate>> {
    this.result = await runHttpConformanceCheck(
      target.config.specExcerpt,
      target.config.implExcerpt,
      target.location,
      target.config.llm,
      target.config.send,
      target.config.protocol,
      target.config.options,
    );
    const items = this.result.attempts.map((attempt, index) => ({
      id: `${attempt.hypothesis.ruleId}:${index}`,
      title: `${target.config.protocol.name} divergence candidate: ${attempt.hypothesis.ruleId}`,
      location: attempt.hypothesis.implLocation,
      hypothesis: attempt.hypothesis.rationale,
      payload: attempt,
    }));
    return {
      items,
      evidence: [{
        stage: "discover",
        status: this.result.ok ? "passed" : "failed",
        summary: this.result.ok
          ? `generated and exercised ${items.length} protocol divergence candidate(s)`
          : this.result.reason ?? "protocol conformance generation failed",
        data: { genIterations: this.result.genIterations, attempts: this.result.attempts },
      }],
      warnings: this.result.ok ? [] : [this.result.reason ?? "protocol conformance generation failed"],
    };
  }

  async verify(
    _target: ProtocolHttpTarget,
    input: { candidates: ProtocolHttpCandidate[] },
  ): Promise<ResearchStageResult<ResearchFinding>> {
    if (!this.result) throw new Error("protocol adapter verify called before discover");
    const byRule = new Map(input.candidates.map((candidate) => [candidate.payload.hypothesis.ruleId, candidate]));
    const items: ResearchFinding[] = this.result.findings.map((finding) => {
      const ruleId = finding.fingerprint?.split(":").at(-1) ?? "unknown";
      const candidate = byRule.get(ruleId);
      return {
        finding,
        candidateId: candidate?.id ?? `unknown:${ruleId}`,
        grade: "observed" as const,
        evidence: [{
          stage: "verify",
          status: "passed",
          summary: `deterministic HTTP oracle confirmed protocol rule ${ruleId}`,
          data: candidate?.payload,
        }],
      };
    });
    const confirmed = new Set(items.map((item) => item.candidateId));
    const evidence = input.candidates.map((candidate) => ({
      stage: "verify" as const,
      status: confirmed.has(candidate.id)
        ? "passed" as const
        : candidate.payload.verdict.status === "refuted"
          ? "failed" as const
          : "inconclusive" as const,
      summary: candidate.payload.verdict.evidence,
      data: candidate.payload,
    }));
    return { items, evidence };
  }
}
