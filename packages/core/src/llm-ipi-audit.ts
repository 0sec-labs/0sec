/**
 * LLM indirect-prompt-injection (IPI) audit stage.
 *
 * Runs the @pwnkit/llm-redteam campaign engine against an LLM/agent endpoint and
 * maps each confirmed break onto a pwnkit Finding so it flows through the normal
 * triage/report pipeline. Kept as a focused module (not another branch in
 * agentic-scanner.ts) per the engineering rules.
 */
import type { Finding, Severity } from "@pwnkit/shared";
import {
  chatTarget,
  runIterativeCampaign,
  builtinBehaviors,
  regexJudge,
  llmJudge,
  type AskFn,
  type Behavior,
  type BreakRecord,
} from "@pwnkit/llm-redteam";

/** Deterministic id so re-running the same audit upserts rather than duplicates. */
function findingId(b: BreakRecord): string {
  return `llm-ipi:${b.behaviorId}:${b.model ?? "single"}`;
}

/** Map a confirmed IPI break onto a pwnkit Finding. */
export function breakRecordToFinding(record: BreakRecord, behavior: Behavior): Finding {
  const severity: Severity = "high"; // an injection that coerces a real action is high-impact
  return {
    id: findingId(record),
    templateId: `llm-ipi-${behavior.id}`,
    title: `Indirect prompt injection: ${behavior.title}`,
    description:
      `The target was coerced into "${behavior.goal.action}" via untrusted ${behavior.vector} content.\n` +
      `Model: ${record.model ?? "n/a"} · strategies: ${record.strategies.join(", ")}`,
    severity,
    category: "prompt-injection",
    status: "verified", // the judge confirmed the break
    evidence: {
      request: record.payloadText,
      response: record.transcriptExcerpt,
      analysis: record.evidence
        ? `Break proof: ${record.evidence}`
        : "Judge confirmed the success criterion was met.",
    },
    fingerprint: findingId(record),
    confidence: 0.9,
    timestamp: Date.now(),
  };
}

export interface LlmIpiAuditOptions {
  baseUrl: string;
  apiKey: string;
  models: string[];
  /** Behaviours to test; defaults to the engine's built-in set. */
  behaviors?: Behavior[];
  /** Cap per-behaviour attempts (depth-driven). */
  maxAttempts?: number;
  /** Optional judge-model call; enables the LLM judge for semantic behaviours
   *  (exfil, deanonymize, weak-policy). Without it those fall back to regex. */
  judgeAsk?: AskFn;
  onProgress?: (msg: string) => void;
}

/**
 * Run the IPI audit against an OpenAI-compatible endpoint. Returns Findings for
 * every (model, behaviour) that broke. `results` is empty for now — the audit
 * produces Findings directly rather than per-attack AttackResults.
 */
export async function runLlmIpiAudit(opts: LlmIpiAuditOptions): Promise<{ findings: Finding[] }> {
  const target = chatTarget({ baseUrl: opts.baseUrl, apiKey: opts.apiKey, models: opts.models });
  const behaviors = opts.behaviors ?? builtinBehaviors;
  const findings: Finding[] = [];

  const judge = (b: Behavior, r: Parameters<typeof regexJudge>[1]) =>
    b.goal.criteria && opts.judgeAsk ? llmJudge(b, r, opts.judgeAsk) : regexJudge(b, r);

  for (const behavior of behaviors) {
    opts.onProgress?.(`IPI: behaviour "${behavior.id}" across ${opts.models.length} model(s)`);
    const result = await runIterativeCampaign(behavior, target, { maxAttempts: opts.maxAttempts, judge });
    for (const record of result.breaks) findings.push(breakRecordToFinding(record, behavior));
    opts.onProgress?.(`IPI: "${behavior.id}" → ${result.brokenModels.length}/${opts.models.length} broken`);
  }
  return { findings };
}
