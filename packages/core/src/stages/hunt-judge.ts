/**
 * Hunt candidate LLM judge — best-of-N disambiguation for `runHuntScan`.
 *
 * Mirrors the CyberGym best-of-N judge (`judgeCyberGymCandidatesWithLlm` in
 * `@pwnkit/benchmark`'s cybergym-runner.ts): when a (candidate, model) pair
 * produced more than one attempt, an LLM judge scores each finding against the
 * hunt brief's bug class/pattern so only the strongest survives to the
 * (expensive) skeptic+prover gate — keeping skeptic call-count flat while the
 * finder pool widens N×. Same `LlmApiRuntime({type:"api", model, timeout})` +
 * `executeNative` provider routing as `makeLloreJudge` (novelty-check.ts), the
 * other native LLM judge in this stage directory.
 */

import type { Finding, RuntimeMode } from "@pwnkit/shared";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import type { HuntBrief } from "./hunt-scan.js";

export interface HuntCandidateScore {
  score: number;
  reason: string;
}

/** Scores every finding surfaced for ONE (candidate, model) group against the hunt brief. */
export type HuntCandidateJudge = (
  brief: HuntBrief,
  findings: readonly Finding[],
  opts: { model?: string; runtime: RuntimeMode },
) => Promise<Map<string, HuntCandidateScore>>;

function extractJudgeText(result: { content: Array<{ type: string; text?: string }> }): string {
  return result.content
    .filter((b): b is { type: "text"; text: string } => b.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join("\n")
    .trim();
}

function extractJsonObject(s: string): string {
  const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/);
  const body = fence ? fence[1].trim() : s.trim();
  const start = body.indexOf("{");
  const end = body.lastIndexOf("}");
  return start >= 0 && end > start ? body.slice(start, end + 1) : body;
}

function parseJudgeJson(text: string): HuntCandidateScore {
  const parsed = JSON.parse(extractJsonObject(text)) as { score?: unknown; reason?: unknown };
  const rawScore = typeof parsed.score === "number" ? parsed.score : Number(parsed.score);
  if (!Number.isFinite(rawScore)) throw new Error("judge response missing numeric score");
  return {
    score: Math.max(0, Math.min(10, rawScore)),
    reason: typeof parsed.reason === "string" ? parsed.reason : "",
  };
}

/**
 * Heuristic fallback when the judge call throws: score by whether the
 * finding's evidence names the sink shape from `brief.pattern` (crude
 * keyword-overlap, no LLM call — matches `heuristicCandidateScore`'s role in
 * cybergym-runner.ts).
 */
export function heuristicCandidateScore(brief: HuntBrief, finding: Finding): HuntCandidateScore {
  const text = `${finding.description} ${finding.evidence?.analysis ?? ""}`.toLowerCase();
  const patternWords = Array.from(
    new Set(brief.pattern.toLowerCase().match(/[a-z_][a-z0-9_]{3,}/g) ?? []),
  );
  if (patternWords.length === 0) return { score: 1, reason: "heuristic fallback: no pattern keywords to match" };
  const hits = patternWords.filter((w) => text.includes(w));
  const score = Math.min(10, Math.round((hits.length / patternWords.length) * 10));
  return {
    score,
    reason:
      hits.length > 0
        ? `heuristic: sink pattern keyword(s) matched (${hits.length}/${patternWords.length}: ${hits.slice(0, 5).join(", ")})`
        : "heuristic fallback: no sink pattern keyword match",
  };
}

/**
 * Score every finding surfaced for one candidate against the hunt brief's bug
 * class/pattern, one `executeNative` call per finding (same shape as
 * `judgeCyberGymCandidatesWithLlm`). Falls back to {@link heuristicCandidateScore}
 * per-finding when the judge call throws or returns an unparseable response —
 * a single provider hiccup must not drop the whole group's ranking.
 */
export const judgeHuntCandidatesWithLlm: HuntCandidateJudge = async (brief, findings, opts) => {
  const scores = new Map<string, HuntCandidateScore>();
  if (findings.length === 0) return scores;
  const runtime = new LlmApiRuntime({
    type: "api",
    timeout: 120_000,
    ...(opts.model ? { model: opts.model } : {}),
  });
  const system =
    "You are judging candidate findings from a kernel/source variant-hunt finder. You see only the " +
    "target bug class + pattern and one candidate finding's description/analysis. Score how well the " +
    "finding matches that EXACT bug class and sink shape. Return only JSON.";
  for (const finding of findings) {
    try {
      const user =
        `Bug class: ${brief.bugClass}\n` +
        `Concrete pattern to match (the sink/shape): ${brief.pattern}\n\n` +
        `Candidate finding:\n  title: ${finding.title}\n  description: ${finding.description}\n` +
        `  analysis: ${finding.evidence?.analysis ?? ""}\n\n` +
        'How well does this candidate match the described bug class/pattern (not just "a bug", the SAME ' +
        'one)? Return JSON {"score":0-10,"reason":"..."}';
      const result = await runtime.executeNative(
        system,
        [{ role: "user", content: [{ type: "text", text: user }] }],
        [],
      );
      const text = extractJudgeText(result);
      if (!text) throw new Error("empty judge response");
      scores.set(finding.id, parseJudgeJson(text));
    } catch {
      scores.set(finding.id, heuristicCandidateScore(brief, finding));
    }
  }
  return scores;
};
