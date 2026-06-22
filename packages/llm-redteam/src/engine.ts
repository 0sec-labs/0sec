/**
 * Campaign engine: sweep candidate payloads across a target's models, judge
 * each, and record unique breaks.
 *
 * Bakes in the lesson from the Gray Swan run: a break is unique per
 * (model, behaviour), so once a model is broken we stop spending attempts on
 * it — only unbroken models are retried with the next candidate.
 */
import type { Behavior, BreakRecord, CampaignResult, Payload, Target, Verdict } from "./types.js";
import { regexJudge } from "./judge.js";
import { generateCandidates } from "./strategies/index.js";

export interface CampaignOptions {
  /** Candidate payloads to sweep; defaults to the full framing×concealment set. */
  candidates?: Payload[];
  /** Judge to use; defaults to the regex/proof judge. */
  judge?: (behavior: Behavior, response: Awaited<ReturnType<Target["send"]>>) => Verdict;
  /** Stop once every model is broken. */
  stopWhenAllBroken?: boolean;
  /** Max total send() calls (budget guard). */
  maxAttempts?: number;
  /** Called after each attempt for progress reporting. */
  onAttempt?: (info: { model?: string; strategies: string[]; broken: boolean; attempt: number }) => void;
}

export async function runCampaign(
  behavior: Behavior,
  target: Target,
  opts: CampaignOptions = {},
): Promise<CampaignResult> {
  const candidates = opts.candidates ?? generateCandidates(behavior);
  const judge = opts.judge ?? regexJudge;
  const models = target.models && target.models.length ? target.models : [undefined];
  const brokenModels = new Set<string>();
  const breaks: BreakRecord[] = [];
  let attempts = 0;

  outer: for (const payload of candidates) {
    for (const model of models) {
      const key = model ?? "_single";
      if (brokenModels.has(key)) continue; // unique-breaks: don't re-hit a broken model
      if (opts.maxAttempts && attempts >= opts.maxAttempts) break outer;

      attempts++;
      let verdict: Verdict;
      let transcript = "";
      try {
        const response = await target.send(payload, behavior, model);
        transcript = response.transcript;
        verdict = judge(behavior, response);
      } catch (err) {
        verdict = { broken: false, confidence: 0, judge: "error", evidence: String(err) };
      }

      opts.onAttempt?.({ model, strategies: payload.strategies, broken: verdict.broken, attempt: attempts });

      if (verdict.broken) {
        brokenModels.add(key);
        breaks.push({
          behaviorId: behavior.id,
          target: target.name,
          model,
          strategies: payload.strategies,
          broken: true,
          evidence: verdict.evidence,
          payloadText: payload.text,
          transcriptExcerpt: transcript.slice(0, 500),
        });
      }
    }
    if (opts.stopWhenAllBroken && brokenModels.size >= models.length) break;
  }

  return {
    behaviorId: behavior.id,
    target: target.name,
    attempts,
    breaks,
    brokenModels: [...brokenModels].filter((m) => m !== "_single"),
  };
}
