/**
 * Adversarial Debate Verification.
 *
 * An additional verification gate that pits two adversarial agents against
 * each other — a prosecutor arguing the finding is real, a defender arguing
 * it is a false positive — and asks a skeptical judge to pick the winner.
 *
 * Motivation: single-pass verification has correlated error modes with the
 * original discovery pass (same model, similar priors). An adversarial debate
 * setup has uncorrelated error modes — the prosecutor and defender are
 * explicitly instructed to argue opposing positions, so their reasoning
 * diverges. Anthropic's "Debate" paper (arXiv:2402.06782) showed this
 * pattern catches errors a single-pass verifier misses and that accuracy
 * scales with debater capability even when the judge is weaker.
 *
 * Each agent gets a fresh context — they see only the written arguments of
 * the other side, never each other's internal reasoning.
 */

import type { Finding } from "@pwnkit/shared";
import type {
  NativeRuntime,
  NativeMessage,
  NativeContentBlock,
} from "../runtime/types.js";

// ── Public Types ──

export interface DebateRound {
  /** Prosecutor's argument this round: "this is a real vulnerability because..." */
  prosecutor: string;
  /** Defender's argument this round: "this is a false positive because..." */
  defender: string;
}

export type DebateVerdict = "real" | "false_positive" | "unclear";

export interface DebateResult {
  verdict: DebateVerdict;
  /** Judge's confidence in the verdict, 0-1. */
  confidence: number;
  /** Full debate transcript, in order. */
  rounds: DebateRound[];
  /** The judge's written reasoning for the verdict. */
  judgeReasoning: string;
  /** True iff the judge ruled in favor of the prosecutor (verdict === "real"). */
  prosecutorWon: boolean;
}

export interface AdversarialDebateOptions {
  /** Number of prosecutor/defender turn pairs. Default: 2. */
  maxRounds?: number;
}

// ── Prompt Builders ──

/**
 * Render a Finding into a compact evidence block that is shared verbatim by
 * both debaters and the judge. Kept deterministic so debate transcripts are
 * reproducible in tests.
 */
function renderFindingBlock(finding: Finding, target: string): string {
  const ev = finding.evidence ?? {};
  const request = (ev as { request?: string }).request ?? "(none)";
  const response = (ev as { response?: string }).response ?? "(none)";
  return `## Target
${target}

## Finding
- id: ${finding.id}
- title: ${finding.title}
- category: ${finding.category}
- severity: ${finding.severity}
- description: ${finding.description}

## Evidence
### Request
${request}

### Response
${response}`;
}

function prosecutorSystemPrompt(finding: Finding, target: string): string {
  return `You are the PROSECUTOR in an adversarial debate about a reported security finding.

Your job: make the strongest possible case that this finding is a REAL, exploitable vulnerability that a competent maintainer should accept as a bug.

Be specific about each of the following:
1. The attack vector — exactly how the input reaches the sink.
2. Why it is reachable from untrusted input (no obvious auth gate, not dev-only code, not behind a private network).
3. What concrete impact it has (data exfiltration, privilege escalation, RCE, etc.).
4. Why a competent maintainer would accept this as a bug rather than dismissing it as "holding it wrong" or "works as designed".

Rules:
- Ground every claim in the evidence below. Do not invent facts.
- If the defender has made arguments in prior rounds, rebut each specific point.
- Write in clear, paragraph-level prose. No JSON, no bullet headers beyond the points above.
- Do NOT concede. Your role is to argue for the prosecution, even if the case is weak.

${renderFindingBlock(finding, target)}`;
}

function defenderSystemPrompt(finding: Finding, target: string): string {
  return `You are the DEFENDER in an adversarial debate about a reported security finding.

Your job: make the strongest possible case that this finding is a FALSE POSITIVE — a non-issue that should not be reported to the maintainer.

Be specific about each of the following:
1. Works-as-designed patterns — is this behavior documented or intentional?
2. Documented behavior — does the project's docs/README/CHANGELOG acknowledge it?
3. Non-realistic attack surface — does reaching the sink require attacker-controlled state that is never actually attacker-controlled (e.g. config files, CLI args, DEBUG mode)?
4. Caller responsibility — is this a "holding it wrong" issue where the caller is documented to be trusted?
5. Framework defenses — does the framework auto-escape, parameterize, or validate in a way the prosecutor is ignoring?

Rules:
- Ground every claim in the evidence below. Do not invent facts.
- If the prosecutor has made arguments in prior rounds, rebut each specific point.
- Write in clear, paragraph-level prose. No JSON.
- Do NOT concede. Your role is to argue for the defense, even if the finding looks damning.

${renderFindingBlock(finding, target)}`;
}

function judgeSystemPrompt(
  finding: Finding,
  target: string,
  transcript: string,
): string {
  return `You are a skeptical senior security researcher judging a debate about whether a security finding is real or a false positive.

The prosecutor argues it's real. The defender argues it's a FP. Read the full debate below and decide.

Bias: when in doubt, favor "false positive" — the cost of submitting a FP to a maintainer is high (reputation damage). Only mark "real" if the prosecutor demonstrated: (1) reachable attack path from untrusted input, (2) concrete impact, (3) no obvious caller responsibility pattern.

${renderFindingBlock(finding, target)}

## Debate Transcript
${transcript}

Output JSON and nothing else:
{
  "verdict": "real" | "false_positive" | "unclear",
  "confidence": 0.0-1.0,
  "reasoning": "2-5 sentences explaining who made the stronger case and why."
}`;
}

// ── Transcript Rendering ──

/**
 * Render the running transcript that gets passed to each debater (so they can
 * rebut the other side) and to the judge at the end.
 */
function renderTranscript(rounds: DebateRound[]): string {
  if (rounds.length === 0) return "(no prior rounds)";
  const parts: string[] = [];
  rounds.forEach((r, i) => {
    parts.push(`### Round ${i + 1} — Prosecutor\n${r.prosecutor}`);
    parts.push(`### Round ${i + 1} — Defender\n${r.defender}`);
  });
  return parts.join("\n\n");
}

// ── LLM Interaction ──

/**
 * Extract the concatenated text of all text blocks from a NativeRuntime
 * response. Matches the helper pattern used in structured-verify.ts.
 */
function extractText(content: NativeContentBlock[]): string {
  return content
    .filter((b): b is NativeContentBlock & { type: "text" } => b.type === "text")
    .map((b) => b.text)
    .join("\n");
}

/**
 * Ask one debater for their argument, given the current transcript as context.
 * The debater sees the prior written arguments but not any internal reasoning.
 */
async function runDebaterTurn(
  role: "prosecutor" | "defender",
  finding: Finding,
  target: string,
  priorTranscript: string,
  runtime: NativeRuntime,
): Promise<string> {
  const systemPrompt =
    role === "prosecutor"
      ? prosecutorSystemPrompt(finding, target)
      : defenderSystemPrompt(finding, target);

  const userText =
    priorTranscript === "(no prior rounds)"
      ? `Make your opening argument as the ${role}.`
      : `Prior debate transcript:\n\n${priorTranscript}\n\nMake your next argument as the ${role}. Rebut any points the other side raised.`;

  const userMessage: NativeMessage = {
    role: "user",
    content: [{ type: "text", text: userText }],
  };

  const result = await runtime.executeNative(systemPrompt, [userMessage], []);
  return extractText(result.content).trim();
}

interface JudgeOutput {
  verdict: DebateVerdict;
  confidence: number;
  reasoning: string;
}

/**
 * Parse the judge's JSON verdict. Handles markdown fencing and surrounding
 * prose the same way verify-pipeline's parser does.
 */
export function parseJudgeOutput(raw: string): JudgeOutput {
  let cleaned = raw.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "");

  const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    throw new Error(`No JSON object found in judge response: ${raw.slice(0, 200)}`);
  }

  const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;

  const verdict = parsed.verdict;
  if (
    verdict !== "real" &&
    verdict !== "false_positive" &&
    verdict !== "unclear"
  ) {
    throw new Error(`Invalid 'verdict' field in judge response: ${String(verdict)}`);
  }
  if (
    typeof parsed.confidence !== "number" ||
    parsed.confidence < 0 ||
    parsed.confidence > 1
  ) {
    throw new Error(`Missing or invalid 'confidence' field in judge response`);
  }
  if (typeof parsed.reasoning !== "string") {
    throw new Error(`Missing or invalid 'reasoning' field in judge response`);
  }

  return {
    verdict,
    confidence: parsed.confidence,
    reasoning: parsed.reasoning,
  };
}

// ── Entry Point ──

/**
 * Run an adversarial prosecutor-vs-defender debate about a finding and ask a
 * skeptical judge to rule.
 *
 * Algorithm:
 *   1. Prosecutor opening argument (fresh context).
 *   2. Defender opening argument (sees prosecutor's argument).
 *   3. Repeat for maxRounds-1 more rebuttal rounds.
 *   4. Judge reads the full transcript and outputs a JSON verdict.
 *
 * On judge-parse failure the result falls back to a low-confidence "unclear"
 * verdict — we prefer to surface uncertainty rather than let a malformed
 * judgment crash the caller.
 */
export async function runAdversarialDebate(
  finding: Finding,
  target: string,
  runtime: NativeRuntime,
  options?: AdversarialDebateOptions,
): Promise<DebateResult> {
  const maxRounds = Math.max(1, options?.maxRounds ?? 2);

  const rounds: DebateRound[] = [];

  for (let i = 0; i < maxRounds; i += 1) {
    const transcriptBefore = renderTranscript(rounds);

    const prosecutorArg = await runDebaterTurn(
      "prosecutor",
      finding,
      target,
      transcriptBefore,
      runtime,
    );

    // Defender sees prosecutor's fresh argument for this round, appended to
    // the transcript that it would otherwise have seen.
    const transcriptWithProsecutor =
      transcriptBefore === "(no prior rounds)"
        ? `### Round ${i + 1} — Prosecutor\n${prosecutorArg}`
        : `${transcriptBefore}\n\n### Round ${i + 1} — Prosecutor\n${prosecutorArg}`;

    const defenderArg = await runDebaterTurn(
      "defender",
      finding,
      target,
      transcriptWithProsecutor,
      runtime,
    );

    rounds.push({ prosecutor: prosecutorArg, defender: defenderArg });
  }

  const fullTranscript = renderTranscript(rounds);
  const judgePrompt = judgeSystemPrompt(finding, target, fullTranscript);

  const judgeResult = await runtime.executeNative(
    judgePrompt,
    [
      {
        role: "user",
        content: [
          {
            type: "text",
            text: "Read the debate above and output your JSON verdict.",
          },
        ],
      },
    ],
    [],
  );
  const judgeText = extractText(judgeResult.content);

  try {
    const parsed = parseJudgeOutput(judgeText);
    return {
      verdict: parsed.verdict,
      confidence: Math.round(parsed.confidence * 100) / 100,
      rounds,
      judgeReasoning: parsed.reasoning,
      prosecutorWon: parsed.verdict === "real",
    };
  } catch (err) {
    return {
      verdict: "unclear",
      confidence: 0,
      rounds,
      judgeReasoning: `Failed to parse judge response: ${err instanceof Error ? err.message : String(err)}. Raw: ${judgeText.slice(0, 300)}`,
      prosecutorWon: false,
    };
  }
}

// ── Test-Only Hooks ──

export const __testing = {
  prosecutorSystemPrompt,
  defenderSystemPrompt,
  judgeSystemPrompt,
  renderTranscript,
};
