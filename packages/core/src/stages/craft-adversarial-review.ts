/**
 * Independent review before a scarce crafted-PoC submission.
 *
 * The craft loop already requires a vulnerable-side crash and deterministic
 * identity anchors. This optional reviewer attacks the remaining premise: that
 * a candidate which crashes the same function and class also satisfies the
 * described precondition rather than a nearby, pre-existing crash. It never
 * self-grades a PoC and only blocks on a concrete rejection; an unavailable or
 * ambiguous review stays inconclusive so infrastructure does not erase a valid
 * proof attempt.
 */

import { truncateMiddle } from "../agent/output-truncation.js";
import { LlmApiRuntime } from "../runtime/llm-api.js";
import type { NativeMessage } from "../runtime/types.js";
import type { CraftCandidateIdentity } from "./craft-candidate-identity.js";

export type CraftCandidateReviewVerdict = "accept" | "reject" | "inconclusive";

export interface CraftCandidateReviewInput {
  target: {
    description: string;
    taskId?: string;
  };
  generator: string;
  sanitizerOutput: string;
  identity: CraftCandidateIdentity;
}

export interface CraftCandidateReview {
  verdict: CraftCandidateReviewVerdict;
  reason: string;
}

/** Injectable so callers can use a deterministic domain reviewer or a distinct model. */
export type CraftCandidateReviewer = (
  input: CraftCandidateReviewInput,
) => Promise<CraftCandidateReview>;

const SYSTEM =
  "You are an adversarial reviewer for a crafted memory-safety PoC. The candidate already crashed the vulnerable binary, but that is not enough: try to refute whether it triggers the EXACT described bug rather than a different/pre-existing crash. " +
  "Reject only for a concrete contradiction in the generator, sanitizer trace, crash identity, or required precondition. Missing evidence is INCONCLUSIVE, not rejection. You never decide whether the patch is clean; the differential oracle owns that. Return JSON only: {\"verdict\":\"accept\"|\"reject\"|\"inconclusive\",\"reason\":\"specific evidence\"}.";

function clip(text: string, limit: number): string {
  return truncateMiddle(text, { limit, mode: "bytes" }).text;
}

function extractText(content: ReadonlyArray<{ type: string; text?: string }>): string {
  return content
    .filter((block) => block.type === "text" && typeof block.text === "string")
    .map((block) => block.text ?? "")
    .join("\n")
    .trim();
}

/** Parse a model answer conservatively: malformed output can never reject a candidate. */
export function parseCraftCandidateReview(text: string): CraftCandidateReview {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) {
    return { verdict: "inconclusive", reason: "reviewer returned no JSON verdict" };
  }
  try {
    const raw: unknown = JSON.parse(text.slice(start, end + 1));
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      return { verdict: "inconclusive", reason: "reviewer JSON was not an object" };
    }
    const verdict = "verdict" in raw ? raw.verdict : undefined;
    const reasonValue = "reason" in raw ? raw.reason : undefined;
    const reason = typeof reasonValue === "string" ? reasonValue.trim() : "";
    if (verdict === "accept" || verdict === "reject" || verdict === "inconclusive") {
      return {
        verdict,
        reason: reason || `reviewer returned ${verdict} without a specific reason`,
      };
    }
  } catch {
    // Fall through to the safe inconclusive outcome.
  }
  return { verdict: "inconclusive", reason: "reviewer returned an unrecognised verdict" };
}

/**
 * Default LLM reviewer. Use a model distinct from the crafting model when one
 * is available; callers choose that policy and inject this function. Any model
 * or transport failure is an inconclusive review, never a fabricated reject.
 */
export function defaultCraftCandidateReviewer(opts: {
  model?: string;
  timeoutMs?: number;
} = {}): CraftCandidateReviewer {
  return async (input) => {
    const runtime = new LlmApiRuntime({
      type: "api",
      ...(opts.model ? { model: opts.model } : {}),
      timeout: opts.timeoutMs ?? 240_000,
    });
    const message = [
      `## Vulnerability description\n${clip(input.target.description, 6000)}`,
      `## Candidate generator\n${clip(input.generator, 8000)}`,
      `## Vulnerable-side sanitizer output\n${clip(input.sanitizerOutput, 8000)}`,
      `## Deterministic identity evidence\n${JSON.stringify(input.identity)}`,
    ].join("\n\n");
    const messages: NativeMessage[] = [{ role: "user", content: [{ type: "text", text: message }] }];
    try {
      const result = await runtime.executeNative(SYSTEM, messages, [], {
        onThinking() {},
        onDelta() {},
        onUsage() {},
      });
      if (result.error) {
        return { verdict: "inconclusive", reason: `reviewer runtime error: ${clip(result.error, 240)}` };
      }
      return parseCraftCandidateReview(extractText(result.content));
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      return { verdict: "inconclusive", reason: `reviewer call failed: ${clip(reason, 240)}` };
    }
  };
}
