import type { SubagentLifecyclePayload } from "@0sec/core";

export type { SubagentLifecyclePayload } from "@0sec/core";


/**
 * Pure reducer: apply one lifecycle event to a record keyed by agent_id.
 * Returns a NEW object when anything changed, or the SAME reference when the
 * event is a no-op. Exported for testing without React.
 */
export function reduceActiveSubagents(
  prev: Record<string, SubagentLifecyclePayload>,
  event: SubagentLifecyclePayload,
): Record<string, SubagentLifecyclePayload> {
  // Always upsert — a finished agent PARKS in the roster (kept with its terminal
  // completed/failed status) instead of vanishing, so the operator can still see
  // it and drill into its retained transcript. This mirrors Oh My Pi, where an
  // agent that finishes a task parks rather than dies. New object so React
  // detects the change.
  return { ...prev, [event.agent_id]: event };
}

/**
 * Parsed structured result from spawn_agent tool.
 * Null means the output was malformed (fall back to generic tool card).
 */
export interface SubagentCardData {
  outcome: "completed" | "failed";
  turns: number;
  findings: number;
  summary: string;
  error?: string;
}

/**
 * Parse a spawn_agent ToolResult output into card data.
 * Returns null when the shape is unrecognised — caller falls back to the
 * generic tool card.
 */
export function parseSubagentCard(
  success: boolean,
  output: unknown,
  error?: string,
): SubagentCardData | null {
  if (!success) {
    // Failed spawn_agent: always show as a subagent card with the error.
    return {
      outcome: "failed",
      turns: 0,
      findings: 0,
      summary: "",
      error: error ?? "unknown error",
    };
  }

  if (output == null || typeof output !== "object") return null;

  const data = output as Record<string, unknown>;
  const turns = data.turns;
  const findings = data.findings;

  // The core emits { turns, findings, summary, done } on success.
  if (typeof turns !== "number" || !Number.isSafeInteger(turns) || turns < 0) return null;
  if (typeof findings !== "number" || !Number.isSafeInteger(findings) || findings < 0) return null;
  if (typeof data.summary !== "string") return null;

  return {
    outcome: data.done === true ? "completed" : "failed",
    turns,
    findings,
    summary: data.summary.trim(),
  };
}