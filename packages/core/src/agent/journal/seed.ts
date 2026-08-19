/**
 * Journal → conversation seed rendering (#494, slice 2).
 *
 * `rehydrateContext` (rehydrate.ts) is deliberately STRUCTURAL: it returns a
 * `ConversationState` (toolSteps / hypotheses / findings / notes / decisions),
 * not a model-specific message array. The design doc's "render step" lives
 * here: it turns that structure into the `NativeMessage[]` window the native
 * agent loop drives off. Keeping render separate from rehydrate lets a future
 * slice emit a compact seed for a short-context open-weight model without
 * reshaping the journal or touching the pure rehydrator (see
 * docs/research/agent-execution-journal-design.md §"Rehydration").
 *
 * The function is pure (state in → messages out, no I/O) so it is trivially
 * snapshot-testable. It renders the rehydrated state into a single `user`
 * message: a compact, deterministic transcript-style summary of what the run
 * has done so far. This mirrors how the existing resume path hands the model a
 * prior conversation window — the model reads it and continues — but sources
 * that window from the durable journal instead of the truncated 40-message DB
 * blob.
 */

import type { NativeMessage } from "../../runtime/types.js";
import type { ConversationState } from "./rehydrate.js";

/** Max chars rendered per tool output so a huge result can't blow the seed. */
const MAX_OUTPUT_CHARS = 1200;

function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  return text.slice(0, max - 1) + "…";
}

function renderValue(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function renderToolStep(step: ConversationState["toolSteps"][number], index: number): string {
  const turn = typeof step.turn === "number" ? ` (turn ${step.turn})` : "";
  const args = step.arguments !== undefined ? ` ${clip(renderValue(step.arguments), 400)}` : "";
  const lines = [`${index + 1}. ${step.tool}${turn}:${args}`];
  if (step.result) {
    if (step.result.ok) {
      const out = clip(renderValue(step.result.output ?? ""), MAX_OUTPUT_CHARS);
      lines.push(`   → ok${out ? `: ${out}` : ""}`);
    } else {
      lines.push(`   → error: ${clip(step.result.error ?? "unknown", 400)}`);
    }
  } else {
    lines.push("   → (no result recorded)");
  }
  return lines.join("\n");
}

/**
 * Render a rehydrated `ConversationState` into the conversation window the
 * native loop seeds itself with. Returns an EMPTY array when the state carries
 * no actual progress (empty journal) — the caller treats that as "nothing to
 * rehydrate" and falls through to the normal fresh-start prompt, which keeps a
 * fresh run byte-equivalent to today regardless of the flag.
 */
export function renderSeedMessages(state: ConversationState): NativeMessage[] {
  const hasProgress =
    state.toolSteps.length > 0 ||
    state.hypotheses.length > 0 ||
    state.findings.length > 0 ||
    state.notes.length > 0 ||
    state.decisions.length > 0 ||
    state.done ||
    state.summary.trim().length > 0;

  if (!hasProgress) return [];

  const sections: string[] = [
    "[Execution journal — prior progress on this run, rehydrated from disk]",
  ];

  if (state.toolSteps.length > 0) {
    sections.push(
      "## Tool steps so far\n" +
        state.toolSteps.map((step, i) => renderToolStep(step, i)).join("\n"),
    );
  }

  if (state.hypotheses.length > 0) {
    sections.push(
      "## Hypotheses\n" +
        state.hypotheses
          .map((h) => {
            const conf =
              typeof h.confidence === "number" ? ` (confidence ${h.confidence})` : "";
            const rationale = h.rationale ? ` — ${h.rationale}` : "";
            return `- [${h.status}] ${h.statement}${conf}${rationale}`;
          })
          .join("\n"),
    );
  }

  if (state.findings.length > 0) {
    sections.push(
      "## Findings recorded\n" +
        state.findings.map((f, i) => `${i + 1}. ${clip(renderValue(f), MAX_OUTPUT_CHARS)}`).join("\n"),
    );
  }

  if (state.decisions.length > 0) {
    sections.push("## Decisions\n" + state.decisions.map((d) => `- ${d}`).join("\n"));
  }

  if (state.notes.length > 0) {
    sections.push("## Notes\n" + state.notes.map((n) => `- ${n}`).join("\n"));
  }

  if (state.done && state.summary.trim()) {
    sections.push(`## Prior run closed\n${state.summary}`);
  }

  sections.push(
    "Continue from this state. Use your tools — do not repeat steps already completed above.",
  );

  return [
    {
      role: "user",
      content: [{ type: "text", text: sections.join("\n\n") }],
    },
  ];
}
