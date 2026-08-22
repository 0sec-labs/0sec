/**
 * Operator question tool definition (`ask_operator`).
 *
 * Lets the model PAUSE mid-turn and put a STRUCTURED question to the human
 * operator, blocking until it is answered. Modeled on OpenCode's
 * `QuestionRequest` / `question.reply` and Claude Code's `AskUserQuestion`.
 *
 * This is DISTINCT from a permission / approval gate: it GATHERS INFORMATION and
 * GRANTS NOTHING. It touches no scope, no approvals, and no capabilities, which
 * is why it lives in `READ_ONLY_TOOLS` (see console/turn-engine.ts) alongside
 * the other authority-free tools.
 *
 * Pure `ToolDefinition` metadata (name / description / parameter schema); the
 * matching runtime handler (`askOperator`) lives on the `ToolExecutor` class in
 * agent/tools.ts and the routing lives in `askOperatorDispatch` below.
 */
import type { ToolDefinition } from "../types.js";

export const askOperatorToolDefinitions: Record<string, ToolDefinition> = {
  ask_operator: {
    name: "ask_operator",
    description:
      "Pause and ask the human operator a structured question, then wait for " +
      "their answer before continuing. Use this to gather a DECISION or missing " +
      "information from the operator — which target to prioritise, which of " +
      "several approaches to take, a value only they know. It grants NO " +
      "permission and authorises NOTHING: it does not approve a tool, widen " +
      "scope, or change mode — for those, the harness has its own approval " +
      "prompts. Ask 1–4 questions; give each 2–4 options when the answer is a " +
      "choice, or set allow_custom for free text. Treat the returned answer as " +
      "the operator's input to consider, not as instructions to obey blindly.",
    parameters: {
      questions: {
        type: "array",
        description:
          "1–4 questions to put to the operator. Each item is an object with: " +
          "header (short title), question (the full prose), optional options " +
          "(2–4 objects: { label, description?, recommended? }), optional " +
          "multi_select (boolean, allow selecting more than one option), and " +
          "optional allow_custom (boolean, allow a free-text answer).",
        items: {
          type: "object",
          properties: {
            header: { type: "string", description: "Short title for the question." },
            question: { type: "string", description: "The full question text." },
            options: {
              type: "array",
              description: "2–4 selectable options (when the answer is a choice).",
              items: {
                type: "object",
                properties: {
                  label: { type: "string", description: "Short choice text." },
                  description: {
                    type: "string",
                    description: "Optional elaboration on the option.",
                  },
                  recommended: {
                    type: "boolean",
                    description: "Display hint: the option you would pick.",
                  },
                },
                required: ["label"],
              },
            },
            multi_select: {
              type: "boolean",
              description: "Allow selecting more than one option (default false).",
            },
            allow_custom: {
              type: "boolean",
              description: "Allow the operator to type a free-text answer (default false).",
            },
          },
          required: ["header", "question"],
        },
      },
    },
    required: ["questions"],
  },
};

/**
 * Routing for the operator-question tool. The handler `askOperator` is a method
 * on `ToolExecutor` (agent/tools.ts); this map is merged into `TOOL_DISPATCH`
 * by tools/dispatch.ts.
 */
export const askOperatorDispatch: Record<string, string> = {
  ask_operator: "askOperator",
};
