/**
 * Structured TODOS tool definitions (`update_todos`, alias `write_todos`).
 *
 * A full-state plan write in the `TodoWrite` shape: the model re-declares the
 * ENTIRE plan on each call and the last write wins. This is the render-facing
 * counterpart to the action-based `plan` ledger (tools/system.ts) — the TUI
 * repaints its live task tree from each snapshot.
 *
 * It authorizes NOTHING and grants no capability: it mutates only the run's
 * plan tracker, which is why it belongs alongside the other authority-free
 * tools in `console/turn-engine.ts`'s READ_ONLY_TOOLS allow-list (a one-line
 * follow-up — that file is owned elsewhere).
 *
 * Pure `ToolDefinition` metadata; the runtime handler (`updateTodos`) lives on
 * the `ToolExecutor` class in agent/tools.ts and the routing in `todosDispatch`
 * below. `write_todos` is a registered ALIAS: same handler, kept in the
 * registry so a model that reaches for the `TodoWrite`-style name still routes
 * (dispatch.test pins TOOL_DISPATCH keys to the registry), but kept OUT of the
 * advertised role tool-sets so only one name (`update_todos`) is offered.
 */
import type { ToolDefinition } from "../types.js";

const TODOS_DESCRIPTION =
  "Declare or update your task plan. Pass the COMPLETE list of tasks every " +
  "time — this REPLACES the current plan (full-state write, like a to-do " +
  "list you rewrite in place), so include finished tasks too, marking them " +
  "completed. Each task has content (a short imperative line), an optional " +
  "status (pending | in_progress | completed; defaults to pending), and an " +
  "optional group (a phase label, e.g. \"Inspection\") that buckets tasks " +
  "into phases the operator sees rendered as a live tree. Keep exactly one " +
  "task in_progress at a time. Use this to think out loud about multi-step " +
  "work and to show progress. It authorizes nothing and grants no " +
  "capability — it only records the plan.";

const todoItemSchema = {
  type: "object",
  properties: {
    content: { type: "string", description: "Short imperative statement of the task." },
    status: {
      type: "string",
      description: "Task status (default pending).",
      enum: ["pending", "in_progress", "completed"],
    },
    group: {
      type: "string",
      description: 'Optional phase label, e.g. "Inspection". Tasks with the same group render together.',
    },
  },
  required: ["content"],
};

export const todosToolDefinitions: Record<string, ToolDefinition> = {
  update_todos: {
    name: "update_todos",
    description: TODOS_DESCRIPTION,
    parameters: {
      todos: {
        type: "array",
        description:
          "The COMPLETE plan (up to 50 tasks). Replaces the previous plan in full.",
        items: todoItemSchema,
      },
    },
    required: ["todos"],
  },
  // Alias for the TodoWrite-style name. Same handler; registered so it routes,
  // but not advertised in role tool-sets (see getToolsForRole).
  write_todos: {
    name: "write_todos",
    description: TODOS_DESCRIPTION + " (Alias of update_todos.)",
    parameters: {
      todos: {
        type: "array",
        description:
          "The COMPLETE plan (up to 50 tasks). Replaces the previous plan in full.",
        items: todoItemSchema,
      },
    },
    required: ["todos"],
  },
};

/**
 * Routing for the structured-todos tools. Both names resolve to the same
 * `updateTodos` handler on `ToolExecutor` (agent/tools.ts); merged into
 * `TOOL_DISPATCH` by tools/dispatch.ts.
 */
export const todosDispatch: Record<string, string> = {
  update_todos: "updateTodos",
  write_todos: "updateTodos",
};

/** The alias name, excluded from advertised role tool-sets. */
export const TODOS_ALIAS_NAME = "write_todos";
