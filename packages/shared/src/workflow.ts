// ── YAML-defined FSM workflows (pwnkit#225) ─────────────────────────────────
//
// A workflow is a small finite-state machine that an orchestrator can step
// through: each `state` invokes a named specialist, then transitions to the
// next state based on the result. The shape here is the static-validation
// surface — orchestrator interpretation (the actual specialist dispatch +
// state transition loop) lives in pwnkit#249 and is out of scope for this
// schema PR.
//
// The schema is intentionally tiny:
//
//   workflow:
//     name: web-pentest
//     version: 1
//     description: ...
//     initial_state: recon
//     states:
//       recon:
//         specialist: web-recon
//         on_success: { to: triage }
//         transitions:
//           - when: { kind: cmp, lhs: last_entry_kind, op: "==", rhs: "finding" }
//             to: report
//       triage: ...
//
// Condition expressions are a small typed AST (`ConditionExpr`) — NOT a
// general expression language. They support the comparison + boolean
// combinators needed to express the journal-entry checks used by today's
// orchestrator (e.g. "the last journal entry was a finding AND its
// confidence was >= 0.7"). Anything more elaborate is intentionally
// out-of-scope; if a workflow needs richer logic, it should be modelled as
// additional states rather than a clever expression.

import { z } from "zod";

// ── Condition AST ───────────────────────────────────────────────────────────

// Comparison operators we support. Keep this minimal — every additional
// op is a new evaluator branch + new docs. Equality, ordering, and a
// `in` for kind-set membership cover the journal-entry checks the issue
// calls out without ballooning the surface.
export const conditionCmpOpSchema = z.enum(["==", "!=", ">=", "<=", ">", "<", "in"]);
export type ConditionCmpOp = z.infer<typeof conditionCmpOpSchema>;

// LHS identifiers the evaluator knows how to resolve against a journal
// slice. New identifiers are additive — adding one here is a backwards-
// compatible change. Unknown identifiers throw at evaluate time so
// typos surface fast (rather than silently evaluating to undefined).
export const conditionLhsSchema = z.enum([
  // Most-recent journal entry kind: "finding" | "decision" | "error" | etc.
  "last_entry_kind",
  // Confidence on the most-recent finding/decision entry (0–1).
  "confidence",
  // Total entry count seen so far.
  "entry_count",
  // True iff at least one finding has been recorded.
  "has_finding",
  // True iff the most-recent entry was an error.
  "last_error",
]);
export type ConditionLhs = z.infer<typeof conditionLhsSchema>;

// RHS is a literal: string, number, boolean, or string array. Allowing
// `in` against an array of strings covers the "kind is one of ..." case
// that journal-driven transitions naturally want.
export const conditionRhsSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.array(z.string()),
]);
export type ConditionRhs = z.infer<typeof conditionRhsSchema>;

// Leaf comparison node. Discriminator is `kind: "cmp"`.
export const conditionCmpSchema = z.object({
  kind: z.literal("cmp"),
  lhs: conditionLhsSchema,
  op: conditionCmpOpSchema,
  rhs: conditionRhsSchema,
});
export type ConditionCmp = z.infer<typeof conditionCmpSchema>;

// Boolean combinators. Modelled as `z.lazy` so the recursive `clauses`
// array typechecks. We capped depth at "whatever fits in YAML" since a
// 10-deep AND/OR in a workflow file is its own code smell.
export type ConditionAnd = { kind: "and"; clauses: ConditionExpr[] };
export type ConditionOr = { kind: "or"; clauses: ConditionExpr[] };
export type ConditionExpr = ConditionCmp | ConditionAnd | ConditionOr;

export const conditionExprSchema: z.ZodType<ConditionExpr> = z.lazy(() =>
  z.union([
    conditionCmpSchema,
    z.object({
      kind: z.literal("and"),
      clauses: z.array(conditionExprSchema).min(1),
    }),
    z.object({
      kind: z.literal("or"),
      clauses: z.array(conditionExprSchema).min(1),
    }),
  ]),
);

// ── Transitions ─────────────────────────────────────────────────────────────

// A transition either targets a named state OR halts the workflow.
//   { to: "triage" }          → step to the named state next
//   { to: "__end__" }         → terminate the workflow successfully
// We model halt as a reserved identifier rather than a separate field so
// the YAML round-trips cleanly through the same loader path.
export const HALT_STATE = "__end__";

export const transitionTargetSchema = z
  .string()
  .min(1)
  .regex(/^[A-Za-z_][A-Za-z0-9_-]*$/, "state names must be identifier-shaped");

export const transitionRefSchema = z.object({
  to: transitionTargetSchema,
});
export type TransitionRef = z.infer<typeof transitionRefSchema>;

export const transitionRuleSchema = z.object({
  when: conditionExprSchema,
  to: transitionTargetSchema,
});
export type TransitionRule = z.infer<typeof transitionRuleSchema>;

// ── States ──────────────────────────────────────────────────────────────────

export const stateDefSchema = z.object({
  // Named specialist this state invokes. The string is resolved at
  // orchestrator dispatch time (#249); this schema only validates the
  // shape, not the existence of the specialist.
  specialist: z.string().min(1),
  // Default-happy-path transition. Optional — a state can rely entirely
  // on `transitions[].when` rules or terminate via `__end__`.
  on_success: transitionRefSchema.optional(),
  // Default-error transition. When omitted, the orchestrator surfaces
  // the error per its own policy (today: halt with status `failed`).
  on_failure: transitionRefSchema.optional(),
  // Ordered rule list. Evaluated top-to-bottom by the orchestrator; the
  // first rule whose `when` matches wins. Falls through to on_success /
  // on_failure when no rule matches.
  transitions: z.array(transitionRuleSchema).optional(),
});
export type StateDef = z.infer<typeof stateDefSchema>;

// ── Specialists (optional reference table) ──────────────────────────────────
//
// Workflows MAY declare a `specialists:` block that maps a short name to
// a longer reference (e.g. an internal agent ID, a future MCP server URL,
// or a model alias). This is purely documentary in the v1 schema — the
// orchestrator looks up specialists by the `state.specialist` name and is
// free to ignore the ref. We capture it so workflows can self-document
// and so future versions can hook richer dispatch semantics here without
// schema migrations.
export const specialistRefSchema = z.object({
  ref: z.string().min(1),
  description: z.string().optional(),
});
export type SpecialistRef = z.infer<typeof specialistRefSchema>;

// ── Top-level WorkflowDefinition ────────────────────────────────────────────

export const workflowDefinitionSchema = z
  .object({
    name: z
      .string()
      .min(1)
      .regex(/^[A-Za-z][A-Za-z0-9_-]*$/, "workflow name must be identifier-shaped"),
    version: z.number().int().positive(),
    description: z.string().min(1),
    initial_state: transitionTargetSchema,
    states: z.record(z.string(), stateDefSchema).refine((v) => Object.keys(v).length > 0, {
      message: "workflow must declare at least one state",
    }),
    specialists: z.record(z.string(), specialistRefSchema).optional(),
  })
  // Cross-field check: every `to:` target must reference a declared state
  // or the reserved `__end__` halt sentinel, and `initial_state` must exist.
  // We do this here (rather than in the loader) so the schema is the single
  // source of truth for "what does a valid workflow look like".
  .superRefine((wf, ctx) => {
    const stateNames = new Set(Object.keys(wf.states));
    const targetOk = (t: string) => t === HALT_STATE || stateNames.has(t);

    if (!targetOk(wf.initial_state)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["initial_state"],
        message: `initial_state '${wf.initial_state}' is not declared in states`,
      });
    }

    for (const [stateName, state] of Object.entries(wf.states)) {
      if (state.on_success && !targetOk(state.on_success.to)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["states", stateName, "on_success", "to"],
          message: `on_success.to '${state.on_success.to}' references an unknown state`,
        });
      }
      if (state.on_failure && !targetOk(state.on_failure.to)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["states", stateName, "on_failure", "to"],
          message: `on_failure.to '${state.on_failure.to}' references an unknown state`,
        });
      }
      state.transitions?.forEach((rule, idx) => {
        if (!targetOk(rule.to)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["states", stateName, "transitions", idx, "to"],
            message: `transitions[${idx}].to '${rule.to}' references an unknown state`,
          });
        }
      });
    }
  });

export type WorkflowDefinition = z.infer<typeof workflowDefinitionSchema>;
