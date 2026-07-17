import type { InvariantViolation } from "../stages/subsystem-invariant-model.js";
import {
  createResearchProposal,
  type ResearchProposal,
  type TargetSourceSnapshot,
} from "./proposal.js";

export interface InvariantViolationProposalInput {
  target: TargetSourceSnapshot;
  /** Binds the exact stored invariant model plus deterministic checker build. */
  generator: { id: string; digest: string };
  violations: readonly InvariantViolation[];
  externallyReachable?: (violation: InvariantViolation) => boolean;
}

/**
 * Converts deterministic, target-derived invariant violations into immutable
 * experiment proposals. It deliberately does not infer truth: every output
 * still requires an independent replay/oracle attempt.
 */
export function proposalsFromInvariantViolations(
  input: InvariantViolationProposalInput,
): ResearchProposal[] {
  const externallyReachable = input.externallyReachable ?? (() => false);
  return input.violations.map((violation) =>
    createResearchProposal({
      target: input.target,
      generator: input.generator,
      origin: "spec_invariant",
      kind:
        violation.kind === "use-after-free-order"
          ? "lifecycle"
          : violation.kind === "refcount-imbalance"
            ? "resource_balance"
            : "state_transition",
      observedFact: `${violation.detail} The deterministic checker reported this at ${violation.file}:${violation.line}.`,
      falsifiableQuestion: `Does an independently executed reproducer violate this invariant: ${violation.invariant}?`,
      citations: [
        {
          path: violation.file,
          startLine: violation.line,
          endLine: violation.line,
          ...(violation.functionName ? { symbol: violation.functionName } : {}),
        },
      ],
      features: {
        crossesTrustBoundary: externallyReachable(violation) ? 1 : 0,
        hasStateTransition: violation.kind === "unlocked-field-access" ? 1 : 0,
        hasBehavioralDifferential: 0,
        externallyReachable: externallyReachable(violation) ? 1 : 0,
      },
    }),
  );
}
