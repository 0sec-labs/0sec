import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createResearchProposal, type ProposalKind } from "./proposal.js";
import {
  createProposalAttempt,
  readProposalReplay,
  type ProposalOutcome,
} from "./proposal-replay.js";
import { runProposalLearningLoop } from "./proposal-learning-loop.js";

const digest = (char: string) => `sha256:${char.repeat(64)}`;

function proposal(suffix: string, kind: ProposalKind, reachable: 0 | 1 = 0) {
  return createResearchProposal({
    target: {
      targetId: `target-${suffix}`,
      targetFamily: `family-${suffix}`,
      files: [{ path: `src/${suffix}.c`, content: `int ${suffix}(char *p) { return p[0]; }\n` }],
    },
    generator: { id: "observer-v1", digest: digest("a") },
    origin: "target_observation",
    kind,
    observedFact: `${suffix} reads target-derived state.`,
    falsifiableQuestion: `Can ${suffix} violate its inferred boundary?`,
    citations: [{ path: `src/${suffix}.c`, startLine: 1, endLine: 1 }],
    features: {
      crossesTrustBoundary: reachable,
      hasStateTransition: kind === "state_transition" ? 1 : 0,
      hasBehavioralDifferential: kind === "behavior_differential" ? 1 : 0,
      externallyReachable: reachable,
    },
  });
}

function attempt(
  value: ReturnType<typeof proposal>,
  outcome: ProposalOutcome,
  char: string,
) {
  return createProposalAttempt({
    proposal: value,
    experiment: { id: `experiment-${char}`, digest: digest(char) },
    outcome,
    evidence:
      outcome === "confirmed" || outcome === "refuted" || outcome === "duplicate"
        ? [
            {
              kind: "deterministic_oracle",
              digest: digest(char),
              producer: { id: "independent-verifier-v1", digest: digest("9") },
            } as const,
          ]
        : [],
    ...(outcome === "refuted"
      ? { coverage: { adequate: true, digest: digest("f") } }
      : {}),
    ...(outcome === "duplicate"
      ? { duplicateOfProposalId: proposal("prior", "lifecycle").id }
      : {}),
  });
}

function replayPath(): string {
  return join(mkdtempSync(join(tmpdir(), "proposal-learning-")), "replay.jsonl");
}

describe("automatic proposal learning loop", () => {
  it("starts label-free, stays bounded, and preserves deferred hypotheses", async () => {
    const path = replayPath();
    const values = [
      proposal("alpha", "input_boundary"),
      proposal("beta", "state_transition"),
      proposal("gamma", "behavior_differential"),
    ];
    const result = await runProposalLearningLoop({
      proposals: values,
      replayPath: path,
      maxAttempts: 2,
      execute: async (selected, context) => {
        expect(context.model.status).toBe("untrained");
        return attempt(selected, "inconclusive", String(context.attemptNumber));
      },
    });

    expect(result.modelBefore.status).toBe("untrained");
    expect(result.attempted).toHaveLength(2);
    expect(result.deferredProposalIds).toHaveLength(1);
    expect(readProposalReplay(path)).toEqual(result.attempted);
  });

  it("learns online after independent positive and negative evidence", async () => {
    const path = replayPath();
    const positive = proposal("positive", "input_boundary", 1);
    const negative = proposal("negative", "lifecycle", 0);
    const result = await runProposalLearningLoop({
      proposals: [positive, negative],
      replayPath: path,
      maxAttempts: 2,
      explorationFraction: 0,
      execute: async (selected, context) => {
        if (context.attemptNumber === 1) return attempt(selected, "confirmed", "b");
        return attempt(selected, "refuted", "c");
      },
    });

    expect(result.modelBefore.status).toBe("untrained");
    expect(result.modelAfter.status).toBe("trained");
    expect(result.modelAfter.positiveCount).toBe(1);
    expect(result.modelAfter.negativeCount).toBe(1);
  });

  it("rejects mismatched executor output without fabricating a label", async () => {
    const path = replayPath();
    const selected = proposal("selected", "input_boundary");
    const other = proposal("other", "lifecycle");
    const result = await runProposalLearningLoop({
      proposals: [selected],
      replayPath: path,
      maxAttempts: 1,
      execute: async () => attempt(other, "confirmed", "b"),
    });

    expect(result.attempted).toEqual([]);
    expect(result.warnings[0]).toMatch(/expected/);
    expect(result.deferredProposalIds).toEqual([selected.id]);
    expect(readProposalReplay(path)).toEqual([]);
  });

  it("counts failed executions against the hard experiment ceiling", async () => {
    const path = replayPath();
    const values = [
      proposal("failure-one", "input_boundary"),
      proposal("failure-two", "lifecycle"),
    ];
    let calls = 0;
    const result = await runProposalLearningLoop({
      proposals: values,
      replayPath: path,
      maxAttempts: 1,
      execute: async () => {
        calls += 1;
        throw new Error("verifier unavailable");
      },
    });

    expect(calls).toBe(1);
    expect(result.attempted).toEqual([]);
    expect(result.deferredProposalIds).toHaveLength(2);
    expect(result.warnings[0]).toMatch(/verifier unavailable/);
  });

  it("does not spend budget rechecking terminal proposals by default", async () => {
    const path = replayPath();
    const terminal = proposal("terminal", "input_boundary");
    const first = await runProposalLearningLoop({
      proposals: [terminal],
      replayPath: path,
      maxAttempts: 1,
      execute: async (selected) => attempt(selected, "confirmed", "b"),
    });
    expect(first.attempted).toHaveLength(1);

    let called = false;
    const second = await runProposalLearningLoop({
      proposals: [terminal],
      replayPath: path,
      maxAttempts: 1,
      execute: async () => {
        called = true;
        throw new Error("must not run");
      },
    });
    expect(called).toBe(false);
    expect(second.skippedTerminalProposalIds).toEqual([terminal.id]);
  });
});
