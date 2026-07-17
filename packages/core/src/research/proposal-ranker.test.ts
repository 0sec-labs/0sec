import { describe, expect, it } from "vitest";

import { createResearchProposal, type ProposalKind } from "./proposal.js";
import { createProposalAttempt } from "./proposal-replay.js";
import { rankResearchProposals, trainProposalRanker } from "./proposal-ranker.js";

const digest = (char: string) => `sha256:${char.repeat(64)}`;

function proposal(
  suffix: string,
  family: string,
  kind: ProposalKind,
  reachable: 0 | 1,
) {
  return createResearchProposal({
    target: {
      targetId: `target-${suffix}`,
      targetFamily: family,
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

function labeled(value: ReturnType<typeof proposal>, label: 0 | 1, char: string) {
  return createProposalAttempt({
    proposal: value,
    experiment: { id: `experiment-${char}`, digest: digest(char) },
    outcome: label === 1 ? "confirmed" : "refuted",
    evidence: [
      {
        kind: "deterministic_oracle",
        digest: digest(char),
        producer: { id: "independent-verifier-v1", digest: digest("9") },
      },
    ],
    ...(label === 0 ? { coverage: { adequate: true, digest: digest("f") } } : {}),
  });
}

describe("proposal ranker", () => {
  it("is explicitly untrained without both trustworthy classes", () => {
    const candidate = proposal("alpha", "family-a", "input_boundary", 1);
    const model = trainProposalRanker([labeled(candidate, 1, "b")]);
    expect(model.status).toBe("untrained");
    expect(Object.values(model.weights).every((weight) => weight === 0)).toBe(true);
  });

  it("trains byte-identically and excludes held-out target families", () => {
    const positive = labeled(proposal("positive", "train-family", "input_boundary", 1), 1, "b");
    const negative = labeled(proposal("negative", "train-family", "lifecycle", 0), 0, "c");
    const heldout = labeled(proposal("heldout", "heldout-family", "state_transition", 1), 1, "d");
    const first = trainProposalRanker([positive, negative, heldout], {
      heldoutTargetFamilies: ["heldout-family"],
    });
    const second = trainProposalRanker([positive, negative, heldout], {
      heldoutTargetFamilies: ["heldout-family"],
    });
    expect(second).toEqual(first);
    expect(first.status).toBe("trained");
    expect(first.heldoutCount).toBe(1);
    expect(first.seenKinds).not.toContain("state_transition");
  });

  it("uses diversity at cold start without dropping any proposal", () => {
    const values = [
      proposal("one", "family-a", "input_boundary", 1),
      proposal("two", "family-b", "state_transition", 0),
      proposal("three", "family-c", "behavior_differential", 0),
    ];
    const ranked = rankResearchProposals(trainProposalRanker([]), values);
    expect(ranked.every((item) => item.selection === "explore")).toBe(true);
    expect(new Set(ranked.map((item) => item.proposal.id))).toEqual(new Set(values.map((item) => item.id)));
  });

  it("learns ordering while reserving explicit exploration slots", () => {
    const positive = labeled(proposal("positive", "family-a", "input_boundary", 1), 1, "b");
    const negative = labeled(proposal("negative", "family-b", "lifecycle", 0), 0, "c");
    const model = trainProposalRanker([positive, negative]);
    const values = [
      proposal("a1", "family-c", "input_boundary", 1),
      proposal("a2", "family-d", "input_boundary", 1),
      proposal("a3", "family-e", "lifecycle", 0),
      proposal("novel", "family-f", "state_transition", 0),
    ];
    const ranked = rankResearchProposals(model, values, { explorationFraction: 0.25 });
    expect(ranked.filter((item) => item.selection === "explore")).toHaveLength(1);
    expect(ranked.find((item) => item.selection === "explore")?.proposal.kind).toBe("state_transition");
    expect(new Set(ranked.map((item) => item.proposal.id))).toEqual(new Set(values.map((item) => item.id)));
  });
});
