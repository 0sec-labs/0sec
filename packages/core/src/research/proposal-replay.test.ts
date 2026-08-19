import { mkdtempSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { createResearchProposal } from "./proposal.js";
import {
  appendProposalAttempt,
  createProposalAttempt,
  proposalTrainingExamples,
  readProposalReplay,
  serializeProposalReplay,
  validateProposalAttempt,
  validateProposalReplay,
  type CreateProposalAttemptInput,
} from "./proposal-replay.js";

const digest = (char: string) => `sha256:${char.repeat(64)}`;
const evidence = (kind: "deterministic_oracle" | "sanitizer" | "journal" | "model_report", char: string) => ({
  kind,
  digest: digest(char),
  producer: { id: "independent-verifier-v1", digest: digest("9") },
});

function proposal(targetId = "parser-v1", targetFamily = "parser-family") {
  return createResearchProposal({
    target: {
      targetId,
      targetFamily,
      files: [{ path: "parser.c", content: "int parse(char *p) { return p[0]; }\n" }],
    },
    generator: { id: "observer-v1", digest: digest("a") },
    origin: "target_observation",
    kind: "input_boundary",
    observedFact: "The parser indexes caller-controlled input.",
    falsifiableQuestion: "Can an empty input reach this read?",
    citations: [{ path: "parser.c", startLine: 1, endLine: 1 }],
    features: {
      crossesTrustBoundary: 1,
      hasStateTransition: 0,
      hasBehavioralDifferential: 0,
      externallyReachable: 1,
    },
  });
}

function attempt(overrides: Partial<CreateProposalAttemptInput> = {}) {
  return createProposalAttempt({
    proposal: proposal(),
    experiment: { id: "asan-replay-v1", digest: digest("b") },
    outcome: "confirmed",
    evidence: [evidence("sanitizer", "c")],
    ...overrides,
  });
}

describe("proposal replay", () => {
  it("content-addresses independently evidenced outcomes", () => {
    const result = attempt();
    expect(validateProposalAttempt(result)).toEqual(result);
    expect(serializeProposalReplay([result])).toContain(result.id);
  });

  it("does not accept a model or journal assertion as a truth label", () => {
    expect(() =>
      attempt({ evidence: [evidence("model_report", "d")] }),
    ).toThrow(/deterministic truth evidence/);
    expect(() =>
      attempt({ outcome: "refuted", evidence: [evidence("journal", "d")] }),
    ).toThrow(/deterministic truth evidence/);
  });

  it("requires adequate measured coverage before learning a negative", () => {
    expect(() =>
      attempt({ outcome: "refuted", evidence: [evidence("deterministic_oracle", "d")] }),
    ).toThrow(/adequate coverage/);

    const refuted = attempt({
      outcome: "refuted",
      evidence: [evidence("deterministic_oracle", "d")],
      coverage: { adequate: true, digest: digest("e") },
    });
    expect(proposalTrainingExamples([refuted])).toHaveLength(1);
    expect(proposalTrainingExamples([refuted])[0]?.label).toBe(0);
  });

  it("excludes censored and duplicate outcomes from training", () => {
    const base = proposal();
    const untried = attempt({ proposal: base, outcome: "untried", evidence: [] });
    const inconclusive = attempt({ proposal: base, outcome: "inconclusive", evidence: [] });
    const duplicate = attempt({
      proposal: base,
      outcome: "duplicate",
      duplicateOfProposalId: proposal("parser-v0").id,
    });
    expect(proposalTrainingExamples([untried, inconclusive, duplicate])).toEqual([]);
  });

  it("rejects tampering, duplicate attempts, and contradictory truth labels", () => {
    const confirmed = attempt();
    expect(() => validateProposalAttempt({ ...confirmed, outcome: "inconclusive" })).toThrow(
      /canonical content digest/,
    );
    expect(() => validateProposalReplay([confirmed, confirmed])).toThrow(/duplicate attempt/);

    const refuted = attempt({
      outcome: "refuted",
      evidence: [evidence("deterministic_oracle", "f")],
      coverage: { adequate: true, digest: digest("e") },
    });
    expect(() => validateProposalReplay([confirmed, refuted])).toThrow(/conflicting truth labels/);
  });

  it("does not let the proposal generator verify its own truth label", () => {
    expect(() =>
      attempt({
        evidence: [
          {
            kind: "deterministic_oracle",
            digest: digest("c"),
            producer: { id: "observer-v1", digest: digest("a") },
          },
        ],
      }),
    ).toThrow(/independent producer/);
  });

  it("durably appends validated JSONL records and refuses symlink sinks", () => {
    const directory = mkdtempSync(join(tmpdir(), "proposal-replay-"));
    const path = join(directory, "replay.jsonl");
    const confirmed = attempt();
    appendProposalAttempt(path, confirmed);
    expect(readProposalReplay(path)).toEqual([confirmed]);
    expect(() => appendProposalAttempt(path, confirmed)).toThrow(/duplicate attempt/);

    const link = join(directory, "linked.jsonl");
    symlinkSync(path, link);
    expect(() => appendProposalAttempt(link, confirmed)).toThrow(/symbolic link/);
  });
});
