import { describe, expect, it } from "vitest";

import {
  createResearchProposal,
  digestTargetSnapshot,
  validateResearchProposal,
  type CreateResearchProposalInput,
  type TargetSourceSnapshot,
} from "./proposal.js";

const target: TargetSourceSnapshot = {
  targetId: "parser-v1",
  targetFamily: "example-parser",
  files: [
    { path: "src/parser.c", content: "int parse(char *p) {\n  return p[0];\n}\n" },
    { path: "include/parser.h", content: "int parse(char *p);\n" },
  ],
};

function input(overrides: Partial<CreateResearchProposalInput> = {}): CreateResearchProposalInput {
  return {
    target,
    generator: { id: "target-observer-v1", digest: `sha256:${"a".repeat(64)}` },
    origin: "target_observation",
    kind: "input_boundary",
    observedFact: "parse reads from the supplied pointer without a visible length parameter.",
    falsifiableQuestion: "Can an empty input reach the indexed read?",
    citations: [{ path: "src/parser.c", startLine: 1, endLine: 2, symbol: "parse" }],
    features: {
      crossesTrustBoundary: 1,
      hasStateTransition: 0,
      hasBehavioralDifferential: 0,
      externallyReachable: 1,
    },
    ...overrides,
  };
}

describe("research proposals", () => {
  it("binds proposals to real cited target bytes deterministically", () => {
    const proposal = createResearchProposal(input());
    const reorderedTarget = { ...target, files: [...target.files].reverse() };
    const reordered = createResearchProposal(input({ target: reorderedTarget }));

    expect(reordered).toEqual(proposal);
    expect(proposal.features.citedSpanCount).toBe(1);
    expect(proposal.features.distinctFileCount).toBe(1);
    expect(validateResearchProposal(proposal)).toEqual(proposal);
  });

  it("changes target and proposal identity when cited source changes", () => {
    const changed = {
      ...target,
      files: target.files.map((file) =>
        file.path === "src/parser.c" ? { ...file, content: file.content.replace("p[0]", "p[1]") } : file,
      ),
    };

    expect(digestTargetSnapshot(changed)).not.toBe(digestTargetSnapshot(target));
    expect(createResearchProposal(input({ target: changed })).id).not.toBe(
      createResearchProposal(input()).id,
    );
  });

  it("rejects fabricated paths, traversal, and invalid line ranges", () => {
    expect(() => createResearchProposal(input({ citations: [{ path: "src/missing.c", startLine: 1, endLine: 1 }] }))).toThrow(
      /not in the target snapshot/,
    );
    expect(() => createResearchProposal(input({ citations: [{ path: "../parser.c", startLine: 1, endLine: 1 }] }))).toThrow(
      /repository-relative/,
    );
    expect(() => createResearchProposal(input({ citations: [{ path: "src/parser.c", startLine: 1, endLine: 99 }] }))).toThrow(
      /exceeds/,
    );
  });

  it("keeps memory-derived priors explicit in immutable proposal identity", () => {
    const observed = createResearchProposal(input());
    const fromMemory = createResearchProposal(
      input({ origin: "memory_prior", parentProposalIds: [observed.id] }),
    );

    expect(fromMemory.origin).toBe("memory_prior");
    expect(fromMemory.parentProposalIds).toEqual([observed.id]);
    expect(fromMemory.id).not.toBe(observed.id);
  });

  it("rejects tampered identifiers and derived feature counts", () => {
    const proposal = createResearchProposal(input());
    expect(() => validateResearchProposal({ ...proposal, observedFact: "tampered" })).toThrow(
      /canonical content digest/,
    );
    expect(() =>
      validateResearchProposal({ ...proposal, features: { ...proposal.features, citedSpanCount: 2 } }),
    ).toThrow(/canonical content digest/);
  });
});
