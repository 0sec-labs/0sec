import { describe, expect, it } from "vitest";

import { proposalsFromInvariantViolations } from "./target-proposal-generator.js";

const digest = `sha256:${"a".repeat(64)}`;

describe("target-derived proposal generators", () => {
  it("turns deterministic invariant violations into cited, unconfirmed proposals", () => {
    const proposals = proposalsFromInvariantViolations({
      target: {
        targetId: "kernel-revision-a",
        targetFamily: "kernel-nfc",
        files: [
          {
            path: "net/nfc/example.c",
            content: "void release(struct obj *o) {\n  put_obj(o);\n  use_obj(o);\n}\n",
          },
        ],
      },
      generator: { id: "invariant-checker-v1", digest },
      violations: [
        {
          kind: "use-after-free-order",
          object: "struct obj",
          file: "net/nfc/example.c",
          line: 3,
          functionName: "release",
          invariant: "o must not be used after put_obj",
          detail: "use_obj observes o after its release",
        },
      ],
      externallyReachable: () => true,
    });

    expect(proposals).toHaveLength(1);
    expect(proposals[0]?.origin).toBe("spec_invariant");
    expect(proposals[0]?.kind).toBe("lifecycle");
    expect(proposals[0]?.citations[0]).toMatchObject({
      path: "net/nfc/example.c",
      startLine: 3,
      endLine: 3,
      symbol: "release",
    });
    expect(proposals[0]).not.toHaveProperty("outcome");
  });

  it("fails closed when a checker points outside the bound target snapshot", () => {
    expect(() =>
      proposalsFromInvariantViolations({
        target: {
          targetId: "kernel-revision-a",
          targetFamily: "kernel-nfc",
          files: [{ path: "real.c", content: "int main(void) {}\n" }],
        },
        generator: { id: "invariant-checker-v1", digest },
        violations: [
          {
            kind: "unlocked-field-access",
            object: "struct obj",
            file: "invented.c",
            line: 1,
            functionName: "invented",
            invariant: "field is guarded",
            detail: "invented access",
          },
        ],
      }),
    ).toThrow(/not in the target snapshot/);
  });
});
