import { describe, expect, it } from "vitest";
import { CraftEvidenceLedger, mergeCraftEvidence } from "./craft-evidence-ledger.js";

describe("CraftEvidenceLedger", () => {
  it("records bounded deterministic observations without retaining mutable sources", () => {
    const ledger = new CraftEvidenceLedger();
    ledger.record({
      kind: "self-test",
      status: "refuted",
      summary: "candidate did not trigger the vulnerable binary",
      step: 4,
      candidateSha256: "abc123",
      source: { path: "fuzz/entry.cc", line: 17 },
    });

    const receipt = ledger.snapshot();
    expect(receipt).toEqual([
      {
        sequence: 1,
        kind: "self-test",
        status: "refuted",
        summary: "candidate did not trigger the vulnerable binary",
        step: 4,
        candidateSha256: "abc123",
        source: { path: "fuzz/entry.cc", line: 17 },
      },
    ]);

    receipt[0].source!.path = "changed";
    expect(ledger.snapshot()[0].source?.path).toBe("fuzz/entry.cc");
  });

  it("keeps a visible marker when evidence capacity is reached", () => {
    const ledger = new CraftEvidenceLedger();
    for (let index = 0; index < 257; index++) {
      ledger.record({ kind: "self-test", status: "observed", summary: `test ${index}` });
    }

    const receipt = ledger.snapshot();
    expect(receipt).toHaveLength(257);
    expect(receipt.at(-1)).toMatchObject({
      kind: "oracle",
      status: "inconclusive",
      summary: "evidence ledger capacity reached; later observations omitted",
    });
  });

  it("re-sequences independent trajectory ledgers without dropping their origin", () => {
    const merged = mergeCraftEvidence([
      [{ sequence: 1, kind: "target-spec", status: "observed", summary: "entrypoint located" }],
      [
        { sequence: 1, kind: "self-test", status: "refuted", summary: "candidate did not trigger" },
        { sequence: 2, kind: "run-summary", status: "refuted", summary: "self-tests=1; vulnerable-crashes=0" },
      ],
    ]);

    expect(merged).toEqual([
      { sequence: 1, trajectory: 1, kind: "target-spec", status: "observed", summary: "entrypoint located" },
      { sequence: 2, trajectory: 2, kind: "self-test", status: "refuted", summary: "candidate did not trigger" },
      { sequence: 3, trajectory: 2, kind: "run-summary", status: "refuted", summary: "self-tests=1; vulnerable-crashes=0" },
    ]);
  });
});
