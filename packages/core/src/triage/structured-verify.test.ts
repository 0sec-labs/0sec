import { describe, it, expect } from "vitest";
import {
  runSelfConsistencyVerify,
  tallyConsensus,
  type VerifyFn,
  type VerifyResult,
} from "./structured-verify.js";
import type { AttackCategory, Finding } from "@pwnkit/shared";
import type { NativeRuntime } from "../runtime/types.js";

function makeFinding(): Finding {
  return {
    id: "consensus-test",
    templateId: "audit-sink",
    title: "Possible SQL injection",
    description: "User input flows into a SQL query.",
    severity: "high",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: {
      request: "GET /items?id=1' OR 1=1-- HTTP/1.1",
      response: "HTTP/1.1 200 OK\n\n[{\"id\":1}, {\"id\":2}]",
    },
    confidence: 0.7,
    timestamp: Date.now(),
  };
}

function fakeVerifyResult(verdict: "confirmed" | "rejected"): VerifyResult {
  return {
    verdict,
    confidence: 0.9,
    steps: [],
    reasoning: `fake ${verdict}`,
  };
}

/**
 * Build a VerifyFn mock that returns the given verdicts in FIFO order.
 * Every call consumes one verdict from the queue.
 */
function queueVerifier(verdicts: Array<"confirmed" | "rejected">): VerifyFn {
  const queue = [...verdicts];
  return async () => {
    const next = queue.shift();
    if (!next) throw new Error("verifier called more times than expected");
    return fakeVerifyResult(next);
  };
}

// A NativeRuntime stand-in — runSelfConsistencyVerify never touches it when
// a mock verifyFn is provided, so an `as any` cast is safe here.
const fakeRuntime = {} as NativeRuntime;

describe("tallyConsensus", () => {
  it("returns confirmed with confidence 1.0 when all runs agree", () => {
    const runs = [
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
    ];
    const result = tallyConsensus(runs);
    expect(result.verdict).toBe("confirmed");
    expect(result.confidence).toBe(1.0);
    expect(result.agreement).toBe(1.0);
  });

  it("returns confirmed with confidence 0.8 on a 4/5 split", () => {
    const runs = [
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("rejected"),
    ];
    const result = tallyConsensus(runs);
    expect(result.verdict).toBe("confirmed");
    expect(result.confidence).toBe(0.8);
  });

  it("returns confirmed with confidence 0.6 on a 3/5 split", () => {
    const runs = [
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("rejected"),
      fakeVerifyResult("rejected"),
    ];
    const result = tallyConsensus(runs);
    expect(result.verdict).toBe("confirmed");
    expect(result.confidence).toBe(0.6);
  });

  it("returns rejected with confidence 0.6 on a 2/5 confirmed split", () => {
    const runs = [
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("confirmed"),
      fakeVerifyResult("rejected"),
      fakeVerifyResult("rejected"),
      fakeVerifyResult("rejected"),
    ];
    const result = tallyConsensus(runs);
    expect(result.verdict).toBe("rejected");
    expect(result.confidence).toBe(0.6);
  });

  it("throws on an empty runs array", () => {
    expect(() => tallyConsensus([])).toThrow();
  });
});

describe("runSelfConsistencyVerify", () => {
  // earlyStopThreshold > 1 disables early termination so every run completes,
  // making the test deterministic regardless of Promise settle ordering.
  const finding = makeFinding();

  it("5/5 confirmed → confidence 1.0, verdict confirmed", async () => {
    const result = await runSelfConsistencyVerify(finding, "http://t", fakeRuntime, {
      numRuns: 5,
      earlyStopThreshold: 2,
      verifyFn: queueVerifier([
        "confirmed",
        "confirmed",
        "confirmed",
        "confirmed",
        "confirmed",
      ]),
    });
    expect(result.verdict).toBe("confirmed");
    expect(result.confidence).toBe(1.0);
    expect(result.runs).toHaveLength(5);
  });

  it("4/5 confirmed → confidence 0.8, verdict confirmed", async () => {
    const result = await runSelfConsistencyVerify(finding, "http://t", fakeRuntime, {
      numRuns: 5,
      earlyStopThreshold: 2,
      verifyFn: queueVerifier([
        "confirmed",
        "confirmed",
        "confirmed",
        "confirmed",
        "rejected",
      ]),
    });
    expect(result.verdict).toBe("confirmed");
    expect(result.confidence).toBe(0.8);
    expect(result.runs).toHaveLength(5);
  });

  it("3/5 confirmed → confidence 0.6, verdict confirmed", async () => {
    const result = await runSelfConsistencyVerify(finding, "http://t", fakeRuntime, {
      numRuns: 5,
      earlyStopThreshold: 2,
      verifyFn: queueVerifier([
        "confirmed",
        "confirmed",
        "confirmed",
        "rejected",
        "rejected",
      ]),
    });
    expect(result.verdict).toBe("confirmed");
    expect(result.confidence).toBe(0.6);
    expect(result.runs).toHaveLength(5);
  });

  it("2/5 confirmed → confidence 0.6, verdict rejected (majority rejected)", async () => {
    const result = await runSelfConsistencyVerify(finding, "http://t", fakeRuntime, {
      numRuns: 5,
      earlyStopThreshold: 2,
      verifyFn: queueVerifier([
        "confirmed",
        "confirmed",
        "rejected",
        "rejected",
        "rejected",
      ]),
    });
    expect(result.verdict).toBe("rejected");
    expect(result.confidence).toBe(0.6);
    expect(result.runs).toHaveLength(5);
  });

  it("early-stops once the majority can no longer be overturned", async () => {
    // With numRuns=5 and every run returning "confirmed", the ensemble
    // should return as soon as it becomes impossible for the rejected pile
    // to catch up (i.e. after 3 unanimous confirmations out of 5 — the
    // remaining 2 cannot flip the majority).
    let calls = 0;
    const result = await runSelfConsistencyVerify(finding, "http://t", fakeRuntime, {
      numRuns: 5,
      earlyStopThreshold: 0.8,
      verifyFn: async () => {
        calls += 1;
        return fakeVerifyResult("confirmed");
      },
    });
    expect(result.verdict).toBe("confirmed");
    expect(result.confidence).toBe(1.0);
    // All 5 runs are launched in parallel.
    expect(calls).toBe(5);
    // But the resolved result reflects only the minimum needed to decide.
    expect(result.runs.length).toBeLessThan(5);
    expect(result.runs.length).toBeGreaterThanOrEqual(3);
  });

  it("honours numRuns=1 by executing a single verify call", async () => {
    let calls = 0;
    const result = await runSelfConsistencyVerify(finding, "http://t", fakeRuntime, {
      numRuns: 1,
      verifyFn: async () => {
        calls += 1;
        return fakeVerifyResult("confirmed");
      },
    });
    expect(calls).toBe(1);
    expect(result.verdict).toBe("confirmed");
    expect(result.confidence).toBe(1.0);
    expect(result.runs).toHaveLength(1);
  });
});
