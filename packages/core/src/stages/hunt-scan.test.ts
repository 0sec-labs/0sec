/**
 * `runHuntScan` best-of-N + judge gate. Mock-at-module-boundary for the
 * finder (`agenticScan`, mirrors `unified-pipeline.dispatch.test.ts`'s
 * strategy) so these tests never make a real LLM call; the `verify` and
 * `judgeCandidates` seams are already injectable so tests supply plain fakes.
 *
 * Coverage:
 *   - Backward compat: attemptsPerCandidate=1 / judgeTopK=1 (unset env knobs)
 *     reproduces today's candidate × model fan-out byte-for-byte, INCLUDING
 *     the model-diversity case (multiple models on one candidate) — the judge
 *     never fires and every finding reaches `verify` individually.
 *   - Best-of-N: attemptsPerCandidate>1 surfaces >1 finding at a site; only
 *     the judge's top-judgeTopK reach `verify`, keeping skeptic call-count
 *     flat while `records` still carries the full judged pool (never
 *     flattened to titles).
 *   - No-brief fallback: attemptsPerCandidate>1 with no `brief` skips the
 *     judge (no bug-class/pattern to score against) and keeps the first
 *     `judgeTopK` attempts in order.
 *   - Flywheel wiring (PWNKIT_HUNT_FLYWHEEL=1, hunt-flywheel.ts): with
 *     judgeTopK == group size (nothing dropped), priming reorders which
 *     finding `verify` is called on FIRST, but the resulting `confirmed` SET
 *     is byte-identical to the flag-off run — the primes-never-confirms
 *     invariant, proven at the real `runHuntScan` integration seam (not just
 *     the standalone flywheel module — see hunt-flywheel.test.ts for that).
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";
import { HuntMemory } from "./hunt-flywheel.js";

const agenticScanMock = vi.fn();
vi.mock("../agentic-scanner.js", () => ({
  agenticScan: (...args: unknown[]) => agenticScanMock(...args),
}));

const { runHuntScan } = await import("./hunt-scan.js");

function mkFinding(id: string, title: string, analysis: string): Finding {
  return {
    id,
    templateId: "hunt-test",
    title,
    description: title,
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis },
    timestamp: 1_700_000_000_000,
  };
}

describe("runHuntScan — best-of-N + judge gate", () => {
  it("attemptsPerCandidate=1/judgeTopK=1 (defaults) reproduces plain candidate × model fan-out, including model diversity", async () => {
    agenticScanMock.mockReset();
    // Two models, one candidate: each model's finder call returns ONE finding.
    agenticScanMock.mockImplementation(async ({ config }: { config: { model?: string } }) => ({
      findings: [mkFinding(`f-${config.model}`, `finding from ${config.model}`, "")],
    }));

    const verifyCalls: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      verifyCalls.push(finding.id);
      return { confirmed: true, reason: "ok" };
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }],
      models: ["model-a", "model-b"],
      runtime: "api",
      concurrency: 4,
      verify,
    });

    // No widening: both model findings go straight to verify, unmodified.
    expect(res.scanned).toBe(2); // 1 candidate × 2 models × 1 attempt
    expect(res.findings).toHaveLength(2);
    expect(verifyCalls.sort()).toEqual(["f-model-a", "f-model-b"]);
    expect(res.confirmed).toHaveLength(2);
    // No judge call: no finding carries a judge score.
    expect(res.records.every((r) => r.judgeScore === undefined)).toBe(true);
    expect(res.records.every((r) => r.skepticConfirmed === true)).toBe(true);
  });

  it("attemptsPerCandidate>1 judges the widened pool and only the top-judgeTopK reach verify", async () => {
    agenticScanMock.mockReset();
    let call = 0;
    agenticScanMock.mockImplementation(async () => {
      const i = call++;
      return { findings: [mkFinding(`f-${i}`, `attempt ${i}`, i === 2 ? "the real sink pattern" : "noise")] };
    });

    const verifyCalls: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      verifyCalls.push(finding.id);
      return { confirmed: true, reason: "survived" };
    };

    const judgeCandidates: Parameters<typeof runHuntScan>[0]["judgeCandidates"] = async (_brief, findings) => {
      const scores = new Map<string, { score: number; reason: string }>();
      for (const f of findings) {
        scores.set(f.id, { score: f.id === "f-2" ? 9 : 2, reason: f.id === "f-2" ? "matches pattern" : "noise" });
      }
      return scores;
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }],
      brief: { bugClass: "missing length check", pattern: "memcpy without bound check" },
      runtime: "api",
      concurrency: 4,
      attemptsPerCandidate: 4,
      judgeTopK: 1,
      judgeCandidates,
      verify,
    });

    expect(res.scanned).toBe(4); // 1 candidate × 1 model × 4 attempts
    expect(res.findings).toHaveLength(4);
    // Only the top-judged finding (f-2) reached verify — skeptic call-count stayed flat.
    expect(verifyCalls).toEqual(["f-2"]);
    expect(res.confirmed).toHaveLength(1);
    expect(res.confirmed[0].id).toBe("f-2");

    // Every attempt in the group is judged (never dropped from the corpus)...
    const byId = new Map(res.records.map((r) => [r.finding.id, r]));
    expect(byId.get("f-2")?.judgeScore).toBe(9);
    expect(byId.get("f-0")?.judgeScore).toBe(2);
    // ...but only the winner ran through the skeptic gate.
    expect(byId.get("f-2")?.skepticConfirmed).toBe(true);
    expect(byId.get("f-0")?.skepticConfirmed).toBeUndefined();
  });

  it("attemptsPerCandidate>1 with no brief skips the judge and keeps the first judgeTopK by attempt order", async () => {
    agenticScanMock.mockReset();
    let call = 0;
    agenticScanMock.mockImplementation(async () => {
      const i = call++;
      return { findings: [mkFinding(`f-${i}`, `attempt ${i}`, "")] };
    });

    const verifyCalls: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      verifyCalls.push(finding.id);
      return { confirmed: true, reason: "ok" };
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }],
      // no brief -> generic hunt, judge has nothing to score against
      runtime: "api",
      concurrency: 4,
      attemptsPerCandidate: 3,
      judgeTopK: 1,
      verify,
    });

    expect(res.scanned).toBe(3);
    expect(verifyCalls).toEqual(["f-0"]); // first attempt, in order
    expect(res.warnings.some((w) => w.includes("no brief to judge against"))).toBe(true);
    expect(res.records.every((r) => r.judgeScore === undefined)).toBe(true);
  });

  it("does NOT drop a confirmed finding when second-audit refine deepens two DISTINCT candidates to the same path (no brief)", async () => {
    // Regression: the best-of-N judge groups by SITE. The second-audit refiner
    // rewrites `candidate.path` to a deeper root-cause path BEFORE grouping, so
    // two symptoms of one lifetime bug — surfaced at two DISTINCT original sites
    // (a.c, b.c) — can be refined to the SAME path (core.c). Grouping on the
    // post-refine path collapsed them into one group; with no `brief` that group
    // was truncated to `judgeTopK` (default 1) with only a warning, silently
    // dropping the second CONFIRMED finding before it ever reached `verify`.
    // Grouping on the ORIGINAL site keeps them apart so BOTH survive.
    agenticScanMock.mockReset();
    // Two distinct candidates, each surfaces exactly one finding at its own site.
    agenticScanMock.mockImplementation(async ({ config }: { config: { target: string } }) => {
      const site = config.target; // "/src/a.c" or "/src/b.c"
      const id = site.endsWith("a.c") ? "f-a" : "f-b";
      return { findings: [mkFinding(id, `finding at ${site}`, "")] };
    });

    // Second-audit deepens BOTH findings to the SAME root-cause path.
    const refined: string[] = [];
    const refine: NonNullable<Parameters<typeof runHuntScan>[0]["refine"]> = async (_finding, _candidate) => {
      refined.push(_candidate.path);
      return { path: "/src/core.c" }; // both symptoms → one lifetime bug's path
    };

    const verifyCalls: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      verifyCalls.push(finding.id);
      return { confirmed: true, reason: "reproduced" };
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }, { path: "/src/b.c" }],
      // no brief -> generic hunt: the collapsed group can't be judged, only truncated
      runtime: "api",
      concurrency: 4,
      // default attemptsPerCandidate=1: one finding per site, so any >1 group is
      // PURELY the refine collapse — not real best-of-N widening.
      refine,
      verify,
    });

    // Both original sites were refined and both deepened to the shared path.
    expect(refined.sort()).toEqual(["/src/a.c", "/src/b.c"]);
    expect(res.records.map((r) => r.candidatePath).sort()).toEqual(["/src/core.c", "/src/core.c"]);
    // The drop: pre-fix only f-a reached verify and confirmed had length 1.
    expect(verifyCalls.sort()).toEqual(["f-a", "f-b"]);
    expect(res.confirmed.map((f) => f.id).sort()).toEqual(["f-a", "f-b"]);
    // No spurious "no brief to judge against" truncation warning was emitted.
    expect(res.warnings.some((w) => w.includes("no brief to judge against"))).toBe(false);
  });
});

describe("runHuntScan — finder-fanout resilience (HUNT_FINDER_TIMEOUT_MS / HUNT_FINDER_MAX_RETRIES)", () => {
  const prevTimeout = process.env.HUNT_FINDER_TIMEOUT_MS;
  const prevRetries = process.env.HUNT_FINDER_MAX_RETRIES;

  afterEach(() => {
    if (prevTimeout === undefined) delete process.env.HUNT_FINDER_TIMEOUT_MS;
    else process.env.HUNT_FINDER_TIMEOUT_MS = prevTimeout;
    if (prevRetries === undefined) delete process.env.HUNT_FINDER_MAX_RETRIES;
    else process.env.HUNT_FINDER_MAX_RETRIES = prevRetries;
  });

  it("a finder that never resolves is abandoned after HUNT_FINDER_TIMEOUT_MS and the run still completes with the other candidates", async () => {
    process.env.HUNT_FINDER_TIMEOUT_MS = "20";
    process.env.HUNT_FINDER_MAX_RETRIES = "0";
    agenticScanMock.mockReset();
    agenticScanMock.mockImplementation(async ({ config }: { config: { target: string } }) => {
      if (config.target === "/src/hangs.c") return new Promise(() => {}); // never resolves
      return { findings: [mkFinding(`f-${config.target}`, `finding from ${config.target}`, "")] };
    });

    const verifyCalls: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      verifyCalls.push(finding.id);
      return { confirmed: true, reason: "ok" };
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/hangs.c" }, { path: "/src/ok.c" }],
      runtime: "api",
      concurrency: 2,
      verify,
    });

    // The hung candidate is abandoned (not awaited to completion) and skipped;
    // the other candidate's finding still makes it through the whole gate.
    expect(res.scanned).toBe(2);
    expect(res.finderTimedOut).toBe(1);
    expect(res.finderCompleted).toBe(1);
    expect(res.finderErrored).toBe(0);
    expect(res.findings).toHaveLength(1);
    expect(res.confirmed).toHaveLength(1);
    expect(verifyCalls).toEqual(["f-/src/ok.c"]);
    expect(res.warnings.some((w) => w.includes("timed out") && w.includes("/src/hangs.c"))).toBe(true);
  });

  it("a transient-error finder retries up to HUNT_FINDER_MAX_RETRIES then gives up on that candidate", async () => {
    process.env.HUNT_FINDER_TIMEOUT_MS = "5000";
    process.env.HUNT_FINDER_MAX_RETRIES = "2";
    agenticScanMock.mockReset();
    let calls = 0;
    agenticScanMock.mockImplementation(async () => {
      calls++;
      throw new Error("fetch failed: ECONNRESET");
    });

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/flaky.c" }],
      runtime: "api",
      concurrency: 1,
    });

    // 1 initial attempt + 2 retries = 3 calls, then gives up.
    expect(calls).toBe(3);
    expect(res.scanned).toBe(1);
    expect(res.finderErrored).toBe(1);
    expect(res.finderCompleted).toBe(0);
    expect(res.finderTimedOut).toBe(0);
    expect(res.findings).toHaveLength(0);
    expect(res.warnings.some((w) => w.includes("finder failed on /src/flaky.c"))).toBe(true);
  });

  it("a non-transient error is not retried and is recorded as errored", async () => {
    process.env.HUNT_FINDER_TIMEOUT_MS = "5000";
    process.env.HUNT_FINDER_MAX_RETRIES = "2";
    agenticScanMock.mockReset();
    let calls = 0;
    agenticScanMock.mockImplementation(async () => {
      calls++;
      throw new Error("target file not found");
    });

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/missing.c" }],
      runtime: "api",
      concurrency: 1,
    });

    expect(calls).toBe(1); // no retries — not a transient-looking error
    expect(res.finderErrored).toBe(1);
    expect(res.finderCompleted).toBe(0);
  });

  it("the result carries accurate completed/timed-out/errored counts across a mixed sweep", async () => {
    process.env.HUNT_FINDER_TIMEOUT_MS = "20";
    process.env.HUNT_FINDER_MAX_RETRIES = "0";
    agenticScanMock.mockReset();
    agenticScanMock.mockImplementation(async ({ config }: { config: { target: string } }) => {
      if (config.target === "/src/hangs.c") return new Promise(() => {});
      if (config.target === "/src/broken.c") throw new Error("target file not found");
      return { findings: [] };
    });

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/hangs.c" }, { path: "/src/broken.c" }, { path: "/src/ok.c" }],
      runtime: "api",
      concurrency: 3,
    });

    expect(res.scanned).toBe(3);
    expect(res.finderTimedOut).toBe(1);
    expect(res.finderErrored).toBe(1);
    expect(res.finderCompleted).toBe(1);
    expect(res.finderCompleted + res.finderTimedOut + res.finderErrored).toBe(res.scanned);
  });
});

describe("runHuntScan — memory-flywheel priming (PWNKIT_HUNT_FLYWHEEL=1)", () => {
  it("reorders which finding verify sees first, but leaves the confirmed SET identical to the flag-off run", async () => {
    const brief = {
      bugClass: "nf_tables set-element deferred-free UAF (CWE-416)",
      pattern: "nft_set_elem_deactivate races the GC and frees the element while referenced",
    };

    // f-0 is the true match (buried under a generically-higher judge score);
    // f-1/f-2 are unrelated noise the generic judge over-rates.
    agenticScanMock.mockReset();
    let call = 0;
    agenticScanMock.mockImplementation(async () => {
      const i = call++;
      const bodies = [
        ["f-0", "nf_tables element UAF", "nft_set_elem_deactivate use-after-free race with gc"],
        ["f-1", "unrelated noise A", "generic parsing issue"],
        ["f-2", "unrelated noise B", "generic overflow issue"],
      ] as const;
      const [id, title, analysis] = bodies[i % bodies.length];
      return { findings: [mkFinding(id, title, analysis)] };
    });
    const judgeScores = new Map([
      ["f-0", 2],
      ["f-1", 8],
      ["f-2", 7],
    ]);
    const judgeCandidates: Parameters<typeof runHuntScan>[0]["judgeCandidates"] = async (_brief, findings) => {
      const scores = new Map<string, { score: number; reason: string }>();
      for (const f of findings) scores.set(f.id, { score: judgeScores.get(f.id) ?? 0, reason: "" });
      return scores;
    };
    // Confirmation depends ONLY on finding identity/content, never on call
    // order or priming — f-2 is always refuted, the other two always confirmed.
    const mkVerify = (callOrder: string[]) =>
      (async (finding: Finding) => {
        callOrder.push(finding.id);
        return { confirmed: finding.id !== "f-2", reason: "deterministic-by-content" };
      }) satisfies Parameters<typeof runHuntScan>[0]["verify"];

    const baseOpts = {
      sourceRoot: "/src",
      candidates: [{ path: "/src/nf_tables_api.c" }],
      brief,
      runtime: "api" as const,
      concurrency: 1, // deterministic start order for the call-order assertion
      attemptsPerCandidate: 3,
      judgeTopK: 3, // == group size: nothing is dropped, only reordered
      judgeCandidates,
    };

    const prevFlag = process.env.PWNKIT_HUNT_FLYWHEEL;
    try {
      delete process.env.PWNKIT_HUNT_FLYWHEEL;
      call = 0;
      const coldOrder: string[] = [];
      const cold = await runHuntScan({ ...baseOpts, verify: mkVerify(coldOrder) });

      const memory = new HuntMemory();
      memory.remember(
        {
          candidatePath: "net/netfilter/nf_tables_api.c",
          model: "seed",
          attempt: 0,
          finding: mkFinding("seed", "nf_tables deferred-free UAF", "nft_set_elem_deactivate races gc, use-after-free"),
          skepticConfirmed: true,
          skepticReason: "reproduced under KASAN",
          duplicate: false,
        },
        brief,
      );
      process.env.PWNKIT_HUNT_FLYWHEEL = "1";
      call = 0;
      const primedOrder: string[] = [];
      const primed = await runHuntScan({ ...baseOpts, huntMemory: memory, verify: mkVerify(primedOrder) });

      // Reordering happened: the matching (but generically-underscored)
      // finding moves to the front once memory recognizes its shape.
      expect(coldOrder[0]).not.toBe("f-0");
      expect(primedOrder[0]).toBe("f-0");

      // The confirmed SET is identical either way — priming only ever
      // reordered who got verified first, never what verify decided.
      expect([...cold.confirmed.map((f) => f.id)].sort()).toEqual(["f-0", "f-1"]);
      expect([...primed.confirmed.map((f) => f.id)].sort()).toEqual(["f-0", "f-1"]);
    } finally {
      if (prevFlag === undefined) delete process.env.PWNKIT_HUNT_FLYWHEEL;
      else process.env.PWNKIT_HUNT_FLYWHEEL = prevFlag;
    }
  });
});

describe("runHuntScan — exploitable-geometry rank (PWNKIT_HUNT_GEOMETRY_RANK / opts.geometryRank)", () => {
  // Three findings surfaced at one site (no brief → judge is skipped, so the
  // pre-geometry order is plain attempt order): a pure read-OOB DoS, a neutral
  // logic bug, and — last — a weaponizable qdisc UAF (type-confusion +
  // elastic-reclaim). Geometry rank should pull the UAF to the FRONT of the
  // verify queue; with the flag off the queue stays in attempt order.
  const bodies = [
    ["dos", "out-of-bounds read in foo_parse", "OOB read info leak, denial of service, no write"],
    ["neutral", "config parser off-by-one", "generic logic issue"],
    ["weap", "HFSC qdisc use-after-free", "UAF in a sibling qdisc class, kmalloc-256, reclaim via msg_msg"],
  ] as const;

  function mockThreeAttempts(): void {
    agenticScanMock.mockReset();
    let call = 0;
    agenticScanMock.mockImplementation(async () => {
      const [id, title, analysis] = bodies[call % bodies.length];
      call += 1;
      return { findings: [mkFinding(id, title, analysis)] };
    });
  }

  const baseOpts = {
    sourceRoot: "/src",
    candidates: [{ path: "/src/sch_hfsc.c" }],
    runtime: "api" as const,
    concurrency: 1, // deterministic attempt order for the call-order assertion
    attemptsPerCandidate: 3,
    judgeTopK: 3, // nothing dropped — only reordered
  };

  it("leaves the verify queue in attempt order when OFF (default)", async () => {
    mockThreeAttempts();
    const order: string[] = [];
    await runHuntScan({
      ...baseOpts,
      verify: async (f) => {
        order.push(f.id);
        return { confirmed: true, reason: "ok" };
      },
    });
    expect(order).toEqual(["dos", "neutral", "weap"]);
  });

  it("pulls the type-confusion + elastic-reclaim UAF to the front when ON", async () => {
    mockThreeAttempts();
    const order: string[] = [];
    await runHuntScan({
      ...baseOpts,
      geometryRank: true,
      verify: async (f) => {
        order.push(f.id);
        return { confirmed: true, reason: "ok" };
      },
    });
    expect(order[0]).toBe("weap");
    // The read-OOB DoS (negative geometry) sinks to last.
    expect(order[order.length - 1]).toBe("dos");
    // Re-rank only: the verified SET is unchanged.
    expect([...order].sort()).toEqual(["dos", "neutral", "weap"]);
  });
});
