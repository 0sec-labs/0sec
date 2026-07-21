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

const { runHuntScan, makeMultiLensVerifier } = await import("./hunt-scan.js");

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

  it("a finder that streams a finding then hangs surfaces the partial (tagged partial/timed-out, NOT confirmed) AND records an incomplete-coverage entry", async () => {
    process.env.HUNT_FINDER_TIMEOUT_MS = "20";
    process.env.HUNT_FINDER_MAX_RETRIES = "0";
    agenticScanMock.mockReset();
    // The hung finder emits ONE `finding` event (raw save_finding args) before
    // it hangs forever — mirrors agentic-scanner.ts streaming a save_finding
    // per turn, then the Codex backend stalling mid-call.
    agenticScanMock.mockImplementation(
      async ({
        config,
        onEvent,
      }: {
        config: { target: string };
        onEvent?: (e: { type: string; message: string; data?: unknown }) => void;
      }) => {
        if (config.target === "/src/hangs.c") {
          onEvent?.({
            type: "finding",
            message: "method-authz bypass",
            data: {
              title: "method-authz bypass",
              severity: "high",
              category: "missing-validation",
              description: "partial lead observed before the finder hung",
              evidence_request: "GET /admin",
              evidence_response: "200 OK",
            },
          });
          return new Promise(() => {}); // never resolves — hang after streaming the partial
        }
        return { findings: [] };
      },
    );

    // Capture the finding + its status AT the verify gate: if the code had
    // auto-confirmed the partial, status would be "confirmed" here.
    const statusAtVerify: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      statusAtVerify.push(finding.status);
      return { confirmed: false, reason: "unproven partial" };
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/hangs.c" }],
      runtime: "api",
      concurrency: 1,
      verify,
    });

    // (a) The partial is surfaced instead of an empty array.
    expect(res.finderTimedOut).toBe(1);
    expect(res.findings).toHaveLength(1);
    const partial = res.findings[0];
    expect(partial.title).toBe("method-authz bypass");
    expect(partial.severity).toBe("high");
    expect(partial.triageNote).toContain("partial/timed-out");

    // (b) A structured incomplete-coverage entry is recorded for the cell.
    expect(res.incompleteCoverage).toEqual([
      { file: "/src/hangs.c", lensId: "", reason: "timeout", budgetMs: 20 },
    ]);

    // (c) The partial is adjudicated by verify — reached it as "discovered",
    // never auto-confirmed, and (verify said no) is NOT in `confirmed`.
    expect(statusAtVerify).toEqual(["discovered"]);
    expect(partial.status).not.toBe("confirmed");
    expect(res.confirmed).toHaveLength(0);
  });

  it("a finder that hangs with NO streamed findings still records the coverage gap (signal is independent of partial recovery)", async () => {
    process.env.HUNT_FINDER_TIMEOUT_MS = "20";
    process.env.HUNT_FINDER_MAX_RETRIES = "0";
    agenticScanMock.mockReset();
    agenticScanMock.mockImplementation(async () => new Promise(() => {})); // hang, emit nothing

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/silent.c" }],
      runtime: "api",
      concurrency: 1,
    });

    expect(res.finderTimedOut).toBe(1);
    expect(res.findings).toHaveLength(0);
    expect(res.incompleteCoverage).toEqual([
      { file: "/src/silent.c", lensId: "", reason: "timeout", budgetMs: 20 },
    ]);
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

describe("runHuntScan — specialized-lens finder fan-out (depth method, default-off)", () => {
  it("lenses absent leaves the run product byte-identical and the finder hint free of any lens text; a lens hint is purely APPENDED", async () => {
    // Capture the exact challengeHint each finder run receives.
    const capture = (): string[] => {
      const hints: string[] = [];
      agenticScanMock.mockReset();
      agenticScanMock.mockImplementation(async ({ challengeHint }: { challengeHint: string }) => {
        hints.push(challengeHint);
        return { findings: [] as Finding[] };
      });
      return hints;
    };
    const brief = { bugClass: "missing length check", pattern: "memcpy without bound" };
    const candidates = [{ path: "/src/a.c", hint: "CANDHINT" }];

    // Run A: NO lenses (today's path). One finder run, one hint.
    const hintsA = capture();
    const resA = await runHuntScan({ sourceRoot: "/src", candidates, brief, runtime: "api", concurrency: 1 });
    expect(resA.scanned).toBe(1); // 1 candidate × 1 model × (sentinel) × 1 attempt — unchanged product
    expect(hintsA).toHaveLength(1);
    // The default hint carries the brief + candidate hint and NOTHING lens-shaped.
    expect(hintsA[0]).toContain("missing length check");
    expect(hintsA[0]).toContain("CANDHINT");
    expect(hintsA[0]).not.toContain("LENS_MARK");

    // Run B: one real lens with a marker hint — same everything else.
    const hintsB = capture();
    const resB = await runHuntScan({
      sourceRoot: "/src",
      candidates,
      brief,
      runtime: "api",
      concurrency: 1,
      lenses: [{ id: "arithmetic", challengeHint: "LENS_MARK arithmetic focus" }],
    });
    expect(resB.scanned).toBe(1); // 1 candidate × 1 model × 1 lens × 1 attempt
    expect(hintsB).toHaveLength(1);
    // The lens hint is appended VERBATIM to the exact default hint — nothing else changed.
    expect(hintsB[0]).toBe(`${hintsA[0]} LENS_MARK arithmetic focus`);
  });

  it("N lenses multiply the run product and each lens keeps its OWN best-of-N group so findings UNION instead of truncating", async () => {
    // Two lenses, ONE candidate, no brief, one attempt each. Each lens surfaces a
    // distinct finding at the SAME site. Pre-lens-key grouping would collapse both
    // into one (path, model) group and — with no brief — truncate to judgeTopK=1,
    // silently dropping the second lens's finding with a warning. The lens segment
    // in siteGroupKey keeps them in two groups of one, so BOTH reach verify.
    agenticScanMock.mockReset();
    agenticScanMock.mockImplementation(async ({ challengeHint }: { challengeHint: string }) => {
      const lens = challengeHint.includes("LENS_A") ? "a" : "b";
      return { findings: [mkFinding(`f-${lens}`, `finding via lens ${lens}`, "")] };
    });

    const verifyCalls: string[] = [];
    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => {
      verifyCalls.push(finding.id);
      return { confirmed: true, reason: "ok" };
    };

    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }],
      // no brief -> generic hunt; a >1 group would only be truncatable, never judged
      runtime: "api",
      concurrency: 2,
      lenses: [
        { id: "lens-a", challengeHint: "LENS_A angle" },
        { id: "lens-b", challengeHint: "LENS_B angle" },
      ],
      verify,
    });

    expect(res.scanned).toBe(2); // 1 candidate × 1 model × 2 lenses × 1 attempt
    expect(res.findings.map((f) => f.id).sort()).toEqual(["f-a", "f-b"]); // union
    expect(verifyCalls.sort()).toEqual(["f-a", "f-b"]); // BOTH reached the gate
    expect(res.confirmed.map((f) => f.id).sort()).toEqual(["f-a", "f-b"]);
    // No collapse: the no-brief truncation warning must NOT fire — they were separate groups.
    expect(res.warnings.some((w) => w.includes("no brief to judge against"))).toBe(false);
  });
});

describe("makeMultiLensVerifier — multi-lens verify quorum (depth method)", () => {
  const lenses = [
    { id: "reachability", challengeHint: "reach" },
    { id: "completeness", challengeHint: "complete" },
    { id: "novelty", challengeHint: "novel" },
    { id: "scope", challengeHint: "scope" },
  ];
  const finding = mkFinding("f-1", "candidate finding", "");
  const candidate = { path: "/src/x.c" };

  // Inject fake per-lens passes so the quorum logic is tested with ZERO LLM calls.
  // `outcomes[lensId]`: true = survives, false = refutes, "throw" = errors.
  const makePassFrom =
    (outcomes: Record<string, boolean | "throw">) =>
    (lens: { id: string; challengeHint: string }) =>
    async () => {
      const o = outcomes[lens.id];
      if (o === "throw") throw new Error(`lens ${lens.id} errored`);
      return { confirmed: o, reason: o ? "survived" : "refuted" };
    };

  const base = { sourceRoot: "/src", runtime: "api" as const };

  it("confirms when 0 lenses refute AND survivors meet the majority quorum", async () => {
    const verify = makeMultiLensVerifier(lenses, {
      ...base,
      makePass: makePassFrom({ reachability: true, completeness: true, novelty: true, scope: true }),
    });
    const v = await verify(finding, candidate);
    expect(v.confirmed).toBe(true);
    expect(v.reason).toContain("quorum met");
  });

  it("confirms at exactly the quorum boundary even when some lenses ERROR (fail-closed on survivors, not on errors)", async () => {
    // 4 lenses, majority quorum = 2. Two survive, two error (neither survives nor refutes).
    const verify = makeMultiLensVerifier(lenses, {
      ...base,
      makePass: makePassFrom({ reachability: true, completeness: true, novelty: "throw", scope: "throw" }),
    });
    const v = await verify(finding, candidate);
    expect(v.confirmed).toBe(true); // 2 survived >= quorum 2, 0 refuted
  });

  it("does NOT confirm when ANY lens refutes, even with a survivor majority", async () => {
    const verify = makeMultiLensVerifier(lenses, {
      ...base,
      makePass: makePassFrom({ reachability: true, completeness: true, novelty: true, scope: false }),
    });
    const v = await verify(finding, candidate);
    expect(v.confirmed).toBe(false);
    expect(v.reason).toContain("refuted by scope");
  });

  it("does NOT confirm when survivors fall below quorum (no refutes, but too many errors)", async () => {
    // Only 1 survives, 3 error → survived 1 < majority quorum 2, 0 refuted.
    const verify = makeMultiLensVerifier(lenses, {
      ...base,
      makePass: makePassFrom({ reachability: true, completeness: "throw", novelty: "throw", scope: "throw" }),
    });
    const v = await verify(finding, candidate);
    expect(v.confirmed).toBe(false);
    expect(v.reason).toContain("below quorum");
  });

  it("honors an explicit quorum override (unanimous)", async () => {
    // quorum = 4 (all): 3 survivors is not enough.
    const verify = makeMultiLensVerifier(lenses, {
      ...base,
      quorum: 4,
      makePass: makePassFrom({ reachability: true, completeness: true, novelty: true, scope: "throw" }),
    });
    const v = await verify(finding, candidate);
    expect(v.confirmed).toBe(false);
    expect(v.reason).toContain("below quorum");
  });

  it("throws when constructed with zero lenses", () => {
    expect(() => makeMultiLensVerifier([], base)).toThrow(/at least one/);
  });
});

describe("runHuntScan — incremental persistence (opts.onConfirmed)", () => {
  it("fires the hook exactly once per CONFIRMED finding (not for refuted ones), as each clears the gate", async () => {
    // Two candidates, one finding each; verify confirms f-good, refutes f-bad.
    agenticScanMock.mockReset();
    agenticScanMock.mockImplementation(async ({ config }: { config: { target: string } }) => {
      const id = config.target.endsWith("good.c") ? "f-good" : "f-bad";
      return { findings: [mkFinding(id, `finding at ${config.target}`, "")] };
    });

    const verify: NonNullable<Parameters<typeof runHuntScan>[0]["verify"]> = async (finding) => ({
      confirmed: finding.id === "f-good",
      reason: "deterministic-by-id",
    });

    const streamed: string[] = [];
    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/good.c" }, { path: "/src/bad.c" }],
      runtime: "api",
      concurrency: 2,
      verify,
      onConfirmed: (finding) => {
        streamed.push(finding.id);
      },
    });

    // Only the confirmed finding was streamed, and it was streamed exactly once.
    expect(streamed).toEqual(["f-good"]);
    expect(res.confirmed.map((f) => f.id)).toEqual(["f-good"]);
  });

  it("never fires for any finding when no verifier confirms", async () => {
    agenticScanMock.mockReset();
    agenticScanMock.mockImplementation(async () => ({ findings: [mkFinding("f-1", "x", "")] }));
    const streamed: string[] = [];
    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }],
      runtime: "api",
      concurrency: 1,
      verify: async () => ({ confirmed: false, reason: "refuted" }),
      onConfirmed: (f) => {
        streamed.push(f.id);
      },
    });
    expect(streamed).toEqual([]);
    expect(res.confirmed).toHaveLength(0);
  });

  it("a throwing onConfirmed hook NEVER drops the finding — it stays confirmed and the error is a warning", async () => {
    agenticScanMock.mockReset();
    agenticScanMock.mockImplementation(async () => ({ findings: [mkFinding("f-1", "leak", "")] }));
    const res = await runHuntScan({
      sourceRoot: "/src",
      candidates: [{ path: "/src/a.c" }],
      runtime: "api",
      concurrency: 1,
      verify: async () => ({ confirmed: true, reason: "reproduced" }),
      onConfirmed: async () => {
        throw new Error("sink POST failed");
      },
    });
    // The persistence failure does not lose the finding from the result set.
    expect(res.confirmed.map((f) => f.id)).toEqual(["f-1"]);
    expect(res.warnings.some((w) => w.includes("onConfirmed hook failed"))).toBe(true);
  });
});
