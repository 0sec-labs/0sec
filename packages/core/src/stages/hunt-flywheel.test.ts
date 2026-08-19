/**
 * `HuntMemory` — the preseeded 5-layer flywheel (hunt-flywheel.ts). Coverage:
 *
 *   - `classTokens`: CWE + phrase-map join-key extraction.
 *   - The store ships preseeded (principle/semantic/procedural from the
 *     archetype registry), never empty at construction.
 *   - `recall`/`prime`: no-signal is inert (rankBonus always 0, cost_route
 *     "cheap"); a genuine recall bounds the bonus at 0.70 and routes "full".
 *   - `remember`: an episodic memory folded in is recallable afterward.
 *   - `provePriming()`: the controlled primed-vs-cold proof — a similar
 *     target's judge-rank is lifted, an un-similar control's is NOT (delta 0),
 *     proving the flywheel primes/reorders only and never confirms.
 */

import { describe, expect, it } from "vitest";
import type { Finding } from "@pwnkit/shared";
import {
  HuntMemory,
  classTokens,
  huntFlywheelEnabled,
  provePriming,
  PRIME_MIN,
} from "./hunt-flywheel.js";
import type { HuntBrief } from "./hunt-scan.js";

function mkFinding(id: string, title: string, analysis: string): Finding {
  return {
    id,
    templateId: "flywheel-test",
    title,
    description: title,
    severity: "medium",
    category: "other",
    status: "discovered",
    evidence: { request: "", response: "", analysis },
  };
}

describe("huntFlywheelEnabled", () => {
  it("is OFF by default and ON only for a truthy PWNKIT_HUNT_FLYWHEEL", () => {
    const prev = process.env.PWNKIT_HUNT_FLYWHEEL;
    try {
      delete process.env.PWNKIT_HUNT_FLYWHEEL;
      expect(huntFlywheelEnabled()).toBe(false);
      process.env.PWNKIT_HUNT_FLYWHEEL = "0";
      expect(huntFlywheelEnabled()).toBe(false);
      process.env.PWNKIT_HUNT_FLYWHEEL = "1";
      expect(huntFlywheelEnabled()).toBe(true);
    } finally {
      if (prev === undefined) delete process.env.PWNKIT_HUNT_FLYWHEEL;
      else process.env.PWNKIT_HUNT_FLYWHEEL = prev;
    }
  });
});

describe("classTokens", () => {
  it("extracts CWE codes and maps recognized phrases to the same lens id", () => {
    const a = classTokens("CWE-416 deferred-free use-after-free");
    const b = classTokens("a use after free bug, CWE-416");
    expect(a.has("cwe-416")).toBe(true);
    expect(a.has("uaf")).toBe(true);
    // Both spellings join on the same token set.
    expect([...a].sort()).toEqual([...b].sort());
  });

  it("returns an empty set for text with no recognized class signal", () => {
    expect(classTokens("just some prose about nothing in particular").size).toBe(0);
  });
});

describe("HuntMemory — preseed", () => {
  it("ships preseeded (principle/semantic/procedural > 0) at construction — never empty", () => {
    const memory = new HuntMemory();
    const counts = memory.counts();
    expect(counts.principle).toBeGreaterThan(0);
    expect(counts.procedural).toBeGreaterThan(0);
    expect(counts.semantic).toBeGreaterThan(0);
    // No corpus path given -> no episodic/analogical yet.
    expect(counts.episodic).toBe(0);
    expect(counts.analogical).toBe(0);
    expect(counts.total).toBe(counts.principle + counts.semantic + counts.procedural);
  });
});

describe("HuntMemory — recall/prime", () => {
  const unrelatedBrief: HuntBrief = {
    bugClass: "an entirely made-up class with no kernel-archetype overlap xyzzy",
    pattern: "plugh plover frobnicate wibble",
  };

  it("prime() with no similar signal is inert: rankBonus always 0, cost_route cheap", () => {
    const memory = new HuntMemory();
    const priming = memory.prime(unrelatedBrief);
    expect(priming.active).toBe(false);
    expect(priming.costRoute).toBe("cheap");
    expect(priming.rankBonus(mkFinding("f1", "anything", "anything"))).toBe(0);
    expect(priming.framing).toBe("");
  });

  it("recall() against a known archetype shape returns matches above PRIME_MIN", () => {
    const memory = new HuntMemory();
    const brief: HuntBrief = {
      bugClass: "nf_tables set-element deferred-free UAF (CWE-416)",
      pattern: "nft_set_elem_deactivate races the GC and frees the element while referenced",
    };
    const recalls = memory.recall(brief);
    expect(recalls.length).toBeGreaterThan(0);
    for (const r of recalls) expect(r.score).toBeGreaterThanOrEqual(PRIME_MIN);
  });

  it("prime() with a genuine recall is active, bounds rankBonus at <= 0.70, and routes full", () => {
    const memory = new HuntMemory();
    const brief: HuntBrief = {
      bugClass: "nf_tables set-element deferred-free UAF (CWE-416)",
      pattern: "nft_set_elem_deactivate races the GC and frees the element while referenced",
    };
    const priming = memory.prime(brief);
    expect(priming.active).toBe(true);
    expect(priming.costRoute).toBe("full");
    expect(priming.framing.length).toBeGreaterThan(0);
    const matching = mkFinding("f1", "nf_tables UAF", "nft_set_elem_deactivate use-after-free");
    const bonus = priming.rankBonus(matching);
    expect(bonus).toBeGreaterThan(0);
    expect(bonus).toBeLessThanOrEqual(0.7);
  });
});

describe("HuntMemory — remember", () => {
  it("folds a confirmed finding into EPISODIC, recallable by a matching brief afterward", () => {
    const memory = new HuntMemory();
    const brief: HuntBrief = { bugClass: "a wholly novel vendor cmdi shape (CWE-78)", pattern: "getenv feeds doSystem unchecked" };
    expect(memory.recall(brief)).toHaveLength(0);

    memory.remember(
      {
        candidatePath: "vendor/router_a.c",
        model: "test",
        attempt: 0,
        finding: mkFinding("seed-1", "vendor cmdi", "getenv feeds doSystem unchecked, command injection"),
        skepticConfirmed: true,
        skepticReason: "reproduced",
        duplicate: false,
      },
      brief,
    );

    const recalls = memory.recall(brief);
    expect(recalls.length).toBeGreaterThan(0);
    expect(recalls[0].memory.layer).toBe("episodic");
    expect(recalls[0].memory.confirmed).toBe(true);
    expect(memory.counts().episodic).toBe(1);
  });
});

describe("provePriming — the primes-never-confirms invariant", () => {
  it("lifts a SIMILAR target's judge-rank, gives an UN-SIMILAR control zero lift, and never touches confirmation", () => {
    const report = provePriming();

    // The similar target was ranked behind generic noise cold, and priming
    // moves it strictly forward (fewer escalations needed to reach it).
    expect(report.similarColdRank).toBeGreaterThan(report.similarPrimedRank);
    expect(report.similarRecallTop).toBeGreaterThanOrEqual(PRIME_MIN);
    expect(report.similarCostRoute).toBe("full");

    // The un-similar control gets NO spurious lift: rank unchanged, no recall
    // signal, cost-router stays on the cheap lane.
    expect(report.controlPrimedRank).toBe(report.controlColdRank);
    expect(report.controlRecallTop).toBe(0);
    expect(report.controlCostRoute).toBe("cheap");

    // provePriming() never calls opts.verify / any confirmation path at all —
    // it only exercises `primedOrderKey`, the ordering function. There is no
    // `confirmed` field on `HuntProofReport` to flip: structurally, priming
    // cannot manufacture a verdict here.
    expect("confirmed" in report).toBe(false);
  });
});
