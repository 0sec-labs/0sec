import { describe, expect, it } from "vitest";

import type { Finding } from "@pwnkit/shared";

import { rankByGeometry, scoreGeometry } from "./geometry-score.js";

/** Minimal offline Finding fixture — only the fields the scorer reads matter. */
function finding(partial: {
  title: string;
  description?: string;
  analysis?: string;
  request?: string;
  category?: Finding["category"];
}): Finding {
  return {
    id: "id",
    templateId: "t",
    title: partial.title,
    description: partial.description ?? "",
    severity: "high",
    category: partial.category ?? "other",
    status: "discovered",
    evidence: {
      request: partial.request ?? "",
      response: "",
      analysis: partial.analysis ?? "",
    },
    timestamp: Date.now(),
  };
}

describe("kernel/geometry-score", () => {
  const weaponizable = finding({
    title: "HFSC qdisc use-after-free in net/sched/sch_hfsc.c",
    description:
      "A use-after-free on a sibling qdisc class object (kmalloc-256) — the freed slot " +
      "is reclaimable with a msg_msg spray, giving a type-confusion into a differently-seeded cache.",
    analysis: "Subsystem: net/sched\nFaulting function: hfsc_change_class\nPrimitive: UAF write",
    request: "net/sched/sch_hfsc.c:812",
  });

  const readOobDos = finding({
    title: "out-of-bounds read in foo_parse()",
    description:
      "An out-of-bounds read leaks a few bytes past the buffer; a denial of service / info leak. " +
      "No write primitive, no attacker-controlled corruption.",
    analysis: "Subsystem: drivers/misc\nPrimitive: OOB read (info leak)",
    request: "drivers/misc/foo.c:44",
  });

  it("flags type-confusion + elastic-reclaim geometry on a weaponizable candidate", () => {
    const g = scoreGeometry(weaponizable);
    expect(g.hasTypeConfusion).toBe(true);
    expect(g.hasReclaimPath).toBe(true);
    expect(g.geometryScore).toBeGreaterThan(0);
    // Cites the concrete signals in the rationale.
    expect(g.rationale.join(" ")).toMatch(/type-confusion/i);
    expect(g.rationale.join(" ")).toMatch(/reclaim/i);
  });

  it("penalizes a pure read-OOB / DoS with no write primitive", () => {
    const g = scoreGeometry(readOobDos);
    expect(g.hasReclaimPath).toBe(false);
    expect(g.geometryScore).toBeLessThan(0);
    expect(g.rationale.join(" ")).toMatch(/DoS|read-OOB/i);
  });

  it("up-ranks the weaponizable candidate above the read-OOB DoS", () => {
    expect(scoreGeometry(weaponizable).geometryScore).toBeGreaterThan(
      scoreGeometry(readOobDos).geometryScore,
    );
    const ranked = rankByGeometry(
      [readOobDos, weaponizable],
      (f) => f,
    );
    expect(ranked[0]).toBe(weaponizable);
    expect(ranked[1]).toBe(readOobDos);
  });

  it("credits a heap-corruption primitive with no established reclaim, below a full-geometry bug", () => {
    // OOB-write but no slab/elastic context and no sibling-type signal.
    const partial = finding({
      title: "out-of-bounds write in stack buffer of quux()",
      description: "An out-of-bounds write past a fixed stack buffer.",
      analysis: "Primitive: OOB write",
    });
    const g = scoreGeometry(partial);
    expect(g.hasReclaimPath).toBe(false);
    // Positive (a write primitive), but strictly below the full type-confusion+reclaim bug.
    expect(g.geometryScore).toBeGreaterThan(0);
    expect(g.geometryScore).toBeLessThan(scoreGeometry(weaponizable).geometryScore);
  });

  it("returns a neutral score with no geometry signal", () => {
    const g = scoreGeometry(finding({ title: "logic error in config parser", description: "off-by-one in a loop bound" }));
    expect(g.geometryScore).toBe(0);
    expect(g.hasTypeConfusion).toBe(false);
    expect(g.hasReclaimPath).toBe(false);
  });

  it("rank is stable for equal scores (preserves input order)", () => {
    const a = finding({ title: "neutral a" });
    const b = finding({ title: "neutral b" });
    const ranked = rankByGeometry([a, b], (f) => f);
    expect(ranked).toEqual([a, b]);
  });
});
